use v5.20;
use experimental qw(signatures postderef);

package Dist::Zilla::Plugin::ReleaseSignature;

{
  use Moose;
  use Moose::Util::TypeConstraints qw(enum);
}
use Carp                  qw(croak);
use File::Spec::Functions qw(devnull);
use Path::Tiny            qw(path);
use IPC::Open3            qw(open3);
use Text::ParseWords      qw(shellwords);

use namespace::autoclean;

our $VERSION = 'v0.1.0';

with qw(
  Dist::Zilla::Role::BeforeRelease
  Dist::Zilla::Role::Releaser
);

has git => (
  is => 'ro',
  lazy => 1,
  default => sub ($self) {
    Git::Wrapper->new($self->zilla->root->stringify);
  },
);

sub git_config ($self, @args) {
   eval { $self->git->RUN('config', @args ) }
}


has format => (
  is => 'ro',
  lazy => 1,
  isa => enum([qw( openpgp ssh x509 signify )]),
  builder => '_build_format',
);

sub _build_format ($self) {
  my $zilla = $self->zilla;
  my $stash = $zilla->stash_named('%Sign');

  my $format = $stash ? $stash->format : undef;
  return $format // $self->git_config('gpg.format') // 'openpgp';
}

has program => (
  is => 'ro',
  lazy => 1,
  builder => '_build_program',
);

sub _build_program ($self) {
  my $format = $self->format;
  my $program = $self->git_config("gpg.$format.program");
  $program //= $self->git_config("gpg.program")
    if $format eq 'openpgp';
  $program //=
    $format eq 'openpgp'    ? 'gpg'
    : $format eq 'ssh'      ? 'ssh-keygen'
    : $format eq 'x509'     ? 'gpgsm'
    : $format eq 'signify'  ? 'signify'
    : croak "unsupported format $format!";
  return $program;
}

has signing_key => (
  is => 'ro',
  lazy => 1,
  builder => '_build_signing_key',
);

sub _build_signing_key ($self) {
  my $zilla = $self->zilla;
  my $stash = $zilla->stash_named('%Sign');

  my $signing_key = $stash ? $stash->signing_key : undef;
  $signing_key //= $self->git_config('--type=path', 'user.signingKey');
  $signing_key //= do {
    my $format = $self->format;
    my $key;
    if ($format eq 'ssh') {
      my $def_command = $self->git_config("gpg.$format.defaultKeyCommand") // "ssh-add -L";
      my @command = shellwords($def_command);
      open my $in, '<', devnull
        or die "$!";
      open my $err, '>', devnull
        or die "$!";
      my $pid = open3($in, my $fh, $err, @command);
      my $keys = do { local $/; <$fh> };
      close $fh;
      waitpid $pid, 0;
      $keys =~ /(.+)/
        and $key = "key::$1";
    }
    $key;
  };

  if (defined $signing_key) {
    $signing_key =~ s/^ssh-/key::ssh-/;
  }

  $signing_key;
}

sub signing_file ($self) {
  my $key = $self->signing_key;
  if ($key =~ /\Akey::(.*)/s) {
    my $key_content = $1;
    my $temp = Path::Tiny->tempfile(
      TEMPLATE => 'Dist-Zilla-signing-key-XXXXXX',
    );
    $temp->spew_raw($key_content);
    return $temp;
  }
  elsif ($key) {
    return path($key)->assert( sub { $_->exists } );
  }
  croak "No signing key specified";
}

has ascii => (
  is => 'ro',
  default => 1,
);

has signature_pattern => (
  is => 'ro',
  default => '%s.sig',
);

sub signature_file_for ($self, $file) {
  return path(sprintf $self->signature_pattern, $file);
}

sub other_releasers ($self) {
  my @releasers = grep { $_ != $self } $self->zilla->plugins_with(-Releaser)->@*;

  croak "you can't release without any Releaser plugins"
    if !@releases;

  return @releasers;
}

sub generate_signature ($self, $archive) {
  my $sig_file = $self->signature_file_for($archive);

  my $format = $self->format;
  my $program = $self->program;
  my $tgz_fh = $archive->openr_raw;
  my @args
    = $format eq 'openpgp' ? (
      '--detach-sign',
      '--local-user' => $self->signing_key,
      ($self->ascii ? '--armor' : ()),
    )
    : $format eq 'ssh' ? (
      '-Y' => 'sign',
      '-f' => $self->signing_file,
      '-n' => 'file',
    )
    : $format eq 'x509' ? (
      '--sign',
      '--local-user' => $self->signing_key,
      ($self->ascii ? '--armor' : ()),
    )
    : $format eq 'signify' ? (
      '-S',
      '-s' => $self->signing_file,
      '-m' => '-',
      '-x' => '-',
    )
    : croak "unsupported format $format!";

  $self->log([ 'Generating %s signature for %s', $format, $archive]);

  my $pid = open3($tgz_fh, my $fh, '>&STDERR', $program, @args)
    or die "can't run $program: $!";

  my $sig = do { local $/; <$fh> };
  close $fh;
  waitpid $pid, 0;
  if ($? != 0) {
    croak "Signing failed! (wstat $?)";
  }

  $sig_file->spew_raw($sig);

  return $sig_file;
}

sub before_release ($self, $archive) {
  my ($self, $archive) = @_;

  # assert that another releaser exists
  $self->other_releasers;

  $self->generate_signature($archive);

  return;
}

sub release ($self, $archive) {
  my @releasers = $self->other_releasers;

  my $sig_file = $self->signature_file_for($archive);

  $_->release($sig_file)
    for $self->other_releasers;

  return;
}

__PACKAGE__->meta->make_immutable;
1;
