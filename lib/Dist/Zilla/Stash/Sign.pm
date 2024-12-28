use v5.20;
use experimental qw(signatures postderef);

package Dist::Zilla::Stash::Sign;

{ use Moose; }

use namespace::autoclean;

our $VERSION = 'v0.1.0';

with 'Dist::Zilla::Role::Stash';

has format => (
  is  => 'ro',
  isa => 'Str',
);

has signing_key => (
  is  => 'ro',
  isa => 'Str',
);

__PACKAGE__->meta->make_immutable;
1;
__END__
