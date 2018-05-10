package Mail::Milter::Authentication::Exception;
use strict;
use warnings;
# VERSION

sub new {
    my ( $class, $args ) = @_;
    my $self = $args;
    bless $self, $class;
    return $self;
}

1;
