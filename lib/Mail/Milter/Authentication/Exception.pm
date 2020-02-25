package Mail::Milter::Authentication::Exception;
use 5.20.0;
use strict;
use warnings;
use Mail::Milter::Authentication::Pragmas;
# ABSTRACT: Class representing an exception
# VERSION

=constructor I<new( $args )>

die Mail::Milter::Authentication::Exception->new({ 'Type' => 'Timeout', 'Text' => 'Example timeout exception' });

Create a new exception object.

=cut

sub new {
    my ( $class, $args ) = @_;
    my $self = $args;
    bless $self, $class;
    return $self;
}

1;
