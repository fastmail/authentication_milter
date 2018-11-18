package Mail::Milter::Authentication::Resolver;
use strict;
use warnings;
# VERSION
use base 'Net::DNS::Resolver';
use Scalar::Util qw{ weaken };

=head1 DESCRIPTION

Subclass for Net::DNS::Resolver, Versions of Net::DNS::Resolver from 1.03 up (to at least
1.18 at time of writing) do not timeout as expected. This introduces a wrapper timeout around
the query, send, and search calls which will fire 0.1 seconds after the timeout value passed
to Net::DNS::Resolver

=cut

{
    sub new {
        my $class = shift;
        my %args = @_;
        my $self = $class->SUPER::new( @_ );
        weaken($args{_handler});
        $self->{ _handler } = $args{_handler};
        return $self;
    }
}

sub _do { ## no critic
    my $self = shift;
    my $what = shift;
    my $handler = $self->{_handler};
    my $config = $handler->config();
    my $timeout = $config->{'dns_timeout'};

    my $return;

    eval {
        $handler->set_handler_alarm( ( $timeout + 0.1 ) * 1000000 ); # 0.1 seconds over that passed to Net::DNS::Resolver
        $return = $self->SUPER::send( @_ )   if $what eq 'send';
        $return = $self->SUPER::query( @_ )  if $what eq 'query';
        $return = $self->SUPER::search( @_ ) if $what eq 'search';
        $handler->reset_alarm();
    };

    if ( my $error = $@ ) {
        $handler->reset_alarm();
        my $type = $handler->is_exception_type( $error );
        if ( $type && $type eq 'Timeout' ) {
            # We have a timeout, is it global or is it ours?
            if ( $handler->get_time_remaining() > 0 ) {
                # We have time left, but the aggregate save timed out
                # Log this and move on!
                $handler->log_error( 'DNS Lookup timeout not caught by Net::DNS::Resolver' );
                return;
            }
        }
        $handler->handle_exception( $error );
    }
    return $return;
}

sub query { ## no critic
    my $self = shift;
    return $self->_do( 'query', @_ );
}

sub search { ## no critic
    my $self = shift;
    return $self->_do( 'search', @_ );
}

sub send { ## no critic
    my $self = shift;
    return $self->_do( 'send', @_ );
}

1;
