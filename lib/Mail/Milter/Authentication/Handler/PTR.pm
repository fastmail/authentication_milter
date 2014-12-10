package Mail::Milter::Authentication::Handler::PTR;

use strict;
use warnings;

our $VERSION = 0.5;

use base 'Mail::Milter::Authentication::Handler::Generic';

use Sys::Syslog qw{:standard :macros};

sub helo_callback {

    # On HELO
    my ( $self, $helo_host ) = @_;
    return if ( $self->is_local_ip_address() );
    return if ( $self->is_trusted_ip_address() );
    return if ( $self->is_authenticated() );

    if ( ! $self->is_handler_loaded( 'IPRev' ) ) {
        $self->log_error( 'PTR Config Error: IPRev is missing ');
        return;
    }

    my $iprev_handler = $self->get_handler('IPRev');
    my $domain =
      exists( $iprev_handler->{'verified_ptr'} )
      ? $iprev_handler->{'verified_ptr'}
      : q{};

    if ( lc $domain eq lc $helo_host ) {
        $self->dbgout( 'PTRMatch', 'pass', LOG_DEBUG );
        $self->add_c_auth_header(
                $self->format_header_entry( 'x-ptr',        'pass' ) . q{ }
              . $self->format_header_entry( 'x-ptr-helo',   $helo_host ) . q{ }
              . $self->format_header_entry( 'x-ptr-lookup', $domain ) );
    }
    else {
        $self->dbgout( 'PTRMatch', 'fail', LOG_DEBUG );
        $self->add_c_auth_header(
                $self->format_header_entry( 'x-ptr',        'fail' ) . q{ }
              . $self->format_header_entry( 'x-ptr-helo',   $helo_host ) . q{ }
              . $self->format_header_entry( 'x-ptr-lookup', $domain ) );
    }
}

1;
