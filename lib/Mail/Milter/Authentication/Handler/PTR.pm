package Mail::Milter::Authentication::Handler::PTR;

use strict;
use warnings;

our $VERSION = 0.3;

use base 'Mail::Milter::Authentication::Handler::Generic';

use Sys::Syslog qw{:standard :macros};

sub helo_callback {
    # On HELO
    my ( $self, $helo_host ) = @_;
    my $CONFIG = $self->config();
    my $priv = $self->{'ctx'}->getpriv();
    return if ( !$CONFIG->{'check_ptr'} );
    return if ( $priv->{'is_local_ip_address'} );
    return if ( $priv->{'is_trusted_ip_address'} );
    return if ( $priv->{'is_authenticated'} );

    my $domain =
      exists( $priv->{'iprev.verified_ptr'} ) ? $priv->{'iprev.verified_ptr'} : q{};
    my $helo_name = $priv->{'core.helo_name'};

    if ( lc $domain eq lc $helo_name ) {
        $self->dbgout( 'PTRMatch', 'pass', LOG_DEBUG );
        $self->add_c_auth_header(
                $self->format_header_entry( 'x-ptr', 'pass' ) . q{ }
              . $self->format_header_entry( 'x-ptr-helo',   $helo_name ) . q{ }
              . $self->format_header_entry( 'x-ptr-lookup', $domain ) );
    }
    else {
        $self->dbgout( 'PTRMatch', 'fail', LOG_DEBUG );
        $self->add_c_auth_header(
                $self->format_header_entry( 'x-ptr', 'fail' ) . q{ }
              . $self->format_header_entry( 'x-ptr-helo',   $helo_name ) . q{ }
              . $self->format_header_entry( 'x-ptr-lookup', $domain ) );
    }
}

1;
