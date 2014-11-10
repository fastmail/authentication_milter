package Mail::Milter::Authentication::Handler::PTR;

$VERSION = 0.2;

use strict;
use warnings;

use Mail::Milter::Authentication::Config qw{ get_config };
use Mail::Milter::Authentication::Util;

use Sys::Syslog qw{:standard :macros};

my $CONFIG = get_config();

sub helo_callback {
    # On HELO
    my ( $ctx, $helo_host ) = @_;
    my $priv = $ctx->getpriv();
    return if ( !$CONFIG->{'check_ptr'} );
    return if ( $priv->{'is_local_ip_address'} );
    return if ( $priv->{'is_trusted_ip_address'} );
    return if ( $priv->{'is_authenticated'} );

    my $domain =
      exists( $priv->{'iprev.verified_ptr'} ) ? $priv->{'iprev.verified_ptr'} : q{};
    my $helo_name = $priv->{'core.helo_name'};

    if ( lc $domain eq lc $helo_name ) {
        dbgout( $ctx, 'PTRMatch', 'pass', LOG_DEBUG );
        add_c_auth_header( $ctx,
                format_header_entry( 'x-ptr', 'pass' ) . q{ }
              . format_header_entry( 'x-ptr-helo',   $helo_name ) . q{ }
              . format_header_entry( 'x-ptr-lookup', $domain ) );
    }
    else {
        dbgout( $ctx, 'PTRMatch', 'fail', LOG_DEBUG );
        add_c_auth_header( $ctx,
                format_header_entry( 'x-ptr', 'fail' ) . q{ }
              . format_header_entry( 'x-ptr-helo',   $helo_name ) . q{ }
              . format_header_entry( 'x-ptr-lookup', $domain ) );
    }
}

1;
