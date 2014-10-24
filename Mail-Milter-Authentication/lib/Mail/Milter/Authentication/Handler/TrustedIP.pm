package Mail::Milter::Authentication::Handler::TrustedIP;

$VERSION = 0.1;

use strict;
use warnings;

use Mail::Milter::Authentication::Config qw{ get_config };
use Mail::Milter::Authentication::Util;

use Net::IP;
use Sys::Syslog qw{:standard :macros};

my $CONFIG = get_config();

sub is_trusted_ip_address {
    my ( $ctx, $ip_address ) = @_;
    return 0 if not exists ( $CONFIG->{'trusted_ip_list'} );
    my $trusted = 0;
    my $ip_obj = new Net::IP( $ip_address );
    foreach my $trusted_ip ( @{ $CONFIG->{'trusted_ip_list'} } ) {
        my $trusted_obj = new Net::IP( $trusted_ip );
        my $is_overlap = $ip_obj->overlaps( $trusted_obj ) || 0;
        if ( $is_overlap == $IP_A_IN_B_OVERLAP
          || $is_overlap == $IP_B_IN_A_OVERLAP # Should never happen
          || $is_overlap == $IP_PARTIAL_OVERLAP # Should never happen
          || $is_overlap == $IP_IDENTICAL
        ) {
            $trusted = 1;
        }
    }
    return $trusted;;
}

sub connect_callback {
    my ( $ctx, $hostname, $sockaddr_in ) = @_;
    my $priv = $ctx->getpriv();
    $priv->{ 'is_trusted_ip_address' } = 0;
    return if ( !$CONFIG->{'check_trusted_ip'} );
    my $ip_address = $priv->{'core.ip_address'};
    if ( is_trusted_ip_address( $ctx, $ip_address ) ) {
        dbgout( $ctx, 'TrustedIP', 'pass', LOG_DEBUG );
        add_c_auth_header( $ctx, 'x-trusted-ip=pass' );
        $priv->{ 'is_trusted_ip_address' } = 1;
    }
}

1;
