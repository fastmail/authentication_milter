package Mail::Milter::Authentication::Handler::LocalIP;

$VERSION = 0.3;

use strict;
use warnings;

use Mail::Milter::Authentication::Config qw{ get_config };
use Mail::Milter::Authentication::Util;

use Net::IP;
use Sys::Syslog qw{:standard :macros};

sub is_local_ip_address {
    my ( $ctx, $ip_address ) = @_;
    my $ip = Net::IP->new( $ip_address );
    my $ip_type = $ip->iptype();
    my $type_map = {
        'PRIVATE'              => 1,
        'SHARED'               => 1,
        'LOOPBACK'             => 1,
        'LINK-LOCAL'           => 1,
        'RESERVED'             => 1,
        'TEST-NET'             => 0,
        '6TO4-RELAY'           => 0,
        'MULTICAST'            => 0,
        'BROADCAST'            => 0,
        'UNSPECIFIED'          => 0,
        'IPV4MAP'              => 0,
        'DISCARD'              => 0,
        'GLOBAL-UNICAST'       => 0,
        'TEREDO'               => 0,
        'BMWG'                 => 0,
        'DOCUMENTATION'        => 0,
        'ORCHID'               => 0,
        '6TO4'                 => 0,
        'UNIQUE-LOCAL-UNICAST' => 1,
        'LINK-LOCAL-UNICAST'   => 1,
    };
    dbgout( $ctx, 'IPAddress', "Address $ip_address detected as type $ip_type", LOG_DEBUG );
    return $type_map->{ $ip_type } || 0;
}

sub connect_callback {
    my ( $ctx, $hostname, $sockaddr_in ) = @_;
    my $CONFIG = get_config();
    my $priv = $ctx->getpriv();
    $priv->{ 'is_local_ip_address' } = 0;
    return if ( !$CONFIG->{'check_local_ip'} );
    my $ip_address = $priv->{'core.ip_address'};
    if ( is_local_ip_address( $ctx, $ip_address ) ) {
        dbgout( $ctx, 'LocalIP', 'pass', LOG_DEBUG );
        add_c_auth_header( $ctx, 'x-local-ip=pass' );
        $priv->{ 'is_local_ip_address' } = 1;
    }
}

1;
