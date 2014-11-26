package Mail::Milter::Authentication::Handler::LocalIP;

use strict;
use warnings;

our $VERSION = 0.4;

use base 'Mail::Milter::Authentication::Handler::Generic';

use Net::IP;
use Sys::Syslog qw{:standard :macros};

sub is_local_ip_address {
    my ( $self, $ip_address ) = @_;
    my $ip       = Net::IP->new($ip_address);
    my $ip_type  = $ip->iptype();
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
    $self->dbgout( 'IPAddress', "Address $ip_address detected as type $ip_type", LOG_DEBUG );
    return $type_map->{ $ip_type } || 0;
}

sub connect_callback {
    my ( $self, $hostname, $sockaddr_in ) = @_;
    my $CONFIG = $self->config();
    $self->{'is_local_ip_address'} = 0;
    return if ( !$CONFIG->{'check_local_ip'} );
    my $ip_address = $self->ip_address();
    if ( $self->is_local_ip_address($ip_address) ) {
        $self->dbgout( 'LocalIP', 'pass', LOG_DEBUG );
        $self->add_c_auth_header('x-local-ip=pass');
        $self->{'is_local_ip_address'} = 1;
    }
}

1;
