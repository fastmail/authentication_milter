package Mail::Milter::Authentication::Handler::LocalIP;
use 5.20.0;
use strict;
use warnings;
use Mail::Milter::Authentication::Pragmas;
# ABSTRACT: Handler class for Local IP Connections
# VERSION
use base 'Mail::Milter::Authentication::Handler';

sub default_config {
    return {};
}

sub grafana_rows {
    my ( $self ) = @_;
    my @rows;
    push @rows, $self->get_json( 'LocalIP_metrics' );
    return \@rows;
}

sub is_local_ip_address {
    my ( $self, $ip ) = @_;
    my $ip_address = $ip->short();
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

sub register_metrics {
    return {
        'localip_connect_total' => 'The number of connections from a local IP',
    };
}

sub connect_callback {
    my ( $self, $hostname, $ip ) = @_;
    $self->{'is_local_ip_address'} = 0;
    if ( $self->is_local_ip_address($ip) ) {
        $self->dbgout( 'LocalIP', 'pass', LOG_DEBUG );
        my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'x-local-ip' )->safe_set_value( 'pass' );
        $self->add_c_auth_header( $header );
        $self->{'is_local_ip_address'} = 1;
        $self->metric_count( 'localip_connect_total' );
    }
}

sub close_callback {
    my ( $self ) = @_;
    delete $self->{'is_local_ip_address'};
}

1;

__END__

=head1 DESCRIPTION

Detect a Local IP address and act accordingly.

=head1 CONFIGURATION

No configuration options exist for this handler.

