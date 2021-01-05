package Mail::Milter::Authentication::Handler::TrustedIP;
use 5.20.0;
use strict;
use warnings;
use Mail::Milter::Authentication::Pragmas;
# ABSTRACT: Handler class for Trusted IP addresses
# VERSION
use base 'Mail::Milter::Authentication::Handler';
use Net::IP;

sub default_config {
    return {
        'trusted_ip_list' => [],
    };
}

sub grafana_rows {
    my ( $self ) = @_;
    my @rows;
    push @rows, $self->get_json( 'TrustedIP_metrics' );
    return \@rows;
}

sub is_trusted_ip_address {
    my ( $self, $ip_obj ) = @_;
    my $config = $self->handler_config();
    return 0 if not exists( $config->{'trusted_ip_list'} );
    my $trusted = 0;
    foreach my $trusted_ip ( @{ $config->{'trusted_ip_list'} } ) {
        my $trusted_obj = Net::IP->new($trusted_ip);
        if ( !$trusted_obj ) {
            $self->log_error( 'TrustedIP: Could not parse Trusted IP '.$trusted_ip );
        }
        else {
            my $is_overlap = $ip_obj->overlaps($trusted_obj) || 0;
            if (
                   $is_overlap == $IP_A_IN_B_OVERLAP
                || $is_overlap == $IP_B_IN_A_OVERLAP     # Should never happen
                || $is_overlap == $IP_PARTIAL_OVERLAP    # Should never happen
                || $is_overlap == $IP_IDENTICAL
              )
            {
                $trusted = 1;
            }
        }
    }
    return $trusted;
}

sub register_metrics {
    return {
        'trustedip_connect_total' => 'The number of connections from a trusted IP',
    };
}

sub connect_callback {
    my ( $self, $hostname, $ip ) = @_;
    $self->{'is_trusted_ip_address'} = 0;
    if ( $self->is_trusted_ip_address($ip) ) {
        $self->dbgout( 'TrustedIP', 'pass', LOG_DEBUG );
        my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'x-trusted-ip' )->safe_set_value( 'pass' );
        $self->add_c_auth_header( $header );
        $self->{'is_trusted_ip_address'} = 1;
        $self->metric_count( 'trustedip_connect_total' );
    }
}

sub close_callback {
    my ( $self ) = @_;
    delete $self->{'is_trusted_ip_address'};
}

1;

__END__

=head1 DESCRIPTION

Detect a trusted IP address and act accordingly.

=head1 CONFIGURATION

        "TrustedIP" : {                                 | Config the the TruetedIP Module
                                                        | Check for TrustedIP Addresses
            "trusted_ip_list" : [                       | List of IP Addresses considered to be trusted
                "100.200.100.2",                        | CIDR Ranges are valid syntax
                "2001:44c2:3881:aa00::/56",
                "2001:44b8:3021:123:dead:beef:abcd:1234"
            ],
        },

