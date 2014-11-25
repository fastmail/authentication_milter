package Mail::Milter::Authentication::Handler::TrustedIP;

use strict;
use warnings;

our $VERSION = 0.3;

use base 'Mail::Milter::Authentication::Handler::Generic';

use Mail::Milter::Authentication::Config qw{ get_config };
use Mail::Milter::Authentication::Util;

use Net::IP;
use Sys::Syslog qw{:standard :macros};

sub is_trusted_ip_address {
    my ( $self, $ip_address ) = @_;
    my $CONFIG = get_config();
    return 0 if not exists ( $CONFIG->{'trusted_ip_list'} );
    my $trusted = 0;
    my $ip_obj = Net::IP->new( $ip_address );
    foreach my $trusted_ip ( @{ $CONFIG->{'trusted_ip_list'} } ) {
        my $trusted_obj = Net::IP->new( $trusted_ip );
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
    my ( $self, $hostname, $sockaddr_in ) = @_;
    my $CONFIG = get_config();
    my $priv = $self->{'ctx'}->getpriv();
    $priv->{ 'is_trusted_ip_address' } = 0;
    return if ( !$CONFIG->{'check_trusted_ip'} );
    my $ip_address = $priv->{'core.ip_address'};
    if ( $self->is_trusted_ip_address( $ip_address ) ) {
        dbgout( $self->{'ctx'}, 'TrustedIP', 'pass', LOG_DEBUG );
        add_c_auth_header( $self->{'ctx'}, 'x-trusted-ip=pass' );
        $priv->{ 'is_trusted_ip_address' } = 1;
    }
}

1;
