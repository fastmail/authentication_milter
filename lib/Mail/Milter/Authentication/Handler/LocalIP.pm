package Mail::Milter::Authentication::Handler::LocalIP;
use strict;
use warnings;
use base 'Mail::Milter::Authentication::Handler';
use version; our $VERSION = version->declare('v0.1.1');

use Sys::Syslog qw{:standard :macros};

sub is_local_ip_address {
    my ( $self, $ip ) = @_;
    my $ip_address = $ip->ip();
    if ( ! $ip ) {
        $self->dbgout( 'IPAddress', "Address $ip_address detected as invalid", LOG_DEBUG );
        return 0; 
    }
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
    my ( $self, $hostname, $ip ) = @_;
    $self->{'is_local_ip_address'} = 0;
    if ( $self->is_local_ip_address($ip) ) {
        $self->dbgout( 'LocalIP', 'pass', LOG_DEBUG );
        $self->add_c_auth_header('x-local-ip=pass');
        $self->{'is_local_ip_address'} = 1;
    }
    return;
}

sub close_callback {
    my ( $self ) = @_;
    delete $self->{'is_local_ip_address'};
    return;
}

1;

__END__

=head1 NAME

  Authentication Milter - LocalIP Module

=head1 DESCRIPTION

Detect a Local IP address and act accordingly.

=head1 CONFIGURATION

No configuration options exist for this handler.

=head1 SYNOPSIS

=head1 AUTHORS

Marc Bradshaw E<lt>marc@marcbradshaw.netE<gt>

=head1 COPYRIGHT

Copyright 2015

This library is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.


