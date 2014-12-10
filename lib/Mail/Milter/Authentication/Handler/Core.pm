package Mail::Milter::Authentication::Handler::Core;

use strict;
use warnings;

our $VERSION = 0.5;

use base 'Mail::Milter::Authentication::Handler::Generic';

use Socket;
use MIME::Base64;
use Sys::Syslog qw{:standard :macros};

sub connect_callback {
    my ( $self, $hostname, $sockaddr_in ) = @_;
    eval {
        my ( $port, $iaddr, $ip_address );

        # Process the connecting IP Address
        my $family = sockaddr_family($sockaddr_in);
        if ( $family == AF_INET ) {
            ( $port, $iaddr ) = sockaddr_in($sockaddr_in);
            $ip_address = inet_ntoa($iaddr);
        }
        elsif ( $family == AF_INET6 ) {
            ( $port, $iaddr ) = sockaddr_in6($sockaddr_in);
            $ip_address = Socket::inet_ntop( AF_INET6, $iaddr );
        }
        else {
            ## TODO something better here - this should never happen
            $self->log_error('Unknown IP address format - ' . encode_base64($sockaddr_in,q{}) );
            $ip_address = q{};
        }
        $self->{'ip_address'} = $ip_address;
        $self->dbgout( 'ConnectFrom', $ip_address, LOG_DEBUG );
    };
}

sub helo_callback {
    my ( $self, $helo_host ) = @_;
    $self->{'helo_name'} = $helo_host;
}

sub envfrom_callback {
    my ( $self, $env_from ) = @_;

    # Reset private data for this MAIL transaction
    delete $self->{'mail_from'};
    delete $self->{'auth_headers'};
    delete $self->{'pre_headers'};
    delete $self->{'add_headers'};

    $self->{'mail_from'} = $env_from || q{};
    $self->dbgout( 'EnvelopeFrom', $env_from, LOG_DEBUG );
}

sub envrcpt_callback {
    my ( $self, $env_to ) = @_;
    $self->dbgout( 'EnvelopeTo', $env_to, LOG_DEBUG );
}

sub header_callback {

    # On Each Header
    my ( $self, $header, $value ) = @_;
    $self->dbgout( 'Header', $header . ': ' . $value, LOG_DEBUG );
}

1;
