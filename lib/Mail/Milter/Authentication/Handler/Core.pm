package Mail::Milter::Authentication::Handler::Core;

use strict;
use warnings;

our $VERSION = 0.3;

use base 'Mail::Milter::Authentication::Handler::Generic';

use Socket;
use Sys::Syslog qw{:standard :macros};

sub connect_callback {
    my ( $self, $hostname, $sockaddr_in ) = @_;
    my $priv = $self->{'ctx'}->getpriv();
    eval {
        my ( $port, $iaddr, $ip_address );
        # Process the connecting IP Address
        my $ip_length = length( $sockaddr_in );
        if ( $ip_length eq 16 ) {
            ( $port, $iaddr ) = sockaddr_in($sockaddr_in);
            $ip_address = inet_ntoa($iaddr);
        }
        elsif ( $ip_length eq 28 ) {
            ( $port, $iaddr ) = sockaddr_in6($sockaddr_in);
            $ip_address = Socket::inet_ntop(AF_INET6, $iaddr);
        }
        else {
            ## TODO something better here - this should never happen
            $self->log_error( 'Unknown IP address format');
            $ip_address = q{};
        }
        $priv->{'core.ip_address'} = $ip_address;
        $self->dbgout( 'ConnectFrom', $ip_address, LOG_DEBUG );
    }
}

sub helo_callback {
    my ( $self, $helo_host ) = @_;
    my $priv = $self->{'ctx'}->getpriv();
    $priv->{'core.helo_name'} = $helo_host;
}

sub envfrom_callback {
    my ( $self, $env_from ) = @_;
    my $priv = $self->{'ctx'}->getpriv();

    # Reset private data for this MAIL transaction
    delete $priv->{'core.mail_from'};
    delete $priv->{'core.auth_headers'};
    delete $priv->{'core.pre_headers'};
    delete $priv->{'core.add_headers'};

    $priv->{'core.mail_from'} = $env_from || q{};
    $self->dbgout( 'EnvelopeFrom', $env_from, LOG_DEBUG );
}

sub envrcpt_callback {
    my ( $self, $env_to ) = @_;
    $self->dbgout( 'EnvelopeTo', $env_to, LOG_DEBUG );
}

sub header_callback {
    # On Each Header
    my ( $self, $header, $value ) = @_;
    my $priv = $self->{'ctx'}->getpriv();
    $self->dbgout( 'Header', $header . ': ' . $value, LOG_DEBUG );
}

1;
