package Mail::Milter::Authentication::Handler::Core;

$VERSION = 0.2;

use strict;
use warnings;

use Mail::Milter::Authentication::Config qw{ get_config };
use Mail::Milter::Authentication::Util;

use Socket;
use Sys::Syslog qw{:standard :macros};

my $CONFIG = get_config();

sub connect_callback {
    my ( $ctx, $hostname, $sockaddr_in ) = @_;
    my $priv = $ctx->getpriv();
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
            log_error( $ctx, 'Unknown IP address format');
            $ip_address = q{};
        }
        $priv->{'core.ip_address'} = $ip_address;
        dbgout( $ctx, 'ConnectFrom', $ip_address, LOG_DEBUG );
    }
}

sub helo_callback {
    my ( $ctx, $helo_host ) = @_;
    my $priv = $ctx->getpriv();
    $priv->{'core.helo_name'} = $helo_host;
}

sub envfrom_callback {
    my ( $ctx, $env_from ) = @_;
    my $priv = $ctx->getpriv();

    # Reset private data for this MAIL transaction
    delete $priv->{'core.mail_from'};
    delete $priv->{'core.auth_headers'};
    delete $priv->{'core.pre_headers'};
    delete $priv->{'core.add_headers'};

    $priv->{'core.mail_from'} = $env_from || q{};
    dbgout( $ctx, 'EnvelopeFrom', $env_from, LOG_DEBUG );
}

sub envrcpt_callback {
    my ( $ctx, $env_to ) = @_;
    dbgout( $ctx, 'EnvelopeTo', $env_to, LOG_DEBUG );
}

sub header_callback {
    # On Each Header
    my ( $ctx, $header, $value ) = @_;
    my $priv = $ctx->getpriv();
    dbgout( $ctx, 'Header', $header . ': ' . $value, LOG_DEBUG );
}

1;
