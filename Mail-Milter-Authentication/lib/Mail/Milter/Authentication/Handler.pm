package Mail::Milter::Authentication::Handler;

$VERSION = 0.1;

use strict;
use warnings;

use Mail::Milter::Authentication;
use Mail::Milter::Authentication::Util;
use Mail::Milter::Authentication::Config qw{ get_config };

use Mail::Milter::Authentication::Auth;
use Mail::Milter::Authentication::DKIM;
use Mail::Milter::Authentication::DMARC;
use Mail::Milter::Authentication::IPRev;
use Mail::Milter::Authentication::LocalIP;
use Mail::Milter::Authentication::PTR;
use Mail::Milter::Authentication::Sanitize;
use Mail::Milter::Authentication::SPF;
use Mail::Milter::Authentication::TrustedIP;

use Sys::Syslog qw{:standard :macros};
use Sendmail::PMilter qw { :all };
use Socket;

my $CONFIG = get_config();

sub connect_callback {
    # On Connect
    my ( $ctx, $hostname, $sockaddr_in ) = @_;
    dbgout( $ctx, 'CALLBACK', 'Connect', LOG_DEBUG );
    my $priv = {};
    $ctx->setpriv($priv);
    
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
        $priv->{'ip_address'} = $ip_address;
        dbgout( $ctx, 'ConnectFrom', $ip_address, LOG_DEBUG );

        Mail::Milter::Authentication::Auth::connect_callback( $ctx, $hostname, $sockaddr_in );
        Mail::Milter::Authentication::TrustedIP::connect_callback( $ctx, $hostname, $sockaddr_in );
        Mail::Milter::Authentication::LocalIP::connect_callback( $ctx, $hostname, $sockaddr_in );
        Mail::Milter::Authentication::IPRev::connect_callback( $ctx, $hostname, $sockaddr_in );

    };
    if ( my $error = $@ ) {
        log_error( $ctx, 'Connect callback error ' . $error );
    }

    return SMFIS_CONTINUE;
}

sub helo_callback {
    # On HELO
    my ( $ctx, $helo_host ) = @_;
    dbgout( $ctx, 'CALLBACK', 'Helo', LOG_DEBUG );
    my $priv = $ctx->getpriv();
    $helo_host = q{} if not $helo_host;
    eval {
        if ( ! exists( $priv->{'helo_name'} ) ) {
            # Ignore any further HELOs from this connection
            $priv->{'helo_name'} = $helo_host;
            dbgout( $ctx, 'HeloFrom', $helo_host, LOG_DEBUG );
            
            Mail::Milter::Authentication::PTR::helo_callback( $ctx, $helo_host );

        }
    };
    if ( my $error = $@ ) {
        log_error( $ctx, 'HELO callback error ' . $error );
    }

    return SMFIS_CONTINUE;
}

sub envfrom_callback {
    # On MAILFROM
    #...
    my ( $ctx, $env_from ) = @_;
    dbgout( $ctx, 'CALLBACK', 'EnvFrom', LOG_DEBUG );
    my $priv = $ctx->getpriv();

    # Reset private data for this MAIL transaction
    delete $priv->{'auth_headers'};
    delete $priv->{'mail_from'};
    delete $priv->{'from_header'}; # DMARC
    delete $priv->{'auth_result_header_index'};
    delete $priv->{'remove_auth_headers'}; # Sanitize
    delete $priv->{'auth_headers'};
    delete $priv->{'pre_headers'};
    delete $priv->{'add_headers'};

    $env_from = q{} if not $env_from;

    eval {
        $priv->{'mail_from'} = $env_from || q{};
        dbgout( $ctx, 'EnvelopeFrom', $env_from, LOG_DEBUG );

        Mail::Milter::Authentication::DMARC::envfrom_callback( $ctx, $env_from ); # MUST go before SPF
        Mail::Milter::Authentication::Auth::envfrom_callback( $ctx, $env_from );
        Mail::Milter::Authentication::SPF::envfrom_callback( $ctx, $env_from );
        Mail::Milter::Authentication::DKIM::envfrom_callback( $ctx, $env_from );

    };
    if ( my $error = $@ ) {
        log_error( $ctx, 'Env From callback error ' . $error );
    }

    return SMFIS_CONTINUE;
}

sub envrcpt_callback {
    # On RCPTTO
    #...
    my ( $ctx, $env_to ) = @_;
    dbgout( $ctx, 'CALLBACK', 'EnvRcpt', LOG_DEBUG );
    $env_to = q{} if not $env_to;
    dbgout( $ctx, 'EnvelopeTo', $env_to, LOG_DEBUG );
    eval {
        Mail::Milter::Authentication::DMARC::envrcpt_callback( $ctx, $env_to );
    };
    if ( my $error = $@ ) {
        log_error( $ctx, 'Rcpt To callback error ' . $error );
    }

    return SMFIS_CONTINUE;
}

sub header_callback {
    # On Each Header
    my ( $ctx, $header, $value ) = @_;
    dbgout( $ctx, 'CALLBACK', 'Header', LOG_DEBUG );
    my $priv = $ctx->getpriv();
    $value = q{} if not $value;
    eval {
        dbgout( $ctx, 'Header', $header . ': ' . $value, LOG_DEBUG );

        Mail::Milter::Authentication::Sanitize::header_callback( $ctx, $header, $value );
        Mail::Milter::Authentication::DKIM::header_callback( $ctx, $header, $value );
        Mail::Milter::Authentication::DMARC::header_callback( $ctx, $header, $value );

    };
    if ( my $error = $@ ) {
        log_error( $ctx, 'Header callback error ' . $error );
    }
    return SMFIS_CONTINUE;
}

sub eoh_callback {
    # On End of headers
    my ($ctx) = @_;
    dbgout( $ctx, 'CALLBACK', 'EOH', LOG_DEBUG );

    eval {
        Mail::Milter::Authentication::DKIM::eoh_callback( $ctx );
        Mail::Milter::Authentication::SPF::eoh_callback( $ctx );
    };
    if ( my $error = $@ ) {
        log_error( $ctx, 'EOH callback error ' . $error );
    }
    dbgoutwrite($ctx);
    return SMFIS_CONTINUE;
}

sub body_callback {
    # On each body chunk
    my ( $ctx, $body_chunk, $len ) = @_;
    dbgout( $ctx, 'CALLBACK', 'Body', LOG_DEBUG );

    eval {
        Mail::Milter::Authentication::DKIM::body_callback( $ctx, $body_chunk, $len );
    };
    if ( my $error = $@ ) {
        log_error( $ctx, 'Body callback error ' . $error );
    }
    dbgoutwrite($ctx);
    return SMFIS_CONTINUE;
}

sub eom_callback {
    # On End of Message
    my ($ctx) = @_;
    dbgout( $ctx, 'CALLBACK', 'EOM', LOG_DEBUG );

    eval {
        Mail::Milter::Authentication::DKIM::eom_callback( $ctx );
        Mail::Milter::Authentication::DMARC::eom_callback( $ctx );
        Mail::Milter::Authentication::Sanitize::eom_callback( $ctx );
    };
    if ( my $error = $@ ) {
        log_error( $ctx, 'EOM callback error ' . $error );
    }
    add_headers($ctx);
    dbgoutwrite($ctx);
    return SMFIS_ACCEPT;
}

sub abort_callback {
    # On any out of our control abort
    my ($ctx) = @_;
    dbgout( $ctx, 'CALLBACK', 'Abort', LOG_DEBUG );
    dbgoutwrite($ctx);
    return SMFIS_CONTINUE;
}

sub close_callback {
    # On end of connection
    my ($ctx) = @_;
    dbgout( $ctx, 'CALLBACK', 'Close', LOG_DEBUG );
    dbgoutwrite($ctx);
    $ctx->setpriv(undef);
    return SMFIS_CONTINUE;
}

1;
