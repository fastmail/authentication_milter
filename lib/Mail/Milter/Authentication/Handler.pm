package Mail::Milter::Authentication::Handler;

use strict;
use warnings;

our $VERSION = 0.3;

use Mail::Milter::Authentication;
use Mail::Milter::Authentication::Util;
use Mail::Milter::Authentication::Config qw{ get_config };

use Mail::Milter::Authentication::Handler::Auth;
use Mail::Milter::Authentication::Handler::Core;
use Mail::Milter::Authentication::Handler::DKIM;
use Mail::Milter::Authentication::Handler::DMARC;
use Mail::Milter::Authentication::Handler::IPRev;
use Mail::Milter::Authentication::Handler::LocalIP;
use Mail::Milter::Authentication::Handler::PTR;
use Mail::Milter::Authentication::Handler::Sanitize;
use Mail::Milter::Authentication::Handler::SenderID;
use Mail::Milter::Authentication::Handler::SPF;
use Mail::Milter::Authentication::Handler::TrustedIP;

use Sys::Syslog qw{:standard :macros};
use Sendmail::PMilter qw { :all };

sub connect_callback {
    # On Connect
    my ( $ctx, $hostname, $sockaddr_in ) = @_;
    dbgout( $ctx, 'CALLBACK', 'Connect', LOG_DEBUG );
    my $priv = {};
    $ctx->setpriv($priv);
    eval {
        Mail::Milter::Authentication::Handler::Core::connect_callback( $ctx, $hostname, $sockaddr_in );
        Mail::Milter::Authentication::Handler::Auth::connect_callback( $ctx, $hostname, $sockaddr_in );
        Mail::Milter::Authentication::Handler::TrustedIP::connect_callback( $ctx, $hostname, $sockaddr_in );
        Mail::Milter::Authentication::Handler::LocalIP::connect_callback( $ctx, $hostname, $sockaddr_in );
        Mail::Milter::Authentication::Handler::IPRev::connect_callback( $ctx, $hostname, $sockaddr_in );
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
        # Take only the first HELO from a connection
        if ( ! exists( $priv->{'core.helo_name'} ) ) {
            Mail::Milter::Authentication::Handler::Core::helo_callback( $ctx, $helo_host );
            Mail::Milter::Authentication::Handler::PTR::helo_callback( $ctx, $helo_host );
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
    $env_from = q{} if not $env_from;
    eval {
        Mail::Milter::Authentication::Handler::Core::envfrom_callback( $ctx, $env_from );
        Mail::Milter::Authentication::Handler::Sanitize::envfrom_callback( $ctx, $env_from );
        Mail::Milter::Authentication::Handler::Auth::envfrom_callback( $ctx, $env_from );
        Mail::Milter::Authentication::Handler::DMARC::envfrom_callback( $ctx, $env_from ); # DMARC MUST go before SPF
        Mail::Milter::Authentication::Handler::SPF::envfrom_callback( $ctx, $env_from );
        Mail::Milter::Authentication::Handler::DKIM::envfrom_callback( $ctx, $env_from );
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
    eval {
        Mail::Milter::Authentication::Handler::Core::envrcpt_callback( $ctx, $env_to );
        Mail::Milter::Authentication::Handler::DMARC::envrcpt_callback( $ctx, $env_to );
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
        Mail::Milter::Authentication::Handler::Core::header_callback( $ctx, $header, $value );
        Mail::Milter::Authentication::Handler::Sanitize::header_callback( $ctx, $header, $value );
        Mail::Milter::Authentication::Handler::DKIM::header_callback( $ctx, $header, $value );
        Mail::Milter::Authentication::Handler::DMARC::header_callback( $ctx, $header, $value );
        Mail::Milter::Authentication::Handler::SenderID::header_callback( $ctx, $header, $value );
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
        Mail::Milter::Authentication::Handler::DKIM::eoh_callback( $ctx );
        Mail::Milter::Authentication::Handler::SenderID::eoh_callback( $ctx );
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
        Mail::Milter::Authentication::Handler::DKIM::body_callback( $ctx, $body_chunk, $len );
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
        Mail::Milter::Authentication::Handler::DKIM::eom_callback( $ctx );
        Mail::Milter::Authentication::Handler::DMARC::eom_callback( $ctx );
        Mail::Milter::Authentication::Handler::Sanitize::eom_callback( $ctx );
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
    return SMFIS_CONTINUE;
}

1;
