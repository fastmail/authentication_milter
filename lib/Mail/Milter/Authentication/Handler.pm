package Mail::Milter::Authentication::Handler;

use strict;
use warnings;

our $VERSION = 0.3;

use Mail::Milter::Authentication;
use Mail::Milter::Authentication::Config qw{ get_config };
use Mail::Milter::Authentication::Util;

use Mail::Milter::Authentication::Handler::Generic;
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
    my $priv = {};
    $priv->{'handler'}->{'generic'} = Mail::Milter::Authentication::Handler::Generic->new( $ctx );
    $ctx->setpriv($priv);
    $priv->{'handler'}->{'generic'}->dbgout( 'CALLBACK', 'Connect', LOG_DEBUG );
    eval {
        $priv->{'handler'}->{'auth'}      = Mail::Milter::Authentication::Handler::Auth->new( $ctx );
        $priv->{'handler'}->{'core'}      = Mail::Milter::Authentication::Handler::Core->new( $ctx );
        $priv->{'handler'}->{'dkim'}      = Mail::Milter::Authentication::Handler::DKIM->new( $ctx );
        $priv->{'handler'}->{'dmarc'}     = Mail::Milter::Authentication::Handler::DMARC->new( $ctx );
        $priv->{'handler'}->{'iprev'}     = Mail::Milter::Authentication::Handler::IPRev->new( $ctx );
        $priv->{'handler'}->{'localip'}   = Mail::Milter::Authentication::Handler::LocalIP->new( $ctx );
        $priv->{'handler'}->{'ptr'}       = Mail::Milter::Authentication::Handler::PTR->new( $ctx );
        $priv->{'handler'}->{'sanitize'}  = Mail::Milter::Authentication::Handler::Sanitize->new( $ctx );
        $priv->{'handler'}->{'senderid'}  = Mail::Milter::Authentication::Handler::SenderID->new( $ctx );
        $priv->{'handler'}->{'spf'}       = Mail::Milter::Authentication::Handler::SPF->new( $ctx );
        $priv->{'handler'}->{'trustedip'} = Mail::Milter::Authentication::Handler::TrustedIP->new( $ctx );

        foreach my $handler (qw{ core auth trustedip localip iprev }) { 
            $priv->{'handler'}->{$handler}->connect_callback( $hostname, $sockaddr_in );
        }
    };
    if ( my $error = $@ ) {
        $priv->{'handler'}->{'generic'}->log_error( 'Connect callback error ' . $error );
    }
    return SMFIS_CONTINUE;
}

sub helo_callback {
    # On HELO
    my ( $ctx, $helo_host ) = @_;
    my $priv = $ctx->getpriv();
    $priv->{'handler'}->{'generic'}->dbgout( 'CALLBACK', 'Helo', LOG_DEBUG );
    $helo_host = q{} if not $helo_host;
    eval {
        # Take only the first HELO from a connection
        if ( ! exists( $priv->{'core.helo_name'} ) ) {
            foreach my $handler (qw{ core ptr }) { 
                $priv->{'handler'}->{$handler}->helo_callback( $helo_host );
           }
        }
    };
    if ( my $error = $@ ) {
        $priv->{'handler'}->{'generic'}->log_error( 'HELO callback error ' . $error );
    }
    return SMFIS_CONTINUE;
}

sub envfrom_callback {
    # On MAILFROM
    #...
    my ( $ctx, $env_from ) = @_;
    my $priv = $ctx->getpriv();
    $priv->{'handler'}->{'generic'}->dbgout( 'CALLBACK', 'EnvFrom', LOG_DEBUG );
    $env_from = q{} if not $env_from;
    eval {
        foreach my $handler (qw{ core sanitize auth dmarc spf dkim }) { 
            $priv->{'handler'}->{$handler}->envfrom_callback( $env_from );
        }
    };
    if ( my $error = $@ ) {
        $priv->{'handler'}->{'generic'}->log_error( 'Env From callback error ' . $error );
    }
    return SMFIS_CONTINUE;
}

sub envrcpt_callback {
    # On RCPTTO
    #...
    my ( $ctx, $env_to ) = @_;
    my $priv = $ctx->getpriv();
    $priv->{'handler'}->{'generic'}->dbgout( 'CALLBACK', 'EnvRcpt', LOG_DEBUG );
    $env_to = q{} if not $env_to;
    eval {
        foreach my $handler (qw{ core dmarc }) { 
            $priv->{'handler'}->{$handler}->envrcpt_callback( $env_to );
        }
    };
    if ( my $error = $@ ) {
        $priv->{'handler'}->{'generic'}->log_error( 'Rcpt To callback error ' . $error );
    }
    return SMFIS_CONTINUE;
}

sub header_callback {
    # On Each Header
    my ( $ctx, $header, $value ) = @_;
    my $priv = $ctx->getpriv();
    $priv->{'handler'}->{'generic'}->dbgout( 'CALLBACK', 'Header', LOG_DEBUG );
    $value = q{} if not $value;
    eval {
        foreach my $handler (qw{ core sanitize dkim dmarc senderid }) { 
            $priv->{'handler'}->{$handler}->header_callback( $header, $value );
        }
    };
    if ( my $error = $@ ) {
        $priv->{'handler'}->{'generic'}->log_error( 'Header callback error ' . $error );
    }
    return SMFIS_CONTINUE;
}

sub eoh_callback {
    # On End of headers
    my ($ctx) = @_;
    my $priv = $ctx->getpriv();
    $priv->{'handler'}->{'generic'}->dbgout( 'CALLBACK', 'EOH', LOG_DEBUG );
    eval {
        foreach my $handler (qw{ dkim senderid }) { 
            $priv->{'handler'}->{$handler}->eoh_callback();
        }
    };
    if ( my $error = $@ ) {
        $priv->{'handler'}->{'generic'}->log_error( 'EOH callback error ' . $error );
    }
    dbgoutwrite($ctx);
    return SMFIS_CONTINUE;
}

sub body_callback {
    # On each body chunk
    my ( $ctx, $body_chunk, $len ) = @_;
    my $priv = $ctx->getpriv();
    $priv->{'handler'}->{'generic'}->dbgout( 'CALLBACK', 'Body', LOG_DEBUG );
    eval {
        $priv->{'handler'}->{'dkim'}->body_callback( $body_chunk, $len );
    };
    if ( my $error = $@ ) {
        $priv->{'handler'}->{'generic'}->log_error( 'Body callback error ' . $error );
    }
    dbgoutwrite($ctx);
    return SMFIS_CONTINUE;
}

sub eom_callback {
    # On End of Message
    my ($ctx) = @_;
    my $priv = $ctx->getpriv();
    $priv->{'handler'}->{'generic'}->dbgout( 'CALLBACK', 'EOM', LOG_DEBUG );
    eval {
        foreach my $handler (qw{ dkim dmarc sanitize }) { 
            $priv->{'handler'}->{$handler}->eom_callback();
        }
    };
    if ( my $error = $@ ) {
        $priv->{'handler'}->{'generic'}->log_error( 'EOM callback error ' . $error );
    }
    add_headers($ctx);
    dbgoutwrite($ctx);
    return SMFIS_ACCEPT;
}

sub abort_callback {
    # On any out of our control abort
    my ($ctx) = @_;
    my $priv = $ctx->getpriv();
    $priv->{'handler'}->{'generic'}->dbgout( 'CALLBACK', 'Abort', LOG_DEBUG );
    dbgoutwrite($ctx);
    return SMFIS_CONTINUE;
}

sub close_callback {
    # On end of connection
    my ($ctx) = @_;
    my $priv = $ctx->getpriv();
    $priv->{'handler'}->{'generic'}->dbgout( 'CALLBACK', 'Close', LOG_DEBUG );
    dbgoutwrite($ctx);
    return SMFIS_CONTINUE;
}

1;
