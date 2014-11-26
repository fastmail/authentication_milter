package Mail::Milter::Authentication::Handler;

use strict;
use warnings;

our $VERSION = 0.4;

use base 'Mail::Milter::Authentication::Handler::Generic';

use Sys::Syslog qw{:standard :macros};
use Sendmail::PMilter qw { :all };

sub connect_callback {
    # On Connect
    my ( $self, $hostname, $sockaddr_in ) = @_;
    $self->dbgout( 'CALLBACK', 'Connect', LOG_DEBUG );
    eval {
        foreach my $handler (qw{ core auth trustedip localip iprev }) { 
            $self->get_handler($handler)->connect_callback( $hostname, $sockaddr_in );
        }
    };
    if ( my $error = $@ ) {
        $self->log_error( 'Connect callback error ' . $error );
    }
    return SMFIS_CONTINUE;
}

sub helo_callback {
    # On HELO
    my ( $self, $helo_host ) = @_;
    $self->dbgout( 'CALLBACK', 'Helo', LOG_DEBUG );
    $helo_host = q{} if not $helo_host;
    eval {
        # Take only the first HELO from a connection
           
        if ( ! ( $self->helo_name() ) ) {
            foreach my $handler (qw{ core ptr }) { 
                $self->get_handler($handler)->helo_callback( $helo_host );
           }
        }
    };
    if ( my $error = $@ ) {
        $self->log_error( 'HELO callback error ' . $error );
    }
    return SMFIS_CONTINUE;
}

sub envfrom_callback {
    # On MAILFROM
    #...
    my ( $self, $env_from ) = @_;
    $self->dbgout( 'CALLBACK', 'EnvFrom', LOG_DEBUG );
    $env_from = q{} if not $env_from;
    eval {
        foreach my $handler (qw{ core sanitize auth dmarc spf dkim }) { 
            $self->get_handler($handler)->envfrom_callback( $env_from );
        }
    };
    if ( my $error = $@ ) {
        $self->log_error( 'Env From callback error ' . $error );
    }
    return SMFIS_CONTINUE;
}

sub envrcpt_callback {
    # On RCPTTO
    #...
    my ( $self, $env_to ) = @_;
    $self->dbgout( 'CALLBACK', 'EnvRcpt', LOG_DEBUG );
    $env_to = q{} if not $env_to;
    eval {
        foreach my $handler (qw{ core dmarc }) { 
            $self->get_handler($handler)->envrcpt_callback( $env_to );
        }
    };
    if ( my $error = $@ ) {
        $self->log_error( 'Rcpt To callback error ' . $error );
    }
    return SMFIS_CONTINUE;
}

sub header_callback {
    # On Each Header
    my ( $self, $header, $value ) = @_;
    $self->dbgout( 'CALLBACK', 'Header', LOG_DEBUG );
    $value = q{} if not $value;
    eval {
        foreach my $handler (qw{ core sanitize dkim dmarc senderid }) { 
            $self->get_handler($handler)->header_callback( $header, $value );
        }
    };
    if ( my $error = $@ ) {
        $self->log_error( 'Header callback error ' . $error );
    }
    return SMFIS_CONTINUE;
}

sub eoh_callback {
    # On End of headers
    my ($self) = @_;
    $self->dbgout( 'CALLBACK', 'EOH', LOG_DEBUG );
    eval {
        foreach my $handler (qw{ dkim senderid }) { 
            $self->get_handler($handler)->eoh_callback();
        }
    };
    if ( my $error = $@ ) {
        $self->log_error( 'EOH callback error ' . $error );
    }
    $self->dbgoutwrite();
    return SMFIS_CONTINUE;
}

sub body_callback {
    # On each body chunk
    my ( $self, $body_chunk, $len ) = @_;
    $self->dbgout( 'CALLBACK', 'Body', LOG_DEBUG );
    eval {
        $self->get_handler('dkim')->body_callback( $body_chunk, $len );
    };
    if ( my $error = $@ ) {
        $self->log_error( 'Body callback error ' . $error );
    }
    $self->dbgoutwrite();
    return SMFIS_CONTINUE;
}

sub eom_callback {
    # On End of Message
    my ($self) = @_;
    $self->dbgout( 'CALLBACK', 'EOM', LOG_DEBUG );
    eval {
        foreach my $handler (qw{ dkim dmarc sanitize }) { 
            $self->get_handler($handler)->eom_callback();
        }
    };
    if ( my $error = $@ ) {
        $self->log_error( 'EOM callback error ' . $error );
    }
    $self->add_headers();
    $self->dbgoutwrite();
    return SMFIS_ACCEPT;
}

sub abort_callback {
    # On any out of our control abort
    my ($self) = @_;
    $self->dbgout( 'CALLBACK', 'Abort', LOG_DEBUG );
    $self->dbgoutwrite();
    return SMFIS_CONTINUE;
}

sub close_callback {
    # On end of connection
    my ($self) = @_;
    $self->dbgout( 'CALLBACK', 'Close', LOG_DEBUG );
    $self->dbgoutwrite();
    return SMFIS_CONTINUE;
}

1;
