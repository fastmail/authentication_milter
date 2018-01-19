package Mail::Milter::Authentication::Handler;
use strict;
use warnings;
use version; our $VERSION = version->declare('v1.1.7');

use Digest::MD5 qw{ md5_hex };
use English qw{ -no_match_vars };
use Mail::SPF;
use MIME::Base64;
use Net::DNS::Resolver;
use Net::IP;
use Sys::Syslog qw{:standard :macros};
use Sys::Hostname;
use Time::HiRes qw{ gettimeofday };

use Mail::Milter::Authentication::Constants qw { :all };
use Mail::Milter::Authentication::Config;
#use Mail::AuthenticationResults::Parser;

our $TestResolver; # For Testing

sub new {
    my ( $class, $thischild ) = @_;
    my $self = {
        'thischild' => $thischild,
    };
    bless $self, $class;
    return $self;
}

sub get_version {
    my ( $self ) = @_;
    {
        no strict 'refs'; ## no critic;
        return ${ ref( $self ) . "::VERSION" }; # no critic;
    }
    return;
}

sub get_json {
    my ( $self, $file ) = @_;
    my $basefile = __FILE__;
    $basefile =~ s/Handler\.pm$/Handler\/$file/;
    $basefile .= '.json';
    if ( ! -e $basefile ) {
        die 'json file ' . $file . ' not found';
    }
    open my $InF, '<', $basefile;
    my @Content = <$InF>;
    close $InF;
    return join( q{}, @Content );
}

sub metric_register {
    my ( $self, $id, $help ) = @_;
    $self->{'thischild'}->{'metric'}->register( $id, $help, $self->{'thischild'} );
    return;
}

sub metric_count {
    my ( $self, $count_id, $labels, $count ) = @_;
    $labels = {} if ! defined $labels;
    $count = 1 if ! defined $count;

    my $metric = $self->{'thischild'}->{'metric'};
    $metric->count({
        'count_id' => $count_id,
        'labels'   => $labels,
        'server'   => $self->{'thischild'},
        'count'    => $count,
    });
    return;
}

sub metric_send {
    my ( $self ) = @_;
    $self->{'thischild'}->{'metric'}->send( $self->{ 'thischild' });
    return;
}

sub get_microseconds {
    my ( $self ) = @_;
    my ($seconds, $microseconds) = gettimeofday;
    return ( ( $seconds * 1000000 ) + $microseconds );
}

# Top Level Callbacks

sub register_metrics {
    return {
        'connect_total'           => 'The number of connections made to authentication milter',
        'callback_error_total'    => 'The number of errors in callbacks',
        'time_microseconds_total' => 'The time in microseconds spent in various handlers',
    };
}

sub top_setup_callback {

    my ( $self ) = @_;
    $self->status('setup');
    $self->dbgout( 'CALLBACK', 'Setup', LOG_DEBUG );
    $self->set_return( $self->smfis_continue() );
    my $callbacks = $self->get_callbacks( 'setup' );
    foreach my $handler ( @$callbacks ) {
        $self->dbgout( 'CALLBACK', 'Setup ' . $handler, LOG_DEBUG );
        my $start_time = $self->get_microseconds();
        $self->get_handler($handler)->setup_callback();
        $self->metric_count( 'time_microseconds_total', { 'callback' => 'setup', 'handler' => $handler }, $self->get_microseconds() - $start_time );
    }
    $self->status('postsetup');
    return;
}

sub top_connect_callback {

    # On Connect
    my ( $self, $hostname, $ip ) = @_;
    $self->metric_count( 'connect_total' );
    $self->status('connect');
    $self->dbgout( 'CALLBACK', 'Connect', LOG_DEBUG );
    $self->set_return( $self->smfis_continue() );
    my $config = $self->config();
    eval {
        local $SIG{'ALRM'} = sub{ die "Timeout\n" };
        if ( $config->{'connect_timeout'} ) {
            alarm( $config->{'connect_timeout'} );
        }

        $self->dbgout( 'ConnectFrom', $ip->ip(), LOG_DEBUG );
        $self->{'raw_ip_object'} = $ip;

        if ( exists ( $config->{ 'ip_map' } ) ) {
            foreach my $ip_map ( sort keys %{ $config->{ 'ip_map' } } ) {
                my $map_obj = Net::IP->new( $ip_map );
                my $is_overlap = $ip->overlaps($map_obj) || 0;
                if (
                       $is_overlap == $IP_A_IN_B_OVERLAP
                    || $is_overlap == $IP_B_IN_A_OVERLAP     # Should never happen
                    || $is_overlap == $IP_PARTIAL_OVERLAP    # Should never happen
                    || $is_overlap == $IP_IDENTICAL
                  )
                {
                    if ( exists ( $config->{ 'ip_map' }->{ $ip_map }->{ 'ip' } ) ) {
                        $ip = Net::IP->new( $config->{ 'ip_map' }->{ $ip_map }->{ 'ip' } );
                        $self->dbgout( 'ConnectFromRemapped', $self->{'raw_ip_object'}->ip() . ' > ' . $ip->ip(), LOG_DEBUG );
                        last;
                    }
                }
            }
        }

        $self->{'ip_object'} = $ip;

        my $callbacks = $self->get_callbacks( 'connect' );
        foreach my $handler ( @$callbacks ) {
            $self->dbgout( 'CALLBACK', 'Connect ' . $handler, LOG_DEBUG );
            my $start_time = $self->get_microseconds();
            eval{ $self->get_handler($handler)->connect_callback( $hostname, $ip ); };
            if ( my $error = $@ ) {
                $self->log_error( 'Connect callback error ' . $error );
                $self->exit_on_close();
                $self->tempfail_on_error();
                $self->metric_count( 'callback_error_total', { 'stage' => 'connect', 'handler' => $handler } );
                if ( $error =~ /Timeout/ ) {
                    alarm( 1 );
                }
            }
            $self->metric_count( 'time_microseconds_total', { 'callback' => 'connect', 'handler' => $handler }, $self->get_microseconds() - $start_time );
        }
        alarm(0);
    };
    if ( my $error = $@ ) {
        $self->log_error( 'Connect callback error ' . $error );
        $self->exit_on_close();
        $self->tempfail_on_error();
        $self->metric_count( 'callback_error_total', { 'stage' => 'connect' } );
    }
    $self->status('postconnect');
    return $self->get_return();
}

sub top_helo_callback {

    # On HELO
    my ( $self, $helo_host ) = @_;
    $self->status('helo');
    $self->dbgout( 'CALLBACK', 'Helo', LOG_DEBUG );
    $self->set_return( $self->smfis_continue() );
    $helo_host = q{} if not $helo_host;
    my $config = $self->config();
    eval {
        local $SIG{'ALRM'} = sub{ die "Timeout\n" };
        if ( $config->{'command_timeout'} ) {
            alarm( $config->{'command_timeout'} );
        }

        # Take only the first HELO from a connection
        if ( !( $self->{'helo_name'} ) ) {

            $self->{'raw_helo_name'} = $helo_host;
            if ( exists ( $config->{ 'ip_map' } ) ) {
                my $ip_object = $self->{ 'raw_ip_object' };
                foreach my $ip_map ( sort keys %{ $config->{ 'ip_map' } } ) {
                    my $map_obj = Net::IP->new( $ip_map );
                    my $is_overlap = $ip_object->overlaps($map_obj) || 0;
                    if (
                           $is_overlap == $IP_A_IN_B_OVERLAP
                        || $is_overlap == $IP_B_IN_A_OVERLAP     # Should never happen
                        || $is_overlap == $IP_PARTIAL_OVERLAP    # Should never happen
                        || $is_overlap == $IP_IDENTICAL
                      )
                    {
                        my $mapped_to = $config->{ 'ip_map' }->{ $ip_map };
                        if ( exists ( $config->{ 'ip_map' }->{ $ip_map }->{ 'helo' } ) ) {
                            $helo_host = $config->{ 'ip_map' }->{ $ip_map }->{ 'helo' };
                            $self->dbgout( 'HELORemapped', $self->{'raw_helo_name'} . ' > ' . $helo_host, LOG_DEBUG );
                            last;
                        }
                    }
                }
            }

            $self->{'helo_name'} = $helo_host;
            my $callbacks = $self->get_callbacks( 'helo' );
            foreach my $handler ( @$callbacks ) {
                $self->dbgout( 'CALLBACK', 'Helo ' . $handler, LOG_DEBUG );
                my $start_time = $self->get_microseconds();
                eval{ $self->get_handler($handler)->helo_callback($helo_host); };
                if ( my $error = $@ ) {
                    $self->log_error( 'HELO callback error ' . $error );
                    $self->exit_on_close();
                    $self->tempfail_on_error();
                    $self->metric_count( 'callback_error_total', { 'stage' => 'helo', 'handler' => $handler } );
                    if ( $error =~ /Timeout/ ) {
                        alarm( 1 );
                    }
                }
                $self->metric_count( 'time_microseconds_total', { 'callback' => 'helo', 'handler' => $handler }, $self->get_microseconds() - $start_time );
            }
        }
        else {
            $self->dbgout('Multiple HELO callbacks detected and ignored', $self->{'helo_name'} . ' / ' . $helo_host, LOG_DEBUG );
        }

        alarm(0);
    };
    if ( my $error = $@ ) {
        $self->metric_count( 'callback_error_total', { 'stage' => 'helo' } );
        $self->log_error( 'HELO callback error ' . $error );
        $self->exit_on_close();
        $self->tempfail_on_error();
    }
    $self->status('posthelo');
    return $self->get_return();
}

sub top_envfrom_callback {

    # On MAILFROM
    #...
    my ( $self, $env_from ) = @_;
    $self->status('envfrom');
    $self->dbgout( 'CALLBACK', 'EnvFrom', LOG_DEBUG );
    $self->set_return( $self->smfis_continue() );
    $env_from = q{} if not $env_from;
    my $config = $self->config();
    eval {
        local $SIG{'ALRM'} = sub{ die "Timeout\n" };
        if ( $config->{'command_timeout'} ) {
            alarm( $config->{'command_timeout'} );
        }

        # Reset private data for this MAIL transaction
        delete $self->{'auth_headers'};
        delete $self->{'pre_headers'};
        delete $self->{'add_headers'};

        my $callbacks = $self->get_callbacks( 'envfrom' );
        foreach my $handler ( @$callbacks ) {
            $self->dbgout( 'CALLBACK', 'EnvFrom ' . $handler, LOG_DEBUG );
            my $start_time = $self->get_microseconds();
            eval { $self->get_handler($handler)->envfrom_callback($env_from); };
            if ( my $error = $@ ) {
                $self->log_error( 'Env From callback error ' . $error );
                $self->exit_on_close();
                $self->tempfail_on_error();
                $self->metric_count( 'callback_error_total', { 'stage' => 'envfrom', 'handler' => $handler } );
                if ( $error =~ /Timeout/ ) {
                    alarm( 1 );
                }
            }
            $self->metric_count( 'time_microseconds_total', { 'callback' => 'envfrom', 'handler' => $handler }, $self->get_microseconds() - $start_time );
        }
        alarm(0);
    };
    if ( my $error = $@ ) {
        $self->metric_count( 'callback_error_total', { 'stage' => 'envfrom' } );
        $self->log_error( 'Env From callback error ' . $error );
        $self->exit_on_close();
        $self->tempfail_on_error();
    }
    $self->status('postenvfrom');
    return $self->get_return();
}

sub top_envrcpt_callback {

    # On RCPTTO
    #...
    my ( $self, $env_to ) = @_;
    $self->status('envrcpt');
    $self->dbgout( 'CALLBACK', 'EnvRcpt', LOG_DEBUG );
    $self->set_return( $self->smfis_continue() );
    $env_to = q{} if not $env_to;
    my $config = $self->config();
    eval {
        local $SIG{'ALRM'} = sub{ die "Timeout\n" };
        if ( $config->{'command_timeout'} ) {
            alarm( $config->{'command_timeout'} );
        }
        my $callbacks = $self->get_callbacks( 'envrcpt' );
        foreach my $handler ( @$callbacks ) {
            $self->dbgout( 'CALLBACK', 'EnvRcpt ' . $handler, LOG_DEBUG );
            my $start_time = $self->get_microseconds();
            eval{ $self->get_handler($handler)->envrcpt_callback($env_to); };
            if ( my $error = $@ ) {
                $self->log_error( 'Rcpt To callback error ' . $error );
                $self->exit_on_close();
                $self->tempfail_on_error();
                $self->metric_count( 'callback_error_total', { 'stage' => 'rcptto', 'handler' => $handler } );
                if ( $error =~ /Timeout/ ) {
                    alarm( 1 );
                }
            }
            $self->metric_count( 'time_microseconds_total', { 'callback' => 'rcptto', 'handler' => $handler }, $self->get_microseconds() - $start_time );
        }
        alarm(0);
    };
    if ( my $error = $@ ) {
        $self->metric_count( 'callback_error_total', { 'stage' => 'rcptto' } );
        $self->log_error( 'Rcpt To callback error ' . $error );
        $self->exit_on_close();
        $self->tempfail_on_error();
    }
    $self->status('postenvrcpt');
    return $self->get_return();
}

sub top_header_callback {

    # On Each Header
    my ( $self, $header, $value ) = @_;
    $self->status('header');
    $self->dbgout( 'CALLBACK', 'Header', LOG_DEBUG );
    $self->set_return( $self->smfis_continue() );
    $value = q{} if not $value;
    my $config = $self->config();
    eval {
        local $SIG{'ALRM'} = sub{ die "Timeout\n" };
        if ( $config->{'content_timeout'} ) {
            $self->dbgout( 'Content Timeout set', $config->{'content_timeout'}, LOG_DEBUG );
            alarm( $config->{'content_timeout'} );
        }
        if ( my $error = $@ ) {
            $self->dbgout( 'inline error $error', '', LOG_DEBUG );
        }

        my $callbacks = $self->get_callbacks( 'header' );
        foreach my $handler ( @$callbacks ) {
            $self->dbgout( 'CALLBACK', 'Header ' . $handler, LOG_DEBUG );
            my $start_time = $self->get_microseconds();
            eval{ $self->get_handler($handler)->header_callback( $header, $value ); };
            if ( my $error = $@ ) {
                $self->log_error( 'Header callback error ' . $error );
                $self->exit_on_close();
                $self->tempfail_on_error();
                $self->metric_count( 'callback_error_total', { 'stage' => 'header', 'handler' => $handler } );
                if ( $error =~ /Timeout/ ) {
                    alarm( 1 );
                }
            }
            $self->metric_count( 'time_microseconds_total', { 'callback' => 'header', 'handler' => $handler }, $self->get_microseconds() - $start_time );
        }
        alarm(0);
    };
    if ( my $error = $@ ) {
        $self->metric_count( 'callback_error_total', { 'stage' => 'header' } );
        $self->log_error( 'Header callback error ' . $error );
        $self->exit_on_close();
        $self->tempfail_on_error();
    }
    $self->status('postheader');
    return $self->get_return();
}

sub top_eoh_callback {

    # On End of headers
    my ($self) = @_;
    $self->status('eoh');
    $self->dbgout( 'CALLBACK', 'EOH', LOG_DEBUG );
    $self->set_return( $self->smfis_continue() );
    my $config = $self->config();
    eval {
        local $SIG{'ALRM'} = sub{ die "Timeout\n" };
        if ( $config->{'content_timeout'} ) {
            alarm( $config->{'content_timeout'} );
        }
        my $callbacks = $self->get_callbacks( 'eoh' );
        foreach my $handler ( @$callbacks ) {
            $self->dbgout( 'CALLBACK', 'EOH ' . $handler, LOG_DEBUG );
            my $start_time = $self->get_microseconds();
            eval{ $self->get_handler($handler)->eoh_callback(); };
            if ( my $error = $@ ) {
                $self->log_error( 'EOH callback error ' . $error );
                $self->exit_on_close();
                $self->tempfail_on_error();
                $self->metric_count( 'callback_error_total', { 'stage' => 'eoh', 'handler' => $handler } );
                if ( $error =~ /Timeout/ ) {
                    alarm( 1 );
                }
            }
            $self->metric_count( 'time_microseconds_total', { 'callback' => 'eoh', 'handler' => $handler }, $self->get_microseconds() - $start_time );
        }
        alarm(0);
    };
    if ( my $error = $@ ) {
        $self->metric_count( 'callback_error_total', { 'stage' => 'eoh' } );
        $self->log_error( 'EOH callback error ' . $error );
        $self->exit_on_close();
        $self->tempfail_on_error();
    }
    $self->dbgoutwrite();
    $self->status('posteoh');
    return $self->get_return();
}

sub top_body_callback {

    # On each body chunk
    my ( $self, $body_chunk ) = @_;
    $self->status('body');
    $self->dbgout( 'CALLBACK', 'Body', LOG_DEBUG );
    $self->set_return( $self->smfis_continue() );
    my $config = $self->config();
    eval {
        local $SIG{'ALRM'} = sub{ die "Timeout\n" };
        if ( $config->{'content_timeout'} ) {
            alarm( $config->{'content_timeout'} );
        }
        my $callbacks = $self->get_callbacks( 'body' );
        foreach my $handler ( @$callbacks ) {
            $self->dbgout( 'CALLBACK', 'Body ' . $handler, LOG_DEBUG );
            my $start_time = $self->get_microseconds();
            eval{ $self->get_handler($handler)->body_callback( $body_chunk ); };
            if ( my $error = $@ ) {
                $self->log_error( 'Body callback error ' . $error );
                $self->exit_on_close();
                $self->tempfail_on_error();
                $self->metric_count( 'callback_error_total', { 'stage' => 'body', 'handler' => $handler } );
                if ( $error =~ /Timeout/ ) {
                    alarm( 1 );
                }
            }
            $self->metric_count( 'time_microseconds_total', { 'callback' => 'body', 'handler' => $handler }, $self->get_microseconds() - $start_time );
        }
        alarm(0);
    };
    if ( my $error = $@ ) {
        $self->metric_count( 'callback_error_total', { 'stage' => 'body' } );
        $self->log_error( 'Body callback error ' . $error );
        $self->exit_on_close();
        $self->tempfail_on_error();
    }
    $self->dbgoutwrite();
    $self->status('postbody');
    return $self->get_return();
}

sub top_eom_callback {

    # On End of Message
    my ($self) = @_;
    $self->status('eom');
    $self->dbgout( 'CALLBACK', 'EOM', LOG_DEBUG );
    $self->set_return( $self->smfis_continue() );
    my $config = $self->config();
    eval {
        local $SIG{'ALRM'} = sub{ die "Timeout\n" };
        if ( $config->{'content_timeout'} ) {
            alarm( $config->{'content_timeout'} );
        }
        my $callbacks = $self->get_callbacks( 'eom' );
        foreach my $handler ( @$callbacks ) {
            $self->dbgout( 'CALLBACK', 'EOM ' . $handler, LOG_DEBUG );
            my $start_time = $self->get_microseconds();
            eval{ $self->get_handler($handler)->eom_callback(); };
            if ( my $error = $@ ) {
                $self->log_error( 'EOM callback error ' . $error );
                $self->exit_on_close();
                $self->tempfail_on_error();
                $self->metric_count( 'callback_error_total', { 'stage' => 'eom', 'handler' => $handler } );
                if ( $error =~ /Timeout/ ) {
                    alarm( 1 );
                }
            }
            $self->metric_count( 'time_microseconds_total', { 'callback' => 'eom', 'handler' => $handler }, $self->get_microseconds() - $start_time );
        }
        alarm(0);
    };
    if ( my $error = $@ ) {
        $self->metric_count( 'callback_error_total', { 'stage' => 'eom' } );
        $self->log_error( 'EOM callback error ' . $error );
        $self->exit_on_close();
        $self->tempfail_on_error();
    }
    $self->apply_policy();
    $self->add_headers();
    $self->dbgoutwrite();
    $self->status('posteom');
    return $self->get_return();
}

sub apply_policy {
    my ($self) = @_;

    my @auth_headers;
    my $top_handler = $self->get_top_handler();
    if ( exists( $top_handler->{'c_auth_headers'} ) ) {
        @auth_headers = @{ $top_handler->{'c_auth_headers'} };
    }
    if ( exists( $top_handler->{'auth_headers'} ) ) {
        @auth_headers = ( @auth_headers, @{ $top_handler->{'auth_headers'} } );
    }

    #my $parsed_headers = Mail::AuthenticationResults::Parser->new( \@auth_headers );;

    #use Data::Dumper;
    #print Dumper \@structured_headers;

    return;
}

sub top_abort_callback {

    # On any out of our control abort
    my ($self) = @_;
    $self->status('abort');
    $self->dbgout( 'CALLBACK', 'Abort', LOG_DEBUG );
    $self->set_return( $self->smfis_continue() );
    my $config = $self->config();
    eval {
        local $SIG{'ALRM'} = sub{ die "Timeout\n" };
        if ( $config->{'command_timeout'} ) {
            alarm( $config->{'command_timeout'} );
        }
        my $callbacks = $self->get_callbacks( 'abort' );
        foreach my $handler ( @$callbacks ) {
            $self->dbgout( 'CALLBACK', 'Abort ' . $handler, LOG_DEBUG );
            my $start_time = $self->get_microseconds();
            eval{ $self->get_handler($handler)->abort_callback(); };
            if ( my $error = $@ ) {
                $self->log_error( 'Abort callback error ' . $error );
                $self->exit_on_close();
                $self->tempfail_on_error();
                $self->metric_count( 'callback_error_total', { 'stage' => 'abort', 'handler' => $handler } );
                if ( $error =~ /Timeout/ ) {
                    alarm( 1 );
                }
            }
            $self->metric_count( 'time_microseconds_total', { 'callback' => 'abort', 'handler' => $handler }, $self->get_microseconds() - $start_time );
        }
        alarm(0);
    };
    if ( my $error = $@ ) {
        $self->metric_count( 'callback_error_total', { 'stage' => 'abort' } );
        $self->log_error( 'Abort callback error ' . $error );
        $self->exit_on_close();
        $self->tempfail_on_error();
    }
    $self->status('postabort');
    return $self->get_return();
}

sub top_close_callback {

    # On end of connection
    my ($self) = @_;
    $self->status('close');
    $self->dbgout( 'CALLBACK', 'Close', LOG_DEBUG );
    $self->set_return( $self->smfis_continue() );
    my $config = $self->config();
    eval {
        local $SIG{'ALRM'} = sub{ die "Timeout\n" };
        if ( $config->{'content_timeout'} ) {
            alarm( $config->{'content_timeout'} );
        }
        my $callbacks = $self->get_callbacks( 'close' );
        foreach my $handler ( @$callbacks ) {
            $self->dbgout( 'CALLBACK', 'Close ' . $handler, LOG_DEBUG );
            my $start_time = $self->get_microseconds();
            eval{ $self->get_handler($handler)->close_callback(); };
            if ( my $error = $@ ) {
                $self->log_error( 'Close callback error ' . $error );
                $self->exit_on_close();
                $self->tempfail_on_error();
                $self->metric_count( 'callback_error_total', { 'stage' => 'close', 'handler' => $handler } );
                if ( $error =~ /Timeout/ ) {
                    alarm( 1 );
                }
            }
            $self->metric_count( 'time_microseconds_total', { 'callback' => 'close', 'handler' => $handler }, $self->get_microseconds() - $start_time );
        }
        alarm(0);
    };
    if ( my $error = $@ ) {
        $self->metric_count( 'callback_error_total', { 'stage' => 'close' } );
        $self->log_error( 'Close callback error ' . $error );
        $self->exit_on_close();
        $self->tempfail_on_error();
    }
    delete $self->{'helo_name'};
    delete $self->{'raw_helo_name'};
    delete $self->{'c_auth_headers'};
    delete $self->{'auth_headers'};
    delete $self->{'pre_headers'};
    delete $self->{'add_headers'};
    delete $self->{'ip_object'};
    delete $self->{'raw_ip_object'};
    $self->dbgoutwrite();
    $self->clear_all_symbols();
    $self->status('postclose');
    return $self->get_return();
}



# Other methods

sub status {
    my ($self, $status) = @_;
    my $count = $self->{'thischild'}->{'count'};
    if ( exists ( $self->{'thischild'}->{'smtp'} ) ) {
        if ( $self->{'thischild'}->{'smtp'}->{'count'} ) {
            $count .= '.' . $self->{'thischild'}->{'smtp'}->{'count'};
        }
    }
    if ( $status ) {
        $PROGRAM_NAME = $Mail::Milter::Authentication::Config::IDENT . ':processing:' . $status . '(' . $count . ')';
    }
    else {
        $PROGRAM_NAME = $Mail::Milter::Authentication::Config::IDENT . ':processing(' . $count . ')';
    }
    return;
}

sub config {
    my ($self) = @_;
    return $self->{'thischild'}->{'config'};
}

sub handler_config {
    my ($self) = @_;
    my $type = $self->handler_type();
    return if ! $type;
    if ( $self->is_handler_loaded( $type ) ) {
        my $config = $self->config();
        return $config->{'handlers'}->{$type};
    }
    return;
}

sub handler_type {
    my ($self) = @_;
    my $type = ref $self;
    if ( $type eq 'Mail::Milter::Authentication::Handler' ) {
        return 'Handler';
    }
    elsif ( $type =~ /^Mail::Milter::Authentication::Handler::(.*)/ ) {
        my $handler_type = $1;
        return $handler_type;
    }
    else {
        return undef; ## no critic
    }
}

sub set_return {
    my ( $self, $return ) = @_;
    my $top_handler = $self->get_top_handler();
    $top_handler->{'return_code'} = $return;
    return;
}

sub get_return {
    my ( $self ) = @_;
    my $top_handler = $self->get_top_handler();
    if ( defined $self->get_reject_mail() ) {
        return $self->smfis_reject();
    }
    return $top_handler->{'return_code'};
}

sub get_reject_mail {
    my ( $self ) = @_;
    my $top_handler = $self->get_top_handler();
    return $top_handler->{'reject_mail'};
}

sub clear_reject_mail {
    my ( $self ) = @_;
    my $top_handler = $self->get_top_handler();
    delete $top_handler->{'reject_mail'};
    return;
}

sub get_top_handler {
    my ($self) = @_;
    my $thischild = $self->{'thischild'};
    my $object = $thischild->{'handler'}->{'_Handler'};
    return $object;
}

sub is_handler_loaded {
    my ( $self, $name ) = @_;
    my $config = $self->config();
    if ( exists ( $config->{'handlers'}->{$name} ) ) {
        return 1;
    }
    return 0;
}

sub get_handler {
    my ( $self, $name ) = @_;
    my $thischild = $self->{'thischild'};
    my $object = $thischild->{'handler'}->{$name};
    return $object;
}


sub get_callbacks {
    my ( $self, $callback ) = @_;
    my $thischild = $self->{'thischild'};
    return $thischild->{'callbacks_list'}->{$callback};
}

sub set_object_maker {
    my ( $self, $name, $ref ) = @_;
    my $thischild = $self->{'thischild'};
    return if $thischild->{'object_maker'}->{$name};
    $thischild->{'object_maker'}->{$name} = $ref;
    return;
}

sub get_object {
    my ( $self, $name ) = @_;

    my $thischild = $self->{'thischild'};
    my $object = $thischild->{'object'}->{$name};
    if ( ! $object ) {

        if ( exists( $thischild->{'object_maker'}->{$name} ) ) {
            my $maker = $thischild->{'object_maker'}->{$name};
            &$maker( $self, $name );
        }

        elsif ( $name eq 'resolver' ) {
            $self->dbgout( 'Object created', $name, LOG_DEBUG );
            my $config = $self->config();
            my $timeout           = $config->{'dns_timeout'}           || 8;
            my $dns_retry         = $config->{'dns_retry'}             || 2;
            my $resolvers         = $config->{'dns_resolvers'}         || [];
            if ( defined $TestResolver ) {
                $object = $TestResolver;
                warn "Using FAKE TEST DNS Resolver - I Hope this isn't production!";
                # If it is you better know what you're doing!
            }
            else {
                $object = Net::DNS::Resolver->new(
                    'udp_timeout'       => $timeout,
                    'tcp_timeout'       => $timeout,
                    'retry'             => $dns_retry,
                    'nameservers'       => $resolvers,
                );
                $object->udppacketsize(1240);
                $object->persistent_udp(1);
            }
            $thischild->{'object'}->{$name} = {
                'object'  => $object,
                'destroy' => 0,
            };
        }

    }
    return $thischild->{'object'}->{$name}->{'object'};
}

sub set_object {
    my ( $self, $name, $object, $destroy ) = @_;
    my $thischild = $self->{'thischild'};
    $self->dbgout( 'Object set', $name, LOG_DEBUG );
    $thischild->{'object'}->{$name} = {
        'object'  => $object,
        'destroy' => $destroy,
    };
    return;
}

sub destroy_object {
    my ( $self, $name ) = @_;
    my $thischild = $self->{'thischild'};

    # Objects may be set to not be destroyed,
    # eg. resolver and spf_server are not
    # destroyed for performance reasons
    return if ! $thischild->{'object'}->{$name}->{'destroy'};
    return if ! $thischild->{'object'}->{$name};
    $self->dbgout( 'Object destroyed', $name, LOG_DEBUG );
    delete $thischild->{'object'}->{$name};
    return;
}

sub destroy_all_objects {
    # Unused!
    my ( $self ) = @_;
    my $thischild = $self->{'thischild'};
    foreach my $name ( keys %{ $thischild->{'object'} } )
    {
        $self->destroy_object( $name );
    }
    return;
}

sub exit_on_close {
    my ( $self ) = @_;
    my $top_handler = $self->get_top_handler();
    $top_handler->{'exit_on_close'} = 1;
    return;
}

sub reject_mail {
    my ( $self, $reason ) = @_;
    my $top_handler = $self->get_top_handler();
    $top_handler->{'reject_mail'} = $reason;
    return;
}

sub clear_all_symbols {
    my ( $self ) = @_;
    my $top_handler = $self->get_top_handler();
    delete $top_handler->{'symbols'};
    return;
}

sub clear_symbols {
    my ( $self ) = @_;
    my $top_handler = $self->get_top_handler();

    my $connect_symbols;
    if ( exists ( $top_handler->{'symbols'} ) ) {
        if ( exists ( $top_handler->{'symbols'}->{'C'} ) ) {
            $connect_symbols = $top_handler->{'symbols'}->{'C'};
        }
    }

    delete $top_handler->{'symbols'};

    if ( $connect_symbols ) {
        $top_handler->{'symbols'} = {
            'C' => $connect_symbols,
        };
    }

    return;
}

sub set_symbol {
    my ( $self, $code, $key, $value ) = @_;
    $self->dbgout( 'SetSymbol', "$code: $key: $value", LOG_DEBUG );
    my $top_handler = $self->get_top_handler();
    if ( ! exists ( $top_handler->{'symbols'} ) ) {
        $top_handler->{'symbols'} = {};
    }
    if ( ! exists ( $top_handler->{'symbols'}->{$code} ) ) {
        $top_handler->{'symbols'}->{$code} = {};
    }
    $top_handler->{'symbols'}->{$code}->{$key} = $value;;
    return;
}

sub get_symbol {
    my ( $self, $searchkey ) = @_;
    my $top_handler = $self->get_top_handler();
    my $symbols = $top_handler->{'symbols'} || {};
    foreach my $code ( keys %{$symbols} ) {
        my $subsymbols = $symbols->{$code};
        foreach my $key ( keys %{$subsymbols} ) {
            if ( $searchkey eq $key ) {
                return $subsymbols->{$key};
            }
        }
    }
    return;
}

sub tempfail_on_error {
    my ( $self ) = @_;
    my $config = $self->config();
    if ( $self->is_authenticated() ) {
        if ( $config->{'tempfail_on_error_authenticated'} ) {
            $self->log_error('TempFail set');
            $self->set_return( $self->smfis_tempfail() );
        }
    }
    elsif ( $self->is_local_ip_address() ) {
        if ( $config->{'tempfail_on_error_local'} ) {
            $self->log_error('TempFail set');
            $self->set_return( $self->smfis_tempfail() );
        }
    }
    elsif ( $self->is_trusted_ip_address() ) {
        if ( $config->{'tempfail_on_error_trusted'} ) {
            $self->log_error('TempFail set');
            $self->set_return( $self->smfis_tempfail() );
        }
    }
    else {
        if ( $config->{'tempfail_on_error'} ) {
            $self->log_error('TempFail set');
            $self->set_return( $self->smfis_tempfail() );
        }
    }
    return;
}



# Common calls into other Handlers

sub is_local_ip_address {
    my ($self) = @_;
    return 0 if ! $self->is_handler_loaded('LocalIP');
    return $self->get_handler('LocalIP')->{'is_local_ip_address'};
}

sub is_trusted_ip_address {
    my ($self) = @_;
    return 0 if ! $self->is_handler_loaded('TrustedIP');
    return $self->get_handler('TrustedIP')->{'is_trusted_ip_address'};
}

sub is_authenticated {
    my ($self) = @_;
    return 0 if ! $self->is_handler_loaded('Auth');
    return $self->get_handler('Auth')->{'is_authenticated'};
}

sub ip_address {
    my ($self) = @_;
    my $top_handler = $self->get_top_handler();
    return $top_handler->{'ip_object'}->ip();
}



# Header formatting and data methods

sub format_ctext {

    # Return ctext (but with spaces intact)
    my ( $self, $text ) = @_;
    $text = q{} if ! defined $text;
    $text =~ s/\t/ /g;
    $text =~ s/\n/ /g;
    $text =~ s/\r/ /g;
    $text =~ s/\(/ /g;
    $text =~ s/\)/ /g;
    $text =~ s/\\/ /g;
    return $text;
}

sub format_ctext_no_space {
    my ( $self, $text ) = @_;
    $text = $self->format_ctext($text);
    $text =~ s/ //g;
    $text =~ s/;/_/g;
    return $text;
}

sub format_header_comment {
    my ( $self, $comment ) = @_;
    $comment = $self->format_ctext($comment);
    return $comment;
}

sub format_header_entry {
    my ( $self, $key, $value ) = @_;
    $key   = $self->format_ctext_no_space($key);
    $value = $self->format_ctext_no_space($value);
    my $string = "$key=$value";
    return $string;
}

sub get_domain_from {
    my ( $self, $address ) = @_;
    $address = q{} if ! defined $address;
    $address = $self->get_address_from($address);
    my $domain = 'localhost.localdomain';
    $address =~ s/<//g;
    $address =~ s/>//g;
    if ( $address =~ /\@/ ) {
        ($domain) = $address =~ /.*\@(.*)/;
    }
    $domain =~ s/\s//g;
    return lc $domain;
}

sub get_domains_from {
    my ( $self, $addresstxt ) = @_;
    $addresstxt = q{} if ! defined $addresstxt;
    my $addresses = $self->get_addresses_from($addresstxt);
    my $domains = [];
    foreach my $address ( @$addresses ) {
        my $domain;
        $address =~ s/<//g;
        $address =~ s/>//g;
        if ( $address =~ /\@/ ) {
            ($domain) = $address =~ /.*\@(.*)/;
        }
        $domain =~ s/\s//g;
        push @$domains, lc $domain;
    }
    return $domains;
}

use constant IsSep => 0;
use constant IsPhrase => 1;
use constant IsEmail => 2;
use constant IsComment => 3;

sub get_address_from {
    my ( $self, $Str ) = @_;
    my $addresses = $self->get_addresses_from( $Str );
    return $addresses->[0];
}

sub get_addresses_from {
    my ( $self, $Str ) = @_;
    $Str = q{} if !defined $Str;

    if ( $Str eq q{} ) {
        $self->log_error( 'Could not parse empty address' );
        return [ $Str ];
    }

    my $IDNComponentRE = qr/[^\x20-\x2c\x2e\x2f\x3a-\x40\x5b-\x60\x7b-\x7f]+/;
    my $IDNRE = qr/(?:$IDNComponentRE\.)+$IDNComponentRE/;
    my $RFC_atom = qr/[a-z0-9\!\#\$\%\&\'\*\+\-\/\=\?\^\_\`\{\|\}\~]+/i;
    my $RFC_dotatom = qr/${RFC_atom}(?:\.${RFC_atom})*/;

    # Break everything into Tokens
    my ( @Tokens, @Types );
    TOKEN_LOOP:
    while (1) {
        if ($Str =~ m/\G\"(.*?)(?<!\\)(?:\"|\z)\s*/sgc) {
            # String " ... "
            push @Tokens, $1;
            push @Types, IsPhrase;
        }
        elsif ( $Str =~ m/\G\<(.*?)(?<!\\)(?:[>,;]|\z)\s*/sgc) {
            # String < ... >
            push @Tokens, $1;
            push @Types, IsEmail;
        }
        elsif ($Str =~ m/\G\((.*?)(?<!\\)\)\s*/sgc) {
            # String ( ... )
            push @Tokens, $1;
            push @Types, IsComment;
        }
        elsif ($Str =~ m/\G[,;]\s*/gc) {
            # Comma or semi-colon
            push @Tokens, undef;
            push @Types, IsSep;
        }
        elsif ($Str =~ m/\G$/gc) {
            # End of line
            last TOKEN_LOOP;
        }
        elsif ($Str =~ m/\G([^\s,;"<]*)\s*/gc) {
            # Anything else
            if (length $1) {
                push @Tokens, $1;
                push @Types, IsPhrase;
            }
        }
        else {
            # Incomplete line. We'd like to die, but we'll return what we can
            $self->log_error('Could not parse address ' . $Str . ' : Unknown line remainder : ' . substr( $Str, pos() ) );
            push @Tokens, substr($Str, pos($Str));
            push @Types, IsComment;
            last TOKEN_LOOP;
        }
    }

    # Now massage Tokens into [ "phrase", "emailaddress", "comment" ]
    my @Addrs;
    my ($Phrase, $Email, $Comment, $Type);
    for (my $i = 0; $i < scalar(@Tokens); $i++) {
        my ($Type, $Token) = ($Types[$i], $Tokens[$i]);

        # If  - a separator OR
        #     - email address and already got one OR
        #     - phrase and already got email address
        # then add current data as token
        if (($Type == IsSep) ||
            ($Type == IsEmail && defined($Email)) ||
            ($Type == IsPhrase && defined($Email)) ) {
            push @Addrs, $Email if defined $Email;
            ($Phrase, $Email, $Comment) = (undef, undef, undef);
        }

        # A phrase...
        if ($Type == IsPhrase) {
            # Strip '...' around token
            $Token =~ s/^'(.*)'$/$1/;
            # Strip any newlines assuming folded headers
            $Token =~ s/\r?\n//g;

            # Email like token?
            if ($Token =~ /^$RFC_dotatom\@$IDNRE$/o) {
                $Token =~ s/^\s+//;
                $Token =~ s/\s+$//;
                $Token =~ s/\s+\@/\@/;
                $Token =~ s/\@\s+/\@/;
                # Yes, check if next token is definitely email. If yes,
                #  make this a phrase, otherwise make it an email item
                if ($i+1 < scalar(@Tokens) && $Types[$i+1] == IsEmail) {
                    $Phrase = defined($Phrase) ? $Phrase . " " . $Token : $Token;
                }
                else {
                    # If we've already got an email address, add current address
                    if (defined($Email)) {
                        push @Addrs, $Email;
                        ($Phrase, $Email, $Comment) = (undef, undef, undef);
                    }
                    $Email = $Token;
                }
            }
            else {
                # No, just add as phrase
                $Phrase = defined($Phrase) ? $Phrase . " " . $Token : $Token;
            }
        }
        elsif ($Type == IsEmail) {
             # If an email, set email addr. Should be empty
             $Email = $Token;
        }
        elsif ($Type == IsComment) {
            $Comment = defined($Comment) ? $Comment . ", " . $Token : $Token;
        }
        # Must be separator, do nothing
    }

    # Add any remaining addresses
    push @Addrs, $Email if defined($Email);

    if ( ! @Addrs ) {
        # We couldn't parse, so just run with it and hope for the best
        push @Addrs, $Str;
        $self->log_error( 'Could not parse address ' . $Str );
    }

    my @TidyAddresses;
    foreach my $Address ( @Addrs ) {

        next if ( $Address =~ /\@unspecified-domain$/ );

        if ( $Address =~ /^mailto:(.*)$/ ) {
            $Address = $1;
        }

        # Trim whitelist that's possible, but not useful and
        #  almost certainly a copy/paste issue
        #  e.g. < foo @ bar.com >

        $Address =~ s/^\s+//;
        $Address =~ s/\s+$//;
        $Address =~ s/\s+\@/\@/;
        $Address =~ s/\@\s+/\@/;

        push @TidyAddresses, $Address;
    }

    if ( ! @TidyAddresses ) {
        # We really couldn't parse, so just run with it and hope for the best
        push @TidyAddresses, $Str;
    }

    return \@TidyAddresses;

}

sub get_my_hostname {
    my ($self) = @_;
    my $hostname = $self->get_symbol('j');
    if ( ! $hostname ) {
        $hostname = $self->get_symbol('{rcpt_host}');
    }
    if ( ! $hostname ) { # Fallback
        $hostname = hostname;
    }
    return $hostname;
}



# Logging

sub dbgout {
    my ( $self, $key, $value, $priority ) = @_;
    my $queue_id = $self->get_symbol('i') || q{--};
    $key   = q{--} if ! defined $key;
    $value = q{--} if ! defined $value;

    my $config = $self->config();
    if (
        $priority == LOG_DEBUG
        &&
        ! $config->{'debug'}
    ) {
        return;
    }

    if ( $self->config()->{'logtoerr'} ) {
        Mail::Milter::Authentication::_warn( "$queue_id: $key: $value" );
    }

    my $top_handler = $self->get_top_handler();
    if ( !exists( $top_handler->{'dbgout'} ) ) {
        $top_handler->{'dbgout'} = [];
    }
    push @{ $top_handler->{'dbgout'} },
      {
        'priority' => $priority || LOG_INFO,
        'key'      => $key      || q{},
        'value'    => $value    || q{},
      };

    # Write now if we can.
    if ( $self->get_symbol('i') ) {
        $self->dbgoutwrite();
    }

    return;
}

sub log_error {
    my ( $self, $error ) = @_;
    $self->dbgout( 'ERROR', $error, LOG_ERR );
    return;
}

sub dbgoutwrite {
    my ($self) = @_;
    eval {
        my $config = $self->config();
        my $queue_id = $self->get_symbol('i') ||
            'NOQUEUE.' . substr( uc md5_hex( "Authentication Milter Client $PID " . time() . rand(100) ) , -11 );
        my $top_handler = $self->get_top_handler();
        if ( exists( $top_handler->{'dbgout'} ) ) {
            LOGENTRY:
            foreach my $entry ( @{ $top_handler->{'dbgout'} } ) {
                my $key      = $entry->{'key'};
                my $value    = $entry->{'value'};
                my $priority = $entry->{'priority'};
                my $line     = "$queue_id: $key: $value";
                if (
                    $priority == LOG_DEBUG
                    &&
                    ! $config->{'debug'}
                ) {
                    next LOGENTRY;
                }
                syslog( $priority, $line );
            }
        }
        delete $top_handler->{'dbgout'};
    };
    return;
}



# Header handling

sub can_sort_header {
    my ( $self, $header ) = @_;
    return 0;
}

sub header_sort {
    my ( $self, $sa, $sb ) = @_;

    my $config = $self->config();

    my ( $handler_a ) = split( '=', $sa, 2 );
    my ( $handler_b ) = split( '=', $sb, 2 );

    if ( $handler_a eq $handler_b ) {
        # Check for a handler specific sort method
        foreach my $name ( @{$config->{'load_handlers'}} ) {
            my $handler = $self->get_handler($name);
            if ( $handler->can_sort_header( lc $handler_a ) ) {
                if ( $handler->can( 'handler_header_sort' ) ) {
                    return $handler->handler_header_sort( $sa, $sb );
                }
            }
        }
    }

    return $sa cmp $sb;
}

sub add_headers {
    my ($self) = @_;

    my $config = $self->config();

    my $header = $self->get_my_hostname();
    my @auth_headers;
    my $top_handler = $self->get_top_handler();
    if ( exists( $top_handler->{'c_auth_headers'} ) ) {
        @auth_headers = @{ $top_handler->{'c_auth_headers'} };
    }
    if ( exists( $top_handler->{'auth_headers'} ) ) {
        @auth_headers = ( @auth_headers, @{ $top_handler->{'auth_headers'} } );
    }
    if (@auth_headers) {
        $header .= ";\n    ";
        $header .= join( ";\n    ", sort { $self->header_sort( $a, $b ) } @auth_headers );
    }
    else {
        $header .= '; none';
    }

    $self->prepend_header( 'Authentication-Results', $header );

    eval {
        local $SIG{'ALRM'} = sub{ die "Timeout\n" };
        if ( $config->{'addheader_timeout'} ) {
            alarm( $config->{'addheader_timeout'} );
        }
        my $callbacks = $self->get_callbacks( 'addheader' );
        foreach my $handler ( @$callbacks ) {
            my $start_time = $self->get_microseconds();
            $self->get_handler($handler)->addheader_callback($self);
            $self->metric_count( 'time_microseconds_total', { 'callback' => 'addheader', 'handler' => $handler }, $self->get_microseconds() - $start_time );
        }
        alarm(0);
    };
    if ( my $error = $@ ) {
        $self->metric_count( 'callback_error_total', { 'stage' => 'addheader' } );
        $self->log_error( 'Final callback error ' . $error );
        $self->exit_on_close();
        $self->tempfail_on_error();
    }

    if ( exists( $top_handler->{'pre_headers'} ) ) {
        foreach my $header ( @{ $top_handler->{'pre_headers'} } ) {
            $self->dbgout( 'PreHeader',
                $header->{'field'} . ': ' . $header->{'value'}, LOG_INFO );
            $self->insert_header( 1, $header->{'field'}, $header->{'value'} );
        }
    }

    if ( exists( $top_handler->{'add_headers'} ) ) {
        foreach my $header ( @{ $top_handler->{'add_headers'} } ) {
            $self->dbgout( 'AddHeader',
                $header->{'field'} . ': ' . $header->{'value'}, LOG_INFO );
            $self->add_header( $header->{'field'}, $header->{'value'} );
        }
    }

    return;
}

sub prepend_header {
    my ( $self, $field, $value ) = @_;
    my $top_handler = $self->get_top_handler();
    if ( !exists( $top_handler->{'pre_headers'} ) ) {
        $top_handler->{'pre_headers'} = [];
    }
    push @{ $top_handler->{'pre_headers'} },
      {
        'field' => $field,
        'value' => $value,
      };
    return;
}

sub add_auth_header {
    my ( $self, $value ) = @_;
    my $top_handler = $self->get_top_handler();
    if ( !exists( $top_handler->{'auth_headers'} ) ) {
        $top_handler->{'auth_headers'} = [];
    }
    push @{ $top_handler->{'auth_headers'} }, $value;
    return;
}

sub add_c_auth_header {

    # Connection wide auth headers
    my ( $self, $value ) = @_;
    my $top_handler = $self->get_top_handler();
    if ( !exists( $top_handler->{'c_auth_headers'} ) ) {
        $top_handler->{'c_auth_headers'} = [];
    }
    push @{ $top_handler->{'c_auth_headers'} }, $value;
    return;
}

sub append_header {
    my ( $self, $field, $value ) = @_;
    my $top_handler = $self->get_top_handler();
    if ( !exists( $top_handler->{'add_headers'} ) ) {
        $top_handler->{'add_headers'} = [];
    }
    push @{ $top_handler->{'add_headers'} },
      {
        'field' => $field,
        'value' => $value,
      };
    return;
}



# Lower level methods

sub smfis_continue {
    return SMFIS_CONTINUE;
}

sub smfis_tempfail {
    return SMFIS_TEMPFAIL;
}

sub smfis_reject {
    return SMFIS_REJECT;
}

sub smfis_discard {
    return SMFIS_DISCARD;
}

sub smfis_accept {
    return SMFIS_ACCEPT;
}



sub write_packet {
    my ( $self, $type, $data ) = @_;
    my $thischild = $self->{'thischild'};
    $thischild->write_packet( $type, $data );
    return;
}

sub add_header {
    my ( $self, $key, $value ) = @_;
    my $thischild = $self->{'thischild'};
    my $config = $self->config();
    return if $config->{'dryrun'};
    $thischild->add_header( $key, $value );
    return;
}

sub insert_header {
    my ( $self, $index, $key, $value ) = @_;
    my $thischild = $self->{'thischild'};
    my $config = $self->config();
    return if $config->{'dryrun'};
    $thischild->insert_header( $index, $key, $value );
    return;
}

sub change_header {
    my ( $self, $key, $index, $value ) = @_;
    my $thischild = $self->{'thischild'};
    my $config = $self->config();
    return if $config->{'dryrun'};
    $thischild->change_header( $key, $index, $value );
    return;
}

1;

__END__

=head1 NAME

Mail::Milter::Authentication::Handler - Main handler class and methods

=head1 DESCRIPTION

Handle the milter requests and pass off to individual handlers

=head1 CONSTRUCTOR

=over

=item new( $thischild )

my $object = Mail::Milter::Authentication::Handler->new( $thischild );

Takes the argument of the current Mail::Milter::Authentication object
and creates a new handler object.

=back

=head1 METHODS

=over

=item get_version()

Return the version of this handler

=item get_json ( $file )

Retrieve json data from external file

=item metric_register( $id, $help )

Register a metric type

=item metric_count( $id, $labels, $count )

Increment a metrics counter by $count (defaults to 1 if undef)

=item metric_send()

Send metrics to the parent

=item register_metrics

Return details of the metrics this module exports.

=item get_microseconds()

Return current time in microseconds

=item top_setup_callback()

Top level handler for handler setup.

=item top_connect_callback( $hostname, $ip )

Top level handler for the connect event.

=item top_helo_callback( $helo_host )

Top level handler for the HELO event.

=item top_envfrom_callback( $env_from )

Top level handler for the MAIL FROM event.

=item top_envrcpt_callback( $env_to )

Top level handler for the RCPT TO event.

=item top_header_callback( $header, $value )

Top level handler for a Mail Header event.

=item top_eoh_callback()

Top level handler for the end of headers event.

=item top_body_callback( $body_chunk )

Top level handler for a Body Chunk event.

=item top_eom_callback()

Top level handler for the End of Message event.

=item apply_policy()

Apply a policy to the generated authentication results

=item top_abort_callback()

Top level handler for the Abort event.

=item top_close_callback()

Top level handler for the Close event.

=item status( $status )

Set the status of the current child as visible by ps.

=item config()

Return the configuration hashref.

=item handler_config( $type )

Return the configuration for the current handler.

=item handler_type()

Return the current handler type.

=item set_return( $code )

Set the return code to be passed back to the MTA.

=item get_return()

Get the current return code.

=item get_reject_mail()

Get the reject mail reason (or undef)

=item clear_reject_mail()

Clear the reject mail reason

=item get_top_handler()

Return the current top Handler object.

=item is_handler_loaded( $name )

Check if the named handler is loaded.

=item get_handler( $name )

Return the named handler object.

=item get_callbacks( $callback )

Return the list of handlers which have callbacks for the given event in the order they must be called in.

=item set_object_maker( $name, $ref )

Register an object maker for type 'name'

=item get_object( $name )

Return the named object from the object store.

Object 'resolver' will be created if it does not already exist.

Object 'spf_server' will be created by the SPF handler if it does not already exist.

Handlers may register makers for other types as required.

=item set_object( $name, $object, $destroy )

Store the given object in the object store with the given name.

If $destroy then the object will be destroyed when the connection to the child closes

=item destroy_object( $name )

Remove the reference to the named object from the object store.

=item destroy_all_objects()

Remove the references to all objects currently stored in the object store.

Certain objects (resolver and spf_server) are not destroyed for performance reasons.

=item exit_on_close()

Exit this child once it has completed, do not process further requests with this child.

=item reject_mail( $reason )

Reject mail with the given reason

=item clear_all_symbols()

Clear the symbol store.

=item clear_symbols()

Clear the symbol store but do not remove the Connect symbols.

=item set_symbol( $code, $key, $value )

Store the key value pair in the symbol store with the given code (event stage).

=item get_symbol( $searchkey )

Return a value from the symbol store, searches all codes for the given key.

=item tempfail_on_error()

Returns a TEMP FAIL to the calling MTA if the configuration is set to do so.

Config can be set for all, authenticated, local, and trusted connections.

=item is_local_ip_address()

Is the current connection from a local ip address?

Requires the LocalIP Handler to be loaded.

=item is_trusted_ip_address()

Is the current connection from a trusted ip address?

Requires the TrustedIP Handler to be loaded.

=item is_authenticated()

Is the current connection authenticated?

Requires the Auth Handler to be loaded.

=item ip_address()

Return the ip address of the current connection.

=item format_ctext( $text )

Format text as ctext for use in headers.

=item format_ctext_no_space( $text )

Format text as ctext with no spaces for use in headers.

=item format_header_comment( $comment )

Format text as a comment for use in headers.

=item format_header_entry( $key, $value )

Format text as a key value pair for use in authentication header.

=item get_domain_from( $address )

Extract the domain from an email address.

=item get_domains_from( $address )

Extract the domains from an email address as an arrayref.

=item get_address_from( $text )

Extract an email address from a string.

=item get_addresses_from( $text )

Extract all email address from a string as an arrayref.

=item get_my_hostname()

Return the effective hostname of the MTA.

=item dbgout( $key, $value, $priority )

Send output to debug and/or Mail Log.

priority is a standard Syslog priority.

=item log_error( $error )

Log an error.

=item dbgoutwrite()

Write out logs to disc.

Logs are not written immediately, they are written at the end of a connection so we can
include a queue id. This is not available at the start of the process.

=item can_sort_header( $header )

Returns 1 is this handler has a header_sort method capable or sorting entries for $header
Returns 0 otherwise

=item header_sort()

Sorting function for sorting the Authentication-Results headers
Calls out to __HANDLER__->header_sort() to sort headers of a particular type if available,
otherwise sorts alphabetically.

=item add_headers()

Send the header changes to the MTA.

=item prepend_header( $field, $value )

Add a trace header to the email.

=item add_auth_header( $value )

Add a section to the authentication header for this email.

=item add_c_auth_header( $value )

Add a section to the authentication header for this email, and to any subsequent emails for this connection.

=item append_header( $field, $value )

Add a normal header to the email.

=item smfis_continue()

Return Continue code.

=item smfis_tempfail()

Return TempFail code.

=item smfis_reject()

Return Reject code.

=item smfis_discard()

Return Discard code.

=item smfis_accept()

Return Accept code.

=item write_packet( $type, $data )

Write a packet to the MTA (calls Protocol object)

=item add_header( $key, $value )

Write an Add Header packet to the MTA (calls Protocol object)

=item insert_header( $index, $key, $value )

Write an Insert Header packet to the MTA (calls Protocol object)

=item change_header( $key, $index, $value )

Write a Change Header packet to the MTA (calls Protocol object)

=back

=head1 WRITING HANDLERS

tbc

=head1 AUTHORS

Marc Bradshaw E<lt>marc@marcbradshaw.netE<gt>

=head1 COPYRIGHT

Copyright 2017

This library is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.



