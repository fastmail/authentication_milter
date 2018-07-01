package Mail::Milter::Authentication::Protocol::SMTP;
use strict;
use warnings;
# VERSION

use English qw{ -no_match_vars };
use Email::Date::Format qw{ email_date };
use File::Temp;
use IO::Socket;
use IO::Socket::INET;
use IO::Socket::UNIX;
use Digest::MD5 qw{ md5_hex };
use Net::IP;
use Sys::Syslog qw{:standard :macros};

use Mail::Milter::Authentication::Constants qw{ :all };
use Mail::Milter::Authentication::Config;

sub register_metrics {
    return {
        'mail_processed_total' => 'Number of emails processed',
    };
}

sub get_smtp_config {
    my ( $self ) = @_;
    my $client_details = $self->get_client_details();
    my $smtp_config;

    if ( exists( $self->{'config'}->{'smtp'}->{ $client_details } ) ) {
        $smtp_config = $self->{'config'}->{'smtp'}->{ $client_details };
    }
    else {
        $smtp_config = $self->{'config'}->{'smtp'};
    }

    return $smtp_config;
}

sub queue_type {
    my ( $self ) = @_;
    my $smtp_config = $self->get_smtp_config();
    return $smtp_config->{'queue_type'} eq 'before' ? 'before' : 'after';
}

sub smtp_status {
    my ( $self, $status ) = @_;
    my $smtp = $self->{'smtp'};
    $PROGRAM_NAME = $Mail::Milter::Authentication::Config::IDENT . ':' . $status . '(' . $self->{'count'} . '.' . $smtp->{'count'} . ')';
    return;
}

sub smtp_init {
    my ( $self ) = @_;

    return if $self->{'smtp'}->{'init_required'} == 0;

    my $handler = $self->{'handler'}->{'_Handler'};
    my $smtp = $self->{'smtp'};

    $handler->set_symbol( 'C', 'j', $smtp->{'server_name'} );
    $handler->set_symbol( 'C', '{rcpt_host}', $smtp->{'server_name'} );

    $smtp->{'queue_id'} = substr( uc md5_hex( "Authentication Milter Client $PID " . time() . rand(100) ) , -11 );
    $handler->set_symbol( 'C', 'i', $self->smtp_queue_id() );

    $smtp->{'count'}++ ;
    $handler->dbgout( 'SMTP Transaction count', $self->{'count'} . '.' . $smtp->{'count'} , LOG_INFO );

    $smtp->{'init_required'} = 0;

    return;
}

sub protocol_process_request {
    my ( $self ) = @_;

    my $handler = $self->{'handler'}->{'_Handler'};
    $handler->top_setup_callback();

    my $config = $self->{ 'config' };
    my $seconds = $config->{'content_timeout'} // 300;
    $handler->set_overall_timeout( $seconds * 1000000 );

    $self->{'smtp'} = {
        'fwd_helo_host'    => undef,
        'fwd_connect_ip'   => undef,
        'fwd_connect_host' => undef,
        'fwd_ident'        => undef,
        'helo_host'        => q{},
        'mail_from'        => q{},
        'rcpt_to'          => [],
        'has_mail_from'    => 0,
        'has_data'         => 0,
        'connect_ip'       => $self->{'server'}->{'peeraddr'},
        'connect_host'     => $self->{'server'}->{'peeraddr'},
        'last_command'     => 0,
        'headers'          => [],
        'body'             => q{},
        'using_lmtp'       => 0,
        'lmtp_rcpt'        => [],
        'init_required'    => 1,
        'string'           => q{},
        'count'            => 0,
    };

    # If we have a UNIX connection then these will be undef,
    # Set them to localhost to avoid warnings later.
    if ( ! $self->{'smtp'}->{'connect_ip'} ) { $self->{'smtp'}->{'connect_ip'} = '127.0.0.1'; }

    if ( $self->{'smtp'}->{'connect_ip'} eq '127.0.0.1' ) {
        $self->{'smtp'}->{'connect_host'} = 'localhost';
    }
    else {
        # TODO do a reverse lookup  here!
    }

    my $smtp = $self->{'smtp'};
    my $socket = $self->{'socket'};

    my $smtp_config = $self->get_smtp_config();
    $smtp->{'server_name'} = $smtp_config->{'server_name'} || 'server.example.com';
    $smtp->{'smtp_timeout_in'}  = $smtp_config->{'timeout_in'}  || 60;
    $smtp->{'smtp_timeout_out'} = $smtp_config->{'timeout_out'} || 60;

    print $socket "220 " . $smtp->{'server_name'} . " ESMTP AuthenticationMilter\r\n";

    $self->smtp_init();

    COMMAND:
    while ( ! $smtp->{'last_command'} ) {

        my $command;
        local $SIG{'ALRM'} = sub{ die "Timeout\n" };
        alarm( $smtp->{'smtp_timeout_in'} );
        eval {
            $command = <$socket>;
        };
        if ( my $error = $@ ) {
            $self->logerror( "Read Error: $error" );
            last COMMAND;
        }
        alarm( 0 );

        if ( ! $command ) {
            $self->logdebug( "receive NULL command" );
            last COMMAND;
        }

        $command =~ s/\r?\n$//;
        my $uccommand = uc $command;

        $self->logdebug( "receive command $command" );

        if ( exists ( $smtp_config->{ 'debug_triggers' } ) ) {
            my $triggers = $smtp_config->{ 'debug_triggers' };
            foreach my $trigger ( @$triggers ) {
                if ( $command =~ /$trigger/ ) {
                    $self->enable_extra_debugging();
                }
            }
        }

        my $returncode = SMFIS_CONTINUE;

        if ( $uccommand =~ /^EHLO/ ) {
            $self->smtp_command_ehlo( $command );
        }
        elsif ( $uccommand =~ /^LHLO/ ) {
            $self->smtp_command_lhlo( $command );
        }
        elsif ( $uccommand =~ /^HELO/ ) {
            $self->smtp_command_helo( $command );
        }
        elsif ( $uccommand =~ /^XFORWARD/ ) {
            $self->smtp_command_xforward( $command );
        }
        elsif ( $uccommand =~ /^MAIL FROM:/ ) {
            $self->smtp_init();
            $self->smtp_command_mailfrom( $command );
        }
        elsif ( $uccommand =~ /^RCPT TO:/ ) {
            $self->smtp_command_rcptto( $command );
        }
        elsif ( $uccommand =~ /^RSET/ ) {
            $self->smtp_command_rset( $command );
        }
        elsif ( $uccommand =~ /^DATA/ ) {
            $handler->set_overall_timeout( $seconds * 1000000 );
            $self->smtp_command_data( $command );
        }
        elsif ( $uccommand =~ /^QUIT/ ){
            $self->smtp_status('smtp.i.quit');
            print $socket "221 2.0.0 Bye\n";
            last COMMAND;
        }
        else {
            $self->smtp_status('smtp.i.unknown');
            $self->logerror( "Unknown SMTP command: $command" );
            print $socket "502 5.5.2 I don't understand\r\n";
        }

    }
    $handler->clear_overall_timeout();

    $self->smtp_status('smtp.close');

    $self->close_destination_socket();

    delete $self->{'smtp'};
    return;
}

sub smtp_queue_id {
    my ( $self ) = @_;
    my $smtp = $self->{'smtp'};
    my $queue_id = $smtp->{'queue_id'};
    if ( $smtp->{'fwd_ident'} && $smtp->{'fwd_ident'} ne '[UNAVAILABLE]' ) {
        $queue_id .= '.' . $smtp->{'fwd_ident'};
    }
    return $queue_id;
}

sub command_param {
    my ( $command, $index ) = @_;
    my $p = q{};
    if ( length( $command ) >= $index ) {
        $p = substr( $command, $index );
    }
    return $p;
}

sub smtp_command_lhlo {
    my ( $self, $command ) = @_;
    my $smtp = $self->{'smtp'};
    my $socket = $self->{'socket'};
    my $handler = $self->{'handler'}->{'_Handler'};
    $self->smtp_status('smtp.i.lhlo');

    $smtp->{'using_lmtp'} = 1;

    if ( $smtp->{'has_data'} ) {
        $self->logerror( "Out of Order SMTP command: $command" );
        print $socket "501 5.5.2 Out of Order\r\n";
        return;
    }
    $smtp->{'helo_host'} = command_param( $command,5 );
    print $socket "250-" . $smtp->{'server_name'} . "\r\n";
    if ( $self->queue_type() eq 'before' ) {
        print $socket "250-XFORWARD NAME ADDR HELO \r\n";
    }
    else {
        print $socket "250-XFORWARD NAME ADDR HELO IDENT \r\n";
    }
    print $socket "250-PIPELINING\r\n";
    print $socket "250-ENHANCEDSTATUSCODES\r\n";
    print $socket "250 8BITMIME\r\n";
    return;
}

sub smtp_command_ehlo {
    my ( $self, $command ) = @_;
    my $smtp = $self->{'smtp'};
    my $socket = $self->{'socket'};
    my $handler = $self->{'handler'}->{'_Handler'};
    $self->smtp_status('smtp.i.ehlo');

    if ( $smtp->{'has_data'} ) {
        $self->logerror( "Out of Order SMTP command: $command" );
        print $socket "501 5.5.2 Out of Order\r\n";
        return;
    }
    $smtp->{'helo_host'} = command_param( $command,5 );
    print $socket "250-" . $smtp->{'server_name'} . "\r\n";
    if ( $self->queue_type() eq 'before' ) {
        print $socket "250-XFORWARD NAME ADDR HELO \r\n";
    }
    else {
        print $socket "250-XFORWARD NAME ADDR HELO IDENT \r\n";
    }
    print $socket "250-PIPELINING\r\n";
    print $socket "250-ENHANCEDSTATUSCODES\r\n";
    print $socket "250 8BITMIME\r\n";
    return;
}

sub smtp_command_helo {
    my ( $self, $command ) = @_;
    my $smtp = $self->{'smtp'};
    my $socket = $self->{'socket'};
    my $handler = $self->{'handler'}->{'_Handler'};
    $self->smtp_status('smtp.i.helo');

    if ( $smtp->{'has_data'} ) {
        $self->logerror( "Out of Order SMTP command: $command" );
        print $socket "501 5.5.2 Out of Order\r\n";
        return;
    }
    $smtp->{'helo_host'} = command_param( $command,5 );
    print $socket "250 " . $smtp->{'server_name'} . " Hi " . $smtp->{'helo_host'} . "\r\n";
    return;
}

sub smtp_command_xforward {
    my ( $self, $command ) = @_;
    my $smtp = $self->{'smtp'};
    my $socket = $self->{'socket'};
    my $handler = $self->{'handler'}->{'_Handler'};
    $self->smtp_status('smtp.i.xforward');

    $self->smtp_init();

    if ( $smtp->{'has_data'} ) {
        $self->logerror( "Out of Order SMTP command: $command" );
        print $socket "503 5.5.2 Out of Order\r\n";
        return;
    }
    my $xdata = command_param( $command,9 );
    foreach my $entry ( split( q{ }, $xdata ) ) {
        my ( $key, $value ) = split( '=', $entry, 2 );
        if ( $key eq 'NAME' ) {
            $smtp->{'fwd_connect_host'} = $value;
        }
        elsif ( $key eq 'ADDR' ) {
            $smtp->{'fwd_connect_ip'} = $value;
        }
        elsif ( $key eq 'HELO' ) {
            $smtp->{'fwd_helo_host'} = $value;
        }
        elsif ( $key eq 'IDENT' ) {
            if ( $self->queue_type() eq 'before' ) {
                $self->logerror( "XForward IDENT received in before queue mode: $key=$value" );
            }
            else {
                $smtp->{'fwd_ident'} = $value;
                $handler->set_symbol( 'C', 'i', $self->smtp_queue_id() );
                $handler->dbgout( 'Upstream ID', $value, LOG_INFO );
            }
        }
        else {
            # NOP
            $self->logerror( "Unknown XForward Entry: $key=$value" );
            ### log it here though
        }
    }
    print $socket "250 2.0.0 Ok\r\n";
    return;
}

sub smtp_command_rset {
    my ( $self, $command ) = @_;
    my $smtp = $self->{'smtp'};
    my $socket = $self->{'socket'};
    $self->smtp_status('smtp.i.rset');
    $smtp->{'mail_from'}        = q{};
    $smtp->{'rcpt_to'}          = [];
    $smtp->{'headers'}          = [];
    $smtp->{'body'}             = q{};
    $smtp->{'has_data'}         = 0;
    $smtp->{'has_mail_from'}    = 0;
    $smtp->{'fwd_connect_host'} = undef;
    $smtp->{'fwd_connect_ip'}   = undef;
    $smtp->{'fwd_helo_host'}    = undef;
    $smtp->{'fwd_ident'}        = undef;
    $smtp->{'lmtp_rcpt'}        = [];
    $smtp->{'string'}           = q{};
    $self->{'handler'}->{'_Handler'}->top_close_callback();

    $smtp->{'init_required'}    = 1;
    $self->smtp_init();

    my $smtp_conf = $self->get_smtp_config();
    my $handler = $self->{'handler'}->{'_Handler'};
        if ( $smtp_conf->{'pipeline_limit'} ) {
        my $count = $smtp->{'count'};
        my $limit = $smtp_conf->{'pipeline_limit'};
        if ( $count > $limit ) {
            $smtp->{'last_command'} = 1;
            $handler->dbgout( 'SMTP Pipeline limit reached', 'closing on RSET', LOG_INFO );
            print $socket "421 4.3.2 Pipeline limit reached\r\n";
            return;
        }
    }
    print $socket "250 2.0.0 Ok\r\n";

    return;
}

sub smtp_command_mailfrom {
    my ( $self, $command ) = @_;
    my $smtp = $self->{'smtp'};
    my $socket = $self->{'socket'};
    my $handler = $self->{'handler'}->{'_Handler'};
    $self->smtp_status('smtp.i.mailfrom');

    my $returncode;
    if ( $smtp->{'has_data'} ) {
        $self->logerror( "Out of Order SMTP command: $command" );
        print $socket "503 5.5.2 Out of Order\r\n";
        return;
    }
    if ( $smtp->{'has_mail_from'} ) {
        $self->logerror( "Out of Order SMTP command: $command" );
        print $socket "503 5.5.1 Nested MAIL Command\r\n";
        return;
    }

    # Do connect callback here, because of XFORWARD
    my $host = $smtp->{'fwd_connect_host'} || $smtp->{'connect_host'};
    my $ip   = $smtp->{'fwd_connect_ip'}   || $smtp->{'connect_ip'};
    my $helo = $smtp->{'fwd_helo_host'}    || $smtp->{'helo_host'};

    if ( substr( $ip, 0, 5 ) eq 'IPv6:' ) {
        $ip = substr( $ip, 5 );
    }

    $self->logdebug( "Inbound IP Address $ip" );
    $returncode = $handler->top_connect_callback( $host, Net::IP->new( $ip ) );
    if ( $returncode == SMFIS_CONTINUE ) {
        $returncode = $handler->top_helo_callback( $helo );
        if ( $returncode == SMFIS_CONTINUE ) {
            my $envfrom = command_param( $command,10 );
            $smtp->{'mail_from'} = $envfrom;
            $envfrom =~ s/ BODY=8BITMIME$//;
            $returncode = $handler->top_envfrom_callback( $envfrom );
            if ( $returncode == SMFIS_CONTINUE ) {
                $smtp->{'has_mail_from'} = 1;
                print $socket "250 2.0.0 Ok\r\n";
            }
            elsif ( my $reject_reason = $handler->get_reject_mail() ) {
                $handler->clear_reject_mail();
                $self->loginfo ( "SMTPReject: $reject_reason" );
                print $socket $reject_reason . "\r\n";
            }
            elsif ( my $defer_reason = $handler->get_defer_mail() ) {
                $handler->clear_defer_mail();
                $self->loginfo ( "SMTPDefer: $defer_reason" );
                print $socket $defer_reason . "\r\n";
            }
            else {
                print $socket "451 4.0.0 MAIL - That's not right\r\n";
            }
        }
        elsif ( my $reject_reason = $handler->get_reject_mail() ) {
            $handler->clear_reject_mail();
            $self->loginfo ( "SMTPReject: $reject_reason" );
            print $socket $reject_reason . "\r\n";
        }
        elsif ( my $defer_reason = $handler->get_defer_mail() ) {
            $handler->clear_defer_mail();
            $self->loginfo ( "SMTPDefer: $defer_reason" );
            print $socket $defer_reason . "\r\n";
        }
        else {
            print $socket "451 4.0.1 HELO - That's not right\r\n";
        }
    }
    elsif ( my $reject_reason = $handler->get_reject_mail() ) {
        $handler->clear_reject_mail();
        $self->loginfo ( "SMTPReject: $reject_reason" );
        print $socket $reject_reason . "\r\n";
    }
    elsif ( my $defer_reason = $handler->get_defer_mail() ) {
        $handler->clear_defer_mail();
        $self->loginfo ( "SMTPDefer: $defer_reason" );
        print $socket $defer_reason . "\r\n";
    }
    else {
        print $socket "451 4.0.2 Connection - That's not right\r\n";
    }

    return;
}

sub smtp_command_rcptto {
    my ( $self, $command ) = @_;
    my $smtp = $self->{'smtp'};
    my $socket = $self->{'socket'};
    my $handler = $self->{'handler'}->{'_Handler'};
    $self->smtp_status('smtp.i.rcptto');

    if ( $smtp->{'has_data'} ) {
        $self->logerror( "Out of Order SMTP command: $command" );
        print $socket "503 5.5.2 Out of Order\r\n";
        return;
    }
    my $envrcpt = command_param( $command,8 );
    push @{ $smtp->{'rcpt_to'} }, $envrcpt;
    my $returncode = $handler->top_envrcpt_callback( $envrcpt );
    if ( $returncode == SMFIS_CONTINUE ) {
        push @{ $smtp->{'lmtp_rcpt'} }, $envrcpt;
        print $socket "250 2.0.0 Ok\r\n";
    }
    elsif ( my $reject_reason = $handler->get_reject_mail() ) {
        $handler->clear_reject_mail();
        $self->loginfo ( "SMTPReject: $reject_reason" );
        print $socket $reject_reason . "\r\n";
    }
    elsif ( my $defer_reason = $handler->get_defer_mail() ) {
        $handler->clear_defer_mail();
        $self->loginfo ( "SMTPDefer: $defer_reason" );
        print $socket $defer_reason . "\r\n";
    }
    else {
        print $socket "451 4.0.3 That's not right\r\n";
    }

    return;
}

sub smtp_command_data {
    my ( $self, $command ) = @_;
    my $smtp = $self->{'smtp'};
    my $socket = $self->{'socket'};
    my $handler = $self->{'handler'}->{'_Handler'};
    $self->smtp_status('smtp.i.data');

    my $body    = q{};
    my $done    = 0;
    my $fail    = 0;
    my @header_split;
    my $returncode;

    if ( $smtp->{'has_data'} ) {
        $self->logerror( "Repeated SMTP DATA command: $command" );
        print $socket "503 5.5.2 One at a time please\r\n";
        return;
    }
    print $socket "354 2.0.0 Send body\r\n";

    local $SIG{'ALRM'} = sub{ die "Timeout\n" };
    eval{
        alarm( $smtp->{'smtp_timeout_in'} );
        HEADERS:
        while ( my $dataline = <$socket> ) {
            $self->extra_debugging( "RAW DEBUG: ". $dataline );
            alarm( 0 );
            $dataline =~ s/\r?\n$//;
            if ( $dataline eq '.' ) {
                $done = 1;
                last HEADERS;
            }
            # Handle transparency
            if ( $dataline =~ /^\./ ) {
                $dataline = substr( $dataline, 1 );
            }
            if ( $dataline eq q{} ) {
                last HEADERS;
            }
            push @header_split, $dataline;
            alarm( $smtp->{'smtp_timeout_in'} );
        }
    };
    if ( my $error = $@ ) {
        $self->logerror( "Read Error: $error" );
        $done = 1;
        $fail = 1;
    }
    alarm( 0 );

    $self->smtp_status('smtp.i.data.process');
    my $value = q{};
    foreach my $header_line ( @header_split ) {
        if ( $header_line =~ /^\s/ ) {
            $value .= "\r\n" . $header_line;
        }
        else {
            if ( $value ) {
                push @{ $smtp->{'headers'} } , $value;
                my ( $hkey, $hvalue ) = split ( ':', $value, 2 );
                $hvalue =~ s/^ //;
                if ( ! $fail ) {
                    my $returncode = $handler->top_header_callback( $hkey, $hvalue );
                    if ( $returncode != SMFIS_CONTINUE ) {
                        $fail = 1;
                    }
                }
            }
            $value = $header_line;
        }
    }
    if ( $value ) {
        push @{ $smtp->{'headers'} } , $value;
        my ( $hkey, $hvalue ) = split ( ':', $value, 2 );
        $hvalue =~ s/^ //;
        if ( ! $fail ) {
            my $returncode = $handler->top_header_callback( $hkey, $hvalue );
            if ( $returncode != SMFIS_CONTINUE ) {
                $fail = 1;
            }
        }
    }
    if ( ! $fail ) {
        $returncode = $handler->top_eoh_callback();
        if ( $returncode != SMFIS_CONTINUE ) {
            $fail = 1;
        }
    }

    my $smtp_conf = $self->get_smtp_config();

    my $chunk_limit = 1048576; # Process in chunks no larger than...
    if ( exists ( $smtp_conf->{ 'chunk_limit' } ) ) {
        $chunk_limit = $smtp_conf->{ 'chunk_limit' };
    }

    my $temp_file;
    if ( exists ( $smtp_conf->{ 'temp_dir' } ) ) {
        $temp_file = File::Temp->new( DIR => $smtp_conf->{ 'temp_dir' } );
    }

    $self->smtp_status('smtp.i.body');
    my $body_chunk;
    if ( ! $done ) {
        eval {
            alarm( $smtp->{'smtp_timeout_in'} );
            DATA:
            while ( my $dataline = <$socket> ) {
                $self->extra_debugging( "RAW DEBUG: ". $dataline );
                alarm( 0 );
                last DATA if $dataline =~  /^\.\r\n/;
                # Handle transparency
                if ( $dataline =~ /^\./ ) {
                    $dataline = substr( $dataline, 1 );
                }

                if ( $temp_file ) {
                    print $temp_file $dataline;
                }
                else {
                   $body .= $dataline;
                }

                if ( length( $body_chunk ) + length( $dataline ) > $chunk_limit ) {
                    $returncode = $handler->top_body_callback( $body_chunk );
                    if ( $returncode != SMFIS_CONTINUE ) {
                        $fail = 1;
                    }
                    $body_chunk = q{};
                }

                $body_chunk .= $dataline;

                alarm( $smtp->{'smtp_timeout_in'} );
            }
            if ( ! $fail ) {
                $returncode = $handler->top_body_callback( $body_chunk );
                if ( $returncode != SMFIS_CONTINUE ) {
                    $fail = 1;
                }
                $body_chunk = q{};
            }
        };
        if ( my $error = $@ ) {
            $self->logerror( "Read Error: $error" );
            $done = 1;
            $fail = 1;
        }
        alarm( 0 );
    }

    if ( ! $fail ) {
        $returncode = $handler->top_eom_callback();
        if ( $returncode != SMFIS_CONTINUE ) {
            $fail = 1;
        }
    }

    $self->smtp_status('smtp.i.data.received');

    if ( ! $fail ) {

        if ( $temp_file ) {
            $smtp->{'spool'} = $temp_file;
        }
        else {
            $smtp->{'body'} = $body;
        }

        if ( $self->smtp_forward_to_destination() ) {

            $handler->metric_count( 'mail_processed_total', { 'result' => 'accepted' } );
            $handler->dbgout( 'Accept string', $smtp->{'string'}, LOG_INFO );
            $smtp->{'has_data'} = 1;

            if ( $smtp->{'using_lmtp'} ) {
                foreach my $rcpt_to ( @{ $smtp->{'lmtp_rcpt'} } ) {
                    print $socket "250 2.0.0 Queued as " . $self->smtp_queue_id() . "\r\n";
                }
            }
            else {
                print $socket "250 2.0.0 Queued as " . $self->smtp_queue_id() . "\r\n";
            }
        }
        else {
            $self->logerror( "SMTP Mail Rejected" );
            my $error =  '451 4.0.4 That\'s not right';
            my $upstream_error = $smtp->{'string'};
            if ( $upstream_error =~ /^4\d\d / ) {
                $handler->metric_count( 'mail_processed_total', { 'result' => 'deferred' } );
                $error = $upstream_error;
            }
            elsif ( $upstream_error =~ /^5\d\d / ) {
                # Also pass back rejects
                $handler->metric_count( 'mail_processed_total', { 'result' => 'rejected' } );
                $error = $upstream_error;
            }
            else {
                $handler->metric_count( 'mail_processed_total', { 'result' => 'deferred_error' } );
                $error .= ': ' . $upstream_error;
            }
            if ( $smtp->{'using_lmtp'} ) {
                foreach my $rcpt_to ( @{ $smtp->{'lmtp_rcpt'} } ) {
                    print $socket "$error\r\n";
                }
            }
            else {
                print $socket "$error\r\n";
            }
        }
    }
    elsif ( my $reject_reason = $handler->get_reject_mail() ) {
        $handler->metric_count( 'mail_processed_total', { 'result' => 'rejected' } );
        $handler->clear_reject_mail();
        if ( $smtp->{'using_lmtp'} ) {
            foreach my $rcpt_to ( @{ $smtp->{'lmtp_rcpt'} } ) {
                $self->loginfo ( "SMTPReject: $reject_reason" );
                print $socket $reject_reason . "\r\n";
            }
        }
        else {
            $self->loginfo ( "SMTPReject: $reject_reason" );
            print $socket $reject_reason . "\r\n";
        }
    }
    elsif ( my $defer_reason = $handler->get_defer_mail() ) {
        $handler->metric_count( 'mail_processed_total', { 'result' => 'defered' } );
        $handler->clear_defer_mail();
        if ( $smtp->{'using_lmtp'} ) {
            foreach my $rcpt_to ( @{ $smtp->{'lmtp_rcpt'} } ) {
                $self->loginfo ( "SMTPDefer: $defer_reason" );
                print $socket $defer_reason . "\r\n";
            }
        }
        else {
            $self->loginfo ( "SMTPDefer: $defer_reason" );
            print $socket $defer_reason . "\r\n";
        }
    }
    else {
        $handler->metric_count( 'mail_processed_total', { 'result' => 'deferred_error' } );
        if ( $smtp->{'using_lmtp'} ) {
            foreach my $rcpt_to ( @{ $smtp->{'lmtp_rcpt'} } ) {
                print $socket "451 4.0.5 That's not right\r\n";
            }
        }
        else {
            print $socket "451 4.0.6 That's not right\r\n";
        }
    }
    $self->smtp_status('smtp.i.data.done');

    # Reset
    $smtp->{'mail_from'}        = q{};
    $smtp->{'rcpt_to'}          = [];
    $smtp->{'headers'}          = [];
    $smtp->{'body'}             = q{};
    $smtp->{'has_data'}         = 0;
    $smtp->{'fwd_connect_host'} = undef;
    $smtp->{'fwd_connect_ip'}   = undef;
    $smtp->{'fwd_helo_host'}    = undef;
    $smtp->{'lmtp_rcpt'}        = [];
    $smtp->{'string'}           = q{};
    $self->{'handler'}->{'_Handler'}->top_close_callback();
    $smtp->{'init_required'}    = 1;
    return;
}

sub smtp_insert_received_header {
    my ( $self ) = @_;
    my $smtp = $self->{'smtp'};

    my $value = join ( q{},

        'from ',
        $smtp->{'helo_host'},
        ' (',
            $smtp->{'connect_host'}
        ,
        ' [',
            $smtp->{'connect_ip'},
        '])',
        "\r\n",

        '    by ',
        $smtp->{'server_name'},
        ' (Authentication Milter)',
        ' with ESMTP',
        "\r\n",

        '    id ',
        $self->smtp_queue_id(),
        ';',
        "\r\n",

        '    ',
        email_date(),

    );

    splice @{ $smtp->{'headers'} }, 0, 0, 'Received: '. $value;
    return;
}

sub smtp_forward_to_destination {
    my ( $self ) = @_;
    $self->smtp_status('smtp.o');

    my $smtp = $self->{'smtp'};

    $self->smtp_insert_received_header();

    my $smtp_conf = $self->get_smtp_config();

    my $sock = $smtp->{'destination_sock'};

    my $new_sock = 0;

    my $line;

    if ( $sock ) {
        if ( ! $sock->connected() ) {
            $self->logerror( "Outbound SMTP socket was disconnected by remote end" );
            undef $sock;
        }
    }

    if ( ! $sock ) {
        $new_sock = 1;
        $self->smtp_status('smtp.o.open');

        if ( $smtp_conf->{'sock_type'} eq 'inet' ) {
           $sock = IO::Socket::INET->new(
                'Proto' => 'tcp',
                'PeerAddr' => $smtp_conf->{'sock_host'},
                'PeerPort' => $smtp_conf->{'sock_port'},
            );
        }
        elsif ( $smtp_conf->{'sock_type'} eq 'unix' ) {
        $sock = IO::Socket::UNIX->new(
                'Peer' => $smtp_conf->{'sock_path'},
            );
        }
        else {
            $self->logerror( 'Outbound SMTP Socket type unknown or undefined: ' . $smtp_conf->{'sock_type'} );
            return 0;
        }

        if ( ! $sock ) {
            $self->logerror( "Could not open outbound SMTP socket: $!" );
            return 0;
        }
        eval {
            $line = <$sock>;
        };
        if ( my $error = $@ ) {
            $self->logerror( "Outbound SMTP Read Error: $error" );
            return 0;
        }
        alarm( 0 );

        if ( ! $line =~ /250/ ) {
            $self->logerror( "Unexpected SMTP response $line" );
            return 0;
        }

        $smtp->{'destination_sock'} = $sock;
    }

    $self->logdebug( 'Sending envelope to destination' );

    if ( $new_sock ) {
        $self->send_smtp_packet( $sock, 'EHLO ' .      $smtp->{'server_name'}, '250' ) || return;
    }
    else {
        $self->send_smtp_packet( $sock, 'RSET', '250' ) || return;
    }

    if ( $smtp->{'fwd_helo_host'} ) {
        $self->send_smtp_packet( $sock, 'XFORWARD HELO=' . $smtp->{'fwd_helo_host'}, '250' ) || return;
    }
    if ( $smtp->{'fwd_connect_ip'} ) {
        $self->send_smtp_packet( $sock, 'XFORWARD ADDR=' . $smtp->{'fwd_connect_ip'}, '250' ) || return;
    }
    if ( $smtp->{'fwd_connect_host'} ) {
        $self->send_smtp_packet( $sock, 'XFORWARD NAME=' . $smtp->{'fwd_connect_host'}, '250' ) || return;
    }
    if ( $smtp->{'fwd_ident'} ) {
        $self->send_smtp_packet( $sock, 'XFORWARD IDENT=' . $smtp->{'fwd_ident'}, '250' ) || return;
    }

    $self->send_smtp_packet( $sock, 'MAIL FROM:' . $smtp->{'mail_from'},   '250' ) || return;
    foreach my $rcpt_to ( @{ $smtp->{'rcpt_to'} } ) {
        $self->send_smtp_packet( $sock, 'RCPT TO:' .   $rcpt_to, '250' ) || return;
    }

    $self->logdebug( 'Sending data to destination' );
    $self->send_smtp_packet( $sock, 'DATA', '354' ) || return;

    $self->smtp_status('smtp.o.body');
    my $email = q{};
    foreach my $header ( @{ $smtp->{'headers'} } ) {
        $email .= "$header\r\n";
    }
    $email .= "\r\n";

    my $spool = $smtp->{'spool'};
    if ( $spool ) {

        # Handle transparency - should not be any in headers, but for completeness
        $email =~ s/\015\012\./\015\012\.\./g;

        print $sock $email;

        seek( $spool, 0, 0 );
        while ( my $line = <$spool> ) {
            $line =~ s/\015?\012/\015\012/g;
            $line =~ s/^\./\.\./g;
            print $sock $line;
        }

    }
    else {
        my $body = $smtp->{'body'};
        $body =~ s/\015?\012/\015\012/g;
        $email .= $body;

        # Handle transparency
        $email =~ s/\015\012\./\015\012\.\./g;

        print $sock $email;
    }

    $self->logdebug( 'Sending end to destination' );
    $self->send_smtp_packet( $sock, '.',    '250' ) || return;
    $self->logdebug( 'Sent to destination' );
    $self->smtp_status('smtp.o.done');

    return 1;
}

sub close_destination_socket {
    my ( $self ) = @_;
    my $smtp = $self->{'smtp'};
    my $sock = $smtp->{'destination_sock'};
    return if ! $sock;
    $self->send_smtp_packet( $sock, 'QUIT', '221' ) || return;
    $sock->close();
    delete $smtp->{'destination_sock'};
    return;
}

sub send_smtp_packet {
    my ( $self, $socket, $send, $expect ) = @_;
    my $smtp = $self->{'smtp'};

    my $status = lc $send;
    $status =~ s/^([^ ]+) .*$/$1/;
    $status = 'dot' if $status eq '.';
    $self->smtp_status('smtp.o.' . $status);

    print $socket "$send\r\n";

    $self->smtp_status('smtp.o.' . $status . '.wait');

    local $SIG{'ALRM'} = sub{ die "Timeout\n" };
    alarm( $smtp->{'smtp_timeout_out'} );
    my $recv;
    eval {
        $recv = <$socket>;
        $self->extra_debugging( "RAW DEBUG: ". $recv );
        while ( $recv =~ /^\d\d\d\-/ ) {
            $self->smtp_status('smtp.o.' . $status . '.waitext');
            $recv = <$socket>;
            $self->extra_debugging( "RAW DEBUG: ". $recv );
        }
    };
    if ( my $error = $@ ) {
        $self->logerror( "Outbound SMTP Read Error: $error" );
        $smtp->{'string'} = $error;
        return 0;
    }
    alarm( 0 );
    $self->smtp_status('smtp.o');

    $smtp->{'string'} = $recv || q{};
    $smtp->{'string'} =~ s/\r//g;
    $smtp->{'string'} =~ s/\n//g;

    if ( $recv =~ /^$expect/ ) {
        return 1;
    }
    else {
        $self->logerror( "SMTP Send expected $expect received $recv when sending $send" );
        return 0;
    }
}

sub add_header {
    my ( $self, $header, $value ) = @_;
    my $smtp = $self->{'smtp'};
    $value =~ s/\015?\012/\015\012/g;
    push @{ $smtp->{'headers'} } , "$header: $value";
    return;
}

sub change_header {
    my ( $self, $header, $index, $value ) = @_;
    my $smtp = $self->{'smtp'};

    my $header_i = 0;
    my $search_i  = 0;
    my $result_i;

    HEADER:
    foreach my $header_v ( @{ $smtp->{'headers'} } ) {
        if ( substr( lc $header_v, 0, length($header) + 1 ) eq lc "$header:" ) {
            $search_i ++;
            if ( $search_i == $index ) {
                $result_i = $header_i;
                last HEADER;
            }
        }
        $header_i ++;
    }

    if ( $result_i ) {
        if ( $value eq q{} ) {
            splice @{ $smtp->{'headers'} }, $result_i, 1;
        }
        else {
            $value =~ s/\015?\012/\015\012/g;
            $smtp->{'headers'}->[ $result_i ] = "$header: $value";
            #untested.
        }
    }

    return;
}

sub insert_header {
    my ( $self, $index, $key, $value ) = @_;
    my $smtp = $self->{'smtp'};
    $value =~ s/\015?\012/\015\012/g;
    splice @{ $smtp->{'headers'} }, $index - 1, 0, "$key: $value";
    return;
}

1;

__END__

=head1 DESCRIPTION

A Perl implenmetation of email authentication standards rolled up into a single easy to use milter.

=head1 SYNOPSIS

Subclass of Net::Server::PreFork for bringing up the main server process for authentication_milter.

Please see Net::Server docs for more detail of the server code.

=head1 FUNCTIONS

=over

=item I<command_param( $command, $index )>

Extract parameters from a SMTP command line.

=back

=head1 METHODS

=over

=item register_metrics

Return details of the metrics this module exports.

=item I<protocol_process_request( $command, $buffer )>

Process the command from the SMTP protocol stream.

=item I<get_smtp_config()>

Return the SMTP config for the given connection, or
the default config if no connection specific config
exists.

=item I<queue_type()>

Return the smtp queue type, either before or after
A before queue will not have an upstream queue id, an
after queue will.

=item I<send_smtp_packet( $socket, $send, $expect )>

Send an SMTP command to the protocol stream.
Expecting a response $expect.

=item I<smtp_command_data( $command )>

Process the SMTP DATA command.

=item I<smtp_command_ehlo( $command )>

Process the SMTP EHLO command.

=item I<smtp_command_helo( $command )>

Process the SMTP HELO command.

=item I<smtp_command_lhlo( $command )>

Process the LMTP LHLO command.

=item I<smtp_command_mailfrom( $command )>

Process the SMTP MAIL FROM command.

=item I<smtp_command_rcptto( $command )>

Process the SMTP RCPT TO command.

=item I<smtp_command_rset( $command )>

Process the SMTP RSET command.

=item I<smtp_command_xforward( $command )>

Process the SMTP XFORWARD command.

=item I<smtp_forward_to_destination()>

Send the received SMTP transaction on to its destination
with authentication results headers (etc) added.

=item I<close_destination_socket()>

QUIT and close the destination socket if open.

=item I<smtp_init()>

Initialise transaction data as/when required.

=item I<smtp_insert_received_header()>

Insert a SMTP Received header into the email.

=item I<smtp_queue_id()>

Return a generated Queue ID for the email.
This can include the received ID from XFORWARD.

=item I<add_header( $header, $value )>

Add a header

=item I<change_header( $header, $index, $value )>

Change a header

=item I<insert_header( $index, $key, $value )>

Insert a header

=item I<smtp_status( $status )>

Update the process name status line

=back

=head1 DEPENDENCIES

  English
  Digest::MD5
  Net::IP

