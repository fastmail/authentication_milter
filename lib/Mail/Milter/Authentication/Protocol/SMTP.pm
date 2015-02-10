package Mail::Milter::Authentication::Protocol::SMTP;
use strict;
use warnings;
our $VERSION = 0.7;

use English qw{ -no_match_vars };
use Email::Date::Format qw{ email_date };
use Email::Simple;
use IO::Socket;
use IO::Socket::INET;
use IO::Socket::UNIX;
use Digest::MD5 qw{ md5_hex };
use Net::IP;
use Sys::Syslog qw{:standard :macros};

use Mail::Milter::Authentication::Constants qw{ :all };

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
    $handler->dbgout( 'SMTP Transaction count', $smtp->{'count'} , LOG_INFO );

    $smtp->{'init_required'} = 0;

    return;
}

sub protocol_process_request {
    my ( $self ) = @_;

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
    my $handler = $self->{'handler'}->{'_Handler'};

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

        $self->logdebug( "receive command $command" );

        my $returncode = SMFIS_CONTINUE;

        if ( $command =~ /^EHLO/ ) {
            $self->smtp_command_ehlo( $command );
        }
        elsif ( $command =~ /^LHLO/ ) {
            $self->smtp_command_lhlo( $command );
        }
        elsif ( $command =~ /^HELO/ ) {
            $self->smtp_command_helo( $command );
        }
        elsif ( $command =~ /^XFORWARD/ ) {
            $self->smtp_command_xforward( $command );
        }
        elsif ( $command =~ /^MAIL FROM:/ ) {
            $self->smtp_init();
            $self->smtp_command_mailfrom( $command );
        }
        elsif ( $command =~ /^RCPT TO:/ ) {
            $self->smtp_command_rcptto( $command );
        }
        elsif ( $command =~ /^RSET/ ) {
            $self->smtp_command_rset( $command );
        }
        elsif ( $command =~ /^DATA/ ) {
            $self->smtp_command_data( $command );
        }
        elsif ( $command =~ /^QUIT/ ){
            print $socket "221 2.0.0 Bye\n";
            last COMMAND;
        }
        else {
            $self->logerror( "Unknown SMTP command: $command" );
            print $socket "502 5.5.2 I don't understand\r\n";
        }

    }

    $self->close_destination_socket();

    delete $self->{'smtp'};
    return;
}

sub smtp_queue_id {
    my ( $self ) = @_;
    my $smtp = $self->{'smtp'};
    my $queue_id = $smtp->{'queue_id'};
    if ( $smtp->{'fwd_ident'} ) {
        $queue_id .= '.' . $smtp->{'fwd_ident'};
    }
    return $queue_id;
}

sub smtp_command_lhlo {
    my ( $self, $command ) = @_;
    my $smtp = $self->{'smtp'};
    my $socket = $self->{'socket'};
    my $handler = $self->{'handler'}->{'_Handler'};

    $smtp->{'using_lmtp'} = 1;

    if ( $smtp->{'has_data'} ) {
        $self->logerror( "Out of Order SMTP command: $command" );
        print $socket "501 5.5.2 Out of Order\r\n";
        return;
    }
    $smtp->{'helo_host'} = substr( $command,5 );
    print $socket "250-" . $smtp->{'server_name'} . "\r\n";
    print $socket "250-XFORWARD NAME ADDR IDENT HELO\r\n";
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

    if ( $smtp->{'has_data'} ) {
        $self->logerror( "Out of Order SMTP command: $command" );
        print $socket "501 5.5.2 Out of Order\r\n";
        return;
    }
    $smtp->{'helo_host'} = substr( $command,5 );
    print $socket "250-" . $smtp->{'server_name'} . "\r\n";
    print $socket "250-XFORWARD NAME ADDR IDENT HELO\r\n";
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

    if ( $smtp->{'has_data'} ) {
        $self->logerror( "Out of Order SMTP command: $command" );
        print $socket "501 5.5.2 Out of Order\r\n";
        return;
    }
    $smtp->{'helo_host'} = substr( $command,5 );
    print $socket "250 " . $smtp->{'server_name'} . " Hi " . $smtp->{'helo_host'} . "\r\n";
    return;
}

sub smtp_command_xforward {
    my ( $self, $command ) = @_;
    my $smtp = $self->{'smtp'};
    my $socket = $self->{'socket'};
    my $handler = $self->{'handler'}->{'_Handler'};

    $self->smtp_init();

    if ( $smtp->{'has_data'} ) {
        $self->logerror( "Out of Order SMTP command: $command" );
        print $socket "503 5.5.2 Out of Order\r\n";
        return;
    }
    my $xdata = substr( $command,9 );
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
            $smtp->{'fwd_ident'} = $value;
            $handler->set_symbol( 'C', 'i', $self->smtp_queue_id() );
            $handler->dbgout( 'Upstream ID', $value, LOG_INFO );
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
    print $socket "250 2.0.0 Ok\r\n";
    $self->{'handler'}->{'_Handler'}->top_close_callback();

    $smtp->{'init_required'}    = 1;
    $self->smtp_init();

    return;
}

sub smtp_command_mailfrom {
    my ( $self, $command ) = @_;
    my $smtp = $self->{'smtp'};
    my $socket = $self->{'socket'};
    my $handler = $self->{'handler'}->{'_Handler'};

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

    $smtp->{'has_mail_from'} = 1;

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
            my $envfrom = substr( $command,10 );
            $smtp->{'mail_from'} = $envfrom;
            $envfrom =~ s/ BODY=8BITMIME$//;
            $returncode = $handler->top_envfrom_callback( $envfrom );
            if ( $returncode == SMFIS_CONTINUE ) {
                print $socket "250 2.0.0 Ok\r\n";
            }
            else {
                print $socket "451 4.0.0 MAIL - That's not right\r\n";
            }
        }
        else { 
            print $socket "451 4.0.0 HELO - That's not right\r\n";
        }
    }
    else { 
        print $socket "451 4.0.0 Connection - That's not right\r\n";
    }
    
    return;
}

sub smtp_command_rcptto {
    my ( $self, $command ) = @_;
    my $smtp = $self->{'smtp'};
    my $socket = $self->{'socket'};
    my $handler = $self->{'handler'}->{'_Handler'};

    if ( $smtp->{'has_data'} ) {
        $self->logerror( "Out of Order SMTP command: $command" );
        print $socket "503 5.5.2 Out of Order\r\n";
        return;
    }
    my $envrcpt = substr( $command,8 );
    push @{ $smtp->{'rcpt_to'} }, $envrcpt;
    my $returncode = $handler->top_envrcpt_callback( $envrcpt );
    if ( $returncode == SMFIS_CONTINUE ) {
        push @{ $smtp->{'lmtp_rcpt'} }, $envrcpt;  
        print $socket "250 2.0.0 Ok\r\n";
    }
    else {
        print $socket "451 4.0.0 That's not right\r\n";
    }

    return;
}

sub smtp_command_data {
    my ( $self, $command ) = @_;
    my $smtp = $self->{'smtp'};
    my $socket = $self->{'socket'};
    my $handler = $self->{'handler'}->{'_Handler'};

    my $headers = q{};
    my $body    = q{};
    my $done    = 0;
    my $fail    = 0;
    my $returncode;

    if ( $smtp->{'has_data'} ) {
        $self->logerror( "Repeated SMTP DATA command: $command" );
        print $socket "503 5.5.2 One at a time please\r\n";
        return;
    }
    $smtp->{'has_data'} = 1;
    print $socket "354 2.0.0 Send body\r\n";

    local $SIG{'ALRM'} = sub{ die "Timeout\n" };
    eval{
        alarm( $smtp->{'smtp_timeout_in'} );
        HEADERS:
        while ( my $dataline = <$socket> ) {
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
            $headers .= $dataline . "\r\n";
        }
    };
    if ( my $error = $@ ) {
        $self->logerror( "Read Error: $error" );
        $done = 1;
        $fail = 1;
    }
    alarm( 0 );

    {
        my $message_object = Email::Simple->new( $headers );
        my $header_object = $message_object->header_obj();
        my @header_pairs = $header_object->header_pairs();
        while ( @header_pairs ) {
            my $key   = shift @header_pairs;
            my $value = shift @header_pairs;
            push @{ $smtp->{'headers'} } , {
                'key'   => $key,
                'value' => $value,
            };
            my $returncode = $handler->top_header_callback( $key, $value );
            if ( $returncode != SMFIS_CONTINUE ) {
                $fail = 1;
            }
        }
    }

    $returncode = $handler->top_eoh_callback();
    if ( $returncode != SMFIS_CONTINUE ) {
        $fail = 1;
    }

    if ( ! $done ) {
        eval {
            alarm( $smtp->{'smtp_timeout_in'} );
            DATA:
            while ( my $dataline = <$socket> ) {
                alarm( 0 );
                last DATA if $dataline =~  /^\.\r\n/;
                # Handle transparency
                if ( $dataline =~ /^\./ ) {
                    $dataline = substr( $dataline, 1 );
                }
                $body .= $dataline;
            }
            $returncode = $handler->top_body_callback( $body );
            if ( $returncode != SMFIS_CONTINUE ) {
                $fail = 1;
            }
        };
        if ( my $error = $@ ) {
            $self->logerror( "Read Error: $error" );
            $done = 1;
            $fail = 1;
        }
        alarm( 0 );
    }

    $returncode = $handler->top_eom_callback();
    if ( $returncode != SMFIS_CONTINUE ) {
        $fail = 1;
    }

    if ( ! $fail ) {
        $smtp->{'body'} = $body;

        if ( $self->smtp_forward_to_destination() ) {

            $handler->dbgout( 'Accept string', $smtp->{'string'}, LOG_INFO );

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
            my $error =  '451 4.0.0 That\'s not right';
            my $upstream_error = $smtp->{'string'};
            if ( $upstream_error =~ /^451 / ) {
                $error = $upstream_error;
            }
            elsif ( $upstream_error =~ /^554 / ) {
                # Also pass back rejects
                $error = $upstream_error;
            }
            else {
                $error .= ': ' . $upstream_error;
            }
            print $socket "$error\r\n";
        }
    }
    else { 
        print $socket "451 4.0.0 That's not right\r\n";
    }

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

    splice @{ $smtp->{'headers'} }, 0, 0, {
        'key'   => 'Received',
        'value' => $value,
    };
    return;
}

sub smtp_forward_to_destination {
    my ( $self ) = @_;

    my $smtp = $self->{'smtp'};

    $self->smtp_insert_received_header();

    my $smtp_conf = $self->get_smtp_config();

    my $sock = $smtp->{'destination_sock'};

    my $new_sock = 0;

    my $line;

    if ( ! $sock ) {
        $new_sock = 1;

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


    local $SIG{'ALRM'} = sub{ die "Timeout\n" };
    alarm( $smtp->{'smtp_timeout_out'} );

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
    $self->send_smtp_packet( $sock, 'DATA', '354' ) || return;

    my $email = q{};
    foreach my $header ( @{ $smtp->{'headers'} } ) {
        my $key   = $header->{'key'};
        my $value = $header->{'value'};
        $email .= "$key: $value\r\n";
    }
    $email .= "\r\n";

    my $body = $smtp->{'body'};
    $body =~ s/\015?\012/\015\012/g;
    $email .= $body;
    
    # Handle transparency
    $email =~ s/\015\012\./\015\012\.\./g;

    print $sock $email;
    
    $self->send_smtp_packet( $sock, '.',    '250' ) || return;

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
    print $socket "$send\r\n";

    my $smtp = $self->{'smtp'};

    local $SIG{'ALRM'} = sub{ die "Timeout\n" };
    alarm( $smtp->{'smtp_timeout_out'} );
    my $recv;
    eval {
        $recv = <$socket>;
    };
    if ( my $error = $@ ) {
        $self->logerror( "Outbound SMTP Read Error: $error" );
        $smtp->{'string'} = $error;
        return 0;
    }
    alarm( 0 );

    while ( $recv =~ /^\d\d\d\-/ ) {
        $recv = <$socket>;
    }

    $smtp->{'string'} = $recv;
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
    push @{ $smtp->{'headers'} } , {
        'key'   => $header,
        'value' => $value,
    };
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
        if ( $header_v->{'key'} eq $header ) {
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
            $smtp->{'headers'}->[ $result_i ]->{'value'} = $value;
            #untested.
        }
    }

    return;
}

sub insert_header {
    my ( $self, $index, $key, $value ) = @_;
    my $smtp = $self->{'smtp'};
    $value =~ s/\015?\012/\015\012/g;
    splice @{ $smtp->{'headers'} }, $index - 1, 0, {
        'key'   => $key,
        'value' => $value,
    };
    return;
}

1;

__END__

=head1 NAME

Mail::Milter::Authentication::Protocol::SMTP - SMTP protocol specific methods

=head1 DESCRIPTION

A PERL implemtation of email authentication standards rolled up into a single easy to use milter.

=head1 SYNOPSIS

Subclass of Net::Server::PreFork for bringing up the main server process for authentication_milter.

Please see Net::Server docs for more detail of the server code.

=head1 METHODS

=over

=item I<protocol_process_request( $command, $buffer )>

Process the command from the SMTP protocol stream.

=item I<get_smtp_config()>

Return the SMTP config for the given connection, or
the default config if no connection specific config
exists.

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

=back

=head1 DEPENDENCIES

  English
  Digest::MD5
  Net::IP

=head1 AUTHORS

Marc Bradshaw E<lt>marc@marcbradshaw.netE<gt>

=head1 COPYRIGHT

Copyright 2015

This library is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.


