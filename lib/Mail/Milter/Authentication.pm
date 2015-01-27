package Mail::Milter::Authentication;
use strict;
use warnings;
use base 'Net::Server::PreFork';
our $VERSION = 0.6;

use Digest::MD5 qw{ md5_base64 };
use English qw{ -no_match_vars };
use Mail::Milter::Authentication::Config qw{ get_config };
use Mail::Milter::Authentication::Constants qw{ :all };
use Mail::Milter::Authentication::DNSCache;
use Mail::Milter::Authentication::Handler;
use Module::Load;
use Module::Loaded;
use Net::IP;
use Proc::ProcessTable;
use Sys::Syslog qw{:standard :macros};

sub pre_loop_hook {
    my ( $self ) = @_;
    
    # Load handlers
    my $config = get_config();
    foreach my $name ( @{$config->{'load_handlers'}} ) {
        $self->load_handler( $name );
    }

    if ( $config->{'error_log'} ) {
        open( STDERR, '>>', $config->{'error_log'} ) || die "Cannot open errlog [$!]";
        open( STDOUT, '>>', $config->{'error_log'} ) || die "Cannot open errlog [$!]";
    }

    return;
}

sub child_init_hook {
    my ( $self ) = @_;

    my $config = get_config();
    $self->{'config'} = $config;

    if ( $config->{'error_log'} ) {
        eval {
            open( STDERR, '>>', $config->{'error_log'} ) || die "Cannot open errlog [$!]";
            open( STDOUT, '>>', $config->{'error_log'} ) || die "Cannot open errlog [$!]";
        };
        if ( my $error = $@ ) {
            $self->logerror( "Child process $PID could not open the error log: $error" );
        }
    }

    $self->loginfo( "Child process $PID starting up" );
    $PROGRAM_NAME = '[authentication_milter:starting]';

    # Load handlers (again to allow for reconfiguration)
    foreach my $name ( @{$config->{'load_handlers'}} ) {
        $self->load_handler( $name );
    }

    # BEGIN MILTER PROTOCOL BLOCK
    if ( $config->{'protocol'} eq 'milter' ) {
        my $protocol  = SMFIP_NONE & ~(SMFIP_NOCONNECT|SMFIP_NOMAIL);
           $protocol &= ~SMFIP_NOHELO;
           $protocol &= ~SMFIP_NORCPT;
           $protocol &= ~SMFIP_NOBODY;
           $protocol &= ~SMFIP_NOHDRS;
           $protocol &= ~SMFIP_NOEOH;
        $self->{'protocol'} = $protocol;
    
        my $callback_flags = SMFI_CURR_ACTS|SMFIF_CHGBODY|SMFIF_QUARANTINE|SMFIF_SETSENDER;
        $self->{'callback_flags'} = $callback_flags;
    }
    # END MILTER PROTOCOL BLOCK

    my $callbacks_list = {};
    my $callbacks      = {};
    my $handler        = {};
    my $object         = {};
    my $count          = 0;

    $self->{'callbacks_list'} = $callbacks_list;
    $self->{'callbacks'}      = $callbacks;
    $self->{'count'}          = $count;
    $self->{'handler'}        = $handler;
    $self->{'object'}         = $object;

    $self->setup_handlers();

    $PROGRAM_NAME = '[authentication_milter:waiting(0)]';
    return;
}

sub child_finish_hook {
    my ($self) = @_;
    $self->loginfo( "Child process $PID shutting down" );
    $self->destroy_objects();
    return;
}

sub pre_server_close_hook {
    my ($self) = @_;
    $self->loginfo( 'Server closing down' );
    return;
}

sub process_request {
    my ( $self ) = @_;

    $self->{'count'}++;
    my $count = $self->{'count'};
    my $config = $self->{'config'};
    $PROGRAM_NAME = '[authentication_milter:processing(' . $count . ')]';
    $self->logdebug( 'Processing request ' . $self->{'count'} );
    $self->{'socket'} = $self->{'server'}->{'client'}; 

    if ( $config->{'protocol'} eq 'milter' ) {
        $self->milter_process_request();
    }
    else {
    # Assume SMTP
        $self->smtp_process_request();
    }

    # Call close callback
    $self->{'handler'}->{'_Handler'}->top_close_callback();
    if ( $self->{'handler'}->{'_Handler'}->{'exit_on_close'} ) {
        $self->fatal('exit_on_close requested');
    }

    if ( $config->{'debug'} ) {
        my $process_table = Proc::ProcessTable->new();
        foreach my $process ( @{$process_table->table} ) {
            if ( $process->pid == $PID ) {
                my $size   = $process->size;
                my $rss    = $process->rss;
                my $pctmem = $process->pctmem;
                my $pctcpu = $process->pctcpu;
                $self->loginfo( "Resource usage: ($count) size $size/rss $rss/memory $pctmem\%/cpu $pctcpu\%" );
            }
        }
    }

    delete $self->{'handler'}->{'_Handler'}->{'return_code'};
    delete $self->{'socket'};
    $PROGRAM_NAME = '[authentication_milter:waiting(' . $count . ')]';
    $self->logdebug( 'Request processing completed' );
    return;
}

sub smtp_process_request {
    my ( $self ) = @_;
   
    my $socket = $self->{'socket'};

    my $connect_ip   = $self->{'server'}->{'peeraddr'};
    my $connect_host = $self->{'server'}->{'peeraddr'}; ## TODO Lookup Name Here
    my $fwd_helo_host;
    my $helo_host;
    my $has_connected = 0;
    my $data_sent = 0;

    my $server_name = 'server.example.com';
    my $handler = $self->{'handler'}->{'_Handler'};

    # Get connect host and Connect IP from the connection here!

    print $socket "220 $server_name ESMTP AuthenticationMilter\r\n";

    $handler->set_symbol( 'C', 'j', $server_name );
    $handler->set_symbol( 'C', '{rcpt_host}', $server_name );

    my $queue_id = md5_base64( "Authentication Milter Client $PID " . time() );
    $handler->set_symbol( 'C', 'i', $queue_id );

    COMMAND:
    while ( 1 ) {

        my $command = <$socket> || last COMMAND;
        $command =~ s/\r?\n$//;

        $self->logdebug( "receive command $command" );

        my $returncode = SMFIS_CONTINUE;

        if ( $command =~ /^EHLO/ ) {
            if ( $data_sent ) {
                print $socket "501 Out of Order\r\n";
                last COMMAND;
            }
            $helo_host = substr( $command,5 );
            print $socket "250-$server_name\r\n";
            print $socket "250-XFORWARD NAME ADDR PROTO HELO\r\n";
            print $socket "250 8BITMIME\r\n";
        }
        elsif ( $command =~ /^HELO/ ) {
            if ( $data_sent ) {
                print $socket "501 Out of Order\r\n";
                last COMMAND;
            }
            $helo_host = substr( $command,5 );
            print $socket "250 $server_name Hi $helo_host\r\n";
        }
        elsif ( $command =~ /^XFORWARD/ ) {
            if ( $data_sent ) {
                print $socket "503 Out of Order\r\n";
                last COMMAND;
            }
            my $xdata = substr( $command,9 );
            foreach my $entry ( split( q{ }, $xdata ) ) {
                my ( $key, $value ) = split( '=', $entry, 2 );
                if ( $key eq 'NAME' ) {
                    $connect_host = $value;
                }
                elsif ( $key eq 'ADDR' ) {
                    $connect_ip = $value;
                }
                elsif ( $key eq 'HELO' ) {
                    $fwd_helo_host = $value;
                }
                else {
                    # NOP
                    ### log it here though
                }
            }
            print $socket "250 Ok\r\n";
        }
        elsif ( $command =~ /^MAIL FROM:/ ) {
            if ( $data_sent ) {
                print $socket "503 Out of Order\r\n";
                last COMMAND;
            }
            # Do connect callback here, because of XFORWARD
            if ( ! $has_connected ) {
                $returncode = $handler->top_connect_callback( $connect_host, Net::IP->new( $connect_ip ) );
                if ( $returncode == SMFIS_CONTINUE ) {
                    $returncode = $handler->top_helo_callback( $helo_host );
                    if ( $returncode == SMFIS_CONTINUE ) {
                        $has_connected = 1;
                        my $envfrom = substr( $command,11 );
                        $returncode = $handler->top_envfrom_callback( $envfrom );
                        if ( $returncode == SMFIS_CONTINUE ) {
                            print $socket "250 Ok\r\n";
                        }
                        else {
                            print $socket "451 That's not right\r\n";
                        }
                    }
                    else { 
                        print $socket "451 That's not right\r\n";
                    }
                }
                else { 
                    print $socket "451 That's not right\r\n";
                }
            } 
            else { 
                my $envfrom = substr( $command,11 );
                $returncode = $handler->top_envfrom_callback( $envfrom );
                if ( $returncode == SMFIS_CONTINUE ) {
                    print $socket "250 Ok\r\n";
                }
                else {
                    print $socket "451 That's not right\r\n";
                }
            }
        }
        elsif ( $command =~ /^RCPT TO:/ ) {
            if ( $data_sent ) {
                print $socket "503 Out of Order\r\n";
                last COMMAND;
            }
            my $envrcpt = substr( $command,9 );
            $returncode = $handler->top_envrcpt_callback( $envrcpt );
            if ( $returncode == SMFIS_CONTINUE ) {
                print $socket "250 Ok\r\n";
            }
            else {
                print $socket "451 That's not right\r\n";
            }
        }
        elsif ( $command =~ /^DATA/ ) {
            if ( $data_sent ) {
                print $socket "503 One at a time please\r\n";
                last COMMAND;
            }
            $data_sent = 1;
            print $socket "354 Send body\r\n";
            DATA:
            while ( my $dataline = <$socket> ) {
                $dataline =~ s/\r?\n$//;
                # Don't forget to deal with encoded . in the message text
                last DATA if $dataline eq '.';
            }
            #$returncode = $handler->top_header_callback( '', '' );
            #$returncode = $handler->top_eoh_callback();
            #$returncode = $handler->top_body_callback( '' );
            #$returncode = $handler->top_eom_callback();
            if ( $returncode == SMFIS_CONTINUE ) {
                print $socket "250 Queued as $queue_id\r\n";
            }
            else { 
                print $socket "451 That's not right\r\n";
            }

        }
        elsif ( $command =~ /^QUIT/ ){
            print $socket "221 Bye\n";
            last COMMAND;
        }
        else {
            print $socket "502 I don't understand\r\n";
        }

    }

    # Setup Header arrays

    # Process commands
    
    # Process header results
    
    # Pass on to destination
    
}


# BEGIN MILTER PROTOCOL BLOCK
sub milter_process_request {
    my ( $self ) = @_;

    COMMAND:
    while ( 1 ) {

        # Get packet length 
        my $length = unpack('N', $self->milter_read_block(4) ) || last;
        $self->fatal("bad packet length $length") if ($length <= 0 || $length > 131072);

        # Get command
        my $command = $self->milter_read_block(1) || last;
        $self->logdebug( "receive command $command" );

        # Get data
        my $data = $self->milter_read_block($length - 1);
        if ( ! defined ( $data ) ) {
            $self->fatal('EOF in stream');
        }

        last COMMAND if $command eq SMFIC_QUIT;
        $self->milter_process_command( $command, $data );

    }    

    return;
}
# END MILTER PROTOCOL BLOCK

sub start {
    my ($args)     = @_;

    $PROGRAM_NAME = '[authentication_milter:startup]';

    my $config                 = get_config();

    my $connection             = $config->{'connection'}             || die('No connection details given');
    my $pid_file               = $args->{'pid_file'};

    my $listen_backlog         = $config->{'listen_backlog'}         || 20;
    my $max_children           = $config->{'max_children'}           || 100;
    my $max_requests_per_child = $config->{'max_requests_per_child'} || 200;
    my $min_children           = $config->{'min_children'}           || 20;
    my $max_spare_children     = $config->{'max_spare_children'}     || 20;
    my $min_spare_children     = $config->{'min_spare_children'}     || 10;

    my %srvargs;

    $srvargs{'no_client_stdout'} = 1;

    if ( $args->{'daemon'} ) {
        if ( $EUID == 0 ) {
            warn(
                join( ' ',
                    'daemonize',
                    "servers=$min_children/$max_children",
                    "spares=$min_spare_children/$max_spare_children",
                    "requests=$max_requests_per_child",
                    "\n",
                )
            );
            $srvargs{'background'}        = 1;
            $srvargs{'setsid'}            = 1;
        }
        else {
            warn("Not running as root, daemonize ignored!\n");
        }
    }
    $srvargs{'pid_file'}          = $pid_file;
    $srvargs{'max_servers'}       = $max_children;
    $srvargs{'max_requests'}      = $max_requests_per_child;
    $srvargs{'min_servers'}       = $min_children;
    $srvargs{'min_spare_servers'} = $min_spare_children;
    $srvargs{'max_spare_servers'} = $max_spare_children;

    $srvargs{'log_file'}          = 'Sys::Syslog';
    $srvargs{'syslog_facility'}   = LOG_MAIL;
    $srvargs{'syslog_ident'}      = 'authentication_milter';
    $srvargs{'syslog_logopt'}     = 'pid';

    if ( $EUID == 0 ) {
        my $user  = $config->{'runas'};
        my $group = $config->{'rungroup'};
        if ( $user && $group ) {
        warn("run as user=$user group=$group\n");
            $srvargs{'user'}  = $user;
            $srvargs{'group'} = $group;
        }
        else {
            warn("No runas details supplied, could not drop privs - be careful!\n");
        }
        # Note, Chroot requires a chroot environment which is out of scope at present
        if ( $config->{'error_log'} ) {
            if ( ! -e $config->{'error_log'} ) {
                open my $outf, '>', $config->{'error_log'} || die "Could not create error log: $!\n";;
                close $outf;
            }
            my ($login,$pass,$uid,$gid) = getpwnam($user);
            chown $uid, $gid, $config->{'error_log'};
        }
        if ( exists( $config->{'chroot'} ) ) {
            warn('Chroot to ' . $config->{'chroot'} . "\n");
            $srvargs{'chroot'} = $config->{'chroot'};
        }
    }
    else {
        warn("Not running as root, could not drop privs - be careful!\n");
    }

    {
        $connection =~ /^([^:]+):([^:@]+)(?:@([^:@]+|\[[0-9a-f:\.]+\]))?$/;
        my $type = $1;
        my $path = $2;
        my $host = $3 || q{};
        if ( $type eq 'inet' ) {
            warn(
                join( ' ',
                    'listen on inet',
                    "host=$host",
                    "port=$path",
                    "backlog=$listen_backlog",
                    "\n",
                )
            );
            $srvargs{'host'}   = $host;
            $srvargs{'port'}   = $path;
            $srvargs{'ipv'}    = '*';
            $srvargs{'proto'}  = 'tcp';
            $srvargs{'listen'} = $listen_backlog;
        }
        elsif ( $type eq 'unix' ) {
            warn(
                join( ' ',
                    'listening on unix',
                    "socket=$path",
                    "backlog=$listen_backlog",
                    "\n",
                )
            );
            $srvargs{'port'}   = $path;
            $srvargs{'proto'}  = 'unix';
            $srvargs{'listen'} = $listen_backlog;

            my $umask = $config->{'umask'};
            if ($umask) {
                umask ( oct( $umask ) );
                warn( 'setting umask to ' . $umask . "\n" );
            }

        }
        else {
            die 'Invalid connection';
        }
    }

    $PROGRAM_NAME = '[authentication_milter:master]';

    warn "\nStarting server\n";
    __PACKAGE__->run( %srvargs );

    # Never reaches here.
    die 'Something went horribly wrong';
    return;
}

##### Protocol methods

sub fatal {
    my ( $self, $error ) = @_;
    $self->logerror( "Child process $PID shutting down due to fatal error: $error" );
    die "$error\n";
    return;
}

sub setup_handlers {
    my ( $self ) = @_;

    $self->logdebug( 'setup objects' );
    my $handler = Mail::Milter::Authentication::Handler->new( $self );
    $self->{'handler'}->{'_Handler'} = $handler;

    my $config = $self->{'config'};
    foreach my $name ( @{$config->{'load_handlers'}} ) {
        $self->setup_handler( $name );
    }
    $self->sort_all_callbacks();
    return;
}

sub load_handler {
    my ( $self, $name ) = @_;

    ## TODO error handling here
    $self->logdebug( "Load Handler $name" );

    my $package = "Mail::Milter::Authentication::Handler::$name";
    if ( ! is_loaded ( $package ) ) {
       $self->logdebug( "Load Handler Module $name" );
       load $package;
    }
    return;
}

sub setup_handler {
    my ( $self, $name ) = @_;

    ## TODO error handling here
    $self->logdebug( "Instantiate Handler $name" );

    my $package = "Mail::Milter::Authentication::Handler::$name";
    my $object = $package->new( $self );
    $self->{'handler'}->{$name} = $object;

    foreach my $callback ( qw { connect helo envfrom envrcpt header eoh body eom abort close } ) {
        if ( $object->can( $callback . '_callback' ) ) {
            $self->register_callback( $name, $callback );
        }
    }

    return;
}

sub destroy_handler {
    # Unused!
    my ( $self, $name ) = @_;
    # Remove some back references
    delete $self->{'handler'}->{$name}->{'thischild'};
    # Remove reference to handler
    delete $self->{'handler'}->{$name};
    return;
}


sub register_callback {
    my ( $self, $name, $callback ) = @_;
    $self->logdebug( "Register Callback $name:$callback" );
    if ( ! exists $self->{'callbacks'}->{$callback} ) {
        $self->{'callbacks'}->{$callback} = [];
    }
    push @{ $self->{'callbacks'}->{$callback} }, $name;
    return;
}

sub sort_all_callbacks {
    my ($self) = @_;
    foreach my $callback ( qw { connect helo envfrom envrcpt header eoh body eom abort close } ) {
        $self->sort_callbacks( $callback );
    }
    return;
}

sub sort_callbacks {
    my ( $self, $callback ) = @_;

    if ( ! exists $self->{'callbacks'}->{$callback} ) {
        $self->{'callbacks'}->{$callback} = [];
    }

    if ( ! exists $self->{'callbacks_list'}->{$callback} ) {
        $self->{'callbacks_list'}->{$callback} = [];
    }
    else {
        return $self->{'callbacks_list'}->{$callback};
    }
    
    my $callbacks_ref = $self->{'callbacks'}->{$callback};

    my $added = {};
    my @order;

    my @todo = sort @{$callbacks_ref};
    my $todo_count = scalar @todo;
    while ( $todo_count ) {
        my @defer;
        foreach my $item ( @todo ) {
            my $handler = $self->{'handler'}->{ $item };
            my $requires_method = $callback . '_requires';
            if ( $handler->can( $requires_method ) ) { 
                my $requires_met = 1;
                my $requires = $handler->$requires_method;
                foreach my $require ( @{ $requires } ) {
                    if ( ! exists $added->{$require} ) {
                        $requires_met = 0;
                    }
                }
                if ( $requires_met == 1 ) {
                    push @order, $item;
                    $added->{$item} = 1;
                }
                else {
                    push @defer, $item;
                }
            }
            else {
                push @order, $item;
                $added->{$item} = 1;
            }
        }

        my $defer_count = scalar @defer;
        if ( $defer_count == $todo_count ) {
            $self->fatal('Could not build order list');
        }
        $todo_count = $defer_count;
        @todo = @defer;
    }

    $self->{'callbacks_list'}->{$callback} = \@order;
    return;
}

sub destroy_objects {
    my ( $self ) = @_;
    $self->logdebug ( 'destroy objects' );
    my $handler = $self->{'handler'}->{'_Handler'};
    if ( $handler ) {
        $handler->destroy_all_objects();
        my $config = $self->{'config'};
        foreach my $name ( @{$config->{'load_handlers'}} ) {
            $self->destroy_handler( $name );
        }
        delete $self->{'handler'}->{'_Handler'}->{'config'};
        delete $self->{'handler'}->{'_Handler'}->{'thischild'};
        delete $self->{'handler'}->{'_Handler'};
    }
    return;
}

sub milter_process_command {
    my ( $self, $command, $buffer ) = @_;
    $self->logdebug ( "process command $command" );

    my $handler = $self->{'handler'}->{'_Handler'};

    my $returncode = SMFIS_CONTINUE;

    if ( $command eq SMFIC_CONNECT ) {
        # BEGIN MILTER PROTOCOL BLOCK
        my ( $host, $ip ) = $self->milter_process_connect( $buffer );
        # END MILTER PROTOCOL BLOCK
        $returncode = $handler->top_connect_callback( $host, $ip );
    }
    elsif ( $command eq SMFIC_ABORT ) {
        $returncode = $handler->top_abort_callback();
    }
    elsif ( $command eq SMFIC_BODY ) {
        $returncode = $handler->top_body_callback( $buffer );
    }
    elsif ( $command eq SMFIC_MACRO ) {
        $self->fatal('SMFIC_MACRO: empty packet') unless ( $buffer =~ s/^(.)// );
        my $code = $1;
        my $data = $self->milter_split_buffer( $buffer );
        push ( @$data, q{} ) if (( @$data & 1 ) != 0 ); # pad last entry with empty string if odd number
        my %datahash = @$data;
        foreach my $key ( keys %datahash ) {
            $handler->set_symbol( $code, $key, $datahash{$key} );
        }
        undef $returncode;
    }
    elsif ( $command eq SMFIC_BODYEOB ) {
        $returncode = $handler->top_eom_callback();
    }
    elsif ( $command eq SMFIC_HELO ) {
        my $helo = $self->milter_split_buffer( $buffer );
        $returncode = $handler->top_helo_callback( @$helo );
    }
    elsif ( $command eq SMFIC_HEADER ) {
        my $header = $self->milter_split_buffer( $buffer );
        if ( @$header == 1 ) { push @$header , q{}; };
        $returncode = $handler->top_header_callback( @$header );
    }
    elsif ( $command eq SMFIC_MAIL ) {
        my $envfrom = $self->milter_split_buffer( $buffer );
        $returncode = $handler->top_envfrom_callback( @$envfrom );
    }
    elsif ( $command eq SMFIC_EOH ) {
        $returncode = $handler->top_eoh_callback();
    }
    elsif ( $command eq SMFIC_OPTNEG ) {
        $self->fatal('SMFIC_OPTNEG: packet has wrong size') unless (length($buffer) == 12);
        my ($ver, $actions, $protocol) = unpack('NNN', $buffer);
        $self->fatal("SMFIC_OPTNEG: unknown milter protocol version $ver") unless ($ver >= 2 && $ver <= 6);
        my $actions_reply  = $self->{'callback_flags'} & $actions;
        my $protocol_reply = $self->{'protocol'}       & $protocol;
        $self->write_packet(SMFIC_OPTNEG,
            pack('NNN', 2, $actions_reply, $protocol_reply)
        );
        undef $returncode;
    }
    elsif ( $command eq SMFIC_RCPT ) {
        my $envrcpt = $self->milter_split_buffer( $buffer );
        $returncode = $handler->top_envrcpt_callback( @$envrcpt );
    }
    elsif ( $command eq SMFIC_DATA ) {
    }
    elsif ( $command eq SMFIC_UNKNOWN ) {
        undef $returncode;
        # Unknown SMTP command received
    }
    else {
        $self->fatal("Unknown milter command $command");
    }

    if (defined $returncode) {
        if ( $returncode == SMFIS_CONTINUE ) {
            $returncode = SMFIR_CONTINUE;
        }
        elsif ( $returncode == SMFIS_TEMPFAIL ) {
            $returncode = SMFIR_TEMPFAIL;
        }
        elsif ( $returncode == SMFIS_REJECT ) {
            $returncode = SMFIR_REJECT;
        }
        elsif ( $returncode == SMFIS_DISCARD ) {
            $returncode = SMFIR_DISCARD;
        }
        elsif ( $returncode == SMFIS_ACCEPT ) {
            $returncode = SMFIR_ACCEPT;
        }

        my $config = $self->{'config'};
        if ( $config->{'dryrun'} ) {
            if ( $returncode ne SMFIR_CONTINUE ) {
                $self->loginfo ( "dryrun returncode changed from $returncode to continue" );
                $returncode = SMFIR_CONTINUE;
            }
        }

        if ( $command ne SMFIC_ABORT ) {
            $self->write_packet($returncode);
        }
    } 
 
    return;
}

# BEGIN MILTER PROTOCOL BLOCK
sub milter_process_connect {
    my ( $self, $buffer ) = @_;

    unless ($buffer =~ s/^([^\0]*)\0(.)//) {
        $self->fatal('SMFIC_CONNECT: invalid connect info');
    }
    my $ip;
    my $host = $1;

    my ($port, $addr) = unpack('nZ*', $buffer);

    if ( ! defined ( $addr ) ) {
        $self->log_error('Unknown IP address format UNDEF');
        $ip = undef;
        # Could potentially fail here, connection is likely bad anyway.
    }
    elsif ( length ( $addr ) == 0 ) {
            $self->log_error('Unknown IP address format NULL');
            $ip = undef;
            # Could potentially fail here, connection is likely bad anyway.
    }
    else {
        eval {
            $ip = Net::IP->new( $addr );
        };
        if ( my $error = $@ ) {
            $self->log_error('Unknown IP address format - ' . $addr . ' - ' . $error );
            $ip = undef;
            # Could potentially fail here, connection is likely bad anyway.
        }
    }

    return ( $host, $ip );
}
# END MILTER PROTOCOL BLOCK

# BEGIN MILTER PROTOCOL BLOCK
sub milter_read_block {
    my ( $self, $len ) = @_;
    my $socket = $self->{'socket'};
    my $sofar = 0;
    my $buffer = q{}; 
    while ($len > $sofar) {
        my $read = $socket->sysread($buffer, $len - $sofar, $sofar);
        last if (!defined($read) || $read <= 0); # EOF
        $sofar += $read;
    }
    return $buffer;
}
# END MILTER PROTOCOL BLOCK

# BEGIN MILTER PROTOCOL BLOCK
sub milter_split_buffer {
    my ( $self, $buffer ) = @_;
    $buffer =~ s/\0$//; # remove trailing NUL
    return [ split(/\0/, $buffer) ];
};
# END MILTER PROTOCOL BLOCK

##

# BEGIN MILTER PROTOCOL BLOCK
sub add_header {
    my ( $self, $header, $value ) = @_;
    $self->write_packet( SMFIR_ADDHEADER,
        $header
        . "\0"
        . $value
        . "\0"
    );
    return;
}
# END MILTER PROTOCOL BLOCK

# BEGIN MILTER PROTOCOL BLOCK
sub change_header {
    my ( $self, $header, $index, $value ) = @_;
    $value = '' unless defined($value);
    $self->write_packet( SMFIR_CHGHEADER,
        pack('N', $index)
        . $header
        . "\0"
        . $value
        . "\0"
    );
    return;
}
# END MILTER PROTOCOL BLOCK

# BEGIN MILTER PROTOCOL BLOCK
sub insert_header {
    my ( $self, $index, $key, $value ) = @_;
    $self->write_packet( SMFIR_INSHEADER,
        pack( 'N', $index )
        . $key
        . "\0"
        . $value
        . "\0"
    );
    return;
}
# END MILTER PROTOCOL BLOCK

# BEGIN MILTER PROTOCOL BLOCK
sub write_packet {
    my ( $self, $code, $data ) = @_;
    $self->logdebug ( "send command $code" );
    my $socket = $self->{'socket'};
    $data = q{} unless defined($data);
    my $len = pack('N', length($data) + 1);
    $socket->syswrite($len);
    $socket->syswrite($code);
    $socket->syswrite($data);
    return;
}
# END MILTER PROTOCOL BLOCK


## Logging

sub logerror {
    my ($self,$line) = @_;
    my $config = $self->{'config'} || get_config();
    warn "$PID: $line\n" if $config->{'logtoerr'};
    syslog( LOG_ERR, $line );
    return;
}

sub loginfo {
    my ($self,$line) = @_;
    my $config = $self->{'config'} || get_config();
    warn "$PID: $line\n" if $config->{'logtoerr'};
    syslog( LOG_INFO, $line );
    return;
}

sub logdebug {
    my ($self,$line) = @_;
    my $config = $self->{'config'} || get_config();
    warn "$PID: $line\n" if $config->{'logtoerr'};
    if ( $config->{'debug'} ) {
        syslog( LOG_DEBUG, $line );
    }
    return;
}

1;

__END__

=head1 NAME

Mail::Milter::Authentication - A PERL Mail Authentication Milter

=head1 DESCRIPTION

A PERL implemtation of email authentication standards rolled up into a single easy to use milter.

=head1 SYNOPSIS

Subclass of Net::Server::PreFork for bringing up the main server process for authentication_milter.

Please see Net::Server docs for more detail of the server code.

=head1 METHODS

=over

=item I<child_init_hook()>

Hook which runs after forking, sets up per process items.

=item I<process_request()>

Hook which runs for each request, sets up per request items and processes the request.

=item I<start($hashref)>

Start the server. This method does not return.

    $hashref = {
        'pid_file'   => 'The pid file to use', # 
        'daemon'     => 1/0,                   # Daemonize process?
    }

=item I<fatal($error)>

Log a fatal error and die

=item I<setup_handlers()>

Setup the Handler objects.

=item I<load_handler( $name )>

Load the $name Handler module

=item I<setup_handler( $name )>

Setup the $name Handler object

=item I<destroy_handler( $name )>

Remove the $name Handler

=item I<resister_callback( $name, $callback )>

Register the specified callback

=item I<sort_all_callbacks()>

Sort the callbacks into the order in which they must be called

=item I<sort_callbacks( $callback )>

Sort the callbacks for the $callback callback into the right order

=item I<destroy_objects()>

Remove references to all objects

=item I<milter_process_command( $command, $buffer )>

Process the command from the milter protocol stream.

=item I<milter_processconnect( $buffer )>

Process a milter connect command.

=item I<milter_read_block( $len )>

Read $len bytes from the milter protocol stream.

=item I<milter_split_buffer( $buffer )>

Split the milter buffer at null

=item I<add_header( $header, $value )>

Write an add header packet

=item I<change_header( $header, $index, $value )>

Write a change header packet

=item I<insert_header( $index, $key, $value )>

Writa an insert header packet

=item I<write_packet( $code, $data )>

Write a packet to the protocol stream.

=item I<logerror( $line )>

Log to the error log.

=item I<loginfo( $line )>

Log to the info log.

=item I<logdebug( $line )>

Log to the debug log.

=back

=head1 DEPENDENCIES

  Email::Address
  English
  JSON
  Mail::DKIM
  Mail::DMARC
  Mail::SPF
  MIME::Base64
  Module::Load
  Module::Loaded
  Net::DNS
  Net::IP
  Net::Server
  Pod::Usage
  Proc::ProcessTable
  Sys::Hostname
  Sys::Syslog

=head1 AUTHORS

Marc Bradshaw E<lt>marc@marcbradshaw.netE<gt>

=head1 COPYRIGHT

Copyright 2015

This library is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.
