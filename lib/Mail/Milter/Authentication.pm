package Mail::Milter::Authentication;
use strict;
use warnings;
use base 'Net::Server::PreFork';
our $VERSION = 0.8;

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

use vars qw(@ISA);


sub pre_loop_hook {
    my ( $self ) = @_;

    $PROGRAM_NAME = '[authentication_milter:master]';

    # Load handlers
    my $config = get_config();
    foreach my $name ( @{$config->{'load_handlers'}} ) {
        $self->load_handler( $name );

        my $package = "Mail::Milter::Authentication::Handler::$name";
        my $object = $package->new( $self );
        if ( $object->can( 'pre_loop_setup' ) ) {
            $object->pre_loop_setup();
        }

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

    my $base;
    if ( $config->{'protocol'} eq 'milter' ) {
        $base = 'Mail::Milter::Authentication::Protocol::Milter';
    }
    elsif ( $config->{'protocol'} eq 'smtp' ) {
        $base = 'Mail::Milter::Authentication::Protocol::SMTP';
    }
    else {
        die "Unknown protocol " . $config->{'protocol'} . "\n";
    }
    load $base;
    push @ISA, $base;

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

sub get_client_proto {
    my ( $self ) = @_;
    my $socket = $self->{server}{client};
    if ($socket->isa("Net::Server::Proto")) {
        my $proto = $socket->NS_proto;
        $proto = "UNIX" if $proto =~ m/^UNIX/;
        return $proto;
    }

    if ($socket->isa("IO::Socket::INET")) {
        return "TCP";
    }

    if ($socket->isa("IO::Socket::INET6")) {
      return "TCP";
    }

    if ($socket->isa("IO::Socket::UNIX")) {
        return "UNIX";
    }

    $self->logerror( "Could not determine connection protocol: " . ref($socket) );

    return;
}

sub get_client_port {
    my ( $self ) = @_;
    my $socket = $self->{server}{client};
    return $socket->sockport();
}

sub get_client_path {
    my ( $self ) = @_;
    my $socket = $self->{'socket'};
    return $socket->hostpath();
}

sub get_client_details {
    my ( $self ) = @_;
    my $proto = lc $self->get_client_proto();
    if ( $proto eq 'tcp' ) {
        return 'inet:' . $self->get_client_port();
    }
    elsif ( $proto eq 'unix' ) {
        return 'unix:' . $self->get_client_path();
    }
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

    $self->protocol_process_request();

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




sub start {
    my ($args)     = @_;

    my $config                 = get_config();

    my $default_connection     = $config->{'connection'}             || die('No connection details given');

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

    my $connections = {};

    if ( exists $config->{'connections'} ) {
        $connections = $config->{'connections'};
    }

    $connections->{'default'} = {
        'connection' => $default_connection,
        'umask'      => $config->{'umask'},
    };

    my @ports;
    foreach my $key ( keys %$connections ) {
        my $connection = $connections->{$key}->{'connection'};
        my $umask      = $connections->{$key}->{'umask'};

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
            push @ports, {
                'host'  => $host,
                'port'  => $path,
                'ipv'   => '*',
                'proto' => 'tcp',
            };
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
            push @ports, {
                'port'  => $path,
                'proto' => 'unix',
            };

            if ($umask) {
                umask ( oct( $umask ) );
                warn( 'setting umask to ' . $umask . "\n" );
            }

        }
        else {
            die 'Invalid connection';
        }
    }

    $srvargs{'port'} = \@ports;
    $srvargs{'listen'} = $listen_backlog;

    warn "\nStarting server\n";
    __PACKAGE__->run( %srvargs );

    # Never reaches here.
    die 'Something went horribly wrong';
}

##### Protocol methods

sub fatal {
    my ( $self, $error ) = @_;
    $self->logerror( "Child process $PID shutting down due to fatal error: $error" );
    die "$error\n";
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




## Logging

sub logerror {
    my ($self,$line) = @_;
    my $config = $self->{'config'} || get_config();
    if ( exists ( $self->{'smtp'} ) ) {
        if ( $self->{'smtp'}->{'queue_id'} ) {
            $line = $self->{'smtp'}->{'queue_id'} . ': ' . $line;
        }
    }
    warn "$PID: $line\n" if $config->{'logtoerr'};
    syslog( LOG_ERR, $line );
    return;
}

sub loginfo {
    my ($self,$line) = @_;
    my $config = $self->{'config'} || get_config();
    if ( exists ( $self->{'smtp'} ) ) {
        if ( $self->{'smtp'}->{'queue_id'} ) {
            $line = $self->{'smtp'}->{'queue_id'} . ': ' . $line;
        }
    }
    warn "$PID: $line\n" if $config->{'logtoerr'};
    syslog( LOG_INFO, $line );
    return;
}

sub logdebug {
    my ($self,$line) = @_;
    my $config = $self->{'config'} || get_config();
    if ( exists ( $self->{'smtp'} ) ) {
        if ( $self->{'smtp'}->{'queue_id'} ) {
            $line = $self->{'smtp'}->{'queue_id'} . ': ' . $line;
        }
    }
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

=item I<register_callback( $name, $callback )>

Register the specified callback

=item I<sort_all_callbacks()>

Sort the callbacks into the order in which they must be called

=item I<sort_callbacks( $callback )>

Sort the callbacks for the $callback callback into the right order

=item I<destroy_objects()>

Remove references to all objects

=item I<logerror( $line )>

Log to the error log.

=item I<loginfo( $line )>

Log to the info log.

=item I<logdebug( $line )>

Log to the debug log.

=item I<child_finish_hook()>

Hook which runs when the child is about to finish.

=item I<get_client_details()>

Get the details of the connecting client.

=item I<get_client_path()>

Get the path of the connecting client.

=item I<get_client_port()>

Get the port of the connecting client.

=item I<get_client_proto()>

Get the protocol of the connecting client.

=item I<pre_loop_hook()>

Hook which runs in the master before looping.

=item I<pre_server_close_hook()>

Hook which runs before the server closes.

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
