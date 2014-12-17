package Mail::Milter::Authentication::Protocol;

use strict;
use warnings;

our $VERSION = 0.5;

use English;
use Mail::Milter::Authentication::Util qw{ loginfo logdebug logerror };
use Module::Load;
use Module::Loaded;
use Socket;
use Socket6;

use Mail::Milter::Authentication::Constants qw{ :all };

sub new {
    my ( $class, $args ) = @_;

    my $callbacks_list = $args->{'callbacks_list'}; 
    my $callbacks      = $args->{'callbacks'};
    my $config         = $args->{'config'};
    my $count          = $args->{'count'};
    my $handler        = $args->{'handler'};
    my $object         = $args->{'object'};
    my $socket         = $args->{'socket'};

    my $callback_flags = SMFI_CURR_ACTS|SMFIF_CHGBODY|SMFIF_QUARANTINE|SMFIF_SETSENDER;

    my $protocol  = SMFIP_NONE & ~(SMFIP_NOCONNECT|SMFIP_NOMAIL);
       $protocol &= ~SMFIP_NOHELO;
       $protocol &= ~SMFIP_NORCPT;
       $protocol &= ~SMFIP_NOBODY;
       $protocol &= ~SMFIP_NOHDRS;
       $protocol &= ~SMFIP_NOEOH;

    my $self = {
        'config'         => $config,
        'callback_flags' => $callback_flags,
        'callbacks'      => $callbacks,
        'callbacks_list' => $callbacks_list,
        'count'          => $count,
        'handler'        => $handler,
        'object'         => $object,
        'protocol'       => $protocol,
        'socket'         => $socket,
    };
    bless $self, $class;

    if ( ! exists( $handler->{'_Handler'} ) ) {
        $self->setup_objects();
    }

    return $self;
}

sub fatal {
    my ( $self, $error ) = @_;
    logerror( "Child process $PID shutting down due to fatal error: $error" );
    die "$error\n";
}

sub main {
    my ( $self ) = @_;
  
    my $quit = 0;
    while ( ! $quit ) {

        # Get packet length 
        my $length = unpack('N', $self->read_block(4) ) || last;
        $self->fatal("bad packet length $length") if ($length <= 0 || $length > 131072);

        # Get command
        my $command = $self->read_block(1) || last;
        logdebug( "receive command $command" );

        # Get data
        my $data = $self->read_block($length - 1);
        if ( ! defined ( $data ) ) {
            $self->fatal('EOF in stream');
        }

        last if $command eq SMFIC_QUIT;
        $self->process_command( $command, $data );

    }    

    # Call close callback
    $self->{'handler'}->{'_Handler'}->top_close_callback();
    if ( $self->{'handler'}->{'_Handler'}->{'exit_on_close'} ) {
        $quit = 1;
    }
    #$self->destroy_objects();
    $self->fatal('exit_on_close requested') if $quit;

    #use Devel::Peek;
    #warn Dump($self);
    #use Data::Dumper;
    #print Dumper($self);
    #use Devel::Cycle;
    #find_cycle($self);
}

sub setup_objects {
    my ( $self ) = @_;

    logdebug( 'setup objects' );
    if ( ! is_loaded ( 'Mail::Milter::Authentication::Handler' ) ) {
        load 'Mail::Milter::Authentication::Handler';
    }
    my $handler = Mail::Milter::Authentication::Handler->new( $self );
    $self->{'handler'}->{'_Handler'} = $handler;

    my $CONFIG = $self->{'config'};
    foreach my $name ( @{$CONFIG->{'load_handlers'}} ) {
        $self->setup_handler( $name );
    }
    $self->sort_all_callbacks();
}

sub setup_handler {
    my ( $self, $name ) = @_;

    ## TODO error handling here
    logdebug( "Load Handler $name" );

    my $package = "Mail::Milter::Authentication::Handler::$name";
    if ( ! is_loaded ( $package ) ) {
       load $package;
    }
    my $object = $package->new( $self );
    $self->{'handler'}->{$name} = $object;

    foreach my $callback ( qw { connect helo envfrom envrcpt header eoh body eom abort close } ) {
        if ( $object->can( $callback . '_callback' ) ) {
            $self->register_callback( $name, $callback );
        }
    }

}

sub destroy_handler {
    # Unused!
    my ( $self, $name ) = @_;
    # Remove some back references
    delete $self->{'handler'}->{$name}->{'protocol'};
    # Remove reference to handler
    delete $self->{'handler'}->{$name};
}


sub register_callback {
    my ( $self, $name, $callback ) = @_;
    logdebug( "Register Callback $name:$callback" );
    if ( ! exists $self->{'callbacks'}->{$callback} ) {
        $self->{'callbacks'}->{$callback} = [];
    }
    push @{ $self->{'callbacks'}->{$callback} }, $name;
}

sub sort_all_callbacks {
    my ($self) = @_;
    foreach my $callback ( qw { connect helo envfrom envrcpt header eoh body eom abort close } ) {
        $self->sort_callbacks( $callback );
    }
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
}

sub destroy_objects {
    # Unused!
    my ( $self ) = @_;
    logdebug ( 'destroy objects' );
    my $handler = $self->{'handler'}->{'_Handler'};
    $handler->destroy_all_objects();
    my $CONFIG = $self->{'config'};
    foreach my $name ( @{$CONFIG->{'load_handlers'}} ) {
        $self->destroy_handler( $name );
    }
    delete $self->{'handler'}->{'_Handler'}->{'config'};
    delete $self->{'handler'}->{'_Handler'}->{'protocol'};
    delete $self->{'handler'}->{'_Handler'};
}

sub process_command {
    my ( $self, $command, $buffer ) = @_;
    logdebug ( "process command $command" );

    my $handler = $self->{'handler'}->{'_Handler'};

    my $returncode = SMFIS_CONTINUE;

    if ( $command eq SMFIC_CONNECT ) {
        my ( $host, $sockaddr_in ) = $self->connect_callback( $buffer );
        $returncode = $handler->top_connect_callback( $host, $sockaddr_in );
    }
    elsif ( $command eq SMFIC_ABORT ) {
        $handler->clear_symbols();
        $returncode = $handler->top_abort_callback();
    }
    elsif ( $command eq SMFIC_BODY ) {
        $returncode = $handler->top_body_callback( $buffer );
    }
    elsif ( $command eq SMFIC_MACRO ) {
        $self->fatal('SMFIC_MACRO: empty packet') unless ( $buffer =~ s/^(.)// );
        my $code = $1;
        my $data = $self->split_buffer( $buffer );
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
        my $helo = $self->split_buffer( $buffer );
        $returncode = $handler->top_helo_callback( @$helo );
    }
    elsif ( $command eq SMFIC_HEADER ) {
        my $header = $self->split_buffer( $buffer );
        if ( @$header == 1 ) { push @$header , q{}; };
        $returncode = $handler->top_header_callback( @$header );
    }
    elsif ( $command eq SMFIC_MAIL ) {
        my $envfrom = $self->split_buffer( $buffer );
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
        my $envrcpt = $self->split_buffer( $buffer );
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

        my $CONFIG = $self->{'config'};
        if ( $CONFIG->{'dryrun'} ) {
            if ( $returncode ne SMFIR_CONTINUE ) {
                loginfo ( "dryrun returncode changed from $returncode to continue" );
                $returncode = SMFIR_CONTINUE;
            }
        }

        if ( $command ne SMFIC_ABORT ) {
            $self->write_packet($returncode);
        }
    } 
 
}

sub connect_callback {
    my ( $self, $buffer ) = @_;

    unless ($buffer =~ s/^([^\0]*)\0(.)//) {
        $self->fatal('SMFIC_CONNECT: invalid connect info');
    }
    my $host = $1;
    my $af = $2;
    my ($port, $addr) = unpack('nZ*', $buffer);
    my $pack; # default undef
    if ($af eq SMFIA_INET) {
        $pack = pack_sockaddr_in($port, inet_aton($addr));
    }
    elsif ($af eq SMFIA_INET6) {
        $pack = eval {
            $addr =~ s/^IPv6://;
            Socket6::pack_sockaddr_in6($port,
            Socket6::inet_pton(&Socket6::AF_INET6, $addr));
        };
    }
    elsif ($af eq SMFIA_UNIX) {
        $pack = eval {
            sockaddr_un($addr);
        };
    }
    return ( $host, $pack );
}

sub read_block {
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

sub split_buffer {
    my ( $self, $buffer ) = @_;
    $buffer =~ s/\0$//; # remove trailing NUL
    return [ split(/\0/, $buffer) ];
};


sub add_header {
    my ( $self, $header, $value ) = @_;
    $self->write_packet( SMFIR_ADDHEADER,
        $header
        . "\0"
        . $value
        . "\0"
    );
}

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
}

sub insert_header {
    my ( $self, $index, $key, $value ) = @_;
    $self->write_packet( SMFIR_INSHEADER,
        pack( 'N', $index )
        . $key
        . "\0"
        . $value
        . "\0"
    );
}

sub write_packet {
    my ( $self, $code, $data ) = @_;
    logdebug ( "send command $code" );
    my $socket = $self->{'socket'};
    $data = q{} unless defined($data);
    my $len = pack('N', length($data) + 1);
    $socket->syswrite($len);
    $socket->syswrite($code);
    $socket->syswrite($data);
}

1;
