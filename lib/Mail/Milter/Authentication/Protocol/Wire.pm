package Mail::Milter::Authentication::Protocol::Wire;

use strict;
use warnings;

our $VERSION = 0.4;

use English;
use Mail::Milter::Authentication::Util qw{ logdebug };
use Module::Load;
use Socket;
use Socket6;

use Mail::Milter::Authentication::Constants qw{ :all };

sub new {
    my ( $class, $socket ) = @_;

    my $callback_flags = SMFI_CURR_ACTS|SMFIF_CHGBODY|SMFIF_QUARANTINE|SMFIF_SETSENDER;

    my $protocol  = SMFIP_NONE & ~(SMFIP_NOCONNECT|SMFIP_NOMAIL);
       $protocol &= ~SMFIP_NOHELO;
       $protocol &= ~SMFIP_NORCPT;
       $protocol &= ~SMFIP_NOBODY;
       $protocol &= ~SMFIP_NOHDRS;
       $protocol &= ~SMFIP_NOEOH;

    my $self = {
        'socket'         => $socket,
        'callback_flags' => $callback_flags,
        'protocol'       => $protocol,
    };
    bless $self, $class;
    return $self;
}

sub main {
    my ( $self ) = @_;

    my $quit = 0;
    while ( ! $quit ) {

        # Get packet length 
        my $length = unpack('N', $self->read_block(4) ) || last;
        die "bad packet length $length\n" if ($length <= 0 || $length > 131072);

        # Get command
        my $command = $self->read_block(1) || last;
        logdebug( "receive command $command" );

        # Get data
        my $data = $self->read_block($length - 1);
        if ( ! defined ( $data ) ) {
            die "EOF in stream\n";
        }

        last if $command eq SMFIC_QUIT;
        $self->process_command( $command, $data );

    }    

    # Call close callback
    $self->{'handler'}->close_callback();
    if ( $self->{'handler'}->{'exit_on_close'} ) {
        $quit = 1;
    }
    $self->destroy_objects();
    die 'exit_on_close' if $quit;
}

sub setup_objects {
    my ( $self ) = @_;
    logdebug( 'setup objects' );

    load 'Mail::Milter::Authentication::Handler';
    my $handler = Mail::Milter::Authentication::Handler->new( $self );
    $self->{'handler'} = $handler;

    foreach my $name (qw{ Generic Auth Core DKIM DMARC IPRev LocalIP PTR Sanitize SenderID SPF TrustedIP }) {
        $handler->setup_handler( $name );
    }
}

sub destroy_objects {
    my ( $self ) = @_;
    logdebug ( 'destroy objects' );
    my $handler = $self->{'handler'};
    foreach my $name (qw{ Generic Auth Core DKIM DMARC IPRev LocalIP PTR Sanitize SenderID SPF TrustedIP }) {
        $handler->destroy_handler( $name );
    }
    delete $self->{'handler'};
}

sub process_command {
    my ( $self, $command, $buffer ) = @_;
    logdebug ( "process command $command" );

    my $handler = $self->{'handler'};
    if ( ! defined ( $handler ) ) {
        $self->setup_objects();
        $handler = $self->{'handler'};
    }

    my $returncode = SMFIS_CONTINUE;

    if ( $command eq SMFIC_CONNECT ) {
        my ( $host, $sockaddr_in ) = $self->connect_callback( $buffer );
        $returncode = $handler->connect_callback( $host, $sockaddr_in );
    }
    elsif ( $command eq SMFIC_ABORT ) {
        $handler->clear_symbols();
        $returncode = $handler->abort_callback();
    }
    elsif ( $command eq SMFIC_BODY ) {
        $returncode = $handler->body_callback( $buffer );
    }
    elsif ( $command eq SMFIC_MACRO ) {
        die "SMFIC_MACRO: empty packet\n" unless ( $buffer =~ s/^(.)// );
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
        $returncode = $handler->eom_callback();
    }
    elsif ( $command eq SMFIC_HELO ) {
        my $helo = $self->split_buffer( $buffer );
        $returncode = $handler->helo_callback( @$helo );
    }
    elsif ( $command eq SMFIC_HEADER ) {
        my $header = $self->split_buffer( $buffer );
        if ( @$header == 1 ) { push @$header , q{}; };
        $returncode = $handler->header_callback( @$header );
    }
    elsif ( $command eq SMFIC_MAIL ) {
        my $envfrom = $self->split_buffer( $buffer );
        $returncode = $handler->envfrom_callback( @$envfrom );
    }
    elsif ( $command eq SMFIC_EOH ) {
        $returncode = $handler->eoh_callback();
    }
    elsif ( $command eq SMFIC_OPTNEG ) {
        die "SMFIC_OPTNEG: packet has wrong size\n" unless (length($buffer) == 12);
        my ($ver, $actions, $protocol) = unpack('NNN', $buffer);
        die "SMFIC_OPTNEG: unknown milter protocol version $ver\n" unless ($ver >= 2 && $ver <= 6);
        my $actions_reply  = $self->{'callback_flags'} & $actions;
        my $protocol_reply = $self->{'protocol'}       & $protocol;
        $self->write_packet(SMFIC_OPTNEG,
            pack('NNN', 2, $actions_reply, $protocol_reply)
        );
        undef $returncode;
    }
    elsif ( $command eq SMFIC_RCPT ) {
        my $envrcpt = $self->split_buffer( $buffer );
        $returncode = $handler->envrcpt_callback( @$envrcpt );
    }
    elsif ( $command eq SMFIC_DATA ) {
    }
    elsif ( $command eq SMFIC_UNKNOWN ) {
        undef $returncode;
        # Unknown SMTP command received
    }
    else {
        die "Unknown milter command $command";
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

        if ( $command ne SMFIC_ABORT ) {
            $self->write_packet($returncode);
        }
    } 
 
}

sub connect_callback {
    my ( $self, $buffer ) = @_;

    unless ($buffer =~ s/^([^\0]*)\0(.)//) {
        die "SMFIC_CONNECT: invalid connect info\n";
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
