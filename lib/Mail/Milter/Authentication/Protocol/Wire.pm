package Mail::Milter::Authentication::Protocol::Wire;

use strict;
use warnings;

our $VERSION = 0.4;

use Socket;
use Socket6;

use Mail::Milter::Authentication::Handler;
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

use Mail::Milter::Authentication::Constants qw{ :all };

sub new {
    my ( $class, $socket ) = @_;

    my $callback_flags = SMFI_CURR_ACTS;
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
    my $close_called = 0;
    while ( ! $quit ) {

        # Get packet length 
        my $length = unpack('N', $self->read_block(4) ) || last;
        die "bad packet length $length\n" if ($length <= 0 || $length > 131072);

        # Get command
        my $command = $self->read_block(1) || last;

        # Get data
        my $data = $self->read_block($length - 1) || die "EOF in stream\n";

        $self->process_command( $command, $data );

    }    

    if ( ! $close_called ) {
    # Call close callback
        $self->{'handler'}->close_callback();
        $self->destroy_objects();
    }
}

sub setup_objects {
    my ( $self ) = @_;
    my $handler = Mail::Milter::Authentication::Handler->new( $self );
    $handler->set_handler( 'generic',   Mail::Milter::Authentication::Handler::Generic->new( $self ) );
    $handler->set_handler( 'auth',      Mail::Milter::Authentication::Handler::Auth->new( $self ) );
    $handler->set_handler( 'core',      Mail::Milter::Authentication::Handler::Core->new( $self ) );
    $handler->set_handler( 'dkim',      Mail::Milter::Authentication::Handler::DKIM->new( $self ) );
    $handler->set_handler( 'dmarc',     Mail::Milter::Authentication::Handler::DMARC->new( $self ) );
    $handler->set_handler( 'iprev',     Mail::Milter::Authentication::Handler::IPRev->new( $self ) );
    $handler->set_handler( 'localip',   Mail::Milter::Authentication::Handler::LocalIP->new( $self ) );
    $handler->set_handler( 'ptr',       Mail::Milter::Authentication::Handler::PTR->new( $self ) );
    $handler->set_handler( 'sanitize',  Mail::Milter::Authentication::Handler::Sanitize->new( $self ) );
    $handler->set_handler( 'senderid',  Mail::Milter::Authentication::Handler::SenderID->new( $self ) );
    $handler->set_handler( 'spf',       Mail::Milter::Authentication::Handler::SPF->new( $self ) );
    $handler->set_handler( 'trustedip', Mail::Milter::Authentication::Handler::TrustedIP->new( $self ) );
    $self->{'handler'} = $handler;
}

sub destroy_objects {
    my ( $self ) = @_;
    my $handler = $self->{'handler'};
    $handler->destroy_handler( 'generic' );
    $handler->destroy_handler( 'auth' );
    $handler->destroy_handler( 'core' );
    $handler->destroy_handler( 'dkim' );
    $handler->destroy_handler( 'dmarc' );
    $handler->destroy_handler( 'iprev' );
    $handler->destroy_handler( 'localip' );
    $handler->destroy_handler( 'ptr' );
    $handler->destroy_handler( 'sanitize' );
    $handler->destroy_handler( 'senderid' );
    $handler->destroy_handler( 'spf' );
    $handler->destroy_handler( 'trustedip' );
    delete $self->{'handler'};
}

sub process_command {
    my ( $self, $command, $buffer ) = @_;

    my $handler = $self->{'handler'};
    my $returncode = SMFIS_CONTINUE;

    if ( $command == SMFIC_CONNECT ) {
        $self->setup_objects();
        $handler = $self->{'handler'};
        my ( $host, $sockaddr_in ) = $$self->connect_callback( $buffer );
        $returncode = $handler->connect_callback( $host, $sockaddr_in );
    }
    elsif ( $command == SMFIC_ABORT ) {
        $handler->clear_symbols();
        $returncode = $handler->abort_callback();
    }
    elsif ( $command == SMFIC_BODY ) {
        $returncode = $handler->body_callback( $buffer );
    }
    elsif ( $command == SMFIC_MACRO ) {
        die "SMFIC_MACRO: empty packet\n" unless ( $buffer =~ s/^(.)// );
        my $code = $1;
        my $data = $self->split_buffer( $buffer );
        push ( @$data, q{} ) if (( @$data & 1 ) != 0 ); # pad last entry with empty string if odd number
        my %datahash = @$data;
        foreach my $key ( keys %datahash ) {
            $self->set_symbol( $code, $key, $datahash{$key} );
        }
        undef $returncode;
    }
    elsif ( $command == SMFIC_BODYEOB ) {
        $returncode = $handler->eom_callback();
    }
    elsif ( $command == SMFIC_HELO ) {
        my $helo = $self->split_buffer( $buffer );
        $returncode = $handler->helo_callback( @$helo );
    }
    elsif ( $command == SMFIC_HEADER ) {
        my $header = $self->split_buffer( $buffer );
        if ( @$header == 1 ) { push @$header , q{}; };
        $returncode = $handler->header_callback( @$header );
    }
    elsif ( $command == SMFIC_MAIL ) {
        my $envfrom = $self->split_buffer( $buffer );
        $returncode = $handler->envfrom_callback( @$envfrom );
    }
    elsif ( $command == SMFIC_EOH ) {
        $returncode = $handler->eoh_callback();
    }
    elsif ( $command == SMFIC_OPTNEG ) {
        die "SMFIC_OPTNEG: packet has wrong size\n" unless (length($buffer) == 12);
        my ($ver, $actions, $protocol) = unpack('NNN', $buffer);
        die "SMFIC_OPTNEG: unknown milter protocol version $ver\n" unless ($ver >= 2 && $ver <= 6);
        $self->write_packet(SMFIC_OPTNEG,
            pack('NNN', 2,
                $self->{callback_flags} & $actions,
                $self->{protocol} & $protocol,
            )
        );
    }
    elsif ( $command == SMFIC_RCPT ) {
        my $envrcpt = $self->split_buffer( $buffer );
        $returncode = $handler->envrcpt_callback( @$envrcpt );
    }
    elsif ( $command == SMFIC_DATA ) {
    }
    elsif ( $command == SMFIC_QUIT ) {
        last;
    }
    elsif ( $command == SMFIC_UNKNOWN ) {
        # Unknown SMTP command received
    }
    else {
        die "Unknown milter command $command";
    }

    if ( $command != SMFIC_ABORT ) {
        if (defined $returncode) {
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
        return ( $host, $pack );
    }
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

sub add_header {
    my ( $self, $header, $value ) = @_;
    $self->write_packet( SMFIR_ADDHEADER,
        $header
        . "\0"
        . $value
        ."\0"
    );
}

sub change_header {
    my ( $self, $header, $index, $value );
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
    my $socket = $self->{'socket'};
    $data = q{} unless defined($data);
    my $len = pack('N', length($data) + 1);
    $socket->syswrite($len);
    $socket->syswrite($code);
    $socket->syswrite($data);
}

1;
