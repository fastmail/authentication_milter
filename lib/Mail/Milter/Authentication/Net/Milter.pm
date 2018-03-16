package Mail::Milter::Authentication::Net::Milter;
use strict;
use Carp;
use vars qw($DEBUG);
# VERSION
$DEBUG=0;

use constant PROTOCOL_NEGATION => 0;

############
sub new
{
# create new blank class
    my $proto = shift;
    my $class = ref($proto) || $proto;
    my $self= {};

# define the various negotiation options
# we'll put them here and not touch them so we can loop through and do bit wise checks later
   $self->{action_types} = ['SMFIF_ADDHDRS', 'SMFIF_CHGBODY', 'SMFIF_ADDRCPT', 'SMFIF_DELRCPT', 'SMFIF_CHGHDRS', 'SMFIF_QUARANTINE'];
   $self->{content_types} = ['SMFIP_NOCONNECT', 'SMFIP_NOHELO', 'SMFIP_NOMAIL', 'SMFIP_NORCPT', 'SMFIP_NOBODY', 'SMFIP_NOHDRS', 'SMFIP_NOEOH'];

    bless($self,$class);
    return $self;
} # end sub new
############

############
sub open {
# open the socket
    use IO::Socket;

    my $self = shift;
    my ($addr,$port,$proto) = @_;

    if ($DEBUG==1) {print STDERR "open\n";}

    my $sock;

    if (lc($proto) eq 'tcp' || lc($proto) eq 'inet') {
    if ($DEBUG==1) {print STDERR "\topen tcp socket\n";}
    use IO::Socket::INET;
        $sock = new IO::Socket::INET (PeerAddr => $addr,
                                      PeerPort => $port,
                                      Proto => 'tcp',
                                      Type => SOCK_STREAM,
                                      Timeout => 10,
                                      ) or carp "Couldn't connect to $addr:$port : $@\n";
    } # end if tcp
    elsif (lc($proto) eq 'unix' || lc($proto) eq 'local') {
    if ($DEBUG==1) {print STDERR "\topen unix socket\n";}
        use IO::Socket::UNIX;
        $sock = new IO::Socket::UNIX (Peer => $addr,
                                      Type => SOCK_STREAM,
                                      Timeout => $port
                                      ) or carp "Couldn't connect to unix socket on $addr : $@\n";
    } # end if unix
    else {carp "$proto is unknown to me\n";}

    if (!defined($sock)) {return 0;}
    else {
        $self->{socket} = $sock;
        return 1;
    }

} # end sub open
############

############
sub protocol_negotiation {
# negotiate with the filter as to what options to use
    my $self = shift;

    my (%options) = @_;

    if ($DEBUG==1) {print STDERR "protocol_negotiation\n";}

# set up the bit mask of allowed actions
    my (@action_types) = @{$self->{action_types}};
    my (@content_types) = @{$self->{content_types}};

    my ($count,$action,$content);

    if ($DEBUG==1) {print STDERR "\tsetting bits\n";}

    my $action_field = 0;

    $count=0;
    while ($action = shift(@action_types)) {
        if (defined($options{$action}) && $options{$action}==0) {
            # do nothing
        }
        else {
            $action_field = $action_field | (2**$count);
        }

        $count++;
    } # end while


# set up the bit mask for possible protocols
    my $protocol_field = 0;

    $count=0;
    while ($content = shift(@content_types)) {
        if (defined($options{$content}) && $options{$content}==1) {
            $protocol_field = $protocol_field | 2**$count;
        }
        else {
            # do nothing
        }

        $count++;
    } # end while

### hmmm this bit might not be right on 64 bit architecture
# we want a 32 bit unsigned integer in network order
    my $smfi_version = 2;  # version of protocol
    my $length = 13;

    if ($DEBUG==1) {print STDERR "\tpacking\n";}

    $action_field = $self->_pack_number($action_field);
    $protocol_field = $self->_pack_number($protocol_field);
    if (PROTOCOL_NEGATION == 1) {$protocol_field = ~$protocol_field;}
    $smfi_version = $self->_pack_number($smfi_version);
    $length = $self->_pack_number($length);

    if ($DEBUG==1) {print STDERR "\tsendsubing\n";}

    $self->{socket}->send($length);
    $self->{socket}->send('O');
    $self->{socket}->send($smfi_version);
    $self->{socket}->send($action_field);
    $self->{socket}->send($protocol_field);

    if ($DEBUG==1) {print STDERR "\treceiving\n";}

    my ($command,$data)=$self->_receive();

    if ($command ne 'O') {carp "error in protocol negotiation \n";}

    my($ret_version,$ret_actions,$ret_protocol)=unpack "NNN",$data;

    if ($DEBUG==1) {print STDERR "\treturned version : $ret_version\n";}
    if ($DEBUG==1) {printf STDERR "\treturned actions : %8b\n", $ret_actions;}
    if ($DEBUG==1) {printf STDERR "\treturned protocol : %7b\n", $ret_protocol;}

# translate returned bit mask into fields
    if ($DEBUG==1) {print STDERR "\ttranslating bit mask\n";}

    my (@returned_actions, @returned_protocol);

    $count=0;
    while ($action = shift(@action_types)) {
        if ($ret_actions & 2**$count) {
            push @returned_actions,$action;
        }
        $count++;
    } # end while

    $count=0;
    while ($content = shift(@content_types)) {
        if ($ret_protocol & 2**$count) {
            push @returned_protocol,$content;
        }
        $count++;
    } # end while



    return ($ret_version,\@returned_actions,\@returned_protocol);
} # end sub protocol_negotiation
############

############
sub send_abort {
# send an abort command, SMFIC_ABORT
# no response expected
# but dont close the connection
if ($DEBUG==1) {print STDERR "send_abort\n";}
    my $self = shift;
    $self->_send('A');

} # end sub send_abort
############

############
sub send_body {
# send body chunk of message, SMFIC_BODY

    my $self = shift;
    my $body = shift;
    if ($DEBUG==1) {print STDERR "send_body\n";}
# restrict body size to max allowable

    if ($DEBUG==1) {print STDERR "\tsending".substr($body,0,5).'...'."\n";}

    if (length ($body)>65535) {
        warn "the message body is too big; its length must be less than 65536 bytes";
        $self->_send('B',substr($body,0,65535));
        $body = substr($body,65535);
    }
    else {
        $self->_send('B',$body);
    }

    if ($DEBUG==1) {print STDERR "\treceiving from body\n";}

# get response
    my (@replies)=$self->_retrieve_responses();
    return(@replies);

} # end sub send_body
############

############
sub send_end_body {
# send body chunk of message, SMFIC_BODY

    my $self = shift;
    my $body = shift;
    if ($DEBUG==1) {print STDERR "send end_body\n";}

    $self->_send('E');
    if ($DEBUG==1) {print STDERR "\treceiving\n";}

# get response
    my (@replies)=$self->_retrieve_responses();
    return(@replies);

} # end sub send_end_body
############

############
sub send_connect {
# send connect message, SMFIC_CONNECT

    my $self = shift;
    my ($hostname,$family,$port,$ip_address) = @_;

    my ($protocol_family);

    $hostname .="\0";
    $ip_address .="\0";

    if ($DEBUG==1) {print STDERR "send connect\n";}

    if (lc($family) eq 'unix') {$protocol_family='L';}
    elsif (lc($family) eq 'tcp4') {$protocol_family='4';}
    elsif (lc($family) eq 'tcp6') {$protocol_family='6';}
    else {$protocol_family='U';}

    $port = pack "n",$port;

    if ($DEBUG==1) {print STDERR "\tsending\n";}

    $self->_send('C',$hostname,$protocol_family,$port,$ip_address);

    my (@replies)=$self->_retrieve_responses();
    return (@replies);
} # end sub send_connect
############

############
sub send_helo {
# send helo string, SMFIC_HELO
    my $self=shift;
    my $helo_string = shift;
    if ($DEBUG==1) {print STDERR "send_helo\n";}

    $helo_string .="\0";
    $self->_send('H',$helo_string);

    if  ($DEBUG==1) {print STDERR "\treceiving\n";}

    my (@replies)=$self->_retrieve_responses();
    return (@replies);
} # end sub send_helo
############

############
sub send_header {
# send a header name and value from message, SMFIC_HEADER

    my $self=shift;
    my $header_name = shift;
    my $header_value = shift;

    if ($DEBUG==1) {print STDERR "send_header\n";}

    $header_name.="\0";
    $header_value.="\0";

    $self->_send('L',$header_name,$header_value);

    my (@replies)=$self->_retrieve_responses();
    return (@replies);
} # end sub send_header
############

############
sub send_mail_from {
# send MAIL FROM information from message, SMFIC_MAIL

    my $self=shift;
    my $mail_from = shift;

    if ($DEBUG==1) {print STDERR "send_mail_from\n";}

    $mail_from.="\0";

    $self->_send('M',$mail_from);

    my (@replies)=$self->_retrieve_responses();
    return (@replies);
} # end sub send_mail_from
############

############
sub send_end_headers {
# send end of headers marker, SMFIC_EOH

    my $self=shift;

    if ($DEBUG==1) {print STDERR "send_end_headers\n";}

    $self->_send('N');

    my (@replies)=$self->_retrieve_responses();
    return (@replies);
} # end sub send_end_headers
############

############
sub send_rcpt_to {
# send RCPT TO information from message, SMFIC_RCPT

    my $self=shift;
    my $rcpt_to = shift;

    if ($DEBUG==1) {print STDERR "send_rcpt_to\n";}

    $rcpt_to.="\0";

    $self->_send('R',$rcpt_to);

    my (@replies)=$self->_retrieve_responses();
    return (@replies);
} # end sub send_rcpt_to
############

############
sub send_quit {
# send a quit command, SMFIC_QUIT
# no response expected
# close the connection
    my $self=shift;

    if ($DEBUG==1) {print STDERR "send_quit\n";}

    $self->_send('Q');

    $self->{socket}->close;

} # end sub send_quit
############

############
sub _send {
# concerned with the details of sending stuff

    my $self = shift;
    my $command = shift;
    my (@data) = @_;

    if ($DEBUG==1) {print STDERR "send\n";}

    my $data = join '',@data;
    my $length = length($data);
    $length += 1;

    if ($DEBUG==1) {
        print STDERR "sending - command : $command\tlength : $length";
        if (length($data)<100) {print STDERR "\tdata : $data\n";}
        else {print STDERR "\n";}
    }

    $length = $self->_pack_number($length);

    if (!defined($self->{socket})) {carp "can't connect no connection defined !\n";}
   $self->_io_send($length);
   $self->_io_send($command);
   $self->_io_send($data) if (length($data) > 0);


} # end sub _send
############

############
sub _receive {
# concerned with the details of receiving stuff

    use IO::Select;

    my $self = shift;

    if ($DEBUG==1) {print STDERR "_receive\n";}

    my $length = $self->_io_recv(4);
    my $command = $self->_io_recv(1);
    $length = $self->_unpack_number($length);
    if ($DEBUG==1) {print STDERR "\tcommand : $command\n\tlength : $length\n";}
    $length -= 1;

    my $data;
    if ($length > 0) {
        $data = $self->_io_recv($length);
    }

    return ($command,$data);
} # end sub _receive
############

############
sub _pack_number {
# single place to pack numbers
    my $self = shift;
    my $number = shift;

    if ($DEBUG==1) {print STDERR "_pack_number\n";}

    my $ret_number =  pack "N",$number;

    return ($ret_number);
} # end sub _pack_number
############

############
sub _unpack_number {
# single place to unpack numbers
    my $self = shift;
    my $number = shift;

    if ($DEBUG==1) {print STDERR "_unpack_number\n";}

    my $ret_number =  unpack "N",$number;

    return ($ret_number);
} # end sub _unpack_number
############

############
sub _translate_response {
# turn what we get from the filter into something more manageable

    my $self = shift;
    my ($command,$data)=@_;

    if ($DEBUG==1) {
        print STDERR "_translate_response\n";
        print STDERR "\tcommand : $command\n";
        if (defined($data) && $command !~/[hm]/) {print STDERR "\tdata : $data\n";}
    }

    my %reply=();

    $reply{command}=$command;

    if ($command eq '+') {
        $reply{explanation}='Add a recipient';
        $reply{header}='To';
        $reply{action}='add';
        $reply{value}=$data;
    }

    elsif ($command eq '-') {
        $reply{explanation}='Remove a recipient';
        $reply{header}='To';
        $reply{action}='delete';
        $reply{value}=$data;
    }

    elsif ($command eq 'a') {
        $reply{explanation}='Accept message completely';
        $reply{action}='accept';
    }

    elsif ($command eq 'b') {
        $reply{explanation}='Replace body chunk';
        $reply{header}='body';
        $reply{action}='replace';
        $reply{value}=$data;
    }

    elsif ($command eq 'c') {
        $reply{explanation}='Accept and continue';
        $reply{action}='continue';
    }

    elsif ($command eq 'd') {
        $reply{explanation}='Reject message completely';
        $reply{action}='reject';
    }

    elsif ($command eq 'h') {
        $reply{explanation}='Add header';
        ($reply{header},$reply{value},undef)=split(/\0/,$data);
        $reply{action}='add';
    }

    elsif ($command eq 'i') {
        $reply{explanation}='Insert header';
        $reply{index}=$self->_unpack_number(substr($data,0,4));
        $data = substr($data,4);
        ($reply{header},$reply{value},undef)=split(/\0/,$data);
        $reply{action}='insert';
    }

    elsif ($command eq 'm') {
        $reply{explanation}='Replace body header';
        $reply{index}=$self->_unpack_number(substr($data,0,4));
        $data = substr($data,4);
        ($reply{header},$reply{value},undef)=split(/\0/,$data);
        $reply{action}='replace';
    }

    elsif ($command eq 'p') {
        $reply{explanation}='Progress';
        $reply{action}='continue';
    }

    elsif ($command eq 'r') {
        $reply{explanation}='Reject command with 5xx error';
        $reply{action}='reject';
        $reply{value}=5;
    }

    elsif ($command eq 't') {
        $reply{explanation}='Reject command with 4xx error';
        $reply{action}='reject';
        $reply{value}=4;
    }

    elsif ($command eq 'y') {
        $reply{explanation}='Reject command with xxx error';
        $reply{action}='reject';
        $reply{value}=$data;
    }


    return (\%reply);
} # end sub _translate_response
############

############
sub _retrieve_responses {

    my $self = shift;

    my (@replies,$command,$data,$reply_ref);

    if ($DEBUG==1) {print STDERR "_retrieve_response\n";}

    while () {
        if ($DEBUG==1) {print STDERR "\twaiting for response\n";}
        ($command,$data)=$self->_receive();
        ($reply_ref)=$self->_translate_response($command,$data);

        push @replies,$reply_ref;

        if ($DEBUG==1) {print STDERR "\tcommand : $$reply_ref{command}";}
        if ($$reply_ref{command} eq 'c') {last;}
        elsif ($$reply_ref{command} eq 'a') {last;}
        elsif ($$reply_ref{command} eq 'r') {last;}
        elsif ($$reply_ref{command} eq 't') {last;}
        elsif ($$reply_ref{command} eq 'y') {last;}
        elsif ($$reply_ref{command} eq 'd') {last;}
    } # end while

    return (@replies);
} # end sub retrieve_responses
############

############
sub send_macros {
    my $self=shift;
    my %macros = @_;

    if ($DEBUG==1) {print STDERR "retrieve_response\n";}

    my (@data);

    if ($DEBUG==1) {
        foreach (keys(%macros)) {
            print STDERR "\tmacro : $_ = $macros{$_}\n";
        }
    } # end if DEBUG

    if (defined($macros{j})) {push @data,'j'."\0".$macros{j}."\0";}
    if (defined($macros{_})) {push @data,'_'."\0",$macros{_}."\0";}
    if (defined($macros{'{daemon_name}'})) {push @data,'{daemon_name}'."\0".$macros{'{daemon_name}'}."\0";}
    if (defined($macros{'{if_name}'})) {push @data,'{if_name}'."\0".$macros{'{if_name}'}."\0";}
    if (defined($macros{'{if_addr}'})) {push @data,'{if_addr}'."\0".$macros{'{if_addr}'}."\0";}

    if (@data) {
        if ($DEBUG==1) {print STDERR "\tsending D,C\n";}
        $self->_send('D','C',@data);
    }

    @data=();
    if (defined($macros{'{tls_version}'})) {push @data,'{tls_version}'."\0".$macros{'{tls_version}'}."\0";}
    if (defined($macros{'{cipher}'})) {push @data,'{cipher}'."\0".$macros{'{cipher}'}."\0";}
    if (defined($macros{'{cipher_bits}'})) {push @data,'{cipher_bits}'."\0".$macros{'{cipher_bits}'}."\0";}
    if (defined($macros{'{cert_subject}'})) {push @data,'{cert_subject}'."\0".$macros{'{cert_subject}'}."\0";}
    if (defined($macros{'{cert_issuer}'})) {push @data,'{cert_issuer}'."\0".$macros{'{cert_issuer}'}."\0";}

    if (@data) {
        if ($DEBUG==1) {print STDERR "\tsending D,H\n";}
        $self->_send('D','H',@data);
    }



    @data=();
    if (defined($macros{i})) {push @data,'i'."\0".$macros{i}."\0";}
    if (defined($macros{'{auth_type}'})) {push @data,'{auth_type}'."\0".$macros{'{auth_type}'}."\0";}
    if (defined($macros{'{auth_authen}'})) {push @data,'{auth_authen}'."\0".$macros{'{auth_authen}'}."\0";}
    if (defined($macros{'{auth_ssf}'})) {push @data,'{auth_ssf}'."\0".$macros{'{auth_ssf}'}."\0";}
    if (defined($macros{'{auth_author}'})) {push @data,'{auth_author}'."\0".$macros{'{auth_author}'}."\0";}
    if (defined($macros{'{mail_mailer}'})) {push @data,'{mail_mailer}'."\0".$macros{'{mail_mailer}'}."\0";}
    if (defined($macros{'{mail_host}'})) {push @data,'{mail_host}'."\0".$macros{'{mail_host}'}."\0";}
    if (defined($macros{'{mail_addr}'})) {push @data,'{mail_addr}'."\0".$macros{'{mail_addr}'}."\0";}

    if (@data) {
        if ($DEBUG==1) {print STDERR "\tsending D,M\n";}
        $self->_send('D','M',@data);
    }


    @data=();
    if (defined($macros{'{rcpt_mailer}'})) {push @data,'{rcpt_mailer}'."\0".$macros{'{rcpt_mailer}'}."\0";}
    if (defined($macros{'{rcpt_host}'})) {push @data,'{rcpt_host}'."\0".$macros{'{rcpt_host}'}."\0";}
    if (defined($macros{'{rcpt_addr}'})) {push @data,'{rcpt_addr}'."\0".$macros{'{rcpt_addr}'}."\0";}

    if (@data) {
        if ($DEBUG==1) {print STDERR "\tsending D,R\n";}
        $self->_send('D','R',@data);
    }


# no response after sending macros
    return 1;

} # end sub send_macros
############

############
sub _io_send {
    my $self = shift;
    my ($data) = @_;

    my $must_send = length($data);
    my $did_send = 0;
    while ($did_send < $must_send) {
        my $len = $self->{socket}->send(substr($data, $did_send));
        if (defined($len)) {
            $did_send += $len;
        }
        else {
            carp "Error while writing to the socket: $!";
        }
    }

    return 1;
}
############

############
sub _io_recv {
    my $self = shift;
    my ($must_recv) = @_;

    my $did_recv = 0;
    my $data = "";
    while ($did_recv < $must_recv) {
        my $len = $self->{socket}->sysread($data, $must_recv-$did_recv, $did_recv);
        if (defined($len)) {
            $did_recv += $len;
        }
        else {
            carp "Error while reading from the socket: $!";
        }
    }

    return $data;
}
############

############
sub DESTROY {
    my $self = shift;
    if (defined($self->{socket})) {
        $self->{socket}->close;
    } # end if

} # end sub DESTROY
############

1;

__END__

=head1 NAME

Net::Milter - Masquerade as the MTA to communicate with email
filters through a milter interface.

=head1 SYNOPSIS

    use Net::Milter;
    my $milter = new Net::Milter;
    $milter->open('127.0.0.1',5513,'tcp');

    my ($milter_version,$returned_actions_ref,$returned_protocol_ref) =
    $milter->protocol_negotiation();

    my (@results) = $milter->send_header('From','martin@localhost');
    foreach (@results) {
      if ($$_{action} eq 'reject')  {exit;}
    }


Also see example in scripts directory.

=head1 DESCRIPTION

Perl module to provide a pure Perl implementation of the MTA part the
milter interface. The goal of this module is to allow other email
systems to easily integrate with the various email filters that accept
content via milter.

This implementation of milter is developed from the description provided
by Todd Vierling,
cvs.sourceforge.net/viewcvs.py/pmilter/pmilter/doc/milter-protocol.txt?rev=1.2
and from examining the tcp output from Sendmail.

=head2 Attributes

=over

=item action_types

Reference to an array of the set of actions defined within Sendmail's milter code.

=item content_types

Reference to an array of the set of content types which may be witheld.

=back

=head2 Methods

=over

=item new

Constructor, creates a new blank Net::Milter object.

=item open

Open a socket to a milter filter. Takes three arguments, the last
argument, can be 'tcp' or 'unix' depending if the connection is to be
made to a TCP socket or through a UNIX file system socket. For TCP
sockets, the first two argument are the IP address and the port number;
for UNIX sockets the first argument is the file path, the second the
timeout value.
Accepted synonyms for tcp and unix are inet and local respecively.

e.g.

    $milter->open('127.0.0.1',5513,'tcp');

to open a connection to port 5513 on address 127.0.0.1,
or

    $milter->open('/tmp/file.sck',10,'unix');

to open a connection to /tmp/file.sck with a timeout of 10 seconds.

The method creates the attribute, 'socket' containing an IO::Handle
object.

=item protocol_negotiation

Talk to the milter filter, describing the list of actions it may
perform, and any email content that won't be sent.
Accepts as argument the hash of allowable actions and withheld content.
The hash keys are :
Allowable actions by the filter :

=over

=item SMFIF_ADDHDRS - Add message headers.

=item SMFIF_CHGBODY - Alter the message body.

=item SMFIF_ADDRCPT - Add recipients to the message.

=item SMFIF_DELRCPT - Delete recipients from the message.

=item SMFIF_CHGHDRS - Change or delete message headers.

=back

The default is to allow all actions, setting the value to be '0' of any
of these keys in the argument hash informs the filter not perform the
action.

e.g.

    $milter->protocol_negotiation(
        SMFIF_ADDHDRS => 0,
        SMFIF_CHGBODY => 1
        );

informs the filter it is able to change the contents of the message
body, but it may not add message headers.

Withheld content :

=over

=item SMFIP_NOCONNECT - Do not expect the connection details.

=item SMFIP_NOHELO - Do not expect the HELO string.

=item SMFIP_NOMAIL - Do not expect the MAIL FROM string.

=item SMFIP_NORCPT - Do not expect the RCPT TO string.

=item SMFIP_NOBODY - Do not expect the email body.

=item SMFIP_NOHDRS - Do not expect any email headers.

=item SMFIP_NOEOH - Do not expect an end of headers signal.

=back

The default is to inform the filter to expect everything, setting the
value of the key to '1' informs the filter to not expect the content.

e.g.

    $milter->protocol_negotiation(
        SMFIF_ADDHDRS => 0,
        SMFIF_CHGBODY => 1,
        SMFIP_NOEHO => 1,
        SMFIP_NOCONNECT => 1
    );

informs the filter it is able to change the contents of the message
body, but it may not add message headers, it will not receive an end
of headers signal, nor will it receive the connection details.

The method returns three parameters, the protocol version, an array
reference containing all the names of the actions the filter
understands it is able to perform, and an array reference
containing the names of the content it understands it won't be sent.

=item send_abort

Send an abort signal to the mail filter.
Accepts nothing, returns nothing.

=item send_body

Send the body of the email to the mail filter.
NOTE the filter will only accept up to 65535 bytes of body at a time.
Feed the body to the filter piece by piece by repeat calls to send_body
with each body chunk until all the body is sent.
Accepts the message body, returns reference to an array of return codes
(see RETURN CODE section).

=item send_end_body

Send an end of body signal, i.e. no more body information will
follow. Returns a reference to an array of return codes (see RETURN
CODE section).

=item send_connect

Send the SMTP connect information to the mail filter.
Accepts the hostname, the family ('unix' for file sockets, 'tcp4' for
tcp connections (v4), 'tcp6' for version 6 tcp connections), the sending
connection port, the IP address of the sender. Returns a reference to an
array of return codes (see RETURN CODE section).

e.g.

    $milter->send_connect(
                          'host.domain',
                          'tcp4',
                          '12345',
                          '127.0.0.1'
                          );

The machine host.domain with IP address 127.0.0.1 connected to
us from port 12345 using TCP version 4.

=item send_helo

Send the HELO (or EHLO) string provided by the connecting computer.
Accepts the HELO string as an argument. Returns a reference to an array
of return codes (see RETURN CODE section).

=item send_header

Send a single header name and contents to the filter, accepts two
arguments, the header name and the header contents. Returns a reference
to an array of return codes (see RETURN CODE section).

=item send_mail_from

Send the MAIL FROM string to the filter, accepts the MAIL FROM data as
an argument. Returns a reference to an array of return codes (see
RETURN CODE section).

=item send_end_headers

Send an end of headers signal, i.e. no more header information will
follow. Returns a reference to an array of return codes (see RETURN
CODE section).

=item send_rcpt_to

Send the RCPT TO string to the filter, accepts an array of RCPT TO
recipients as argument. Returns a reference to an array of return
codes (see RETURN CODE section).

=item send_quit

Quit the milter communication, accepts nothing, returns nothing.

=item send_macros

Send Sendmail macro information to the filter. The method accepts a
hash of the Sendmail macro names, returns  a reference to an array of
return codes (see RETURN CODE section).

The potential macro names (hash keys) are :

=over

=item _              - email address of the Sendmail user.

=item j              - canonical hostname of the recipeint machine.

=item {daemon_name}  - name of the daemon from DaemonPortOptions.

=item {if_name}      - hostname of the incoming connection.

=item {if_addr}      - IP address of the incoming connection.

=item {tls_version}  - TLS/SSL version used for connection.

=item {cipher}       - cipher suite used for the connection.

=item {cipher_bits}  - keylength of the encryption algorith.

=item {cert_subject} - distinguished name of the presented certificate.

=item {cert_issuer}  - name of the certificate authority.

=item i              - queue ID.

=item {auth_type}    - SMTP authentication mechanism.

=item {auth_authen}  - client's authenticated username.

=item {auth_ssf}     - keylength of encryption algorithm.

=item {auth_author}  - authorization identity.

=item {mail_mailer}  - mailer from SMTP MAIL command.

=item {mail_host}    - host from SMTP MAIL command.

=item {mail_addr}    - address from SMTP MAIL command.

=item {rcpt_mailer}  - mailer from SMTP RCPT command.

=item {rcpt_host}    - host from SMTP RCPT command.

=item {rcpt_addr}    - address from SMTP RCPT command.

=back

Yes I know most of this is redundant, since other methods repeat this
information, but this is what the spec says.

e.g.
    $milter->send_macros(
        mail_addr => '127.0.0.1',
        mail_host => 'localhost',
        rcpt_addr => '127.0.0.1',
        rcpt_addr => 'postmaster@localhost.localdomain'
    );

For further explanation of macros see :

http://people.freenet.de/slgig/op_en/macros.html
and
http://www.sendmail.com/idemo/prod_guide/switch/switchdemo/helplets/en/Macros.html

=back

=head1 RETURN CODES

Many methods return an array of hash references. Each hash describes
one response from the filter, a filter may return more than one
response to any sent data, such as 'add a header','modify body',
'continue'.
The hash keys are :

=over

=item command - the response from the filter

=item explanation - verbose explanation of the required action

=item action - action to perform, may be I<add>, I<delete>, I<accept>, I<replace>, I<continue> or I<reject>

=item header - the name of header the action refers to (may be equal to 'body' to refer to the message body)

=item value - the value relating to the action

=back

=head1 TIPS

Call the various methods in the order that they would be called if accepting
a SMTP stream, ie send_connect(), send_helo(),  send_mail_from(), send_rcpt_to(),
send_header(), send_end_headers(), send_body(). Some milter filters expect this
and refuse to return values when expected.
Equally continuing to send data when a filter has rejected or accepted a
message may confuse it, and refuse to return values for subsequent data, so
always check the codes returned.

In some circumstantes 'read' has not worked, now replaced by 'sysread' which is
reported to fix the problem. If this doesn't work, change 'sysread' to 'read' and
email me please.

Some filters appear to expect a bitwise negation of the protocol field. This is
now disabled as default. If you wish to enable this, please set
PROTOCOL_NEGATION => 1

=head1 SEE ALSO

This module is the Yang to Ying's Sendmail::Milter, which can act as the other end
of the communication.

=head1 NAMING

I choose not to put this module in the Sendmail namespace, as it has nothing to do
with Sendmail itself, neither is it anything to do with SMTP, its a net protocol,
hence the Net namespace.

=head1 AUTHOR

Martin Lee, MessageLabs Ltd. (mlee@messagelabs.com)

Copyright (c) 2003 Star Technology Group Ltd / 2004 MessageLabs Ltd.

=cut


