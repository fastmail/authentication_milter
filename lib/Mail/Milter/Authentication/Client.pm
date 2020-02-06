package Mail::Milter::Authentication::Client;
use 5.20.0;
use strict;
use warnings;
use Mail::Milter::Authentication::Pragmas;
# ABSTRACT: Client for connecting back to the authmilter server
# VERSION
use Mail::Milter::Authentication::Net::Milter;
use Data::Dumper;
use Digest::MD5 qw{ md5_base64 };
use Email::Simple;

=head1 DESCRIPTION

Client to the Authentication Milter

=head1 SYNOPSIS

Connect to the Authentication Milter and pass it email, returning the result.

=cut

=constructor I<new( $args )>

Instantiate a new Client object

    my $client = Mail::Milter::Authentication::Client->new({
        'mailer_name'   => 'test.mta.yoga.fastmail.com',
        'connect_ip'    => '66.111.4.148',
        'connect_name'  => 'test.fastmail.com',
        'connect_port'  => '54321',
        'connect_type'  => 'tcp4',
        'helo_host'     => 'test.helo.fastmail.com',
        'mail_from'     => 'test@marc.fastmail.com',
        'rcpt_to'       => 'marc@yoga',
        'mail_data'     => $email_content,
        'mail_file'     => '/path/to/email.txt',
    });

=head2 Arguments

=over

=item mailer_name

The name (fqdn) of the MTA

=item connect_ip

The IP address of the host connecting to the mailer.

=item connect_name

The name of the host connecting to the mailer.

=item connect_port

The port of the connection to the mailer.

=item connect_type

The type of connection to the mailer (eg tcp4).

=item helo_host

The string passed in the HELO stage of the SMTP transaction.

=item mail_from

The string passed in the MAIL FROM stage of the SMTP transaction.

=item rcpt_to

The string passed in the RCPT TO stage of the SMTP transaction.

=item mail_data

The EMail body as a string.

=item mail_file

The EMail body can also be passed as a filename.

=back

=cut

sub new {
    my ( $class, $args ) = @_;

    $class = ref($class) || $class;
    my $self = {};

    my $config = get_config();
    {
        my $connection = $config->{'connection'}             || die('No connection details given');
        $connection =~ /^([^:]+):([^:@]+)(?:@([^:@]+|\[[0-9a-f:\.]+\]))?$/;
        my $type = $1;
        my $path = $2;
        my $host = $3 || q{};
        if ( $type eq 'inet' ) {
            $self->{'type'} = 'tcp';
            $self->{'port'} = $path;
            $self->{'path'} = $host;
        }
        elsif ( $type eq 'unix' ) {
            $self->{'type'} = 'unix';
            $self->{'port'} = 10;
            $self->{'path'} = $path;
        }
        else {
            die 'Invalid connection';
        }
    }

    if ( $config->{'protocol'} ne 'milter' ) {
        die 'Client only works with milter protocol mode';
    }

    $self->{'mailer_string'} = 'Testfix 1.00.0';
    $self->{'mailer_name'}   = $args->{'mailer_name'}  || 'test.mta.example.com';

    $self->{'connect_ip'}    = $args->{'connect_ip'}   || '66.111.4.147';
    $self->{'connect_name'}  = $args->{'connect_name'} || 'test.example.com';
    $self->{'connect_port'}  = $args->{'connect_port'} || '123456';
    $self->{'connect_type'}  = $args->{'connect_type'} || 'tcp4';

    $self->{'helo_host'}     = $args->{'helo_host'}    || 'test.host.example.com';
    $self->{'mail_from'}     = $args->{'mail_from'}    || '';
    $self->{'rcpt_to'}       = $args->{'rcpt_to'}      || 'test@to.example.com';

    # Generate a unique Queue ID
    $self->{'queue_id'}      = md5_base64( "Authentication Milter Client $PID " . time() );

    $self->{'mail_file'}     = $args->{'mail_file'};
    $self->{'mail_data'}     = $args->{'mail_data'};
    if ( ! $self->{'mail_file'} && ! $self->{'mail_data'} ) {
        die 'No mail file or data supplied';
    }

    $self->{'testing'}       = $args->{'testing'};

    $self->{'milter'} = Mail::Milter::Authentication::Net::Milter->new();

    bless($self,$class);
    return $self;
}

=method I<r()>

Private method, do not call this directly

=cut

sub r { ## no critic [Subroutines::RequireArgUnpacking]
    my $self = shift;
    my @results = @_;
    RESULT:
    foreach my $result ( @results ) {
        my $action = $result->{'action'};
        if ( $action eq 'continue' ) {
            next RESULT;
        }
        elsif ( $action eq 'insert' ) {
            my $value = $result->{'value'};
            my $header = $result->{'header'};
            my $index = $result->{'index'};
            $self->insert_header( $index, $header, $value );
#            warn "INSERT HEADER $header at position $index\n$value\n\n";
        }
        elsif ( $action eq 'replace' ) {
            my $value = $result->{'value'};
            my $header = $result->{'header'};
            my $index = $result->{'index'};
            $self->replace_header( $index, $header, $value );
#            warn "REPLACE HEADER $header at position $index\n$value\n\n";
        }
        elsif ( $action eq 'add' ) {
            my $value = $result->{'value'};
            my $header = $result->{'header'};
            $self->add_header( $header, $value );
#            warn "ADD HEADER $header\n$value\n\n";
        }
        elsif ( $action eq 'reject' ) {
            my $value = $result->{'value'} || q{};
            $value =~ s/\0/ /g;
            if ( $self->{'testing'} ) {
                $self->{'rejected'} = "Message rejected with code : $value";
            }
            else {
                die "Message rejected with code : $value\n";
            }
        }
        else {
            warn "Unknown Action\n";
            warn Dumper $result;
        }
    }
    return;
}

=method I<insert_header()>

Private method, do not call this directly

=cut

sub insert_header {
    my ( $self, $index, $header, $value ) = @_;
    my @process_header = @{ $self->{'header_pairs'} };
    my @header_pairs;
    my $i = 1;
    while ( @process_header ) {
        my $key = shift @process_header;
        my $evalue = shift @process_header;
        if ( $i == $index ) {
            push @header_pairs, $header;
            push @header_pairs, $value;
        }
        push @header_pairs, $key;
        push @header_pairs, $evalue;
        $i++;
    }
    $self->{'header_pairs'} = \@header_pairs;
    return;
}

=method I<replace_header()>

Private method, do not call this directly

=cut

sub replace_header {
    my ( $self, $index, $header, $value ) = @_;

    my @process_header = @{ $self->{'header_pairs'} };
    my @header_pairs;
    my $i = 1;
    while ( @process_header ) {
        my $key = shift @process_header;
        my $evalue = shift @process_header;
        if ( lc $key eq lc $header ) {
            if ( $i == $index ) {
                if ( $value eq q{} ) {
                    # NOP
                }
                else {
                    push @header_pairs, $key;
                    push @header_pairs, $value;
                }
            }
            else {
                push @header_pairs, $key;
                push @header_pairs, $evalue;
            }
            $i++;
        }
        else {
            push @header_pairs, $key;
            push @header_pairs, $evalue;
        }
    }
    $self->{'header_pairs'} = \@header_pairs;
    return;
}

=method I<add_header()>

Private method, do not call this directly

=cut

sub add_header {
    my ( $self, $header, $value ) = @_;
    my @header_pairs = @{ $self->{'header_pairs'} };
    push @header_pairs, $header;
    push @header_pairs, $value;
    $self->{'header_pairs'} = \@header_pairs;
    return;
}

=method I<load_mail()>

Private method, do not call this directly

=cut

sub load_mail {
    my ( $self ) = @_;

    my $mail_data;
    if ( $self->{'mail_file'} ) {
        open my $inf, '<', $self->{'mail_file'};
        my @mail_content = <$inf>;
        close $inf;
        $mail_data = join( q{}, @mail_content );
    }
    elsif ( $self->{'mail_data'} ) {
        $mail_data = $self->{'mail_data'};
    }

    my @header_pairs;
    my @header_split;

    HEADERS:
    foreach my $dataline ( split ( "\n", $mail_data ) ) {
        $dataline =~ s/\r?\n$//;
        # Handle transparency
        if ( $dataline =~ /^\./ ) {
            $dataline = substr( $dataline, 1 );
        }
        if ( $dataline eq q{} ) {
            last HEADERS;
        }
        push @header_split, $dataline;
    }

    my $value = q{};
    foreach my $header_line ( @header_split ) {
        if ( $header_line =~ /^\s/ ) {
            $value .= "\r\n" . $header_line;
        }
        else {
            if ( $value ) {
                my ( $hkey, $hvalue ) = split ( ':', $value, 2 );
                $hvalue =~ s/^ // if defined $hvalue;
                push @header_pairs , $hkey;
                push @header_pairs , $hvalue;
            }
            $value = $header_line;
        }
    }
    if ( $value ) {
        my ( $hkey, $hvalue ) = split ( ':', $value, 2 );
        $hvalue =~ s/^ // if defined $hvalue;
        push @header_pairs , $hkey;
        push @header_pairs , $hvalue;
    }

    my $message_object = Email::Simple->new( $mail_data );
    $self->{'message_object'} = $message_object;
    $self->{'header_pairs'}   = \@header_pairs;
    return;
}

=method I<process()>

Send the email to the milter and process the result.

=cut

sub process {
    my ( $self ) = @_;

    $self->load_mail();
    my $milter = $self->{'milter'};

    $milter->open( $self->{'path'}, $self->{'port'}, $self->{'type'} );
    $milter->protocol_negotiation(
        SMFIF_ADDHDRS => 1,
        SMFIF_CHGBODY => 0,
        SMFIF_ADDRCPT => 0,
        SMFIF_DELRCPT => 0,
        SMFIF_CHGHDRS => 1,
        SMFIP_NOCONNECT => 0,
        SMFIP_NOHELO => 0,
        SMFIP_NOMAIL => 0,
        SMFIP_NORCPT => 0,
        SMFIP_NOBODY => 0,
        SMFIP_NOHDRS => 0,
        SMFIP_NOEOH => 0,
    );

    $milter->send_macros(
        'v' => $self->{'mailer_string'},
        'j' => $self->{'mailer_name'},
        '{daemon_name}' => $self->{'$mailer_name'},
    );

    $self->r( $milter->send_connect(
        $self->{'connect_name'},
        $self->{'connect_type'},
        $self->{'connect_port'},
        $self->{'connect_ip'},
    ));

    $self->r( $milter->send_helo( $self->{'helo_host'} ));

    $milter->send_macros(
        '{mail_mailer}' => 'smtp',
        '{mail_addr}' => $self->{'mail_from'},
        '{mail_host}' => $self->{'helo_host'},
    );
    $self->r( $milter->send_mail_from( $self->{'mail_from'} ));

    $milter->send_macros(
        '{rcpt_mailer}' => 'local',
        '{rcpt_addr}' => $self->{'rcpt_to'},
        '{rcpt_host}' => $self->{'helo_host'},
    );
    $self->r( $milter->send_rcpt_to( $self->{'rcpt_to'} ));

    my @process_header = @{ $self->{'header_pairs'} };
    while ( @process_header ) {
        my $key = shift @process_header;
        my $value = shift @process_header;
        $self->r( $milter->send_header( $key, $value ));
    }

    $milter->send_macros( 'i' => $self->{'queue_id'} );
    $self->r( $milter->send_end_headers());

    my $body = $self->{'message_object'}->body();
    $milter->send_macros( 'i' => $self->{'queue_id'} );
    $self->r( $milter->send_body( $body ));

    $milter->send_macros( 'i' => $self->{'queue_id'} );
    $self->r( $milter->send_end_body());

    $milter->send_abort();

    $milter->send_quit();

    my $header_string = q{};
    {
        my @process_header = @{ $self->{'header_pairs'} };
        while ( @process_header ) {
            my $key = shift @process_header;
            my $value = shift @process_header;
            $value = '' unless defined $value;
            $header_string .= "$key: $value\015\012";
        }
        my $header_obj = Email::Simple::Header->new( $header_string );
        $self->{'message_object'}->header_obj_set( $header_obj );
    }

    $self->{'result'} =  $self->{'message_object'}->as_string();
    return;
}

=method I<result()>

Return the result of the milter run

=cut

sub result {
    my ( $self ) = @_;
    return $self->{'rejected'} if $self->{'rejected'} && $self->{'testing'};
    return $self->{'result'};
}

1;

=pod

=head1 Net::Milter

This project includes a modified copy of Net::Milter which is
imported into the Mail::Milter::Authentication::Net::Milter
namespace.

The included module has been modified to support all of the
features required by Authentication Milter.

If these required features are ever merged back into Net::Milter
then we may just use it instead, however at this point the
modified version does the job.

=cut

