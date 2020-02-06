package Mail::Milter::Authentication::Protocol::Milter;
use 5.20.0;
use strict;
use warnings;
use Mail::Milter::Authentication::Pragmas;
# ABSTRACT: Milter protocol handling
# VERSION
use Net::IP;

sub register_metrics {
    return {
        'mail_processed_total' => 'Number of emails processed',
    };
}

sub protocol_process_request {
    my ( $self ) = @_;

    my $handler = $self->{'handler'}->{'_Handler'};
    $handler->top_setup_callback();

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

sub milter_process_command {
    my ( $self, $command, $buffer ) = @_;
    $self->logdebug ( "process command $command" );

    my $handler = $self->{'handler'}->{'_Handler'};

    my $returncode = SMFIS_CONTINUE;

    if ( $command eq SMFIC_CONNECT ) {
        my ( $host, $ip ) = $self->milter_process_connect( $buffer );
        $handler->remap_connect_callback( $host, $ip );
        $returncode = $handler->top_connect_callback( $host, $handler->{'ip_object'} );
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
        if ( $returncode == SMFIS_CONTINUE ) {
            $handler->metric_count( 'mail_processed_total', { 'result' => 'accepted' } );
        }
    }
    elsif ( $command eq SMFIC_HELO ) {
        my $helo = $self->milter_split_buffer( $buffer );
        $handler->remap_helo_callback( @$helo );
        $returncode = $handler->top_helo_callback( $handler->{'helo_name'} );
    }
    elsif ( $command eq SMFIC_HEADER ) {
        my $header = $self->milter_split_buffer( $buffer );
        if ( @$header == 1 ) { push @$header , q{}; };
        my $original = join( ':', @$header );
        push @$header, $original;
        $header->[1] =~ s/^\s+//;
        $header->[0] =~ s/^\s+//;
        $header->[0] =~ s/\s+$//;
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

    my $config = $self->{'config'};

    my $reject_reason;
    my $defer_reason;
    my $quarantine_reason;
    if ( $reject_reason = $handler->get_reject_mail() ) {
        $handler->clear_reject_mail();
        $returncode = SMFIS_REJECT;
    }
    elsif ( $defer_reason = $handler->get_defer_mail() ) {
        $handler->clear_defer_mail();
        $returncode = SMFIS_TEMPFAIL;
    }
    elsif ( $quarantine_reason = $handler->get_quarantine_mail() ) {
        if ( $config->{'milter_quarantine'} ) {
            $handler->clear_quarantine_mail();
            $returncode = SMFIR_QUARANTINE;
        }
        else {
            undef $quarantine_reason;
        }
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
            $handler->metric_count( 'mail_processed_total', { 'result' => 'accepted' } );
        }

        if ( $config->{'dryrun'} ) {
            if ( $returncode ne SMFIR_CONTINUE ) {
                $self->loginfo ( "dryrun returncode changed from $returncode to continue" );
                $returncode = SMFIR_CONTINUE;
            }
        }

        if ( $command ne SMFIC_ABORT ) {
            if ( $reject_reason ) {
                my ( $rcode, $xcode, $message ) = split( ' ', $reject_reason, 3 );
                if ($rcode !~ /^[5]\d\d$/ || $xcode !~ /^[5]\.\d\.\d$/ || substr($rcode, 0, 1) ne substr($xcode, 0, 1)) {
                    $handler->metric_count( 'mail_processed_total', { 'result' => 'deferred_error' } );
                    $self->loginfo ( "Invalid reject message $reject_reason - setting to TempFail" );
                    $self->write_packet(SMFIR_TEMPFAIL );
                }
                else {
                    $handler->metric_count( 'mail_processed_total', { 'result' => 'rejected' } );
                    $self->loginfo ( "SMTPReject: $reject_reason" );
                    $self->write_packet( SMFIR_REPLYCODE,
                        $reject_reason
                        . "\0"
                    );
                }
            }
            elsif ( $defer_reason ) {
                my ( $rcode, $xcode, $message ) = split( ' ', $defer_reason, 3 );
                if ($rcode !~ /^[4]\d\d$/ || $xcode !~ /^[4]\.\d\.\d$/ || substr($rcode, 0, 1) ne substr($xcode, 0, 1)) {
                    $handler->metric_count( 'mail_processed_total', { 'result' => 'deferred_error' } );
                    $self->loginfo ( "Invalid defer message $defer_reason - setting to TempFail" );
                    $self->write_packet(SMFIR_TEMPFAIL );
                }
                else {
                    $handler->metric_count( 'mail_processed_total', { 'result' => 'deferred' } );
                    $self->loginfo ( "SMTPDefer: $reject_reason" );
                    $self->write_packet( SMFIR_REPLYCODE,
                        $defer_reason
                        . "\0"
                    );
                }
            }
            elsif ( $quarantine_reason ) {
                $handler->metric_count( 'mail_processed_total', { 'result' => 'quarantined' } );
                $self->loginfo ( "SMTPQuarantine: $quarantine_reason" );
                $self->write_packet( SMFIR_QUARANTINE,
                    $quarantine_reason
                    . "\0"
                );
            }
            else {
                $self->write_packet($returncode);
            }
        }
    }

    return;
}

sub milter_process_connect {
    my ( $self, $buffer ) = @_;

    unless ($buffer =~ s/^([^\0]*)\0(.)//) {
        $self->fatal('SMFIC_CONNECT: invalid connect info');
    }
    my $ip;
    my $host = $1;

    my ($port, $addr) = unpack('nZ*', $buffer);

    if ( substr( $addr, 0, 5 ) eq 'IPv6:' ) {
        $addr = substr( $addr, 5 );
    }

    if ( ! defined ( $addr ) ) {
        $self->logerror('Unknown IP address format UNDEF');
        $ip = undef;
        # Could potentially fail here, connection is likely bad anyway.
    }
    elsif ( length ( $addr ) == 0 ) {
            $self->logerror('Unknown IP address format NULL');
            $ip = undef;
            # Could potentially fail here, connection is likely bad anyway.
    }
    else {
        eval {
            $ip = Net::IP->new( $addr );
        };
        if ( my $error = $@ ) {
            $self->logerror('Unknown IP address format - ' . $addr . ' - ' . $error );
            $ip = undef;
            # Could potentially fail here, connection is likely bad anyway.
        }
    }

    return ( $host, $ip );
}

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

sub milter_split_buffer {
    my ( $self, $buffer ) = @_;
    $buffer =~ s/\0$//; # remove trailing NUL
    return [ split(/\0/, $buffer) ];
};

##

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

1;

__END__

=head1 DESCRIPTION

A Perl implementation of email authentication standards rolled up into a single easy to use milter.

=head1 SYNOPSIS

Subclass of Net::Server::PreFork for bringing up the main server process for authentication_milter.

Please see Net::Server docs for more detail of the server code.

=head1 METHODS

=over

=item register_metrics

Return details of the metrics this module exports.

=item I<protocol_process_command( $command, $buffer )>

Process the command from the milter protocol stream.

=item I<milter_process_connect( $buffer )>

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

=item I<milter_process_command( $command, $data )>

Process the milter command $command with the data from
$data.

=item I<protocol_process_request()>

Receive a new command from the protocol stream and process it.

=back

