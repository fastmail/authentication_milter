#!/usr/bin/env perl

# In SMTP mode the connect, helo, and envfrom callbacks are run from MAIL FROM,
# so RCPT TO and DATA must not be accepted without a successful MAIL FROM,
# otherwise a message is processed and forwarded without them and with an
# empty envelope sender.
#
# A completed DATA ends the transaction, so a following MAIL FROM is accepted
# without RSET, and a following RCPT TO is not.

use strict;
use warnings;
use lib 't';
use Test::More;

use Socket;
use IO::Handle;
use Net::IP;

use Mail::Milter::Authentication::Protocol::SMTP;

package TestHandler {
    use Mail::Milter::Authentication::Constants qw{ :all };
    sub new { return bless { 'calls' => [] }, shift }
    sub remap_connect_callback { $_[0]->{'ip_object'} = $_[2] }
    sub remap_helo_callback { $_[0]->{'helo_name'} = $_[1] }
    sub top_connect_callback { push $_[0]->{'calls'}->@*, 'connect'; return SMFIS_CONTINUE }
    sub top_helo_callback { push $_[0]->{'calls'}->@*, 'helo'; return SMFIS_CONTINUE }
    sub top_envfrom_callback { push $_[0]->{'calls'}->@*, 'envfrom'; return SMFIS_CONTINUE }
    sub top_envrcpt_callback { push $_[0]->{'calls'}->@*, 'envrcpt'; return SMFIS_CONTINUE }
    sub top_header_callback { return SMFIS_CONTINUE }
    sub top_eoh_callback { return SMFIS_CONTINUE }
    sub top_body_callback { return SMFIS_CONTINUE }
    sub top_eom_callback { push $_[0]->{'calls'}->@*, 'eom'; return SMFIS_CONTINUE }
    sub top_close_callback { push $_[0]->{'calls'}->@*, 'close' }
    sub metric_count {}
    sub dbgout {}
    sub get_quarantine_mail { return }
    sub get_reject_mail { return }
    sub get_defer_mail { return }
    sub set_symbol {}
}

package TestSMTP {
    our @ISA = ( 'Mail::Milter::Authentication::Protocol::SMTP' );
    sub smtp_status {}
    sub logerror {}
    sub logdebug {}
    sub loginfo {}
    sub extra_debugging {}
    sub get_smtp_config { return {} }
    sub smtp_queue_id { return 'TESTID' }
    sub smtp_forward_to_destination {
        my ( $self ) = @_;
        push $self->{'forwarded'}->@*, $self->{'smtp'}->{'mail_from'};
        $self->{'smtp'}->{'string'} = '250 OK';
        return 1;
    }
}

sub new_session {
    socketpair( my $client, my $server, AF_UNIX, SOCK_STREAM, PF_UNSPEC ) || die "socketpair: $!";
    $_->autoflush(1) for $client, $server;
    my $protocol = bless {
        'socket'    => $server,
        'client'    => $client,
        'handler'   => { '_Handler' => TestHandler->new() },
        'forwarded' => [],
        'smtp'      => {
            'connect_ip'      => '192.0.2.1',
            'connect_host'    => 'client.example.com',
            'helo_host'       => 'client.example.com',
            'mail_from'       => q{},
            'has_mail_from'   => 0,
            'has_data'        => 0,
            'lmtp_rcpt'       => [],
            'headers'         => [],
            'smtp_timeout_in' => 10,
        },
    }, 'TestSMTP';
    return $protocol;
}

# Run a command and return the final response line
sub command {
    my ( $protocol, $command, $data ) = @_;
    my $client = $protocol->{'client'};
    print $client $data if defined $data;
    if ( $command =~ /^MAIL/ ) { $protocol->smtp_command_mailfrom( $command ) }
    elsif ( $command =~ /^RCPT/ ) { $protocol->smtp_command_rcptto( $command ) }
    elsif ( $command =~ /^DATA/ ) { $protocol->smtp_command_data( $command ) }
    elsif ( $command =~ /^RSET/ ) { $protocol->smtp_command_rset( $command ) }
    my $response = <$client>;
    $response = <$client> if $response =~ /^354 /;
    $response =~ s/\r\n$//;
    return $response;
}

my $message = "From: test\@example.com\r\nSubject: Test\r\n\r\nBody\r\n.\r\n";

subtest 'RCPT before MAIL is refused' => sub {
    my $protocol = new_session();
    like( command( $protocol, 'RCPT TO:<test@example.com>' ), qr{^503 5\.5\.1 }, 'RCPT refused' );
    like( command( $protocol, 'DATA', $message ), qr{^503 5\.5\.1 }, 'DATA refused' );
    is_deeply( $protocol->{'forwarded'}, [], 'Nothing forwarded' );
    is_deeply( $protocol->{'handler'}->{'_Handler'}->{'calls'}, [], 'No callbacks run' );
};

subtest 'complete transaction' => sub {
    my $protocol = new_session();
    like( command( $protocol, 'MAIL FROM:<sender@example.com>' ), qr{^250 }, 'MAIL accepted' );
    like( command( $protocol, 'RCPT TO:<test@example.com>' ), qr{^250 }, 'RCPT accepted' );
    like( command( $protocol, 'DATA', $message ), qr{^250 2\.0\.0 Queued as TESTID$}, 'Message queued' );
    is_deeply( $protocol->{'forwarded'}, [ '<sender@example.com>' ], 'Forwarded with the envelope sender' );
    is_deeply( $protocol->{'handler'}->{'_Handler'}->{'calls'}, [ qw{ connect helo envfrom envrcpt eom close } ], 'All callbacks run' );
};

subtest 'RCPT after a completed DATA is refused' => sub {
    my $protocol = new_session();
    command( $protocol, 'MAIL FROM:<sender@example.com>' );
    command( $protocol, 'RCPT TO:<test@example.com>' );
    command( $protocol, 'DATA', $message );
    like( command( $protocol, 'RCPT TO:<test@example.com>' ), qr{^503 5\.5\.1 }, 'RCPT refused' );
    like( command( $protocol, 'DATA', $message ), qr{^503 5\.5\.1 }, 'DATA refused' );
    is_deeply( $protocol->{'forwarded'}, [ '<sender@example.com>' ], 'Only the first message forwarded' );
};

subtest 'MAIL after a completed DATA is accepted without RSET' => sub {
    my $protocol = new_session();
    command( $protocol, 'MAIL FROM:<sender@example.com>' );
    command( $protocol, 'RCPT TO:<test@example.com>' );
    command( $protocol, 'DATA', $message );
    like( command( $protocol, 'MAIL FROM:<second@example.com>' ), qr{^250 }, 'Second MAIL accepted' );
    like( command( $protocol, 'RCPT TO:<test@example.com>' ), qr{^250 }, 'Second RCPT accepted' );
    like( command( $protocol, 'DATA', $message ), qr{^250 2\.0\.0 Queued as TESTID$}, 'Second message queued' );
    is_deeply( $protocol->{'forwarded'}, [ '<sender@example.com>', '<second@example.com>' ], 'Both forwarded with their envelope sender' );
};

subtest 'RCPT after RSET is refused' => sub {
    my $protocol = new_session();
    command( $protocol, 'MAIL FROM:<sender@example.com>' );
    command( $protocol, 'RSET' );
    like( command( $protocol, 'RCPT TO:<test@example.com>' ), qr{^503 5\.5\.1 }, 'RCPT refused' );
};

done_testing();
