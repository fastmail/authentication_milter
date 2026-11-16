#!/usr/bin/env perl

# In SMTP mode a message is only complete once the CRLF.CRLF end of data
# marker is received. If the connection closes before then the message must
# not be passed to the end of message callbacks or forwarded.
#
# Only an exact CRLF.CRLF ends DATA. A bare LF form could be read as message
# content by the MTA in front of us, letting the rest be read as commands.

use strict;
use warnings;
use lib 't';
use Test::More;

use Socket;
use IO::Handle;
use Mail::Milter::Authentication::Protocol::SMTP;

package TestHandler {
    use Mail::Milter::Authentication::Constants qw{ :all };
    sub new { return bless { 'calls' => [], 'body' => q{} }, shift }
    sub top_header_callback { my ( $self, $key ) = @_; push $self->{'calls'}->@*, "header:$key"; return SMFIS_CONTINUE }
    sub top_eoh_callback { push $_[0]->{'calls'}->@*, 'eoh'; return SMFIS_CONTINUE }
    sub top_body_callback { $_[0]->{'body'} .= $_[1]; push $_[0]->{'calls'}->@*, 'body'; return SMFIS_CONTINUE }
    sub top_eom_callback { push $_[0]->{'calls'}->@*, 'eom'; return SMFIS_CONTINUE }
    sub metric_count {}
    sub dbgout {}
    sub get_quarantine_mail { return }
    sub get_reject_mail { return }
    sub get_defer_mail { return }
    sub top_close_callback { push $_[0]->{'calls'}->@*, 'close' }
}

package TestSMTP {
    our @ISA = ( 'Mail::Milter::Authentication::Protocol::SMTP' );
    sub smtp_status {}
    sub logerror { push $_[0]->{'errors'}->@*, $_[1] }
    sub loginfo {}
    sub extra_debugging {}
    sub get_smtp_config { return {} }
    sub smtp_queue_id { return 'TESTID' }
    sub smtp_forward_to_destination { $_[0]->{'forwarded'} = 1; $_[0]->{'smtp'}->{'string'} = '250 OK'; return 1 }
}

# Run a DATA command with the given input, closing the connection after it
sub run_data {
    my ( $input ) = @_;
    socketpair( my $client, my $server, AF_UNIX, SOCK_STREAM, PF_UNSPEC ) || die "socketpair: $!";
    $_->autoflush(1) for $client, $server;
    print $client $input;
    shutdown( $client, 1 );
    my $handler = TestHandler->new();
    my $protocol = bless {
        'socket'  => $server,
        'handler' => { '_Handler' => $handler },
        'errors'  => [],
        'smtp'    => {
            'has_mail_from'   => 1,
            'lmtp_rcpt'       => [ 'test@example.com' ],
            'headers'         => [],
            'smtp_timeout_in' => 10,
        },
    }, 'TestSMTP';
    $protocol->smtp_command_data( 'DATA' );
    close $server;
    my $response = do { local $/; <$client> };
    close $client;
    return {
        'forwarded' => $protocol->{'forwarded'} ? 1 : 0,
        'calls'     => $handler->{'calls'},
        'body'      => $handler->{'body'},
        'response'  => $response,
        'errors'    => $protocol->{'errors'},
    };
}

my $headers = "From: test\@example.com\r\nSubject: Test\r\n";

subtest 'complete message is forwarded' => sub {
    my $result = run_data( "${headers}\r\nBody line\r\n.\r\n" );
    is( $result->{'forwarded'}, 1, 'Forwarded' );
    is_deeply( $result->{'calls'}, [ 'header:From', 'header:Subject', 'eoh', 'body', 'eom', 'close' ], 'All callbacks called' );
    is( $result->{'body'}, "Body line\r\n", 'Body received' );
    like( $result->{'response'}, qr{^354 .*\r\n250 2\.0\.0 Queued as TESTID\r\n$}s, 'Queued' );
};

subtest 'complete message with no body is forwarded' => sub {
    my $result = run_data( "${headers}.\r\n" );
    is( $result->{'forwarded'}, 1, 'Forwarded' );
    is_deeply( $result->{'calls'}, [ 'header:From', 'header:Subject', 'eoh', 'eom', 'close' ], 'Callbacks called' );
};

subtest 'connection closed during headers' => sub {
    my $result = run_data( $headers );
    is( $result->{'forwarded'}, 0, 'Not forwarded' );
    ok( ! grep( { $_ eq 'eom' } $result->{'calls'}->@* ), 'EOM not called' );
    like( join( "\n", $result->{'errors'}->@* ), qr{Connection closed during DATA}, 'Error logged' );
};

subtest 'connection closed during body' => sub {
    my $result = run_data( "${headers}\r\nBody line\r\nTruncated" );
    is( $result->{'forwarded'}, 0, 'Not forwarded' );
    ok( ! grep( { $_ eq 'eom' } $result->{'calls'}->@* ), 'EOM not called' );
    unlike( $result->{'response'}, qr{^250 }m, 'Not queued' );
};

subtest 'connection closed after a complete body line' => sub {
    my $result = run_data( "${headers}\r\nBody line\r\n" );
    is( $result->{'forwarded'}, 0, 'Not forwarded' );
    ok( ! grep( { $_ eq 'eom' } $result->{'calls'}->@* ), 'EOM not called' );
};

subtest 'bare LF dot does not end DATA in the body' => sub {
    my $result = run_data( "${headers}\r\nBody line\n.\nMAIL FROM:<x\@example.com>\r\n.\r\n" );
    is( $result->{'forwarded'}, 1, 'Forwarded' );
    is( $result->{'body'}, "Body line\n\nMAIL FROM:<x\@example.com>\r\n", 'Bare LF dot treated as content' );
};

subtest 'bare LF dot does not end DATA in the headers' => sub {
    my $result = run_data( "From: test\@example.com\r\n.\nBody line\r\n" );
    is( $result->{'forwarded'}, 0, 'Not forwarded, no end of data marker' );
};

subtest 'dot stuffed line is not the end of data' => sub {
    my $result = run_data( "${headers}\r\n..\r\n.\r\n" );
    is( $result->{'forwarded'}, 1, 'Forwarded' );
    is( $result->{'body'}, ".\r\n", 'Dot unstuffed' );
};

done_testing();
