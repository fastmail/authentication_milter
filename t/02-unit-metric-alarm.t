#!/usr/bin/env perl

# child_handler sets an alarm while handling a metrics http request. It must
# be cleared on every exit path, otherwise it fires later in the child, which
# has no SIGALRM handler, and the child exits.

use strict;
use warnings;
use lib 't';

use Socket;
use IO::Handle;
use Test::More;

use Mail::Milter::Authentication::Config qw{ set_config };
use Mail::Milter::Authentication::Metric;

package TestCallbacks {
    sub new { return bless {}, shift }
    sub get_callbacks { return [] }
}

set_config( { 'metric_timeout' => 30 } );

# Send a request to child_handler and return the response
sub request {
    my ( $request ) = @_;
    my $metric = bless { 'enabled' => 1 }, 'Mail::Milter::Authentication::Metric';
    socketpair( my $client, my $server_socket, AF_UNIX, SOCK_STREAM, PF_UNSPEC ) || die "socketpair: $!";
    $_->autoflush(1) for $client, $server_socket;
    print $client $request;
    shutdown( $client, 1 );
    my $server = {
        'server'  => { 'client' => $server_socket },
        'handler' => { '_Handler' => TestCallbacks->new() },
    };
    $metric->child_handler( $server );
    close $server_socket;
    my $response = do { local $/; <$client> };
    close $client;
    return $response;
}

my @cases = (
    [ 'malformed request', "THIS IS NOT HTTP\r\n\r\n", qr{^HTTP/1.0 500 } ],
    [ 'empty request',     q{},                        qr{^HTTP/1.0 500 } ],
    [ 'non GET request',   "POST / HTTP/1.0\r\n\r\n",  qr{^HTTP/1.0 500 } ],
    [ 'not found',         "GET /missing HTTP/1.0\r\n\r\n", qr{^HTTP/1.0 404 } ],
    [ 'index',             "GET / HTTP/1.0\r\n\r\n",   qr{^HTTP/1.0 200 } ],
);

for my $case ( @cases ) {
    my ( $name, $request, $expect ) = @$case;
    subtest $name => sub {
        alarm( 0 );
        like( request( $request ), $expect, 'Expected response' );
        is( alarm( 0 ), 0, 'No alarm left pending' );
    };
}

done_testing();
