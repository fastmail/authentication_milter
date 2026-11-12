#!/usr/bin/env perl

# The effective config may contain secrets, so it is only served over http
# when metric_config_http is enabled, and never when metric_basic_http is set.

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

# Send a request to child_handler and return the response
sub request {
    my ( $uri ) = @_;
    my $metric = bless { 'enabled' => 1 }, 'Mail::Milter::Authentication::Metric';
    socketpair( my $client, my $server_socket, AF_UNIX, SOCK_STREAM, PF_UNSPEC ) || die "socketpair: $!";
    $_->autoflush(1) for $client, $server_socket;
    print $client "GET $uri HTTP/1.0\n\n";
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

sub config_with {
    my ( %options ) = @_;
    my $config = {
        'connection'  => 'inet:12345@localhost',
        'connections' => { 'second' => { 'connection' => 'inet:12346@localhost' } },
        'handlers'    => { 'Example' => { 'secret_key' => 'do-not-show' } },
        %options,
    };
    set_config( $config );
    return $config;
}

my @config_uris = ( '/config', '/config/json', '/config/toml' );

subtest 'config is not served by default' => sub {
    config_with();
    for my $uri ( @config_uris ) {
        my $response = request( $uri );
        like( $response, qr{^HTTP/1.0 403 }, "$uri denied" );
        unlike( $response, qr{do-not-show}, "$uri does not contain config" );
    }
    unlike( request( '/' ), qr{/config/json}, 'Index does not link to config' );
};

subtest 'config is served when metric_config_http is set' => sub {
    config_with( 'metric_config_http' => 1 );
    for my $uri ( @config_uris ) {
        my $response = request( $uri );
        like( $response, qr{^HTTP/1.0 200 }, "$uri served" );
        like( $response, qr{do-not-show}, "$uri contains config" );
    }
    like( request( '/' ), qr{/config/json}, 'Index links to config' );
};

subtest 'metric_basic_http overrides metric_config_http' => sub {
    config_with( 'metric_config_http' => 1, 'metric_basic_http' => 1 );
    for my $uri ( @config_uris ) {
        my $response = request( $uri );
        like( $response, qr{^HTTP/1.0 403 }, "$uri denied" );
        unlike( $response, qr{do-not-show}, "$uri does not contain config" );
    }
    unlike( request( '/' ), qr{/config/json}, 'Index does not link to config' );
};

subtest 'index does not modify the shared config' => sub {
    my $config = config_with();
    my $response = request( '/' );
    like( $response, qr{<li>default: inet:12345\@localhost</li>}, 'Default connection listed' );
    like( $response, qr{<li>second: inet:12346\@localhost</li>}, 'Other connection listed' );
    is_deeply( [ sort keys %{ $config->{'connections'} } ], [ 'second' ], 'Config connections unchanged' );
};

done_testing();
