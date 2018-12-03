#!/usr/bin/env perl

use strict;
use warnings;
use lib 't';

use Data::Dumper;

use Mail::Milter::Authentication::Tester::HandlerTester;
use Mail::Milter::Authentication::Constants qw{ :all };
use Test::Exception;
use Test::More;
use JSON;

my $basedir = q{};

open( STDERR, '>>', $basedir . 't/tmp/misc.err' ) || die "Cannot open errlog [$!]";
#open( STDOUT, '>>', $basedir . 't/tmp/misc.err' ) || die "Cannot open errlog [$!]";

my $tester = Mail::Milter::Authentication::Tester::HandlerTester->new({
    'protocol' => 'smtp',
    'prefix'   => $basedir . 't/config/handler/etc',
    'zonedata' => '4.3.2.1.in-addr.arpa. PTR reverse.example.com.',
    'handler_config' => {
        'AbusixDataFeed' => { 'feed_name' => 'test_feed', 'feed_dest' => '', 'feed_key' => 'secret_key', 'listening_port' => 25 },
    },
});

subtest 'config' => sub {
    my $config = $tester->{ 'authmilter' }->{ 'handler' }->{ 'AbusixDataFeed' }->default_config();
    is_deeply( $config, { 'feed_name' => 'name_of_feed', 'feed_dest' => 'server:port', 'feed_key' => 'this_is_a_secret', 'listening_port' => 25 }, 'Returns correct config' );
};

subtest 'metrics' => sub {
    is( $tester->{ 'authmilter' }->{ 'handler' }->{ 'AbusixDataFeed' }->can( 'grafana_rows' ), undef, 'Has no grafana rows' );
};

subtest 'feedset' => sub {

    $tester->run({
        'connect_ip' => '1.2.3.4',
        'connect_name' => 'mx.example.com',
        'helo' => 'mx.example.com',
        'mailfrom' => 'test@example.net',
        'rcptto' => [ 'test@example.net' ],
        'body' => 'From: test@example.net
To: test@example.net
Subject: This is a test

Testing',
    });

    my $feed = $tester->{ 'authmilter' }->{ 'handler' }->{ 'AbusixDataFeed' }->{ 'abusix_feed' };

    my $expected_feed = {
        'feed_key' => 'secret_key',
        'feed_name' => 'test_feed',
        'helo' => 'mx.example.com',
        'mail_from_domain' => 'example.net',
        'port' => 25,
        'ip_address' => '1.2.3.4',
        'reverse_dns' => 'reverse.example.com.',
        'used_tls' => undef,
        'used_esmtp' => undef,
        'used_auth' => 0
    };

    foreach my $key ( sort keys %$expected_feed ) {
        is( $feed->{$key}, $expected_feed->{$key}, "$key was correctly set" );
    }

};

done_testing();

