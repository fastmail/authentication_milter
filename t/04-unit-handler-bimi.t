#!/usr/bin/env perl

use strict;
use warnings;
use lib 't';

use Data::Dumper;

use Mail::Milter::Authentication::Tester::HandlerTester;
use Mail::Milter::Authentication::Constants qw{ :all };
use Test::Exception;
use Test::More;

my $basedir = q{};

mkdir 't/tmp';
open( STDERR, '>>', $basedir . 't/tmp/misc.err' ) || die "Cannot open errlog [$!]";
#open( STDOUT, '>>', $basedir . 't/tmp/misc.err' ) || die "Cannot open errlog [$!]";

my $tester = Mail::Milter::Authentication::Tester::HandlerTester->new({
    'protocol' => 'smtp',
    'prefix'   => $basedir . 't/config/handler/etc',
    'zonefile' => $basedir . 't/zonefile',
    'handler_config' => {
        'DMARC' => {},
        'DKIM' => {},
        'SPF' => {},
        'BIMI' => {},
    },
});
$tester->snapshot( 'new' );

subtest 'config' => sub {
    my $config = $tester->{ 'authmilter' }->{ 'handler' }->{ 'BIMI' }->default_config();
    is_deeply( $config, {}, 'Returns correct config' );
};

#subtest 'metrics' => sub {
#    is( $tester->{ 'authmilter' }->{ 'handler' }->{ 'AbusixDataFeed' }->can( 'grafana_rows' ), undef, 'Has no grafana rows' );
#};

subtest 'default' => sub {

    $tester->switch( 'new' );
    $tester->run({
        'connect_ip' => '1.2.3.4',
        'connect_name' => 'mx.example.com',
        'helo' => 'mx.example.com',
        'mailfrom' => 'test@example.com',
        'rcptto' => [ 'test@example.net' ],
        'body' => 'From: test@example.com
To: test@example.net
Subject: This is a test
BIMI-Location: BIMI1

Testing',
    });

    is( $tester->{authmilter}->{handler}->{BIMI}->{bimi_object}->result->get_authentication_results, 'bimi=pass header.d=example.com selector=default', 'Default BIMI pass' );

    $tester->switch( 'new' );
    $tester->run({
        'connect_ip' => '1.2.3.5',
        'connect_name' => 'mx.example.com',
        'helo' => 'mx.example.com',
        'mailfrom' => 'test@example.com',
        'rcptto' => [ 'test@example.net' ],
        'body' => 'From: test@example.com
To: test@example.net
Subject: This is a test
BIMI-Location: BIMI1

Testing',
    });

    is( $tester->{authmilter}->{handler}->{BIMI}->{bimi_object}->result->get_authentication_results, 'bimi=skipped (DMARC fail)', 'Default BIMI no auth' );

};

subtest 'fallbackt' => sub {

    $tester->switch( 'new' );
    $tester->run({
        'connect_ip' => '1.2.3.4',
        'connect_name' => 'mx.example.com',
        'helo' => 'mx.example.com',
        'mailfrom' => 'test@example.com',
        'rcptto' => [ 'test@example.net' ],
        'body' => 'From: test@one.example.com
To: test@example.net
Subject: This is a test
BIMI-Location: BIMI1

Testing',
    });

    is( $tester->{authmilter}->{handler}->{BIMI}->{bimi_object}->result->get_authentication_results, 'bimi=pass header.d=example.com selector=default', 'Fallback BIMI pass' );

};

done_testing;
