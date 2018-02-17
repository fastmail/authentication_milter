#!/usr/bin/env perl

use strict;
use warnings;
use lib 't';

use Data::Dumper;

use Mail::Milter::Authentication::Tester::HandlerTester;
use Mail::Milter::Authentication::Constants qw{ :all };
use Test::More;

my $basedir = q{};

open( STDERR, '>>', $basedir . 't/tmp/misc.err' ) || die "Cannot open errlog [$!]";
#open( STDOUT, '>>', $basedir . 't/tmp/misc.err' ) || die "Cannot open errlog [$!]";

my $tester = Mail::Milter::Authentication::Tester::HandlerTester->new({
    'prefix'   => $basedir . 't/config/handler/etc',
    'zonedata' => '',
    'handler_config' => {
        'TrustedIP' => {
            'trusted_ip_list' => [
                '100.200.100.2',
                '200.200.100.0/24',
                '2001:44c2:3881:aa00::/56',
                '2001:44b8:3021:123:dead:beef:abcd:1234',
            ],
        },
    },
});

subtest 'Trusted IP Ranges' => sub{
    test( $tester, { 'name' => 'Listed IP', 'result' => 'pass', 'ip' => '100.200.100.2' });
    test( $tester, { 'name' => 'Listed Range', 'result' => 'pass', 'ip' => '200.200.100.5' });
    test( $tester, { 'name' => 'Listed IPv6', 'result' => 'pass', 'ip' => '2001:44b8:3021:123:dead:beef:abcd:1234' });
    test( $tester, { 'name' => 'Listed IPv6 Range', 'result' => 'pass', 'ip' => '2001:44c2:3881:aa00:0000:dead:beef:1234' });
};

subtest 'Untrusted IP Ranges' => sub {
    test( $tester, { 'name' => 'Untrusted IPv4', 'result' => '', 'ip' => '8.8.8.8' });
    test( $tester, { 'name' => 'Untrusted IPv6', 'result' => '', 'ip' => '2002:54c2:3581:aa00:0000:dead:beef:1234' });
};

#test( $tester, { 'name' => '', 'result' => 'pass', 'ip' => '' });

$tester->close();

done_testing();

sub test {
    my ( $tester, $args ) = @_;

    $tester->run({
        'connect_ip' => $args->{ 'ip' },
        'connect_name' => 'mx.example.com',
        'helo' => 'mx.example.com',
        'mailfrom' => 'test@example.net',
        'rcptto' => [ 'test@example.net' ],
        'body' => 'From: test@example.net
To: test@example.net
Subject: This is a test

Testing',
});

    my $header = $tester->get_authresults_header()->search({ 'key' => 'x-trusted-ip' });
    #print Dumper $header;
    my $result = eval{ $header->children()->[0]->value(); } // q{};

    is( $result, $args->{ 'result' }, $args->{ 'name' } . ' result' );

    return;
}

