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
    'prefix'   => $basedir . 't/config/handler/localip',
    'zonefile' => $basedir . 't/zonefile',
});

test( $tester, { 'name' => 'IANA local', 'result' => 'pass', 'ip' => '0.1.2.3' });
test( $tester, { 'name' => 'localhost', 'result' => 'pass', 'ip' => '127.0.0.1' });
test( $tester, { 'name' => 'loopback', 'result' => 'pass', 'ip' => '127.1.2.3' });
test( $tester, { 'name' => 'IANA private', 'result' => 'pass', 'ip' => '10.2.3.4' });
test( $tester, { 'name' => 'IANA shared', 'result' => 'pass', 'ip' => '100.64.0.0' });
test( $tester, { 'name' => 'Link local', 'result' => 'pass', 'ip' => '169.254.2.3' });

test( $tester, { 'name' => 'Private use 172', 'result' => 'pass', 'ip' => '172.16.3.4' });
test( $tester, { 'name' => 'Private use 192', 'result' => 'pass', 'ip' => '192.168.0.1' });

test( $tester, { 'name' => '8.8.8.8', 'result' => '', 'ip' => '8.8.8.8' });
test( $tester, { 'name' => '1.2.3.4', 'result' => '', 'ip' => '1.2.3.4' });

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

    my $header = $tester->get_authresults_header()->search({ 'key' => 'x-local-ip' });
    #print Dumper $header;
    my $result = eval{ $header->children()->[0]->value(); } // q{};

    is( $result, $args->{ 'result' }, $args->{ 'name' } . ' result' );

    return;
}

