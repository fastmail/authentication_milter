#!/usr/bin/env perl

use strict;
use warnings;
use lib 't';

use Data::Dumper;

use Mail::Milter::Authentication::Tester::HandlerTester;
use Mail::Milter::Authentication::Constants qw{ :all };
use Test::Exception;
use Test::More;
use JSON::XS;

my $basedir = q{};

open( STDERR, '>>', $basedir . 't/tmp/misc.err' ) || die "Cannot open errlog [$!]";
#open( STDOUT, '>>', $basedir . 't/tmp/misc.err' ) || die "Cannot open errlog [$!]";

my $tester = Mail::Milter::Authentication::Tester::HandlerTester->new({
    'prefix'   => $basedir . 't/config/handler/etc',
    'zonedata' => '',
    'handler_config' => {
        'LocalIP' => {
            'ignore_local_ip_list' => [
                '10.0.0.0/24',
                '10.1.0.5'
            ],
        },
    },
});

subtest 'config' => sub {
    my $config = $tester->{ 'authmilter' }->{ 'handler' }->{ 'LocalIP' }->default_config();
    is_deeply( $config, { 'ignore_local_ip_list' => [] }, 'Returns correct config' );
};

subtest 'metrics' => sub {
    my $grafana_rows = $tester->{ 'authmilter' }->{ 'handler' }->{ 'LocalIP' }->grafana_rows();
    is( scalar @$grafana_rows, 1, '1 Grafana row returned' );
    lives_ok( sub{ JSON::XS->new()->decode( $grafana_rows->[0] ); }, 'Metrics returns valid JSON' );
};

subtest 'Local IP Ranges' => sub{
    test( $tester, { 'name' => 'IANA local', 'result' => 'pass', 'ip' => '0.1.2.3' });
    test( $tester, { 'name' => 'localhost', 'result' => 'pass', 'ip' => '127.0.0.1' });
    test( $tester, { 'name' => 'loopback', 'result' => 'pass', 'ip' => '127.1.2.3' });
    test( $tester, { 'name' => 'IANA private', 'result' => 'pass', 'ip' => '10.2.3.4' });
    test( $tester, { 'name' => 'IANA shared', 'result' => 'pass', 'ip' => '100.64.0.0' });
    test( $tester, { 'name' => 'Link local', 'result' => 'pass', 'ip' => '169.254.2.3' });
};

subtest 'Private IP Ranges' => sub {
    test( $tester, { 'name' => 'Private use 172', 'result' => 'pass', 'ip' => '172.16.3.4' });
    test( $tester, { 'name' => 'Private use 192', 'result' => 'pass', 'ip' => '192.168.0.1' });
};

subtest 'Global IP Ranges' => sub {
    test( $tester, { 'name' => '8.8.8.8', 'result' => '', 'ip' => '8.8.8.8' });
    test( $tester, { 'name' => '1.2.3.4', 'result' => '', 'ip' => '1.2.3.4' });
};

subtest 'Private IPv6 Ranges' => sub {
    test( $tester, { 'name' => 'Private use', 'result' => 'pass', 'ip' => 'FD00:ABCD::1234' });
};

subtest 'Global IPv6 Ranges' => sub {
    test( $tester, { 'name' => 'Global', 'result' => '', 'ip' => '2400:8900::f03c:91ff:fe6e:84c7' });
};

subtest 'Ignore Local IP' => sub {
    test( $tester, { 'name' => '10.0.0.5', 'result' => '', 'ip' => '10.0.0.5' });
    test( $tester, { 'name' => '10.1.0.5', 'result' => '', 'ip' => '10.1.0.5' });
    test( $tester, { 'name' => '10.1.0.6', 'result' => 'pass', 'ip' => '10.1.0.6' });
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

    my $header = $tester->get_authresults_header()->search({ 'key' => 'x-local-ip' });
    #print Dumper $header;
    if ( $args->{ 'result' } eq q{} ) {
        is( scalar @{ $header->children() }, 0, 'No Entries' );
    }
    else {
        is( scalar @{ $header->children() }, 1, '1 Entry' );
    }
    my $result = eval{ $header->children()->[0]->value(); } // q{};

    is( $result, $args->{ 'result' }, $args->{ 'name' } . ' result' );

    return;
}

