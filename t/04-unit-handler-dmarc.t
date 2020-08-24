#!/usr/bin/env perl

use strict;
use warnings;
use lib 't';

use Mail::Milter::Authentication::Tester::HandlerTester;
use Mail::Milter::Authentication::Constants qw{ :all };
use Test::Exception;
use Test::More;
use JSON::XS;

my $basedir = q{};

open( STDERR, '>>', $basedir . 't/tmp/misc.err' ) || die "Cannot open errlog [$!]";
#open( STDOUT, '>>', $basedir . 't/tmp/misc.err' ) || die "Cannot open errlog [$!]";

my $test_params = {
    'none' => {
        'connect_ip' => '1.2.3.4',
        'connect_name' => 'mx.example.net',
        'helo' => 'mx.example.net',
        'mailfrom' => 'test@example.net',
        'rcptto' => [ 'test@example.net' ],
        'body' => 'From: test@example.net
To: test@example.net
Subject: Test

This is a test',
    },
    'spf_fail' => {
        'connect_ip' => '1.2.3.4',
        'connect_name' => 'mx.goestheweasel.com',
        'helo' => 'mx.goestheweasel.com',
        'mailfrom' => 'test@goestheweasel.com',
        'rcptto' => [ 'test@goestheweasel.com' ],
        'body' => 'From: test@goestheweasel.com
To: test@goestheweasel.com
Subject: Test

This is a test',
    },
    'spf_pass' => {
        'connect_ip' => '106.187.51.197',
        'connect_name' => 'mx.goestheweasel.com',
        'helo' => 'mx.goestheweasel.com',
        'mailfrom' => 'test@goestheweasel.com',
        'rcptto' => [ 'test@goestheweasel.com' ],
        'body' => 'From: test@goestheweasel.com
To: test@goestheweasel.com
Subject: Test

This is a test',
    },
};

my $testers = {
    'defaults' => Mail::Milter::Authentication::Tester::HandlerTester->new({
        'prefix'   => $basedir . 't/config/handler/etc',
        'zonefile' => $basedir . 't/zonefile',
        'handler_config' => {
            'DKIM' => {},
            'SPF' => {},
            'DMARC' => {},
        },
    }),
    'hide_none' => Mail::Milter::Authentication::Tester::HandlerTester->new({
        'prefix'   => $basedir . 't/config/handler/etc',
        'zonefile' => $basedir . 't/zonefile',
        'handler_config' => {
            'DKIM' => {},
            'SPF' => {},
            'DMARC' => { 'hide_none' => 1 },
        },
    }),
};

subtest 'config' => sub {
    my $config = $testers->{ 'defaults' }->{ 'authmilter' }->{ 'handler' }->{ 'DMARC' }->default_config();
    is_deeply( $config,
        {
            'hide_none'      => 0,
            'use_arc'        => 1,
            'hard_reject'    => 0,
            'no_list_reject' => 1,
            'arc_before_list' => 0,
            'whitelisted'    => [],
            'detect_list_id' => 1,
            'report_skip_to' => [ 'my_report_from_address@example.com' ],
            'no_report'      => 0,
            'hide_report_to' => 0,
            'config_file'    => '/etc/mail-dmarc.ini',
            'no_reject_disposition' => 'quarantine',
            'no_list_reject_disposition' => 'none',
            'reject_on_multifrom' => 30,
            'quarantine_on_multifrom' => 20,
            'skip_on_multifrom' => 10,
        },               
        'Returns correct config' );
};

subtest 'metrics' => sub {
    my $grafana_rows = $testers->{ 'defaults' }->{ 'authmilter' }->{ 'handler' }->{ 'DMARC' }->grafana_rows();
    is( scalar @$grafana_rows, 1, '1 Grafana row returned' );
    lives_ok( sub{ JSON::XS->new()->decode( $grafana_rows->[0] ); }, 'Metrics returns valid JSON' );
};

subtest 'none shown' => sub {
    my $tester = $testers->{ 'defaults' };
    $tester->run( $test_params->{ 'none' } );
    is_dmarc_result( $tester, 'none' );
};

subtest 'none hidden' => sub {
    my $tester = $testers->{ 'hide_none' };
    $tester->run( $test_params->{ 'none' } );
    my $header = $tester->get_authresults_header()->search({ 'key' => 'dmarc' });
    is( scalar @{ $header->children() }, 0, 'No DMARC entry' );
};

while (my ($tester_name, $tester) = each %$testers) {
    subtest "SPF fail $tester_name" => sub {
        $tester->run( $test_params->{ 'spf_fail' } );
        is_dmarc_result( $tester, 'fail' );
    };
}

while (my ($tester_name, $tester) = each %$testers) {
    subtest "SPF pass $tester_name" => sub {
        $tester->run( $test_params->{ 'spf_pass' } );
        is_dmarc_result( $tester, 'pass' );
    };
}

done_testing();

sub is_dmarc_result {
    my ( $tester, $expected ) = @_;
    my $header = $tester->get_authresults_header()->search({ 'key' => 'dmarc' });
    is( scalar @{ $header->children() }, 1, 'One DMARC entry' );
    my $result = eval{ $header->children()->[0]->value(); } // q{};
    is( $result, $expected, "DMARC result is $expected");
}
