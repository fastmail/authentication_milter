#!/usr/bin/env perl

use strict;
use warnings;
use lib 't';

use Data::Dumper;

use TestAlignedFromHandler;
use Test::Exception;
use Test::More;
use JSON::XS;

my $basedir = q{};

open( STDERR, '>>', $basedir . 't/tmp/misc.err' ) || die "Cannot open errlog [$!]";
#open( STDOUT, '>>', $basedir . 't/tmp/misc.err' ) || die "Cannot open errlog [$!]";

# Tester instance with access to a loaded DMARC Handler

my $tester_dmarc = Mail::Milter::Authentication::Tester::HandlerTester->new({
    'prefix'   => $basedir . 't/config/handler/etc',
    'zonefile' => $basedir . 't/zonefile',
    'handler_config' => {
        'AlignedFrom' => {},
        'SPF' => {
            'hide_none' => 0,
        },
        'DMARC' => {
            'hide_none' => 0,
            'detect_list_id' => 1,
        },
        'DKIM' => {
            'hide_none' => 0,
            'show_default_adsp' => 0,
            'check_adsp' => 1,
            'adsp_hide_none' => 0,
        },
    },
});

subtest 'config' => sub {
    my $config = $tester_dmarc->{ 'authmilter' }->{ 'handler' }->{ 'AlignedFrom' }->default_config();
    is_deeply( $config, {}, 'Returns correct config' );
};

subtest 'metrics' => sub {
    my $grafana_rows = $tester_dmarc->{ 'authmilter' }->{ 'handler' }->{ 'AlignedFrom' }->grafana_rows();
    is( scalar @$grafana_rows, 1, '1 Grafana row returned' );
    lives_ok( sub{ JSON::XS->new()->decode( $grafana_rows->[0] ); }, 'Metrics returns valid JSON' );
};

TestAlignedFromHandler::test_dmarc_or_not( $tester_dmarc );
TestAlignedFromHandler::test_dmarc( $tester_dmarc );

$tester_dmarc->close();

done_testing();

