#!/usr/bin/env perl

use strict;
use warnings;
use lib 't';

use File::Slurp qw{ read_file };
use File::Temp qw{ tempdir };
use Mail::DMARC::PurePerl;
use Sereal qw{ encode_sereal decode_sereal };
use Test::More;

use Mail::Milter::Authentication::Tester::HandlerTester;

my $basedir = q{};

# save_aggregate stores via a new Mail::DMARC::Report which does not inherit
# config_file, without this it writes dmarc_reports.sqlite to the current directory
$ENV{'MAIL_DMARC_CONFIG_FILE'} = $basedir . 't/config/handler/etc/mail-dmarc.ini';

mkdir 't/tmp';
open( STDERR, '>>', $basedir . 't/tmp/misc.err' ) || die "Cannot open errlog [$!]";

my $tester = Mail::Milter::Authentication::Tester::HandlerTester->new({
    'prefix'   => $basedir . 't/config/handler/etc',
    'zonefile' => $basedir . 't/zonefile',
    'handler_config' => {
        'DKIM'  => {},
        'SPF'   => {},
        'DMARC' => { 'config_file' => $basedir . 't/config/handler/etc/mail-dmarc.ini' },
    },
});

my $spool = tempdir( CLEANUP => 1 );
$tester->handler()->config()->{'spool_dir'} = $spool;
# run() restores this snapshot, so retake it with the new spool_dir
$tester->snapshot( '_new' );

sub dmarc_handler { return $tester->{ 'authmilter' }->{ 'handler' }->{ 'DMARC' } }

subtest 'report is queued as plain data' => sub {
    $tester->run({
        'connect_ip'   => '106.187.51.197',
        'connect_name' => 'mx.goestheweasel.com',
        'helo'         => 'mx.goestheweasel.com',
        'mailfrom'     => 'test@goestheweasel.com',
        'rcptto'       => [ 'test@goestheweasel.com' ],
        'body'         => 'From: test@goestheweasel.com
To: test@goestheweasel.com
Subject: Test

This is a test',
    });
    $tester->close();

    my @files = glob "$spool/dequeue/dmarc_report.*.dequeue";
    is( scalar @files, 1, 'One report queued' );
    my $data = eval { decode_sereal( scalar read_file( $files[0] ), { refuse_objects => 1 } ) };
    is( $@, q{}, 'Queued report decodes with objects refused' );
    ok( ! exists $data->{'config'}, 'Mail::DMARC config is not queued' );
    is( $data->{'header_from'}, 'goestheweasel.com', 'header_from queued' );
    is( $data->{'published'}->{'rua'}, 'mailto:dmarc.reports@ops.twofiftyeight.ltd.uk', 'rua queued' );
    is_deeply( $data->{'spf'}, [ { 'domain' => 'goestheweasel.com', 'result' => 'pass', 'scope' => 'mfrom' } ], 'SPF results queued' );

    my $report = dmarc_handler()->_dmarc_report_from_queue( $data );
    isa_ok( $report, 'Mail::DMARC::PurePerl' );
    is( $report->source_ip(), '106.187.51.197', 'source_ip rebuilt' );
    is( $report->result()->published()->rua(), 'mailto:dmarc.reports@ops.twofiftyeight.ltd.uk', 'Published policy rebuilt' );
    is( $report->result()->disposition(), 'none', 'Result rebuilt' );
};

subtest 'queued report is dequeued and saved' => sub {
    $tester->handler()->top_dequeue_callback();
    is( scalar @{ [ glob "$spool/dequeue/dmarc_report.*" ] }, 0, 'Report was saved and removed from the queue' );
};

subtest 'all report fields survive the queue' => sub {
    my $dmarc = Mail::DMARC::PurePerl->new();
    $dmarc->source_ip( '192.0.2.1' );
    $dmarc->envelope_to( 'example.net' );
    $dmarc->envelope_from( 'example.com' );
    $dmarc->header_from( 'example.com' );
    $dmarc->is_subdomain( 0 );
    $dmarc->dkim( domain => 'example.com', selector => 'sel', result => 'pass', human_result => 'pass' );
    $dmarc->{'dkim'} = [ @{ $dmarc->{'dkim'} }, { domain => 'example.org', selector => 'arc', result => 'fail' } ];
    $dmarc->spf( domain => 'example.com', scope => 'mfrom', result => 'pass' );
    my $result = $dmarc->result();
    $result->result( 'fail' );
    $result->disposition( 'none' );
    $result->dkim( 'fail' );
    $result->spf( 'pass' );
    $result->spf_align( 'relaxed' );
    $result->reason( type => 'local_policy', comment => 'arc=pass' );
    my $policy = Mail::DMARC::Policy->new()->parse( 'v=DMARC1; p=reject; rua=mailto:dmarc@example.com' );
    $policy->{'domain'} = 'example.com';
    $result->published( $policy );

    my $queued = dmarc_handler()->_dmarc_report_to_queue( $dmarc );
    my $thawed = decode_sereal( encode_sereal( $queued, { croak_on_bless => 1 } ), { refuse_objects => 1 } );
    my $rebuilt = dmarc_handler()->_dmarc_report_from_queue( $thawed );
    is_deeply( dmarc_handler()->_dmarc_report_to_queue( $rebuilt ), $queued, 'Rebuilt report queues identically' );
    is_deeply( $rebuilt->result()->reason()->[0], { type => 'local_policy', comment => 'arc=pass' }, 'Reason rebuilt' );
};

done_testing();
