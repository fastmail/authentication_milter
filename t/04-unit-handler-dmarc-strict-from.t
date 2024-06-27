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
    'single' => {
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
    'multiple_address' => {
        'connect_ip' => '1.2.3.4',
        'connect_name' => 'mx.example.net',
        'helo' => 'mx.example.net',
        'mailfrom' => 'test@example.net',
        'rcptto' => [ 'test@example.net' ],
        'body' => 'From: test@example.net, test@example.org
To: test@example.net
Subject: Test

This is a test',
    },
    'multiple_headers' => {
        'connect_ip' => '1.2.3.4',
        'connect_name' => 'mx.example.net',
        'helo' => 'mx.example.net',
        'mailfrom' => 'test@example.net',
        'rcptto' => [ 'test@example.net' ],
        'body' => 'From: test@example.net
From: test@example.org
To: test@example.net
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
    'strict' => Mail::Milter::Authentication::Tester::HandlerTester->new({
        'prefix'   => $basedir . 't/config/handler/etc',
        'zonefile' => $basedir . 't/zonefile',
        'handler_config' => {
            'DKIM' => {},
            'SPF' => {},
            'DMARC' => { 'strict_multifrom' => 1 },
        },
    }),
    'reject' => Mail::Milter::Authentication::Tester::HandlerTester->new({
        'prefix'   => $basedir . 't/config/handler/etc',
        'zonefile' => $basedir . 't/zonefile',
        'handler_config' => {
            'DKIM' => {},
            'SPF' => {},
            'DMARC' => { 'hard_reject' => 1, 'strict_multifrom' => 1 },
        },
    }),
};

subtest 'defaults single' => sub {
    my $tester = $testers->{ 'defaults' };
    $tester->run( $test_params->{ 'single' } );
    is_dmarc_result( $tester, 'none', 'none', 'none', 1 );
    is(has_pre_header( $tester, 'X-Disposition-Quarantine', 'Quarantined due to DMARC policy' ), 0, 'not quarantined' );
};

subtest 'defaults multiple_headers' => sub {
    my $tester = $testers->{ 'defaults' };
    $tester->run( $test_params->{ 'multiple_headers' } );
    is_dmarc_result( $tester, 'none', 'none', 'none', 2 );
    is(has_pre_header( $tester, 'X-Disposition-Quarantine', 'Quarantined due to DMARC policy' ), 0, 'not quarantined' );
};

subtest 'defaults multiple_address' => sub {
    my $tester = $testers->{ 'defaults' };
    $tester->run( $test_params->{ 'multiple_address' } );
    is_dmarc_result( $tester, 'none', 'none', 'none', 2 );
    is(has_pre_header( $tester, 'X-Disposition-Quarantine', 'Quarantined due to DMARC policy' ), 0, 'not quarantined' );
};

subtest 'strict single' => sub {
    my $tester = $testers->{ 'strict' };
    $tester->run( $test_params->{ 'single' } );
    is_dmarc_result( $tester, 'none', 'none', 'none', 1 );
    is(has_pre_header( $tester, 'X-Disposition-Quarantine', 'Quarantined due to DMARC policy' ), 0, 'not quarantined' );
};

subtest 'strict multiple_headers' => sub {
    my $tester = $testers->{ 'strict' };
    $tester->run( $test_params->{ 'multiple_headers' } );
    is_dmarc_result( $tester, 'none', 'none', 'quarantine', 2 );
    is(has_pre_header( $tester, 'X-Disposition-Quarantine', 'Quarantined due to DMARC policy' ), 1, 'quarantined' );
};

subtest 'strict multiple_address' => sub {
    my $tester = $testers->{ 'strict' };
    $tester->run( $test_params->{ 'multiple_address' } );
    is_dmarc_result( $tester, 'none', 'none', 'quarantine', 2 );
    is(has_pre_header( $tester, 'X-Disposition-Quarantine', 'Quarantined due to DMARC policy' ), 1, 'quarantined' );
};

subtest 'reject single' => sub {
    my $tester = $testers->{ 'reject' };
    $tester->run( $test_params->{ 'single' } );
    is_dmarc_result( $tester, 'none', 'none', 'none', 1 );
};

subtest 'reject multiple_headers' => sub {
    my $tester = $testers->{ 'reject' };
    eval{$tester->run( $test_params->{ 'multiple_headers' } )};
    my $died = $@;
    is($died =~ /^body/, 1, "tester died in body stage");
};

subtest 'reject multiple_address' => sub {
    my $tester = $testers->{ 'reject' };
    eval{$tester->run( $test_params->{ 'multiple_headers' } )};
    my $died = $@;
    is($died =~ /^body/, 1, "tester died in body stage");
};

done_testing();

sub has_pre_header {
    my ( $tester, $field, $value ) = @_;
    my $pre_headers = $tester->handler->{pre_headers};
    for my $pre_header ($pre_headers->@*) {
        next unless $pre_header->{field} eq $field;
        next unless $pre_header->{value} eq $value;
        return 1;
    }
    return 0;
}

sub is_dmarc_result {
    my ( $tester, $expected, $evaluated, $applied, $count ) = @_;

    my $header = $tester->get_authresults_header()->search({ 'key' => 'dmarc' });
    is( scalar @{ $header->children() }, $count, 'One DMARC entry' );

    for my $header_instance( $header->children()->@*) {
        my $evaluated_disposition = $header_instance->search({ 'key' => 'policy.evaluated-disposition' })->children()->[0]->value();
        my $applied_disposition = $header_instance->search({ 'key' => 'policy.applied-disposition' })->children()->[0]->value();
        my $result = eval{ $header_instance->children()->[0]->value(); } // q{};
        is( $result, $expected, "DMARC result is $expected");
    }
}
