#!/usr/bin/env perl

use strict;
use warnings;
use lib 't';

use Mail::Milter::Authentication::Tester::HandlerTester;
use Mail::Milter::Authentication::Constants qw{ :all };
use Test::Exception;
use Test::More;

my $basedir = q{};

open( STDERR, '>>', $basedir . 't/tmp/misc.err' ) || die "Cannot open errlog [$!]";

# Multiple from domains must never allow a domain to escape DMARC evaluation
# silently. Decoy domains sort before the target domain, so the target is
# always the last entity to be considered.

my $testers = {
    'defaults' => Mail::Milter::Authentication::Tester::HandlerTester->new({
        'prefix'   => $basedir . 't/config/handler/etc',
        'zonefile' => $basedir . 't/zonefile',
        'handler_config' => {
            'DKIM' => {},
            'SPF' => {},
            'DMARC' => {
                'reject_on_multifrom' => 30,
                'quarantine_on_multifrom' => 20,
                'skip_on_multifrom' => 10,
            },
        },
    }),
    'strict' => Mail::Milter::Authentication::Tester::HandlerTester->new({
        'prefix'   => $basedir . 't/config/handler/etc',
        'zonefile' => $basedir . 't/zonefile',
        'handler_config' => {
            'DKIM' => {},
            'SPF' => {},
            'DMARC' => {
                'reject_on_multifrom' => 30,
                'quarantine_on_multifrom' => 20,
                'skip_on_multifrom' => 10,
                'strict_multifrom' => 1,
            },
        },
    }),
    'nolimits' => Mail::Milter::Authentication::Tester::HandlerTester->new({
        'prefix'   => $basedir . 't/config/handler/etc',
        'zonefile' => $basedir . 't/zonefile',
        'handler_config' => {
            'DKIM' => {},
            'SPF' => {},
            'DMARC' => {
                'reject_on_multifrom' => 0,
                'quarantine_on_multifrom' => 0,
                'skip_on_multifrom' => 0,
            },
        },
    }),
};

my $target = 'zz-target.example.net';

subtest 'below skip limit' => sub {
    for my $count ( 1, 9, 10 ) {
        subtest "$count from headers" => sub {
            my $tester = $testers->{ 'defaults' };
            $tester->run( multifrom_params( $count, 'headers' ) );
            my $results = dmarc_results( $tester );
            is( scalar keys %$results, $count, 'all domains have a DMARC result' );
            is( $results->{ $target }, 'none', 'target domain was evaluated' );
            is( too_many_count( $tester ), 0, 'nothing skipped' );
            is( is_quarantined( $tester ), 0, 'not quarantined' );
        };
    }
};

subtest 'above skip limit' => sub {
    for my $count ( 11, 15, 20 ) {
        for my $style ( qw{ headers addresses } ) {
            subtest "$count from $style" => sub {
                my $tester = $testers->{ 'defaults' };
                $tester->run( multifrom_params( $count, $style ) );
                my $results = dmarc_results( $tester );
                is( scalar keys %$results, $count, 'all domains have a DMARC result' );
                is( $results->{ $target }, 'permerror', 'target domain has an explicit permerror' );
                is( too_many_count( $tester ), $count - 10, 'skipped domains are marked' );
                is( is_quarantined( $tester ), 1, 'quarantined' );
            };
        }
    }
};

subtest 'above reject limit' => sub {
    my $tester = $testers->{ 'defaults' };
    eval{ $tester->run( multifrom_params( 31, 'headers' ) ) };
    like( $@, qr/^body/, 'rejected' );
};

subtest 'at reject limit' => sub {
    my $tester = $testers->{ 'defaults' };
    $tester->run( multifrom_params( 30, 'headers' ) );
    is( is_quarantined( $tester ), 1, 'quarantined but not rejected' );
};

subtest 'strict with invalid decoys' => sub {
    for my $count ( 2, 11 ) {
        subtest "$count from headers" => sub {
            my $tester = $testers->{ 'strict' };
            $tester->run( multifrom_params( $count, 'headers', 'invalid' ) );
            my $results = dmarc_results( $tester );
            ok( exists $results->{ $target }, 'target domain has a DMARC result' );
            is( is_quarantined( $tester ), 1, 'quarantined' );
        };
    }
};

subtest 'no limits configured' => sub {
    my $tester = $testers->{ 'nolimits' };
    $tester->run( multifrom_params( 15, 'headers' ) );
    my $results = dmarc_results( $tester );
    is( scalar keys %$results, 15, 'all domains have a DMARC result' );
    is( $results->{ $target }, 'none', 'target domain was evaluated' );
    is( is_quarantined( $tester ), 0, 'not quarantined' );
};

done_testing();

sub multifrom_params {
    my ( $count, $style, $invalid ) = @_;
    my @domains = map { $invalid ? sprintf( 'decoy%02d', $_ ) : sprintf( 'decoy%02d.example.com', $_ ) } ( 1 .. $count - 1 );
    push @domains, $target;
    my @addresses = map { "test\@$_" } @domains;
    my $from = $style eq 'headers'
        ? join( "\n", map { "From: $_" } @addresses )
        : 'From: ' . join( ', ', @addresses );
    return {
        'connect_ip' => '1.2.3.4',
        'connect_name' => 'mx.example.net',
        'helo' => 'mx.example.net',
        'mailfrom' => 'test@envelope.example.net',
        'rcptto' => [ 'test@example.net' ],
        'body' => "$from\nTo: test\@example.net\nSubject: Test\n\nThis is a test",
    };
}

sub dmarc_results {
    my ( $tester ) = @_;
    my $header = $tester->get_authresults_header()->search({ 'key' => 'dmarc' });
    my %results;
    for my $entry ( $header->children()->@* ) {
        my $from = $entry->search({ 'key' => 'header.from' })->children()->[0];
        next unless $from;
        $results{ $from->value() } = $entry->value();
    }
    return \%results;
}

sub too_many_count {
    my ( $tester ) = @_;
    my $header = $tester->get_authresults_header()->search({ 'key' => 'dmarc' });
    return scalar grep { $_->as_string() =~ /too many from domains/ } $header->children()->@*;
}

sub is_quarantined {
    my ( $tester ) = @_;
    for my $pre_header ( $tester->handler->{pre_headers}->@* ) {
        return 1 if $pre_header->{field} eq 'X-Disposition-Quarantine';
    }
    return 0;
}
