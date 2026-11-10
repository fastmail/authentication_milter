#!/usr/bin/env perl

# SPF and DKIM results taken from a trusted ARC-Authentication-Results header
# are passed on to DMARC. Each result must carry the domain it applies to.
#
# smtp.mailfrom may be a bare domain (RFC 8601 Appendix B.3, as used by
# Microsoft and AOL), which is used as the domain. Otherwise it must be a
# single valid mailbox. A value which yields no domain must be skipped rather
# than passed on with an empty domain, which DMARC may treat as aligned with
# the From domain.
#
# A DKIM result with header.i but no header.d takes its domain from header.i.

use strict;
use warnings;
use lib 't';

use Mail::Milter::Authentication::Tester::HandlerTester;
use Test::More;

my $basedir = q{};

mkdir 't/tmp';
open( STDERR, '>>', $basedir . 't/tmp/misc.err' ) || die "Cannot open errlog [$!]";

sub trusted_arc_handler {
    my ( $aar ) = @_;
    my $tester = Mail::Milter::Authentication::Tester::HandlerTester->new({
        'prefix'         => $basedir . 't/config/handler/etc',
        'zonedata'       => '',
        'handler_config' => {
            'ARC' => {
                'trusted_domains' => [ 'forwarder.example' ],
            },
        },
    });
    my $arc = $tester->{'authmilter'}->{'handler'}->{'ARC'};
    $arc->envfrom_callback( 'sender@example.com' );
    $arc->header_callback( 'ARC-Authentication-Results', $aar, 'ARC-Authentication-Results: ' . $aar );
    # Stand in for a verified chain sealed at instance 1 by the trusted forwarder
    $arc->{'arc_result'} = 'pass';
    $arc->{'arc_domain'} = { 1 => 'forwarder.example' };
    return ( $tester, $arc );
}

subtest 'SPF results' => sub {
    my @cases = (
        [ 'test@example.com',          [ 'example.com' ], 'mailbox' ],
        [ '<test@example.com>',        [ 'example.com' ], 'angle bracketed mailbox' ],
        [ 'example.com',               [ 'example.com' ], 'bare domain' ],
        [ 'Example.COM',               [ 'example.com' ], 'bare domain is lower cased' ],
        [ '@example.com',              [],                'empty local part is skipped' ],
        [ '"a@b.example,c@d.example"', [],                'multiple mailboxes are skipped' ],
        [ '"not an address@"',         [],                'invalid address is skipped' ],
    );
    for my $case ( @cases ) {
        my ( $mailfrom, $want, $name ) = @$case;
        my ( $tester, $arc ) = trusted_arc_handler( "i=1; forwarder.example; spf=pass smtp.mailfrom=$mailfrom" );
        my $results = $arc->get_trusted_spf_results();
        is_deeply( [ map { $_->{'domain'} } @$results ], $want, $name );
        $tester->close();
    }
};

subtest 'SPF results alongside a skipped entry' => sub {
    my ( $tester, $arc ) = trusted_arc_handler( 'i=1; forwarder.example; spf=pass smtp.mailfrom=@example.org; spf=pass smtp.mailfrom=test@example.com' );
    my $results = $arc->get_trusted_spf_results();
    is_deeply( $results, [ { 'domain' => 'example.com', 'scope' => 'mfrom', 'result' => 'pass' } ], 'only the entry with a domain is returned' );
    $tester->close();
};

subtest 'SPF results in Microsoft style' => sub {
    # As in t/04-unit-handler-spfu.t
    my ( $tester, $arc ) = trusted_arc_handler( 'i=1; forwarder.example 1; spf=pass (sender ip is 23.26.253.8) smtp.rcpttodomain=example.net smtp.mailfrom=Example.com; dmarc=pass action=none header.from=example.com; dkim=none (message not signed); arc=none' );
    my $results = $arc->get_trusted_spf_results();
    is_deeply( $results, [ { 'domain' => 'example.com', 'scope' => 'mfrom', 'result' => 'pass' } ], 'bare domain smtp.mailfrom is used' );
    $tester->close();
};

subtest 'DKIM results' => sub {
    my @cases = (
        [ 'header.d=example.com header.s=sel',        [ 'example.com' ], 'header.d' ],
        [ 'header.i=@Example.com header.s=sel',       [ 'example.com' ], 'header.i without header.d' ],
        [ 'header.i=test@sub.example.com header.s=sel', [ 'sub.example.com' ], 'header.i with local part' ],
        [ 'header.s=sel',                             [],                'no identifier is skipped' ],
    );
    for my $case ( @cases ) {
        my ( $subentries, $want, $name ) = @$case;
        my ( $tester, $arc ) = trusted_arc_handler( "i=1; forwarder.example; dkim=pass $subentries" );
        my $results = $arc->get_trusted_dkim_results();
        is_deeply( [ map { $_->{'domain'} } @$results ], $want, $name );
        $tester->close();
    }
};

done_testing();
