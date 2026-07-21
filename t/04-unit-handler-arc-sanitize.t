#!/usr/bin/env perl

# The ARC sealer must not attest to Authentication-Results headers that
# Sanitize has removed from the outgoing message.
#
# Mail::DKIM::ARC::Signer builds the AAR by concatenating every
# Authentication-Results header in its input whose authserv-id equals SrvId.
# ARC.pm feeds it a cache of the ORIGINAL headers, which does not reflect
# change_header removals -- so without the fix an inbound A-R forged to claim
# our own authserv-id is stripped from delivery yet still sealed into an AAR we
# sign. On an untrusted connection its contents are attacker chosen, and
# get_trusted_arc_authentication_results() feeds AAR entries from trusted
# chains back into DMARC enforcement.

use strict;
use warnings;
use lib 't';

use Mail::Milter::Authentication::Tester::HandlerTester;
use Mail::Milter::Authentication::Constants qw{ :all };
use Test::Exception;
use Test::More;

my $basedir = q{};

mkdir 't/tmp';
open( STDERR, '>>', $basedir . 't/tmp/misc.err' ) || die "Cannot open errlog [$!]";

# Same throwaway test key used by t/04-unit-handler-bimi.t
my $private_key = 'MIICXQIBAAKBgQDErv0qLGKJ933gdhx2MUBqb/XhTloMjJhH0kdQsxkVuhRFzINgDzMGOq83xEwNEk4jC/J+E49fNQ+TSVymq+XGvrkeW7/7llEOTFosY6OGlwdeUZyyUCEM6SIYIBeHuIQn4Ohwhq7P0nZFfXNAG7Wrlxx1O+E881wTRhFOBxAjdQIDAQABAoGAP4cF3olXipiV39pGdyaRV8+x64QTMdp3lTsmLbqrb4ka4zCbfntqT6jEz45nwhEXi9pgCLjopifNUBVyB6OeI3KdaGQzfYVBCgTyvwMp+68rTnYtDeByrhXm+yccMpvFNA1BHxYiByucCGy8cc8jTfAvSKPTRpJ5TZM4S59ZkEECQQDkHOJ/Uzt5mm5Yq34HF78FzkY8w8TKRhVcsI0ZWS+Y1EBJTKZOoOS08d6Zetk0TNd52e6Gb0zxt325l5msKH3TAkEA3Lp67CXopC43Y8H7sJwMJiIYpN2F1lgt0XYsnyHhBnANS4Ap6d32j3MhtIEHwWv1vbRkCOSOm0h6Tq2Tj6rklwJBAOHQylN7JLxbqXLzyZ3h3wMzUQqkTjJjMJCCYhu+00R6kW0+iL/7vIx3h4HuQAjrLL/+gobotYXvvHE2ZzUrHGsCQQDAvmZQh9naZDEh/2ZVFi7VrbhvXrFcNqvr2JGmc+MXyAkUANqYyaZgJV0tTe8Dy85O1ZL04QBWQLfstE3CiqwJAkBJz/qjnUlfbyuTU1PHaWbkcTCZH48VE6nvsoHOKlyvxTUtRlfTILBPcQ5G5U3TePQMdzXInQASs0oncbz51NQ3';

# The authserv-id must be discovered at runtime, NOT hardcoded.
#
# It is the running host's name, which in a container or CI runner is an
# arbitrary value -- it is NOT $tester->servername(). Mail::DKIM::ARC::Signer
# only merges an Authentication-Results header into the AAR when its
# authserv-id equals SrvId exactly, so a hardcoded guess produces a forged
# header that never enters the AAR and a test that passes on vulnerable code.
#
# Sanitize needs no hosts_to_remove for this: is_hostname_mine() matches our
# own authserv_id directly.
sub make_tester {
    my (%args) = @_;

    my $arc_config = {
        'arcseal_domain'   => 'example.com',
        'arcseal_selector' => 'dkim1',
        'arcseal_key'      => $private_key,
    };
    $arc_config->{'arcseal_headers'} = $args{'arcseal_headers'}
        if $args{'arcseal_headers'};

    my $handler_config = { 'ARC' => $arc_config };

    # Sanitize is opt-in per test: with it absent, the sealer has no removals
    # to honour and must behave exactly as before.
    $handler_config->{'Sanitize'} = {
        'hosts_to_remove' => [],
        'remove_headers'  => 'yes',
    } if $args{'with_sanitize'};

    my $tester = Mail::Milter::Authentication::Tester::HandlerTester->new({
        'prefix'         => $basedir . 't/config/handler/etc',
        'zonedata'       => '',
        'handler_config' => $handler_config,
    });

    my $authserv
        = $tester->{'authmilter'}->{'handler'}->{'ARC'}->get_my_authserv_id();

    return ( $tester, $authserv );
}

sub run_message {
    my ( $tester, $body ) = @_;
    $tester->run({
        'connect_ip'   => '1.2.3.4',          # untrusted: Sanitize skips trusted IPs
        'connect_name' => 'mx.example.net',
        'helo'         => 'mx.example.net',
        'mailfrom'     => 'attacker@example.net',
        'rcptto'       => [ 'test@example.net' ],
        'body'         => $body,
    });
    return;
}

# The generated ARC headers are pushed onto the top handler's pre_headers.
sub get_added_header {
    my ( $tester, $want ) = @_;
    my $pre = $tester->handler()->{'pre_headers'} // [];
    foreach my $header ( @{ $pre } ) {
        return $header->{'value'} if lc( $header->{'field'} ) eq lc( $want );
    }
    return undef;
}

sub forged { my ($authserv) = @_;
    return "Authentication-Results: $authserv; dkim=pass header.d=victim.com; spf=pass smtp.mailfrom=victim.com";
}

subtest 'forged A-R claiming our authserv-id is not sealed into the AAR' => sub {
    my ( $tester, $authserv ) = make_tester( 'with_sanitize' => 1 );
    my $FORGED = forged( $authserv );

    run_message( $tester, "$FORGED
From: attacker\@example.net
To: test\@example.net
Subject: forged A-R

Testing" );

    my $aar = get_added_header( $tester, 'ARC-Authentication-Results' );
    ok( defined $aar, 'AAR header was generated' );

    unlike( $aar, qr/victim\.com/,
        'attacker-supplied entries are absent from the signed AAR' );
    unlike( $aar, qr/dkim=pass/,
        'forged dkim=pass did not survive into the seal' );

    $tester->close();
};

subtest 'a third-party A-R is untouched and never reaches the AAR' => sub {
    my ( $tester, $authserv ) = make_tester( 'with_sanitize' => 1 );
    my $FORGED = forged( $authserv );

    # Different authserv-id, and it mentions our own domain in header.d --
    # neither Sanitize nor the Signer may act on it.
    run_message( $tester, "Authentication-Results: mx.google.com; dkim=pass header.d=$authserv
From: attacker\@example.net
To: test\@example.net
Subject: third party A-R

Testing" );

    my $aar = get_added_header( $tester, 'ARC-Authentication-Results' );
    ok( defined $aar, 'AAR header was generated' );
    unlike( $aar, qr/mx\.google\.com/,
        'third-party authserv-id does not enter the AAR' );

    $tester->close();
};

subtest 'multiple interleaved A-R headers: only ours are excluded' => sub {
    my ( $tester, $authserv ) = make_tester( 'with_sanitize' => 1 );
    my $FORGED = forged( $authserv );

    # Two forged (ours) either side of a legitimate third-party header. This is
    # the case where occurrence numbering between Sanitize and the sealer must
    # line up: if the index mapping is off by one, the wrong chunk is skipped.
    run_message( $tester, "$FORGED
Authentication-Results: mx.google.com; dkim=pass header.d=elsewhere.com
Authentication-Results: $authserv; dmarc=pass header.from=victim.com
From: attacker\@example.net
To: test\@example.net
Subject: interleaved

Testing" );

    my $aar = get_added_header( $tester, 'ARC-Authentication-Results' );
    ok( defined $aar, 'AAR header was generated' );
    unlike( $aar, qr/victim\.com/,
        'neither forged header contributed to the AAR' );
    unlike( $aar, qr/dmarc=pass header\.from=victim\.com/,
        'forged dmarc=pass specifically is absent -- this is the entry that '
        . 'would override DMARC enforcement downstream' );

    $tester->close();
};

subtest 'folded forged header is excluded in full' => sub {
    my ( $tester, $authserv ) = make_tester( 'with_sanitize' => 1 );
    my $FORGED = forged( $authserv );

    run_message( $tester, "Authentication-Results: $authserv;
\tdkim=pass header.d=victim.com;
\tspf=pass smtp.mailfrom=victim.com
From: attacker\@example.net
To: test\@example.net
Subject: folded

Testing" );

    my $aar = get_added_header( $tester, 'ARC-Authentication-Results' );
    ok( defined $aar, 'AAR header was generated' );
    unlike( $aar, qr/victim\.com/,
        'continuation lines of a folded forged header are excluded too' );

    $tester->close();
};

subtest 'no Sanitize handler: sealing still works, behaviour unchanged' => sub {
    my ( $tester ) = make_tester();   # Sanitize deliberately not loaded

    run_message( $tester, "From: attacker\@example.net
To: test\@example.net
Subject: no sanitize

Testing" );

    my $aar  = get_added_header( $tester, 'ARC-Authentication-Results' );
    my $seal = get_added_header( $tester, 'ARC-Seal' );
    ok( defined $aar,  'AAR still generated with Sanitize absent' );
    ok( defined $seal, 'ARC-Seal still generated with Sanitize absent' );

    $tester->close();
};

subtest 'arcseal_headers including Authentication-Results' => sub {
    # When an operator signs A-R in the AMS, excluding a header that is also
    # removed from delivery keeps the signed set aligned with what is sent.
    my ( $tester, $authserv ) = make_tester(
        'with_sanitize'   => 1,
        'arcseal_headers' => 'Authentication-Results:From:To:Subject',
    );
    my $FORGED = forged( $authserv );

    run_message( $tester, "$FORGED
From: attacker\@example.net
To: test\@example.net
Subject: signed ar

Testing" );

    my $aar = get_added_header( $tester, 'ARC-Authentication-Results' );
    my $ams = get_added_header( $tester, 'ARC-Message-Signature' );
    ok( defined $aar, 'AAR generated with A-R in arcseal_headers' );
    ok( defined $ams, 'AMS generated with A-R in arcseal_headers' );
    unlike( $aar, qr/victim\.com/,
        'forged entries still excluded when A-R is in the signed header set' );

    $tester->close();
};

done_testing();
