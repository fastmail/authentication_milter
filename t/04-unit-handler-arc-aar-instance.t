#!/usr/bin/env perl

# ARC-Authentication-Results headers are cached by instance number, and the
# trust decision for an instance is taken from the verified ARC-Seal for that
# instance. The two must agree on which header is instance N.
#
# The instance tag must be parsed strictly, as Mail::DKIM does, otherwise an
# AAR the sender added to their own message (e.g. "x i=1; ...") is ignored by
# Mail::DKIM during verification but cached by us as instance 1, and its
# results are then served as though they came from the trusted sealer.
#
# A second AAR for an instance we have already seen must not replace the
# first, and must cause that instance to be untrusted.

use strict;
use warnings;
use lib 't';

use Mail::Milter::Authentication::Tester::HandlerTester;
use Test::More;

my $basedir = q{};

mkdir 't/tmp';
open( STDERR, '>>', $basedir . 't/tmp/misc.err' ) || die "Cannot open errlog [$!]";

my $genuine = 'i=1; forwarder.example; spf=fail smtp.mailfrom=victim.com; dkim=none; dmarc=fail header.from=victim.com';

sub make_arc_handler {
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
    $arc->envfrom_callback( 'sender@victim.com' );
    return ( $tester, $arc );
}

sub add_aar {
    my ( $arc, $value ) = @_;
    $arc->header_callback( 'ARC-Authentication-Results', $value, 'ARC-Authentication-Results: ' . $value );
    return;
}

# Stand in for a verified chain sealed at instance 1 by the trusted forwarder
sub verified_chain {
    my ( $arc ) = @_;
    $arc->{'arc_result'} = 'pass';
    $arc->{'arc_domain'} = { 1 => 'forwarder.example' };
    return;
}

sub trusted_dmarc {
    my ( $arc ) = @_;
    my $aar = $arc->get_trusted_arc_authentication_results();
    return if ! $aar;
    return $aar->{1}->search({ 'isa' => 'entry', 'key' => 'dmarc' })->children()->[0]->value();
}

subtest 'control: genuine AAR alone is trusted' => sub {
    my ( $tester, $arc ) = make_arc_handler();
    add_aar( $arc, $genuine );
    verified_chain( $arc );
    is( trusted_dmarc( $arc ), 'fail', 'genuine results are returned' );
    ok( $arc->is_chain_trusted(), 'chain is trusted' );
    $tester->close();
};

subtest 'AAR with text before the instance tag is not instance 1' => sub {
    my ( $tester, $arc ) = make_arc_handler();
    add_aar( $arc, $genuine );
    add_aar( $arc, 'x i=1; a.example; dmarc=pass header.from=victim.com; spf=pass smtp.mailfrom=victim.com' );
    verified_chain( $arc );
    is( trusted_dmarc( $arc ), 'fail', 'forged results are not attributed to instance 1' );
    is_deeply( [ keys %{ $arc->{'arc_auth_results'} } ], [ 1 ], 'malformed AAR is not cached' );
    $tester->close();
};

subtest 'AAR with trailing text after the instance tag is not instance 1' => sub {
    my ( $tester, $arc ) = make_arc_handler();
    add_aar( $arc, $genuine );
    add_aar( $arc, 'i=1 x; a.example; dmarc=pass header.from=victim.com' );
    verified_chain( $arc );
    is( trusted_dmarc( $arc ), 'fail', 'forged results are not attributed to instance 1' );
    $tester->close();
};

subtest 'duplicate AAR for an instance is not trusted' => sub {
    my ( $tester, $arc ) = make_arc_handler();
    add_aar( $arc, $genuine );
    add_aar( $arc, 'i=1; a.example; dmarc=pass header.from=victim.com' );
    verified_chain( $arc );
    ok( ! defined $arc->get_trusted_arc_authentication_results(), 'nothing is trusted' );
    ok( ! $arc->is_chain_trusted(), 'chain is not trusted' );
    $tester->close();
};

subtest 'state is reset between messages' => sub {
    my ( $tester, $arc ) = make_arc_handler();
    add_aar( $arc, $genuine );
    add_aar( $arc, 'i=1; a.example; dmarc=pass header.from=victim.com' );
    $arc->envfrom_callback( 'sender@victim.com' );
    add_aar( $arc, $genuine );
    verified_chain( $arc );
    is( trusted_dmarc( $arc ), 'fail', 'genuine results are trusted on the next message' );
    $tester->close();
};

done_testing();
