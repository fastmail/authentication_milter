#!/usr/bin/env perl

# ARC instances must be walked newest-to-oldest in NUMERIC order.
#
# get_trusted_arc_authentication_results() and is_chain_trusted() walk
# %arc_auth_results from the newest instance back towards instance 1,
# stopping trust propagation the moment they hit a signing domain that is
# not trusted -- everything from that hop backwards in the chain's history
# is assumed to be forwarded through (and possibly modified by) a party we
# don't vouch for, so it must not be trusted.
#
# A plain `sort keys %$aar` orders instance numbers as STRINGS, so once a
# chain reaches ten hops, "10" sorts as if it were the second instance
# ("1", "10", "2", "3", ... "9") rather than the tenth. `reverse sort` on
# that ordering visits 9,8,7,...,1,10 -- the newest hop (10) is checked
# LAST instead of first. If instance 10 was added by an untrusted or
# malicious relay, the string-sorted walk would mark instances 1-9 trusted
# before ever reaching instance 10, handing an attacker-modified chain's
# earlier results to SPF/DKIM/DMARC enforcement as if they were trustworthy.
# The fix sorts numerically ( sort { $a <=> $b } keys %$aar ) so instance 10
# is always evaluated in its correct, newest position.

use strict;
use warnings;
use lib 't';

use Mail::Milter::Authentication::Tester::HandlerTester;
use Test::More;

my $basedir = q{};

mkdir 't/tmp';
open( STDERR, '>>', $basedir . 't/tmp/misc.err' ) || die "Cannot open errlog [$!]";

sub make_arc_handler {
    my $tester = Mail::Milter::Authentication::Tester::HandlerTester->new({
        'prefix'         => $basedir . 't/config/handler/etc',
        'zonedata'       => '',
        'handler_config' => {
            'ARC' => {
                'trusted_domains' => [ 'trusted.example.com' ],
            },
        },
    });
    return ( $tester, $tester->{'authmilter'}->{'handler'}->{'ARC'} );
}

# Wire up a fake ARC chain directly on the handler object, bypassing the
# DKIM/ARC crypto verification entirely -- we are testing the ordering of
# the trust walk, not signature validation.
sub set_chain {
    my ( $arc, $domain_by_instance ) = @_;
    $arc->{'arc_result'}       = 'pass';
    $arc->{'arc_domain'}       = $domain_by_instance;
    $arc->{'arc_auth_results'} = {
        map { $_ => { 'instance' => $_ } } keys %$domain_by_instance
    };
    return;
}

subtest 'a ten hop chain where only the newest instance is untrusted' => sub {
    my ( $tester, $arc ) = make_arc_handler();

    # Instances 1-9 came through trusted infrastructure. Instance 10 is the
    # freshest hop, and it is NOT trusted -- e.g. an attacker-controlled
    # relay appended it, potentially having modified the message before
    # resigning. Nothing before it can be vouched for.
    my %domain_by_instance = map { $_ => 'trusted.example.com' } ( 1 .. 9 );
    $domain_by_instance{10} = 'attacker.example.net';
    set_chain( $arc, \%domain_by_instance );

    my $trusted_aar = $arc->get_trusted_arc_authentication_results();
    ok( ! defined $trusted_aar,
        'nothing is trusted when the newest instance (10) is untrusted' );

    ok( ! $arc->is_chain_trusted(),
        'the chain as a whole is not trusted' );

    $tester->close();
};

subtest 'control: a fully trusted ten hop chain is trusted in full' => sub {
    my ( $tester, $arc ) = make_arc_handler();

    my %domain_by_instance = map { $_ => 'trusted.example.com' } ( 1 .. 10 );
    set_chain( $arc, \%domain_by_instance );

    my $trusted_aar = $arc->get_trusted_arc_authentication_results();
    ok( defined $trusted_aar, 'a trusted result set is returned' );
    is( scalar keys %$trusted_aar, 10,
        'all ten instances are trusted, including instance 10' );

    ok( $arc->is_chain_trusted(), 'the chain as a whole is trusted' );

    $tester->close();
};

subtest 'an untrusted hop further back in a ten hop chain limits trust to what follows it' => sub {
    my ( $tester, $arc ) = make_arc_handler();

    # Instance 1 (the oldest, entry hop) is untrusted; everything from
    # instance 2 onwards is trusted. Trust should extend back only as far
    # as instance 2 -- instance 1's untrusted domain must not poison
    # newer, otherwise-trusted instances, but it does mean the chain as a
    # whole is not fully trusted.
    my %domain_by_instance = map { $_ => 'trusted.example.com' } ( 2 .. 10 );
    $domain_by_instance{1} = 'attacker.example.net';
    set_chain( $arc, \%domain_by_instance );

    my $trusted_aar = $arc->get_trusted_arc_authentication_results();
    ok( defined $trusted_aar, 'a trusted result set is returned' );
    is_deeply( [ sort { $a <=> $b } keys %$trusted_aar ], [ 2 .. 10 ],
        'instances 2 through 10 are trusted, instance 1 is excluded' );

    ok( ! $arc->is_chain_trusted(),
        'the chain as a whole is still not fully trusted' );

    $tester->close();
};

done_testing();
