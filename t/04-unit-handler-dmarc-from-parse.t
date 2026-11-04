#!/usr/bin/env perl

# Every From header must either have its domains evaluated by DMARC, or cause
# the mail to be quarantined. A From header which only partly parses must not
# let a domain escape evaluation, either on its own or alongside another From
# header which does parse.
#
# Empty list members (RFC 5322 obs-mbox-list) must be accepted and do not
# prevent the remaining mailboxes from being evaluated.

use strict;
use warnings;
use lib 't';

use Mail::Milter::Authentication::Tester::HandlerTester;
use Test::More;

my $basedir = q{};

mkdir 't/tmp';
open( STDERR, '>>', $basedir . 't/tmp/misc.err' ) || die "Cannot open errlog [$!]";

# goestheweasel.com publishes p=reject in t/zonefile, decoy.example.com has no policy
sub run_from {
    my ( $from_headers, $dmarc_config ) = @_;
    my $tester = Mail::Milter::Authentication::Tester::HandlerTester->new({
        'prefix'         => $basedir . 't/config/handler/etc',
        'zonefile'       => $basedir . 't/zonefile',
        'handler_config' => {
            'SPF'   => {},
            'DKIM'  => {},
            'DMARC' => { 'hard_reject' => 1, %{ $dmarc_config // {} } },
        },
    });
    # run() dies when the mail is rejected, the result is still available
    eval {
        $tester->run({
            'connect_ip'   => '1.2.3.4',
            'connect_name' => 'mx.example.com',
            'helo'         => 'mx.example.com',
            'mailfrom'     => 'test@goestheweasel.com',
            'rcptto'       => [ 'test@example.com' ],
            'body'         => join( q{}, map { "From: $_\n" } @$from_headers ) . "To: test\@example.com\nSubject: Test\n\nThis is a test\n",
        });
    };
    my @dmarc = map { $_->as_string() } $tester->get_authresults_header()->search({ 'key' => 'dmarc' })->children()->@*;
    s/\s+/ /g for @dmarc;
    return {
        'rejected'    => defined $tester->get_reject_mail() ? 1 : 0,
        'quarantined' => defined $tester->handler()->get_quarantine_mail() ? 1 : 0,
        'dmarc'       => \@dmarc,
    };
}

sub check {
    my ( $name, $from_headers, $expect, $dmarc_config ) = @_;
    subtest $name => sub {
        my $result = run_from( $from_headers, $dmarc_config );
        is( $result->{'rejected'}, $expect->{'rejected'}, 'rejected' );
        is( $result->{'quarantined'}, $expect->{'quarantined'}, 'quarantined' );
        my @from_domains = sort map { /header\.from=(\S+)/ ? $1 : () } $result->{'dmarc'}->@*;
        is_deeply( \@from_domains, [ sort $expect->{'evaluated'}->@* ], 'evaluated domains' ) or diag explain $result->{'dmarc'};
        my @permerrors = map { /^dmarc=permerror \((.*)\)$/ ? $1 : () } $result->{'dmarc'}->@*;
        is_deeply( \@permerrors, $expect->{'permerror'} // [], 'permerror' ) or diag explain $result->{'dmarc'};
    };
}

check( 'control', [ 'Bank <test@goestheweasel.com>' ],
    { 'rejected' => 1, 'quarantined' => 0, 'evaluated' => [ 'goestheweasel.com' ] } );

check( 'leading empty list member', [ ',Bank <test@goestheweasel.com>' ],
    { 'rejected' => 1, 'quarantined' => 0, 'evaluated' => [ 'goestheweasel.com' ] } );

check( 'trailing empty list members', [ 'Bank <test@goestheweasel.com>,,' ],
    { 'rejected' => 1, 'quarantined' => 0, 'evaluated' => [ 'goestheweasel.com' ] } );

check( 'folded quoted display name', [ "\"Bank\n Name\" <test\@goestheweasel.com>" ],
    { 'rejected' => 1, 'quarantined' => 0, 'evaluated' => [ 'goestheweasel.com' ] } );

check( 'domain literal alongside a domain', [ 'Bank <test@goestheweasel.com>, <x@[192.0.2.1]>' ],
    { 'rejected' => 1, 'quarantined' => 1, 'evaluated' => [ 'goestheweasel.com' ], 'permerror' => [ 'unparseable from header' ] } );

check( 'invalid mailbox keeps its domain', [ 'Bank <test@goestheweasel.com, me@decoy.example.com' ],
    { 'rejected' => 1, 'quarantined' => 1, 'evaluated' => [ 'decoy.example.com', 'goestheweasel.com' ], 'permerror' => [ 'unparseable from header' ] } );

check( 'unparseable from header', [ '"Unterminated test@goestheweasel.com' ],
    { 'rejected' => 0, 'quarantined' => 1, 'evaluated' => [], 'permerror' => [ 'no parseable from domain' ] } );

check( 'group with no mailboxes', [ 'undisclosed-senders:;' ],
    { 'rejected' => 0, 'quarantined' => 1, 'evaluated' => [], 'permerror' => [ 'no parseable from domain' ] } );

check( 'second from header, both parse', [ 'Bank <test@goestheweasel.com>', 'me@decoy.example.com' ],
    { 'rejected' => 1, 'quarantined' => 0, 'evaluated' => [ 'decoy.example.com', 'goestheweasel.com' ] } );

check( 'second from header, empty list member', [ ',Bank <test@goestheweasel.com>', 'me@decoy.example.com' ],
    { 'rejected' => 1, 'quarantined' => 0, 'evaluated' => [ 'decoy.example.com', 'goestheweasel.com' ] } );

check( 'second from header, first unparseable', [ '"Unterminated test@goestheweasel.com', 'me@decoy.example.com' ],
    { 'rejected' => 0, 'quarantined' => 1, 'evaluated' => [ 'decoy.example.com' ], 'permerror' => [ 'unparseable from header' ] } );

check( 'strict_multifrom with the first from header unparseable', [ '"Unterminated test@goestheweasel.com', 'me@decoy.example.com' ],
    { 'rejected' => 1, 'quarantined' => 1, 'evaluated' => [ 'decoy.example.com' ], 'permerror' => [ 'unparseable from header' ] },
    { 'strict_multifrom' => 1 } );

check( 'strict_multifrom without hard_reject', [ '"Unterminated test@goestheweasel.com', 'me@decoy.example.com' ],
    { 'rejected' => 0, 'quarantined' => 1, 'evaluated' => [ 'decoy.example.com' ], 'permerror' => [ 'unparseable from header' ] },
    { 'strict_multifrom' => 1, 'hard_reject' => 0 } );

done_testing();
