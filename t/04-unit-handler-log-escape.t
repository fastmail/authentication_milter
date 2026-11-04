#!/usr/bin/env perl

# dbgout logs values taken from headers and DNS. Folded header values are
# unfolded and any other control characters escaped, so that each log entry
# stays on a single line.

use strict;
use warnings;
use lib 't';

use Mail::Milter::Authentication::Tester::HandlerTester;
use Mail::Milter::Authentication::Constants qw{ :all };
use Test::More;

my $basedir = q{};

mkdir 't/tmp';
open( STDERR, '>>', $basedir . 't/tmp/misc.err' ) || die "Cannot open errlog [$!]";

my $tester = Mail::Milter::Authentication::Tester::HandlerTester->new({
    'prefix'         => $basedir . 't/config/handler/etc',
    'zonedata'       => '',
    'handler_config' => {
        'Logger' => { 'header' => [ 'From' ] },
    },
});
my $handler = $tester->handler();

subtest 'escape_for_log' => sub {
    my @cases = (
        [ 'plain text',                        'plain text',                    'printable text unchanged' ],
        [ "a\@b.example\r\n  (Example User)",  'a@b.example (Example User)',    'CRLF folding unfolded' ],
        [ "a\@b.example\n\t(Example User)",    'a@b.example (Example User)',    'LF tab folding unfolded' ],
        [ "one\r\ntwo",                        'one\x0D\x0Atwo',                'bare CRLF escaped' ],
        [ "one\ntwo\rthree",                   'one\x0Atwo\x0Dthree',           'bare LF and CR escaped' ],
        [ "nul\x00del\x7Fesc\x1B",             'nul\x00del\x7Fesc\x1B',         'other control characters escaped' ],
        [ "caf\x{e9} back\\slash",             "caf\x{e9} back\\slash",         'non-ASCII and backslash unchanged' ],
    );
    for my $case ( @cases ) {
        my ( $in, $want, $name ) = @$case;
        is( $handler->escape_for_log( $in ), $want, $name );
    }
};

subtest 'dbgout escapes key and value' => sub {
    $tester->{'authmilter'}->{'tracelog'} = [];
    $handler->dbgout( "Key\nTwo", "Value\r\nSecond line", LOG_INFO );
    my @lines = map { $_->[1] } $tester->{'authmilter'}->{'tracelog'}->@*;
    is( scalar @lines, 1, 'one entry logged' );
    unlike( $lines[0], qr/[\r\n]/, 'no CR or LF in logged line' );
    like( $lines[0], qr/: Key\\x0ATwo: Value\\x0D\\x0ASecond line\z/, 'key and value escaped' );
};

subtest 'Logger with folded header' => sub {
    # run() starts from the _new snapshot, so capture the tracelog in it
    $tester->{'authmilter'}->{'tracelog'} = [];
    $tester->snapshot( '_new' );
    $tester->run({
        'connect_ip'   => '1.2.3.4',
        'connect_name' => 'mx.example.com',
        'helo'         => 'mx.example.com',
        'mailfrom'     => 'a@b.example',
        'rcptto'       => [ 'test@example.com' ],
        'body'         => "From: a\@b.example\n  (Example User)\nTo: test\@example.com\nSubject: Folded header\n\nbody\n",
    });
    my @lines = map { $_->[1] } $tester->{'authmilter'}->{'tracelog'}->@*;
    my @from = grep { /Logger: Header: From:/ } @lines;
    is( scalar @from, 1, 'From header logged once' );
    is( ( $from[0] =~ s/^.*?Logger: //r ), 'Header: From: a@b.example (Example User)', 'folded header logged on one line' );
    is( scalar( grep { /[\r\n]/ } @lines ), 0, 'no logged line contains CR or LF' );
};

done_testing();
