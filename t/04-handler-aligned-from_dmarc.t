#!/usr/bin/env perl

use strict;
use warnings;
use lib 't';

use Data::Dumper;

use TestAlignedFromHandler;
use Test::More;

my $basedir = q{};

open( STDERR, '>>', $basedir . 't/tmp/misc.err' ) || die "Cannot open errlog [$!]";
#open( STDOUT, '>>', $basedir . 't/tmp/misc.err' ) || die "Cannot open errlog [$!]";

# Tester instance with access to a loaded DMARC Handler

my $tester_dmarc = Mail::Milter::Authentication::Tester::HandlerTester->new({
    'prefix'   => $basedir . 't/config/handler/aligned-from',
    'zonefile' => $basedir . 't/zonefile',
});

TestAlignedFromHandler::test_dmarc_or_not( $tester_dmarc );
TestAlignedFromHandler::test_dmarc( $tester_dmarc );

$tester_dmarc->close();

done_testing();

