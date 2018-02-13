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

# Tester instance without access to a loaded DMARC Handler

my $tester_no_dmarc = Mail::Milter::Authentication::Tester::HandlerTester->new({
    'prefix'   => $basedir . 't/config/handler/aligned-from_no-dmarc',
    'zonefile' => $basedir . 't/zonefile',
});

TestAlignedFromHandler::test_dmarc_or_not( $tester_no_dmarc );
TestAlignedFromHandler::test_no_dmarc( $tester_no_dmarc );

done_testing();

