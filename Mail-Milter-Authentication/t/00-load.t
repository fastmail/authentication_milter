#!perl -T
use 5.006;
use strict;
use warnings FATAL => 'all';
use Test::More;

plan tests => 2;

BEGIN {
    use_ok( 'Mail::Milter::Authentication' ) || print "Bail out!\n";
    use_ok( 'Mail::Milter::Authentication::Handler' ) || print "Bail out!\n";
}

diag( "Testing Mail::Milter::Authentication $Mail::Milter::Authentication::VERSION, Perl $], $^X" );
