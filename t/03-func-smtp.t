#!perl
use 5.006;
use strict;
use warnings FATAL => 'all';
use lib 't';
use Test::More;
use Test::File::Contents;
use Net::DNS::Resolver::Mock;
use AuthMilterTest;

if ( $ENV{SKIP_SMTP_TESTS} ) {
    plan( skip_all => "Tests skipped by environment" );
}

if ( ! -e 't/00-load.t' ) {
    die 'Could not find required files, are we in the correct directory?';
}

chdir 't';

plan tests => 34;

{
#    system 'rm -rf tmp';
    mkdir 'tmp';
    mkdir 'tmp/result';

    AuthMilterTest::run_smtp_processing();

};

