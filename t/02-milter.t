#!perl
use 5.006;
use strict;
use warnings FATAL => 'all';
use lib 't';
use Test::More;
use Test::File::Contents;
use AuthMilterTestDNSCache;
use AuthMilterTest;

if ( ! -e 't/01-tools.t' ) {
    die 'Could not find required files, are we in the correct directory?';
}

chdir 't';

plan tests => 14;

{
    system 'rm -rf tmp';
    mkdir 'tmp';
    mkdir 'tmp/result';

    AuthMilterTest::run_milter_processing();

};

