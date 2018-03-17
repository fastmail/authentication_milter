#!perl
use 5.006;
use strict;
use warnings FATAL => 'all';
use lib 't';
use Test::More;
use Test::File::Contents;
use Net::DNS::Resolver::Mock;
use AuthMilterTest;

if ( ! -e 't/00-load.t' ) {
    die 'Could not find required files, are we in the correct directory?';
}

chdir 't';

plan tests => 1;

{
    #system 'rm -rf tmp';
    mkdir 'tmp';
    mkdir 'tmp/result';

    AuthMilterTest::tools_pipeline_test();

};

