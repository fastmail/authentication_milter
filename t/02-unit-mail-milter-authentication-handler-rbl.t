#!perl
use 5.006;
use strict;
use warnings FATAL => 'all';
use lib 't';
use Test::More;

use Net::IP;
use AuthMilterTest;
use Mail::Milter::Authentication::Handler;
use Net::DNS::Resolver::Mock;

if ( ! -e 't/00-load.t' ) {
    die 'Could not find required files, are we in the correct directory?';
}

chdir 't';

open( STDERR, '>>', 'tmp/misc.err' ) || die "Cannot open errlog [$!]";
open( STDOUT, '>>', 'tmp/misc.err' ) || die "Cannot open errlog [$!]";

## Set up a fake handler object
my $prefix = 'config/normal.smtp';
$Mail::Milter::Authentication::Config::PREFIX = $prefix;
$Mail::Milter::Authentication::Config::IDENT  = 'test_authentication_milter_test';
my $Resolver = Net::DNS::Resolver::Mock->new();
$Resolver->zonefile_read( 'zonefile' );
$Mail::Milter::Authentication::Handler::TestResolver = $Resolver;

my $Authentication = Mail::Milter::Authentication->new();
$Authentication->{'config'} = $Authentication->get_config();
my $Handler = Mail::Milter::Authentication::Handler->new( $Authentication );

is( $Handler->rbl_check_domain( 'messagingengine.com', 'domainwl.authmilter.org' ), 1, 'domain listed' );
is( $Handler->rbl_check_ip( Net::IP->new('66.111.4.25'), 'ipwl.authmilter.org' ), 1, 'ip listed' );
is( $Handler->rbl_check_ip( Net::IP->new('2404:6800:4006:80a::200e'), 'ipwl.authmilter.org' ), 1, 'ip6 listed' );

is( $Handler->rbl_check_domain( 'fastmail.com', 'domainwl.authmilter.org' ), 0, 'domain not listed' );
is( $Handler->rbl_check_ip( Net::IP->new('1.1.1.1'), 'ipwl.authmilter.org' ), 0, 'ip not listed' );
is( $Handler->rbl_check_ip( Net::IP->new('2405:6800:4006:80a::200e'), 'ipwl.authmilter.org' ), 0, 'ip6 not listed' );

done_testing();
