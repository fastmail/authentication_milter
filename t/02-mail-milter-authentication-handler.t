#!perl
use 5.006;
use strict;
use warnings FATAL => 'all';
use lib 't';
use Test::More;

use AuthMilterTest;
use Mail::Milter::Authentication::Handler;

if ( ! -e 't/01-tools.t' ) {
    die 'Could not find required files, are we in the correct directory?';
}

chdir 't';

my $Tests = {
    'Dear Customer

this is a very long long email address
<test@example.com>'                             => [ 'test@example.com', 'example.com' ],
    'Marc Bradshaw <marc@goestheweasel.com>'    => [ 'marc@goestheweasel.com', 'goestheweasel.com' ],
    'Marc Bradshaw <marc@ marcbradshaw.net>'    => [ 'marc@marcbradshaw.net', 'marcbradshaw.net' ],
    '"Marc Bradshaw" <marc@marcbradshaw.net>'   => [ 'marc@marcbradshaw.net', 'marcbradshaw.net' ],
    'test@example.com (With comment)'           => [ 'test@example.com', 'example.com' ],
    'test@example.com'                          => [ 'test@example.com', 'example.com' ],
    'test@goestheweasel.com'                    => [ 'test@goestheweasel.com', 'goestheweasel.com' ],
    'nothing in here is an address'             => [ 'nothing in here is an address', 'localhost.localdomain' ],
};

my $NumTests = ( scalar keys %$Tests ) * 2;
plan tests => $NumTests;

## Set up a fake handler object
my $prefix = 'config/normal.smtp';
$Mail::Milter::Authentication::Config::PREFIX = $prefix;
$Mail::Milter::Authentication::Config::IDENT  = 'test_authentication_milter_test';
$Mail::Milter::Authentication::Handler::TestResolver = AuthMilterTestDNSCache->new(),
my $Authentication = Mail::Milter::Authentication->new();
$Authentication->{'config'} = $Authentication->get_config();
my $Handler = Mail::Milter::Authentication::Handler->new( $Authentication );

{
    foreach my $Line ( sort keys %$Tests )  {

        my $ExpectedAddress = $Tests->{ $Line }->[0];
        my $ReturnedAddress = $Handler->get_address_from( $Line );
        is( $ReturnedAddress, $ExpectedAddress, 'get_address_from()' );

        my $ExpectedDomain = $Tests->{ $Line }->[1];
        my $ReturnedDomain = $Handler->get_domain_from( $Line );
        is( $ReturnedDomain, $ExpectedDomain, 'get_domain_from()' );
    }

}

