#!perl
use 5.006;
use strict;
use warnings FATAL => 'all';
use lib 't';
use Test::More;

use AuthMilterTest;
use Mail::Milter::Authentication::Handler;
use Net::DNS::Resolver::Mock;

if ( ! -e 't/01-tools.t' ) {
    die 'Could not find required files, are we in the correct directory?';
}

chdir 't';

open( STDERR, '>>', 'tmp/misc.err' ) || die "Cannot open errlog [$!]";
open( STDOUT, '>>', 'tmp/misc.err' ) || die "Cannot open errlog [$!]";

my $AddressTests = {
    '"Dear Customer

 Happy new Year Ray-Ban Sunglasses items on online shop.
 All items are in new condition,and new style.Ray-Ban Sunglasses Just 19.
  99$ & Up To 87% OFF
 Welcome to check our website: http://www.example.com/
 
 
 
 
 
 
 
 ",
        <noreply@example.com>'                  => [ 'noreply@example.com', 'example.com' ],
    'Dear Customer

this is a very long long email address
<test@example.com>'                             => [ 'test@example.com', 'example.com' ],
    'Marc Bradshaw <marc@goestheweasel.com>'    => [ 'marc@goestheweasel.com', 'goestheweasel.com' ],
    'marc@ marcbradshaw.net'                    => [ 'marc@marcbradshaw.net', 'marcbradshaw.net' ],
    'Marc Bradshaw <marc@ marcbradshaw.net>'    => [ 'marc@marcbradshaw.net', 'marcbradshaw.net' ],
    '"Marc Bradshaw" <marc@marcbradshaw.net>'   => [ 'marc@marcbradshaw.net', 'marcbradshaw.net' ],
    'test@example.com (With comment)'           => [ 'test@example.com', 'example.com' ],
    'test@example.com'                          => [ 'test@example.com', 'example.com' ],
    'test@goestheweasel.com'                    => [ 'test@goestheweasel.com', 'goestheweasel.com' ],
    'nothing in here is an address'             => [ 'nothing in here is an address', 'localhost.localdomain' ],
    ''                                          => [ '', 'localhost.localdomain' ],
};

my $AddressesTests = {
    '<security@example.net>, <foo@example.com>'    => [ [ 'security@example.net', 'foo@example.com' ], [ 'example.net', 'example.com' ] ],
};

my $NumTests = ( ( scalar keys %$AddressTests ) + ( scalar keys %$AddressesTests ) ) * 2;

plan tests => $NumTests;

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

{
    foreach my $Line ( sort keys %$AddressTests )  {

        my $ExpectedAddress = $AddressTests->{ $Line }->[0];
        my $ReturnedAddress = $Handler->get_address_from( $Line );
        is( $ReturnedAddress, $ExpectedAddress, 'get_address_from()' );

        my $ExpectedDomain = $AddressTests->{ $Line }->[1];
        my $ReturnedDomain = $Handler->get_domain_from( $Line );
        is( $ReturnedDomain, $ExpectedDomain, 'get_domain_from()' );
    }

}

{
    foreach my $Line ( sort keys %$AddressesTests )  {

        my $ExpectedAddresses = $AddressesTests->{ $Line }->[0];
        my $ReturnedAddresses = $Handler->get_addresses_from( $Line );
        is_deeply( $ReturnedAddresses, $ExpectedAddresses, 'get_addresses_from()' );

        my $ExpectedDomains = $AddressesTests->{ $Line }->[1];
        my $ReturnedDomains = $Handler->get_domains_from( $Line );
        is_deeply( $ReturnedDomains, $ExpectedDomains, 'get_domains_from()' );
    }

}

