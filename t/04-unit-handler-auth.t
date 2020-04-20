#!/usr/bin/env perl

use strict;
use warnings;
use lib 't';

use Data::Dumper;

use Mail::Milter::Authentication::Tester::HandlerTester;
use Mail::Milter::Authentication::Constants qw{ :all };
use Test::Exception;
use Test::More;
use JSON::XS;

my $basedir = q{};

open( STDERR, '>>', $basedir . 't/tmp/misc.err' ) || die "Cannot open errlog [$!]";
#open( STDOUT, '>>', $basedir . 't/tmp/misc.err' ) || die "Cannot open errlog [$!]";

my $tester = Mail::Milter::Authentication::Tester::HandlerTester->new({
    'protocol' => 'milter',
    'prefix'   => $basedir . 't/config/handler/etc',
    'zonedata' => '',
    'handler_config' => {
        'Auth' => {},
    },
});

subtest 'config' => sub {
    my $config = $tester->{ 'authmilter' }->{ 'handler' }->{ 'Auth' }->default_config();
    is_deeply( $config, {}, 'Returns correct config' );
};

subtest 'metrics' => sub {
    my $grafana_rows = $tester->{ 'authmilter' }->{ 'handler' }->{ 'Auth' }->grafana_rows();
    is( scalar @$grafana_rows, 1, '1 Grafana row returned' );
    lives_ok( sub{ JSON::XS->new()->decode( $grafana_rows->[0] ); }, 'Metrics returns valid JSON' );
};

{

    $tester->run({
        'connect_ip' => '1.2.3.4',
        'connect_name' => 'mx.example.com',
        'helo' => 'mx.example.com',
        'mailfrom' => 'test@example.net',
        'rcptto' => [ 'test@example.net' ],
        'body' => 'From: test@example.net
To: test@example.net
Subject: This is a test

Testing',
    });

    my $header = $tester->get_authresults_header()->search({ 'key' => 'auth' });
    is( scalar @{ $header->children() }, 0, 'No Entries' );
    my $result = eval{ $header->children()->[0]->value(); } // q{};
    is( $result, q{}, 'Unauthenticated' );
}

{
    $tester->switch( '_new' );
    $tester->connect( 'mx.example.com', '1.2.3.4' );
    $tester->helo( 'mx.example.com' );
    $tester->handler()->set_symbol('C', '{auth_authen}','testAuthUser'); 
    $tester->mailfrom( 'test@example.net' );
    $tester->rcptto( 'test@example.net' );
    $tester->header( 'From', 'test@example.net' );
    $tester->header( 'To', 'test@example.net' );
    $tester->end_of_headers();
    $tester->body( 'This is a test' );
    $tester->end_of_message();

    my $header = $tester->get_authresults_header()->search({ 'key' => 'auth' });
    is( scalar @{ $header->children() }, 1, '1 Entry' );
    my $result = eval{ $header->children()->[0]->value(); } // q{};
    is( $result, 'pass', 'Authenticated' );

}

done_testing();

