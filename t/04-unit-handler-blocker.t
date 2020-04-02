#!/usr/bin/env perl

use strict;
use warnings;
use lib 't';

use Data::Dumper;

use Mail::Milter::Authentication::Tester::HandlerTester;
use Mail::Milter::Authentication::Constants qw{ :all };
use Test::Exception;
use Test::More;

my $basedir = q{};

mkdir 't/tmp';
open( STDERR, '>>', $basedir . 't/tmp/misc.err' ) || die "Cannot open errlog [$!]";
#open( STDOUT, '>>', $basedir . 't/tmp/misc.err' ) || die "Cannot open errlog [$!]";

my $tester_no_conf = Mail::Milter::Authentication::Tester::HandlerTester->new({
    'protocol' => 'smtp',
    'prefix'   => $basedir . 't/config/handler/etc',
    'zonedata' => '',
    'handler_config' => {
        'Blocker' => { 'blocker_configs' => [] },
    },
});
$tester_no_conf->snapshot( 'new' );

my $tester_one_conf = Mail::Milter::Authentication::Tester::HandlerTester->new({
    'protocol' => 'smtp',
    'prefix'   => $basedir . 't/config/handler/etc',
    'zonedata' => '',
    'handler_config' => {
        'Blocker' => { 'blocker_configs' => [ 't/conf/blocker.toml' ] },
    },
});
$tester_one_conf->snapshot( 'new' );

my $tester_two_conf = Mail::Milter::Authentication::Tester::HandlerTester->new({
    'protocol' => 'smtp',
    'prefix'   => $basedir . 't/config/handler/etc',
    'zonedata' => '',
    'handler_config' => {
        'Blocker' => { 'blocker_configs' => [ 't/conf/blocker.toml','t/conf/blocker2.toml' ] },
    },
});
$tester_two_conf->snapshot( 'new' );

my $tester_until_conf = Mail::Milter::Authentication::Tester::HandlerTester->new({
    'protocol' => 'smtp',
    'prefix'   => $basedir . 't/config/handler/etc',
    'zonedata' => '',
    'handler_config' => {
        'Blocker' => { 'blocker_configs' => [ 't/conf/blocker3.toml' ] },
    },
});
$tester_until_conf->snapshot( 'new' );

subtest 'config' => sub {
    my $config = $tester_no_conf->{ 'authmilter' }->{ 'handler' }->{ 'Blocker' }->default_config();
    is_deeply( $config, { 'blocker_configs' => [ '/tmpfs/authmilter-blocker.toml' ] }, 'Returns correct config' );
};

## TODO This SHOULD have grafana rows!
subtest 'metrics' => sub {
    is( $tester_no_conf->{ 'authmilter' }->{ 'handler' }->{ 'Blocker' }->can( 'grafana_rows' ), undef, 'Has no grafana rows' );
};

subtest 'no_config' => sub {

    $tester_no_conf->switch( 'new' );
    lives_ok( sub{ $tester_no_conf->run({
        'connect_ip' => '1.2.3.4',
        'connect_name' => 'mx.example.com',
        'helo' => 'mx.example.com',
        'mailfrom' => 'test@example.net',
        'rcptto' => [ 'test@example.net' ],
        'body' => 'From: test@example.net
To: test@example.net
Subject: This is a test

Testing',
    })},'accepted');

};

subtest 'one_config' => sub {

    $tester_one_conf->switch( 'new' );
    lives_ok( sub{ $tester_one_conf->run({
        'connect_ip' => '1.2.3.4',
        'connect_name' => 'mx.example.com',
        'helo' => 'mx.example.com',
        'mailfrom' => 'test@example.net',
        'rcptto' => [ 'test@example.net' ],
        'body' => 'From: test@example.net
To: test@example.net
Subject: This is a test

Testing',
    })},'no match accepted');

    $tester_one_conf->switch( 'new' );
    lives_ok( sub{ $tester_one_conf->run({
        'connect_ip' => '192.168.0.2',
        'connect_name' => 'mx.example.com',
        'helo' => 'mx.example.com',
        'mailfrom' => 'test@example.net',
        'rcptto' => [ 'test@example.net' ],
        'body' => 'From: test@example.net
To: test@example.net
Subject: This is a test

Testing',
    })},'sampled out match accepted');

    $tester_one_conf->switch( 'new' );
    dies_ok( sub{ $tester_one_conf->run({
        'connect_ip' => '192.168.0.1',
        'connect_name' => 'mx.example.com',
        'helo' => 'mx.example.com',
        'mailfrom' => 'test@example.net',
        'rcptto' => [ 'test@example.net' ],
        'body' => 'From: test@example.net
To: test@example.net
Subject: This is a test

Testing',
    })},'connect match rejected');

    $tester_one_conf->switch( 'new' );
    dies_ok( sub{ $tester_one_conf->run({
        'connect_ip' => '1.2.3.4',
        'connect_name' => 'mx.example.com',
        'helo' => 'helo.example.bad',
        'mailfrom' => 'test@example.net',
        'rcptto' => [ 'test@example.net' ],
        'body' => 'From: test@example.net
To: test@example.net
Subject: This is a test

Testing',
    })},'helo match rejected');

    $tester_one_conf->switch( 'new' );
    dies_ok( sub{ $tester_one_conf->run({
        'connect_ip' => '1.2.3.4',
        'connect_name' => 'mx.example.com',
        'helo' => 'mx.example.com',
        'mailfrom' => 'bad@example.com',
        'rcptto' => [ 'test@example.net' ],
        'body' => 'From: test@example.net
To: test@example.net
Subject: This is a test

Testing',
    })},'from match rejected');

    $tester_one_conf->switch( 'new' );
    dies_ok( sub{ $tester_one_conf->run({
        'connect_ip' => '1.2.3.4',
        'connect_name' => 'mx.example.com',
        'helo' => 'mx.example.com',
        'mailfrom' => 'test@example.net',
        'rcptto' => [ 'bad@example.net' ],
        'body' => 'From: test@example.net
To: test@example.net
Subject: This is a test

Testing',
    })},'to match rejected');

    $tester_one_conf->switch( 'new' );
    dies_ok( sub{ $tester_one_conf->run({
        'connect_ip' => '1.2.3.4',
        'connect_name' => 'mx.example.com',
        'helo' => 'mx.example.com',
        'mailfrom' => 'test@example.net',
        'rcptto' => [ 'test@example.net' ],
        'body' => 'From: test@example.net
To: test@example.net
BadHeader: Reject Me!
Subject: This is a test

Testing',
    })},'header match rejected');

};

subtest 'two_config' => sub {

    $tester_two_conf->switch( 'new' );
    lives_ok( sub{ $tester_two_conf->run({
        'connect_ip' => '1.2.3.4',
        'connect_name' => 'mx.example.com',
        'helo' => 'mx.example.com',
        'mailfrom' => 'test@example.net',
        'rcptto' => [ 'test@example.net' ],
        'body' => 'From: test@example.net
To: test@example.net
Subject: This is a test

Testing',
    })},'no match accepted');

    $tester_two_conf->switch( 'new' );
    dies_ok( sub{ $tester_two_conf->run({
        'connect_ip' => '192.168.0.1',
        'connect_name' => 'mx.example.com',
        'helo' => 'mx.example.com',
        'mailfrom' => 'test@example.net',
        'rcptto' => [ 'test@example.net' ],
        'body' => 'From: test@example.net
To: test@example.net
Subject: This is a test

Testing',
    })},'connect match file 1 rejected');
    is( $tester_two_conf->{'authmilter'}->{'handler'}->{'_Handler'}->{'defer_mail'}, '451 4.7.28 flood policy violation (HOTtest)', 'Defer reason correct' );
    is( $tester_two_conf->{'authmilter'}->{'handler'}->{'_Handler'}->{'reject_mail'}, undef, 'Reject reason undef' );

    $tester_two_conf->switch( 'new' );
    dies_ok( sub{ $tester_two_conf->run({
        'connect_ip' => '192.168.0.2',
        'connect_name' => 'mx.example.com',
        'helo' => 'mx.example.com',
        'mailfrom' => 'test@example.net',
        'rcptto' => [ 'test@example.net' ],
        'body' => 'From: test@example.net
To: test@example.net
Subject: This is a test

Testing',
    })},'connect match file 2 rejected');
    is( $tester_two_conf->{'authmilter'}->{'handler'}->{'_Handler'}->{'defer_mail'}, undef, 'Defer reason undef' );
    is( $tester_two_conf->{'authmilter'}->{'handler'}->{'_Handler'}->{'reject_mail'}, '500 5.0.0 Blocked', 'Reject reason correct' );

};

subtest 'until_config' => sub {

    $tester_until_conf->switch( 'new' );
    dies_ok( sub{ $tester_until_conf->run({
        'connect_ip' => '192.168.0.1',
        'connect_name' => 'mx.example.com',
        'helo' => 'mx.example.com',
        'mailfrom' => 'test@example.net',
        'rcptto' => [ 'test@example.net' ],
        'body' => 'From: test@example.net
To: test@example.net
Subject: This is a test

Testing',
    })},'no until blocked');

    $tester_until_conf->switch( 'new' );
    lives_ok( sub{ $tester_until_conf->run({
        'connect_ip' => '192.168.0.2',
        'connect_name' => 'mx.example.com',
        'helo' => 'mx.example.com',
        'mailfrom' => 'test@example.net',
        'rcptto' => [ 'test@example.net' ],
        'body' => 'From: test@example.net
To: test@example.net
Subject: This is a test

Testing',
    })},'past until accepted');

    $tester_until_conf->switch( 'new' );
    dies_ok( sub{ $tester_until_conf->run({
        'connect_ip' => '192.168.0.3',
        'connect_name' => 'mx.example.com',
        'helo' => 'mx.example.com',
        'mailfrom' => 'test@example.net',
        'rcptto' => [ 'test@example.net' ],
        'body' => 'From: test@example.net
To: test@example.net
Subject: This is a test

Testing',
    })},'future until blocked');

    $tester_until_conf->switch( 'new' );
    dies_ok( sub{ $tester_until_conf->run({
        'connect_ip' => '192.168.0.4',
        'connect_name' => 'mx.example.com',
        'helo' => 'mx.example.com',
        'mailfrom' => 'test@example.net',
        'rcptto' => [ 'test@example.net' ],
        'body' => 'From: test@example.net
To: test@example.net
Subject: This is a test

Testing',
    })},'zero until blocked');

};

done_testing();

