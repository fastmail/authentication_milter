#!/usr/bin/env perl

use strict;
use warnings;
use lib 't';

use Mail::Milter::Authentication::Tester::HandlerTester;
use Mail::Milter::Authentication::Constants qw{ :all };
use Test::Exception;
use Test::More;
use Mail::DKIM::Signer;
use Mail::DKIM::ARC::Signer;
use Mail::DKIM::PrivateKey;

my $private_key = Mail::DKIM::PrivateKey->load(Data=>'MIICXQIBAAKBgQDErv0qLGKJ933gdhx2MUBqb/XhTloMjJhH0kdQsxkVuhRFzINgDzMGOq83xEwNEk4jC/J+E49fNQ+TSVymq+XGvrkeW7/7llEOTFosY6OGlwdeUZyyUCEM6SIYIBeHuIQn4Ohwhq7P0nZFfXNAG7Wrlxx1O+E881wTRhFOBxAjdQIDAQABAoGAP4cF3olXipiV39pGdyaRV8+x64QTMdp3lTsmLbqrb4ka4zCbfntqT6jEz45nwhEXi9pgCLjopifNUBVyB6OeI3KdaGQzfYVBCgTyvwMp+68rTnYtDeByrhXm+yccMpvFNA1BHxYiByucCGy8cc8jTfAvSKPTRpJ5TZM4S59ZkEECQQDkHOJ/Uzt5mm5Yq34HF78FzkY8w8TKRhVcsI0ZWS+Y1EBJTKZOoOS08d6Zetk0TNd52e6Gb0zxt325l5msKH3TAkEA3Lp67CXopC43Y8H7sJwMJiIYpN2F1lgt0XYsnyHhBnANS4Ap6d32j3MhtIEHwWv1vbRkCOSOm0h6Tq2Tj6rklwJBAOHQylN7JLxbqXLzyZ3h3wMzUQqkTjJjMJCCYhu+00R6kW0+iL/7vIx3h4HuQAjrLL/+gobotYXvvHE2ZzUrHGsCQQDAvmZQh9naZDEh/2ZVFi7VrbhvXrFcNqvr2JGmc+MXyAkUANqYyaZgJV0tTe8Dy85O1ZL04QBWQLfstE3CiqwJAkBJz/qjnUlfbyuTU1PHaWbkcTCZH48VE6nvsoHOKlyvxTUtRlfTILBPcQ5G5U3TePQMdzXInQASs0oncbz51NQ3');

sub signed {
  my ( $text, %args ) = @_;
  my $dkim = Mail::DKIM::Signer->new(
    Algorithm => 'rsa-sha256',
    Method => 'relaxed',
    Domain => $args{domain},
    Selector => $args{selector},
    Key => $private_key,
    Headers => $args{headers},
  );
  my $signtext = $text;
  $signtext =~ s/\n/\r\n/g;
  $dkim->PRINT( $signtext );
  $dkim->CLOSE;
  my $signed = $dkim->signature->as_string . "\n" . $text;
  $signed =~ s/\r\n/\n/g;
  return $signed;
};

sub sealed {
  my ( $text, %args ) = @_;
  my $arc = Mail::DKIM::ARC::Signer->new(
    Algorithm => 'rsa-sha256',
    SrvId => $args{srvid},,
    Domain => $args{domain},
    Selector => $args{selector},
    Key => $private_key,
    Chain => 'none',
    Timestamp => time(),
  );
  my $signtext = $text;
  $signtext =~ s/\n/\r\n/g;
  $arc->PRINT( $signtext );
  $arc->CLOSE;
  my $sealed = $arc->as_string . $text;
  return $sealed;
}

my $basedir = q{};

mkdir 't/tmp';
open( STDERR, '>>', $basedir . 't/tmp/misc.err' ) || die "Cannot open errlog [$!]";
#open( STDOUT, '>>', $basedir . 't/tmp/misc.err' ) || die "Cannot open errlog [$!]";

my $tester = Mail::Milter::Authentication::Tester::HandlerTester->new({
    'protocol' => 'smtp',
    'prefix'   => $basedir . 't/config/handler/etc',
    'zonefile' => $basedir . 't/zonefile',
    'handler_config' => {
        'DMARC' => { use_arc => 1 },
        'ARC' => { trusted_domains => [ 'arcsealed.com' ] },
        'DKIM' => {},
        'SPF' => {},
        'BIMI' => {},
    },
});
$tester->snapshot( 'new' );

subtest 'config' => sub {
    my $config = $tester->{ 'authmilter' }->{ 'handler' }->{ 'BIMI' }->default_config();
    is_deeply( $config, {}, 'Returns correct config' );
};

#subtest 'metrics' => sub {
#    is( $tester->{ 'authmilter' }->{ 'handler' }->{ 'AbusixDataFeed' }->can( 'grafana_rows' ), undef, 'Has no grafana rows' );
#};

subtest 'default no dkim' => sub {

    $tester->switch( 'new' );
    $tester->run({
        'connect_ip' => '1.2.3.4',
        'connect_name' => 'mx.example.com',
        'helo' => 'mx.example.com',
        'mailfrom' => 'test@example.com',
        'rcptto' => [ 'test@example.net' ],
        'body' => 'From: test@example.com
To: test@example.net
Subject: This is a test

Testing',
    });

    is( $tester->{authmilter}->{handler}->{BIMI}->{bimi_object}->result->get_authentication_results, 'bimi=pass header.d=example.com selector=default', 'Default BIMI pass' );

    $tester->switch( 'new' );
    $tester->run({
        'connect_ip' => '1.2.3.5',
        'connect_name' => 'mx.example.com',
        'helo' => 'mx.example.com',
        'mailfrom' => 'test@example.com',
        'rcptto' => [ 'test@example.net' ],
        'body' => 'From: test@example.com
To: test@example.net
Subject: This is a test

Testing',
    });

    is( $tester->{authmilter}->{handler}->{BIMI}->{bimi_object}->result->get_authentication_results, 'bimi=skipped (DMARC fail)', 'Default BIMI no auth' );

};

subtest 'unsigned selector' => sub {

    $tester->switch( 'new' );
    $tester->run({
        'connect_ip' => '1.2.3.4',
        'connect_name' => 'mx.example.com',
        'helo' => 'mx.example.com',
        'mailfrom' => 'test@example.com',
        'rcptto' => [ 'test@example.net' ],
        'body' => 'From: test@one.example.com
To: test@example.net
Subject: This is a test
BIMI-Selector: V=BIMI1; s=testsel;

Testing',
    });

    is( $tester->{authmilter}->{handler}->{BIMI}->{bimi_object}->result->get_authentication_results, 'bimi=pass header.d=example.com selector=default', 'Unsigned Selector BIMI pass' );

};

subtest 'domain signed selector' => sub {
    $tester->switch( 'new' );
    $tester->run({
        'connect_ip' => '1.2.3.4',
        'connect_name' => 'mx.example.com',
        'helo' => 'mx.example.com',
        'mailfrom' => 'test@example.com',
        'rcptto' => [ 'test@example.net' ],
        'body' => signed( 'From: test@example.com
To: test@example.net
Subject: This is a test
BIMI-Selector: V=BIMI1; s=testsel;

Testing
',
          domain => 'example.com',
          selector => 'dkim1',
          headers => 'bimi-selector',
        ),
    });

    is( $tester->{authmilter}->{handler}->{BIMI}->{bimi_object}->result->get_authentication_results, 'bimi=pass header.d=example.com selector=testsel', 'Domain Signed Selector BIMI pass' );

};

subtest 'domain signed selector unsigned header' => sub {
    $tester->switch( 'new' );
    $tester->run({
        'connect_ip' => '1.2.3.4',
        'connect_name' => 'mx.example.com',
        'helo' => 'mx.example.com',
        'mailfrom' => 'test@example.com',
        'rcptto' => [ 'test@example.net' ],
        'body' => signed( 'From: test@example.com
To: test@example.net
Subject: This is a test
BIMI-Selector: V=BIMI1; s=testsel;

Testing
',
          domain => 'example.com',
          selector => 'dkim1',
          headers => '',
        ),
    });

    is( $tester->{authmilter}->{handler}->{BIMI}->{bimi_object}->result->get_authentication_results, 'bimi=pass header.d=example.com selector=default', 'Domain Signed Selector BIMI pass' );

};

subtest 'org domain signed selector' => sub {
    $tester->switch( 'new' );
    $tester->run({
        'connect_ip' => '1.2.3.4',
        'connect_name' => 'mx.example.com',
        'helo' => 'mx.example.com',
        'mailfrom' => 'test@example.com',
        'rcptto' => [ 'test@example.net' ],
        'body' => signed( 'From: test@one.example.com
To: test@example.net
Subject: This is a test
BIMI-Selector: V=BIMI1; s=testselone;

Testing
',
          domain => 'example.com',
          selector => 'dkim1',
          headers => 'bimi-selector',
        ),
    });

    is( $tester->{authmilter}->{handler}->{BIMI}->{bimi_object}->result->get_authentication_results, 'bimi=pass header.d=one.example.com selector=testselone', 'Org Signed Selector BIMI pass' );

};

subtest 'third party signed selector' => sub {
    $tester->switch( 'new' );
    $tester->run({
        'connect_ip' => '1.2.3.4',
        'connect_name' => 'mx.example.com',
        'helo' => 'mx.example.com',
        'mailfrom' => 'test@example.com',
        'rcptto' => [ 'test@example.net' ],
        'body' => signed( 'From: test@example.com
To: test@example.net
Subject: This is a test
BIMI-Selector: V=BIMI1; s=testselone;

Testing
',
          domain => 'example.org',
          selector => 'dkim1',
          headers => 'bimi-selector',
        ),
    });

    is( $tester->{authmilter}->{handler}->{BIMI}->{bimi_object}->result->get_authentication_results, 'bimi=pass header.d=example.com selector=default', 'Third Party Signed Selector BIMI pass' );

};

subtest 'domain and selector fallback' => sub {

    $tester->switch( 'new' );
    $tester->run({
        'connect_ip' => '1.2.3.4',
        'connect_name' => 'mx.example.com',
        'helo' => 'mx.example.com',
        'mailfrom' => 'test@example.com',
        'rcptto' => [ 'test@example.net' ],
        'body' => 'From: test@one.example.com
To: test@example.net
Subject: This is a test
BIMI-Selector: V=BIMI1; s=foobar;

Testing',
    });

    is( $tester->{authmilter}->{handler}->{BIMI}->{bimi_object}->result->get_authentication_results, 'bimi=pass header.d=example.com selector=default', 'Fallback BIMI pass' );

};

subtest 'no bimi' => sub {
    $tester->switch( 'new' );
    $tester->run({
        'connect_ip' => '1.2.3.5',
        'connect_name' => 'mx.nobimi.com',
        'helo' => 'mx.nobimi.com',
        'mailfrom' => 'test@nobimi.com',
        'rcptto' => [ 'test@example.net' ],
        'body' => signed( 'From: test@nobimi.com
To: test@example.net
Subject: This is a test

Testing
',
          domain => 'nobimi.com',
          selector => 'dkim1',
          headers => '',
        ),
    });

    is( $tester->{authmilter}->{handler}->{BIMI}->{bimi_object}->result->get_authentication_results, 'bimi=none (Domain is not BIMI enabled)', 'Does Not Have BIMI' );

};

subtest 'arc passed dmarc' => sub {
    $tester->switch( 'new' );
    $tester->run({
        'connect_ip' => '1.2.3.9',
        'connect_name' => 'mx.example.com',
        'helo' => 'mx.example.com',
        'mailfrom' => 'test@example.com',
        'rcptto' => [ 'test@example.net' ],
        'body' => sealed('Authentication-Results: arcsealed.com; dkim=pass header.d=example.com;
BIMI-Selector: v=BIMI1; s=testsel;
From: test@example.com
To: test@example.net
Subject: ArcSeal

Testing
',
    domain => 'arcsealed.com',
    selector => 'dkim1',
    srvid => 'arcsealed.com',
        ),
    });

    is( $tester->{authmilter}->{handler}->{BIMI}->{bimi_object}->result->get_authentication_results, 'bimi=pass header.d=example.com selector=testsel', 'Domain Signed Selector BIMI pass' );

};

done_testing;
