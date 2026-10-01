#!/usr/bin/env perl

# arcseal_strip_aar_comments: the ARC-Authentication-Results we seal must carry
# our results WITHOUT RFC 8601 comments, while the Authentication-Results header
# we deliver keeps them.
#
# Why: Microsoft 365 returns arc=fail (35) for an otherwise valid chain when an
# AAR result ends with a comment after a property value, e.g.
# "iprev=pass smtp.remote-ip=192.0.2.1 (host.example.net)". Reproduced against
# Exchange Online with seals differing only in that comment.

use strict;
use warnings;
use lib 't';

use Mail::Milter::Authentication::Tester::HandlerTester;
use Mail::Milter::Authentication::Constants qw{ :all };
use Test::More;

my $basedir = q{};

mkdir 't/tmp';
open( STDERR, '>>', $basedir . 't/tmp/misc.err' ) || die "Cannot open errlog [$!]";

# Same throwaway test key used by t/04-unit-handler-bimi.t
my $private_key = 'MIICXQIBAAKBgQDErv0qLGKJ933gdhx2MUBqb/XhTloMjJhH0kdQsxkVuhRFzINgDzMGOq83xEwNEk4jC/J+E49fNQ+TSVymq+XGvrkeW7/7llEOTFosY6OGlwdeUZyyUCEM6SIYIBeHuIQn4Ohwhq7P0nZFfXNAG7Wrlxx1O+E881wTRhFOBxAjdQIDAQABAoGAP4cF3olXipiV39pGdyaRV8+x64QTMdp3lTsmLbqrb4ka4zCbfntqT6jEz45nwhEXi9pgCLjopifNUBVyB6OeI3KdaGQzfYVBCgTyvwMp+68rTnYtDeByrhXm+yccMpvFNA1BHxYiByucCGy8cc8jTfAvSKPTRpJ5TZM4S59ZkEECQQDkHOJ/Uzt5mm5Yq34HF78FzkY8w8TKRhVcsI0ZWS+Y1EBJTKZOoOS08d6Zetk0TNd52e6Gb0zxt325l5msKH3TAkEA3Lp67CXopC43Y8H7sJwMJiIYpN2F1lgt0XYsnyHhBnANS4Ap6d32j3MhtIEHwWv1vbRkCOSOm0h6Tq2Tj6rklwJBAOHQylN7JLxbqXLzyZ3h3wMzUQqkTjJjMJCCYhu+00R6kW0+iL/7vIx3h4HuQAjrLL/+gobotYXvvHE2ZzUrHGsCQQDAvmZQh9naZDEh/2ZVFi7VrbhvXrFcNqvr2JGmc+MXyAkUANqYyaZgJV0tTe8Dy85O1ZL04QBWQLfstE3CiqwJAkBJz/qjnUlfbyuTU1PHaWbkcTCZH48VE6nvsoHOKlyvxTUtRlfTILBPcQ5G5U3TePQMdzXInQASs0oncbz51NQ3';

sub make_tester {
    my (%args) = @_;
    my $arc_config = {
        'arcseal_domain'   => 'example.com',
        'arcseal_selector' => 'dkim1',
        'arcseal_key'      => $private_key,
    };
    $arc_config->{'arcseal_strip_aar_comments'} = $args{'strip'} if defined $args{'strip'};
    $arc_config->{'arcseal_headers'} = $args{'arcseal_headers'} if $args{'arcseal_headers'};

    my $tester = Mail::Milter::Authentication::Tester::HandlerTester->new({
        'prefix'         => $basedir . 't/config/handler/etc',
        'zonedata'       => '',
        'handler_config' => { 'ARC' => $arc_config, 'LocalIP' => {}, 'TrustedIP' => { 'trusted_ip_list' => [] }, 'IPRev' => {} },
    });
    return $tester;
}

sub run_message {
    my ( $tester ) = @_;
    $tester->run({
        'connect_ip'   => '1.2.3.4',
        'connect_name' => 'mx.example.net',
        'helo'         => 'mx.example.net',
        'mailfrom'     => 'sender@example.net',
        'rcptto'       => [ 'test@example.net' ],
        'body'         => "From: sender\@example.net\nTo: test\@example.net\nSubject: aar comments\n\nTesting",
    });
    return;
}

sub get_added_headers {
    my ( $tester, $want ) = @_;
    my $pre = $tester->handler()->{'pre_headers'} // [];
    return map { $_->{'value'} } grep { lc $_->{'field'} eq lc $want } @{ $pre };
}

# Rebuild the delivered message (our added headers on top, then the original)
# and verify the ARC chain with Mail::DKIM, using a mock DNS answer for the
# throwaway key, so "stripped" is proven to still produce a VALID seal.
sub arc_verify_result {
    my ( $tester ) = @_;
    require Mail::DKIM::ARC::Verifier;
    require Mail::DKIM::DNS;
    require Net::DNS::Resolver::Mock;
    require Crypt::OpenSSL::RSA;

    my $pem = "-----BEGIN RSA PRIVATE KEY-----\n"
        . join( "\n", unpack( '(A64)*', $private_key ) )
        . "\n-----END RSA PRIVATE KEY-----\n";
    my $pub = Crypt::OpenSSL::RSA->new_private_key( $pem )->get_public_key_x509_string();
    $pub =~ s/-----[^-]+-----//g;
    $pub =~ s/\s+//g;
    my $resolver = Net::DNS::Resolver::Mock->new();
    $resolver->zonefile_parse( qq{dkim1._domainkey.example.com. 3600 IN TXT "v=DKIM1; k=rsa; p=$pub"\n} );
    Mail::DKIM::DNS::resolver( $resolver );

    my @added = map { "$_->{field}: $_->{value}" } @{ $tester->handler()->{'pre_headers'} // [] };
    my $msg = join( "\n", reverse( @added ),
        'From: sender@example.net', 'To: test@example.net', 'Subject: aar comments', '', 'Testing' );
    $msg =~ s/\015?\012/\015\012/g;

    my $arc = Mail::DKIM::ARC::Verifier->new();
    $arc->PRINT( $msg );
    $arc->CLOSE();
    return $arc->result();
}

subtest 'default: AAR carries comments exactly as before' => sub {
    my $tester = make_tester();
    run_message( $tester );
    my ($aar) = get_added_headers( $tester, 'ARC-Authentication-Results' );
    ok( defined $aar, 'AAR generated' );
    like( $aar, qr/\(NOT FOUND\)/, 'iprev comment is sealed when the option is off' );
    like( $aar, qr/\(no signatures found\)/, 'arc comment is sealed when the option is off' );
    $tester->close();
};

subtest 'strip on: AAR has no comments, delivered A-R keeps them' => sub {
    my $tester = make_tester( 'strip' => 1 );
    run_message( $tester );
    my ($aar) = get_added_headers( $tester, 'ARC-Authentication-Results' );
    my ($ar)  = get_added_headers( $tester, 'Authentication-Results' );
    ok( defined $aar, 'AAR generated' );
    ok( defined $ar,  'A-R generated' );
    unlike( $aar, qr/\(/, 'no comment of any kind in the sealed AAR' );
    like( $aar, qr/iprev=fail smtp\.remote-ip=1\.2\.3\.4\s*$/m,
        'iprev result and its property survive, only the trailing comment is gone' );
    like( $aar, qr/arc=none/, 'arc result survives' );
    like( $ar, qr/\(NOT FOUND\)/, 'delivered A-R still carries the iprev comment' );
    like( $ar, qr/\(no signatures found\)/, 'delivered A-R still carries the arc comment' );
    ok( defined( (get_added_headers( $tester, 'ARC-Seal' ))[0] ), 'ARC-Seal generated' );
    ok( defined( (get_added_headers( $tester, 'ARC-Message-Signature' ))[0] ), 'AMS generated' );
    is( arc_verify_result( $tester ), 'pass', 'the stripped seal verifies (Mail::DKIM::ARC::Verifier)' );
    $tester->close();
};

subtest 'strip on, but A-R is AMS-signed: nothing is stripped' => sub {
    my $tester = make_tester( 'strip' => 1, 'arcseal_headers' => 'Authentication-Results' );
    run_message( $tester );
    my ($aar) = get_added_headers( $tester, 'ARC-Authentication-Results' );
    ok( defined $aar, 'AAR generated' );
    like( $aar, qr/\(NOT FOUND\)/,
        'comments kept: a stripped copy would break the AMS over the delivered A-R' );
    ok( defined( (get_added_headers( $tester, 'ARC-Message-Signature' ))[0] ), 'AMS generated' );
    $tester->close();
};

subtest 'default seal also verifies (control for the verifier helper)' => sub {
    my $tester = make_tester();
    run_message( $tester );
    is( arc_verify_result( $tester ), 'pass', 'unstripped seal verifies too' );
    $tester->close();
};

subtest 'strip on: parse errors pass through, timeouts are re-thrown' => sub {
    my $tester = make_tester( 'strip' => 1 );
    run_message( $tester );
    my $arc    = $tester->handler()->get_handler( 'ARC' );
    my $config = $arc->handler_config();
    my $text   = "Authentication-Results: example.com; iprev=pass (host.example.net)\015\012";

    no warnings 'redefine';
    local *Mail::AuthenticationResults::Parser::parse = sub { die "parse failed\n" };
    my $got = eval { $arc->_aar_seal_copy( $config, $text ) };
    is( $@, q{}, 'ordinary parse error is not re-thrown' );
    is( $got, $text, 'unparseable A-R is passed through unchanged' );

    my $timeout = Mail::Milter::Authentication::Exception->new({ 'Type' => 'Timeout', 'Text' => 'test timeout' });
    local *Mail::AuthenticationResults::Parser::parse = sub { die $timeout };
    eval { $arc->_aar_seal_copy( $config, $text ) };
    is( $@, $timeout, 'timeout raised inside the strip reaches the caller' );
    $tester->close();
};

done_testing();
