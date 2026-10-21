#!/usr/bin/env perl

# IPRev results must follow RFC 8601 2.7.3
#   pass      - forward and reverse lookups agree
#   fail      - forward and reverse lookups completed but do not agree
#   temperror - a lookup failed in a way which may succeed later (SERVFAIL, timeout)
#   permerror - no PTR data for the IP, or the evaluation could not be completed

use strict;
use warnings;
use lib 't';

use Mail::Milter::Authentication::Tester::HandlerTester;
use Mail::Milter::Authentication::Constants qw{ :all };
use Test::More;

my $basedir = q{};

mkdir 't/tmp';
open( STDERR, '>>', $basedir . 't/tmp/misc.err' ) || die "Cannot open errlog [$!]";

# A mock resolver which can return DNS errors for chosen queries, and which
# sets errorstring the way Net::DNS::Resolver does for real lookups.
package TestIPRevResolver {
    use base 'Net::DNS::Resolver::Mock';
    use Net::IP;

    sub set_errors {
        my ( $self, $errors ) = @_;
        $self->{ 'test_errors' } = $errors;
        return;
    }

    sub send { ## no critic
        my ( $self, $name, $type ) = @_;
        $name =~ s/\.$//;
        my $error = $self->{ 'test_errors' }->{ lc "$name $type" };
        if ( $error ) {
            $self->errorstring( $error );
            return;
        }
        if ( lc $type eq 'ptr' && ( my $ip = Net::IP->new( $name ) ) ) {
            $name = $ip->reverse_ip();
        }
        $self->{ 'errorstring' } = q{};
        my $packet = $self->SUPER::send( $name, $type );
        $self->errorstring( 'NOERROR' );
        return $packet;
    }
}
package main;

my $zonedata = join( "\n",
    '1.2.0.192.in-addr.arpa. 3600 IN PTR good.example.com.',
    'good.example.com. 3600 IN A 192.0.2.1',
    '2.2.0.192.in-addr.arpa. 3600 IN PTR mismatch.example.com.',
    'mismatch.example.com. 3600 IN A 198.51.100.1',
    '3.2.0.192.in-addr.arpa. 3600 IN PTR fwdtimeout.example.com.',
    '4.2.0.192.in-addr.arpa. 3600 IN PTR noaddress.example.com.',
    '5.2.0.192.in-addr.arpa. 3600 IN PTR a.multi.example.com.',
    '5.2.0.192.in-addr.arpa. 3600 IN PTR b.multi.example.com.',
    'b.multi.example.com. 3600 IN A 192.0.2.5',
    ( map { "6.2.0.192.in-addr.arpa. 3600 IN PTR host$_.limit.example.com." } ( 1 .. 10 ) ),
    '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa. 3600 IN PTR v6.example.com.',
    'v6.example.com. 3600 IN A 192.0.2.99',
    '2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa. 3600 IN PTR v6mismatch.example.com.',
    'v6mismatch.example.com. 3600 IN AAAA 2001:db8::99',
    q{},
);

sub iprev_for {
    my ( $ip, $errors ) = @_;

    my $tester = Mail::Milter::Authentication::Tester::HandlerTester->new({
        'prefix'   => $basedir . 't/config/handler/etc',
        'zonedata' => '',
        'handler_config' => {
            'IPRev' => {},
            'LocalIP' => {},
            'TrustedIP' => {},
        },
    });

    my $resolver = TestIPRevResolver->new();
    $resolver->zonefile_parse( $zonedata );
    $resolver->set_errors( { map { lc $_ => $errors->{ $_ } } keys %{ $errors // {} } } );
    $Mail::Milter::Authentication::Handler::TestResolver = $resolver;

    $tester->run({
        'connect_ip'   => $ip,
        'connect_name' => 'mx.example.net',
        'helo'         => 'mx.example.net',
        'mailfrom'     => 'sender@example.net',
        'rcptto'       => [ 'test@example.net' ],
        'body'         => "From: sender\@example.net\nTo: test\@example.net\nSubject: iprev\n\nTesting",
    });

    my $entry = $tester->get_authresults_header()->search({ 'key' => 'iprev' })->children()->[0];
    my $result = $entry->value();
    my ( $comment ) = map { $_->value() } grep { $_->isa( 'Mail::AuthenticationResults::Header::Comment' ) } @{ $entry->children() };
    $tester->close();
    return ( $result, $comment // q{} );
}

subtest 'pass' => sub {
    my ( $result, $comment ) = iprev_for( '192.0.2.1' );
    is( $result, 'pass', 'forward and reverse agree' );
    is( $comment, 'good.example.com', 'comment names the verified host' );
};

subtest 'fail on forward mismatch' => sub {
    my ( $result ) = iprev_for( '192.0.2.2' );
    is( $result, 'fail', 'forward lookup does not match' );
};

subtest 'fail when forward lookup has no address' => sub {
    my ( $result ) = iprev_for( '192.0.2.4' );
    is( $result, 'fail', 'forward lookup returned nothing' );
};

subtest 'fail when forward lookup is NXDOMAIN' => sub {
    my ( $result ) = iprev_for( '192.0.2.4', { 'noaddress.example.com A' => 'NXDOMAIN', 'noaddress.example.com AAAA' => 'NXDOMAIN' } );
    is( $result, 'fail', 'NXDOMAIN on the forward lookup is authoritative' );
};

subtest 'PTR transient errors are temperror' => sub {
    for my $error ( 'query timed out', 'SERVFAIL' ) {
        my ( $result, $comment ) = iprev_for( '192.0.2.10', { '192.0.2.10 PTR' => $error } );
        is( $result, 'temperror', "PTR $error" );
        like( $comment, qr/^Error \Q$error\E looking up 192\.0\.2\.10 PTR,NOT FOUND$/, "PTR $error comment" );
    }
};

subtest 'no PTR data is permerror' => sub {
    my ( $result, $comment ) = iprev_for( '192.0.2.10', { '192.0.2.10 PTR' => 'NXDOMAIN' } );
    is( $result, 'permerror', 'PTR NXDOMAIN' );
    like( $comment, qr/^Error NXDOMAIN looking up 192\.0\.2\.10 PTR,NOT FOUND$/, 'PTR NXDOMAIN comment' );

    ( $result ) = iprev_for( '192.0.2.11' );
    is( $result, 'permerror', 'PTR NOERROR with no answers' );
};

subtest 'forward transient errors are temperror' => sub {
    for my $error ( 'query timed out', 'SERVFAIL' ) {
        my ( $result, $comment ) = iprev_for( '192.0.2.3', { 'fwdtimeout.example.com A' => $error } );
        is( $result, 'temperror', "A $error" );
        like( $comment, qr/,Error \Q$error\E looking up fwdtimeout\.example\.com\. A,/, "A $error comment" );
        unlike( $comment, qr/Error Error/, 'comment is not double prefixed' );
    }
};

subtest 'transient error on the other address family is still fail' => sub {
    my ( $result, $comment ) = iprev_for( '192.0.2.4', { 'noaddress.example.com AAAA' => 'SERVFAIL' } );
    is( $result, 'fail', 'AAAA SERVFAIL cannot change the result for an IPv4 client' );
    like( $comment, qr/Error SERVFAIL looking up noaddress\.example\.com\. AAAA/, 'error is still noted' );
};

subtest 'transient error on one host does not prevent a pass on another' => sub {
    my ( $result, $comment ) = iprev_for( '192.0.2.5', { 'a.multi.example.com A' => 'query timed out' } );
    is( $result, 'pass', 'second host matched' );
    is( $comment, 'b.multi.example.com', 'comment names the verified host' );
};

subtest 'lookup limit reached is permerror' => sub {
    my ( $result, $comment ) = iprev_for( '192.0.2.6' );
    is( $result, 'permerror', 'too many lookups' );
    my @limit_errors = $comment =~ /Lookup limit reached/g;
    is( scalar @limit_errors, 1, 'comment notes the lookup limit once' );
};

subtest 'IPv6' => sub {
    my ( $result, $comment ) = iprev_for( '2001:db8::1', { 'v6.example.com AAAA' => 'SERVFAIL' } );
    is( $result, 'temperror', 'AAAA SERVFAIL for an IPv6 client' );
    like( $comment, qr/Error SERVFAIL looking up v6\.example\.com\. AAAA/, 'comment notes why the host did not verify' );

    ( $result ) = iprev_for( '2001:db8::2', { 'v6mismatch.example.com A' => 'SERVFAIL' } );
    is( $result, 'fail', 'A SERVFAIL cannot change the result for an IPv6 client' );
};

done_testing();
