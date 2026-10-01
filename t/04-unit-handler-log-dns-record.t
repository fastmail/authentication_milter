#!/usr/bin/env perl

use strict;
use warnings;
use lib 't';

use Crypt::OpenSSL::RSA;
use Mail::DKIM::Signer;
use Mail::DKIM::TextWrap;
use Mail::DKIM::PrivateKey;
use Mail::Milter::Authentication::Tester::HandlerTester;
use Mail::Milter::Authentication::Constants qw{ :all };
use Test::More;

my $basedir = q{};

mkdir 't/tmp';
open( STDERR, '>>', $basedir . 't/tmp/misc.err' ) || die "Cannot open errlog [$!]";
#open( STDOUT, '>>', $basedir . 't/tmp/misc.err' ) || die "Cannot open errlog [$!]";

# DKIM key (generated once for all DKIM subtests).
# Key stripping follows the pattern used in t/04-unit-handler-dkim.t
my $dkim_domain   = 'example.com';
my $dkim_selector = 'logdnstest';

my $RSA = Crypt::OpenSSL::RSA->generate_key(2048);
my $DKIMPrivate = $RSA->get_private_key_string();
my $DKIMPublic  = $RSA->get_public_key_x509_string();
my @DKIMPublic  = split( m/\n/m, $DKIMPublic );
@DKIMPublic     = @DKIMPublic[ 1 .. ( $#DKIMPublic - 1 ) ];
$DKIMPublic     = join( q{}, @DKIMPublic );
my @DKIMPrivate = split( m/\n/m, $DKIMPrivate );
@DKIMPrivate    = @DKIMPrivate[ 1 .. ( $#DKIMPrivate - 1 ) ];
$DKIMPrivate    = join( q{}, @DKIMPrivate );
my $PrivateKey  = Mail::DKIM::PrivateKey->load( 'Data' => $DKIMPrivate );

my $dkim_txt_record = "v=DKIM1; k=rsa; p=$DKIMPublic";
my $ZoneData = qq{$dkim_selector._domainkey.$dkim_domain. 2600 IN TXT "$dkim_txt_record"\n};

sub sign_email {
    my ( $body, $domain, $selector, $key ) = @_;
    my $dkim = Mail::DKIM::Signer->new(
        Algorithm => 'rsa-sha256',
        Method    => 'relaxed',
        Domain    => $domain,
        Selector  => $selector,
        Key       => $key,
    );
    $dkim->PRINT($body);
    $dkim->CLOSE();
    my $sig = $dkim->signature()->as_string();
    return $sig . "\n" . $body;
}

my $base_mail   = "From: test\@$dkim_domain\nTo: test\@$dkim_domain\nSubject: Test\n\nThis is a test";
my $signed_mail = sign_email( $base_mail, $dkim_domain, $dkim_selector, $PrivateKey );

# goestheweasel.com has real SPF and DMARC records in t/zonefile.
my $spf_dmarc_params = {
    'connect_ip'   => '106.187.51.197',
    'connect_name' => 'mx.goestheweasel.com',
    'helo'         => 'mx.goestheweasel.com',
    'mailfrom'     => 'test@goestheweasel.com',
    'rcptto'       => [ 'test@goestheweasel.com' ],
    'body'         => "From: test\@goestheweasel.com\nTo: test\@goestheweasel.com\nSubject: Test\n\nThis is a test",
};

my $dkim_params = {
    'connect_ip'   => '1.2.3.4',
    'connect_name' => 'mx.example.com',
    'helo'         => 'mx.example.com',
    'mailfrom'     => "test\@$dkim_domain",
    'rcptto'       => [ "test\@$dkim_domain" ],
    'body'         => $signed_mail,
};

# Extract the x-dns-record comment value from an Authentication-Results entry.
# Returns the record content (after "x-dns-record="), or empty string if absent.
sub get_dns_record_comment {
    my ( $tester, $entry_key ) = @_;
    my $entries = $tester->get_authresults_header()->search({ 'key' => $entry_key });
    return q{} unless scalar @{ $entries->children() };
    my $entry = $entries->children()->[0];
    for my $child ( @{ $entry->children() } ) {
        next unless $child->isa('Mail::AuthenticationResults::Header::Comment');
        my $val = $child->value();
        return $1 if $val =~ /^x-dns-record=(.+)/;
    }
    return q{};
}

# Each subtest creates its own HandlerTester so the global DNS resolver
# (Mail::Milter::Authentication::Handler::TestResolver) is always initialised
# with the zone data appropriate for that handler.

subtest 'SPF: log_dns_record enabled' => sub {
    my $t = Mail::Milter::Authentication::Tester::HandlerTester->new({
        'protocol'       => 'milter',
        'prefix'         => $basedir . 't/config/handler/etc',
        'zonefile'       => $basedir . 't/zonefile',
        'handler_config' => { 'SPF' => { 'log_dns_record' => 1 }, 'DKIM' => {}, 'DMARC' => {} },
    });
    $t->run($spf_dmarc_params);
    my $rec = get_dns_record_comment($t, 'spf');
    ok( length($rec) > 0, 'x-dns-record comment present in spf entry' );
    like( $rec, qr/^v=spf1/, 'x-dns-record starts with v=spf1' );
};

subtest 'SPF: log_dns_record disabled' => sub {
    my $t = Mail::Milter::Authentication::Tester::HandlerTester->new({
        'protocol'       => 'milter',
        'prefix'         => $basedir . 't/config/handler/etc',
        'zonefile'       => $basedir . 't/zonefile',
        'handler_config' => { 'SPF' => {}, 'DKIM' => {}, 'DMARC' => {} },
    });
    $t->run($spf_dmarc_params);
    is( get_dns_record_comment($t, 'spf'), q{}, 'no x-dns-record comment in spf when disabled' );
};

subtest 'DMARC: log_dns_record enabled' => sub {
    my $t = Mail::Milter::Authentication::Tester::HandlerTester->new({
        'protocol'       => 'milter',
        'prefix'         => $basedir . 't/config/handler/etc',
        'zonefile'       => $basedir . 't/zonefile',
        'handler_config' => { 'SPF' => {}, 'DKIM' => {}, 'DMARC' => { 'log_dns_record' => 1 } },
    });
    $t->run($spf_dmarc_params);
    my $rec = get_dns_record_comment($t, 'dmarc');
    ok( length($rec) > 0, 'x-dns-record comment present in dmarc entry' );
    like( $rec, qr/^v=DMARC1/, 'x-dns-record starts with v=DMARC1' );
};

subtest 'DMARC: log_dns_record disabled' => sub {
    my $t = Mail::Milter::Authentication::Tester::HandlerTester->new({
        'protocol'       => 'milter',
        'prefix'         => $basedir . 't/config/handler/etc',
        'zonefile'       => $basedir . 't/zonefile',
        'handler_config' => { 'SPF' => {}, 'DKIM' => {}, 'DMARC' => {} },
    });
    $t->run($spf_dmarc_params);
    is( get_dns_record_comment($t, 'dmarc'), q{}, 'no x-dns-record comment in dmarc when disabled' );
};

subtest 'DKIM: log_dns_record enabled' => sub {
    my $t = Mail::Milter::Authentication::Tester::HandlerTester->new({
        'protocol'       => 'milter',
        'prefix'         => $basedir . 't/config/handler/etc',
        'zonedata'       => $ZoneData,
        'handler_config' => { 'DKIM' => { 'log_dns_record' => 1 } },
    });
    $t->run($dkim_params);
    my $rec = get_dns_record_comment($t, 'dkim');
    ok( length($rec) > 0, 'x-dns-record comment present in dkim entry' );
    like( $rec, qr/^v=DKIM1/, 'x-dns-record starts with v=DKIM1' );
    like( $rec, qr/k=rsa/,    'x-dns-record contains k=rsa' );
};

subtest 'DKIM: log_dns_record disabled' => sub {
    my $t = Mail::Milter::Authentication::Tester::HandlerTester->new({
        'protocol'       => 'milter',
        'prefix'         => $basedir . 't/config/handler/etc',
        'zonedata'       => $ZoneData,
        'handler_config' => { 'DKIM' => {} },
    });
    $t->run($dkim_params);
    is( get_dns_record_comment($t, 'dkim'), q{}, 'no x-dns-record comment in dkim when disabled' );
};

done_testing();
