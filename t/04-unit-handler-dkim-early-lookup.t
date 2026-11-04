#!/usr/bin/env perl

# DNS lookups for DKIM keys are started early, while headers are received,
# to warm the resolver cache. These are limited per message, duplicates are
# skipped, and ADSP is only looked up when check_adsp is enabled.

use strict;
use warnings;
use lib 't';

use Mail::Milter::Authentication::Tester::HandlerTester;
use Test::More;

my $basedir = q{};

mkdir 't/tmp';
open( STDERR, '>>', $basedir . 't/tmp/misc.err' ) || die "Cannot open errlog [$!]";

package RecordingResolver {
    sub new { return bless { 'lookups' => [] }, shift }
    sub bgsend {
        my ( $self, $lookup, $type ) = @_;
        push $self->{'lookups'}->@*, "$lookup $type";
        return;
    }
}

sub early_lookups {
    my ( $handler_name, $handler_config, @headers ) = @_;
    my $tester = Mail::Milter::Authentication::Tester::HandlerTester->new({
        'prefix'         => $basedir . 't/config/handler/etc',
        'zonedata'       => '',
        'handler_config' => { $handler_name => $handler_config },
    });
    my $handler = $tester->{'authmilter'}->{'handler'}->{ $handler_name };
    my $resolver = RecordingResolver->new();
    $handler->envfrom_callback( 'sender@example.com' );
    $handler->set_object( 'resolver', $resolver, 1 );
    foreach my $header ( @headers ) {
        my ( $key, $value ) = @$header;
        $handler->header_callback( $key, $value, "$key: $value" );
    }
    $handler->close_callback();
    return $resolver->{'lookups'};
}

sub signatures {
    my ( $key, $count ) = @_;
    return map { [ $key, "v=1; a=rsa-sha256; d=d$_.example.com; s=s$_; h=from; bh=x; b=x;" ] } ( 1 .. $count );
}

subtest 'DKIM with ADSP' => sub {
    my $lookups = early_lookups( 'DKIM', { 'check_adsp' => 1 }, signatures( 'DKIM-Signature', 2 ) );
    is_deeply( $lookups, [
        's1._domainkey.d1.example.com TXT',
        '_adsp._domainkey.d1.example.com TXT',
        's2._domainkey.d2.example.com TXT',
        '_adsp._domainkey.d2.example.com TXT',
    ], 'key and ADSP lookups' );
};

subtest 'DKIM without ADSP' => sub {
    my $lookups = early_lookups( 'DKIM', { 'check_adsp' => 0 }, signatures( 'DKIM-Signature', 2 ) );
    is_deeply( $lookups, [
        's1._domainkey.d1.example.com TXT',
        's2._domainkey.d2.example.com TXT',
    ], 'key lookups only' );
};

subtest 'DKIM default limit' => sub {
    my $lookups = early_lookups( 'DKIM', { 'check_adsp' => 0 }, signatures( 'DKIM-Signature', 20 ) );
    is( scalar @$lookups, 10, 'limited to 10 lookups' );
    is( $lookups->[-1], 's10._domainkey.d10.example.com TXT', 'first signatures are looked up' );
    $lookups = early_lookups( 'DKIM', { 'check_adsp' => 1 }, signatures( 'DKIM-Signature', 20 ) );
    is( scalar @$lookups, 10, 'limited to 10 lookups with ADSP' );
};

subtest 'DKIM configured limit' => sub {
    my $lookups = early_lookups( 'DKIM', { 'check_adsp' => 0, 'early_lookup_limit' => 3 }, signatures( 'DKIM-Signature', 20 ) );
    is( scalar @$lookups, 3, 'limited to 3 lookups' );
    $lookups = early_lookups( 'DKIM', { 'check_adsp' => 1, 'early_lookup_limit' => 0 }, signatures( 'DKIM-Signature', 20 ) );
    is( scalar @$lookups, 0, 'disabled with 0' );
};

subtest 'DKIM duplicates' => sub {
    my @headers = ( signatures( 'DKIM-Signature', 1 ) ) x 5;
    push @headers, [ 'DKIM-Signature', 'v=1; a=rsa-sha256; d=D1.Example.com; s=S1; h=from; bh=x; b=x;' ];
    push @headers, [ 'DKIM-Signature', 'v=1; a=rsa-sha256; d=d1.example.com; s=other; h=from; bh=x; b=x;' ];
    my $lookups = early_lookups( 'DKIM', { 'check_adsp' => 1 }, @headers );
    is_deeply( $lookups, [
        's1._domainkey.d1.example.com TXT',
        '_adsp._domainkey.d1.example.com TXT',
        'other._domainkey.d1.example.com TXT',
    ], 'each lookup made once' );
};

subtest 'XGoogleDKIM' => sub {
    my $lookups = early_lookups( 'XGoogleDKIM', {}, signatures( 'X-Google-DKIM-Signature', 20 ) );
    is( scalar @$lookups, 10, 'limited to 10 lookups' );
    is( $lookups->[0], 's1._domainkey.d1.example.com TXT', 'key lookup' );
    $lookups = early_lookups( 'XGoogleDKIM', { 'early_lookup_limit' => 2 }, ( signatures( 'X-Google-DKIM-Signature', 1 ) ) x 3, signatures( 'X-Google-DKIM-Signature', 5 ) );
    is_deeply( $lookups, [
        's1._domainkey.d1.example.com TXT',
        's2._domainkey.d2.example.com TXT',
    ], 'duplicates skipped and configured limit applied' );
};

done_testing();
