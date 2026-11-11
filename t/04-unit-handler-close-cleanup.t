#!/usr/bin/env perl

# Handlers must remove all per message data in their close callback, any key
# left behind causes the child to exit after the connection closes.

use strict;
use warnings;
use lib 't';

use Mail::Milter::Authentication::Tester::HandlerTester;
use Test::More;

my $basedir = q{};

mkdir 't/tmp';
open( STDERR, '>>', $basedir . 't/tmp/misc.err' ) || die "Cannot open errlog [$!]";

my $tester = Mail::Milter::Authentication::Tester::HandlerTester->new({
    'prefix'         => $basedir . 't/config/handler/etc',
    'zonefile'       => $basedir . 't/zonefile',
    'handler_config' => {
        'AddID'       => {},
        'AlignedFrom' => {},
        'ARC'         => { 'trusted_domains' => [ 'forwarder.example' ] },
        'Auth'        => {},
        'DKIM'        => {},
        'DMARC'       => {},
        'IPRev'       => {},
        'LocalIP'     => {},
        'PTR'         => {},
        'ReturnOK'    => {},
        'Sanitize'    => {},
        'SenderID'    => {},
        'Size'        => {},
        'SPF'         => {},
        'TLS'         => {},
        'TrustedIP'   => {},
        'XGoogleDKIM' => {},
    },
});

eval {
    $tester->run({
        'connect_ip'   => '1.2.3.4',
        'connect_name' => 'mx.example.com',
        'helo'         => 'mx.example.com',
        'mailfrom'     => 'test@goestheweasel.com',
        'rcptto'       => [ 'test@example.com' ],
        'body'         => join( "\n",
            'ARC-Authentication-Results: i=1; forwarder.example; spf=pass smtp.mailfrom=goestheweasel.com',
            'Authentication-Results: forwarder.example; spf=pass smtp.mailfrom=goestheweasel.com',
            'DKIM-Signature: v=1; a=rsa-sha256; d=goestheweasel.com; s=test; h=from; bh=x; b=x',
            'From: test@goestheweasel.com',
            'To: test@example.com',
            'Subject: Test',
            '',
            'This is a test',
        ) . "\n",
    });
};
$tester->close();

my $top = $tester->handler();
ok( ! $top->{'exit_on_close'}, 'No handler left data behind on close' )
    or diag $top->{'exit_on_close_error'};

done_testing();
