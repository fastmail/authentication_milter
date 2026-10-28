#!/usr/bin/env perl

# Sanitize removes received Authentication-Results headers which claim to be
# from us. A fully qualified authserv-id with a trailing dot names the same
# host, so "mx1.example.com." must be removed just as "mx1.example.com" is,
# otherwise a forged header survives sanitisation.

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
    'zonedata'       => '',
    'handler_config' => {
        'Sanitize' => {
            'hosts_to_remove' => [ 'remove.example.com', 'dotted.example.org.' ],
            'remove_headers'  => 'yes',
        },
    },
});
my $sanitize = $tester->{'authmilter'}->{'handler'}->{'Sanitize'};

my $hostname    = $sanitize->get_my_hostname();
my $authserv_id = $sanitize->get_my_authserv_id();
my ( $parent )  = $hostname =~ /^[^\.]+\.(.*)/;

my @mine = (
    $authserv_id,
    "$authserv_id.",
    uc( $authserv_id ) . '.',
    "$authserv_id..",
    'remove.example.com',
    'remove.example.com.',
    'mx.remove.example.com.',
    'dotted.example.org',
    'dotted.example.org.',
);
push @mine, ( $parent, "$parent.", "foo.$parent." ) if defined $parent;

foreach my $id ( @mine ) {
    ok( $sanitize->is_hostname_mine( $id ), "$id is ours" );
}

foreach my $id ( 'evil.example.net', 'evil.example.net.', 'notremove.example.com.' ) {
    ok( ! $sanitize->is_hostname_mine( $id ), "$id is not ours" );
}

$tester->close();

done_testing();
