#!/usr/bin/env perl

# In SMTP mode change_header locates the Nth occurrence of a header in the
# stored raw header lines. Handlers count occurrences using the field name as
# cleaned by smtp_command_data (whitespace around the name trimmed), so
# change_header must identify headers the same way. Otherwise a header such as
# "Authentication-Results : ..." is counted (and reported removed) by Sanitize
# but never removed, and the indexes of every later occurrence are shifted
# onto the wrong header.

use strict;
use warnings;
use lib 't';
use Test::More;

use Mail::Milter::Authentication::Protocol::SMTP;

sub protocol_with_headers {
    my ( @headers ) = @_;
    return bless { 'smtp' => { 'headers' => [ @headers ] } },
        'Mail::Milter::Authentication::Protocol::SMTP';
}

subtest 'space before colon is removed' => sub {
    my $protocol = protocol_with_headers(
        'Authentication-Results : mx.example.com; dkim=pass header.d=bank.example',
        'From: test@example.com',
    );
    $protocol->change_header( 'Authentication-Results', 1, q{} );
    is_deeply( $protocol->{'smtp'}->{'headers'}, [ 'From: test@example.com' ], 'Forged header removed' );
};

subtest 'occurrence indexes match handler counting' => sub {
    my $protocol = protocol_with_headers(
        'Authentication-Results : mx.example.com; dkim=pass header.d=bank.example',
        'Authentication-Results: foreign.example.net; spf=pass',
        'From: test@example.com',
    );
    $protocol->change_header( 'Authentication-Results', 1, q{} );
    is_deeply( $protocol->{'smtp'}->{'headers'}, [
        'Authentication-Results: foreign.example.net; spf=pass',
        'From: test@example.com',
    ], 'First occurrence removed, second kept' );
};

subtest 'case insensitive and tab before colon' => sub {
    my $protocol = protocol_with_headers(
        "x-rbl-test\t: listed",
        'X-RBL-Test: also listed',
    );
    $protocol->change_header( 'X-RBL-Test', 2, q{} );
    $protocol->change_header( 'X-RBL-Test', 1, q{} );
    is_deeply( $protocol->{'smtp'}->{'headers'}, [], 'Both occurrences removed' );
};

subtest 'prefix of a longer name is not matched' => sub {
    my $protocol = protocol_with_headers(
        'Authentication-Results-Extra: foo',
        'Authentication-Results: mx.example.com; none',
    );
    $protocol->change_header( 'Authentication-Results', 1, q{} );
    is_deeply( $protocol->{'smtp'}->{'headers'}, [ 'Authentication-Results-Extra: foo' ], 'Only exact name matched' );
};

done_testing();
