#!/usr/bin/env perl

# The milter client must fail when the milter closes the connection or the
# socket errors, rather than retrying forever, and must not return a short
# read as a complete packet.

use strict;
use warnings;
use lib 't';

use Test::More;

use Mail::Milter::Authentication::Net::Milter;

# A socket which returns the given results in turn, a string is data read
package TestSocket {
    sub new { my ( $class, @results ) = @_; return bless { 'results' => [ @results ], 'sent' => q{} }, $class }
    sub sysread {
        my ( $self, undef, $length, $offset ) = @_;
        my $result = shift $self->{'results'}->@*;
        return $result if ! defined $result || $result =~ /^\d+$/;
        substr( $_[1], $offset ) = $result;
        return length $result;
    }
    sub send {
        my ( $self, $data ) = @_;
        my $result = shift $self->{'results'}->@*;
        return $result if ! defined $result || $result < 0;
        $self->{'sent'} .= substr( $data, 0, $result );
        return $result;
    }
}

sub milter_with {
    my $milter = Mail::Milter::Authentication::Net::Milter->new();
    $milter->{'socket'} = TestSocket->new( @_ );
    return $milter;
}

# Run with a guard, so a regression fails rather than hanging
sub guarded {
    my ( $sub ) = @_;
    my $result = eval {
        local $SIG{'ALRM'} = sub { die "Timeout\n" };
        alarm( 5 );
        my $result = $sub->();
        alarm( 0 );
        $result;
    };
    alarm( 0 );
    return ( $result, $@ );
}

subtest 'receive' => sub {
    my ( $result, $error ) = guarded( sub { milter_with( 'ab', 'cd' )->_io_recv( 4 ) } );
    is( $result, 'abcd', 'Read in parts is joined' );
    is( $error, q{}, 'No error' );

    ( $result, $error ) = guarded( sub { milter_with( 0 )->_io_recv( 4 ) } );
    like( $error, qr{^Unexpected EOF while reading from the socket}, 'EOF is an error' );

    ( $result, $error ) = guarded( sub { milter_with( 'ab', 0 )->_io_recv( 4 ) } );
    like( $error, qr{^Unexpected EOF while reading from the socket}, 'EOF after a short read is an error' );

    ( $result, $error ) = guarded( sub { milter_with( undef )->_io_recv( 4 ) } );
    like( $error, qr{^Error while reading from the socket}, 'Read error is an error' );
};

subtest 'receive packet' => sub {
    my ( $result, $error ) = guarded( sub { milter_with( pack( 'N', 3 ), 'h', 'x' , 0 )->_receive() } );
    like( $error, qr{^Unexpected EOF while reading from the socket}, 'Truncated packet is an error' );
};

subtest 'send' => sub {
    my $milter = milter_with( 2, 2 );
    my ( $result, $error ) = guarded( sub { $milter->_io_send( 'abcd' ) } );
    is( $error, q{}, 'No error' );
    is( $milter->{'socket'}->{'sent'}, 'abcd', 'Write in parts sends all data' );

    ( $result, $error ) = guarded( sub { milter_with( 0 )->_io_send( 'abcd' ) } );
    like( $error, qr{^Unable to write to the socket}, 'No progress is an error' );

    ( $result, $error ) = guarded( sub { milter_with( 2, undef )->_io_send( 'abcd' ) } );
    like( $error, qr{^Error while writing to the socket}, 'Write error is an error' );
};

done_testing();
