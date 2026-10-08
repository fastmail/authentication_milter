#!/usr/bin/env perl

use strict;
use warnings;
use lib 't';

use English;
use File::Slurp qw{ write_file };
use File::Temp qw{ tempdir };
use Sereal qw{ encode_sereal };
use Test::Exception;
use Test::More;

use Mail::Milter::Authentication::Config qw{ secure_private_dir };
use Mail::Milter::Authentication::Tester::HandlerTester;

my $basedir = q{};

mkdir 't/tmp';
open( STDERR, '>>', $basedir . 't/tmp/misc.err' ) || die "Cannot open errlog [$!]";

my $tester = Mail::Milter::Authentication::Tester::HandlerTester->new({
    'prefix'   => $basedir . 't/config/handler/etc',
    'handler_config' => {},
});
my $handler = $tester->handler();

# Give each subtest its own spool, so state does not leak between them
sub fresh_spool {
    my $spool = tempdir( CLEANUP => 1 );
    $handler->config()->{'spool_dir'} = $spool;
    return $spool;
}

sub mode_of { return ( stat $_[0] )[2] & 07777 }

my $other_uid = getpwnam('nobody') // 65534;

subtest 'round trip of plain data' => sub {
    my $spool = fresh_spool();
    my $data = { 'a' => 1, 'b' => [ 2, 3 ], 'c' => { 'd' => 'e' } };
    $handler->add_dequeue( 'test_key', $data );

    my $dir = "$spool/dequeue";
    is( mode_of($dir), 0700, 'Dequeue directory created private' );

    my $list = $handler->get_dequeue_list( 'test_key' );
    is( scalar @$list, 1, 'One item queued' );
    is( mode_of( "$dir/$list->[0]" ), 0600, 'Queued file is private' );
    is_deeply( $handler->get_dequeue( $list->[0] ), $data, 'Data round trips' );
};

subtest 'objects are refused when queued' => sub {
    fresh_spool();
    throws_ok { $handler->add_dequeue( 'test_key', { 'obj' => bless {}, 'Some::Class' } ) }
        qr/croak_on_bless/, 'Queueing a blessed object dies';
    is( scalar @{ $handler->get_dequeue_list( 'test_key' ) }, 0, 'Nothing was queued' );
};

subtest 'objects are refused when dequeued' => sub {
    my $spool = fresh_spool();
    $handler->add_dequeue( 'test_key', {} );
    my $planted = 'test_key.planted.dequeue';
    write_file( "$spool/dequeue/$planted", encode_sereal( bless { 'a' => 1 }, 'Some::Class' ) );
    is( $handler->get_dequeue( $planted ), undef, 'Blessed object is not returned' );
};

subtest 'symlinked files are not followed' => sub {
    my $spool = fresh_spool();
    $handler->add_dequeue( 'test_key', {} );
    my $target = "$spool/target";
    write_file( $target, encode_sereal( { 'a' => 1 } ) );
    symlink $target, "$spool/dequeue/test_key.link.dequeue" or die "symlink: $!";
    is( $handler->get_dequeue( 'test_key.link.dequeue' ), undef, 'Symlinked file is ignored' );
};

subtest 'loose directory mode is tightened' => sub {
    my $spool = fresh_spool();
    mkdir "$spool/dequeue";
    chmod 0777, "$spool/dequeue";
    $handler->add_dequeue( 'test_key', { 'a' => 1 } );
    is( mode_of( "$spool/dequeue" ), 0700, 'Mode tightened to 0700' );
    my $list = $handler->get_dequeue_list( 'test_key' );
    is_deeply( $handler->get_dequeue( $list->[0] ), { 'a' => 1 }, 'Queue still works' );
};

subtest 'symlinked directory is refused' => sub {
    my $spool = fresh_spool();
    my $elsewhere = tempdir( CLEANUP => 1 );
    symlink $elsewhere, "$spool/dequeue" or die "symlink: $!";
    $handler->add_dequeue( 'test_key', { 'a' => 1 } );
    is( scalar @{ [ glob "$elsewhere/*" ] }, 0, 'Nothing written through the symlink' );
    is_deeply( $handler->get_dequeue_list( 'test_key' ), [], 'Nothing listed' );
};

SKIP: {
    skip 'ownership tests need root', 2 if $EUID != 0;

    subtest 'files owned by another user are ignored' => sub {
        my $spool = fresh_spool();
        $handler->add_dequeue( 'test_key', {} );
        my $file = "$spool/dequeue/test_key.other.dequeue";
        write_file( $file, encode_sereal( { 'a' => 1 } ) );
        chown $other_uid, -1, $file;
        is( $handler->get_dequeue( 'test_key.other.dequeue' ), undef, 'File is ignored' );
    };

    subtest 'directory owned by another user is refused' => sub {
        my $spool = fresh_spool();
        mkdir "$spool/dequeue";
        write_file( "$spool/dequeue/test_key.other.dequeue", encode_sereal( { 'a' => 1 } ) );
        chown $other_uid, -1, "$spool/dequeue";
        is_deeply( $handler->get_dequeue_list( 'test_key' ), [], 'Nothing listed' );
        is( $handler->get_dequeue( 'test_key.other.dequeue' ), undef, 'Nothing read' );
    };
}

subtest 'secure_private_dir' => sub {
    my $dir = tempdir( CLEANUP => 1 );
    chmod 0700, $dir;
    is( secure_private_dir( $dir ), 0, 'Private directory left alone' );
    chmod 0755, $dir;
    is( secure_private_dir( $dir ), 1, 'Readable directory tightened' );
    is( mode_of($dir), 0700, 'Mode is now 0700' );
    symlink $dir, "$dir.link" or die "symlink: $!";
    throws_ok { secure_private_dir( "$dir.link" ) } qr/not a directory/, 'Symlink refused';
    unlink "$dir.link";
    throws_ok { secure_private_dir( "$dir/missing" ) } qr/Could not stat/, 'Missing directory refused';
};

done_testing();
