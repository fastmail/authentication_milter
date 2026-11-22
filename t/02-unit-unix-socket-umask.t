#!/usr/bin/env perl

# The configured umask for a unix socket connection sets the mode of that
# socket only. It must not change the process umask, which would otherwise
# apply to every file created afterwards, and each connection gets its own.
# A connection without its own umask uses the top level umask.

use strict;
use warnings;
use lib 't';

use File::Temp qw{ tempdir };
use IO::Socket::UNIX;
use Socket qw{ SOCK_STREAM };
use Test::More;

use Mail::Milter::Authentication;
use Mail::Milter::Authentication::Config qw{ set_config };

mkdir 't/tmp';
open( STDERR, '>>', 't/tmp/misc.err' ) || die "Cannot open errlog [$!]";

package TestSock {
    sub new { my ( $class, %args ) = @_; return bless { %args }, $class }
    sub NS_proto { return $_[0]->{'proto'} }
    sub NS_port { return $_[0]->{'port'} }
}

my $dir = tempdir( CLEANUP => 1 );
my %path = map { $_ => "$dir/$_.sock" } qw{ default other metric unset };

sub socket_mode {
    my ( $path ) = @_;
    return sprintf( '%04o', ( stat $path )[2] & 07777 );
}

my $config = {
    'connection'        => "unix:$path{default}",
    'umask'             => '0007',
    'connections'       => {
        'other' => { 'connection' => "unix:$path{other}", 'umask' => '0077' },
        'unset' => { 'connection' => "unix:$path{unset}" },
        'tcp'   => { 'connection' => 'inet:12345@localhost', 'umask' => '0000' },
    },
    'metric_connection' => "unix:$path{metric}",
    'metric_umask'      => '0000',
};

is_deeply( Mail::Milter::Authentication::unix_socket_umasks( $config ), {
    $path{default} => '0007',
    $path{other}   => '0077',
    $path{metric}  => '0000',
    $path{unset}   => '0007',
}, 'Umask found for each unix socket, falling back to the top level umask' );

is_deeply( Mail::Milter::Authentication::unix_socket_umasks( {
    'connection'        => "unix:$path{default}",
    'connections'       => { 'unset' => { 'connection' => "unix:$path{unset}" } },
    'metric_connection' => "unix:$path{metric}",
} ), {}, 'No umask when none is configured' );

is_deeply( Mail::Milter::Authentication::unix_socket_umasks( {
    'connection'        => "unix:$path{default}",
    'umask'             => '0000',
    'connections'       => { 'unset' => { 'connection' => "unix:$path{unset}" } },
    'metric_connection' => "unix:$path{metric}",
} ), {
    $path{default} => '0000',
    $path{unset}   => '0000',
    $path{metric}  => '0000',
}, 'Top level umask applies to connections and metrics without their own' );

set_config( $config );

my $original_umask = umask( 0022 );
my @socks;
for my $name ( sort keys %path ) {
    IO::Socket::UNIX->new( 'Type' => SOCK_STREAM, 'Local' => $path{$name}, 'Listen' => 1 ) || die "socket $path{$name}: $!";
    push @socks, TestSock->new( 'proto' => 'UNIX', 'port' => $path{$name} );
}
push @socks, TestSock->new( 'proto' => 'TCP', 'port' => '12345' );
my $server = bless { 'server' => { 'sock' => \@socks } }, 'Mail::Milter::Authentication';
$server->post_bind_hook();

is( socket_mode( $path{default} ), '0770', 'Default connection socket mode from umask' );
is( socket_mode( $path{other} ),   '0700', 'Other connection socket has its own mode' );
is( socket_mode( $path{metric} ),  '0777', 'Metrics socket mode from metric_umask' );
is( socket_mode( $path{unset} ),   '0770', 'Socket with no umask of its own uses the top level umask' );
is( umask(), 0022, 'Process umask unchanged' );

umask( $original_umask );

done_testing();
