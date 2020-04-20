#!/usr/bin/env perl

use strict;
use warnings;
use lib 't';

use Data::Dumper;

use Mail::Milter::Authentication::Tester::HandlerTester;
use Mail::Milter::Authentication::Constants qw{ :all };
use Test::Exception;
use Test::More;
use Net::IP;
use Clone qw{ clone };

my $basedir = q{};

open( STDERR, '>>', $basedir . 't/tmp/misc.err' ) || die "Cannot open errlog [$!]";
#open( STDOUT, '>>', $basedir . 't/tmp/misc.err' ) || die "Cannot open errlog [$!]";

my $base_tester = Mail::Milter::Authentication::Tester::HandlerTester->new({
    'prefix'   => $basedir . 't/config/handler/etc',
    'zonedata' => '',
    'handler_config' => {
        'IPRev' => {},
        'PTR' => {},
        'LocalIP' => {},
        'TrustedIP' => {},
        'Auth' => {},
    },
});

my $no_remap_tester = clone $base_tester;
my $remap_tester = clone $base_tester;
$remap_tester->{ 'authmilter' }->{ 'config' }->{ 'ip_map' } = {
    '1.1.0.0/24' => {
        'ip' => '1.2.0.1',
        'helo' => 'ip_remapped.example.com',
        'helo_map' => {
            'matched_helo.example.com' => {
                'ip' => '1.3.0.1',
                'helo' => 'helo_remapped.example.com',
            }
        }
    }
};
my $use_tester;

$use_tester = clone $no_remap_tester;
subtest no_remap_smtp => sub {
    run_test_on( $use_tester, 'smtp', '1.4.0.1', 'sent_helo.example.com', '1.4.0.1', 'sent_helo.example.com' );
};

$use_tester = clone $no_remap_tester;
subtest no_remap_milter => sub {
    run_test_on( $use_tester, 'milter', '1.4.0.1', 'sent_helo.example.com', '1.4.0.1', 'sent_helo.example.com' );
};

$use_tester = clone $remap_tester;
subtest ip_remap_no_hit_smtp => sub {
    run_test_on( $use_tester, 'smtp', '1.4.0.1', 'sent_helo.example.com', '1.4.0.1', 'sent_helo.example.com' );
};

$use_tester = clone $remap_tester;
subtest ip_remap_no_hit_milter => sub {
    run_test_on( $use_tester, 'milter', '1.4.0.1', 'sent_helo.example.com', '1.4.0.1', 'sent_helo.example.com' );
};

$use_tester = clone $remap_tester;
subtest ip_remap_ip_hit_smtp => sub {
    run_test_on( $use_tester, 'smtp', '1.1.0.1', 'sent_helo.example.com', '1.2.0.1', 'ip_remapped.example.com' );
};

$use_tester = clone $remap_tester;
subtest ip_remap_ip_hit_milter => sub {
    run_test_on( $use_tester, 'milter', '1.1.0.1', 'sent_helo.example.com', '1.2.0.1', 'ip_remapped.example.com' );
};

$use_tester = clone $remap_tester;
subtest ip_remap_helo_hit_smtp => sub {
    run_test_on( $use_tester, 'smtp', '1.1.0.1', 'matched_helo.example.com', '1.3.0.1', 'helo_remapped.example.com' );
};

$use_tester = clone $remap_tester;
subtest ip_remap_helo_hit_milter => sub {
    # IP cannot remap in milter protocol, so will be the generic remap not the helo remap
    run_test_on( $use_tester, 'milter', '1.1.0.1', 'matched_helo.example.com', '1.2.0.1', 'helo_remapped.example.com' );
};

done_testing();

sub run_test_on {
  my ( $tester, $order, $send_ip, $send_helo, $expect_ip, $expect_helo ) = @_;

  my $host = 'nothing.example.com';
  my $ip = Net::IP->new( $send_ip );
  my $helo = $send_helo;
  my $from = 'from_address.example.com';
  my $to = 'to_address.example.com';

  my $handler = $tester->{ 'authmilter' }->{ 'handler' }->{ '_Handler' };;

  if ( $order eq 'smtp' ) {
    $handler->remap_connect_callback( $host, $ip );
    $handler->remap_helo_callback( $helo );
    $handler->top_connect_callback( $host, $handler->{ 'ip_object' } );
    $handler->top_helo_callback( $handler->{ 'helo_name' } );
  }
  else {
    $handler->remap_connect_callback( $host, $ip );
    $handler->top_connect_callback( $host, $handler->{ 'ip_object' } );
    $handler->remap_helo_callback( $helo );
    $handler->top_helo_callback( $handler->{ 'helo_name' } );
  }

  $handler->top_envfrom_callback( $from );
  $handler->top_envrcpt_callback( $to );

  $handler->top_header_callback( 'From', $from );
  $handler->top_header_callback( 'To', $to );
  $handler->top_header_callback( 'Subuject', 'Testing');

  $handler->top_eoh_callback();
  $handler->top_body_callback( 'This is a test email' );
  $handler->top_eom_callback();

  my $iprev_header = $tester->get_authresults_header()->search({ 'key' => 'iprev' });
  my $ptr_header = $tester->get_authresults_header()->search({ 'key' => 'x-ptr' });
  my $used_ip = $iprev_header->search({ 'key' => 'smtp.remote-ip' })->children()->[0]->value();
  my $used_helo = $ptr_header->search({ 'key' => 'smtp.helo' })->children()->[0]->value();

  is( $used_ip, $expect_ip, 'IP is correct' );
  is( $used_helo, $expect_helo, 'HELO is correct' );
  $tester->close();

}

