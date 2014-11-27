#!perl -T
use 5.006;
use strict;
use warnings FATAL => 'all';
use Test::More;

plan tests => 19;

BEGIN {
    use_ok( 'Mail::Milter::Authentication' ) || print "Bail out! ";
    use_ok( 'Mail::Milter::Authentication::Config' ) || print "Bail out! ";
    use_ok( 'Mail::Milter::Authentication::Constants' ) || print "Bail out! ";
    use_ok( 'Mail::Milter::Authentication::Dispatcher' ) || print "Bail out! ";
    use_ok( 'Mail::Milter::Authentication::ObjectBroker' ) || print "Bail out! ";
    use_ok( 'Mail::Milter::Authentication::Protocol' ) || print "Bail out! ";
    use_ok( 'Mail::Milter::Authentication::Protocol::Wire' ) || print "Bail out! ";
    use_ok( 'Mail::Milter::Authentication::Handler' ) || print "Bail out! ";
    use_ok( 'Mail::Milter::Authentication::Handler::Core' ) || print "Bail out! ";
    use_ok( 'Mail::Milter::Authentication::Handler::DKIM' ) || print "Bail out! ";
    use_ok( 'Mail::Milter::Authentication::Handler::DMARC' ) || print "Bail out! ";
    use_ok( 'Mail::Milter::Authentication::Handler::LocalIP' ) || print "Bail out! ";
    use_ok( 'Mail::Milter::Authentication::Handler::PTR' ) || print "Bail out! ";
    use_ok( 'Mail::Milter::Authentication::Handler::Sanitize' ) || print "Bail out! ";
    use_ok( 'Mail::Milter::Authentication::Handler::SenderID' ) || print "Bail out! ";
    use_ok( 'Mail::Milter::Authentication::Handler::SPF' ) || print "Bail out! ";
    use_ok( 'Mail::Milter::Authentication::Handler::TrustedIP' ) || print "Bail out! ";
    use_ok( 'Mail::Milter::Authentication::Handler::IPRev' ) || print "Bail out! ";
    use_ok( 'Mail::Milter::Authentication::Util' ) || print "Bail out! ";
}

diag( "Testing Mail::Milter::Authentication $Mail::Milter::Authentication::VERSION, Perl $], $^X" );
