#!perl -T
use 5.006;
use strict;
use warnings FATAL => 'all';
use Test::More;

BEGIN {

my @Modules = qw{
Mail::Milter::Authentication::App::Blocker::App::Command::list
Mail::Milter::Authentication::App::Blocker::App::Command::delete
Mail::Milter::Authentication::App::Blocker::App::Command::add
Mail::Milter::Authentication::App::Blocker::App
Mail::Milter::Authentication::Resolver
Mail::Milter::Authentication::Net::Milter
Mail::Milter::Authentication::HTDocs
Mail::Milter::Authentication::Pragmas
Mail::Milter::Authentication::Handler::TLS
Mail::Milter::Authentication::Handler::IPRev
Mail::Milter::Authentication::Handler::Blocker
Mail::Milter::Authentication::Handler::DMARC
Mail::Milter::Authentication::Handler::ReturnOK
Mail::Milter::Authentication::Handler::DKIM
Mail::Milter::Authentication::Handler::AddID
Mail::Milter::Authentication::Handler::Auth
Mail::Milter::Authentication::Handler::LocalIP
Mail::Milter::Authentication::Handler::AbusixDataFeed
Mail::Milter::Authentication::Handler::SPF
Mail::Milter::Authentication::Handler::ARC
Mail::Milter::Authentication::Handler::XGoogleDKIM
Mail::Milter::Authentication::Handler::AlignedFrom
Mail::Milter::Authentication::Handler::SenderID
Mail::Milter::Authentication::Handler::TestTimeout
Mail::Milter::Authentication::Handler::Sanitize
Mail::Milter::Authentication::Handler::Size
Mail::Milter::Authentication::Handler::PTR
Mail::Milter::Authentication::Handler::BIMI
Mail::Milter::Authentication::Handler::TrustedIP
Mail::Milter::Authentication::Metric
Mail::Milter::Authentication::Metric::Grafana
Mail::Milter::Authentication::Config
Mail::Milter::Authentication::Constants
Mail::Milter::Authentication::Protocol::SMTP
Mail::Milter::Authentication::Protocol::Milter
Mail::Milter::Authentication::Tester::HandlerTester
Mail::Milter::Authentication::Client
Mail::Milter::Authentication::Exception
Mail::Milter::Authentication::Tester
Mail::Milter::Authentication::Handler
Mail::Milter::Authentication
};

    plan tests => scalar @Modules;

    foreach my $Module ( @Modules ) {
        use_ok( $Module ) || print "Bail out!";
    }

}
