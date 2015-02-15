#!perl -T
use 5.006;
use strict;
use warnings FATAL => 'all';
use Test::More;
use Test::Pod::Coverage;

my @modules = qw {
    Mail::Milter::Authentication
    Mail::Milter::Authentication::Client
    Mail::Milter::Authentication::Config
    Mail::Milter::Authentication::Constants
    Mail::Milter::Authentication::DNSCache
    Mail::Milter::Authentication::Handler
    Mail::Milter::Authentication::Protocol::Milter
    Mail::Milter::Authentication::Protocol::SMTP
};
# Mail::Milter::Authentication::Handler::AddID
# Mail::Milter::Authentication::Handler::Auth
# Mail::Milter::Authentication::Handler::DKIM
# Mail::Milter::Authentication::Handler::DMARC
# Mail::Milter::Authentication::Handler::LocalIP
# Mail::Milter::Authentication::Handler::PTR
# Mail::Milter::Authentication::Handler::ReturnOK
# Mail::Milter::Authentication::Handler::Sanitize
# Mail::Milter::Authentication::Handler::SenderID
# Mail::Milter::Authentication::Handler::SPF
# Mail::Milter::Authentication::Handler::TrustedIP
# Mail::Milter::Authentication::Handler::IPRev

plan tests => scalar @modules;

foreach my $module ( @modules ) {
    pod_coverage_ok( $module );
}

