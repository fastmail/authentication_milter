use 5.006;
use strict;
use warnings FATAL => 'all';
use inc::Module::Install;

name     'Mail-Milter-Authentication';
all_from 'lib/Mail/Milter/Authentication.pm';
author   q{Marc Bradshaw <marc@marcbradshaw.net>};
license  'perl';

perl_version 5.006;

tests_recursive('t');

resources (
   #homepage   => '',
   #IRC        => 'irc://irc.perl.org/#Mail-Milter-Authentication',
   license    => 'http://dev.perl.org/licenses/',
   repository => 'https://github.com/fastmail/authentication_milter/',
   bugtracker => 'https://github.com/fastmail/authentication_milter/issues/',
);

configure_requires (
   'Module::Install' => 0,
   'version'         => 0,
);

build_requires (
    'Net::DNS::Packet'     => 0,
    'Net::DNS::Question'   => 0,
    'Net::DNS::Resolver'   => 0,
    'Net::DNS::ZoneFile'   => 0,
    'Test::More'           => 0,
    'Test::File::Contents' => 0,
    'Test::Perl::Critic'   => 0,
    'Test::CheckManifest'  => 0,
    'Test::Pod::Coverage'  => 0,
    'Test::Pod'            => 0,
    'Net::DNS::Resolver::Mock' => '1.20171219',
);

requires (
    'Cwd'                   => 0,
    'Email::Date::Format'   => 0,
    'Email::Simple'         => 0,
    'English'               => 0,
    'ExtUtils::Installed'   => 0,
    'IO::Socket'            => 0,
    'JSON'                  => 0,
    'List::MoreUtils'       => 0,
    'Mail::DKIM::Verifier'  => '0.39',
    'Mail::DMARC'           => '1.20160612',
    'Mail::SPF'             => 0,
    'MIME::Base64'          => 0,
    'Module::Load'          => 0,
    'Module::Loaded'        => 0,
    'Net::DNS'              => 0,
    'Net::IP'               => 0,
    'Net::Server'           => 0,
    'Net::Server::PreFork'  => 0,
    'Pod::Usage'            => 0,
    'Proc::ProcessTable'    => 0,
    'Socket'                => 0,
    'Sys::Hostname'         => 0,
    'Sys::Syslog'           => 0,
    'Time::HiRes'           => 0,
);

install_script (
    'bin/authentication_milter',
    'bin/authentication_milter_client',
);

install_share (
    'share',
);

install_as_cpan;
auto_install;
WriteAll;
