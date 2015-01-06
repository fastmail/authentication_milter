use 5.006;
use strict;
use warnings FATAL => 'all';
use inc::Module::Install;

name     'Mail-Milter-Authentication';
all_from 'lib/Mail/Milter/Authentication.pm';
author   q{Marc Bradshaw <marc@marcbradshaw.net>};
license  'artistic2';

perl_version 5.006;

tests_recursive('t');

resources (
   #homepage   => '',
   #IRC        => 'irc://irc.perl.org/#Mail-Milter-Authentication',
   license    => 'http://www.perlfoundation.org/artistic_license_2_0',
   #repository => 'https://gitlab.com/marcbradshaw/authentication-milter/',
   #bugtracker => 'https://gitlab.com/marcbradshaw/authentication-milter/issues/',
   repository => 'https://github.com/marcbradshaw/authentication-milter/',
   bugtracker => 'https://github.com/marcbradshaw/authentication-milter/issues/',
);

configure_requires (
   'Module::Install' => 0,
);

build_requires (
   'Test::More' => 0,
);

requires (
    'Email::Address'        => 0,
    'English'               => 0,
    'JSON'                  => 0,
    'Mail::DKIM::Verifier'  => '0.39',
    'Mail::DMARC::PurePerl' => 0,
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
);

install_script (
    'bin/authentication_milter',
);

install_share (
    'share',
);

install_as_cpan;
auto_install;
WriteAll;
