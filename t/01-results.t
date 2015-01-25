#!perl
use 5.006;
use strict;
use warnings FATAL => 'all';
use Test::More;
use Test::File::Contents;

if ( ! -e 't/01-results.t' ) {
    die 'Could not find required files, are we in the correct directory?';
}

chdir 't';

plan tests => 8;

{
    system 'rm -rf tmp';
    mkdir 'tmp';
    mkdir 'tmp/result';

    run_milter_processing();

};

sub start_milter {
    my ( $prefix ) = @_;

    if ( ! -e $prefix . '/authentication_milter.json' ) {
        die "Could not find config";
    }

    my $setlib = 'export PERL5LIB=../lib';
    my $cmd = join( q{ },
        '../bin/authentication_milter',
        '--prefix',
        $prefix,
        '--pidfile tmp/authentication_milter.pid',
        '&',
    );
    system( $setlib . ';' . $cmd );
    sleep 5;
    return;
}

sub stop_milter {
    system( 'kill `cat tmp/authentication_milter.pid`' );
    unlink 'tmp/authentication_milter.pid';
    sleep 5;
    return;
}

sub milter_process {
    my ( $args ) = @_;

    if ( ! -e $args->{'prefix'} . '/authentication_milter.json' ) {
        die "Could not find config";
    }
    if ( ! -e 'data/source/' . $args->{'source'} ) {
        die "Could not find source";
    }

    my $setlib = 'export PERL5LIB=../lib';
    my $cmd = join( q{ },
        '../bin/authentication_milter_client',
        '--prefix', $args->{'prefix'},
        '--mailer_name test.module',
        '--mail_file', 'data/source/' . $args->{'source'},
        '--connect_ip', $args->{'ip'},
        '--connect_name', $args->{'name'},
        '--helo_host', $args->{'name'},
        '--mail_from', $args->{'from'},
        '--rcpt_to', $args->{'to'},
        '>', 'tmp/result/' . $args->{'dest'},
    );
    #warn 'Testing ' . $args->{'source'} . ' > ' . $args->{'dest'} . "\n";

    system( $setlib . ';' . $cmd );

    files_eq( 'data/example/' . $args->{'dest'}, 'tmp/result/' . $args->{'dest'}, $args->{'desc'} );

    return;
}

sub run_milter_processing {

    start_milter( 'config/normal' );
    
    milter_process({
        'desc'   => 'Good message',
        'prefix' => 'config/normal',
        'source' => 'google_apps_good.eml',
        'dest'   => 'google_apps_good.eml',
        'ip'     => '74.125.82.171',
        'name'   => 'mail-we0-f171.google.com',
        'from'   => 'marc@marcbradshaw.net',
        'to'     => 'marc@fastmail.com',
    });
    
    milter_process({
        'desc'   => 'SPF Fail',
        'prefix' => 'config/normal',
        'source' => 'google_apps_good.eml',
        'dest'   => 'google_apps_good_spf_fail.eml',
        'ip'     => '123.123.123.123',
        'name'   => 'bad.name.google.com',
        'from'   => 'marc@marcbradshaw.net',
        'to'     => 'marc@fastmail.com',
    });
    
    milter_process({
        'desc'   => 'DKIM Fail',
        'prefix' => 'config/normal',
        'source' => 'google_apps_bad.eml',
        'dest'   => 'google_apps_bad.eml',
        'ip'     => '74.125.82.171',
        'name'   => 'mail-we0-f171.google.com',
        'from'   => 'marc@marcbradshaw.net',
        'to'     => 'marc@fastmail.com',
    });
    
    milter_process({
        'desc'   => 'DKIM/SPF Fail',
        'prefix' => 'config/normal',
        'source' => 'google_apps_bad.eml',
        'dest'   => 'google_apps_bad_spf_fail.eml',
        'ip'     => '123.123.123.123',
        'name'   => 'bad.name.google.com',
        'from'   => 'marc@marcbradshaw.net',
        'to'     => 'marc@fastmail.com',
    });
    
    milter_process({
        'desc'   => 'No DKIM',
        'prefix' => 'config/normal',
        'source' => 'google_apps_nodkim.eml',
        'dest'   => 'google_apps_nodkim.eml',
        'ip'     => '74.125.82.171',
        'name'   => 'mail-we0-f171.google.com',
        'from'   => 'marc@marcbradshaw.net',
        'to'     => 'marc@fastmail.com',
    });
    
    milter_process({
        'desc'   => 'No DKIM/SPF Fail',
        'prefix' => 'config/normal',
        'source' => 'google_apps_nodkim.eml',
        'dest'   => 'google_apps_nodkim_spf_fail.eml',
        'ip'     => '123.123.123.123',
        'name'   => 'bad.name.google.com',
        'from'   => 'marc@marcbradshaw.net',
        'to'     => 'marc@fastmail.com',
    });
    
    milter_process({
        'desc'   => 'Sanitize Headers',
        'prefix' => 'config/normal',
        'source' => 'google_apps_good_sanitize.eml',
        'dest'   => 'google_apps_good_sanitize.eml',
        'ip'     => '74.125.82.171',
        'name'   => 'mail-we0-f171.google.com',
        'from'   => 'marc@marcbradshaw.net',
        'to'     => 'marc@fastmail.com',
    });
    
    stop_milter();
    
    start_milter( 'config/dryrun' );
    
    milter_process({
        'desc'   => 'Dry Run Mode',
        'prefix' => 'config/normal',
        'source' => 'google_apps_good.eml',
        'dest'   => 'google_apps_good_dryrun.eml',
        'ip'     => '74.125.82.171',
        'name'   => 'mail-we0-f171.google.com',
        'from'   => 'marc@marcbradshaw.net',
        'to'     => 'marc@fastmail.com',
    });
    
    stop_milter();

    return;
}

