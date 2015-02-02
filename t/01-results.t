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

plan tests => 21;

{
    system 'rm -rf tmp';
    mkdir 'tmp';
    mkdir 'tmp/result';

    run_smtp_processing();
    run_milter_processing();

};

sub start_milter {
    my ( $prefix ) = @_;

    if ( ! -e $prefix . '/authentication_milter.json' ) {
        die "Could not find config";
    }

    system "cp $prefix/mail-dmarc.ini .";

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
    unlink 'mail-dmarc.ini';
    sleep 5;
    return;
}

sub smtp_process {
    my ( $args ) = @_;

    if ( ! -e $args->{'prefix'} . '/authentication_milter.json' ) {
        die "Could not find config";
    }
    if ( ! -e 'data/source/' . $args->{'source'} ) {
        die "Could not find source";
    }

    my $setlib = 'export PERL5LIB=../lib';

    my $cmd = join( q{ },
        'bin/smtpcat',
        '--sock_type unix',
        '--sock_path tmp/authentication_milter_smtp_out.sock',
        '|', 'sed "10,11d"',
        '>', 'tmp/result/' . $args->{'dest'},
    );
    unlink 'tmp/authentication_milter_smtp_out.sock';
    system( $setlib . ';' . $cmd . '&' );
    sleep 2;

    $cmd = join( q{ },
        'bin/smtpput',
        '--sock_type unix',
        '--sock_path tmp/authentication_milter_test.sock',
        '--mailer_name test.module',
        '--connect_ip', $args->{'ip'},
        '--connect_name', $args->{'name'},
        '--helo_host', $args->{'name'},
        '--mail_from', $args->{'from'},
        '--rcpt_to', $args->{'to'},
        '--mail_file', 'data/source/' . $args->{'source'},
    );
    #warn 'Testing ' . $args->{'source'} . ' > ' . $args->{'dest'} . "\n";

    system( $setlib . ';' . $cmd );

    sleep 1;

    files_eq( 'data/example/' . $args->{'dest'}, 'tmp/result/' . $args->{'dest'}, 'smtp ' . $args->{'desc'} );

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

    files_eq( 'data/example/' . $args->{'dest'}, 'tmp/result/' . $args->{'dest'}, 'milter ' . $args->{'desc'} );

    return;
}

sub run_milter_processing {

    start_milter( 'config/normal' );

    milter_process({
        'desc'   => 'Good message',
        'prefix' => 'config/normal',
        'source' => 'google_apps_good.eml',
        'dest'   => 'google_apps_good.local.eml',
        'ip'     => '127.0.0.1',
        'name'   => 'localhost',
        'from'   => 'marc@marcbradshaw.net',
        'to'     => 'marc@fastmail.com',
    });

    milter_process({
        'desc'   => 'Good message',
        'prefix' => 'config/normal',
        'source' => 'google_apps_good.eml',
        'dest'   => 'google_apps_good.trusted.eml',
        'ip'     => '59.167.198.153',
        'name'   => 'mx4.twofiftyeight.ltd.uk',
        'from'   => 'marc@marcbradshaw.net',
        'to'     => 'marc@fastmail.com',
    });


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

sub run_smtp_processing {

    start_milter( 'config/normal.smtp' );
    
    smtp_process({
        'desc'   => 'Transparency message',
        'prefix' => 'config/normal.smtp',
        'source' => 'transparency.eml',
        'dest'   => 'transparency.smtp.eml',
        'ip'     => '1.2.3.4',
        'name'   => 'test.example.com',
        'from'   => 'test@example.com',
        'to'     => 'test@example.com',
    });

    smtp_process({
        'desc'   => 'Good message',
        'prefix' => 'config/normal.smtp',
        'source' => 'google_apps_good.eml',
        'dest'   => 'google_apps_good.local.smtp.eml',
        'ip'     => '127.0.0.1',
        'name'   => 'localhost',
        'from'   => 'marc@marcbradshaw.net',
        'to'     => 'marc@fastmail.com',
    });
    smtp_process({
        'desc'   => 'Good message',
        'prefix' => 'config/normal.smtp',
        'source' => 'google_apps_good.eml',
        'dest'   => 'google_apps_good.trusted.smtp.eml',
        'ip'     => '59.167.198.153',
        'name'   => 'mx4.twofiftyeight.ltd.uk',
        'from'   => 'marc@marcbradshaw.net',
        'to'     => 'marc@fastmail.com',
    });

    smtp_process({
        'desc'   => 'Good message',
        'prefix' => 'config/normal.smtp',
        'source' => 'google_apps_good.eml',
        'dest'   => 'google_apps_good.smtp.eml',
        'ip'     => '74.125.82.171',
        'name'   => 'mail-we0-f171.google.com',
        'from'   => 'marc@marcbradshaw.net',
        'to'     => 'marc@fastmail.com',
    });
    
    smtp_process({
        'desc'   => 'SPF Fail',
        'prefix' => 'config/normal.smtp',
        'source' => 'google_apps_good.eml',
        'dest'   => 'google_apps_good_spf_fail.smtp.eml',
        'ip'     => '123.123.123.123',
        'name'   => 'bad.name.google.com',
        'from'   => 'marc@marcbradshaw.net',
        'to'     => 'marc@fastmail.com',
    });
    
    smtp_process({
        'desc'   => 'DKIM Fail',
        'prefix' => 'config/normal.smtp',
        'source' => 'google_apps_bad.eml',
        'dest'   => 'google_apps_bad.smtp.eml',
        'ip'     => '74.125.82.171',
        'name'   => 'mail-we0-f171.google.com',
        'from'   => 'marc@marcbradshaw.net',
        'to'     => 'marc@fastmail.com',
    });
    
    smtp_process({
        'desc'   => 'DKIM/SPF Fail',
        'prefix' => 'config/normal.smtp',
        'source' => 'google_apps_bad.eml',
        'dest'   => 'google_apps_bad_spf_fail.smtp.eml',
        'ip'     => '123.123.123.123',
        'name'   => 'bad.name.google.com',
        'from'   => 'marc@marcbradshaw.net',
        'to'     => 'marc@fastmail.com',
    });
    
    smtp_process({
        'desc'   => 'No DKIM',
        'prefix' => 'config/normal.smtp',
        'source' => 'google_apps_nodkim.eml',
        'dest'   => 'google_apps_nodkim.smtp.eml',
        'ip'     => '74.125.82.171',
        'name'   => 'mail-we0-f171.google.com',
        'from'   => 'marc@marcbradshaw.net',
        'to'     => 'marc@fastmail.com',
    });
    
    smtp_process({
        'desc'   => 'No DKIM/SPF Fail',
        'prefix' => 'config/normal.smtp',
        'source' => 'google_apps_nodkim.eml',
        'dest'   => 'google_apps_nodkim_spf_fail.smtp.eml',
        'ip'     => '123.123.123.123',
        'name'   => 'bad.name.google.com',
        'from'   => 'marc@marcbradshaw.net',
        'to'     => 'marc@fastmail.com',
    });
    
    smtp_process({
        'desc'   => 'Sanitize Headers',
        'prefix' => 'config/normal.smtp',
        'source' => 'google_apps_good_sanitize.eml',
        'dest'   => 'google_apps_good_sanitize.smtp.eml',
        'ip'     => '74.125.82.171',
        'name'   => 'mail-we0-f171.google.com',
        'from'   => 'marc@marcbradshaw.net',
        'to'     => 'marc@fastmail.com',
    });
    
    stop_milter();
    
    start_milter( 'config/dryrun.smtp' );
    
    smtp_process({
        'desc'   => 'Dry Run Mode',
        'prefix' => 'config/normal',
        'source' => 'google_apps_good.eml',
        'dest'   => 'google_apps_good_dryrun.smtp.eml',
        'ip'     => '74.125.82.171',
        'name'   => 'mail-we0-f171.google.com',
        'from'   => 'marc@marcbradshaw.net',
        'to'     => 'marc@fastmail.com',
    });
    
    stop_milter();

    return;
}

