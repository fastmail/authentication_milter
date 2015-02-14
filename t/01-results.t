#!perl
use 5.006;
use strict;
use warnings FATAL => 'all';
use Test::More;
use Test::File::Contents;
use Cwd qw{ cwd };

my $base_dir = cwd();
if ( ! -e 't/01-results.t' ) {
    die 'Could not find required files, are we in the correct directory?';
}

chdir 't';

sub set_lib {
    return 'export PERL5LIB=' . $base_dir . '/lib';
}

plan tests => 27;

{
    system 'rm -rf tmp';
    mkdir 'tmp';
    mkdir 'tmp/result';

    tools_test();
    tools_pipeline_test();
    run_smtp_processing();
    run_milter_processing();

};

sub tools_test {

    my $setlib = set_lib();

    my $cmd = join( q{ },
        'bin/smtpcat',
        '--sock_type unix',
        '--sock_path tmp/tools_test.sock',
        '|', 'sed "10,11d"',
        '>', 'tmp/result/tools_test.eml',
    );
    unlink 'tmp/tools_test.sock';
    system( $setlib . ';' . $cmd . '&' );
    sleep 2;
    
    $cmd = join( q{ },
        'bin/smtpput',
        '--sock_type unix',
        '--sock_path tmp/tools_test.sock',
        '--mailer_name test.module',
        '--connect_ip', '123.123.123.123',
        '--connect_name', 'test.connect.name',
        '--helo_host', 'test.helo.host',
        '--mail_from', 'test@mail.from',
        '--rcpt_to', 'test@rcpt.to',
        '--mail_file', 'data/source/tools_test.eml',
    );
    system( $setlib . ';' . $cmd );

    sleep 1;

    files_eq( 'data/example/tools_test.eml', 'tmp/result/tools_test.eml', 'tools test');

    return;
}

sub tools_pipeline_test {

    my $setlib = set_lib();

    my $cmd = join( q{ },
        'bin/smtpcat',
        '--sock_type unix',
        '--sock_path tmp/tools_test.sock',
        '|', 'sed "10,11d"',
        '>', 'tmp/result/tools_pipeline_test.eml',
    );
    unlink 'tmp/tools_test.sock';
    system( $setlib . ';' . $cmd . '&' );
    sleep 2;
    
    $cmd = join( q{ },
        'bin/smtpput',
        '--sock_type unix',
        '--sock_path tmp/tools_test.sock',
        '--mailer_name test.module',
        '--connect_ip', '123.123.123.123',
        '--connect_name', 'test.connect.name',
        '--helo_host', 'test.helo.host',
        '--mail_from', 'test@mail.from',
        '--rcpt_to', 'test@rcpt.to',
        '--mail_file', 'data/source/tools_test.eml',
        '--connect_ip', '1.2.3.4',
        '--connect_name', 'test.connect.example.com',
        '--helo_host', 'test.helo.host.example.com',
        '--mail_from', 'test@mail.again.from',
        '--rcpt_to', 'test@rcpt.again.to',
        '--mail_file', 'data/source/transparency.eml',
        '--connect_ip', '123.123.123.124',
        '--connect_name', 'test.connect.name2',
        '--helo_host', 'test.helo.host2',
        '--mail_from', 'test@mail.from2',
        '--rcpt_to', 'test@rcpt.to2',
        '--mail_file', 'data/source/google_apps_nodkim.eml',
    );
    system( $setlib . ';' . $cmd );

    sleep 1;

    files_eq( 'data/example/tools_pipeline_test.eml', 'tmp/result/tools_pipeline_test.eml', 'tools pipeline test');

    return;
}

sub start_milter {
    my ( $prefix ) = @_;

    if ( ! -e $prefix . '/authentication_milter.json' ) {
        die "Could not find config";
    }

    system "cp $prefix/mail-dmarc.ini .";

    my $setlib = set_lib();

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

    my $setlib = set_lib();

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

sub smtp_process_multi {
    my ( $args ) = @_;

    if ( ! -e $args->{'prefix'} . '/authentication_milter.json' ) {
        die "Could not find config";
    }

    my $setlib = set_lib();

    # Hardcoded lines to remove in subsequent messages
    # If you change the source email then change the awk
    # numbers here too.
    # This could be better!
    my $sed_filter = $args->{'sed_filter'};
    my $cmd = join( q{ },
        'bin/smtpcat',
        '--sock_type unix',
        '--sock_path tmp/authentication_milter_smtp_out.sock',
        '|', 'sed "',
        $sed_filter,
        '"',
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
    );

    foreach my $item ( @{$args->{'ip'}} ) {
        $cmd .= ' --connect_ip ' . $item;
    }
    foreach my $item ( @{$args->{'name'}} ) {
        $cmd .= ' --connect_name ' . $item;
    }
    foreach my $item ( @{$args->{'name'}} ) {
        $cmd .= ' --helo_host ' . $item;
    }
    foreach my $item ( @{$args->{'from'}} ) {
        $cmd .= ' --mail_from ' . $item;
    }
    foreach my $item ( @{$args->{'to'}} ) {
        $cmd .= ' --rcpt_to ' . $item;
    }
    foreach my $item ( @{$args->{'source'}} ) {
        $cmd .= ' --mail_file data/source/' . $item;
    }
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

    my $setlib = set_lib();
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
        'desc'   => 'Good message local',
        'prefix' => 'config/normal',
        'source' => 'google_apps_good.eml',
        'dest'   => 'google_apps_good.local.eml',
        'ip'     => '127.0.0.1',
        'name'   => 'localhost',
        'from'   => 'marc@marcbradshaw.net',
        'to'     => 'marc@fastmail.com',
    });

    milter_process({
        'desc'   => 'Good message trusted',
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

    smtp_process_multi({
        'desc'       => 'Pipelined messages',
        'prefix'     => 'config/normal.smtp',
        'source'     => [ 'transparency.eml', 'google_apps_good.eml','google_apps_bad.eml', ],
        'dest'       => 'pipelined.smtp.eml',
        'ip'         => [ '1.2.3.4', '127.0.0.1', '123.123.123.123', ],
        'name'       => [ 'test.example.com', 'localhost', 'bad.name.google.com', ],
        'from'       => [ 'test@example.com', 'marc@marcbradshaw.net', 'marc@marcbradshaw.net', ],
        'to'         => [ 'test@example.com', 'marc@fastmail.com', 'marc@fastmail.com', ],
        'sed_filter' => "10,11d;45,46d;115,116d",
    });

    smtp_process_multi({
        'desc'       => 'Pipelined messages limit',
        'prefix'     => 'config/normal.smtp',
        'source'     => [ 'transparency.eml', 'google_apps_good.eml', 'google_apps_bad.eml', 'transparency.eml', 'google_apps_good.eml','google_apps_bad.eml', ],
        'dest'       => 'pipelined.limit.smtp.eml',
        'ip'         => [ '1.2.3.4', '127.0.0.1', '123.123.123.123', '1.2.3.4', '127.0.0.1', '123.123.123.123', ],
        'name'       => [ 'test.example.com', 'localhost', 'bad.name.google.com', 'test.example.com', 'localhost', 'bad.name.google.com', ],
        'from'       => [ 'test@example.com', 'marc@marcbradshaw.net', 'marc@marcbradshaw.net', 'test@example.com', 'marc@marcbradshaw.net', 'marc@marcbradshaw.net', ],
        'to'         => [ 'test@example.com', 'marc@fastmail.com', 'marc@fastmail.com', 'test@example.com', 'marc@fastmail.com', 'marc@fastmail.com', ],
        'sed_filter' => "10,11d;45,46d;115,116d;190,191d",
    });

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
        'desc'   => '8BITMIME message',
        'prefix' => 'config/normal.smtp',
        'source' => 'google_apps_good.eml',
        'dest'   => 'google_apps_good.8bit.smtp.eml',
        'ip'     => '127.0.0.1',
        'name'   => 'localhost',
        'from'   => '"<marc@marcbradshaw.net> BODY=8BITMIME"',
        'to'     => 'marc@fastmail.com',
    });

    smtp_process({
        'desc'   => 'Header checks',
        'prefix' => 'config/normal.smtp',
        'source' => 'google_apps_headers.eml',
        'dest'   => 'google_apps_headers.smtp.eml',
        'ip'     => '127.0.0.1',
        'name'   => 'localhost',
        'from'   => 'marc@marcbradshaw.net',
        'to'     => 'marc@fastmail.com',
    });

    smtp_process({
        'desc'   => 'Good message local',
        'prefix' => 'config/normal.smtp',
        'source' => 'google_apps_good.eml',
        'dest'   => 'google_apps_good.local.smtp.eml',
        'ip'     => '127.0.0.1',
        'name'   => 'localhost',
        'from'   => 'marc@marcbradshaw.net',
        'to'     => 'marc@fastmail.com',
    });

    smtp_process({
        'desc'   => 'Good message trusted',
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

