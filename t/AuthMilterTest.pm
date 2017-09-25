package AuthMilterTest;

use strict;
use warnings;
use Net::DNS::Resolver::Mock;
use Test::More;
use Test::File::Contents;

use Cwd qw{ cwd };
use IO::Socket::INET;
use IO::Socket::UNIX;
use JSON;
use Module::Load;

use Mail::Milter::Authentication;
use Mail::Milter::Authentication::Client;
use Mail::Milter::Authentication::Config;
use Mail::Milter::Authentication::Protocol::Milter;
use Mail::Milter::Authentication::Protocol::SMTP;

my $base_dir = cwd();

our $MASTER_PROCESS_PID = $$;

sub tools_test {

    my $catargs = {
        'sock_type' => 'unix',
        'sock_path' => 'tmp/tools_test.sock',
        'remove'    => [],
        'output'    => 'tmp/result/tools_test.eml',
    };
    unlink 'tmp/tools_test.sock';
    my $cat_pid = smtpcat( $catargs );
    sleep 2;

    smtpput({
        'sock_type'    => 'unix',
        'sock_path'    => 'tmp/tools_test.sock',
        'mailer_name'  => 'test.module',
        'connect_ip'   => ['123.123.123.123'],
        'connect_name' => ['test.connect.name'],
        'helo_host'    => ['test.helo.host'],
        'mail_from'    => ['test@mail.from'],
        'rcpt_to'      => ['test@rcpt.to'],
        'mail_file'    => ['data/source/tools_test.eml'],
    });

    waitpid( $cat_pid,0 );

    files_eq( 'data/example/tools_test.eml', 'tmp/result/tools_test.eml', 'tools test');

    return;
}

sub tools_pipeline_test {

    my $catargs = {
        'sock_type' => 'unix',
        'sock_path' => 'tmp/tools_test.sock',
        'remove'    => [],
        'output'    => 'tmp/result/tools_pipeline_test.eml',
    };
    unlink 'tmp/tools_test.sock';
    my $cat_pid = smtpcat( $catargs );
    sleep 2;

    my $putargs = {
        'sock_type'    => 'unix',
        'sock_path'    => 'tmp/tools_test.sock',
        'mailer_name'  => 'test.module',
        'connect_ip'   => [],
        'connect_name' => [],
        'helo_host'    => [],
        'mail_from'    => [],
        'rcpt_to'      => [],
        'mail_file'    => [],
    };

    push @{$putargs->{'connect_ip'}},   '123.123.123.123';
    push @{$putargs->{'connect_name'}}, 'test.connect.name';
    push @{$putargs->{'helo_host'}},    'test.helo.host';
    push @{$putargs->{'mail_from'}},    'test@mail.from';
    push @{$putargs->{'rcpt_to'}},      'test@rcpt.to';
    push @{$putargs->{'mail_file'}},    'data/source/tools_test.eml';

    push @{$putargs->{'connect_ip'}},   '1.2.3.4';
    push @{$putargs->{'connect_name'}}, 'test.connect.example.com';
    push @{$putargs->{'helo_host'}},    'test.helo.host.example.com';
    push @{$putargs->{'mail_from'}},    'test@mail.again.from';
    push @{$putargs->{'rcpt_to'}},      'test@rcpt.again.to';
    push @{$putargs->{'mail_file'}},    'data/source/transparency.eml';

    push @{$putargs->{'connect_ip'}},   '123.123.123.124';
    push @{$putargs->{'connect_name'}}, 'test.connect.name2';
    push @{$putargs->{'helo_host'}},    'test.helo.host2';
    push @{$putargs->{'mail_from'}},    'test@mail.from2';
    push @{$putargs->{'rcpt_to'}},      'test@rcpt.to2';
    push @{$putargs->{'mail_file'}},    'data/source/google_apps_nodkim.eml';

    smtpput( $putargs );

    waitpid( $cat_pid,0 );

    sleep 1;

    files_eq( 'data/example/tools_pipeline_test.eml', 'tmp/result/tools_pipeline_test.eml', 'tools pipeline test');

    return;
}

{
    my $milter_pid;

    sub start_milter {
        my ( $prefix ) = @_;

        return if $milter_pid;

        if ( ! -e $prefix . '/authentication_milter.json' ) {
            die "Could not find config";
        }

        system "cp $prefix/mail-dmarc.ini .";

        $milter_pid = fork();
        die "unable to fork: $!" unless defined($milter_pid);
        if (!$milter_pid) {
            $Mail::Milter::Authentication::Config::PREFIX = $prefix;
            $Mail::Milter::Authentication::Config::IDENT  = 'test_authentication_milter_test';
            my $Resolver = Net::DNS::Resolver::Mock->new();
            $Resolver->zonefile_read( 'zonefile' );
            $Mail::Milter::Authentication::Handler::TestResolver = $Resolver,
            Mail::Milter::Authentication::start({
                'pid_file'   => 'tmp/authentication_milter.pid',
                'daemon'     => 0,
            });
            die;
        }

        sleep 5;
        open my $pid_file, '<', 'tmp/authentication_milter.pid';
        $milter_pid = <$pid_file>;
        close $pid_file;
        print "Milter started at pid $milter_pid\n";
        return;
    }

    sub stop_milter {
        return if ! $milter_pid;
        kill( 'HUP', $milter_pid );
        waitpid ($milter_pid,0);
        print "Milter killed at pid $milter_pid\n";
        undef $milter_pid;
        unlink 'tmp/authentication_milter.pid';
        unlink 'mail-dmarc.ini';
        return;
    }

    END {
        return if $MASTER_PROCESS_PID != $$;
        stop_milter();
    }
}

sub get_metrics {
    my ( $path ) = @_;

    my $sock = IO::Socket::UNIX->new(
        'Peer' => $path,
    );

    print $sock "GET /metrics HTTP/1.0\n\n";

    my $data = {};

    while ( my $line = <$sock> ) {
        chomp $line;
        last if $line eq q{};
    }
    while ( my $line = <$sock> ) {
        chomp $line;
        next if $line =~ /^#/;
        $line =~ /^(.*)\{(.*)\} (.*)$/;
        my $count_id = $1;
        my $labels = $2;
        my $count = $3;
        $data->{ $count_id . '{' . $labels . '}' } = $count;
    }

    return $data;
}

sub test_metrics {
    my ( $expected ) = @_;

    subtest $expected => sub {

        my $metrics =  get_metrics( 'tmp/authentication_milter_test_metrics.sock' );
        my $j = JSON->new();

        if ( -e $expected ) {

            open my $InF, '<', $expected;
            my @content = <$InF>;
            close $InF;
            my $data = $j->decode( join( q{}, @content ) );

            plan tests => scalar keys %$data;

            foreach my $key ( sort keys %$data ) {
                if ( $key =~ /seconds_total/ ) {
                    is( $metrics->{ $key } > 0, $data->{ $key } > 0, "Metrics $key" );
                }
                else {
                    is( $metrics->{ $key }, $data->{ $key }, "Metrics $key" );
                }
            }

        }
        else {
            fail( 'Metrics data does not exist' );
            # Uncomment to write out new json file
            #open my $OutF, '>', $expected;
            #$j->pretty();
            #print $OutF $j->encode( $metrics );
            #close $OutF;
        }

    };

    return;
}

sub smtp_process {
    my ( $args ) = @_;

    if ( ! -e $args->{'prefix'} . '/authentication_milter.json' ) {
        die "Could not find config " . $args->{'prefix'};
    }
    if ( ! -e 'data/source/' . $args->{'source'} ) {
        die "Could not find source";
    }

    my $catargs = {
        'sock_type' => 'unix',
        'sock_path' => 'tmp/authentication_milter_smtp_out.sock',
        'remove'    => [10,11],
        'output'    => 'tmp/result/' . $args->{'dest'},
    };
    unlink 'tmp/authentication_milter_smtp_out.sock';
    my $cat_pid;
    if ( ! $args->{'no_cat'} ) {
        $cat_pid = smtpcat( $catargs );
        sleep 2;
    }

    my $return = smtpput({
        'sock_type'    => 'unix',
        'sock_path'    => 'tmp/authentication_milter_test.sock',
        'mailer_name'  => 'test.module',
        'connect_ip'   => [ $args->{'ip'} ],
        'connect_name' => [ $args->{'name'} ],
        'helo_host'    => [ $args->{'name'} ],
        'mail_from'    => [ $args->{'from'} ],
        'rcpt_to'      => [ $args->{'to'} ],
        'mail_file'    => [ 'data/source/' . $args->{'source'} ],
        'eom_expect'   => $args->{'eom_expect'},
    });

    if ( ! $args->{'no_cat'} ) {
        waitpid( $cat_pid,0 );
        files_eq( 'data/example/' . $args->{'dest'}, 'tmp/result/' . $args->{'dest'}, 'smtp ' . $args->{'desc'} );
    }
    else {
        is( $return, 1, 'SMTP Put Returned ok' );
    }

    return;
}

sub smtp_process_multi {
    my ( $args ) = @_;

    if ( ! -e $args->{'prefix'} . '/authentication_milter.json' ) {
        die "Could not find config";
    }

    # Hardcoded lines to remove in subsequent messages
    # If you change the source email then change the awk
    # numbers here too.
    # This could be better!

    my $catargs = {
        'sock_type' => 'unix',
        'sock_path' => 'tmp/authentication_milter_smtp_out.sock',
        'remove'    => $args->{'filter'},
        'output'    => 'tmp/result/' . $args->{'dest'},
    };
    unlink 'tmp/authentication_milter_smtp_out.sock';
    my $cat_pid = smtpcat( $catargs );
    sleep 2;

    my $putargs = {
        'sock_type'    => 'unix',
        'sock_path'    => 'tmp/authentication_milter_test.sock',
        'mailer_name'  => 'test.module',
        'connect_ip'   => [],
        'connect_name' => [],
        'helo_host'    => [],
        'mail_from'    => [],
        'rcpt_to'      => [],
        'mail_file'    => [],
    };

    foreach my $item ( @{$args->{'ip'}} ) {
        push @{$putargs->{'connect_ip'}}, $item;
    }
    foreach my $item ( @{$args->{'name'}} ) {
        push @{$putargs->{'connect_name'}}, $item;
    }
    foreach my $item ( @{$args->{'name'}} ) {
        push @{$putargs->{'helo_host'}}, $item;
    }
    foreach my $item ( @{$args->{'from'}} ) {
        push @{$putargs->{'mail_from'}}, $item;
    }
    foreach my $item ( @{$args->{'to'}} ) {
        push @{$putargs->{'rcpt_to'}}, $item;
    }
    foreach my $item ( @{$args->{'source'}} ) {
        push @{$putargs->{'mail_file'}}, 'data/source/' . $item;
    }
    #warn 'Testing ' . $args->{'source'} . ' > ' . $args->{'dest'} . "\n";

    smtpput( $putargs );

    waitpid( $cat_pid,0 );

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

    client({
        'prefix'       => $args->{'prefix'},
        'mailer_name'  => 'test.module',
        'mail_file'    => 'data/source/' . $args->{'source'},
        'connect_ip'   => $args->{'ip'},
        'connect_name' => $args->{'name'},
        'helo_host'    => $args->{'name'},
        'mail_from'    => $args->{'from'},
        'rcpt_to'      => $args->{'to'},
        'output'       => 'tmp/result/' . $args->{'dest'},
    });

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
        'desc'   => 'Good message dkim case local',
        'prefix' => 'config/normal',
        'source' => 'google_apps_good_case.eml',
        'dest'   => 'google_apps_good_case.local.eml',
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
        'ip'     => '123.123.12.3',
        'name'   => 'mx4.twofiftyeight.ltd.uk',
        'from'   => 'marc@marcbradshaw.net',
        'to'     => 'marc@fastmail.com',
    });

    milter_process({
        'desc'   => 'Good message no from',
        'prefix' => 'config/normal',
        'source' => 'google_apps_good.eml',
        'dest'   => 'google_apps_good_nofrom.eml',
        'ip'     => '74.125.82.171',
        'name'   => 'marcbradshaw.net',
        'from'   =>  '',
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
        'desc'   => 'DKIM Fail Domain Space',
        'prefix' => 'config/normal',
        'source' => 'google_apps_bad_space.eml',
        'dest'   => 'google_apps_bad_space.eml',
        'ip'     => '74.125.82.171',
        'name'   => 'mail-we0-f171.google.com',
        'from'   => 'marc@ marcbradshaw.net',
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

    milter_process({
        'desc'   => 'Long Lines',
        'prefix' => 'config/normal',
        'source' => 'longlines.eml',
        'dest'   => 'longlines.eml',
        'ip'     => '74.125.82.171',
        'name'   => 'mail-we0-f171.google.com',
        'from'   => 'marc@marcbradshaw.net',
        'to'     => 'marc@fastmail.com',
    });

    milter_process({
        'desc'   => 'DMARC Reject',
        'prefix' => 'config/normal',
        'source' => 'dmarc_reject.eml',
        'dest'   => 'dmarc_reject.eml',
        'ip'     => '123.123.123.123',
        'name'   => 'bad.name.google.com',
        'from'   => 'test@goestheweasel.com',
        'to'     => 'marc@fastmail.com',
    });

    milter_process({
        'desc'   => 'DMARC Reject',
        'prefix' => 'config/normal',
        'source' => 'dmarc_reject_case.eml',
        'dest'   => 'dmarc_reject_case.eml',
        'ip'     => '123.123.123.123',
        'name'   => 'bad.name.google.com',
        'from'   => 'test@goestheweasel.com',
        'to'     => 'marc@fastmail.com',
    });

    test_metrics( 'data/metrics/milter_1.json' );

    stop_milter();

    start_milter( 'config/dmarc_reject' );

    milter_process({
        'desc'   => 'DMARC Reject Hard',
        'prefix' => 'config/dmarc_reject',
        'source' => 'dmarc_reject.eml',
        'dest'   => 'dmarc_reject_hard.eml',
        'ip'     => '123.123.123.123',
        'name'   => 'bad.name.google.com',
        'from'   => 'test@goestheweasel.com',
        'to'     => 'marc@fastmail.com',
    });

    milter_process({
        'desc'   => 'DKIM/SPF Fail Hard',
        'prefix' => 'config/dmarc_reject',
        'source' => 'google_apps_bad.eml',
        'dest'   => 'google_apps_bad_spf_fail_hard.eml',
        'ip'     => '123.123.123.123',
        'name'   => 'bad.name.google.com',
        'from'   => 'marc@marcbradshaw.net',
        'to'     => 'marc@fastmail.com',
    });

    milter_process({
        'desc'   => 'DMARC Reject Hard Whitelisted',
        'prefix' => 'config/dmarc_reject',
        'source' => 'dmarc_reject.eml',
        'dest'   => 'dmarc_reject_hard_whitelisted.eml',
        'ip'     => '99.123.123.123',
        'name'   => 'bad.name.google.com',
        'from'   => 'test@goestheweasel.com',
        'to'     => 'marc@fastmail.com',
    });

    test_metrics( 'data/metrics/milter_2.json' );

    stop_milter();

    start_milter( 'config/dmarc_reject_wl' );

    milter_process({
        'desc'   => 'DMARC Reject DKIM Whitelisted',
        'prefix' => 'config/dmarc_reject_wl',
        'source' => 'dmarc_reject_wl.eml',
        'dest'   => 'dmarc_reject_wl.eml',
        'ip'     => '123.123.123.123',
        'name'   => 'bad.name.google.com',
        'from'   => 'marc@marcbradshaw.net',
        'to'     => 'marc@fastmail.com',
    });

    test_metrics( 'data/metrics/milter_3.json' );

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

    test_metrics( 'data/metrics/milter_4.json' );

    stop_milter();

    return;
}

sub run_milter_processing_spam {

    start_milter( 'config/spam' );

    milter_process({
        'desc'   => 'Gtube',
        'prefix' => 'config/spam',
        'source' => 'gtube.eml',
        'dest'   => 'gtube.eml',
        'ip'     => '74.125.82.171',
        'name'   => 'mail-we0-f171.google.com',
        'from'   => 'marc@marcbradshaw.net',
        'to'     => 'marc@fastmail.com',
    });

    test_metrics( 'data/metrics/milter_spam_1.json' );

    stop_milter();

    return;
}

sub run_smtp_processing {

    start_milter( 'config/normal.smtp' );

    smtp_process_multi({
        'desc'   => 'Pipelined messages',
        'prefix' => 'config/normal.smtp',
        'source' => [ 'transparency.eml', 'google_apps_good.eml','google_apps_bad.eml', ],
        'dest'   => 'pipelined.smtp.eml',
        'ip'     => [ '1.2.3.4', '127.0.0.1', '123.123.123.123', ],
        'name'   => [ 'test.example.com', 'localhost', 'bad.name.google.com', ],
        'from'   => [ 'test@example.com', 'marc@marcbradshaw.net', 'marc@marcbradshaw.net', ],
        'to'     => [ 'test@example.com', 'marc@fastmail.com', 'marc@fastmail.com', ],
        'filter' => [10,11,52,53,128,129],
    });

    smtp_process_multi({
        'desc'   => 'Pipelined messages limit',
        'prefix' => 'config/normal.smtp',
        'source' => [ 'transparency.eml', 'google_apps_good.eml', 'google_apps_bad.eml', 'transparency.eml', 'google_apps_good.eml','google_apps_bad.eml', ],
        'dest'   => 'pipelined.limit.smtp.eml',
        'ip'     => [ '1.2.3.4', '127.0.0.1', '123.123.123.123', '1.2.3.4', '127.0.0.1', '123.123.123.123', ],
        'name'   => [ 'test.example.com', 'localhost', 'bad.name.google.com', 'test.example.com', 'localhost', 'bad.name.google.com', ],
        'from'   => [ 'test@example.com', 'marc@marcbradshaw.net', 'marc@marcbradshaw.net', 'test@example.com', 'marc@marcbradshaw.net', 'marc@marcbradshaw.net', ],
        'to'     => [ 'test@example.com', 'marc@fastmail.com', 'marc@fastmail.com', 'test@example.com', 'marc@fastmail.com', 'marc@fastmail.com', ],
        'filter' => [10,11,52,53,128,129,209,210],
    });

    smtp_process({
        'desc'   => 'Spammy headers message',
        'prefix' => 'config/normal.smtp',
        'source' => 'spam_headers.eml',
        'dest'   => 'spam_headers.smtp.eml',
        'ip'     => '1.2.3.4',
        'name'   => 'test.example.com',
        'from'   => 'test@example.com',
        'to'     => 'test@example.com',
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
        'from'   => '<marc@marcbradshaw.net> BODY=8BITMIME',
        'to'     => 'marc@fastmail.com',
    });

    smtp_process({
        'desc'   => 'List message',
        'prefix' => 'config/normal.smtp',
        'source' => 'list.eml',
        'dest'   => 'list.smtp.eml',
        'ip'     => '1.2.3.4',
        'name'   => 'test.example.com',
        'from'   => 'test@example.com',
        'to'     => 'test@example.com',
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
        'desc'   => 'Good message dkim case',
        'prefix' => 'config/normal.smtp',
        'source' => 'google_apps_good_case.eml',
        'dest'   => 'google_apps_good_case.local.smtp.eml',
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
        'ip'     => '123.123.12.3',
        'name'   => 'mx4.twofiftyeight.ltd.uk',
        'from'   => 'marc@marcbradshaw.net',
        'to'     => 'marc@fastmail.com',
    });

    smtp_process({
        'desc'   => 'Good message no from',
        'prefix' => 'config/normal.smtp',
        'source' => 'google_apps_good.eml',
        'dest'   => 'google_apps_good_nofrom.smtp.eml',
        'ip'     => '74.125.82.171',
        'name'   => 'marcbradshaw.net',
        'from'   => '',
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
        'desc'   => 'DKIM Fail Domain Space',
        'prefix' => 'config/normal.smtp',
        'source' => 'google_apps_bad_space.eml',
        'dest'   => 'google_apps_bad_space.smtp.eml',
        'ip'     => '74.125.82.171',
        'name'   => 'mail-we0-f171.google.com',
        'from'   => 'marc@ marcbradshaw.net',
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

    smtp_process({
        'desc'   => 'Long Lines',
        'prefix' => 'config/normal.smtp',
        'source' => 'longlines.eml',
        'dest'   => 'longlines.smtp.eml',
        'ip'     => '74.125.82.171',
        'name'   => 'mail-we0-f171.google.com',
        'from'   => 'marc@marcbradshaw.net',
        'to'     => 'marc@fastmail.com',
    });

    smtp_process({
        'desc'   => 'DMARC Reject',
        'prefix' => 'config/normal.smtp',
        'source' => 'dmarc_reject.eml',
        'dest'   => 'dmarc_reject.smtp.eml',
        'ip'     => '123.123.123.123',
        'name'   => 'bad.name.google.com',
        'from'   => 'test@goestheweasel.com',
        'to'     => 'marc@fastmail.com',
    });

    smtp_process({
        'desc'   => 'DMARC Reject',
        'prefix' => 'config/normal.smtp',
        'source' => 'dmarc_reject_case.eml',
        'dest'   => 'dmarc_reject_case.smtp.eml',
        'ip'     => '123.123.123.123',
        'name'   => 'bad.name.google.com',
        'from'   => 'test@goestheweasel.com',
        'to'     => 'marc@fastmail.com',
    });

    test_metrics( 'data/metrics/smtp_1.json' );

    stop_milter();

    start_milter( 'config/dmarc_reject.smtp' );

    smtp_process({
        'desc'   => 'DMARC Reject Hard',
        'prefix' => 'config/dmarc_reject.smtp',
        'source' => 'dmarc_reject.eml',
        'dest'   => 'dmarc_reject_hard.smtp.eml',
        'ip'     => '123.123.123.123',
        'name'   => 'bad.name.google.com',
        'from'   => 'test@goestheweasel.com',
        'to'     => 'marc@fastmail.com',
        'eom_expect' => '550',
        'no_cat' => 1,
    });

    smtp_process({
        'desc'   => 'DKIM/SPF Fail Hard',
        'prefix' => 'config/dmarc_reject.smtp',
        'source' => 'google_apps_bad.eml',
        'dest'   => 'google_apps_bad_spf_fail_hard.smtp.eml',
        'ip'     => '123.123.123.123',
        'name'   => 'bad.name.google.com',
        'from'   => 'marc@marcbradshaw.net',
        'to'     => 'marc@fastmail.com',
    });

    smtp_process({
        'desc'   => 'DMARC Reject Hard Whitelisted',
        'prefix' => 'config/dmarc_reject.smtp',
        'source' => 'dmarc_reject.eml',
        'dest'   => 'dmarc_reject_hard_whitelisted.smtp.eml',
        'ip'     => '99.123.123.123',
        'name'   => 'bad.name.google.com',
        'from'   => 'test@goestheweasel.com',
        'to'     => 'marc@fastmail.com',
    });

    test_metrics( 'data/metrics/smtp_2.json' );

    stop_milter();

    start_milter( 'config/dmarc_reject_wl.smtp' );

    smtp_process({
        'desc'   => 'DMARC Reject DKIM Whitelisted',
        'prefix' => 'config/dmarc_reject_wl.smtp',
        'source' => 'dmarc_reject_wl.eml',
        'dest'   => 'dmarc_reject_wl.smtp.eml',
        'ip'     => '123.123.123.123',
        'name'   => 'bad.name.google.com',
        'from'   => 'marc@marcbradshaw.net',
        'to'     => 'marc@fastmail.com',
    });

    test_metrics( 'data/metrics/smtp_3.json' );

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

    test_metrics( 'data/metrics/smtp_4.json' );

    stop_milter();

    return;
}

sub smtpput {
    my ( $args ) = @_;

    my $mailer_name  = $args->{'mailer_name'};

    my $mail_file_a  = $args->{'mail_file'};
    my $mail_from_a  = $args->{'mail_from'};
    my $rcpt_to_a    = $args->{'rcpt_to'};
    my $x_name_a     = $args->{'connect_name'};
    my $x_addr_a     = $args->{'connect_ip'};
    my $x_helo_a     = $args->{'helo_host'};

    my $sock_type    = $args->{'sock_type'};
    my $sock_path    = $args->{'sock_path'};
    my $sock_host    = $args->{'sock_host'};
    my $sock_port    = $args->{'sock_port'};

    my $eom_expect   = $args->{'eom_expect'} || '250';

    my $sock;
    if ( $sock_type eq 'inet' ) {
       $sock = IO::Socket::INET->new(
            'Proto' => 'tcp',
            'PeerAddr' => $sock_host,
            'PeerPort' => $sock_port,
        ) || die "could not open outbound SMTP socket: $!";
    }
    elsif ( $sock_type eq 'unix' ) {
       $sock = IO::Socket::UNIX->new(
            'Peer' => $sock_path,
        ) || die "could not open outbound SMTP socket: $!";
    }

    my $line = <$sock>;

    if ( ! $line =~ /250/ ) {
        die "Unexpected SMTP response $line";
        return 0;
    }

    send_smtp_packet( $sock, 'EHLO ' . $mailer_name,       '250' ) || die;

    my $first_time = 1;

    while ( @$mail_from_a ) {

        if ( ! $first_time ) {
            if ( ! send_smtp_packet( $sock, 'RSET', '250' ) ) {
                $sock->close();
                return;
            };
        }
        $first_time = 0;

        my $mail_file = shift @$mail_file_a;
        my $mail_from = shift @$mail_from_a;
        my $rcpt_to   = shift @$rcpt_to_a;
        my $x_name    = shift @$x_name_a;
        my $x_addr    = shift @$x_addr_a;
        my $x_helo    = shift @$x_helo_a;

        my $mail_data = q{};

        if ( $mail_file eq '-' ) {
            while ( my $l = <> ) {
                $mail_data .= $l;
            }
        }
        else {
            if ( ! -e $mail_file ) {
                die "Mail file $mail_file does not exist";
            }
            open my $inf, '<', $mail_file;
            my @all = <$inf>;
            $mail_data = join( q{}, @all );
            close $inf;
        }

        $mail_data =~ s/\015?\012/\015\012/g;
        # Handle transparency
        $mail_data =~ s/\015\012\./\015\012\.\./g;

        send_smtp_packet( $sock, 'XFORWARD NAME=' . $x_name,   '250' ) || die;
        send_smtp_packet( $sock, 'XFORWARD ADDR=' . $x_addr,   '250' ) || die;
        send_smtp_packet( $sock, 'XFORWARD HELO=' . $x_helo,   '250' ) || die;

        send_smtp_packet( $sock, 'MAIL FROM:' . $mail_from, '250' ) || die;
        send_smtp_packet( $sock, 'RCPT TO:' .   $rcpt_to,   '250' ) || die;
        send_smtp_packet( $sock, 'DATA',                    '354' ) || die;

        print $sock $mail_data;
        print $sock "\r\n";

        send_smtp_packet( $sock, '.',    $eom_expect ) || return 0;

    }

    send_smtp_packet( $sock, 'QUIT', '221' ) || return 0;
    $sock->close();

    return 1;
}

sub send_smtp_packet {
    my ( $socket, $send, $expect ) = @_;
    print $socket "$send\r\n";
    my $recv = <$socket>;
    while ( $recv =~ /^\d\d\d\-/ ) {
        $recv = <$socket>;
    }
    if ( $recv =~ /^$expect/ ) {
        return 1;
    }
    else {
        warn "SMTP Send expected $expect received $recv when sending $send";
        return 0;
    }
}

sub smtpcat {
    my ( $args ) = @_;

    my $cat_pid = fork();
    die "unable to fork: $!" unless defined($cat_pid);
    return $cat_pid if $cat_pid;

    my $sock_type = $args->{'sock_type'};
    my $sock_path = $args->{'sock_path'};
    my $sock_host = $args->{'sock_host'};
    my $sock_port = $args->{'sock_port'};

    my $remove = $args->{'remove'};
    my $output = $args->{'output'};

    my @out_lines;

    my $sock;
    if ( $sock_type eq 'inet' ) {
       $sock = IO::Socket::INET->new(
            'Listen'    => 5,
            'LocalHost' => $sock_host,
            'LocalPort' => $sock_port,
            'Protocol'  => 'tcp',
        ) || die "could not open socket: $!";
    }
    elsif ( $sock_type eq 'unix' ) {
       $sock = IO::Socket::UNIX->new(
            'Listen'    => 5,
            'Local' => $sock_path,
        ) || die "could not open socket: $!";
    }

    my $accept = $sock->accept();

    print $accept "220 smtp.cat ESMTP Test\r\n";

    local $SIG{'ALRM'} = sub{ die "Timeout\n" };
    alarm( 60 );

    my $quit = 0;
    while ( ! $quit ) {
        my $command = <$accept> || { $quit = 1 };
        alarm( 60 );

        if ( $command =~ /^HELO/ ) {
            push @out_lines, $command;
            print $accept "250 HELO Ok\r\n";
        }
        elsif ( $command =~ /^EHLO/ ) {
            push @out_lines, $command;
            print $accept "250 EHLO Ok\r\n";
        }
        elsif ( $command =~ /^MAIL/ ) {
            push @out_lines, $command;
            print $accept "250 MAIL Ok\r\n";
        }
        elsif ( $command =~ /^XFORWARD/ ) {
            push @out_lines, $command;
            print $accept "250 XFORWARD Ok\r\n";
        }
        elsif ( $command =~ /^RCPT/ ) {
            push @out_lines, $command;
            print $accept "250 RCPT Ok\r\n";
        }
        elsif ( $command =~ /^RSET/ ) {
            push @out_lines, $command;
            print $accept "250 RSET Ok\r\n";
        }
        elsif ( $command =~ /^DATA/ ) {
            push @out_lines, $command;
            print $accept "354 Send\r\n";
            DATA:
            while ( my $line = <$accept> ) {
                alarm( 60 );
                push @out_lines, $line;
                last DATA if $line eq ".\r\n";
                # Handle transparency
                if ( $line =~ /^\./ ) {
                    $line = substr( $line, 1 );
                }
            }
            print $accept "250 DATA Ok\r\n";
        }
        elsif ( $command =~ /^QUIT/ ) {
            push @out_lines, $command;
            print $accept "221 Bye\r\n";
            $quit = 1;
        }
        else {
            push @out_lines, $command;
            print $accept "250 Unknown Ok\r\n";
        }
    }

    open my $file, '>', $output;
    my $i = 0;
    foreach my $line ( @out_lines ) {
        $i++;
        $line = "############\n" if grep { $i == $_ } @$remove;
        print $file $line;
    }
    close $file;

    $accept->close();
    $sock->close();

    exit 0;
}

sub client {
    my ( $args ) = @_;
    my $pid = fork();
    die "unable to fork: $!" unless defined($pid);
    if ( ! $pid ) {

        my $output = $args->{'output'};
        delete $args->{'output'};

        $Mail::Milter::Authentication::Config::PREFIX = $args->{'prefix'};
        delete $args->{'prefix'};
        $args->{'testing'} = 1;

        my $client = Mail::Milter::Authentication::Client->new( $args );

        $client->process();

        open my $file, '>', $output;
        print $file $client->result();
        close $file;
        exit 0;

    }
    waitpid( $pid, 0 );
    return;
}

1;
