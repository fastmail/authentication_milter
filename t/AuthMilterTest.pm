package AuthMilterTest;

use strict;
use warnings;
use Test::More;
use Test::File::Contents;
use Cwd qw{ cwd };

use Mail::Milter::Authentication::Tester;

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

sub run_milter_processing {

    start_milter( 'config/timeout' );

    milter_process({
        'desc'   => 'Good message local',
        'prefix' => 'config/normal',
        'source' => 'google_apps_good.eml',
        'dest'   => 'google_apps_good.timeout.eml',
        'ip'     => '127.0.0.1',
        'name'   => 'localhost',
        'from'   => 'marc@marcbradshaw.net',
        'to'     => 'marc@fastmail.com',
    });

    test_metrics( 'data/metrics/milter_timeout.json' );

    stop_milter();

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

1;
