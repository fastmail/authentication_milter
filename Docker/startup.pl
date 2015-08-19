#!/usr/bin/env perl

use strict;
use warnings;
use Mail::DMARC;
use Mail::DMARC::Report;
use Mail::Milter::Authentication::Config qw{ get_config };

my $config = get_config();
my $perl_version = $ENV{'PERLBREW_PERL'};

if ( grep /DMARC/, @{ $config->{'load_handlers'} } ) {
    print "Initialising DMARC environment\n";
    my $dmarc = Mail::DMARC->new();
    dmarc_check_psl_file( $dmarc );
    dmarc_setup_cron( $perl_version );

    if ( ! $config->{'handlers'}->{'DMARC'}->{'no_report'} ) {
        # We want to save reports, so we need a database!
        dmarc_check_db_connection();
        dmarc_check_db_structure();
        #dmarc_init_db_structure();
    }

}

start_authentication_milter();



sub start_authentication_milter {
    my $start_time;
    my $quick_restart_count = 0;
    while(1) {
        $start_time = time;
        system('authentication_milter --pidfile /var/run/authentication_milter.pid');

        print "Server exited, restarting...\n";
        if ( $start_time > ( time - 60 ) ) {
            if ( $quick_restart_count++ > 4 ) {
                print "Problems restarting daemon, exiting.";
                die;
            }
            print "Last start time was within the last minute, delaying restart...\n";
            sleep 10;
        }
        else {
            $quick_restart_count = 0;
        }
    }
    return;
}

sub dmarc_check_psl_file {
    my ( $dmarc ) = @_;
    my $psl_file = $dmarc->config->{dns}{public_suffix_list};
    $psl_file = $dmarc->find_psl_file if ! $psl_file;
    if ( ! -e $psl_file ) {
        print "Downloading PSL file\n";
        open my $h, '>', $psl_file;
        close $h;
        my $time = time()-2592000;
        utime($time,$time,$psl_file);
        $dmarc->update_psl_file();
    }
    return;
}

sub dmarc_setup_cron {
    my ( $perl_version ) = @_;
    # Setup cron for updating PSL file
    print "Setting up PSL update cron job\n";
    system('cron -f &');
    open my $cron, '|-', 'crontab';
    print $cron "0 0 * * 0 perlbrew exec --with $perl_version dmarc_update_public_suffix_list --random\n";
    close $cron;
    return;
}

sub dmarc_check_db_connection {
    print "Checking database connection\n";
    my $backend = Mail::DMARC::Report->new()->store()->backend();
    eval {
        $backend->db_connect();
    };
    if ( my $error = $@ ) {
        print "Could not connect to database:\n$error\n";
        die;
    }
    return;
}

sub dmarc_check_db_structure {
    return;
}

sub dmarc_init_db_structure {
    # ToDo init database
    #my $dsn = $backend->config->{report_store}{dsn};
    #my $type;
    #if    ( $dsn =~ /^dbi:mysql:/i  ) { $type = 'mysql';  }
    #elsif ( $dsn =~ /^dbi:sqlite:/i ) { $type = 'sqlite'; }
    #else  { die "Unknown database type\n"; }
    #my $schema = 'mail_dmarc_schema.' . $type;
    #my $schema_file = $backend->get_db_schema($schema);
    return;
}

