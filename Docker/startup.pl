#!/usr/bin/env perl

use strict;
use warnings;
use English qw{ -no_match_vars };
use Mail::DMARC;
use Mail::DMARC::Report;
use Mail::Milter::Authentication::Config qw{ get_config };

# Setup perlbrew environment
our $perl_bin  = $EXECUTABLE_NAME;
our $perl_path = $perl_bin;
$perl_path =~ s/\/[^\/]*$//;
my $PATH = $ENV{'PATH'};
$ENV{'PATH'} = "$perl_path:$PATH";

# Setup signal handlers
our $PARENT_PID = $PID;
our $CHILDREN = {};
sub handle_shutdown {
    exit 0 if $PID != $PARENT_PID;
    out( 'Exiting' );
    kill( 'INT', $CHILDREN->{'milter'} ) if exists $CHILDREN->{'milter'};
    kill( 'INT', $CHILDREN->{'cron'} ) if exists $CHILDREN->{'milter'};
    foreach my $process ( keys %$CHILDREN ) {
        out( "Waiting for $process" );
        waitpid( $CHILDREN->{$process}, 0 );
    }
    exit 0;
}
sub handle_reload {
    exit 0 if $PID != $PARENT_PID;
    out( 'Reloading' );
    kill( 'INT', $CHILDREN->{'milter'} ) if exists $CHILDREN->{'milter'};
    return;
}
local $SIG{ 'INT' }     = \&handle_shutdown;
local $SIG{ '__DIE__' } = \&handle_shutdown;
local $SIG{ 'TERM' }    = \&handle_shutdown;
local $SIG{ 'HUP' }     = \&handle_reload;

# Setup DMARC
my $config = get_config();
if ( grep /DMARC/, @{ $config->{'load_handlers'} } ) {
    out( 'Initialising DMARC environment' );
    my $dmarc = Mail::DMARC->new();
    dmarc_check_psl_file( $dmarc );
    dmarc_setup_cron( $perl_bin );

    if ( ! $config->{'handlers'}->{'DMARC'}->{'no_report'} ) {
        # We want to save reports, so we need a database!
        dmarc_check_db_connection();
        dmarc_check_db_structure();
        #dmarc_init_db_structure();
    }

}

# Start Authentication Milter
start_authentication_milter();

# Done


sub start_authentication_milter {
    my $start_time;
    my $quick_restart_count = 0;
    while(1) {
        $start_time = time;

        my $milter_pid = fork();
        die "unable to fork: $!" unless defined($milter_pid);
        if (!$milter_pid) {
            exec('authentication_milter', '--pidfile', '/var/run/authentication_milter.pid');
            exit 0;
        }
        $CHILDREN->{'milter'} = $milter_pid;
        waitpid( $milter_pid,0 );
        delete $CHILDREN->{'milter'};

        out( 'Server exited, restarting...' );
        if ( $start_time > ( time - 60 ) ) {
            if ( $quick_restart_count++ > 4 ) {
                out( 'Problems restarting daemon, exiting.' );
                die;
            }
            out( 'Last start time was within the last minute, delaying restart...' );
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
        out( 'Downloading PSL file' );
        open my $h, '>', $psl_file;
        close $h;
        my $time = time()-2592000;
        utime($time,$time,$psl_file);
        $dmarc->update_psl_file();
    }
    return;
}

sub dmarc_setup_cron {
    my ( $perl_bin ) = @_;
    # Setup cron for updating PSL file
    out( 'Setting up PSL update cron job' );

    my $cron_pid = fork();
    die "unable to fork: $!" unless defined($cron_pid);
    if (!$cron_pid) {
        exec('cron', '-f');
        exit 0;
    }
    $CHILDREN->{'cron'} = $cron_pid;
        
    open my $cron, '|-', 'crontab';
    print $cron "0 0 * * 0 $perl_bin dmarc_update_public_suffix_list --random\n";
    close $cron;
    return;
}

sub dmarc_check_db_connection {
    out( 'Checking database connection' );
    my $backend = Mail::DMARC::Report->new()->store()->backend();
    eval {
        $backend->db_connect();
    };
    if ( my $error = $@ ) {
        out( "Could not connect to database:\n$error" );
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

sub out {
    my ( $msg ) = @_;
    my @parts = split "\n", $msg;
    foreach my $part ( @parts ) {
        next if $part eq q{};
        print scalar localtime . " startup[$PID] $part\n";
    }
    return;
}

