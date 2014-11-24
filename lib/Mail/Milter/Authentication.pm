package Mail::Milter::Authentication;

use strict;
use warnings;

our $VERSION = 0.3;

use English;
use Mail::Milter::Authentication::Config qw{ get_config };
use Mail::Milter::Authentication::Dispatcher;
use Mail::Milter::Authentication::Handler;
use Mail::Milter::Authentication::Util qw{ loginfo };
use Proc::Daemon;
use Sendmail::PMilter qw { :all };

sub start {
    my ( $args ) = @_;
    my $CONFIG = get_config();
    my $connection = $args->{ 'connection' } || die ('No connection details given');
    my $pid_file   = $args->{ 'pid_file' };

    # CONCURRENCY CHECKING
    # Cannot use a simple lock due to the way PMilter works.
    if ( -e $pid_file ) {
        open my $pidf, '<', $pid_file;
        my $pid = <$pidf>;
        close $pidf;
        $pid += 0;
        if ( $pid ne q{} ) {
            my $proc = '/proc/' . $pid;
            if ( -e $proc ) {
                die "Process already running";
            }
        }
    }

    # Drop Privs
    my $runas = $CONFIG->{'runas'} || die "No runas user defined"; 
    my $uid = getpwnam( $runas ) || die "Could not find user $runas";

    # Open PID File
    {
        # Check we can before we daemonize
        my $pidf;
        open $pidf, '>>', $pid_file or die 'Could not open PID file';
        close $pidf;
    }

    # Daemonise
    if ( $args->{'daemon'} ) {
        loginfo( 'daemonizing' );
        my $daemon = Proc::Daemon->new();
        $daemon->Init();
    }

    my $callbacks = {
      'connect' => \&Mail::Milter::Authentication::Handler::connect_callback,
      'helo'    => \&Mail::Milter::Authentication::Handler::helo_callback,
      'envfrom' => \&Mail::Milter::Authentication::Handler::envfrom_callback,
      'envrcpt' => \&Mail::Milter::Authentication::Handler::envrcpt_callback,
      'header'  => \&Mail::Milter::Authentication::Handler::header_callback,
      'eoh'     => \&Mail::Milter::Authentication::Handler::eoh_callback,
      'body'    => \&Mail::Milter::Authentication::Handler::body_callback,
      'eom'     => \&Mail::Milter::Authentication::Handler::eom_callback,
      'abort'   => \&Mail::Milter::Authentication::Handler::abort_callback,
      'close'   => \&Mail::Milter::Authentication::Handler::close_callback,
    };

    # PID
    {
        my $pidf;
        open $pidf, '>', $pid_file or die 'Could not open PID file';
        my $pid = $PID;
        print $pidf $pid;
        close $pidf;
    }

    my $listen_backlog         = $CONFIG->{'listen_backlog'}         || 20;

    #Sendmail::PMilter::setdbg( 9 );
    my $milter = Sendmail::PMilter->new();
    $milter->set_dispatcher(
        Mail::Milter::Authentication::Dispatcher::get_dispatcher()
    );
    loginfo( 'setting connection backlog to ' . $listen_backlog );
    $milter->set_listen( $listen_backlog );
    $milter->setconn( $connection ) or die "Could not open connection $connection\n";
    $milter->register( "authentication_milter", $callbacks, SMFI_CURR_ACTS );

    loginfo( 'listening on ' . $connection );

    # Drop Privs
    $> = $uid;
    if ( $> != $uid ) {
        loginfo( 'could not drop privs - bailing' );
        exit 1;
    }
    loginfo( 'privs dropped - starting up' );

    $milter->main();

    # Never reaches here, callbacks are called from Milter.
    loginfo( 'something went horribly wrong' );
    die 'Something went horribly wrong';
}

1;

__END__

=head1 NAME

Mail::Milter::Authentication - A PERL Mail Authentication Milter

=head1 DESCRIPTION

A PERL implemtation of email authentication standards rolled up into a single easy to use milter.

