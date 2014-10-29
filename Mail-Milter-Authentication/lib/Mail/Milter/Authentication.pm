package Mail::Milter::Authentication;

$VERSION = 0.1;

use strict;
use warnings;

use English;
use Mail::Milter::Authentication::Config qw{ get_config };
use Mail::Milter::Authentication::Handler;
use Proc::Daemon;
use Sendmail::PMilter qw { :all };

my $CONFIG = get_config();

sub start {
    my ( $args ) = @_;
    my $connection = $args->{ 'connection' } || die ('No connection details given');
    my $pid_file   = $args->{ 'pid_file' };

    # CONCURRENCY CHECKING
    # Cannot use a simple lock due to the way PMilter works.
    if ( -e $pid_file ) {
        open my $pidf, '<', $pid_file;
        my $pid = <$pidf>;
        close $pidf;
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

    #Sendmail::PMilter::setdbg( 9 );
    my $milter = Sendmail::PMilter->new();
    $milter->setconn( $connection ) or die "Could not open connection $connection\n";
    $milter->register( "authentication_milter", $callbacks, SMFI_CURR_ACTS );


    # Drop Privs
    $> = $uid;

    $milter->main();

    # Never reaches here, callbacks are called from Milter.
    die 'Something went wrong';
}

1;
