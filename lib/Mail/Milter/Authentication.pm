package Mail::Milter::Authentication;

use strict;
use warnings;

our $VERSION = 0.4;

use base 'Net::Server::PreFork';

use English;
use Mail::Milter::Authentication::Config qw{ get_config };
use Mail::Milter::Authentication::Protocol::Wire;
use Mail::Milter::Authentication::Util qw{ loginfo };

sub process_request {
    my ( $self ) = @_;
    my $socket = $self->{server}->{client};
    my $wire = Mail::Milter::Authentication::Protocol::Wire->new( $socket );
    $wire->main();
}

sub start {
    my ($args)     = @_;
    my $CONFIG     = get_config();
    my $connection = $args->{'connection'}
      || die('No connection details given');
    my $pid_file = $args->{'pid_file'};

    my %args;
    $args{'port'} = 12345;

    __PACKAGE__->run( %args );

#    check_pid_file($pid_file);
#
#    my $listen_backlog = $CONFIG->{'listen_backlog'} || 20;
#
#    #Sendmail::PMilter::setdbg( 9 );
#    my $milter = Sendmail::PMilter->new();
#    $milter->set_dispatcher(
#        Mail::Milter::Authentication::Dispatcher::get_dispatcher() );
#    loginfo( 'setting connection backlog to ' . $listen_backlog );
#    $milter->set_listen($listen_backlog);
#    $milter->setconn($connection)
#      or die "Could not open connection $connection\n";
#    $milter->register( "authentication_milter", $callbacks, SMFI_CURR_ACTS );
#
#    loginfo( 'listening on ' . $connection );
#
#    {
#        $connection =~ /^([^:]+):([^:@]+)(?:@([^:@]+|\[[0-9a-f:\.]+\]))?$/;
#        my $type = $1;
#        my $path = $2;
#        if ( $type eq 'unix' ) {
#            my $socketperms = $CONFIG->{'socketperms'};
#            if ($socketperms) {
#                chmod oct($socketperms), $path;
#                loginfo( 'setting socket permissions to ' . $socketperms );
#            }
#        }
#    }
#
#    # Daemonise
#    if ( $args->{'daemon'} ) {
#        my $runas    = $CONFIG->{'runas'}    || 'nobody';
#        my $rungroup = $CONFIG->{'rungroup'} || 'nogroup';
#        loginfo('daemonizing');
#        daemonize( $runas, $rungroup, $pid_file, );
#    }
#    else {
#        # Drop Privs
#        my $runas = $CONFIG->{'runas'};
#        if ($runas) {
#            my $uid = getpwnam($runas) || die "Could not find user $runas";
#            $> = $uid;
#            if ( $> != $uid ) {
#                loginfo('could not drop privs - bailing');
#                exit 1;
#            }
#            loginfo('privs dropped - starting up');
#        }
#        else {
#            loginfo('running as logged in user - please be careful');
#        }
#    }
#
#    $milter->main();

    # Never reaches here, callbacks are called from Milter.
    loginfo('something went horribly wrong');
    die 'Something went horribly wrong';
}

1;

__END__

=head1 NAME

Mail::Milter::Authentication - A PERL Mail Authentication Milter

=head1 DESCRIPTION

A PERL implemtation of email authentication standards rolled up into a single easy to use milter.

