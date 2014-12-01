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
    my $listen_backlog = $CONFIG->{'listen_backlog'} || 20;
    my $max_children           = $CONFIG->{'max_children'} || 100;
    my $max_requests_per_child = $CONFIG->{'max_requests_per_child'} || 200;
    my $min_children           = $CONFIG->{'min_children'} || 20;
    my $max_spare_children     = $CONFIG->{'max_spare_children'} || 20;
    my $min_spare_children     = $CONFIG->{'min_spare_children'} || 10;

    my %args;

    $args{'no_client_stdout'} = 1;

    if ( $args->{'daemon'} ) {
        if ( $> == 0 ) {
            loginfo(
                join( ' ',
                    'daemonize',
                    "servers=$min_children/$max_children",
                    "spares=$min_spare_children/$max_spare_children",
                    "requests=$max_requests_per_child",
                )
            );
            $args{'background'} = 1;
            $args{'setsid'} = 1;
            $args{'pid_file'} = $pid_file;
            $args{'max_servers'} = $max_children;
            $args{'max_requests'} = $max_requests_per_child;
            $args{'min_servers'} = $min_children;
            $args{'min_spare_servers'} = $min_spare_children;
            $args{'max_spare_servers'} = $max_spare_children;
        }
        else {
            loginfo('Not running as root, daemonize ignored!');
        }
    }

    if ( $> == 0 ) {
        my $user  = $CONFIG->{'runas'}    || 'nobody';
        my $group = $CONFIG->{'rungroup'} || 'nogroup'; 
        loginfo("run as user=$user group=$group");
        $args{'user'}  = $user;
        $args{'group'} = $group;
    }
    else {
        loginfo('Not running as root, could not drop privs - be careful!');
    }

    {
        $connection =~ /^([^:]+):([^:@]+)(?:@([^:@]+|\[[0-9a-f:\.]+\]))?$/;
        my $type = $1;
        my $path = $2;
        my $host = $3 || q{};
        if ( $type eq 'inet' ) {
            loginfo(
                join( ' ',
                    'listen on inet',
                    "host=$host",
                    "port=$path",
                    "backlog=$listen_backlog"
                )
            );
            $args{'host'} = $host;
            $args{'port'} = $path;
            $args{'ipv'}  = '*';
            $args{'proto'} = 'tcp';
            $args{'listen'} = $listen_backlog;
        }
        elsif ( $type eq 'unix' ) {
            loginfo(
                join( ' ',
                    'listening on unix',
                    "socket=$path",
                    "backlog=$listen_backlog",
                )
            );
            $args{'port'} = $path;
            $args{'proto'} = 'unix';
            $args{'listen'} = $listen_backlog;
#            my $socketperms = $CONFIG->{'socketperms'};
#            if ($socketperms) {
#                chmod oct($socketperms), $path;
#                loginfo( 'setting socket permissions to ' . $socketperms );
#            }
        }
        else {
            die 'Invalid connection';
        }
    }

    $PROGRAM_NAME = '[authentication_milter]';

    warn "\nStarting server\n";
    __PACKAGE__->run( %args );

    # Never reaches here.
    loginfo('something went horribly wrong');
    die 'Something went horribly wrong';
}

1;

__END__

=head1 NAME

Mail::Milter::Authentication - A PERL Mail Authentication Milter

=head1 DESCRIPTION

A PERL implemtation of email authentication standards rolled up into a single easy to use milter.

