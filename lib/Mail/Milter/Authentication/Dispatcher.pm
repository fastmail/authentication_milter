package Mail::Milter::Authentication::Dispatcher;

use strict;
use warnings;

our $VERSION = 0.4;

use Mail::Milter::Authentication::Config qw{ get_config };
use Mail::Milter::Authentication::Util qw{ loginfo };

sub get_dispatcher {
    my $CONFIG                 = get_config();
    my $dispatcher             = $CONFIG->{'dispatcher'} || 'postfork';
    my $max_children           = $CONFIG->{'max_children'} || 20;
    my $max_requests_per_child = $CONFIG->{'max_requests_per_child'} || 200;

    my $dispatcher_method;

    if ( $dispatcher eq 'prefork' ) {
        loginfo('Using prefork dispatcher');
        $dispatcher_method = Sendmail::PMilter::prefork_dispatcher(
            'max_children'           => $max_children,
            'max_requests_per_child' => $max_requests_per_child,
        );
    }
    elsif ( $dispatcher eq 'postfork' ) {
        loginfo('Using postfork dispatcher');
        $dispatcher_method = Sendmail::PMilter::postfork_dispatcher();
    }
    elsif ( $dispatcher eq 'ithread' ) {
        loginfo('Using ithread dispatcher');
        $dispatcher_method = Sendmail::PMilter::ithread_dispatcher();
    }
    elsif ( $dispatcher eq 'sequential' ) {
        loginfo('Using sequential dispatcher');
        $dispatcher_method = Sendmail::PMilter::sequential_dispatcher();
    }
    else {
        loginfo('Unknown dispatcher - bailing');
        die 'Unknown dispatcher method';
    }
    return $dispatcher_method;

}

1;
