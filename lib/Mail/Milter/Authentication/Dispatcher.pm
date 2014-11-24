package Mail::Milter::Authentication::Dispatcher;

use strict;
use warnings;

our $VERSION = 0.3;

use Mail::Milter::Authentication::Config qw{ get_config };
use Mail::Milter::Authentication::Util qw{ loginfo };

sub get_dispatcher {
    my $CONFIG = get_config();
    my $dispatcher = $CONFIG->{'dispatcher'} || 'postfork';
    my $max_children           = $CONFIG->{'max_children'}           || 20;
    my $max_requests_per_child = $CONFIG->{'max_requests_per_child'} || 200;

    my $dispatcher_method;

    if ( $dispatcher eq 'prefork' ) {
        loginfo( 'Using prefork dispatcher' );
        $dispatcher_method = Sendmail::PMilter::prefork_dispatcher(
            'max_children'           => $max_children,
            'max_requests_per_child' => $max_requests_per_child,
        );
    }
    elsif ( $dispatcher eq 'postfork' ) { 
        loginfo( 'Using postfork dispatcher' );
        $dispatcher_method = Sendmail::PMilter::postfork_dispatcher();
    }
    elsif ( $dispatcher eq 'ithread' ) { 
        #$dispatcher_method = Sendmail::PMilter::ithread_dispatcher();
        loginfo( 'Using ithread dispatcher' );
        $dispatcher_method = ithread_dispatcher();
    }
    elsif ( $dispatcher eq 'sequential' ) { 
        loginfo( 'Using sequential dispatcher' );
        $dispatcher_method = Sendmail::PMilter::sequential_dispatcher();
    }
    else {
        loginfo( 'Unknown dispatcher - bailing' );
        die 'Unknown dispatcher method';
    } 

    return $dispatcher_method;
}

sub ithread_dispatcher {
	require threads;
	require threads::shared;

	my $nchildren = 0;

	threads::shared::share(\$nchildren);

	sub {
		my $this = shift;
		my $lsocket = shift;
		my $handler = shift;
		my $maxchildren = $this->get_max_interpreters();

		my $siginfo = exists($SIG{INFO}) ? 'INFO' : 'USR1';
		local $SIG{$siginfo} = sub {
			warn "Number of active children: $nchildren\n";
		};

		my $child_sub = sub {
			my $socket = shift;

			eval {
				&$handler($socket);
				$socket->close();
			};
			my $died = $@;

			lock($nchildren);
			$nchildren--;
			warn $died if $died;
		};

		while (1) {
			my $socket = $lsocket->accept();
			next if $!{EINTR};

			warn "$$: incoming connection\n" if ($Sendmail::PMilter::DEBUG > 0);

			# If the load's too high, fail and go back to top of loop.
			if ($maxchildren) {
				my $cnchildren = $nchildren; # make constant

				if ($cnchildren >= $maxchildren) {
					warn "load too high: children $cnchildren >= max $maxchildren";

					$socket->autoflush(1);
					$socket->print(pack('N/a*', 't')); # SMFIR_TEMPFAIL
					$socket->close();
					next;
				}
			}

			# scoping block for lock()
			{
				lock($nchildren);

				die "thread creation failed: $!\n"
					unless (threads->create($child_sub, $socket));

				threads->yield();
				$nchildren++;
			}
		}
	};

}

1;
