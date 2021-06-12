package Mail::Milter::Authentication::Handler;
use 5.20.0;
use strict;
use warnings;
use Mail::Milter::Authentication::Pragmas;
# ABSTRACT: Handler superclass
# VERSION
use Mail::Milter::Authentication::Exception;
use Mail::Milter::Authentication::Resolver;
use Date::Format qw{ time2str };
use Digest::MD5 qw{ md5_hex };
use List::MoreUtils qw{ uniq };
use Lock::File;
use MIME::Base64;
use Mail::SPF;
use Net::DNS::Resolver;
use Net::IP;
use Proc::ProcessTable;
use Sereal qw{encode_sereal decode_sereal};
use Sys::Hostname;
use Time::HiRes qw{ ualarm gettimeofday };

=head1 DESCRIPTION

Handle the milter requests and pass off to individual handlers

=cut

our $TestResolver; # For Testing

=constructor I<new( $thischild )>

my $object = Mail::Milter::Authentication::Handler->new( $thischild );

Takes the argument of the current Mail::Milter::Authentication object
and creates a new handler object.

=cut

sub new {
    my ( $class, $thischild ) = @_;
    my $self = {
        'thischild' => $thischild,
    };
    bless $self, $class;
    return $self;
}

=method I<get_version()>

Return the version of this handler

=cut

sub get_version {
    my ( $self ) = @_;
    {
        no strict 'refs'; ## no critic;
        return ${ ref( $self ) . "::VERSION" } // 'unknown'; # no critic;
    }
}

=metric_method I<get_json( $file )>

Return json data from external file

=cut

sub get_json {
    my ( $self, $file ) = @_;
    my $basefile = __FILE__;
    $basefile =~ s/Handler\.pm$/Handler\/$file/;
    $basefile .= '.json';
    if ( ! -e $basefile ) {
        die 'json file ' . $file . ' not found';
    }
    open my $InF, '<', $basefile;
    my @Content = <$InF>;
    close $InF;
    return join( q{}, @Content );
}

=metric_method I<metric_register( $id, $help )>

Register a metric type

=cut

sub metric_register {
    my ( $self, $id, $help ) = @_;
    $self->{'thischild'}->{'metric'}->register( $id, $help, $self->{'thischild'} );
}

=metric_method I<metric_count( $id, $labels, $count )>

Increment a metrics counter by $count (defaults to 1 if undef)

=cut

sub metric_count {
    my ( $self, $count_id, $labels, $count ) = @_;
    $labels = {} if ! defined $labels;
    $count = 1 if ! defined $count;

    my $metric = $self->{'thischild'}->{'metric'};
    $metric->set_handler( $self );
    $metric->count({
        'count_id' => $count_id,
        'labels'   => $labels,
        'server'   => $self->{'thischild'},
        'count'    => $count,
    });
    $metric->set_handler( undef );
}

=metric_method I<metric_set( $id, $labels, $count )>

Set a metrics counter to $count

=cut

sub metric_set {
    my ( $self, $gauge_id, $labels, $value ) = @_;
    $labels = {} if ! defined $labels;
    die 'Must set value in metric_set call' if ! defined $value;

    my $metric = $self->{'thischild'}->{'metric'};
    $metric->set_handler( $self );
    $metric->set({
        'gauge_id' => $gauge_id,
        'labels'   => $labels,
        'server'   => $self->{'thischild'},
        'value'    => $value,
    });
    $metric->set_handler( undef );
}

=metric_method I<metric_send()>

Send metrics to the parent

=cut

sub metric_send {
    my ( $self ) = @_;
    # NOOP
    # TODO Deprecate and remove
}

=rbl_method I<rbl_check_ip( $ip, $list )>

Check the given IP address against an rbl list.

Returns true is listed.

=cut

sub rbl_check_ip {
    my ( $self, $ip, $list ) = @_;

    my $lookup_ip;

    # Reverse the IP
    if ( $ip->version() == 4 ) {
        $lookup_ip = join( '.', reverse( split( /\./, $ip->ip() ) ) );
    }
    elsif ( $ip->version() == 6 ) {
        my $ip_string = $ip->ip();
        $ip_string =~ s/://g;
        $lookup_ip = join( '.', reverse( split( '', $ip_string ) ) );
    }

    return 0 if ! $lookup_ip;
    return $self->rbl_check_domain( $lookup_ip, $list );
}

=rbl_method I<rbl_check_domain( $domain, $list )>

Check the given domain against an rbl list.

Returns true is listed.

=cut

sub rbl_check_domain {
    my ( $self, $domain, $list ) = @_;
    my $resolver = $self->get_object( 'resolver' );
    my $lookup = join( '.', $domain, $list );
    my $packet = $resolver->query( $lookup, 'A' );

    if ($packet) {
        foreach my $rr ( $packet->answer ) {
            if (  lc $rr->type eq 'a' ) {
                return $rr->address();
            }
        }
    }
    return 0;
}

=timeout_method I<get_microseconds()>

Return the current time in microseconds

=cut

sub get_microseconds {
    my ( $self ) = @_;
    my ($seconds, $microseconds) = gettimeofday;
    return ( ( $seconds * 1000000 ) + $microseconds );
}

=timeout_method I<get_microseconds_since( $time )>

Return the number of microseconds since the given time (in microseconds)

=cut

sub get_microseconds_since {
    my ( $self, $since ) = @_;
    my $now = $self->get_microseconds();
    my $elapsed = $now - $since;
    $elapsed = 1 if $elapsed == 0; # Always return at least 1
    return $elapsed;
}

# Top Level Callbacks

=metric_method I<register_metrics()>

Return details of the metrics this module exports.

=cut

sub register_metrics {
    return {
        'connect_total'           => 'The number of connections made to authentication milter',
        'callback_error_total'    => 'The number of errors in callbacks',
        'time_microseconds_total' => 'The time in microseconds spent in various handlers',
    };
}

=callback_method I<top_dequeue_callback()>

Top level handler for dequeue.

=cut

sub top_dequeue_callback {
    my ( $self ) = @_;

    $self->status('dequeue');
    $self->set_symbol('C','i','DEQUEUE.'.substr( uc md5_hex( "Authentication Milter Client $PID " . time() . rand(100) ) , -11 ));
    $self->dbgout( 'CALLBACK', 'Dequeue', LOG_DEBUG );
    my $config = $self->config();
    eval {
        local $SIG{'ALRM'} = sub{ die Mail::Milter::Authentication::Exception->new({ 'Type' => 'Timeout', 'Text' => 'Dequeue callback timeout' }) };
        if ( my $timeout = $self->get_type_timeout( 'dequeue' ) ) {
            $self->set_alarm( $timeout );
        }
        my $callbacks = $self->get_callbacks( 'dequeue' );
        foreach my $handler ( @$callbacks ) {
            $self->dbgout( 'CALLBACK', 'Dequeue ' . $handler, LOG_DEBUG );
            my $start_time = $self->get_microseconds();
            $self->get_handler($handler)->dequeue_callback();
            $self->dbgoutwrite();
            $self->metric_count( 'time_microseconds_total', { 'callback' => 'dequeue', 'handler' => $handler }, $self->get_microseconds_since( $start_time ) );
        }
        $self->set_alarm(0);
    };
    if ( my $error = $@ ) {
        if ( my $type = $self->is_exception_type( $error ) ) {
            $self->metric_count( 'callback_error_total', { 'stage' => 'dequeue', 'type' => $type } );
        }
        else {
            $self->metric_count( 'callback_error_total', { 'stage' => 'dequeue' } );
        }
    }
    $self->dbgoutwrite();
    $self->status('postdequeue');
}

=callback_method I<top_setup_callback()>

Top level handler for handler setup.

=cut

sub top_setup_callback {

    my ( $self ) = @_;
    $self->status('setup');
    $self->dbgout( 'CALLBACK', 'Setup', LOG_DEBUG );
    $self->set_return( $self->smfis_continue() );

    my $callbacks = $self->get_callbacks( 'setup' );
    foreach my $handler ( @$callbacks ) {
        $self->dbgout( 'CALLBACK', 'Setup ' . $handler, LOG_DEBUG );
        my $start_time = $self->get_microseconds();
        $self->get_handler($handler)->setup_callback();
        $self->metric_count( 'time_microseconds_total', { 'callback' => 'setup', 'handler' => $handler }, $self->get_microseconds_since( $start_time ) );
    }
    $self->status('postsetup');
}

=timeout_method I<is_exception_type( $exception )>

Given a Mail::Milter::Authentication::Exception object, this return
the exception object type.
Otherwise returns undef.

=cut

sub is_exception_type {
    my ( $self, $exception ) = @_;
    return if ! defined $exception;
    return if ! $exception;
    return if ref $exception ne 'Mail::Milter::Authentication::Exception';
    my $Type = $exception->{ 'Type' } || 'Unknown';
    return $Type;
}

=timeout_method I<handle_exception( $exception )>

Handle exceptions thrown, this method currently handles the
timeout type, by re-throwing the exception.

Should be called in Handlers when handling local exceptions, such that the
higher level timeout exceptions are properly handled.

=cut

sub handle_exception {
    my ( $self, $exception ) = @_;
    return if ! defined $exception;
    my $Type = $self->is_exception_type( $exception );
    return if ! $Type;
    die $exception if $Type eq 'Timeout';
    #my $Text = $exception->{ 'Text' } || 'Unknown';
}

=timeout_method I<get_time_remaining()>

Return the time remaining (in microseconds) for the current Handler section level
callback timeout.

=cut

sub get_time_remaining {
    my ( $self ) = @_;
    my $top_handler = $self->get_top_handler();
    return if ! exists $top_handler->{ 'timeout_at' };
    my $now = $self->get_microseconds();
    my $remaining = $top_handler->{ 'timeout_at' } - $now;
    # can be zero or -ve
    return $remaining;
}

=timeout_method I<set_alarm( $microseconds )>

Set a timeout alarm for $microseconds, and set the time remaining
in the top level handler object.

=cut

sub set_alarm {
    my ( $self, $microseconds ) = @_;
    my $top_handler = $self->get_top_handler();
    $self->dbgout( 'Timeout set', $microseconds, LOG_DEBUG );
    ualarm( $microseconds );
    if ( $microseconds == 0 ) {
        delete $top_handler->{ 'timeout_at' };
    }
    else {
        $top_handler->{ 'timeout_at' } = $self->get_microseconds() + ( $microseconds );
    }
}

=timeout_method I<set_handler_alarm( $microseconds )>

Set an alarm for $microseconds, or the current time remaining for the section callback, whichever
is the lower. This should be used in Handler timeouts to ensure that a local timeout never goes for
longer than the current handler section, or protocol section level timeout.

=cut

sub set_handler_alarm {
    # Call this in a handler to set a local alarm, will take the lower value
    # of the microseconds passed in, or what is left of a higher level timeout.
    my ( $self, $microseconds ) = @_;
    my $remaining = $self->get_time_remaining();
    if ( $remaining < $microseconds ) {
        # This should already be set of course, but for clarity...
        $self->dbgout( 'Handler timeout set (remaining used)', $remaining, LOG_DEBUG );
        ualarm( $remaining );
    }
    else {
        $self->dbgout( 'Handler timeout set', $microseconds, LOG_DEBUG );
        ualarm( $microseconds );
    }
}

=timeout_method I<reset_alarm()>

Reset the alarm to the current time remaining in the section or protocol level timeouts.

This should be called in Handlers after local timeouts have completed, to reset the higher level
timeout alarm value.

=cut

sub reset_alarm {
    # Call this after any local handler timeouts to reset to the overall value remaining
    my ( $self ) = @_;
    my $remaining = $self->get_time_remaining();
    $self->dbgout( 'Timeout reset', $remaining, LOG_DEBUG );
    if ( $remaining < 1 ) {
        # We have already timed out!
        die Mail::Milter::Authentication::Exception->new({ 'Type' => 'Timeout', 'Text' => 'Reset check timeout' });
    }
    ualarm( $remaining );
}

=timeout_method I<clear_overall_timeout()>

Clear the current Handler level timeout, should be called from the Protocol layer, never from the Handler layer.

=cut

sub clear_overall_timeout {
    my ( $self ) = @_;
    $self->dbgout( 'Overall timeout', 'Clear', LOG_DEBUG );
    my $top_handler = $self->get_top_handler();
    delete $top_handler->{ 'overall_timeout' };
}

=timeout_method I<set_overall_timeout( $microseconds )>

Set the time in microseconds after which the Handler layer should timeout, called from the Protocol later, never from the Handler layer.

=cut

sub set_overall_timeout {
    my ( $self, $microseconds ) = @_;
    my $top_handler = $self->get_top_handler();
    $self->dbgout( 'Overall timeout', $microseconds, LOG_DEBUG );
    $top_handler->{ 'overall_timeout' } = $self->get_microseconds() + $microseconds;
}

=timeout_method I<get_type_timeout( $type )>

For a given timeout type, return the configured timeout value, or the current handler level timeout, whichever is lower.

=cut

sub get_type_timeout {
    my ( $self, $type ) = @_;

    my @log;
    push @log, "Type: $type";

    my $effective;

    my $timeout;
    my $config = $self->config();
    if ( $config->{ $type . '_timeout' } ) {
        $timeout = $config->{ $type . '_timeout' } * 1000000;
        $effective = $timeout;
        push @log, "Section: $timeout";
    }

    my $remaining;
    my $top_handler = $self->get_top_handler();
    if ( my $overall_timeout = $top_handler->{ 'overall_timeout' } ) {
        my $now = $self->get_microseconds();
        $remaining = $overall_timeout - $now;
        push @log, "Overall: $remaining";
        if ( $remaining < 1 ) {
            push @log, "Overall Timedout";
            $remaining = 10; # arb low value;
        }
    }

    if ( $remaining ) {
        if ( $timeout ) {
            if ( $remaining < $timeout ) {
                $effective = $remaining;
            }
        }
        else {
            $effective = $remaining;
        }
    }

    push @log, "Effective: $effective" if $effective;

    $self->dbgout( 'Timeout set', join( ', ', @log ), LOG_DEBUG );

    return $effective;
}

=timeout_method I<check_timeout()>

Manually check the current timeout, and throw if it has passed.

=cut

sub check_timeout {
    my ( $self ) = @_;
    my $top_handler = $self->get_top_handler();
    return if ! exists $top_handler->{ 'timeout_at' };
    return if $top_handler->{ 'timeout_at' } >= $self->get_microseconds();
    delete $top_handler->{ 'timeout_at' };
    ualarm( 0 );
    die Mail::Milter::Authentication::Exception->new({ 'Type' => 'Timeout', 'Text' => 'Manual check timeout' });
}

sub _remap_ip_and_helo {
    my ( $self ) = @_;

    my $config = $self->config();
    if ( exists ( $config->{ 'ip_map' } ) ) {
        my $ip_object = $self->{ 'raw_ip_object' };
        my $helo_host = $self->{'raw_helo_name'};
        foreach my $ip_map ( sort keys %{ $config->{ 'ip_map' } } ) {
            my $map_obj = Net::IP->new( $ip_map );
            if ( !$map_obj ) {
                $self->log_error( 'Core: Could not parse IP '.$ip_map );
            }
            else {
                my $is_overlap = $ip_object->overlaps($map_obj) || 0;
                if (
                       $is_overlap == $IP_A_IN_B_OVERLAP
                    || $is_overlap == $IP_B_IN_A_OVERLAP     # Should never happen
                    || $is_overlap == $IP_PARTIAL_OVERLAP    # Should never happen
                    || $is_overlap == $IP_IDENTICAL
                  )
                {
                    my $mapped_to = $config->{ 'ip_map' }->{ $ip_map };
                    if ( $helo_host && exists $mapped_to->{helo_map} && exists $mapped_to->{helo_map}->{ $helo_host } ) {
                        # We have a specific HELO mapping for this!
                        $mapped_to = $mapped_to->{helo_map}->{ $helo_host };
                        return {
                            ip => Net::IP->new( $mapped_to->{ip} ),
                            helo => $mapped_to->{helo},
                        };
                    }
                    else {
                        # Remap based on IP Only
                        return {
                            ip => Net::IP->new( $mapped_to->{ip} ),
                            helo => $mapped_to->{helo},
                        };
                    }
                }
            }
        }
    }
}

=callback_method I<remap_connect_callback( $hostname, $ip )>

Top level handler for the connect event for remapping only.

=cut

sub remap_connect_callback {
    my ( $self, $hostname, $ip ) = @_;
    $self->{'raw_ip_object'} = $ip;
    my $ip_remap = $self->_remap_ip_and_helo();
    if ( $ip_remap ) {
        if ( !$ip_remap->{ip} ) {
            $self->log_error( 'Core: Ignored bad IP in remapping' );
        }
        else {
            $ip = $ip_remap->{ip};
            $self->dbgout( 'RemappedConnect', $self->{'raw_ip_object'}->ip() . ' > ' . $ip->ip(), LOG_DEBUG );
       }
    }
    $self->{'ip_object'} = $ip;
}

=callback_method I<top_metrics_callback()>

Top level handler for the metrics event.

=cut

sub top_metrics_callback {
    my ( $self ) = @_;
    my $callbacks = $self->get_callbacks( 'metrics' );
    foreach my $handler ( @$callbacks ) {
        $self->dbgout( 'CALLBACK', 'Metrics ' . $handler, LOG_DEBUG );
        eval{ $self->get_handler($handler)->metrics_callback(); };
        if ( my $error = $@ ) {
            $self->handle_exception( $error );
            $self->log_error( 'Metrics callback error ' . $error );
        }
    };
}

=callback_method I<top_connect_callback( $hostname, $ip )>

Top level handler for the connect event.

=cut

sub top_connect_callback {

    # On Connect
    my ( $self, $hostname, $ip ) = @_;
    $self->metric_count( 'connect_total' );
    $self->status('connect');
    $self->dbgout( 'CALLBACK', 'Connect', LOG_DEBUG );
    $self->set_return( $self->smfis_continue() );
    $self->clear_reject_mail();
    $self->clear_defer_mail();
    $self->clear_quarantine_mail();
    my $config = $self->config();
    eval {
        local $SIG{'ALRM'} = sub{ die Mail::Milter::Authentication::Exception->new({ 'Type' => 'Timeout', 'Text' => 'Connect callback timeout' }) };
        if ( my $timeout = $self->get_type_timeout( 'connect' ) ) {
            $self->set_alarm( $timeout );
        }

        $self->dbgout( 'ConnectFrom', $ip->ip(), LOG_DEBUG );

        my $callbacks = $self->get_callbacks( 'connect' );
        foreach my $handler ( @$callbacks ) {
            $self->dbgout( 'CALLBACK', 'Connect ' . $handler, LOG_DEBUG );
            my $start_time = $self->get_microseconds();
            eval{ $self->get_handler($handler)->connect_callback( $hostname, $ip ); };
            if ( my $error = $@ ) {
                $self->handle_exception( $error );
                $self->exit_on_close( 'Connect callback error ' . $error );
                $self->tempfail_on_error();
                $self->metric_count( 'callback_error_total', { 'stage' => 'connect', 'handler' => $handler } );
            }
            $self->metric_count( 'time_microseconds_total', { 'callback' => 'connect', 'handler' => $handler }, $self->get_microseconds_since( $start_time ) );
            $self->check_timeout();
        }
        $self->set_alarm(0);
    };
    if ( my $error = $@ ) {
        if ( my $type = $self->is_exception_type( $error ) ) {
            $self->metric_count( 'callback_error_total', { 'stage' => 'connect', 'type' => $type } );
            $self->exit_on_close( 'Connect callback error ' . $type . ' - ' . $error->{ 'Text' } );
        }
        else {
            $self->metric_count( 'callback_error_total', { 'stage' => 'connect' } );
            $self->exit_on_close( 'Connect callback error ' . $error );
        }
        $self->tempfail_on_error();
    }
    $self->status('postconnect');
    return $self->get_return();
}

=callback_method I<remap_helo_callback( $helo_host )>

Top level handler for the HELO event for remapping only.

=cut

sub remap_helo_callback {
    my ( $self, $helo_host ) = @_;
    if ( !( $self->{'helo_name'} ) ) {

        $self->{'raw_helo_name'} = $helo_host;
        my $ip_remap = $self->_remap_ip_and_helo();
        if ( $ip_remap ) {
            my $ip = $ip_remap->{ip};
            if ( $self->{'ip_object'}->ip() ne $ip_remap->{ip}->ip() ) {
                # The mapped IP has been changed based on the HELO host received
                $self->{'ip_object'} = $ip;
                $self->dbgout( 'RemappedConnectHELO', $self->{'ip_object'}->ip() . ' > ' . $ip->ip(), LOG_DEBUG );
            }
            $helo_host = $ip_remap->{helo};
            $self->dbgout( 'RemappedHELO', $self->{'raw_helo_name'} . ' > ' . $helo_host, LOG_DEBUG );
        }

        $self->{'helo_name'} = $helo_host;
    }
}

=callback_method I<top_helo_callback( $helo_host )>

Top level handler for the HELO event.

=cut

sub top_helo_callback {

    # On HELO
    my ( $self, $helo_host ) = @_;
    $self->status('helo');
    $self->dbgout( 'CALLBACK', 'Helo', LOG_DEBUG );
    $self->set_return( $self->smfis_continue() );
    $helo_host = q{} if ! defined $helo_host;
    my $config = $self->config();
    eval {
        local $SIG{'ALRM'} = sub{ die Mail::Milter::Authentication::Exception->new({ 'Type' => 'Timeout', 'Text' => 'HELO callback timeout' }) };
        if ( my $timeout = $self->get_type_timeout( 'command' ) ) {
            $self->set_alarm( $timeout );
        }

        # Take only the first HELO from a connection
        if ( !( $self->{'seen_helo_name'} ) ) {
            $self->{'seen_helo_name'} = $helo_host;

            my $callbacks = $self->get_callbacks( 'helo' );
            foreach my $handler ( @$callbacks ) {
                $self->dbgout( 'CALLBACK', 'Helo ' . $handler, LOG_DEBUG );
                my $start_time = $self->get_microseconds();
                eval{ $self->get_handler($handler)->helo_callback($helo_host); };
                if ( my $error = $@ ) {
                    $self->handle_exception( $error );
                    $self->exit_on_close( 'HELO callback error ' . $error );
                    $self->tempfail_on_error();
                    $self->metric_count( 'callback_error_total', { 'stage' => 'helo', 'handler' => $handler } );
                }
                $self->metric_count( 'time_microseconds_total', { 'callback' => 'helo', 'handler' => $handler }, $self->get_microseconds_since( $start_time ) );
                $self->check_timeout();
            }
        }
        else {
            $self->dbgout('Multiple HELO callbacks detected and ignored', $self->{'seen_helo_name'} . ' / ' . $helo_host, LOG_DEBUG );
        }

        $self->set_alarm(0);
    };
    if ( my $error = $@ ) {
        if ( my $type = $self->is_exception_type( $error ) ) {
            $self->metric_count( 'callback_error_total', { 'stage' => 'helo', 'type' => $type } );
            $self->exit_on_close( 'HELO error ' . $type . ' - ' . $error->{ 'Text' } );
        }
        else {
            $self->metric_count( 'callback_error_total', { 'stage' => 'helo' } );
            $self->exit_on_close( 'HELO callback error ' . $error );
        }
        $self->tempfail_on_error();
    }
    $self->status('posthelo');
    return $self->get_return();
}

=callback_method I<top_envfrom_callback( $env_from )>

Top level handler for the MAIL FROM event.

=cut

sub top_envfrom_callback {

    # On MAILFROM
    #...
    my ( $self, $env_from, @params ) = @_;
    $self->status('envfrom');
    $self->dbgout( 'CALLBACK', 'EnvFrom', LOG_DEBUG );
    $self->set_return( $self->smfis_continue() );
    $env_from = q{} if ! defined $env_from;
    my $config = $self->config();
    eval {
        local $SIG{'ALRM'} = sub{ die Mail::Milter::Authentication::Exception->new({ 'Type' => 'Timeout', 'Text' => 'EnvFrom callback timeout' }) };
        if ( my $timeout = $self->get_type_timeout( 'command' ) ) {
            $self->set_alarm( $timeout );
        }

        # Reset private data for this MAIL transaction
        delete $self->{'auth_headers'};
        delete $self->{'pre_headers'};
        delete $self->{'add_headers'};
        delete $self->{'suppress_error_emails'};

        my $callbacks = $self->get_callbacks( 'envfrom' );
        foreach my $handler ( @$callbacks ) {
            $self->dbgout( 'CALLBACK', 'EnvFrom ' . $handler, LOG_DEBUG );
            my $start_time = $self->get_microseconds();
            eval { $self->get_handler($handler)->envfrom_callback($env_from, @params); };
            if ( my $error = $@ ) {
                $self->handle_exception( $error );
                $self->exit_on_close( 'Env From callback error ' . $error );
                $self->tempfail_on_error();
                $self->metric_count( 'callback_error_total', { 'stage' => 'envfrom', 'handler' => $handler } );
            }
            $self->metric_count( 'time_microseconds_total', { 'callback' => 'envfrom', 'handler' => $handler }, $self->get_microseconds_since( $start_time ) );
            $self->check_timeout();
        }
        $self->set_alarm(0);
    };
    if ( my $error = $@ ) {
        if ( my $type = $self->is_exception_type( $error ) ) {
            $self->metric_count( 'callback_error_total', { 'stage' => 'envfrom', 'type' => $type } );
            $self->exit_on_close( 'Env From error ' . $type . ' - ' . $error->{ 'Text' } );
        }
        else {
            $self->metric_count( 'callback_error_total', { 'stage' => 'envfrom' } );
            $self->exit_on_close( 'Env From callback error ' . $error );
        }
        $self->tempfail_on_error();
    }
    $self->status('postenvfrom');
    return $self->get_return();
}

=callback_method I<top_envrcpt_callback( $env_to )>

Top level handler for the RCPT TO event.

=cut

sub top_envrcpt_callback {

    # On RCPTTO
    #...
    my ( $self, $env_to, @params ) = @_;
    $self->status('envrcpt');
    $self->dbgout( 'CALLBACK', 'EnvRcpt', LOG_DEBUG );
    $self->set_return( $self->smfis_continue() );
    $env_to = q{} if ! defined $env_to;
    my $config = $self->config();
    eval {
        local $SIG{'ALRM'} = sub{ die Mail::Milter::Authentication::Exception->new({ 'Type' => 'Timeout', 'Text' => 'EnvRcpt callback timeout' }) };
        if ( my $timeout = $self->get_type_timeout( 'command' ) ) {
            $self->set_alarm( $timeout );
        }

        my $callbacks = $self->get_callbacks( 'envrcpt' );
        foreach my $handler ( @$callbacks ) {
            $self->dbgout( 'CALLBACK', 'EnvRcpt ' . $handler, LOG_DEBUG );
            my $start_time = $self->get_microseconds();
            eval{ $self->get_handler($handler)->envrcpt_callback($env_to, @params); };
            if ( my $error = $@ ) {
                $self->handle_exception( $error );
                $self->exit_on_close( 'Env Rcpt callback error ' . $error );
                $self->tempfail_on_error();
                $self->metric_count( 'callback_error_total', { 'stage' => 'rcptto', 'handler' => $handler } );
            }
            $self->metric_count( 'time_microseconds_total', { 'callback' => 'rcptto', 'handler' => $handler }, $self->get_microseconds_since( $start_time ) );
            $self->check_timeout();
        }
        $self->set_alarm(0);
    };
    if ( my $error = $@ ) {
        if ( my $type = $self->is_exception_type( $error ) ) {
            $self->metric_count( 'callback_error_total', { 'stage' => 'rcptto', 'type' => $type } );
            $self->exit_on_close( 'Env Rcpt callback error ' . $type . ' - ' . $error->{ 'Text' } );
        }
        else {
            $self->metric_count( 'callback_error_total', { 'stage' => 'rcptto' } );
            $self->exit_on_close( 'Env Rcpt callback error ' . $error );
        }
        $self->tempfail_on_error();
    }
    $self->status('postenvrcpt');
    return $self->get_return();
}

=callback_method  I<top_header_callback( $header, $value, $original )>

Top level handler for the BODY header event.

=cut

sub top_header_callback {

    # On Each Header
    my ( $self, $header, $value, $original ) = @_;
    $self->status('header');
    $self->dbgout( 'CALLBACK', 'Header', LOG_DEBUG );
    $self->set_return( $self->smfis_continue() );
    $value = q{} if ! defined $value;
    my $config = $self->config();

    if ( $header eq 'X-Authentication-Milter-Error' && $value eq 'Generated Error Report' ) {
        $self->{'suppress_error_emails'} = 1;
    }

    eval {
        local $SIG{'ALRM'} = sub{ die Mail::Milter::Authentication::Exception->new({ 'Type' => 'Timeout', 'Text' => 'Header callback timeout' }) };
        if ( my $timeout = $self->get_type_timeout( 'content' ) ) {
            $self->set_alarm( $timeout );
        }
        if ( my $error = $@ ) {
            $self->dbgout( 'inline error $error', '', LOG_DEBUG );
        }

        my $callbacks = $self->get_callbacks( 'header' );
        foreach my $handler ( @$callbacks ) {
            $self->dbgout( 'CALLBACK', 'Header ' . $handler, LOG_DEBUG );
            my $start_time = $self->get_microseconds();
            eval{ $self->get_handler($handler)->header_callback( $header, $value, $original ); };
            if ( my $error = $@ ) {
                $self->handle_exception( $error );
                $self->exit_on_close( 'Header callback error ' . $error );
                $self->tempfail_on_error();
                $self->metric_count( 'callback_error_total', { 'stage' => 'header', 'handler' => $handler } );
            }
            $self->metric_count( 'time_microseconds_total', { 'callback' => 'header', 'handler' => $handler }, $self->get_microseconds_since( $start_time ) );
            $self->check_timeout();
        }
        $self->set_alarm(0);
    };
    if ( my $error = $@ ) {
        if ( my $type = $self->is_exception_type( $error ) ) {
            $self->metric_count( 'callback_error_total', { 'stage' => 'header', 'type' => $type } );
            $self->exit_on_close( 'Header error ' . $type . ' - ' . $error->{ 'text' } );
        }
        else {
            $self->metric_count( 'callback_error_total', { 'stage' => 'header' } );
            $self->exit_on_close( 'Header callback error ' . $error );
        }
        $self->tempfail_on_error();
    }
    $self->status('postheader');
    return $self->get_return();
}

=callback_method I<top_eoh_callback()>

Top level handler for the BODY end of headers event.

=cut

sub top_eoh_callback {

    # On End of headers
    my ($self) = @_;
    $self->status('eoh');
    $self->dbgout( 'CALLBACK', 'EOH', LOG_DEBUG );
    $self->set_return( $self->smfis_continue() );
    my $config = $self->config();
    eval {
        local $SIG{'ALRM'} = sub{ die Mail::Milter::Authentication::Exception->new({ 'Type' => 'Timeout', 'Text' => 'EOH callback timeout' }) };
        if ( my $timeout = $self->get_type_timeout( 'content' ) ) {
            $self->set_alarm( $timeout );
        }

        my $callbacks = $self->get_callbacks( 'eoh' );
        foreach my $handler ( @$callbacks ) {
            $self->dbgout( 'CALLBACK', 'EOH ' . $handler, LOG_DEBUG );
            my $start_time = $self->get_microseconds();
            eval{ $self->get_handler($handler)->eoh_callback(); };
            if ( my $error = $@ ) {
                $self->handle_exception( $error );
                $self->exit_on_close( 'EOH callback error ' . $error );
                $self->tempfail_on_error();
                $self->metric_count( 'callback_error_total', { 'stage' => 'eoh', 'handler' => $handler } );
            }
            $self->metric_count( 'time_microseconds_total', { 'callback' => 'eoh', 'handler' => $handler }, $self->get_microseconds_since( $start_time ) );
            $self->check_timeout();
        }
        $self->set_alarm(0);
    };
    if ( my $error = $@ ) {
        if ( my $type = $self->is_exception_type( $error ) ) {
            $self->metric_count( 'callback_error_total', { 'stage' => 'eoh', 'type' => $type } );
            $self->exit_on_close( 'EOH error ' . $type . ' - ' . $error->{ 'text' } );
        }
        else {
            $self->metric_count( 'callback_error_total', { 'stage' => 'eoh' } );
            $self->exit_on_close( 'EOH callback error ' . $error );
        }
        $self->tempfail_on_error();
    }
    $self->dbgoutwrite();
    $self->status('posteoh');
    return $self->get_return();
}

=callback_method I<top_body_callback( $body_chunk )>

Top level handler for the BODY body chunk event.

=cut

sub top_body_callback {

    # On each body chunk
    my ( $self, $body_chunk ) = @_;
    $self->status('body');
    $self->dbgout( 'CALLBACK', 'Body', LOG_DEBUG );
    $self->set_return( $self->smfis_continue() );
    my $config = $self->config();
    eval {
        local $SIG{'ALRM'} = sub{ die Mail::Milter::Authentication::Exception->new({ 'Type' => 'Timeout', 'Text' => 'Body callback timeout' }) };
        if ( my $timeout = $self->get_type_timeout( 'content' ) ) {
            $self->set_alarm( $timeout );
        }

        my $callbacks = $self->get_callbacks( 'body' );
        foreach my $handler ( @$callbacks ) {
            $self->dbgout( 'CALLBACK', 'Body ' . $handler, LOG_DEBUG );
            my $start_time = $self->get_microseconds();
            eval{ $self->get_handler($handler)->body_callback( $body_chunk ); };
            if ( my $error = $@ ) {
                $self->handle_exception( $error );
                $self->exit_on_close( 'Body callback error ' . $error );
                $self->tempfail_on_error();
                $self->metric_count( 'callback_error_total', { 'stage' => 'body', 'handler' => $handler } );
            }
            $self->metric_count( 'time_microseconds_total', { 'callback' => 'body', 'handler' => $handler }, $self->get_microseconds_since( $start_time ) );
            $self->check_timeout();
        }
        $self->set_alarm(0);
    };
    if ( my $error = $@ ) {
        if ( my $type = $self->is_exception_type( $error ) ) {
            $self->metric_count( 'callback_error_total', { 'stage' => 'body', 'type' => $type } );
            $self->exit_on_close( 'Body error ' . $type . ' - ' . $error->{ 'text' } );
        }
        else {
            $self->metric_count( 'callback_error_total', { 'stage' => 'body' } );
            $self->exit_on_close( 'Body callback error ' . $error );
        }
        $self->tempfail_on_error();
    }
    $self->dbgoutwrite();
    $self->status('postbody');
    return $self->get_return();
}

=callback_method I<top_eom_callback()>

Top level handler for the BODY end of message event.

=cut

sub top_eom_callback {

    # On End of Message
    my ($self) = @_;
    $self->status('eom');
    $self->dbgout( 'CALLBACK', 'EOM', LOG_DEBUG );
    $self->set_return( $self->smfis_continue() );
    my $config = $self->config();
    eval {
        local $SIG{'ALRM'} = sub{ die Mail::Milter::Authentication::Exception->new({ 'Type' => 'Timeout', 'Text' => 'EOM callback timeout' }) };
        if ( my $timeout = $self->get_type_timeout( 'content' ) ) {
            $self->set_alarm( $timeout );
        }

        my $callbacks = $self->get_callbacks( 'eom' );
        foreach my $handler ( @$callbacks ) {
            $self->dbgout( 'CALLBACK', 'EOM ' . $handler, LOG_DEBUG );
            my $start_time = $self->get_microseconds();
            eval{ $self->get_handler($handler)->eom_callback(); };
            if ( my $error = $@ ) {
                $self->handle_exception( $error );
                $self->exit_on_close( 'EOM callback error ' . $error );
                $self->tempfail_on_error();
                $self->metric_count( 'callback_error_total', { 'stage' => 'eom', 'handler' => $handler } );
            }
            $self->metric_count( 'time_microseconds_total', { 'callback' => 'eom', 'handler' => $handler }, $self->get_microseconds_since( $start_time ) );
            $self->check_timeout();
        }
        $self->set_alarm(0);
    };
    if ( my $error = $@ ) {
        if ( my $type = $self->is_exception_type( $error ) ) {
            $self->metric_count( 'callback_error_total', { 'stage' => 'eom', 'type' => $type } );
            $self->exit_on_close( 'EOM error ' . $type . ' - ' . $error->{ 'text' } );
        }
        else {
            $self->metric_count( 'callback_error_total', { 'stage' => 'eom' } );
            $self->exit_on_close( 'EOM callback error ' . $error );
        }
        $self->tempfail_on_error();
    }
    #$self->apply_policy();
    $self->add_headers();
    $self->dbgoutwrite();
    $self->status('posteom');
    return $self->get_return();
}

=callback_method I<apply_policy()>

Apply policy to the message, currently a nop.

=cut

sub apply_policy {
    #my ($self) = @_;

    #my @auth_headers;
    #my $top_handler = $self->get_top_handler();
    #if ( exists( $top_handler->{'c_auth_headers'} ) ) {
    #    @auth_headers = @{ $top_handler->{'c_auth_headers'} };
    #}
    #if ( exists( $top_handler->{'auth_headers'} ) ) {
    #    @auth_headers = ( @auth_headers, @{ $top_handler->{'auth_headers'} } );
    #}

    #my $parsed_headers = Mail::AuthenticationResults::Parser->new( \@auth_headers );;

    #use Data::Dumper;
    #print Dumper \@structured_headers;
}

=callback_method I<top_abort_callback()>

Top level handler for the abort event.

=cut

sub top_abort_callback {

    # On any out of our control abort
    my ($self) = @_;
    $self->status('abort');
    $self->dbgout( 'CALLBACK', 'Abort', LOG_DEBUG );
    $self->set_return( $self->smfis_continue() );
    my $config = $self->config();
    eval {
        local $SIG{'ALRM'} = sub{ die Mail::Milter::Authentication::Exception->new({ 'Type' => 'Timeout', 'Text' => 'Abord callback timeout' }) };
        if ( my $timeout = $self->get_type_timeout( 'command' ) ) {
            $self->set_alarm( $timeout );
        }

        my $callbacks = $self->get_callbacks( 'abort' );
        foreach my $handler ( @$callbacks ) {
            $self->dbgout( 'CALLBACK', 'Abort ' . $handler, LOG_DEBUG );
            my $start_time = $self->get_microseconds();
            eval{ $self->get_handler($handler)->abort_callback(); };
            if ( my $error = $@ ) {
                $self->handle_exception( $error );
                $self->exit_on_close( 'Abort callback error ' . $error );
                $self->tempfail_on_error();
                $self->metric_count( 'callback_error_total', { 'stage' => 'abort', 'handler' => $handler } );
            }
            $self->metric_count( 'time_microseconds_total', { 'callback' => 'abort', 'handler' => $handler }, $self->get_microseconds_since( $start_time ) );
            $self->check_timeout();
        }
        $self->set_alarm(0);
    };
    if ( my $error = $@ ) {
        if ( my $type = $self->is_exception_type( $error ) ) {
            $self->metric_count( 'callback_error_total', { 'stage' => 'abort', 'type' => $type } );
            $self->exit_on_close( 'Abort error ' . $type . ' - ' . $error->{ 'text' } );
        }
        else {
            $self->metric_count( 'callback_error_total', { 'stage' => 'abort' } );
            $self->exit_on_close( 'Abort callback error ' . $error );
        }
        $self->tempfail_on_error();
    }
    $self->status('postabort');
    return $self->get_return();
}

=callback_method I<top_close_callback()>

Top level handler for the close event.

=cut

sub top_close_callback {

    # On end of connection
    my ($self) = @_;
    $self->status('close');
    $self->dbgout( 'CALLBACK', 'Close', LOG_DEBUG );
    $self->set_return( $self->smfis_continue() );
    $self->clear_reject_mail();
    $self->clear_defer_mail();
    $self->clear_quarantine_mail();
    my $config = $self->config();
    eval {
        local $SIG{'ALRM'} = sub{ die Mail::Milter::Authentication::Exception->new({ 'Type' => 'Timeout', 'Text' => 'Close callback timeout' }) };
        if ( my $timeout = $self->get_type_timeout( 'command' ) ) {
            $self->set_alarm( $timeout );
        }

        my $callbacks = $self->get_callbacks( 'close' );
        foreach my $handler ( @$callbacks ) {
            $self->dbgout( 'CALLBACK', 'Close ' . $handler, LOG_DEBUG );
            my $start_time = $self->get_microseconds();
            eval{ $self->get_handler($handler)->close_callback(); };
            if ( my $error = $@ ) {
                $self->handle_exception( $error );
                $self->exit_on_close( 'Close callback error ' . $error );
                $self->tempfail_on_error();
                $self->metric_count( 'callback_error_total', { 'stage' => 'close', 'handler' => $handler } );
            }
            $self->metric_count( 'time_microseconds_total', { 'callback' => 'close', 'handler' => $handler }, $self->get_microseconds_since( $start_time ) );
            $self->check_timeout();

            my $handler_object = $self->get_handler($handler);
            foreach my $key ( sort keys $handler_object->%* ) {
                next if $key eq 'thischild';
                $self->exit_on_close( 'Handler '.$handler.' did not clean up data for key '.$key.' in close callback' );
            }
        }
        $self->set_alarm(0);
    };
    if ( my $error = $@ ) {
        if ( my $type = $self->is_exception_type( $error ) ) {
            $self->metric_count( 'callback_error_total', { 'stage' => 'close', 'type' => $type } );
            $self->exit_on_close( 'Close error ' . $type . ' - ' . $error->{ 'text' } );
        }
        else {
            $self->metric_count( 'callback_error_total', { 'stage' => 'close' } );
            $self->exit_on_close( 'Close callback error ' . $error );
        }
        $self->tempfail_on_error();
    }
    delete $self->{'helo_name'};
    delete $self->{'seen_helo_name'};
    delete $self->{'raw_helo_name'};
    delete $self->{'c_auth_headers'};
    delete $self->{'auth_headers'};
    delete $self->{'pre_headers'};
    delete $self->{'add_headers'};
    delete $self->{'ip_object'};
    delete $self->{'raw_ip_object'};
    $self->dbgoutwrite();
    $self->clear_all_symbols();
    $self->status('postclose');
    return $self->get_return();
}

=callback_method I<top_addheader_callback()>

Top level handler for the add header event.

Called after the Authentication-Results header has been added, but before any other headers.

=cut

sub top_addheader_callback {
    my ( $self ) = @_;
    my $config = $self->config();

    eval {
        local $SIG{'ALRM'} = sub{ die Mail::Milter::Authentication::Exception->new({ 'Type' => 'Timeout', 'Text' => 'AddHeader callback timeout' }) };
        if ( my $timeout = $self->get_type_timeout( 'addheader' ) ) {
            $self->set_alarm( $timeout );
        }

        my $callbacks = $self->get_callbacks( 'addheader' );
        foreach my $handler ( @$callbacks ) {
            my $start_time = $self->get_microseconds();
            $self->get_handler($handler)->addheader_callback($self);
            $self->metric_count( 'time_microseconds_total', { 'callback' => 'addheader', 'handler' => $handler }, $self->get_microseconds_since( $start_time ) );
            $self->check_timeout();
        }
        $self->set_alarm(0);
    };
    if ( my $error = $@ ) {
        if ( my $type = $self->is_exception_type( $error ) ) {
            $self->metric_count( 'callback_error_total', { 'stage' => 'addheader', 'type' => $type } );
            $self->exit_on_close( 'AddHeader error ' . $type . ' - ' . $error->{ 'text' } );
        }
        else {
            $self->metric_count( 'callback_error_total', { 'stage' => 'addheader' } );
            $self->exit_on_close( 'AddHeader callback error ' . $error );
        }
        $self->tempfail_on_error();
    }
}


# Other methods

=method I<status( $status )>

Set the status of the current child as visible by ps.

=cut

sub status {
    my ($self, $status) = @_;
    my $count = $self->{'thischild'}->{'count'};
    if ( exists ( $self->{'thischild'}->{'smtp'} ) ) {
        if ( $self->{'thischild'}->{'smtp'}->{'count'} ) {
            $count .= '.' . $self->{'thischild'}->{'smtp'}->{'count'};
        }
    }
    if ( $status ) {
        $PROGRAM_NAME = $Mail::Milter::Authentication::Config::IDENT . ':processing:' . $status . '(' . $count . ')';
    }
    else {
        $PROGRAM_NAME = $Mail::Milter::Authentication::Config::IDENT . ':processing(' . $count . ')';
    }
}

=method I<config()>

Return the configuration hashref.

=cut

sub config {
    my ($self) = @_;
    return $self->{'thischild'}->{'config'};
}

=method I<handler_config( $type )>

Return the configuration for the current handler.

=cut

sub handler_config {
    my ($self) = @_;
    my $type = $self->handler_type();
    return if ! $type;
    if ( $self->is_handler_loaded( $type ) ) {
        my $config = $self->config();
        my $handler_config = $config->{'handlers'}->{$type};

        if ( exists( $config->{ '_external_callback_processor' } ) ) {
            if ( $config->{ '_external_callback_processor' }->can( 'handler_config' ) ) {
                $handler_config = clone $handler_config;
                $config->{ '_external_callback_processor' }->handler_config( $type, $handler_config );
            }
        }

        return $handler_config;
    }
}

=method I<handler_type()>

Return the current handler type.

=cut

sub handler_type {
    my ($self) = @_;
    my $type = ref $self;
    if ( $type eq 'Mail::Milter::Authentication::Handler' ) {
        return 'Handler';
    }
    elsif ( $type =~ /^Mail::Milter::Authentication::Handler::(.*)/ ) {
        my $handler_type = $1;
        return $handler_type;
    }
    else {
        return undef; ## no critic
    }
}

=method I<set_return( $code )>

Set the return code to be passed back to the MTA.

=cut

sub set_return {
    my ( $self, $return ) = @_;
    my $top_handler = $self->get_top_handler();
    $top_handler->{'return_code'} = $return;
}

=method I<get_return()>

Get the current return code.

=cut

sub get_return {
    my ( $self ) = @_;
    my $top_handler = $self->get_top_handler();
    if ( defined $self->get_reject_mail() ) {
        return $self->smfis_reject();
    }
    elsif ( defined $self->get_defer_mail() ) {
        return $self->smfis_tempfail();
    }
    elsif ( defined $self->get_quarantine_mail() ) {
        ## TODO Implement this.
    }
    return $top_handler->{'return_code'};
}

=method I<get_reject_mail()>

Get the reject mail reason (or undef)

=cut

sub get_reject_mail {
    my ( $self ) = @_;
    my $top_handler = $self->get_top_handler();
    return $top_handler->{'reject_mail'};
}

=method I<clear_reject_mail()>

Clear the reject mail reason

=cut

sub clear_reject_mail {
    my ( $self ) = @_;
    my $top_handler = $self->get_top_handler();
    delete $top_handler->{'reject_mail'};
}

=method I<get_defer_mail()>

Get the defer mail reason (or undef)

=cut

sub get_defer_mail {
    my ( $self ) = @_;
    my $top_handler = $self->get_top_handler();
    return $top_handler->{'defer_mail'};
}

=method I<clear_defer_mail()>

Clear the defer mail reason

=cut

sub clear_defer_mail {
    my ( $self ) = @_;
    my $top_handler = $self->get_top_handler();
    delete $top_handler->{'defer_mail'};
}


=method I<get_quarantine_mail()>

Get the quarantine mail reason (or undef)

=cut

sub get_quarantine_mail {
    my ( $self ) = @_;
    my $top_handler = $self->get_top_handler();
    return $top_handler->{'quarantine_mail'};
}

=method I<clear_quarantine_mail()>

Clear the quarantine mail reason

=cut

sub clear_quarantine_mail {
    my ( $self ) = @_;
    my $top_handler = $self->get_top_handler();
    delete $top_handler->{'quarantine_mail'};
}

=method I<get_top_handler()>

Return the current top Handler object.

=cut

sub get_top_handler {
    my ($self) = @_;
    my $thischild = $self->{'thischild'};
    my $object = $thischild->{'handler'}->{'_Handler'};
    return $object;
}

=method I<is_handler_loaded( $name )>

Check if the named handler is loaded.

=cut

sub is_handler_loaded {
    my ( $self, $name ) = @_;
    my $config = $self->config();
    if ( exists ( $config->{'handlers'}->{$name} ) ) {
        return 1;
    }
    return 0;
}

=method I<get_handler( $name )>

Return the named handler object.

=cut

sub get_handler {
    my ( $self, $name ) = @_;
    my $thischild = $self->{'thischild'};
    my $object = $thischild->{'handler'}->{$name};
    return $object;
}

=method I<get_callbacks( $callback )>

Return the list of handlers which have callbacks for the given event in the order they must be called in.

=cut

sub get_callbacks {
    my ( $self, $callback ) = @_;
    my $thischild = $self->{'thischild'};
    return $thischild->{'callbacks_list'}->{$callback};
}

=method I<set_object_maker( $name, $ref )>

Register an object maker for type 'name'

=cut

sub set_object_maker {
    my ( $self, $name, $ref ) = @_;
    my $thischild = $self->{'thischild'};
    return if $thischild->{'object_maker'}->{$name};
    $thischild->{'object_maker'}->{$name} = $ref;
}

=method I<get_object( $name )>

Return the named object from the object store.

Object 'resolver' will be created if it does not already exist.

Object 'spf_server' will be created by the SPF handler if it does not already exist.

Handlers may register makers for other types as required.

=cut

sub get_object {
    my ( $self, $name ) = @_;

    my $thischild = $self->{'thischild'};
    my $object = $thischild->{'object'}->{$name};
    if ( ! $object ) {

        if ( exists( $thischild->{'object_maker'}->{$name} ) ) {
            my $maker = $thischild->{'object_maker'}->{$name};
            &$maker( $self, $name );
        }

        elsif ( $name eq 'resolver' ) {
            $self->dbgout( 'Object created', $name, LOG_DEBUG );
            if ( defined $TestResolver ) {
                $object = $TestResolver;
                warn "Using FAKE TEST DNS Resolver - I Hope this isn't production!";
                # If it is you better know what you're doing!
            }
            else {
                my $config = $self->config();
                my %args;
                $args{_handler}    = $self;
                $args{udp_timeout} = $config->{'dns_timeout'}   || 8;
                $args{tcp_timeout} = $config->{'dns_timeout'}   || 8;
                $args{retry}       = $config->{'dns_retry'}     || 2;
                $args{nameservers} = $config->{'dns_resolvers'} if $config->{'dns_resolvers'} && $config->{'dns_resolvers'}->@*;
                $object = Mail::Milter::Authentication::Resolver->new(%args);
                $object->udppacketsize(1240);
                $object->persistent_udp(1);
            }
            $thischild->{'object'}->{$name} = {
                'object'  => $object,
                'destroy' => 0,
            };
        }

    }
    return $thischild->{'object'}->{$name}->{'object'};
}

=method I<set_object( $name, $object, $destroy )>

Store the given object in the object store with the given name.

If $destroy then the object will be destroyed when the connection to the child closes

=cut

sub set_object {
    my ( $self, $name, $object, $destroy ) = @_;
    my $thischild = $self->{'thischild'};
    $self->dbgout( 'Object set', $name, LOG_DEBUG );
    $thischild->{'object'}->{$name} = {
        'object'  => $object,
        'destroy' => $destroy,
    };
}

=method I<destroy_object( $name )>

Remove the reference to the named object from the object store.

=cut

sub destroy_object {
    my ( $self, $name ) = @_;
    my $thischild = $self->{'thischild'};

    # Objects may be set to not be destroyed,
    # eg. resolver and spf_server are not
    # destroyed for performance reasons
    # Resolver, however, has its error cache cleared, as this should only
    # cache errors within a single transaction.
    return if ! $thischild->{'object'}->{$name};
    if ($name eq 'resolver' ) {
        if ( $thischild->{'object'}->{'resolver'}->{'object'}->can( 'clear_error_cache' ) ) {
            $thischild->{'object'}->{'resolver'}->{'object'}->clear_error_cache();
        }
    }
    return if ! $thischild->{'object'}->{$name}->{'destroy'};
    $self->dbgout( 'Object destroyed', $name, LOG_DEBUG );
    delete $thischild->{'object'}->{$name};
}

=method I<destroy_all_objects()>

Remove the references to all objects currently stored in the object store.

Certain objects (resolver and spf_server) are not destroyed for performance reasons.

=cut

sub destroy_all_objects {
    # Unused!
    my ( $self ) = @_;
    my $thischild = $self->{'thischild'};
    foreach my $name ( keys %{ $thischild->{'object'} } )
    {
        $self->destroy_object( $name );
    }
}

=method I<exit_on_close( $error )>

Exit this child once it has completed, do not process further requests with this child.

=cut

sub exit_on_close {
    my ( $self, $error ) = @_;
    $error = 'Generic exit_on_close requested' if ! $error;
    $self->log_error( $error );
    my $top_handler = $self->get_top_handler();
    $top_handler->{'exit_on_close'} = 1;
    $top_handler->{'exit_on_close_error'} = 'Exit on close requested' if ! exists $top_handler->{'exit_on_close_error'};
    $top_handler->{'exit_on_close_error'} .= "\n$error";
}

=method I<reject_mail( $reason )>

Reject mail with the given reason

=cut

sub reject_mail {
    my ( $self, $reason ) = @_;
    my ( $rcode, $xcode, $message ) = split( ' ', $reason, 3 );
    if ($rcode !~ /^[5]\d\d$/ || $xcode !~ /^[5]\.\d+\.\d+$/ || substr($rcode, 0, 1) ne substr($xcode, 0, 1)) {
        $self->loginfo ( "Invalid reject message $reason - setting to default" );
        $reason = '550 5.0.0 Message rejected';
    }
    my $top_handler = $self->get_top_handler();
    $top_handler->{'reject_mail'} = $reason;
}

=method I<quarantine_mail( $reason )>

Request quarantine mail with the given reason

=cut

sub quarantine_mail {
    my ( $self, $reason ) = @_;
    my $top_handler = $self->get_top_handler();
    $top_handler->{'quarantine_mail'} = $reason;
}

=method I<defer_mail( $reason )>

Defer mail with the given reason

=cut

sub defer_mail {
    my ( $self, $reason ) = @_;
    my ( $rcode, $xcode, $message ) = split( ' ', $reason, 3 );
    if ($rcode !~ /^[4]\d\d$/ || $xcode !~ /^[4]\.\d+\.\d+$/ || substr($rcode, 0, 1) ne substr($xcode, 0, 1)) {
        $self->loginfo ( "Invalid defer message $reason - setting to default" );
        $reason = '450 4.0.0 Message deferred';
    }
    my $top_handler = $self->get_top_handler();
    $top_handler->{'defer_mail'} = $reason;
}

=method I<clear_all_symbols()>

Clear the symbol store.

=cut

sub clear_all_symbols {
    my ( $self ) = @_;
    my $top_handler = $self->get_top_handler();
    delete $top_handler->{'symbols'};
}

=method I<clear_symbols()>

Clear the symbol store but do not remove the Connect symbols.

=cut

sub clear_symbols {
    my ( $self ) = @_;
    my $top_handler = $self->get_top_handler();

    my $connect_symbols;
    if ( exists ( $top_handler->{'symbols'} ) ) {
        if ( exists ( $top_handler->{'symbols'}->{'C'} ) ) {
            $connect_symbols = $top_handler->{'symbols'}->{'C'};
        }
    }

    delete $top_handler->{'symbols'};

    if ( $connect_symbols ) {
        $top_handler->{'symbols'} = {
            'C' => $connect_symbols,
        };
    }
}

=method I<set_symbol( $code, $key, $value )>

Store the key value pair in the symbol store with the given code (event stage).

=cut

sub set_symbol {
    my ( $self, $code, $key, $value ) = @_;
    $self->dbgout( 'SetSymbol', "$code: $key: $value", LOG_DEBUG );
    my $top_handler = $self->get_top_handler();
    if ( ! exists ( $top_handler->{'symbols'} ) ) {
        $top_handler->{'symbols'} = {};
    }
    if ( ! exists ( $top_handler->{'symbols'}->{$code} ) ) {
        $top_handler->{'symbols'}->{$code} = {};
    }
    $top_handler->{'symbols'}->{$code}->{$key} = $value;;
}

=method I<get_symbol( $searchkey )>

Return a value from the symbol store, searches all codes for the given key.

=cut

sub get_symbol {
    my ( $self, $searchkey ) = @_;
    my $top_handler = $self->get_top_handler();
    my $symbols = $top_handler->{'symbols'} || {};
    foreach my $code ( keys %{$symbols} ) {
        my $subsymbols = $symbols->{$code};
        foreach my $key ( keys %{$subsymbols} ) {
            if ( $searchkey eq $key ) {
                return $subsymbols->{$key};
            }
        }
    }
}

=method I<tempfail_on_error()>

Returns a TEMP FAIL to the calling MTA if the configuration is set to do so.

Config can be set for all, authenticated, local, and trusted connections.

=cut

sub tempfail_on_error {
    my ( $self ) = @_;
    my $config = $self->config();
    if ( $self->is_authenticated() ) {
        if ( $config->{'tempfail_on_error_authenticated'} ) {
            $self->log_error('TempFail set');
            $self->set_return( $self->smfis_tempfail() );
        }
    }
    elsif ( $self->is_local_ip_address() ) {
        if ( $config->{'tempfail_on_error_local'} ) {
            $self->log_error('TempFail set');
            $self->set_return( $self->smfis_tempfail() );
        }
    }
    elsif ( $self->is_trusted_ip_address() ) {
        if ( $config->{'tempfail_on_error_trusted'} ) {
            $self->log_error('TempFail set');
            $self->set_return( $self->smfis_tempfail() );
        }
    }
    else {
        if ( $config->{'tempfail_on_error'} ) {
            $self->log_error('TempFail set');
            $self->set_return( $self->smfis_tempfail() );
        }
    }
}



# Common calls into other Handlers

sub _dequeue_dir($self) {
    my $config = $self->config();
    my $dir = $config->{spool_dir}.'/dequeue';
    mkdir $dir if ! -d $dir;
    return $dir;
}

=helper_method I<add_dequeue($key,$data)>

Write serialized $data into the queue for later dequeueing

=cut

{
    my $queue_index = 1;
    sub add_dequeue($self,$key,$data) {
        my $dir = $self->_dequeue_dir;
        my $fullpath;
        my $timestamp = join( '.',gettimeofday);
        my $filename = join( '.',$key,$PID,$timestamp,$queue_index++,'dequeue');
        $fullpath = "$dir/$filename";
        my $serialised_data = encode_sereal($data);
        write_file($fullpath,{atomic=>1},$serialised_data);
    }
}

=helper_method I<get_dequeue_list($key)>

Return an ArrayRef of all queued items for $key

This may be a list of filenames, or may be a list of some
other ID, it should not be assumed that this value is
useful outside of the dequeue methods.

Used in get_dequeue_object and delete_dequeue_object

=cut

sub get_dequeue_list($self,$key) {
    my $dir = $self->_dequeue_dir;
    my $dequeue_index_file = $dir.'/dequeue.index';
    my $dequeue_lock_file = $dir.'/dequeue.lock';

    my $lock = Lock::File->new( $dequeue_lock_file, {} );
    my $count_new = 0;
    my $count_allocated = 0;
    my $count_stale = 0;

    my $dequeue_index = {};
    my $j = JSON->new->pretty->canonical->utf8;

    # Build a list of Process IDs
    my $process_ids = {};
    my $process_table = Proc::ProcessTable->new();
    foreach my $process ( @{$process_table->table} ) {
        $process_ids->{$process->pid} = 1;
    }

    # Read the last state from the index file
    if ( -e $dequeue_index_file ) {
        eval {
            my $body = scalar read_file($dequeue_index_file);
            $dequeue_index = $j->decode($body);
        };
    }

    my @dequeue_list;
    opendir(my $dh, $dir) || die "Failed to open dequeue directory: $!";
    FILE:
    while (my $file = readdir $dh) {
        if ( $file =~ /^$key\..*\.dequeue$/ ) {
            if ( exists ( $dequeue_index->{ $file } ) ) {
                if ( exists $process_ids->{ $dequeue_index->{$file}->{pid} } ) {
                    # File exists in the index, and is associated with a currently valid PID
                    $count_allocated++;
                    next FILE;
                }
                else {
                    $count_stale++;
                }
            }
            $dequeue_index->{$file} = {
                pid => $PID,
            };
            $count_new++;
            push @dequeue_list, $file;
        }
    }
    closedir $dh;

    # Remove deleted files from the dequeue index
    foreach my $id ( sort keys $dequeue_index->%* ) {
        my $filepath = join('/',$dir,$id);
        delete $dequeue_index->{$id} unless -e $filepath;
    }
    write_file($dequeue_index_file,{atomic=>1},$j->encode($dequeue_index));

    $lock->unlock;

    $self->metric_set( 'dequeue_files_total', { 'key' => $key, 'state' => 'new' }, $count_new - $count_stale );
    $self->metric_set( 'dequeue_files_total', { 'key' => $key, 'state' => 'allocated' }, $count_allocated );
    $self->metric_set( 'dequeue_files_total', { 'key' => $key, 'state' => 'stale' }, $count_stale );

    return \@dequeue_list;
}

=helper_method I<get_dequeue($id)>

Return a previously queued item

=cut

sub get_dequeue($self,$id) {
    my $dir = $self->_dequeue_dir;
    my $filepath = join('/',$dir,$id);
    return if ! -e $filepath;
    return if ! -f $filepath;
    my $serialized = scalar read_file($filepath);
    my $data = decode_sereal($serialized);
    return $data;
}

=helper_method I<delete_dequeue($id)>

Delete a previously queued item

=cut

sub delete_dequeue($self,$id) {
    my $dir = $self->_dequeue_dir;
    my $filepath = join('/',$dir,$id);
    return if ! -e $filepath;
    return if ! -f $filepath;
    unlink $filepath;
}

=helper_method I<error_dequeue($id)>

Mark a previously queued item as errored

=cut

sub error_dequeue($self,$id) {
    my $dir = $self->_dequeue_dir;
    my $filepath = join('/',$dir,$id);
    return if ! -e $filepath;
    return if ! -f $filepath;
    rename $filepath, $filepath . '.err';
}

=helper_method I<add_header_to_sanitize_list($header,$silent)>

Add the given to the list of headers removed by the Sanitize handler if loaded

=cut

sub add_header_to_sanitize_list {
    my($self,$header,$silent) = @_;
    return 0 if ! $self->is_handler_loaded('Sanitize');
    return $self->get_handler('Sanitize')->add_header_to_sanitize_list($header,$silent);
}

=helper_method I<is_local_ip_address()>

Is the current connection from a local ip address?

Requires the LocalIP Handler to be loaded.

=cut

sub is_local_ip_address {
    my ($self) = @_;
    return 0 if ! $self->is_handler_loaded('LocalIP');
    return $self->get_handler('LocalIP')->{'is_local_ip_address'};
}

=helper_method I<is_trusted_ip_address()>

Is the current connection from a trusted ip address?

Requires the TrustedIP Handler to be loaded.

=cut

sub is_trusted_ip_address {
    my ($self) = @_;
    return 0 if ! $self->is_handler_loaded('TrustedIP');
    return $self->get_handler('TrustedIP')->{'is_trusted_ip_address'};
}

=helper_method I<is_encrypted()>

Is the current connection encrypted?

Requires the TLS Handler to be loaded.

In SMTP mode this is only available AFTER the eoh call.

Returns undef if the state is not yet known.

=cut

sub is_encrypted {
    my ($self) = @_;
    return undef if ! $self->is_handler_loaded('TLS'); ## no critic
    return $self->get_handler('TLS')->{'is_encrypted'};
}

=helper_method I<is_authenticated()>

Is the current connection authenticated?

Requires the Auth Handler to be loaded.

=cut

sub is_authenticated {
    my ($self) = @_;
    return 0 if ! $self->is_handler_loaded('Auth');
    return $self->get_handler('Auth')->{'is_authenticated'};
}

=helper_method I<ip_address()>

Return the ip address of the current connection.

=cut

sub ip_address {
    my ($self) = @_;
    my $top_handler = $self->get_top_handler();
    return $top_handler->{'ip_object'}->ip();
}



# Header formatting and data methods

=helper_method I<format_ctext( $text )>

Format text as ctext for use in headers.

Deprecated.

=cut

sub format_ctext {

    # Return ctext (but with spaces intact)
    my ( $self, $text ) = @_;
    $text = q{} if ! defined $text;
    $text =~ s/\t/ /g;
    $text =~ s/\n/ /g;
    $text =~ s/\r/ /g;
    $text =~ s/\(/ /g;
    $text =~ s/\)/ /g;
    $text =~ s/\\/ /g;
    return $text;
}

=helper_method I<format_ctext_no_space( $text )>

Format text as ctext with no spaces for use in headers.

Deprecated.

=cut

sub format_ctext_no_space {
    my ( $self, $text ) = @_;
    $text = $self->format_ctext($text);
    $text =~ s/ //g;
    $text =~ s/;/_/g;
    return $text;
}

=helper_method I<format_header_comment( $comment )>

Format text as a comment for use in headers.

Deprecated.

=cut

sub format_header_comment {
    my ( $self, $comment ) = @_;
    $comment = $self->format_ctext($comment);
    return $comment;
}

=helper_method I<format_header_entry( $key, $value )>

Format text as a key value pair for use in authentication header.

Deprecated.

=cut

sub format_header_entry {
    my ( $self, $key, $value ) = @_;
    $key   = $self->format_ctext_no_space($key);
    $value = $self->format_ctext_no_space($value);
    my $string = "$key=$value";
    return $string;
}

=helper_method I<get_domain_from( $address )>

Extract a single domain from an email address.

=cut

sub get_domain_from {
    my ( $self, $address ) = @_;
    $address = q{} if ! defined $address;
    $address = $self->get_address_from($address);
    my $domain = 'localhost.localdomain';
    $address =~ s/<//g;
    $address =~ s/>//g;
    if ( $address =~ /\@/ ) {
        ($domain) = $address =~ /.*\@(.*)/;
    }
    $domain =~ s/\s//g;
    return lc $domain;
}

=helper_method I<get_domains_from( $address )>

Extract the domains from an email address as an arrayref.

=cut

sub get_domains_from {
    my ( $self, $addresstxt ) = @_;
    $addresstxt = q{} if ! defined $addresstxt;
    my $addresses = $self->get_addresses_from($addresstxt);
    my $domains = [];
    foreach my $address ( @$addresses ) {
        my $domain;
        $address =~ s/<//g;
        $address =~ s/>//g;
        if ( $address =~ /\@/ ) {
            ($domain) = $address =~ /.*\@(.*)/;
        }
        next if ! defined $domain;
        $domain =~ s/\s//g;
        push @$domains, lc $domain;
    }
    return $domains;
}

use constant IsSep => 0;
use constant IsPhrase => 1;
use constant IsEmail => 2;
use constant IsComment => 3;

=helper_method I<get_address_from( $text )>

Extract a single email address from a string.

=cut

sub get_address_from {
    my ( $self, $Str ) = @_;
    my $addresses = $self->get_addresses_from( $Str );
    return $addresses->[0];
}

=helper_method I<get_addresses_from( $text )>

Extract all email address from a string as an arrayref.

=cut

sub get_addresses_from {
    my ( $self, $Str ) = @_;
    $Str = q{} if ! defined $Str;

    if ( $Str eq q{} ) {
        $self->log_error( 'Could not parse empty address' );
        return [ $Str ];
    }

    my $IDNComponentRE = qr/[^\x20-\x2c\x2e\x2f\x3a-\x40\x5b-\x60\x7b-\x7f]+/;
    my $IDNRE = qr/(?:$IDNComponentRE\.)+$IDNComponentRE/;
    my $RFC_atom = qr/[a-z0-9\!\#\$\%\&\'\*\+\-\/\=\?\^\_\`\{\|\}\~]+/i;
    my $RFC_dotatom = qr/${RFC_atom}(?:\.${RFC_atom})*/;

    # Break everything into Tokens
    my ( @Tokens, @Types );
    TOKEN_LOOP:
    while (1) {
        if ($Str =~ m/\G\"(.*?)(?<!\\)(?:\"|\z)\s*/sgc) {
            # String " ... "
            push @Tokens, $1;
            push @Types, IsPhrase;
        }
        elsif ( $Str =~ m/\G\<(.*?)(?<!\\)(?:[>,;]|\z)\s*/sgc) {
            # String < ... >
            push @Tokens, $1;
            push @Types, IsEmail;
        }
        elsif ($Str =~ m/\G\((.*?)(?<!\\)\)\s*/sgc) {
            # String ( ... )
            push @Tokens, $1;
            push @Types, IsComment;
        }
        elsif ($Str =~ m/\G[,;]\s*/gc) {
            # Comma or semi-colon
            push @Tokens, undef;
            push @Types, IsSep;
        }
        elsif ($Str =~ m/\G$/gc) {
            # End of line
            last TOKEN_LOOP;
        }
        elsif ($Str =~ m/\G([^\s,;"<]*)\s*/gc) {
            # Anything else
            if (length $1) {
                push @Tokens, $1;
                push @Types, IsPhrase;
            }
        }
        else {
            # Incomplete line. We'd like to die, but we'll return what we can
            $self->log_error('Could not parse address ' . $Str . ' : Unknown line remainder : ' . substr( $Str, pos() ) );
            push @Tokens, substr($Str, pos($Str));
            push @Types, IsComment;
            last TOKEN_LOOP;
        }
    }

    # Now massage Tokens into [ "phrase", "emailaddress", "comment" ]
    my @Addrs;
    my ($Phrase, $Email, $Comment, $Type);
    for (my $i = 0; $i < scalar(@Tokens); $i++) {
        my ($Type, $Token) = ($Types[$i], $Tokens[$i]);

        # If  - a separator OR
        #     - email address and already got one OR
        #     - phrase and already got email address
        # then add current data as token
        if (($Type == IsSep) ||
            ($Type == IsEmail && defined($Email)) ||
            ($Type == IsPhrase && defined($Email)) ) {
            push @Addrs, $Email if defined $Email;
            ($Phrase, $Email, $Comment) = (undef, undef, undef);
        }

        # A phrase...
        if ($Type == IsPhrase) {
            # Strip '...' around token
            $Token =~ s/^'(.*)'$/$1/;
            # Strip any newlines assuming folded headers
            $Token =~ s/\r?\n//g;

            # Email like token?
            if ($Token =~ /^$RFC_dotatom\@$IDNRE$/o) {
                $Token =~ s/^\s+//;
                $Token =~ s/\s+$//;
                $Token =~ s/\s+\@/\@/;
                $Token =~ s/\@\s+/\@/;
                # Yes, check if next token is definitely email. If yes,
                #  make this a phrase, otherwise make it an email item
                if ($i+1 < scalar(@Tokens) && $Types[$i+1] == IsEmail) {
                    $Phrase = defined($Phrase) ? $Phrase . " " . $Token : $Token;
                }
                else {
                    # If we've already got an email address, add current address
                    if (defined($Email)) {
                        push @Addrs, $Email;
                        ($Phrase, $Email, $Comment) = (undef, undef, undef);
                    }
                    $Email = $Token;
                }
            }
            else {
                # No, just add as phrase
                $Phrase = defined($Phrase) ? $Phrase . " " . $Token : $Token;
            }
        }
        elsif ($Type == IsEmail) {
             # If an email, set email addr. Should be empty
             $Email = $Token;
        }
        elsif ($Type == IsComment) {
            $Comment = defined($Comment) ? $Comment . ", " . $Token : $Token;
        }
        # Must be separator, do nothing
    }

    # Add any remaining addresses
    push @Addrs, $Email if defined($Email);

    if ( ! @Addrs ) {
        # We couldn't parse, so just run with it and hope for the best
        push @Addrs, $Str;
        $self->log_error( 'Could not parse address ' . $Str );
    }

    my @TidyAddresses;
    foreach my $Address ( @Addrs ) {

        next if ( $Address =~ /\@unspecified-domain$/ );

        if ( $Address =~ /^mailto:(.*)$/ ) {
            $Address = $1;
        }

        # Trim whitelist that's possible, but not useful and
        #  almost certainly a copy/paste issue
        #  e.g. < foo @ bar.com >

        $Address =~ s/^\s+//;
        $Address =~ s/\s+$//;
        $Address =~ s/\s+\@/\@/;
        $Address =~ s/\@\s+/\@/;

        push @TidyAddresses, $Address;
    }

    if ( ! @TidyAddresses ) {
        # We really couldn't parse, so just run with it and hope for the best
        push @TidyAddresses, $Str;
    }

    return \@TidyAddresses;

}

=helper_method I<get_my_hostname()>

Return the effective hostname of the MTA.

=cut

sub get_my_hostname {
    my ($self) = @_;
    my $hostname = $self->get_symbol('j');
    if ( ! $hostname ) {
        $hostname = $self->get_symbol('{rcpt_host}');
    }
    if ( ! $hostname ) { # Fallback
        $hostname = hostname;
    }
    return $hostname;
}

=helper_method I<get_my_authserv_id()>

Return the effective authserv-id. Defaults to hostname if not explicitly set.

=cut

sub get_my_authserv_id {
    my ($self) = @_;
    my $config = $self->config();
    if ( exists( $config->{'authserv_id'} ) && $config->{'authserv_id'} ) {
	return $config->{'authserv_id'};
    }
    return $self->get_my_hostname();
}



# Logging

=log_method I<dbgout( $key, $value, $priority )>

Send output to debug and/or Mail Log.

priority is a standard Syslog priority.

=cut

sub dbgout {
    my ( $self, $key, $value, $priority ) = @_;
    my $queue_id = $self->get_symbol('i') || q{--};
    $key   = q{--} if ! defined $key;
    $value = q{--} if ! defined $value;

    my $thischild = $self->{'thischild'};
    if ( exists $thischild->{'tracelog'} ) {
        push $thischild->{'tracelog'}->@*, time2str('%Y:%m:%d %X %z',time) . " $queue_id: $key: $value";
    }

    my $config = $self->config();
    if (
        $priority == LOG_DEBUG
        &&
        ! $config->{'debug'}
    ) {
        return;
    }

    # Sys::Syslog and Log::Dispatchouli have different priority models
    my $log_priority = $priority == LOG_DEBUG   ? 'debug'
                     : $priority == LOG_INFO    ? 'info'
                     : $priority == LOG_NOTICE  ? 'notice'
                     : $priority == LOG_WARNING ? 'warning'
                     : $priority == LOG_ERR     ? 'error'
                     : $priority == LOG_CRIT    ? 'critical'
                     : $priority == LOG_ALERT   ? 'alert'
                     : $priority == LOG_EMERG   ? 'emergency'
                     : 'info';

    if ( $config->{'logtoerr'} ) {
        Mail::Milter::Authentication::_warn( "$queue_id: $key: $value" );
    }

    my $top_handler = $self->get_top_handler();
    if ( !exists( $top_handler->{'dbgout'} ) ) {
        $top_handler->{'dbgout'} = [];
    }
    push @{ $top_handler->{'dbgout'} },
      {
        'priority' => $log_priority,
        'key'      => $key          || q{},
        'value'    => $value        || q{},
      };

    # Write now if we can.
    if ( $self->get_symbol('i') ) {
        $self->dbgoutwrite();
    }
}

=log_method I<log_error( $error )>

Log an error.

=cut

sub log_error {
    my ( $self, $error ) = @_;
    $self->dbgout( 'ERROR', $error, LOG_ERR );
}

=log_method I<dbgoutwrite()>

Write out logs to disc.

Logs are not written immediately, they are written at the end of a connection so we can
include a queue id. This is not available at the start of the process.

=cut

sub dbgoutwrite {
    my ($self) = @_;
    eval {
        my $config = $self->config();
        my $queue_id = $self->get_symbol('i') ||
            'NOQUEUE.' . substr( uc md5_hex( "Authentication Milter Client $PID " . time() . rand(100) ) , -11 );
        my $top_handler = $self->get_top_handler();
        if ( exists( $top_handler->{'dbgout'} ) ) {
            LOGENTRY:
            foreach my $entry ( @{ $top_handler->{'dbgout'} } ) {
                my $key      = $entry->{'key'};
                my $value    = $entry->{'value'};
                my $priority = $entry->{'priority'};
                my $line     = "$queue_id: $key: $value";
                if (
                    $priority eq 'debug'
                    &&
                    ! $config->{'debug'}
                ) {
                    next LOGENTRY;
                }
                Mail::Milter::Authentication::logger()->log( { 'level' => $priority }, $line );
            }
        }
        delete $top_handler->{'dbgout'};
    };
    $self->handle_exception( $@ );  # Not usually called within an eval, however we shouldn't
                                    # ever get a Timeout (for example) here, so it is safe to
                                    # pass to handle_exception anyway.
}



# Header handling

=method I<can_sort_header( $header )>

Returns 1 is this handler has a header_sort method capable or sorting entries for $header
Returns 0 otherwise

=cut

sub can_sort_header {
    my ( $self, $header ) = @_;
    return 0;
}

=method I<header_sort()>

Sorting function for sorting the Authentication-Results headers
Calls out to __HANDLER__->header_sort() to sort headers of a particular type if available,
otherwise sorts alphabetically.

=cut

sub header_sort {
    my ( $self, $sa, $sb ) = @_;

    my $config = $self->config();

    my $string_a;
    my $string_b;

    my $handler_a;
    if ( ref $sa eq 'Mail::AuthenticationResults::Header::Entry' ) {
        $handler_a = $sa->key();
        $string_a = $sa->as_string();
    }
    else {
        ( $handler_a ) = split( '=', $sa, 2 );
        $string_a = $sa;
    }
    my $handler_b;
    if ( ref $sb eq 'Mail::AuthenticationResults::Header::Entry' ) {
        $handler_b = $sb->key();
        $string_b = $sb->as_string();
    }
    else {
        ( $handler_b ) = split( '=', $sb, 2 );
        $string_b = $sb;
    }

    if ( $handler_a eq $handler_b ) {
        # Check for a handler specific sort method
        foreach my $name ( @{$config->{'load_handlers'}} ) {
            my $handler = $self->get_handler($name);
            if ( $handler->can_sort_header( lc $handler_a ) ) {
                if ( $handler->can( 'handler_header_sort' ) ) {
                    return $handler->handler_header_sort( $sa, $sb );
                }
            }
        }
    }

    return $string_a cmp $string_b;
}

sub _stringify_header {
    my ( $self, $header ) = @_;
    if ( ref $header eq 'Mail::AuthenticationResults::Header::Entry' ) {
        return $header->as_string();
    }
    return $header;
}

=method I<add_headers()>

Send the header changes to the MTA.

=cut

sub add_headers {
    my ($self) = @_;
    my $config = $self->config();
    my $top_handler = $self->get_top_handler();
    my @types;
    push @types, keys $top_handler->{'c_auth_headers'}->%* if exists $top_handler->{'c_auth_headers'};
    push @types, keys $top_handler->{'auth_headers'}->%*   if exists $top_handler->{'auth_headers'};
    for my $type (uniq sort @types) {
        $self->add_auth_headers_of_type($type);
    }

    if ( my $reason = $self->get_quarantine_mail() ) {
        $self->prepend_header( 'X-Disposition-Quarantine', $reason );
    }

    $top_handler->top_addheader_callback();

    if ( exists( $top_handler->{'pre_headers'} ) ) {
        foreach my $header ( @{ $top_handler->{'pre_headers'} } ) {
            $self->dbgout( 'PreHeader',
                $header->{'field'} . ': ' . $header->{'value'}, LOG_INFO );
            $self->insert_header( 1, $header->{'field'}, $header->{'value'} );
        }
    }

    if ( exists( $top_handler->{'add_headers'} ) ) {
        foreach my $header ( @{ $top_handler->{'add_headers'} } ) {
            $self->dbgout( 'AddHeader',
                $header->{'field'} . ': ' . $header->{'value'}, LOG_INFO );
            $self->add_header( $header->{'field'}, $header->{'value'} );
        }
    }
}

=method I<add_headers_of_type( $type )>

Find and add all Authentication-Results style headers of given type

=cut

sub add_auth_headers_of_type($self,$type) {
    my $config = $self->config();
    my $top_handler = $self->get_top_handler();

    my @auth_headers;
    if ( exists( $top_handler->{'c_auth_headers'}->{$type} ) ) {
        @auth_headers = @{ $top_handler->{'c_auth_headers'}->{$type} };
    }
    if ( exists( $top_handler->{'auth_headers'}->{$type} ) ) {
        @auth_headers = ( @auth_headers, @{ $top_handler->{'auth_headers'}->{$type} } );
    }
    if (@auth_headers) {

        @auth_headers = sort { $self->header_sort( $a, $b ) } @auth_headers;

        # Do we have any legacy type headers?
        my $are_string_headers = 0;
        my $header_obj = Mail::AuthenticationResults::Header->new();
        foreach my $header ( @auth_headers ) {
            if ( ref $header ne 'Mail::AuthenticationResults::Header::Entry' ) {
                $are_string_headers = 1;
                last;
            }
            $header->orphan() if exists $header->{parent};
            $header_obj->add_child( $header );
        }

        my $header_text;
        if ( $are_string_headers ) {
            # We have legacy headers, add in a legacy way
            $header_text = $self->get_my_authserv_id();
            $header_text .= ";\n    ";
            $header_text .= join( ";\n    ", map { $self->_stringify_header( $_ ) } @auth_headers );
        }
        else {
            $header_obj->set_value( Mail::AuthenticationResults::Header::AuthServID->new()->safe_set_value( $self->get_my_authserv_id() ) );
            $header_obj->set_eol( "\n" );
            if ( exists( $config->{'header_indent_style'} ) ) {
                $header_obj->set_indent_style( $config->{'header_indent_style'} );
            }
            else {
                $header_obj->set_indent_style( 'entry' );
            }
            if ( exists( $config->{'header_indent_by'} ) ) {
                $header_obj->set_indent_by( $config->{'header_indent_by'} );
            }
            else {
                $header_obj->set_indent_by( 4 );
            }
            if ( exists( $config->{'header_fold_at'} ) ) {
                $header_obj->set_fold_at( $config->{'header_fold_at'} );
            }
            $header_text = $header_obj->as_string();
        }

        $self->prepend_header( $type, $header_text );
    }
    elsif ( !$config->{'hide_none'} ) {
        my $header_text = $self->get_my_authserv_id();
        $header_text .= '; none';
        $self->prepend_header( $type, $header_text );
    } else {
        # the result is none and hide_none is set, so we do not add an AR header
    }
}

=method I<prepend_header( $field, $value )>

Add a trace header to the email.

=cut

sub prepend_header {
    my ( $self, $field, $value ) = @_;
    my $top_handler = $self->get_top_handler();
    if ( !exists( $top_handler->{'pre_headers'} ) ) {
        $top_handler->{'pre_headers'} = [];
    }
    push @{ $top_handler->{'pre_headers'} },
      {
        'field' => $field,
        'value' => $value,
      };
}

=method I<add_auth_header( $value )>

Add a section to the authentication header for this email.

=cut

sub add_auth_header($self,$value) {
    my $config = $self->handler_config();
    my $header_name = $config->{auth_header_name} // 'Authentication-Results';
    my $top_handler = $self->get_top_handler();
    $top_handler->{auth_headers} = {} unless exists $top_handler->{auth_headers};
    $top_handler->{auth_headers}->{$header_name} = [] unless exists $top_handler->{auth_headers}->{$header_name};
    push $top_handler->{auth_headers}->{$header_name}->@*, $value;
}

=method I<add_c_auth_header( $value )>

Add a section to the authentication header for this email, and to any subsequent emails for this connection.

=cut

sub add_c_auth_header($self,$value) {
    # Connection wide auth headers
    my $config = $self->handler_config();
    my $header_name = $config->{auth_header_name} // 'Authentication-Results';
    my $top_handler = $self->get_top_handler();
    $top_handler->{c_auth_headers} = {} unless exists $top_handler->{c_auth_headers};
    $top_handler->{c_auth_headers}->{$header_name} = [] unless exists $top_handler->{c_auth_headers}->{$header_name};
    push $top_handler->{c_auth_headers}->{$header_name}->@*, $value;
}

=method I<append_header( $field, $value )>

Add a normal header to the email.

=cut

sub append_header {
    my ( $self, $field, $value ) = @_;
    my $top_handler = $self->get_top_handler();
    if ( !exists( $top_handler->{'add_headers'} ) ) {
        $top_handler->{'add_headers'} = [];
    }
    push @{ $top_handler->{'add_headers'} },
      {
        'field' => $field,
        'value' => $value,
      };
}



# Lower level methods

=low_method I<smfis_continue()>

Return Continue code.

=cut

sub smfis_continue {
    return SMFIS_CONTINUE;
}

=low_method I<smfis_tempfail()>

Return TempFail code.

=cut

sub smfis_tempfail {
    return SMFIS_TEMPFAIL;
}

=low_method I<smfis_reject()>

Return Reject code.

=cut

sub smfis_reject {
    return SMFIS_REJECT;
}

=low_method I<smfis_discard()>

Return Discard code.

=cut

sub smfis_discard {
    return SMFIS_DISCARD;
}

=low_method I<smfis_accept()>

Return Accept code.

=cut

sub smfis_accept {
    return SMFIS_ACCEPT;
}



=low_method I<write_packet( $type, $data )>

Write a packet to the MTA (calls Protocol object)

=cut

sub write_packet {
    my ( $self, $type, $data ) = @_;
    my $thischild = $self->{'thischild'};
    $thischild->write_packet( $type, $data );
}

=low_method I<add_header( $key, $value )>

Write an Add Header packet to the MTA (calls Protocol object)

=cut

sub add_header {
    my ( $self, $key, $value ) = @_;
    my $thischild = $self->{'thischild'};
    my $config = $self->config();
    return if $config->{'dryrun'};
    $thischild->add_header( $key, $value );
}

=low_method I<insert_header( $index, $key, $value )>

Write an Insert Header packet to the MTA (calls Protocol object)

=cut

sub insert_header {
    my ( $self, $index, $key, $value ) = @_;
    my $thischild = $self->{'thischild'};
    my $config = $self->config();
    return if $config->{'dryrun'};
    $thischild->insert_header( $index, $key, $value );
}

=low_method I<change_header( $key, $index, $value )>

Write a Change Header packet to the MTA (calls Protocol object)

=cut

sub change_header {
    my ( $self, $key, $index, $value ) = @_;
    my $thischild = $self->{'thischild'};
    my $config = $self->config();
    return if $config->{'dryrun'};
    $thischild->change_header( $key, $index, $value );
}

1;

__END__

=head1 WRITING HANDLERS

tbc

