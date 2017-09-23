package Mail::Milter::Authentication::Metric;
use strict;
use warnings;
use version; our $VERSION = version->declare('v1.1.3');
use English qw{ -no_match_vars };
use JSON;
use Mail::Milter::Authentication::Config qw{ get_config };

sub new {
    my ( $class ) = @_;
    my $self = {};
    $self->{'counter'}    = {};
    $self->{'help'}       = {};
    $self->{'start_time'} = time;
    $self->{'queue'}      = [];

    my $config = get_config();

    $self->{'enabled'} = defined( $config->{'metric_port'} ) ? 1
                       : defined( $config->{'metric_connection'} ) ? 1
                       : 0;

    bless $self, $class;
    return $self;
}

sub get_timeout {
    my ( $self ) = @_;
    my $config = get_config();
    return $config->{ 'metric_timeout' } || 5;
}

sub clean_label {
    my ( $self, $text ) = @_;
    $text = lc $text;
    $text =~ s/[^a-z0-9]/_/g;
    if ( $text eq q{} ) {
        $text = '-none-';
    }
    return $text;
}

sub count {
    my ( $self, $args ) = @_;

    my $count_id = $args->{ 'count_id' };
    my $labels   = $args->{ 'labels' };
    my $server   = $args->{ 'server' };
    my $count    = $args->{ 'count '};

    return if ( ! $self->{ 'enabled' } );
    $count = 1 if ! defined $count;

    my $labels_txt = q{};
    if ( $labels ) {
        my @labels_list;
        foreach my $l ( sort keys %$labels ) {
            push @labels_list, $self->clean_label( $l ) .'="' . $self->clean_label( $labels->{$l} ) . '"';
        }
        $labels_txt = ' ' . join( ',', @labels_list );
    }

    $count_id =  $self->clean_label( $count_id );

    push @{ $self->{ 'queue' } }, {
        'count'    => $count,
        'count_id' => $count_id,
        'labels'   => $labels_txt,
    };

    return;
}

sub send {
    my ( $self, $server ) = @_;

    return if ( ! $self->{ 'enabled' } );

    my $psocket = $server->{'server'}->{'parent_sock'};
    return if ! $psocket;

    my $config = get_config();

    eval {
        local $SIG{'ALRM'} = sub{ die 'Timeout sending metrics' };
        alarm( $self->get_timeout() );

        print $psocket encode_json({
            'method' => 'METRIC.COUNT',
            'data'   => $self->{ 'queue' },
        }) . "\n";

        my $ping = <$psocket>;
        alarm( 0 );
        die 'Failure counting metrics, has master gone away?' if ! $ping;
    };
    if ( my $error = $@ ) {
        warn $error;
        return 0;
    }

    $self->{ 'queue' } = [];

    return;
}

sub register_metrics {
    my ( $self, $hash ) = @_;
    return if ( ! $self->{ 'enabled' } );

    foreach my $metric ( keys %$hash ) {
        my $help = $hash->{ $metric };
        if ( ! exists( $self->{'counter'}->{ $metric } ) ) {
            $self->{'counter'}->{ $metric } = { '' => 0 };
        }
        $self->{'help'}->{ $self->clean_label( $metric ) } = $help;
    }
    return;
}

sub master_handler {
    my ( $self, $request, $socket, $server ) = @_;
    my $config = get_config();

    eval {
        local $SIG{'ALRM'} = sub{ die "Timeout\n" };
        alarm( $self->get_timeout() );

        my $ident = '{ident="' . $self->clean_label( $Mail::Milter::Authentication::Config::IDENT ) . '"}';

        my $guage_help = {
            'waiting'    => 'The number of authentication milter processes in a waiting state',
            'processing' => 'The number of authentication milter processes currently processing data',
        };


        if ( $request->{ 'method' } eq 'METRIC.GET' ) {
            print $socket "# TYPE authmilter_uptime_seconds_total counter\n";
            print $socket "# HELP authmilter_uptime_seconds_total Number of seconds since server startup\n";
            print $socket 'authmilter_uptime_seconds_total' . $ident . ' ' . ( time - $self->{'start_time'} ) . "\n";
            foreach my $type ( qw { waiting processing } ) {
                print $socket '# TYPE authmilter_processes_' . $type . " gauge\n";
                print $socket '# HELP authmilter_processes_' . $type . ' ' . $guage_help->{ $type } . "\n";
                print $socket 'authmilter_processes_' . $type . $ident . ' ' . $server->{'server'}->{'tally'}->{ $type } . "\n";
            }
            foreach my $key ( sort keys %{ $self->{'counter'} } ) {
                print $socket '# TYPE authmilter_' . $key . " counter\n";
                my $help = $self->{'help'}->{ $key };
                if ( $help ) {
                    print $socket '# HELP authmilter_' . $key . ' ' . $self->{'help'}->{ $key } . "\n";
                }
                foreach my $labels ( sort keys %{ $self->{'counter'}->{ $key } } ) {
                    my $labels_txt = '{ident="' . $self->clean_label( $Mail::Milter::Authentication::Config::IDENT ) . '"';
                    if ( $labels ne q{} ) {
                        $labels_txt .= ',' . $labels;
                    }
                    $labels_txt .= '}';
                    print $socket 'authmilter_' . $key . $labels_txt . ' ' . $self->{'counter'}->{ $key }->{ $labels } . "\n";
                }
            }
            print $socket "\0\n";
        }
        elsif ( $request->{ 'method' } eq 'METRIC.COUNT' ) {
            my $data = $request->{ 'data' };
            foreach my $datum ( @$data ) {
                my $count    = $datum->{ 'count' };
                my $count_id = $datum->{ 'count_id' };
                my $labels   = $datum->{ 'labels' };
                $labels = '' if ! $labels;
                if ( ! exists( $self->{'counter'}->{ $count_id } ) ) {
                    $self->{'counter'}->{ $count_id } = { $labels => 0 };
                }
                if ( ! exists( $self->{'counter'}->{ $count_id }->{ $labels } ) ) {
                    $self->{'counter'}->{ $count_id }->{ $labels } = 0;
                }
                $self->{'counter'}->{ $count_id }->{ $labels } = $self->{'counter'}->{ $count_id }->{ $labels } + $count;
            }
            print $socket "1\n";

        }

        alarm( 0 );
    };
    if ( my $error = $@ ) {
        warn "Metrics handler error $error";
    }

    return;
}

sub child_handler {
    my ( $self, $server ) = @_;
    my $config = get_config();

    eval {
        local $SIG{'ALRM'} = sub{ die "Timeout\n" };
        alarm( $self->get_timeout() );

        my $socket = $server->{'server'}->{'client'};
        my $req;

        $PROGRAM_NAME = $Mail::Milter::Authentication::Config::IDENT . ':metrics';

        $req = <$socket>;
        $req =~ s/[\n\r]+$//;

        if (!defined($req) || $req !~ m{ ^\s*(GET|POST|PUT|DELETE|PUSH|HEAD|OPTIONS)\s+(.+)\s+(HTTP/1\.[01])\s*$ }ix) {
            print $socket "HTTP/1.0 500 Server Error\n";
            print $socket "\n";
            print $socket "Invalid Request Error\n";
            return;
        }

        my $request_method  = uc $1;
        my $request_uri     = $2;
        my $server_protocol = $3;
        if ( $request_method   ne 'GET' || $request_uri      ne '/metrics' ) {
            print $socket "HTTP/1.0 500 Server Error\n";
            print $socket "\n";
            print $socket "Server Error\n";
            return;
        }

        # Ignore the rest of the HTTP request
        while ( $req = <$socket> ) {
            $req =~ s/[\n\r]+$//;
            last if $req eq q{};
        }

        my $psocket = $server->{'server'}->{'parent_sock'};
        my $request = encode_json({ 'method' => 'METRIC.GET' });
        print $psocket "$request\n";

        print $socket "HTTP/1.0 200 OK\n";
        print $socket "Content-Type: text/plain\n";
        print $socket "\n";
        while ( my $value = <$psocket> ) {
            $value =~ s/[\n\r]+$//;
            last if $value eq "\0";
            print $socket "$value\n";
        }

        alarm( 0 );
    };

    return;
}

1;

__END__

=head1 NAME

Mail::Milter::Authentication::Metric - Collect and produce metrics data

=head1 DESCRIPTION

Handle metrics collection and production for prometheus

=head1 CONSTRUCTOR

=over

=item new()

my $object = Mail::Milter::Authentication::Metric->new();

Creates a new metric object.

=back

=head1 METHODS

=over

=item count( $id, $labels, $server )

Increment the metric for the given counter
Called from the base handler, do not call directly.
$server is the current handler object

=item register_metrics( $hash )

Register a new set of metric types and help texts.
Called from the master process in the setup phase.

=item master_handler( $request, $socket, $server )

Handle a request for metrics from a child in the master process.

=item child_handler( $server )

Handle a request for metrics in a child process.

=back

=head1 AUTHORS

Marc Bradshaw E<lt>marc@marcbradshaw.netE<gt>

=head1 COPYRIGHT

Copyright 2017

This library is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.
