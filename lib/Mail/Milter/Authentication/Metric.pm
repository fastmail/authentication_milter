package Mail::Milter::Authentication::Metric;
use strict;
use warnings;
# VERSION

=head1 DESCRIPTION

Handle metrics collection and production for prometheus

=cut

use English qw{ -no_match_vars };
use JSON;
use Mail::Milter::Authentication::Config qw{ get_config };
use Mail::Milter::Authentication::Metric::Grafana;
use Mail::Milter::Authentication::HTDocs;

=constructor I<new()>

my $object = Mail::Milter::Authentication::Metric->new();

Create a new Mail::Milter::Authentication::Metric object
This object is used to store, modify, and report metrics.

=cut

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

=method I<get_timeout()>

Returns the current value of timeout for metrics operations.

=cut

sub get_timeout {
    my ( $self ) = @_;
    my $config = get_config();
    return $config->{ 'metric_timeout' } || 5;
}

=method I<clean_label($text)>

Given a string, return a version of that string which is safe to use as a metrics label.

=cut

sub clean_label {
    my ( $self, $text ) = @_;
    $text = lc $text;
    $text =~ s/[^a-z0-9]/_/g;
    if ( $text eq q{} ) {
        $text = '-none-';
    }
    return $text;
}

=method I<count($args)>

Increment the metric for the given counter
Called from the base handler, do not call directly.
$server is the current handler object

 count_id - the name of the metric to act on

 labels - hashref of labels to apply

 server - the current server object

 count - number to increment by (defaults to 1)

=cut

sub count {
    my ( $self, $args ) = @_;

    my $count_id = $args->{ 'count_id' };
    my $labels   = $args->{ 'labels' };
    my $server   = $args->{ 'server' };
    my $count    = $args->{ 'count' };

    return if ( ! $self->{ 'enabled' } );
    $count = 1 if ! defined $count;

    my $labels_txt = q{};
    if ( $labels ) {
        my @labels_list;
        foreach my $l ( sort keys %$labels ) {
            push @labels_list, $self->clean_label( $l ) .'="' . $self->clean_label( $labels->{$l} ) . '"';
        }
        if ( @labels_list ) {
            $labels_txt = join( ',', @labels_list );
        }
    }

    $count_id =  $self->clean_label( $count_id );

    # Parent can count it's own metrics.
    my $ppid = $server->{ 'server' }->{ 'ppid' };
    if ( $ppid == $PID ) {
        warn "Parent counting metrics";
        ## ToDo factor this out, the code has changed in the child
        eval {
            $labels = '' if ! $labels;
            if ( ! exists( $self->{'counter'}->{ $count_id } ) ) {
                $self->{'counter'}->{ $count_id } = { $labels => 0 };
            }
            if ( ! exists( $self->{'counter'}->{ $count_id }->{ $labels } ) ) {
                $self->{'counter'}->{ $count_id }->{ $labels } = 0;
            }
            $self->{'counter'}->{ $count_id }->{ $labels } = $self->{'counter'}->{ $count_id }->{ $labels } + $count;
        };
        if ( my $error = $@ ) {
            warn "Error counting metrics $error";
        }
        return;
    }

    push @{ $self->{ 'queue' } }, {
        'count'    => $count,
        'count_id' => $count_id,
        'labels'   => $labels_txt,
    };

    return;
}

=method I<send( $server )>

Send metrics to the parent server process.

=cut

sub send { ## no critic
    my ( $self, $server ) = @_;

    return if ( ! $self->{ 'enabled' } );

    my $ppid = $server->{ 'server' }->{ 'ppid' };
    if ( $ppid == $PID ) {
        warn "Parent tried to talk to itself to send metrics";
        return;
    }

    eval {
        local $SIG{'ALRM'} = sub{ die 'Timeout sending metrics' };
        alarm( $self->get_timeout() );

        my $psocket = $server->{'server'}->{'parent_sock'};
        return if ! $psocket;

        my $config = get_config();

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

=method I<register_metrics( $hash )>

Register a new set of metric types and help texts.
Called from the master process in the setup phase.

Expects a hashref of metric description, keyed on metric name.

=cut

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

=method I<master_metric_get( $request, $socket, $server )>

Called in the master process to return metrics to the requestor

=cut

sub master_metric_get {
    my ( $self, $request, $socket, $server ) = @_;
    my $ident = '{ident="' . $self->clean_label( $Mail::Milter::Authentication::Config::IDENT ) . '"}';
    my $guage_help = {
        'waiting'    => 'The number of authentication milter processes in a waiting state',
        'processing' => 'The number of authentication milter processes currently processing data',
    };
    my $response = q{};
    $response .= "# TYPE authmilter_uptime_seconds_total counter\n";
    $response .= "# HELP authmilter_uptime_seconds_total Number of seconds since server startup\n";
    $response .= 'authmilter_uptime_seconds_total' . $ident . ' ' . ( time - $self->{'start_time'} ) . "\n";
    foreach my $type ( qw { waiting processing } ) {
        $response .= '# TYPE authmilter_processes_' . $type . " gauge\n";
        $response .= '# HELP authmilter_processes_' . $type . ' ' . $guage_help->{ $type } . "\n";
        $response .= 'authmilter_processes_' . $type . $ident . ' ' . $server->{'server'}->{'tally'}->{ $type } . "\n";
    }
    foreach my $key ( sort keys %{ $self->{'counter'} } ) {
        $response .= '# TYPE authmilter_' . $key . " counter\n";
        my $help = $self->{'help'}->{ $key };
        if ( $help ) {
            $response .= '# HELP authmilter_' . $key . ' ' . $self->{'help'}->{ $key } . "\n";
        }
        foreach my $labels ( sort keys %{ $self->{'counter'}->{ $key } } ) {
            my $labels_txt = '{ident="' . $self->clean_label( $Mail::Milter::Authentication::Config::IDENT ) . '"';
            if ( $labels ne q{} ) {
                $labels_txt .= ',' . $labels;
            }
            $labels_txt .= '}';
            $response .= 'authmilter_' . $key . $labels_txt . ' ' . $self->{'counter'}->{ $key }->{ $labels } . "\n";
        }
    }
    print $socket $response . "\0\n";
    return;
}

=method I<master_metric_count( $request, $socket, $server )>

Called in the master process to update metrics values

=cut

sub master_metric_count {
    my ( $self, $request, $socket, $server ) = @_;
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
    return;
}

=method I<master_handler( $request, $socket, $server)>

Handle a metrics request in the master process.

=cut

sub master_handler {
    my ( $self, $request, $socket, $server ) = @_;
    my $config = get_config();

    eval {
        if ( $request->{ 'method' } eq 'METRIC.GET' ) {
            $self->master_metric_get( $request, $socket, $server );
        }
        elsif ( $request->{ 'method' } eq 'METRIC.COUNT' ) {
            $self->master_metric_count( $request, $socket, $server );
        }
    };
    if ( my $error = $@ ) {
        warn "Metrics handler error $error";
    }

    return;
}

=method I<child_handler( $server)>

Handle a metrics or http request in the child process.

=cut

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

        if ( $request_method ne 'GET' ) {
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

        if ( $request_uri eq '/metrics' ) {

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

        }
        elsif ( $request_uri eq '/' ){
            my $config = get_config();
            print $socket "HTTP/1.0 200 OK\n";
            print $socket "Content-Type: text/html\n";
            print $socket "\n";
            print $socket qq{
<html>
<head>
<title>Authentication Milter</title>
<link rel="stylesheet" href="/css/normalize.css" />
<link rel="stylesheet" href="/css/skeleton.css" />
<link rel="stylesheet" href="/css/authmilter.css" />
</head>
<body>

<div class="container">

<h1>Authentication Milter</h1>

    <h2>Running server</h2>
    <ul>
        <li>Version: } . $Mail::Milter::Authentication::VERSION . qq{</li>
        <li>Ident: } . $Mail::Milter::Authentication::Config::IDENT . qq{</li>
    </ul>

    <h2>Installed Handlers</h2>
    <div class="spaceAfter">};

    foreach my $Handler ( sort keys %{ $server->{ 'handler' } } ) {
        next if $Handler eq '_Handler';
        print $socket ' <span class="handler">' . $Handler . ' (' . $server->{ 'handler' }->{ $Handler }->get_version(). ')</span> ';
    }

    print $socket qq{
    </div>

    <h2>Registered Callbacks</h2>
    <table class="callbacksTable">};

    foreach my $stage ( qw{ setup connect helo envfrom envrcpt header eoh body eom abort close addheader } ) {
        my $callbacks = $server->{ 'handler' }->{ '_Handler' }->get_callbacks( $stage );
        print $socket "<tr><td>$stage</td><td>" . join( ' ', map{ "<span class=\"handler\">$_</span>" } @$callbacks ) . "</td></tr>";
    }

    print $socket qq{</table>

    <h2>Connection Details</h2>
    <ul>};
    print $socket '<li>Protocol: ' . $config->{'protocol'} . '</li>';
    my $connections = $config->{'connections'};
    $connections->{'default'} = { 'connection' => $config->{'connection'} };
    foreach my $connection ( sort keys %$connections ) {
        print $socket '<li>' . $connection . ': ' . $connections->{ $connection }->{ 'connection' } . '</li>'
    }
    print $socket qq{
    </ul>

    <h2>Metrics</h2>
    <ul>
        <li><a href="/metrics">Prometheus metrics endpoint</a></li>
        <li>Example <a href="/grafana">Grafana dashboard</a> for this setup</li>
    </ul>

    <hr />

 </div>
</body>
};
        }
        elsif ( $request_uri eq '/grafana' ) {
            print $socket "HTTP/1.0 200 OK\n";
            print $socket "Content-Type: application/json\n";
            print $socket "\n";

            my $Grafana = Mail::Milter::Authentication::Metric::Grafana->new();
            print $socket $Grafana->get_dashboard( $server );
        }
        else {
            my $htdocs = Mail::Milter::Authentication::HTDocs->new();
            my $result = $htdocs->get_file( $request_uri );
            if ( $result ) {
                print $socket $result;
            }
            else {
                print $socket "HTTP/1.0 404 Not Found\n";
                print $socket "Content-Type: text/plain\n";
                print $socket "\n";
                print $socket "Not Found\n";
            }
        }

        alarm( 0 );
    };

    return;
}

1;

