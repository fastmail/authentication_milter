package Mail::Milter::Authentication::Metric;
use 5.20.0;
use strict;
use warnings;
use Mail::Milter::Authentication::Pragmas;
# ABSTRACT: Class for metrics generation
# VERSION
use Mail::Milter::Authentication::Config qw{ get_config };
use Mail::Milter::Authentication::HTDocs;
use Mail::Milter::Authentication::Metric::Grafana;
use JSON;
use Prometheus::Tiny::Shared;
use TOML;

=head1 DESCRIPTION

Handle metrics collection and production for prometheus

=cut


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

    if ( $self->{'enabled'} ) {
        my $cache_args = {};
        $cache_args->{'init_file'} = 1;
        if ( defined( $config->{'metric_tempfile'} ) ) {
            $cache_args->{'share_file'} = $config->{'metric_tempfile'};
        }
        $self->{'prom'} = Prometheus::Tiny::Shared->new( cache_args => $cache_args );
        $self->{'prom'}->declare( 'authmilter_uptime_seconds_total', help => 'Number of seconds since server startup', type => 'counter' );
        $self->{'prom'}->declare( 'authmilter_processes_waiting', help => 'The number of authentication milter processes in a waiting state', type => 'gauge' );
        $self->{'prom'}->declare( 'authmilter_processes_processing', help => 'The number of authentication milter processes currently processing data', type => 'gauge' );
        $self->{'prom'}->declare( 'authmilter_version', help => 'Running versions', type => 'gauge' );
    }

    bless $self, $class;
    return $self;
}

=method I<set_versions( $server )>

Setup version metrics

=cut

sub set_versions {
    my ( $self, $server ) = @_;
    $self->{'prom'}->set( 'authmilter_version', 1, { version => $Mail::Milter::Authentication::VERSION, module => 'core', ident => $self->clean_label( $Mail::Milter::Authentication::Config::IDENT ) });
    foreach my $Handler ( sort keys %{ $server->{ 'handler' } } ) {
        next if $Handler eq '_Handler';
        $self->{'prom'}->set( 'authmilter_version', 1, { version => $server->{ 'handler' }->{ $Handler }->get_version(), module => $Handler, ident => $self->clean_label( $Mail::Milter::Authentication::Config::IDENT ) });
    }
    return;
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
    return if ( ! $self->{ 'enabled' } );

    my $count_id = $args->{ 'count_id' };
    my $labels   = $args->{ 'labels' };
    my $server   = $args->{ 'server' };
    my $count    = $args->{ 'count' };

    $count = 1 if ! defined $count;

    $count_id =  $self->clean_label( $count_id );

    my $clean_labels = {};
    if ( $labels ) {
        foreach my $l ( sort keys %$labels ) {
            $clean_labels->{ $self->clean_label( $l ) } = $self->clean_label( $labels->{$l} );
        }
    }

    $clean_labels->{ident} = $self->clean_label( $Mail::Milter::Authentication::Config::IDENT );

    eval{ $self->{prom}->add( 'authmilter_' . $count_id, $count, $clean_labels ); };
    ## TODO catch and re-throw timeouts

    return;
}

=method I<set($args)>

Set the metric for the given counter
Called from the base handler, do not call directly.
$server is the current handler object

 count_id - the name of the metric to act on

 labels - hashref of labels to apply

 server - the current server object

 count - number to increment by (defaults to 1)

=cut

sub set {
    my ( $self, $args ) = @_;
    return if ( ! $self->{ 'enabled' } );

    my $gauge_id = $args->{ 'gauge_id' };
    my $labels   = $args->{ 'labels' };
    my $server   = $args->{ 'server' };
    my $value    = $args->{ 'value' };

    die 'metric set must define value' if ! defined $value;

    $gauge_id =  $self->clean_label( $gauge_id );

    my $clean_labels = {};
    if ( $labels ) {
        foreach my $l ( sort keys %$labels ) {
            $clean_labels->{ $self->clean_label( $l ) } = $self->clean_label( $labels->{$l} );
        }
    }

    $clean_labels->{ident} = $self->clean_label( $Mail::Milter::Authentication::Config::IDENT );

    eval{ $self->{prom}->set( 'authmilter_' . $gauge_id, $value, $clean_labels ); };
    ## TODO catch and re-throw timeouts

    return;
}

=method I<send( $server )>

Send metrics to the parent server process.

=cut

sub send { ## no critic
    my ( $self, $server ) = @_;
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
        my $data = $hash->{ $metric };
        my $help;
        my $type = 'counter';
        if ( ref $data eq 'HASH' ) {
            $help = $data->{help};
            $type = $data->{type};
        }
        else {
            $help = $data;
        }
        $self->{prom}->declare( 'authmilter_' . $metric, help => $help, type => $type);
        $self->{prom}->set( 'authmilter_' . $metric,0, { ident => $self->clean_label( $Mail::Milter::Authentication::Config::IDENT ) });
    }
    return;
}

=method I<master_metric_update( $server )>

Called in the master process to periodically update some metrics

=cut

sub master_metric_update {
    my ( $self, $server ) = @_;
    return if ( ! $self->{ 'enabled' } );

    eval {
        foreach my $type ( qw { waiting processing } ) {
            $self->{prom}->set('authmilter_processes_' . $type, $server->{'server'}->{'tally'}->{ $type }, { ident => $self->clean_label( $Mail::Milter::Authentication::Config::IDENT ) });
        }
    };

    return;
}

=method I<child_handler( $server )>

Handle a metrics or http request in the child process.

=cut

sub child_handler {
    my ( $self, $server ) = @_;
    return if ( ! $self->{ 'enabled' } );

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
            $server->{'handler'}->{'_Handler'}->top_metrics_callback();
            $self->{prom}->set( 'authmilter_uptime_seconds_total', time - $self->{'start_time'}, { ident => $self->clean_label( $Mail::Milter::Authentication::Config::IDENT ) });

            print $socket "HTTP/1.0 200 OK\n";
            print $socket "Content-Type: text/plain\n";
            print $socket "\n";
            print $socket $self->{prom}->format();

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

    <span class="versionBlock">Version: } . $Mail::Milter::Authentication::VERSION . qq{<br />Ident: } . $Mail::Milter::Authentication::Config::IDENT . qq{</span>

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

    <h2>Connection/Config Details</h2>
    <ul>};
    print $socket '<li>Protocol: ' . $config->{'protocol'} . '</li>';
    my $connections = $config->{'connections'};
    $connections->{'default'} = { 'connection' => $config->{'connection'} };
    foreach my $connection ( sort keys %$connections ) {
        print $socket '<li>' . $connection . ': ' . $connections->{ $connection }->{ 'connection' } . '</li>'
    }
    print $socket qq{
        <li>Effective config (<a href="/config/toml">toml</a>/<a href="/config/json">json</a>)</li>
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
        elsif ( $request_uri eq '/config/json' || $request_uri eq '/config' ) {
            print $socket "HTTP/1.0 200 OK\n";
            print $socket "Content-Type: text/plain\n";
            print $socket "\n";
            my $json = JSON->new();
            $json->canonical();
            $json->pretty();
            print $socket $json->encode( $config );;
        }
        elsif ( $request_uri eq '/config/toml' ) {
            print $socket "HTTP/1.0 200 OK\n";
            print $socket "Content-Type: text/plain\n";
            print $socket "\n";
            my $toml = TOML::to_toml( $config );
            $toml =~ s/\n\[/\n\n\[/g;
            print $socket $toml;
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

