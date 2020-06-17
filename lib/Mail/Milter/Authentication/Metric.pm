package Mail::Milter::Authentication::Metric;
use 5.20.0;
use strict;
use warnings;
use Mail::Milter::Authentication::Pragmas;
# ABSTRACT: Class for metrics generation
# VERSION
use Mail::Milter::Authentication::HTDocs;
use Mail::Milter::Authentication::Metric::Grafana;
use File::Temp;
use Prometheus::Tiny::Shared 0.020;
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
    my ( $class, $thischild ) = @_;
    my $self = {};
    $self->{counter}            = {};
    $self->{help}               = {};
    $self->{start_time}         = time;
    $self->{registered_metrics} = [];
    $self->{thischild}          = $thischild;
    bless $self, $class;

    $self->set_handler( undef );

    my $config = get_config();

    $self->{enabled} = defined( $config->{metric_port} ) ? 1
                     : defined( $config->{metric_connection} ) ? 1
                     : 0;

    return $self;
}

=method I<set_handler($handler)>

Set a reference to the current handler

=cut

sub set_handler {
    my ( $self, $handler ) = @_;
    $self->{handler} = $handler;
}

=method I<handle_exception($exception)>

If we have a handler, then pass any exception to that handlers exception handling

=cut

sub handle_exception {
    my ( $self, $exception ) = @_;
    return if ! defined $exception;
    return if ! defined $self->{handler};
    $self->{handler}->handle_exception($exception);
}

=log_method I<dbgout( $key, $value, $priority )>

Pass arguments along to the dbgout method of the handler if we have one
or log via the Mail::Milter::Authentication object if we do not.

=cut

sub dbgout {
    my ( $self, $key, $value, $priority ) = @_;
    if ( defined ( $self->{handler} ) ) {
        $self->{handler}->dbgout($key,$value,$priority);
    }
    elsif ( $priority == LOG_DEBUG ) {
        $self->{thischild}->logdebug( "$key: $value" );
    }
    elsif ( $priority == LOG_INFO || $priority == LOG_NOTICE ) {
        $self->{thischild}->loginfo( "$key: $value" );
    }
    else {
        $self->{thischild}->logerror( "$key: $value" );
    }
}

=method I<prom()>

Return the prom object if available

=cut

sub prom {
    my ( $self ) = @_;
    my $config = get_config();

    my $metric_tempfile;
    if ( exists( $self->{metric_tempfile} ) ) {
        $metric_tempfile = $self->{metric_tempfile};
    }
    else {
        if ( defined( $config->{metric_tempfile} ) ) {
            $metric_tempfile = $config->{metric_tempfile};
        }
        if ( ! $metric_tempfile ) {
            $metric_tempfile = $config->{lib_dir}.'/metrics';
        }
        $self->{metric_tempfile} = $metric_tempfile;
    }

    my $prom = $self->{prom};
    # Invalidate if the file does not exist!
    if ( ! -e $metric_tempfile ) {
        $prom = undef;
    }
    if ( ! -d $metric_tempfile ) {
        # If metric_tempfile is a regular file then we need to re-init with a directory
        # this is likely a restart after upgrade.
        $prom = undef;
    }

    if ( ! $prom ) {
        if ( -f $metric_tempfile ) {
            unlink $metric_tempfile;
        }
        if ( ! -d $metric_tempfile ) {
            mkdir $metric_tempfile, 0700;
        }
        $self->dbgout( 'Metrics', "Setup new metrics file $metric_tempfile", LOG_DEBUG );
        $prom = eval{ Prometheus::Tiny::Shared->new(filename => $metric_tempfile.'/authmilter_metrics', init_file => 1) };
        $self->handle_exception($@);
        if ( $prom ) {
            $self->{metric_tempfile} = $metric_tempfile;
            $prom->declare( 'authmilter_uptime_seconds_total', help => 'Number of seconds since server startup', type => 'counter' );
            $prom->declare( 'authmilter_processes_waiting', help => 'The number of authentication milter processes in a waiting state', type => 'gauge' );
            $prom->declare( 'authmilter_processes_processing', help => 'The number of authentication milter processes currently processing data', type => 'gauge' );
            $prom->declare( 'authmilter_version', help => 'Running versions', type => 'gauge' );
        }
        else {
            $self->dbgout( 'Metrics', "Failed to setup new metrics file $metric_tempfile", LOG_ERR );
        }
    }
    $self->{prom} = $prom;

    return $prom;
}

=method I<set_versions( $server )>

Setup version metrics

=cut

sub set_versions {
    my ( $self, $server ) = @_;
    return if ! $self->{enabled};
    return if ! $self->prom;
    $self->dbgout( 'Metrics', "Setting up versioning metrics", LOG_DEBUG );
    $self->prom->set( 'authmilter_version', 1, { version => $Mail::Milter::Authentication::VERSION, module => 'core', ident => $self->clean_label( $Mail::Milter::Authentication::Config::IDENT ) });
    foreach my $Handler ( sort keys %{ $server->{handler} } ) {
        next if $Handler eq '_Handler';
        eval{ $self->prom->set( 'authmilter_version', 1, { version => $server->{handler}->{ $Handler }->get_version(), module => $Handler, ident => $self->clean_label( $Mail::Milter::Authentication::Config::IDENT ) }) };
        $self->handle_exception($@);
    }
}


=method I<get_timeout()>

Returns the current value of timeout for metrics operations.

=cut

sub get_timeout {
    my ( $self ) = @_;
    my $config = get_config();
    return $config->{metric_timeout} || 5;
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
    return if ! $self->{enabled};
    return if ! $self->prom;

    my $count_id = $args->{count_id};
    my $labels   = $args->{labels};
    my $server   = $args->{server};
    my $count    = $args->{count};

    $count = 1 if ! defined $count;

    $count_id =  $self->clean_label( $count_id );

    my $clean_labels = {};
    if ( $labels ) {
        foreach my $l ( sort keys %$labels ) {
            $clean_labels->{ $self->clean_label( $l ) } = $self->clean_label( $labels->{$l} );
        }
    }

    $clean_labels->{ident} = $self->clean_label( $Mail::Milter::Authentication::Config::IDENT );

    $self->dbgout( 'Metrics', "Counting $count_id:$count:".join(',',map {"$_=".$clean_labels->{$_}} (sort keys %$clean_labels) ), LOG_DEBUG );

    eval{ $self->prom->add( 'authmilter_' . $count_id, $count, $clean_labels ); };
    $self->handle_exception($@);
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
    return if ! $self->{enabled};
    return if ! $self->prom;

    my $gauge_id = $args->{gauge_id};
    my $labels   = $args->{labels};
    my $server   = $args->{server};
    my $value    = $args->{value};

    die 'metric set must define value' if ! defined $value;

    $gauge_id =  $self->clean_label( $gauge_id );

    my $clean_labels = {};
    if ( $labels ) {
        foreach my $l ( sort keys %$labels ) {
            $clean_labels->{ $self->clean_label( $l ) } = $self->clean_label( $labels->{$l} );
        }
    }

    $clean_labels->{ident} = $self->clean_label( $Mail::Milter::Authentication::Config::IDENT );

    $self->dbgout( 'Metrics', "Setting $gauge_id:$value:".join(',',map {"$_=".$clean_labels->{$_}} (sort keys %$clean_labels) ), LOG_DEBUG );

    eval{ $self->prom->set( 'authmilter_' . $gauge_id, $value, $clean_labels ); };
    $self->handle_exception($@);
}

=method I<send( $server )>

Send metrics to the parent server process.

=cut

sub send { ## no critic
    my ( $self, $server ) = @_;
}

=method I<register_metrics( $hash )>

Register a new set of metric types and help texts.
Called from the master process in the setup phase.

Expects a hashref of metric description, keyed on metric name.

=cut

sub register_metrics {
    my ( $self, $hash ) = @_;
    return if ! $self->{enabled};
    return if ! $self->prom;
    push @{$self->{registered_metrics}}, $hash;
    $self->_register_metrics( $hash );
}

=method I<re_register_metric()>

Re-register currently registered metrics to ensure backend
metadata is correct

=cut

sub re_register_metrics {
    my ( $self ) = @_;
    return if ! $self->{enabled};
    return if ! $self->prom;
    foreach my $metric ( @{$self->{registered_metrics}} ) {
        $self->_register_metrics( $metric );
    }
}

sub _register_metrics {
    my ( $self, $hash ) = @_;
    return if ! $self->{enabled};
    return if ! $self->prom;

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
        $self->prom->declare( 'authmilter_' . $metric, help => $help, type => $type);
        $self->prom->add( 'authmilter_' . $metric,0, { ident => $self->clean_label( $Mail::Milter::Authentication::Config::IDENT ) });
    }
}

=method I<master_metric_update( $server )>

Called in the master process to periodically update some metrics

=cut

sub master_metric_update {
    my ( $self, $server ) = @_;
    return if ! $self->{enabled};
    return if ! $self->prom;

    eval {
        foreach my $type ( qw { waiting processing } ) {
            $self->prom->set('authmilter_processes_' . $type, $server->{server}->{tally}->{$type}, { ident => $self->clean_label( $Mail::Milter::Authentication::Config::IDENT ) });
        }
    };
}

=method I<child_handler( $server )>

Handle a metrics or http request in the child process.

=cut

sub child_handler {
    my ( $self, $server ) = @_;
    return if ! $self->{enabled};

    my $config = get_config();

    eval {
        local $SIG{ALRM} = sub{ die "Timeout\n" };
        alarm( $self->get_timeout() );

        my $socket = $server->{server}->{client};
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
            if ( $self->prom ) {
                $server->{handler}->{_Handler}->top_metrics_callback();
                $self->prom->set( 'authmilter_uptime_seconds_total', time - $self->{start_time}, { ident => $self->clean_label( $Mail::Milter::Authentication::Config::IDENT ) });
            }

            print $socket "HTTP/1.0 200 OK\n";
            print $socket "Content-Type: text/plain\n";
            print $socket "\n";
            if ( $self->prom ) {
                print $socket $self->prom->format();
            }
            else {
                print $socket '# Metrics unavailable';
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

    <span class="versionBlock">Version: } . $Mail::Milter::Authentication::VERSION . qq{<br />Ident: } . $Mail::Milter::Authentication::Config::IDENT . qq{</span>

    <h2>Installed Handlers</h2>
    <div class="spaceAfter">};

    foreach my $Handler ( sort keys %{ $server->{handler} } ) {
        next if $Handler eq '_Handler';
        print $socket ' <span class="handler">' . $Handler . ' (' . $server->{handler}->{ $Handler }->get_version(). ')</span> ';
    }

    print $socket qq{
    </div>

    <h2>Registered Callbacks</h2>
    <table class="callbacksTable">};

    foreach my $stage ( qw{ setup connect helo envfrom envrcpt header eoh body eom abort close addheader } ) {
        my $callbacks = $server->{handler}->{_Handler}->get_callbacks( $stage );
        print $socket "<tr><td>$stage</td><td>" . join( ' ', map{ "<span class=\"handler\">$_</span>" } @$callbacks ) . "</td></tr>";
    }

    print $socket qq{</table>

    <h2>Connection/Config Details</h2>
    <ul>};
    print $socket '<li>Protocol: ' . $config->{protocol} . '</li>';
    my $connections = $config->{connections};
    $connections->{default} = { connection => $config->{connection} };
    foreach my $connection ( sort keys %$connections ) {
        print $socket '<li>' . $connection . ': ' . $connections->{ $connection }->{connection} . '</li>'
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
            my $json = JSON::XS->new();
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
}

1;
