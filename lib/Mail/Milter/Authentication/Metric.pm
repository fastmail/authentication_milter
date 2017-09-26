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
            $labels_txt = ' ' . join( ',', @labels_list );
        }
    }

    $count_id =  $self->clean_label( $count_id );

    # Parent can count it's own metrics.
    my $ppid = $server->{ 'server' }->{ 'ppid' };
    if ( $ppid == $PID ) {
        warn "Parent counting metrics";
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

sub send {
    my ( $self, $server ) = @_;

    return if ( ! $self->{ 'enabled' } );

    my $ppid = $server->{ 'server' }->{ 'ppid' };
    if ( $ppid == $PID ) {
        warn "Parent tried to talk to itself to send metrics";
        return;
    }

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
        elsif ( $request_uri eq '/grafana' ) {
            print $socket "HTTP/1.0 200 OK\n";
            print $socket "Content-Type: text/plain\n";
            print $socket "\n";

            my $Base = '{"id":null,"annotations":{"list":[]},"timezone":"browser","__requires":[{"type":"grafana","name":"Grafana","id":"grafana","version":"4.2.0"},{"version":"","id":"graph","name":"Graph","type":"panel"},{"version":"1.0.0","name":"Prometheus","id":"prometheus","type":"datasource"}],"hideControls":false,"__inputs":[{"type":"datasource","pluginId":"prometheus","pluginName":"Prometheus","description":"","label":"Prometheus","name":"DS_PROMETHEUS"}],"editable":true,"rows":[],"gnetId":null,"refresh":false,"style":"dark","graphTooltip":0,"tags":["fastmail"],"time":{"to":"now","from":"now-1h"},"schemaVersion":14,"timepicker":{"refresh_intervals":["5s","10s","30s","1m","5m","15m","30m","1h","2h","1d"],"time_options":["5m","15m","1h","6h","12h","24h","2d","7d","30d"]},"title":"Authentication Milter","version":56,"templating":{"list":[{"regex":"","tagsQuery":"","options":[],"refresh":1,"tags":[],"allValue":null,"multi":true,"type":"query","query":"label_values(authmilter_uptime_seconds_total, node)","datasource":"${DS_PROMETHEUS}","label":null,"current":{},"hide":0,"useTags":false,"tagValuesQuery":"","includeAll":true,"name":"node","sort":1},{"hide":0,"options":[{"value":"1m","text":"1m","selected":true},{"selected":false,"value":"10m","text":"10m"},{"text":"30m","value":"30m","selected":false},{"text":"1h","value":"1h","selected":false},{"selected":false,"text":"6h","value":"6h"},{"value":"12h","text":"12h","selected":false},{"value":"1d","text":"1d","selected":false},{"selected":false,"text":"7d","value":"7d"},{"selected":false,"text":"14d","value":"14d"},{"text":"30d","value":"30d","selected":false}],"auto_count":30,"includeAll":false,"name":"ratetime","refresh":2,"auto_min":"10s","query":"1m,10m,30m,1h,6h,12h,1d,7d,14d,30d","datasource":null,"multi":false,"type":"interval","auto":false,"label":"","current":{"text":"1m","value":"1m"}}]},"links":[]}';

            my @Rows;

            # Add default system rows

            # Throughput
            push @Rows, '{"panels":[{"renderer":"flot","lines":true,"tooltip":{"value_type":"cumulative","shared":true,"sort":2,"msResolution":false},"id":9,"grid":{},"xaxis":{"values":[],"show":true,"name":null,"mode":"time"},"error":false,"seriesOverrides":[],"pointradius":5,"targets":[{"metric":"authmilter_mail_","refId":"A","step":4,"intervalFactor":2,"interval":"","legendFormat":"{{ result }}","expr":"sum(rate(authmilter_mail_processed_total{node=~\"$node\"}[$ratetime])) by(result)"}],"links":[],"fill":1,"thresholds":[],"title":"Emails processed rate by result","yaxes":[{"show":true,"format":"short","max":null,"label":null,"min":null,"logBase":1},{"show":true,"min":null,"logBase":1,"max":null,"label":null,"format":"short"}],"nullPointMode":"connected","aliasColors":{},"timeShift":null,"span":12,"linewidth":2,"editable":true,"points":false,"legend":{"values":false,"total":false,"min":false,"avg":false,"current":false,"max":false,"hideZero":true,"show":true},"datasource":"${DS_PROMETHEUS}","timeFrom":null,"bars":false,"steppedLine":false,"percentage":false,"stack":false,"type":"graph"},{"xaxis":{"values":[],"name":null,"mode":"time","show":true},"renderer":"flot","lines":true,"tooltip":{"msResolution":false,"value_type":"cumulative","shared":true,"sort":2},"grid":{},"id":37,"links":[],"targets":[{"intervalFactor":2,"step":4,"refId":"A","metric":"authmilter_connect_total","legendFormat":"Connections","expr":"sum(rate(authmilter_connect_total{node=~\"$node\"}[$ratetime]))"}],"pointradius":5,"thresholds":[],"fill":1,"title":"Milter connections rate","yaxes":[{"show":true,"logBase":1,"min":null,"max":null,"label":null,"format":"short"},{"max":null,"label":null,"format":"short","min":null,"logBase":1,"show":true}],"nullPointMode":"connected","aliasColors":{},"error":false,"seriesOverrides":[],"editable":true,"points":false,"legend":{"min":false,"values":false,"total":false,"max":false,"show":true,"current":false,"avg":false},"datasource":"${DS_PROMETHEUS}","timeShift":null,"span":12,"linewidth":2,"percentage":false,"type":"graph","stack":false,"timeFrom":null,"bars":false,"steppedLine":false},{"seriesOverrides":[],"error":false,"aliasColors":{},"yaxes":[{"max":null,"label":null,"format":"short","logBase":1,"min":null,"show":true},{"min":null,"logBase":1,"max":null,"label":null,"format":"short","show":true}],"title":"Emails processed rate by node","nullPointMode":"connected","thresholds":[],"fill":0,"pointradius":5,"targets":[{"step":4,"intervalFactor":2,"metric":"authmilter_mail_","refId":"A","interval":"","legendFormat":"{{ node }}","expr":"sum(rate(authmilter_mail_processed_total{node=~\"$node\"}[$ratetime])) by(node)"}],"links":[],"id":17,"grid":{},"tooltip":{"msResolution":false,"value_type":"cumulative","shared":true,"sort":2},"lines":true,"renderer":"flot","xaxis":{"values":[],"name":null,"mode":"time","show":true},"steppedLine":false,"bars":false,"timeFrom":null,"type":"graph","stack":false,"percentage":false,"linewidth":2,"span":12,"timeShift":null,"datasource":"${DS_PROMETHEUS}","points":false,"legend":{"hideZero":true,"show":true,"max":false,"avg":false,"current":false,"values":false,"total":false,"min":false},"editable":true}],"collapse":true,"repeatIteration":null,"repeatRowId":null,"height":"250px","showTitle":true,"title":"Throughput","repeat":null,"titleSize":"h6"}',
            # Processes
            push @Rows, '{"panels":[{"steppedLine":false,"bars":true,"timeFrom":null,"stack":true,"type":"graph","percentage":false,"linewidth":2,"span":12,"timeShift":null,"datasource":"${DS_PROMETHEUS}","legend":{"current":false,"show":true,"avg":false,"total":false,"values":false,"min":false,"max":false},"points":false,"editable":true,"seriesOverrides":[],"error":false,"aliasColors":{},"yaxes":[{"show":true,"min":0,"logBase":1,"format":"short","label":null,"max":null},{"logBase":1,"min":null,"format":"short","max":null,"label":null,"show":true}],"nullPointMode":"connected","title":"Children count","fill":1,"thresholds":[],"targets":[{"step":4,"intervalFactor":2,"metric":"authmilter_","refId":"A","interval":"","expr":"sum(authmilter_processes_waiting{node=~\"$node\"})","legendFormat":"Spare children"},{"metric":"authmilter_","refId":"B","step":4,"intervalFactor":2,"expr":"sum(authmilter_processes_processing{node=~\"$node\"})","legendFormat":"Busy children"}],"pointradius":5,"links":[],"id":18,"grid":{},"tooltip":{"msResolution":false,"sort":2,"shared":true,"value_type":"individual"},"lines":true,"renderer":"flot","xaxis":{"show":true,"name":null,"mode":"time","values":[]}},{"timeFrom":null,"bars":false,"steppedLine":false,"percentage":false,"stack":false,"type":"graph","timeShift":null,"span":12,"linewidth":2,"editable":true,"points":false,"legend":{"max":false,"min":false,"values":false,"total":false,"avg":false,"show":true,"current":false},"datasource":"${DS_PROMETHEUS}","error":false,"seriesOverrides":[],"pointradius":5,"targets":[{"step":4,"intervalFactor":2,"metric":"authmilter_","refId":"A","interval":"","expr":"sum(authmilter_processes_waiting{node=~\"$node\"}+authmilter_processes_processing{node=~\"$node\"}) by(node)","legendFormat":"{{ node }}"}],"links":[],"fill":0,"thresholds":[],"yaxes":[{"logBase":1,"min":0,"label":null,"max":null,"format":"short","show":true},{"format":"short","label":null,"max":null,"min":null,"logBase":1,"show":true}],"title":"Total children by node","nullPointMode":"connected","aliasColors":{},"renderer":"flot","tooltip":{"msResolution":false,"sort":2,"value_type":"individual","shared":true},"lines":true,"id":7,"grid":{},"xaxis":{"values":[],"show":true,"mode":"time","name":null}},{"xaxis":{"show":true,"mode":"time","name":null,"values":[]},"grid":{},"id":19,"renderer":"flot","lines":true,"tooltip":{"sort":2,"shared":true,"value_type":"individual","msResolution":false},"nullPointMode":"connected","yaxes":[{"format":"short","max":null,"label":null,"min":0,"logBase":1,"show":true},{"show":true,"logBase":1,"min":null,"format":"short","label":null,"max":null}],"title":"Spare children by node","aliasColors":{},"targets":[{"legendFormat":"{{ node }}","expr":"sum(authmilter_processes_waiting{node=~\"$node\"}) by(node)","interval":"","intervalFactor":2,"step":4,"refId":"A","metric":"authmilter_"}],"pointradius":5,"links":[],"thresholds":[],"fill":0,"seriesOverrides":[],"error":false,"points":false,"legend":{"avg":false,"current":false,"show":true,"max":false,"values":false,"total":false,"min":false},"datasource":"${DS_PROMETHEUS}","editable":true,"span":12,"linewidth":2,"timeShift":null,"type":"graph","stack":false,"percentage":false,"steppedLine":false,"timeFrom":null,"bars":false},{"datasource":"${DS_PROMETHEUS}","legend":{"avg":false,"show":true,"current":false,"max":false,"min":false,"total":false,"values":false},"points":false,"editable":true,"linewidth":2,"span":12,"timeShift":null,"stack":false,"type":"graph","percentage":false,"steppedLine":false,"bars":false,"timeFrom":null,"xaxis":{"values":[],"show":true,"mode":"time","name":null},"grid":{},"id":20,"lines":true,"tooltip":{"value_type":"individual","shared":true,"sort":2,"msResolution":false},"renderer":"flot","aliasColors":{},"yaxes":[{"logBase":1,"min":0,"format":"short","label":null,"max":null,"show":true},{"show":true,"max":null,"label":null,"format":"short","logBase":1,"min":null}],"title":"Processing children by node","nullPointMode":"connected","thresholds":[],"fill":0,"targets":[{"intervalFactor":2,"step":4,"refId":"A","metric":"authmilter_","expr":"sum(authmilter_processes_processing{node=~\"$node\"}) by(node)","legendFormat":"{{ node }}","interval":""}],"links":[],"pointradius":5,"seriesOverrides":[],"error":false},{"steppedLine":false,"timeFrom":null,"bars":false,"stack":false,"type":"graph","percentage":false,"span":12,"linewidth":2,"timeShift":null,"legend":{"avg":false,"current":false,"show":true,"max":false,"values":false,"total":false,"min":false},"points":false,"datasource":"${DS_PROMETHEUS}","editable":true,"seriesOverrides":[],"error":false,"title":"Fork rate","yaxes":[{"format":"short","max":null,"label":null,"logBase":1,"min":null,"show":true},{"min":null,"logBase":1,"max":null,"label":null,"format":"short","show":true}],"nullPointMode":"connected","aliasColors":{},"targets":[{"refId":"A","metric":"authmilter_f","intervalFactor":2,"step":4,"expr":"sum(rate(authmilter_forked_children_total{node=~\"$node\"}[$ratetime]))","legendFormat":"Children forked"},{"refId":"B","metric":"authmilter_f","intervalFactor":2,"step":4,"legendFormat":"Children reaped","expr":"-sum(rate(authmilter_reaped_children_total{node=~\"$node\"}[$ratetime]))","interval":""},{"refId":"C","intervalFactor":2,"step":4,"legendFormat":"Children churn","expr":"sum(rate(authmilter_forked_children_total{node=~\"$node\"}[$ratetime]))-sum(rate(authmilter_reaped_children_total{node=~\"$node\"}[$ratetime]))","interval":""}],"links":[],"pointradius":5,"fill":1,"thresholds":[],"grid":{},"id":31,"renderer":"flot","lines":true,"tooltip":{"msResolution":false,"sort":2,"value_type":"cumulative","shared":true},"xaxis":{"values":[],"mode":"time","name":null,"show":true}}],"repeatIteration":null,"collapse":true,"showTitle":true,"height":"250px","repeatRowId":null,"titleSize":"h6","title":"Processes","repeat":null}';
           # Processing Time
            push @Rows, '{"title":"Processing Time","repeat":null,"titleSize":"h6","repeatRowId":null,"showTitle":true,"height":250,"collapse":true,"repeatIteration":null,"panels":[{"span":12,"linewidth":2,"timeShift":null,"legend":{"min":false,"values":false,"total":false,"max":false,"show":true,"current":false,"avg":false},"points":false,"datasource":"${DS_PROMETHEUS}","editable":true,"steppedLine":false,"timeFrom":null,"bars":false,"stack":false,"type":"graph","percentage":false,"id":36,"grid":{},"renderer":"flot","tooltip":{"msResolution":false,"value_type":"cumulative","shared":true,"sort":2},"lines":true,"xaxis":{"name":null,"mode":"time","show":true,"values":[]},"seriesOverrides":[],"error":false,"yaxes":[{"show":true,"logBase":1,"min":null,"format":"µs","max":null,"label":null},{"show":true,"max":null,"label":null,"format":"short","min":null,"logBase":1}],"nullPointMode":"connected","title":"Processing Time","aliasColors":{},"targets":[{"expr":"sum(rate(authmilter_time_microseconds_total{node=~\"$node\"}[$ratetime]))","legendFormat":"Time","interval":"","refId":"A","metric":"authmilter_f","intervalFactor":2,"step":4}],"pointradius":5,"links":[],"fill":1,"thresholds":[]},{"editable":true,"legend":{"max":false,"min":false,"total":false,"values":false,"avg":false,"show":true,"current":false},"points":false,"datasource":"${DS_PROMETHEUS}","timeShift":null,"span":12,"linewidth":2,"percentage":false,"type":"graph","stack":false,"timeFrom":null,"bars":false,"steppedLine":false,"xaxis":{"mode":"time","name":null,"show":true,"values":[]},"renderer":"flot","lines":true,"tooltip":{"sort":2,"value_type":"cumulative","shared":true,"msResolution":false},"grid":{},"id":32,"targets":[{"step":4,"intervalFactor":2,"metric":"authmilter_f","refId":"A","interval":"","legendFormat":"{{ handler }}","expr":"sum(rate(authmilter_time_microseconds_total{node=~\"$node\"}[$ratetime])) by(handler)"}],"pointradius":5,"links":[],"thresholds":[],"fill":1,"yaxes":[{"logBase":1,"min":null,"label":null,"max":null,"format":"µs","show":true},{"show":true,"max":null,"label":null,"format":"short","min":null,"logBase":1}],"title":"Time per Handler","nullPointMode":"connected","aliasColors":{},"error":false,"seriesOverrides":[]},{"error":false,"seriesOverrides":[],"fill":1,"thresholds":[],"pointradius":5,"targets":[{"refId":"A","metric":"authmilter_f","intervalFactor":2,"step":4,"expr":"sum(rate(authmilter_time_microseconds_total{node=~\"$node\"}[$ratetime])) by(callback)","legendFormat":"{{ callback }}","interval":""}],"links":[],"aliasColors":{},"title":"Time per Callback","yaxes":[{"label":null,"max":null,"format":"µs","min":null,"logBase":1,"show":true},{"format":"short","max":null,"label":null,"logBase":1,"min":null,"show":true}],"nullPointMode":"connected","tooltip":{"value_type":"cumulative","shared":true,"sort":2,"msResolution":false},"lines":true,"renderer":"flot","grid":{},"id":33,"xaxis":{"name":null,"mode":"time","show":true,"values":[]},"bars":false,"timeFrom":null,"steppedLine":false,"percentage":false,"type":"graph","stack":false,"timeShift":null,"linewidth":2,"span":12,"editable":true,"datasource":"${DS_PROMETHEUS}","legend":{"current":false,"show":true,"avg":false,"total":false,"values":false,"min":false,"max":false},"points":false},{"seriesOverrides":[],"error":false,"aliasColors":{},"yaxes":[{"show":true,"max":null,"label":null,"format":"µs","min":null,"logBase":1},{"format":"short","max":null,"label":null,"logBase":1,"min":null,"show":true}],"title":"Time per Callback/Handler","nullPointMode":"connected","thresholds":[],"fill":1,"targets":[{"refId":"A","metric":"authmilter_f","intervalFactor":2,"step":4,"legendFormat":"{{ callback }} {{ handler }}","expr":"sum(rate(authmilter_time_microseconds_total{node=~\"$node\"}[$ratetime])) by(callback,handler)","interval":""}],"links":[],"pointradius":5,"id":34,"grid":{},"lines":true,"tooltip":{"msResolution":false,"sort":2,"value_type":"cumulative","shared":true},"renderer":"flot","xaxis":{"show":true,"name":null,"mode":"time","values":[]},"steppedLine":false,"bars":false,"timeFrom":null,"stack":false,"type":"graph","percentage":false,"linewidth":2,"span":12,"timeShift":null,"datasource":"${DS_PROMETHEUS}","points":false,"legend":{"avg":false,"show":true,"current":false,"max":false,"min":false,"values":false,"total":false},"editable":true}]}';
            # Errors
            push @Rows, '{"titleSize":"h6","repeat":null,"title":"Errors","showTitle":true,"height":"250px","repeatRowId":null,"repeatIteration":null,"collapse":true,"panels":[{"fill":1,"thresholds":[],"links":[],"targets":[{"refId":"A","metric":"authmilter_call","intervalFactor":2,"step":4,"legendFormat":"{{ stage }}","expr":"sum(authmilter_callback_error_total{node=~\"$node\"}) by(stage)","interval":""}],"pointradius":5,"aliasColors":{},"yaxes":[{"show":true,"max":null,"label":null,"format":"short","logBase":1,"min":null},{"show":true,"label":null,"max":null,"format":"short","logBase":1,"min":null}],"title":"Callback Errors Total","nullPointMode":"connected","error":false,"seriesOverrides":[],"xaxis":{"values":[],"show":true,"name":null,"mode":"time"},"lines":true,"tooltip":{"value_type":"cumulative","shared":true,"sort":2,"msResolution":false},"renderer":"flot","id":10,"grid":{},"percentage":false,"stack":false,"type":"graph","bars":false,"timeFrom":null,"steppedLine":false,"editable":true,"datasource":"${DS_PROMETHEUS}","legend":{"avg":false,"current":false,"total":false,"values":false,"min":false,"hideZero":true,"show":true,"max":false},"points":false,"timeShift":null,"linewidth":2,"span":12}]}';
            # Uptime
            push @Rows, '{"panels":[{"timeShift":null,"span":12,"linewidth":2,"editable":true,"points":false,"legend":{"min":false,"total":false,"values":false,"max":false,"show":true,"current":false,"avg":false},"datasource":"${DS_PROMETHEUS}","timeFrom":null,"bars":false,"steppedLine":false,"percentage":false,"stack":false,"type":"graph","renderer":"flot","lines":true,"tooltip":{"shared":true,"value_type":"cumulative","sort":2,"msResolution":false},"grid":{},"id":11,"xaxis":{"show":true,"name":null,"mode":"time","values":[]},"error":false,"seriesOverrides":[],"pointradius":5,"targets":[{"intervalFactor":2,"step":4,"refId":"A","legendFormat":"Uptime {{ node }}","expr":"sum(authmilter_uptime_seconds_total{node=~\"$node\"}) by(node)"}],"links":[],"thresholds":[],"fill":0,"title":"Uptime","yaxes":[{"show":true,"max":null,"label":"","format":"s","logBase":1,"min":null},{"format":"short","max":null,"label":null,"logBase":1,"min":null,"show":true}],"nullPointMode":"connected","aliasColors":{}}],"repeatIteration":null,"collapse":true,"showTitle":true,"height":"250px","repeatRowId":null,"titleSize":"h6","title":"Uptime","repeat":null}';

            foreach my $Handler ( sort keys %{ $server->{ 'handler' } } ) {
                my $HandlerObj = $server->{ 'handler' }->{ $Handler };
                if ( $HandlerObj->can( 'grafana_rows' ) ) {
                    my $HandlerRows = $HandlerObj->grafana_rows();
                    foreach my $Row ( @$HandlerRows ) {
                        push @Rows, $Row if $Row;
                    }
                }
            }

            my $J = JSON->new();
            my $BaseData = $J->decode( $Base );
            my $RowsData = $J->decode( '[' . join( ',', @Rows ) . ']' );
            $BaseData->{ 'rows' } = $RowsData;
            print $socket $J->encode( $BaseData ) . "\n";

        }
        else {
            print $socket "HTTP/1.0 404 Not Found\n";
            print $socket "Content-Type: text/plain\n";
            print $socket "\n";
            print $socket "Not Found\n";
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
