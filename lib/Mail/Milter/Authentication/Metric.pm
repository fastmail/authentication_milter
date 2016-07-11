package Mail::Milter::Authentication::Metric;
use strict;
use warnings;
use version; our $VERSION = version->declare('v1.1.1');

use English qw{ -no_match_vars };

sub new {
    my ( $class ) = @_;
    my $self = {};
    $self->{'counter'} = {};
    bless $self, $class;
    return $self;
}

sub count {
    my ( $self, $id, $server ) = @_;
    my $psocket = $server->{'server'}->{'parent_sock'};
    print $psocket "METRIC.COUNT $id\n";
}

sub register {
    my ( $self, $id, $server ) = @_;
    my $psocket = $server->{'server'}->{'parent_sock'};
    print $psocket "METRIC.REGISTER $id\n";
}

## ToDo Add timeouts

sub master_handler {
    my ( $self, $request, $socket, $server ) = @_;

    if ( $request =~ /^METRIC.GET/ ) {
        foreach my $type ( qw { waiting processing } ) {
            print $socket '# TYPE authmilter_processes_' . $type . " gauge\n";
            print $socket 'authmilter_processes_' . $type . ': ' . $server->{'server'}->{'tally'}->{ $type } . "\n";
        }
        foreach my $key ( keys %{ $self->{'counter'} } ) {
            print $socket '# TYPE authmilter_count_' . $key . " counter\n";
            print $socket 'authmilter_count_' . $key . ': ' . $self->{'counter'}->{ $key } . "\n";
        }
        print $socket "\0\n";
    }
    elsif ( $request =~ /^METRIC.REGISTER (.*)$/ ) {
        my $count_id = $1;
        if ( ! exists( $self->{'counter'}->{ $count_id } ) ) {
            $self->{'counter'}->{ $count_id } = 0;
        }
    }
    elsif ( $request =~ /^METRIC.COUNT (.*)$/ ) {
        my $count_id = $1;
        if ( ! exists( $self->{'counter'}->{ $count_id } ) ) {
            $self->{'counter'}->{ $count_id } = 0;
        }
        $self->{'counter'}->{ $count_id }++;
    }
    return;
}

sub child_handler {
    my ( $self, $server ) = @_;

    my $socket = $server->{'server'}->{'client'};
    my $req;
    
    $PROGRAM_NAME = $Mail::Milter::Authentication::Config::IDENT . ':metrics';

    $req = <$socket>;
    $req =~ s/[\n\r]+$//;

    if (!defined($req) || $req !~ m{ ^\s*(GET|POST|PUT|DELETE|PUSH|HEAD|OPTIONS)\s+(.+)\s+(HTTP/1\.[01])\s*$ }ix) {
#            die "Invalid request\n";
        return;
    }

    my $request_method  = uc $1;
    my $request_uri     = $2;
    my $server_protocol = $3;
    if ( $request_method   ne 'GET' || $request_uri      ne '/metrics/' ) {
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
    print $psocket "METRIC.GET\n";

    print $socket "HTTP/1.0 200 OK\n";
    print $socket "Content-Type: text/plain\n";
    print $socket "\n";
    while ( my $value = <$psocket> ) {
        $value =~ s/[\n\r]+$//;
        last if $value eq "\0";
        print $socket "$value\n";
    }

    return;
}

1;
