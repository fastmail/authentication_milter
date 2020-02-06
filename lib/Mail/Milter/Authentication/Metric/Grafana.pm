package Mail::Milter::Authentication::Metric::Grafana;
use 5.20.0;
use strict;
use warnings;
use Mail::Milter::Authentication::Pragmas;
# ABSTRACT: Class for Grafana dashboards
# VERSION
use JSON;

sub get_json {
    my ( $self, $file ) = @_;
    my $basefile = __FILE__;
    $basefile =~ s/Grafana\.pm$/$file/;
    $basefile .= '.json';
    if ( ! -e $basefile ) {
        die 'json file ' . $file . ' not found';
    }
    open my $InF, '<', $basefile;
    my @Content = <$InF>;
    close $InF;
    return join( q{}, @Content );
}

sub new {
    my ( $class ) = @_;
    my $self = {};
    bless $self, $class;
    return $self;
}

sub get_dashboard {
    my ( $self, $server ) = @_;

    my @Rows;
    # Add default system rows
    push @Rows, $self->get_json( 'RowThroughput' );
    push @Rows, $self->get_json( 'RowProcesses' );
    push @Rows, $self->get_json( 'RowProcessingTime' );
    push @Rows, $self->get_json( 'RowErrors' );
    push @Rows, $self->get_json( 'RowUptime' );

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
    $J->pretty();
    $J->canonical();

    my $Base = $self->get_json( 'Base' );
    my $BaseData = $J->decode( $Base );
    my $RowsData = $J->decode( '[' . join( ',', @Rows ) . ']' );
    $BaseData->{ 'rows' } = $RowsData;
    return $J->encode( $BaseData ) . "\n";
}

1;

__END__

=head1 DESCRIPTION

Automatically generate a grafana dashboard for installed handlers

=head1 CONSTRUCTOR

=over

=item new()

my $object = Mail::Milter::Authentication::Metric::Grafana->new();

Creates a new object.

=back

=head1 METHODS

=over

=item get_Base()

Returns the base json for the dashboard

=item get_RowThroughput()

Returns the Row json for THroughput

=item get_RowProcesses()

Returns the Row json for Processes

=item get_RowProcessingTime()

Returns the Row json for Processing TIme

=item get_RowErrors()

Returns the Row json for Errors

=item get_RowUptime()

Returns the Row json for Uptime

=item get_json ( $file )

Retrieve json data from external file

=item get_dashboard( $server )

Returns the json for the grafana dashboard

$server is the current handler object

=back

