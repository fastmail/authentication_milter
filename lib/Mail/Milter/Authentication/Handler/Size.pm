package Mail::Milter::Authentication::Handler::Size;
use strict;
use warnings;
use base 'Mail::Milter::Authentication::Handler';
use version; our $VERSION = version->declare('v1.1.3');

use Data::Dumper;
use English qw{ -no_match_vars };
use Sys::Syslog qw{:standard :macros};

sub default_config {
    return {};
}

sub grafana_rows {
    my ( $self ) = @_;
    my @rows;
    push @rows , '{"repeatRowId":null,"showTitle":true,"height":250,"repeat":null,"title":"Size Handler","titleSize":"h6","panels":[{"lines":true,"tooltip":{"msResolution":false,"shared":true,"value_type":"cumulative","sort":2},"renderer":"flot","grid":{},"id":35,"xaxis":{"values":[],"show":true,"name":null,"mode":"time"},"error":false,"seriesOverrides":[],"thresholds":[],"fill":1,"targets":[{"interval":"","legendFormat":"Combined","expr":"sum(rate(authmilter_size_body_bytes_total{node=~\"$node\"}[$ratetime]))+sum(rate(authmilter_size_header_bytes_total{node=~\"$node\"}[$ratetime]))","step":4,"intervalFactor":2,"refId":"C"},{"expr":"sum(rate(authmilter_size_body_bytes_total{node=~\"$node\"}[$ratetime]))","legendFormat":"Body","interval":"","intervalFactor":2,"step":4,"refId":"A","metric":"authmilter_mail_"},{"legendFormat":"Header","expr":"sum(rate(authmilter_size_header_bytes_total{node=~\"$node\"}[$ratetime]))","refId":"B","intervalFactor":2,"step":4}],"pointradius":5,"links":[],"aliasColors":{},"title":"Data processed rate by result","yaxes":[{"show":true,"max":null,"label":null,"format":"Bps","min":null,"logBase":1},{"show":true,"max":null,"label":null,"format":"short","logBase":1,"min":null}],"nullPointMode":"connected","timeShift":null,"linewidth":2,"span":12,"editable":true,"datasource":"${DS_PROMETHEUS}","points":false,"legend":{"current":false,"avg":false,"values":false,"total":false,"min":false,"show":true,"hideZero":true,"max":false},"bars":false,"timeFrom":null,"steppedLine":false,"percentage":false,"stack":false,"type":"graph"}],"collapse":true,"repeatIteration":null}';
    return \@rows;
}

sub register_metrics {
    return {
        'size_total' => 'The number of emails processed for Size',
        'size_header_bytes_total' => 'The header size of emails processed for Size',
        'size_body_bytes_total' => 'The body size of emails processed for Size',
    };
}

sub envfrom_callback {
    my ( $self, $env_from )  = @_;
    $self->{'headersize'} = 0;
    $self->{'bodysize'} = 0;
    return;
}

sub header_callback {
    my ( $self, $header, $value ) = @_;
    $self->{ 'headersize' } = $self->{ 'headersize' } + length( $header . ': ' . $value ) + 2;

    return;
}

sub body_callback {
    my ( $self, $body_chunk ) = @_;
    $self->{ 'bodysize' } = $self->{ 'bodysize' } + length ( $body_chunk );
    return;
}

sub eom_callback {
    my ($self) = @_;

    $self->metric_count( 'size_total', {}, 1 );
    $self->metric_count( 'size_header_bytes_total', {}, $self->{ 'headersize' } );
    $self->metric_count( 'size_body_bytes_total', {}, $self->{ 'bodysize' } );
}

sub close_callback {
    my ( $self ) = @_;
    delete $self->{'bodysize'};
    delete $self->{'headersize'};
    return;
}

1;

__END__

=head1 NAME

  Authentication-Milter - Size Module

=head1 DESCRIPTION

Module to provide metrics related to message size.

=head1 CONFIGURATION

        "Size" : {}, | Config for the Size Module

=head1 SYNOPSIS

=head1 AUTHORS

Marc Bradshaw E<lt>marc@marcbradshaw.netE<gt>

=head1 COPYRIGHT

Copyright 2017

This library is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.


