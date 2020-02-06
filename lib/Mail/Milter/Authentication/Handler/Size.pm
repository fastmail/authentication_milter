package Mail::Milter::Authentication::Handler::Size;
use 5.20.0;
use strict;
use warnings;
use Mail::Milter::Authentication::Pragmas;
# ABSTRACT: Handler class for message size metrics
# VERSION
use base 'Mail::Milter::Authentication::Handler';

sub default_config {
    return {};
}

sub grafana_rows {
    my ( $self ) = @_;
    my @rows;
    push @rows, $self->get_json( 'Size_metrics' );
    return \@rows;
}

sub register_metrics {
    return {
        'size_total' => 'The number of emails processed for Size',
        'size_header_bytes_added_total' => 'The header size added to emails processed for Size',
        'size_header_bytes_total' => 'The header size of emails processed for Size',
        'size_body_bytes_total' => 'The body size of emails processed for Size',
    };
}

sub envfrom_callback {
    my ( $self, $env_from )  = @_;
    $self->{'headersize'} = 0;
    $self->{'bodysize'} = 0;
}

sub header_callback {
    my ( $self, $header, $value ) = @_;
    $self->{ 'headersize' } = $self->{ 'headersize' } + length( $header . ': ' . $value ) + 2;
}

sub body_callback {
    my ( $self, $body_chunk ) = @_;
    $self->{ 'bodysize' } = $self->{ 'bodysize' } + length ( $body_chunk );
}

sub eom_callback {
    my ($self) = @_;
    $self->metric_count( 'size_total', {}, 1 );
    $self->metric_count( 'size_header_bytes_total', {}, $self->{ 'headersize' } );
    $self->metric_count( 'size_body_bytes_total', {}, $self->{ 'bodysize' } );
}

sub close_callback {
    my ( $self ) = @_;

    my $top_handler = $self->get_top_handler();
    if ( exists( $top_handler->{'pre_headers'} ) ) {
        foreach my $header ( @{ $top_handler->{'pre_headers'} } ) {
            my $size = length( $header->{'field'} ) + length ( $header->{'value'} ) + 3;
            $self->metric_count( 'size_header_bytes_added_total', { where => 'pre', 'header' => $header->{'field'} }, $size );
        }
    }
    if ( exists( $top_handler->{'add_headers'} ) ) {
        foreach my $header ( @{ $top_handler->{'add_headers'} } ) {
            my $size = length( $header->{'field'} ) + length ( $header->{'value'} ) + 3;
            $self->metric_count( 'size_header_bytes_added_total', { where => 'add', 'header' => $header->{'field'} }, $size );
        }
    }

    delete $self->{'bodysize'};
    delete $self->{'headersize'};
}

1;

__END__

=head1 DESCRIPTION

Module to provide metrics related to message size.

=head1 CONFIGURATION

        "Size" : {}, | Config for the Size Module

