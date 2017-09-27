package Mail::Milter::Authentication::Handler::PTR;
use strict;
use warnings;
use base 'Mail::Milter::Authentication::Handler';
use version; our $VERSION = version->declare('v1.1.3');

use Sys::Syslog qw{:standard :macros};

sub default_config {
    return {};
}

sub grafana_rows {
    my ( $self ) = @_;
    my @rows;
    push @rows , '{"titleSize":"h6","collapse":true,"showTitle":true,"repeatIteration":null,"repeat":null,"height":250,"title":"PTR Handler","repeatRowId":null,"panels":[{"pointradius":5,"points":false,"tooltip":{"msResolution":false,"sort":2,"shared":true,"value_type":"cumulative"},"grid":{},"thresholds":[],"timeFrom":null,"timeShift":null,"linewidth":2,"xaxis":{"values":[],"show":true,"name":null,"mode":"time"},"yaxes":[{"logBase":1,"show":true,"label":null,"min":null,"max":null,"format":"short"},{"logBase":1,"show":true,"label":null,"format":"short","max":null,"min":null}],"percentage":false,"fill":1,"links":[],"steppedLine":false,"renderer":"flot","seriesOverrides":[],"id":43,"lines":true,"error":false,"nullPointMode":"connected","targets":[{"metric":"authmilter_dkim_error_total","interval":"","step":60,"legendFormat":"{{ result }}","expr":"sum(rate(authmilter_ptr_total{node=~\"$node\"}[$ratetime])) by(result)","intervalFactor":2,"refId":"A"}],"editable":true,"span":12,"aliasColors":{},"bars":false,"type":"graph","stack":false,"legend":{"total":false,"values":false,"avg":false,"min":false,"hideEmpty":false,"hideZero":true,"current":false,"show":true,"max":false},"datasource":"${DS_PROMETHEUS}","title":"PTR results rate"}]}';
    return \@rows;
}

sub register_metrics {
    return {
        'ptr_total' => 'The number of emails processed for PTR',
    };
}

sub helo_callback {

    # On HELO
    my ( $self, $helo_host ) = @_;
    return if ( $self->is_local_ip_address() );
    return if ( $self->is_trusted_ip_address() );
    return if ( $self->is_authenticated() );

    if ( ! $self->is_handler_loaded( 'IPRev' ) ) {
        $self->log_error( 'PTR Config Error: IPRev is missing ');
        return;
    }

    my $iprev_handler = $self->get_handler('IPRev');
    my $domains =
      exists( $iprev_handler->{'verified_ptr'} )
      ? $iprev_handler->{'verified_ptr'}
      : q{};

    my $found_match = 0;

    foreach my $domain ( split ',', $domains ) {
        if ( lc $domain eq lc $helo_host ) {
            $found_match = 1;
        }
    }

    if ( $found_match ) {
        $self->dbgout( 'PTRMatch', 'pass', LOG_DEBUG );
        $self->add_c_auth_header(
                $self->format_header_entry( 'x-ptr',        'pass' ) . q{ }
              . $self->format_header_entry( 'x-ptr-helo',   $helo_host ) . q{ }
              . $self->format_header_entry( 'x-ptr-lookup', $domains ) );
        $self->metric_count( 'ptr_total', { 'result' => 'pass'} );
    }
    else {
        $self->dbgout( 'PTRMatch', 'fail', LOG_DEBUG );
        $self->add_c_auth_header(
                $self->format_header_entry( 'x-ptr',        'fail' ) . q{ }
              . $self->format_header_entry( 'x-ptr-helo',   $helo_host ) . q{ }
              . $self->format_header_entry( 'x-ptr-lookup', $domains ) );
        $self->metric_count( 'ptr_total', { 'result' => 'fail'} );
    }
    return;
}

1;

__END__

=head1 NAME

  Authentication-Milter - PTR Module

=head1 DESCRIPTION

Check DNS PTR Records match.

This handler requires the IPRev handler to be installed and active.

=head1 CONFIGURATION

No configuration options exist for this handler.

=head1 SYNOPSIS

=head1 AUTHORS

Marc Bradshaw E<lt>marc@marcbradshaw.netE<gt>

=head1 COPYRIGHT

Copyright 2017

This library is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.


