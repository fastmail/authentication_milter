package Mail::Milter::Authentication::Handler::SenderID;
use strict;
use warnings;
use base 'Mail::Milter::Authentication::Handler';
use version; our $VERSION = version->declare('v1.1.3');

use Sys::Syslog qw{:standard :macros};

use Mail::SPF;

use Mail::Milter::Authentication::Handler::SPF;

sub default_config {
    return {
        'hide_none' => 1,
    };
}

sub grafana_rows {
    my ( $self ) = @_;
    my @rows;
    push @rows , '{"titleSize":"h6","title":"SenderID Handler","repeat":null,"height":250,"showTitle":true,"repeatRowId":null,"repeatIteration":null,"collapse":true,"panels":[{"aliasColors":{},"yaxes":[{"show":true,"min":null,"logBase":1,"format":"short","max":null,"label":null},{"show":true,"format":"short","label":null,"max":null,"logBase":1,"min":null}],"title":"SenderID results rate","nullPointMode":"connected","fill":1,"thresholds":[],"targets":[{"metric":"","refId":"A","step":240,"intervalFactor":2,"interval":"","legendFormat":"{{ result }}","expr":"sum(rate(authmilter_senderid_total{node=~\"$node\"}[$ratetime])) by(result)"}],"links":[],"pointradius":5,"seriesOverrides":[],"error":false,"xaxis":{"values":[],"name":null,"mode":"time","show":true},"id":38,"grid":{},"tooltip":{"sort":2,"shared":true,"value_type":"cumulative","msResolution":false},"lines":true,"renderer":"flot","type":"graph","stack":false,"percentage":false,"steppedLine":false,"bars":false,"timeFrom":null,"datasource":"${DS_PROMETHEUS}","legend":{"current":false,"avg":false,"values":false,"total":false,"min":false,"show":true,"hideZero":true,"max":false},"points":false,"editable":true,"linewidth":2,"span":12,"timeShift":null}]}';
    return \@rows;
}

sub setup_callback {
    my ( $self ) = @_;
    # Call connect_callback from SPF handler to setup object creation
    # Required if SenderID is enabled but SPF is disabled.
    return Mail::Milter::Authentication::Handler::SPF::setup_callback( $self );
}

sub register_metrics {
    return {
        'senderid_total'      => 'The number of emails processed for Sender ID',
    };
}

sub helo_callback {
    my ( $self, $helo_host ) = @_;
    $self->{'helo_name'} = $helo_host;
    return;
}

sub envfrom_callback {
    my ( $self, $env_from ) = @_;
    return if ( $self->is_local_ip_address() );
    return if ( $self->is_trusted_ip_address() );
    return if ( $self->is_authenticated() );
    delete $self->{'from_header'};
    return;
}

sub header_callback {
    my ( $self, $header, $value ) = @_;
    return if ( $self->is_local_ip_address() );
    return if ( $self->is_trusted_ip_address() );
    return if ( $self->is_authenticated() );
    if ( lc $header eq 'from' ) {
        $self->{'from_header'} = $value;
    }
    return;
}

sub eoh_callback {
    my ($self) = @_;
    my $config = $self->handler_config();
    return if ( $self->is_local_ip_address() );
    return if ( $self->is_trusted_ip_address() );
    return if ( $self->is_authenticated() );

    my $spf_server = $self->get_object('spf_server');
    if ( ! $spf_server ) {
        $self->log_error( 'SenderID Setup Error' );
        $self->add_auth_header('senderid=temperror');
        $self->metric_count( 'senderid_total', { 'result' => 'error' } );
        return;
    }

    my $scope = 'pra';

    my $identity = $self->get_address_from( $self->{'from_header'} );

    if ( ! $identity ) {
        $self->log_error( 'SENDERID Error No Identity' );
        $self->add_auth_header('senderid=permerror');
        $self->metric_count( 'senderid_total', { 'result' => 'permerror' } );
        return;
    }

    eval {
        my $spf_request = Mail::SPF::Request->new(
            'versions'      => [2],
            'scope'         => $scope,
            'identity'      => $identity,
            'ip_address'    => $self->ip_address(),
            'helo_identity' => $self->{'helo_name'},
        );

        my $spf_result = $spf_server->process($spf_request);

        my $result_code = $spf_result->code();
        $self->metric_count( 'senderid_total',  {'result' => $result_code } );
        $self->dbgout( 'SenderIdCode', $result_code, LOG_INFO );

        if ( ! ( $config->{'hide_none'} && $result_code eq 'none' ) ) {
            my $auth_header = $self->format_header_entry( 'senderid', $result_code );
            $self->add_auth_header( $auth_header );
#my $result_local  = $spf_result->local_explanation;
#my $result_auth   = $spf_result->can( 'authority_explanation' ) ? $spf_result->authority_explanation() : '';
            my $result_header = $spf_result->received_spf_header();
            my ( $header, $value ) = split( ': ', $result_header, 2 );
            $self->prepend_header( $header, $value );
            $self->dbgout( 'SPFHeader', $result_header, LOG_DEBUG );
        }
    };
    if ( my $error = $@ ) {
        $self->log_error( 'SENDERID Error ' . $error );
        $self->metric_count( 'senderid_total', { 'result' => 'error' } );
        $self->add_auth_header('senderid=temperror');
        return;
    }
    return;
}

sub close_callback {
    my ( $self ) = @_;
    delete $self->{'from_header'};
    delete $self->{'helo_name'};
    return;
}

1;

__END__

=head1 NAME

  Authentication-Milter - SenderID Module

=head1 DESCRIPTION

Implements the SenderID standard checks.

=head1 CONFIGURATION

        "SenderID" : {                                  | Config for the SenderID Module
            "hide_none" : 1                             | Hide auth line if the result is 'none'
        },

=head1 SYNOPSIS

=head1 AUTHORS

Marc Bradshaw E<lt>marc@marcbradshaw.netE<gt>

=head1 COPYRIGHT

Copyright 2017

This library is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.


