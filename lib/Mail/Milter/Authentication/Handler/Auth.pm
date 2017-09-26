package Mail::Milter::Authentication::Handler::Auth;
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
    push @rows , '{"titleSize":"h6","title":"Auth Handler","repeat":null,"height":250,"showTitle":true,"repeatRowId":null,"repeatIteration":null,"collapse":true,"panels":[{"xaxis":{"values":[],"show":true,"mode":"time","name":null},"lines":true,"tooltip":{"msResolution":false,"sort":2,"shared":true,"value_type":"cumulative"},"renderer":"flot","grid":{},"id":40,"thresholds":[],"fill":1,"links":[],"targets":[{"expr":"sum(rate(authmilter_connect_total{node=~\"$node\"}[$ratetime]))","legendFormat":"Connections","metric":"authmilter_connect_total","refId":"A","step":2,"intervalFactor":2},{"expr":"sum(rate(authmilter_authenticated_connect_total{node=~\"$node\"}[$ratetime]))","legendFormat":"Authenticated connections","interval":"","intervalFactor":2,"step":2,"refId":"B","metric":"connect"}],"pointradius":5,"aliasColors":{},"nullPointMode":"connected","yaxes":[{"show":true,"min":null,"logBase":1,"format":"short","label":null,"max":null},{"show":true,"min":null,"logBase":1,"format":"short","max":null,"label":null}],"title":"Authenticated connections IP rate","error":false,"seriesOverrides":[],"editable":true,"datasource":"${DS_PROMETHEUS}","legend":{"max":false,"values":false,"total":false,"min":false,"avg":false,"current":false,"show":true},"points":false,"timeShift":null,"linewidth":2,"span":12,"percentage":false,"type":"graph","stack":false,"bars":false,"timeFrom":null,"steppedLine":false}]}';
    return \@rows;
}

sub register_metrics {
    return {
        'authenticated_connect_total' => 'The number of connections from an authenticated host',
    };
}

sub pre_loop_setup {
    my ( $self ) = @_;
    my $protocol = Mail::Milter::Authentication::Config::get_config()->{'protocol'};
    if ( $protocol ne 'milter' ) {
        warn 'The Auth handler only works with the milter protocol';
    }
    return;
}

sub get_auth_name {
    my ($self) = @_;
    my $name = $self->get_symbol('{auth_authen}');
    return $name;
}

sub connect_callback {
    my ( $self, $hostname, $ip ) = @_;
    $self->{'is_authenticated'} = 0;
    return;
}

sub envfrom_callback {
    my ( $self, $env_from ) = @_;
    my $auth_name = $self->get_auth_name();
    if ($auth_name) {
        $self->dbgout( 'AuthenticatedAs', $auth_name, LOG_INFO );
        # Clear the current auth headers ( iprev and helo may already be added )
        # ToDo is this a good idea?
        my $top_handler = $self->get_top_handler();
        $top_handler->{'c_auth_headers'} = [];
        $top_handler->{'auth_headers'}   = [];
        $self->{'is_authenticated'}       = 1;
        $self->metric_count( 'authenticated_connect_total' );
        $self->add_auth_header('auth=pass');
    }
    return;
}

sub close_callback {
    my ( $self ) = @_;
    delete $self->{'is_authenticated'};
    return;
}

1;

__END__

=head1 NAME

  Authentication-Milter - Auth Module

=head1 DESCRIPTION

Module which identifies email that was sent via an authenticated connection.

=head1 CONFIGURATION

No configuration options exist for this handler.

=head1 SYNOPSIS

=head1 AUTHORS

Marc Bradshaw E<lt>marc@marcbradshaw.netE<gt>

=head1 COPYRIGHT

Copyright 2017

This library is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.


