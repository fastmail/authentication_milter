package Mail::Milter::Authentication::Handler::TLS;
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
    push @rows , '{"repeatIteration":null,"collapse":true,"panels":[{"points":false,"legend":{"max":false,"min":false,"values":false,"total":false,"avg":false,"show":true,"current":false},"datasource":"${DS_PROMETHEUS}","timeShift":null,"span":12,"linewidth":1,"percentage":false,"stack":false,"type":"graph","timeFrom":null,"bars":false,"steppedLine":false,"xaxis":{"values":[],"show":true,"mode":"time","name":null},"renderer":"flot","tooltip":{"sort":2,"shared":true,"value_type":"individual"},"lines":true,"id":26,"pointradius":5,"targets":[{"intervalFactor":2,"step":4,"refId":"A","legendFormat":"TLS","expr":"sum(rate(authmilter_tls_connect_total{node=~\"$node\"}[$ratetime]))","interval":"","hide":false},{"refId":"B","intervalFactor":2,"step":4,"hide":false,"legendFormat":"Total Connections","expr":"sum(rate(authmilter_connect_total{node=~\"$node\"}[$ratetime]))","interval":""}],"links":[],"thresholds":[],"fill":1,"yaxes":[{"show":true,"label":null,"max":null,"format":"short","min":"0","logBase":1},{"show":true,"logBase":1,"min":null,"max":null,"label":null,"format":"short"}],"title":"Connections","nullPointMode":"null","aliasColors":{},"seriesOverrides":[]},{"legend":{"values":false,"total":false,"min":false,"max":false,"current":false,"show":true,"avg":false},"points":false,"datasource":"${DS_PROMETHEUS}","span":12,"linewidth":1,"timeShift":null,"stack":false,"type":"graph","percentage":false,"steppedLine":false,"timeFrom":null,"bars":false,"xaxis":{"show":true,"name":null,"mode":"time","values":[]},"id":27,"renderer":"flot","lines":true,"tooltip":{"value_type":"individual","shared":true,"sort":2},"title":"Bits","yaxes":[{"max":null,"label":null,"format":"short","min":null,"logBase":1,"show":true},{"show":true,"max":null,"label":null,"format":"short","logBase":1,"min":null}],"nullPointMode":"null","aliasColors":{},"targets":[{"intervalFactor":2,"step":4,"refId":"A","legendFormat":"{{ bits }}","expr":"sum(rate(authmilter_tls_connect_total{node=~\"$node\"}[$ratetime])) by(bits)","interval":""}],"links":[],"pointradius":5,"thresholds":[],"fill":1,"seriesOverrides":[]},{"xaxis":{"show":true,"name":null,"mode":"time","values":[]},"renderer":"flot","tooltip":{"sort":2,"value_type":"individual","shared":true},"lines":true,"id":28,"links":[],"targets":[{"step":4,"intervalFactor":2,"refId":"A","interval":"","expr":"sum(rate(authmilter_tls_connect_total{node=~\"$node\"}[$ratetime])) by(cipher)","legendFormat":"{{ cipher }}"}],"pointradius":5,"fill":1,"thresholds":[],"yaxes":[{"show":true,"format":"short","max":null,"label":null,"logBase":1,"min":null},{"format":"short","max":null,"label":null,"logBase":1,"min":null,"show":true}],"nullPointMode":"null","title":"Ciphers","aliasColors":{},"seriesOverrides":[],"legend":{"max":false,"total":false,"values":false,"min":false,"avg":false,"current":false,"show":true},"points":false,"datasource":"${DS_PROMETHEUS}","timeShift":null,"span":12,"linewidth":1,"percentage":false,"stack":false,"type":"graph","timeFrom":null,"bars":false,"steppedLine":false}],"titleSize":"h6","repeat":null,"title":"TLS Handler","showTitle":true,"height":250,"repeatRowId":null}';
    return \@rows;
}

sub register_metrics {
    return {
        'tls_connect_total' => 'The number of connections which were enctypted',
    };
}

sub pre_loop_setup {
    my ( $self ) = @_;
    my $protocol = Mail::Milter::Authentication::Config::get_config()->{'protocol'};
    if ( $protocol eq 'smtp' ) {
        warn 'When in smtp mode, the TLS handler requires the MTA to write TLS data into the first Received header.';
    }
    return;
}

sub envfrom_callback {
    my ( $self, $env_from ) = @_;

    delete $self->{'first_header_read'};

    my $protocol = Mail::Milter::Authentication::Config::get_config()->{'protocol'};
    return if $protocol ne 'milter';

    my $version = $self->get_symbol('{tls_version}');
    my $cipher  = $self->get_symbol('{cipher}');
    my $bits    = $self->get_symbol('{cipher_bits}');
    # on postfix the macro is empty on untrusted connections
    my $trusted = $self->get_symbol('{cert_issuer}') ? ', trusted' : '';

    if ($version) {
        $self->dbgout( 'EncryptedAs', "$version, $cipher, $bits bits$trusted", LOG_INFO );

        my $header = q{};
        my $metric_data = {};

        $header .= $self->format_header_entry( 'x-tls', 'pass' ) . ' ';
        $header .= $self->format_header_entry( 'version', $version );
        if ( $cipher ) {
            $header .= ' ' . $self->format_header_entry( 'cipher', $cipher );
            $metric_data->{ 'cipher' } = $cipher;
        }
        if ( $bits ) {
            $header .= ' ' . $self->format_header_entry( 'bits', $bits );
            $metric_data->{ 'bits' } = $bits;
        }
        $metric_data->{ 'trusted' } = $trusted ? 1 : 0;

        $self->metric_count( 'tls_connect_total', $metric_data );

        $self->add_auth_header( $header );
    }
    return;
}

sub header_callback {
    my ( $self, $header, $value ) = @_;

    return if lc $header ne 'received';
    return if ( exists( $self->{'first_header_read'} ) );
    $self->{'first_header_read'} = 1;


    my $protocol = Mail::Milter::Authentication::Config::get_config()->{'protocol'};
    return if $protocol ne 'smtp';

    # Try and parse the first received header, this should be something like...
    # Received: from mail-ua0-f173.google.com (mail-ua0-f173.google.com [209.85.217.173])
    #           (using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
    #           (No client certificate requested)
    #           by mx5.messagingengine.com (Postfix) with ESMTPS
    #           for <marcmctest@fastmail.com>; Thu,  1 Dec 2016 22:35:06 -0500 (EST)

    # Future, extend to check for client certificates

    $value =~ m/using ([^ ]*) with cipher ([^ ]+) \(([^ ]+) bits\)/;
    my $version = $1;
    my $cipher  = $2;
    my $bits    = $3;

    if ($version) {
        $self->dbgout( 'EncryptedAs', "$version, $cipher, $bits bits", LOG_INFO );

        my $header = q{};
        my $metric_data = {};

        $header .= $self->format_header_entry( 'x-tls', 'pass' ) . ' ';
        $header .= $self->format_header_entry( 'version', $version );
        if ( $cipher ) {
            $header .= ' ' . $self->format_header_entry( 'cipher', $cipher );
            $metric_data->{ 'cipher' } = $cipher;
        }
        if ( $bits ) {
            $header .= ' ' . $self->format_header_entry( 'bits', $bits );
            $metric_data->{ 'bits' } = $bits;
        }

        $self->metric_count( 'tls_connect_total', $metric_data );

        $self->add_auth_header( $header );
    }

    return;
}

sub close_callback {
    my ( $self ) = @_;
    delete $self->{'first_header_read'};
    return;
}

1;

__END__

=head1 NAME

  Authentication-Milter - TLS Module

=head1 DESCRIPTION

Identify TLS protected connections.

=head1 CONFIGURATION

No configuration options exist for this handler.

=head1 SYNOPSIS

=head1 AUTHORS

Marc Bradshaw E<lt>marc@marcbradshaw.netE<gt>

=head1 COPYRIGHT

Copyright 2017

This library is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.


