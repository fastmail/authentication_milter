package Mail::Milter::Authentication::Handler::TLS;
use strict;
use warnings;
use base 'Mail::Milter::Authentication::Handler';
use version; our $VERSION = version->declare('v1.1.2');

use Sys::Syslog qw{:standard :macros};

sub default_config {
    return {};
}

sub register_metrics {
    return {
        'tls_connect_total' => 'The number of connections which were enctypted',
    };
}

sub pre_loop_setup {
    my ( $self ) = @_;
    my $protocol = Mail::Milter::Authentication::Config::get_config()->{'protocol'};
    if ( $protocol ne 'milter' ) {
        warn 'The TLS handler only works with the milter protocol';
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

        $self->metric_count( 'authenticated_connect_total', $metric_data );

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

        $self->metric_count( 'authenticated_connect_total', $metric_data );

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

  Authentication Milter - TLS Module

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


