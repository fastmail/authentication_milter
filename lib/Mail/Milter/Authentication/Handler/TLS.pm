package Mail::Milter::Authentication::Handler::TLS;
use strict;
use warnings;
use base 'Mail::Milter::Authentication::Handler';
our $VERSION = 0.8;

use Sys::Syslog qw{:standard :macros};

sub default_config {
    return {};
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

    my $version = $self->get_symbol('{tls_version}');
    my $cipher  = $self->get_symbol('{cipher}');
    my $bits    = $self->get_symbol('{cipher_bits}');

    if ($version) {
        $self->dbgout( 'EncryptedAs', "$version, $cipher, $bits bits", LOG_INFO );

        my $header = q{};

        $header .= $self->format_header_entry( 'x-tls', 'pass' ) . ' ';
        $header .= $self->format_header_entry( 'version', $version );
        if ( $cipher ) {
            $header .= ' ' . $self->format_header_entry( 'cipher', $cipher );
        }
        if ( $bits ) {
            $header .= ' ' . $self->format_header_entry( 'bits', $bits );
        }

        $self->add_auth_header( $header );
    }
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

Copyright 2015

This library is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.


