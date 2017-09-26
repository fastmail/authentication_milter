package Mail::Milter::Authentication::Handler::ReturnOK;
use strict;
use warnings;
use base 'Mail::Milter::Authentication::Handler';
use version; our $VERSION = version->declare('v1.1.3');

use Net::DNS;
use Sys::Syslog qw{:standard :macros};

sub default_config {
    return {};
}

sub register_metrics {
    return {
        'returnok_total' => 'The number of emails processed for ReturnOK',
    };
}

sub _check_address {
    my ( $self, $address, $type ) = @_;

    my $resolver = $self->get_object('resolver');

    my $email = $self->get_address_from( $address );

    if ( ! $email ) {
        $self->log_error( "ReturnOK: No Address for $type" );
    }

    my $domain = $self->get_domain_from( $email );

    if ( ! $domain ) {
        $self->log_error( "ReturnOK: No Domain for $type from $address" );
    }

    my $result = 'fail';
    my @details;

    push @details, "type=$type";

    my $has_mx   = 0;
    my $has_a    = 0;
    my $has_aaaa = 0;
    my $packet;

    $packet = $resolver->query( $domain, 'MX' );
    if ($packet) {
        foreach my $rr ( $packet->answer ) {
            next unless $rr->type eq "MX";
            $has_mx = 1;
            $result = 'pass';
            last;
        }
    }
    else {
        my $error = $resolver->errorstring;
        if ( $error ) {
            push @details, $self->format_header_entry('mx.error', $error);
        }
        else {
            push @details, 'mx.error=none';
        }
    }

    if ( ! $has_mx ) {
        $packet = $resolver->query( $domain, 'A' );
        if ($packet) {
            foreach my $rr ( $packet->answer ) {
                next unless $rr->type eq "A";
                $has_a = 1;
                $result = 'warn';
                last;
            }
        }
        else {
            my $error = $resolver->errorstring;
            if ( $error ) {
                push @details, $self->format_header_entry('a.error', $error);
            }
            else {
                push @details, 'a.error=none';
            }
        }

        $packet = $resolver->query( $domain, 'AAAA' );
        if ($packet) {
            foreach my $rr ( $packet->answer ) {
                next unless $rr->type eq "AAAA";
                $has_a = 1;
                $result = 'warn';
                last;
            }
        }
        else {
            my $error = $resolver->errorstring;
            if ( $error ) {
                push @details, $self->format_header_entry('aaaa.error', $error);
            }
            else {
                push @details, 'aaaa.error=none';
            }
        }
    }

    $self->dbgout( 'ReturnOKCheck', "$type: $result", LOG_DEBUG );
    my $header = join( ' ',
        $self->format_header_entry( 'x-return-mx', $result ),
        @details,
    );

    $self->add_auth_header($header);
    $self->metric_count( 'returnok_total', { 'result' => $result} );

    return;
}

sub envfrom_callback {
    my ( $self, $env_from ) = @_;
    $env_from = q{} if $env_from eq '<>';
    $self->_check_address( $env_from, 'smtp' );
    return;
}

sub header_callback {
    my ( $self, $header, $value ) = @_;
    if ( $header eq 'From' ) {
        $self->_check_address( $value, 'header' );
    }
    return;
}

1;

__END__

=head1 NAME

  Authentication-Milter - ReturnOK Module

=head1 DESCRIPTION

Check that return addresses have valid MX records.

=head1 CONFIGURATION

No configuration options exist for this handler.

=head1 SYNOPSIS

=head1 AUTHORS

Marc Bradshaw E<lt>marc@marcbradshaw.netE<gt>

=head1 COPYRIGHT

Copyright 2017

This library is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.


