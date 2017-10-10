package Mail::Milter::Authentication::Handler::AlignedFrom;
use strict;
use warnings;
use base 'Mail::Milter::Authentication::Handler';
use version; our $VERSION = version->declare('v1.1.4');

use Net::DNS;
use Sys::Syslog qw{:standard :macros};

sub default_config {
    return {};
}

sub grafana_rows {
    my ( $self ) = @_;
    my @rows;
    push @rows, $self->get_json( 'AlignedFrom_metrics' );
    return \@rows;
}

sub register_metrics {
    return {
        'alignedfrom_total' => 'The number of emails processed for AlignedFrom',
    };
}

sub envfrom_callback {
    my ( $self, $env_from ) = @_;

    $env_from = q{} if $env_from eq '<>';

    # Defaults
    $self->{ 'from_header_count' } = 0;
    $self->{ 'smtp_address' } = q{};
    $self->{ 'smtp_domain' } = q{};
    $self->{ 'header_address' } = q{};
    $self->{ 'header_domain' } = q{};

    my $email = $self->get_address_from( $env_from );
    return if ! $email;
    $self->{ 'smtp_address'} = lc $email;
    $self->{ 'smtp_domain'} = lc $self->get_domain_from( $email );

    return;
}

sub header_callback {
    my ( $self, $header, $value ) = @_;

    return if $header ne 'From';

    $self->{ 'from_header_count' } = $self->{ 'from_header_count' } + 1;

    my $email = $self->get_address_from( $value );
    return if ! $email;
    $self->{ 'header_address'} = lc $email;
    $self->{ 'header_domain'} = lc $self->get_domain_from( $email );

    return;
}

sub close_callback {
    my ( $self ) = @_;
    delete $self->{ 'from_header_count' };
    delete $self->{ 'header_address' };
    delete $self->{ 'header_domain' };
    delete $self->{ 'smtp_address' };
    delete $self->{ 'smtp_domain' };
    return;
}

# error = multiple from headers present
# null = no addresses present
# null_smtp = no smtp address present
# null_header = no header address present
# pass = addresses match
# domain_pass = domains match
# orgdomain_pass = domains in same orgdomain

sub eom_callback {
    my ( $self ) = @_;

    my $result;

    if ( $self->{ 'from_header_count' } > 1 ) {
        $result = 'error';
    }

    elsif ( ( ! $self->{ 'smtp_domain' } ) && ( ! $self->{ 'header_domain' } ) ) {
        $result = 'null';
    }

    elsif ( ! $self->{ 'smtp_domain' } ) {
        $result = 'null_smtp';
    }

    elsif ( ! $self->{ 'header_domain' } ) {
        $result = 'null_header';
    }

    elsif ( $self->{ 'smtp_address' } eq $self->{ 'header_address' } ) {
        $result = 'pass';
    }

    elsif ( $self->{ 'smtp_domain' } eq $self->{ 'header_domain' } ) {
        $result = 'domain_pass';
    }

    else {

        # Get Org domain and check that if different.
        if ( $self->is_handler_loaded( 'DMARC' ) ) {
            my $dmarc_handler = $self->get_handler('DMARC');
            my $dmarc_object = $dmarc_handler->get_dmarc_object();
            my $org_smtp_domain   = eval{ $dmarc_object->get_organizational_domain( $self->{ 'smtp_domain' } ); };
            my $org_header_domain = eval{ $dmarc_object->get_organizational_domain( $self->{ 'header_domain' } ); };

            if ( $org_smtp_domain eq $org_header_domain ) {
                $result = 'orgdomain_pass';
            }

            else {
                $result = 'fail';
            }

        }

        else {
            $result = 'fail';
        }

    }


    $self->dbgout( 'AlignedFrom', $result, LOG_DEBUG );
    $self->add_auth_header( $self->format_header_entry( 'x-aligned-from', $result ) );

    $self->metric_count( 'alignedfrom_total', { 'result' => $result } );

    return;
}

1;

__END__

=head1 NAME

  Authentication-Milter - AlignedFrom Module

=head1 DESCRIPTION

Check that Mail From and Header From addresses are in alignment.

=head1 CONFIGURATION

No configuration options exist for this handler.

=head1 SYNOPSIS

=head1 AUTHORS

Marc Bradshaw E<lt>marc@marcbradshaw.netE<gt>

=head1 COPYRIGHT

Copyright 2017

This library is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.


