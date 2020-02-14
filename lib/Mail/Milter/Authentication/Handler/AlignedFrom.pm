package Mail::Milter::Authentication::Handler::AlignedFrom;
use 5.20.0;
use strict;
use warnings;
use Mail::Milter::Authentication::Pragmas;
# ABSTRACT: Handler class for Address alignment
# VERSION
use base 'Mail::Milter::Authentication::Handler';
use Net::DNS;

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
    $self->{ 'envfrom_count' } = 0;
    $self->{ 'smtp_address' } = q{};
    $self->{ 'smtp_domain' } = q{};
    $self->{ 'header_address' } = q{};
    $self->{ 'header_domain' } = q{};

    my $emails = $self->get_addresses_from( $env_from );
    foreach my $email ( @$emails ) {
        next if ! $email;
        $self->{ 'envfrom_count' } = $self->{ 'envfrom_count' } + 1;
        # More than 1 here? we set to error in eom callback.!
        $self->{ 'smtp_address'} = lc $email;
        $self->{ 'smtp_domain'} = lc $self->get_domain_from( $email );
    }
}

sub header_callback {
    my ( $self, $header, $value ) = @_;

    return if lc $header ne 'from';

    my $emails = $self->get_addresses_from( $value );

    my $found_domains = {};


    foreach my $email ( @$emails ) {
        next if ! $email;
        $self->{ 'header_address'} = lc $email;
        my $domain = lc $self->get_domain_from( $email );
        $self->{ 'header_domain'} = $domain;
        $found_domains->{ $domain } = $1;
    }

    # We don't consider finding 2 addresses at the same domain in a header to be 2 separate entries
    # for alignment checking, only count them as one.
    foreach my $domain ( sort keys %$found_domains ) {
        $self->{ 'from_header_count' } = $self->{ 'from_header_count' } + 1;
        # If there are more than 1 then the result will be set to error in the eom callback
        # Multiple from headers should always set the result to error.
    }
}

sub close_callback {
    my ( $self ) = @_;
    delete $self->{ 'envfrom_count' };
    delete $self->{ 'from_header_count' };
    delete $self->{ 'header_address' };
    delete $self->{ 'header_domain' };
    delete $self->{ 'smtp_address' };
    delete $self->{ 'smtp_domain' };
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
    my $comment;

    if ( $self->{ 'from_header_count' } > 1 ) {
        $result = 'error';
        $comment = 'Multiple addresses in header';
    }

    elsif ( $self->{ 'envfrom_count' } > 1 ) {
        $result = 'error';
        $comment = 'Multiple addresses in envelope';
    }

    elsif ( ( ! $self->{ 'smtp_domain' } ) && ( ! $self->{ 'header_domain' } ) ) {
        $result = 'null';
        $comment = 'No domains found';
    }

    elsif ( ! $self->{ 'smtp_domain' } ) {
        $result = 'null_smtp';
        $comment = 'No envelope domain';
    }

    elsif ( ! $self->{ 'header_domain' } ) {
        $result = 'null_header';
        $comment = 'No header domain';
    }

    elsif ( $self->{ 'smtp_address' } eq $self->{ 'header_address' } ) {
        $result = 'pass';
        $comment = 'Address match';
    }

    elsif ( $self->{ 'smtp_domain' } eq $self->{ 'header_domain' } ) {
        $result = 'domain_pass';
        $comment = 'Domain match';
    }

    else {

        # Get Org domain and check that if different.
        if ( $self->is_handler_loaded( 'DMARC' ) ) {
            my $dmarc_handler = $self->get_handler('DMARC');
            my $dmarc_object = $dmarc_handler->get_dmarc_object();
            my $org_smtp_domain   = eval{ $dmarc_object->get_organizational_domain( $self->{ 'smtp_domain' } ); };
            $self->handle_exception( $@ );
            my $org_header_domain = eval{ $dmarc_object->get_organizational_domain( $self->{ 'header_domain' } ); };
            $self->handle_exception( $@ );

            if ( $org_smtp_domain eq $org_header_domain ) {
                $result = 'orgdomain_pass';
                $comment = 'Domain org match';
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
    my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'x-aligned-from' )->safe_set_value( $result );
    if ( $comment ) {
      $header->add_child( Mail::AuthenticationResults::Header::Comment->new()->safe_set_value( $comment ) );
    }
    $self->add_auth_header( $header );

    $self->metric_count( 'alignedfrom_total', { 'result' => $result } );
}

1;

__END__

=head1 DESCRIPTION

Check that Mail From and Header From addresses are in alignment.

=head1 CONFIGURATION

No configuration options exist for this handler.

