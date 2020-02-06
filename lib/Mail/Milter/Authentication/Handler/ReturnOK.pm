package Mail::Milter::Authentication::Handler::ReturnOK;
use 5.20.0;
use strict;
use warnings;
use Mail::Milter::Authentication::Pragmas;
use base 'Mail::Milter::Authentication::Handler';
# VERSION

use Net::DNS;
use Sys::Syslog qw{:standard :macros};
use Mail::AuthenticationResults::Header::Entry;
use Mail::AuthenticationResults::Header::SubEntry;
use Mail::AuthenticationResults::Header::Comment;

sub default_config {
    return {};
}

sub grafana_rows {
    my ( $self ) = @_;
    my @rows;
    push @rows, $self->get_json( 'ReturnOK_metrics' );
    return \@rows;
}

sub register_metrics {
    return {
        'returnok_total' => 'The number of emails processed for ReturnOK',
    };
}

sub _check_address {
    my ( $self, $address, $type ) = @_;

    my $email = $self->get_address_from( $address );

    if ( ! $email ) {
        $self->log_error( "ReturnOK: No Address for $type" );
    }

    my $domain = lc $self->get_domain_from( $email );

    $self->_check_domain ( $domain, $type );

    return;
}

sub _check_domain_rr {
    my ( $self, $domain, $rrtype ) = @_;
    my $resolver = $self->get_object('resolver');
    my $return = {
        'result' => 0,
        'error'  => '',
        'values' => [],
    };
    eval {
        my $packet = $resolver->query( $domain, $rrtype );
        if ($packet) {
            foreach my $rr ( $packet->answer ) {
                next unless $rr->type eq $rrtype;
                $return->{ 'result' } = 1;
                push @{$return->{'values'}}, $rr->exchange if $rrtype eq 'MX';
                push @{$return->{'values'}}, $rr->address if $rrtype eq 'A';
                push @{$return->{'values'}}, $rr->address if $rrtype eq 'AAAA';
                ## TODO Check the returned record is in fact valid for its type
            }
        }
        else {
            my $error = $resolver->errorstring;
            if ( $error ) {
                $return->{ 'error' } = $error;
            }
        }
    };
    if ( my $error = $@ ) {
        $self->handle_exception( $error );
        $return->{ 'error' } = 'lookup_error';
        $self->log_error( "ReturnOK: Domain lookup fatal error $error for $domain $rrtype" );
    }
    return $return;
}

sub _check_domain {
    my ( $self, $domain, $type ) = @_;

    return if exists $self->{ 'done' }->{ join(':',$domain,$type) };
    $self->{ 'done' }->{ join(':',$domain,$type) } = 1;

    my $metrics = {};
    my @details;

    if ( ! $domain ) {
        $self->log_error( "ReturnOK: No Domain for $type" );
        my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'x-return-mx' )->safe_set_value( 'none' );
        $metrics->{ $type . '_result' } = 'none';
        $self->dbgout( 'ReturnOKCheck', 'none', LOG_DEBUG );
        $self->add_auth_header($header);
        push @{ $self->{ 'metrics' } }, $metrics;
        return;
    }

    push @details, Mail::AuthenticationResults::Header::SubEntry->new()->set_key( $type . '.domain' )->safe_set_value( $domain );

    # Get Org domain and check that if different.
    my $is_org = -1;
    my $org_domain;
    if ( $self->is_handler_loaded( 'DMARC' ) ) {
        my $dmarc_handler = $self->get_handler('DMARC');
        my $dmarc_object = $dmarc_handler->get_dmarc_object();
        if ( $domain ) {
            $org_domain = eval{ $dmarc_object->get_organizational_domain( $domain ); };
            $self->handle_exception( $@ );
            if ( $org_domain eq $domain ) {
                $is_org = 1;
                $metrics->{ $type . '_is_org_domain' } = 'yes';
            }
            else {
                $is_org = 0;
                $metrics->{ $type . '_is_org_domain' } = 'no';
                push @details, Mail::AuthenticationResults::Header::SubEntry->new()->set_key( 'policy.org_domain' )->safe_set_value( $org_domain );
            }
            push @details, Mail::AuthenticationResults::Header::SubEntry->new()->set_key( 'policy.is_org' )->safe_set_value( $is_org ? 'yes' : 'no' );
        }
    }

    my $lookup_mx = $self->_check_domain_rr( $domain, 'MX' );
    if ( $lookup_mx->{ 'error' } ) {
        push @details, Mail::AuthenticationResults::Header::SubEntry->new()->set_key( 'policy.mx_error' )->safe_set_value( $lookup_mx->{ 'error' } );
    }

    # If MX passed then that's it, stop checking
    if ( $lookup_mx->{ 'result' } == 1 ) {
        my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'x-return-mx' )->safe_set_value( 'pass' );
        push @details, Mail::AuthenticationResults::Header::Comment->new()->safe_set_value( 'MX Records found: '.join(',',@{$lookup_mx->{'values'}}) );
        $metrics->{ $type . '_result' } = 'pass';
        $metrics->{ $type . '_has_mx' } = 'yes';
        $self->dbgout( 'ReturnOKCheck', 'pass', LOG_DEBUG );
        foreach my $detail ( @details ) {
            $header->add_child( $detail );
        }
        $self->add_auth_header($header);
        push @{ $self->{ 'metrics' } }, $metrics;
        return;
    }
    $metrics->{ $type . '_has_mx' } = 'no';

    my $lookup_a    = $self->_check_domain_rr( $domain, 'A' );
    if ( $lookup_a->{ 'error' } ) {
        push @details, Mail::AuthenticationResults::Header::SubEntry->new()->set_key( 'policy.a_error' )->safe_set_value( $lookup_a->{ 'error' } );
    }
    my $lookup_aaaa = $self->_check_domain_rr( $domain, 'AAAA' );
    if ( $lookup_aaaa->{ 'error' } ) {
        push @details, Mail::AuthenticationResults::Header::SubEntry->new()->set_key( 'policy.aaaa_error' )->safe_set_value( $lookup_aaaa->{ 'error' } );
    }

    # If we have an A or AAAA recoed then consider this a warn.
    if ( $lookup_a->{ 'result' } || $lookup_aaaa->{ 'result' } ) {
        my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'x-return-mx' )->safe_set_value( 'warn' );
        $metrics->{ $type . '_result' } = 'warn';
        $self->dbgout( 'ReturnOKCheck', 'warn', LOG_DEBUG );
        if ( $lookup_a->{ 'result' } == 1 ) {
            $metrics->{ $type . '_has_a' } = 'yes';
            push @details, Mail::AuthenticationResults::Header::Comment->new()->safe_set_value( 'A Records found: '.join(',',@{$lookup_a->{'values'}}) );
        }
        else {
            $metrics->{ $type . '_has_a' } = 'no';
        }
        if ( $lookup_aaaa->{ 'result' } == 1 ) {
            $metrics->{ $type . '_has_aaaa' } = 'yes';
            push @details, Mail::AuthenticationResults::Header::Comment->new()->safe_set_value( 'AAAA Records found: '.join(',',@{$lookup_aaaa->{'values'}}) );
        }
        else {
            $metrics->{ $type . '_has_aaaa' } = 'no';
        }
        foreach my $detail ( @details ) {
            $header->add_child( $detail );
        }
        $self->add_auth_header($header);
        push @{ $self->{ 'metrics' } }, $metrics;
        return;
    }
    $metrics->{ $type . '_has_a' } = 'no';
    $metrics->{ $type . '_has_aaaa' } = 'no';

    if ( $is_org == 0 ) {
        # We have DMARC to look this up, have done so, and found that we are NOT the org domain, so recheck at the org domain

        my $lookup_mx = $self->_check_domain_rr( $org_domain, 'MX' );
        if ( $lookup_mx->{ 'error' } ) {
            push @details, Mail::AuthenticationResults::Header::SubEntry->new()->set_key( 'policy.org_mx_error' )->safe_set_value( $lookup_mx->{ 'error' } );
        }

        # If MX passed then that's it, stop checking
        if ( $lookup_mx->{ 'result' } == 1 ) {
            my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'x-return-mx' )->safe_set_value( 'warn' );
            $self->dbgout( 'ReturnOKCheck', 'warn', LOG_DEBUG );
            push @details, Mail::AuthenticationResults::Header::Comment->new()->safe_set_value( 'Org Domain MX Records found: '.join(',',@{$lookup_mx->{'values'}}) );
            foreach my $detail ( @details ) {
            $metrics->{ $type . '_result' } = 'warn';
            $metrics->{ $type . '_has_org_mx' } = 'yes';
                $header->add_child( $detail );
            }
            $self->add_auth_header($header);
            push @{ $self->{ 'metrics' } }, $metrics;
            return;
        }
        $metrics->{ $type . '_has_org_mx' } = 'no';

        my $lookup_a    = $self->_check_domain_rr( $org_domain, 'A' );
        if ( $lookup_a->{ 'error' } ) {
            push @details, Mail::AuthenticationResults::Header::SubEntry->new()->set_key( 'policy.org_a_error' )->safe_set_value( $lookup_a->{ 'error' } );
        }
        my $lookup_aaaa = $self->_check_domain_rr( $org_domain, 'AAAA' );
        if ( $lookup_aaaa->{ 'error' } ) {
            push @details, Mail::AuthenticationResults::Header::SubEntry->new()->set_key( 'policy.org_aaaa_error' )->safe_set_value( $lookup_aaaa->{ 'error' } );
        }

        # If we have an A or AAAA recoed then consider this a warn.
        if ( $lookup_a->{ 'result' } || $lookup_aaaa->{ 'result' } ) {
            my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'x-return-mx' )->safe_set_value( 'warn' );
            $metrics->{ $type . '_result' } = 'warn';
            $self->dbgout( 'ReturnOKCheck', 'warn', LOG_DEBUG );
            if ( $lookup_a->{ 'result' } == 1 ) {
                $metrics->{ $type . '_has_org_a' } = 'yes';
                push @details, Mail::AuthenticationResults::Header::Comment->new()->safe_set_value( 'Org Domain A Records found: '.join(',',@{$lookup_a->{'values'}}) );
            }
            else {
                $metrics->{ $type . '_has_org_a' } = 'no';
            }
            if ( $lookup_aaaa->{ 'result' } == 1 ) {
                $metrics->{ $type . '_has_org_aaaa' } = 'yes';
                push @details, Mail::AuthenticationResults::Header::Comment->new()->safe_set_value( 'Org Domain AAAA Records found: '.join(',',@{$lookup_aaaa->{'values'}}) );
            }
            else {
                $metrics->{ $type . '_has_org_aaaa' } = 'no';
            }
            foreach my $detail ( @details ) {
                $header->add_child( $detail );
            }
            $self->add_auth_header($header);
            push @{ $self->{ 'metrics' } }, $metrics;
            return;
        }
        $metrics->{ $type . '_has_org_a' } = 'no';
        $metrics->{ $type . '_has_org_aaaa' } = 'no';

    }

    # We got here, we fail!
    my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'x-return-mx' )->safe_set_value( 'fail' );
    $metrics->{ $type . '_result' } = 'fail';
    $self->dbgout( 'ReturnOKCheck', 'fail', LOG_DEBUG );
    foreach my $detail ( @details ) {
        $header->add_child( $detail );
    }
    $self->add_auth_header($header);

    push @{ $self->{ 'metrics' } }, $metrics;
    return;
}

sub envfrom_callback {
    my ( $self, $env_from ) = @_;

    $self->{ 'metrics' } = [];
    $self->{ 'done' } = {};

    $env_from = q{} if $env_from eq '<>';
    my $addresses = $self->get_addresses_from( $env_from );
    foreach my $address ( @$addresses ) {
        $self->_check_address( $address, 'smtp' );
    }

    return;
}

sub header_callback {
    my ( $self, $header, $value ) = @_;

    if ( $header eq 'From' ) {
        my $addresses = $self->get_addresses_from( $value );
        foreach my $address ( @$addresses ) {
            $self->_check_address( $address, 'header' );
        }
    }

    return;
}

sub close_callback {
    my ( $self ) = @_;
    delete $self->{ 'done' };
    delete $self->{ 'metrics' };
    return;
}

sub eom_callback {
    my ( $self ) = @_;

    my $metrics = $self->{ 'metrics' };

    foreach my $metric ( @$metrics ) {
        $self->metric_count( 'returnok_total', $metric );
    }

    return;
}

1;

__END__

=head1 DESCRIPTION

Check that return addresses have valid MX records.

=head1 CONFIGURATION

No configuration options exist for this handler.

