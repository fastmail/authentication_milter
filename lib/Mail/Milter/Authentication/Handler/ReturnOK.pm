package Mail::Milter::Authentication::Handler::ReturnOK;
use strict;
use warnings;
use base 'Mail::Milter::Authentication::Handler';
use version; our $VERSION = version->declare('v1.1.7');

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

    $self->_check_domain ( $domain, $type, 0 );

    # Get Org domain and check that if different.
    if ( $self->is_handler_loaded( 'DMARC' ) ) {
        my $dmarc_handler = $self->get_handler('DMARC');
        my $dmarc_object = $dmarc_handler->get_dmarc_object();
        if ( $domain ) {
            my $org_domain = eval{ $dmarc_object->get_organizational_domain( $domain ); };
            if ( $org_domain eq $domain ) {
                $self->{ 'metrics' }->{ $type . '_is_org_domain' } = 'yes';
                push @{ $self->{ 'details' } }, Mail::AuthenticationResults::Header::SubEntry->new()->set_key( $type . '_is_org_domain' )->set_value( 'yes' );
            }
            else {
                $self->_check_domain( $org_domain, $type, 1 );
                $self->{ 'metrics' }->{ $type . '_is_org_domain' } = 'no';
                push @{ $self->{ 'details' } }, Mail::AuthenticationResults::Header::SubEntry->new()->set_key( $type . '_is_org_domain' )->set_value( 'no' );
            }
        }
    }

    return;
}

sub _check_domain {
    my ( $self, $domain, $type, $is_org ) = @_;

    my $resolver = $self->get_object('resolver');

    if ( ! $domain ) {
        $self->log_error( "ReturnOK: No Domain for $type" );
        $self->{ 'metrics' }->{ ( $is_org ? 'org_' : '' ) . $type } = 'empty';
        return;
    }

    my $result = 'fail';
    $self->{ 'metrics' }->{ ( $is_org ? 'org_' : '' ) . $type } = 'fail';
    my @details;

    push @details, Mail::AuthenticationResults::Header::SubEntry->new()->set_key( 'domain' )->set_value( $domain );

    my $has_mx   = 0;
    my $has_a    = 0;
    my $has_aaaa = 0;
    my $packet;

    eval {
        $packet = $resolver->query( $domain, 'MX' );
        if ($packet) {
            foreach my $rr ( $packet->answer ) {
                next unless $rr->type eq "MX";
                $has_mx = 1;
                $result = 'pass';
                $self->{ 'metrics' }->{ 'result' } = 'pass' if ! $is_org;
                $self->{ 'metrics' }->{ ( $is_org ? 'org_' : '' ) . $type } = 'mx_pass';
                last;
            }
        }
        else {
            my $error = $resolver->errorstring;
            if ( $error ) {
                push @details, Mail::AuthenticationResults::Header::SubEntry->new()->set_key( 'mx.error' )->set_value( $error );
            }
            else {
                push @details, Mail::AuthenticationResults::Header::SubEntry->new()->set_key( 'mx.error' )->set_value( 'none' );
            }
        }
    };
    if ( my $error = $@ ) {
        $self->log_error( "ReturnOK: Domain lookup fatal error $error for $domain" );
        push @details, Mail::AuthenticationResults::Header::SubEntry->new()->set_key( 'mx.error' )->set_value( 'lookup_error' );
    }

    if ( ! $has_mx ) {

        eval {
            $packet = $resolver->query( $domain, 'A' );
            if ($packet) {
                foreach my $rr ( $packet->answer ) {
                    next unless $rr->type eq "A";
                    $has_a = 1;
                    $result = 'warn';
                    $self->{ 'metrics' }->{ 'result' } = 'warn' if $self->{ 'metrics' }->{ 'result' } ne 'pass' and ( ! $is_org );
                    last;
                }
            }
            else {
                my $error = $resolver->errorstring;
                if ( $error ) {
                    push @details, Mail::AuthenticationResults::Header::SubEntry->new()->set_key( 'a.error' )->set_value( $error );
                }
                else {
                    push @details, Mail::AuthenticationResults::Header::SubEntry->new()->set_key( 'a.error' )->set_value( 'none' );
                }
            }
        };
        if ( my $error = $@ ) {
            $self->log_error( "ReturnOK: Domain lookup fatal error $error for $domain" );
            push @details, Mail::AuthenticationResults::Header::SubEntry->new()->set_key( 'a.error' )->set_value( 'lookup_error' );
        }

        eval {
            $packet = $resolver->query( $domain, 'AAAA' );
            if ($packet) {
                foreach my $rr ( $packet->answer ) {
                    next unless $rr->type eq "AAAA";
                    $has_aaaa = 1;
                    $result = 'warn';
                    $self->{ 'metrics' }->{ 'result' } = 'warn' if $self->{ 'metrics' }->{ 'result' } ne 'pass';
                    last;
                }
            }
            else {
                my $error = $resolver->errorstring;
                if ( $error ) {
                    push @details, Mail::AuthenticationResults::Header::SubEntry->new()->set_key( 'aaaa.error' )->set_value( $error );
                }
                else {
                    push @details, Mail::AuthenticationResults::Header::SubEntry->new()->set_key( 'aaaa.error' )->set_value( 'none' );
                }
            }
        };
        if ( my $error = $@ ) {
            $self->log_error( "ReturnOK: Domain lookup fatal error $error for $domain" );
            push @details, Mail::AuthenticationResults::Header::SubEntry->new()->set_key( 'aaaa.error' )->set_value( 'lookup_error' );
        }


        if ( $has_a && $has_aaaa ) {
            $self->{ 'metrics' }->{ ( $is_org ? 'org_' : '' ) . $type } = 'a_pass';
        }
        elsif ( $has_a ) {
            $self->{ 'metrics' }->{ ( $is_org ? 'org_' : '' ) . $type } = 'a4_pass';
        }
        elsif ( $has_aaaa ) {
            $self->{ 'metrics' }->{ ( $is_org ? 'org_' : '' ) . $type } = 'a6_pass';
        }
    }

    push @details, Mail::AuthenticationResults::Header::SubEntry->new()->set_key( 'result' )->set_value( $result );

    my $prefix = $type . ( $is_org ? '_org' : q{} );
    foreach my $detail ( @details ) {
        $detail->set_key( $prefix . '.' . $detail->key() );
        push @{ $self->{ 'details' } }, $detail;
    }

    return;
}

sub envfrom_callback {
    my ( $self, $env_from ) = @_;

    $self->{ 'metrics' } = { 'result' => 'fail' };
    $self->{ 'details' } = [];

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

sub close_callback {
    my ( $self ) = @_;
    delete $self->{ 'metrics' };
    delete $self->{ 'details' };
    return;
}

sub eom_callback {
    my ( $self ) = @_;

    my $metrics = $self->{ 'metrics' };

    $self->dbgout( 'ReturnOKCheck', $self->{ 'metrics' }->{ 'result'} , LOG_DEBUG );
    my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'x-return-mx' )->set_value( $metrics->{ 'result' } );
    foreach my $detail ( @{ $self->{ 'details' } } ) {
        $header->add_child( $detail );
    }

    $self->add_auth_header($header);

    $self->metric_count( 'returnok_total', $metrics );

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


