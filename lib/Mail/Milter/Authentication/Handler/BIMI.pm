package Mail::Milter::Authentication::Handler::BIMI;
use 5.20.0;
use strict;
use warnings;
use Mail::Milter::Authentication::Pragmas;
# ABSTRACT: Handler class for BIMI
# VERSION
use base 'Mail::Milter::Authentication::Handler';
use Clone qw{ clone };
use English qw{ -no_match_vars };
use Mail::AuthenticationResults::Header::Comment;
use Mail::AuthenticationResults::Header::Entry;
use Mail::AuthenticationResults::Header::SubEntry;
use Mail::BIMI 1.20190210;
use Sys::Syslog qw{:standard :macros};

sub default_config {
    return {
    };
}

sub register_metrics {
    return {
        'bimi_total' => 'The number of emails processed for BIMI',
        'bimi_removed_total' => 'The number BIMI-Location headers removed',
    };
}

sub remove_bimi_header {
    my ( $self, $value ) = @_;
    $self->metric_count( 'bimi_remove_total' );
    if ( !exists( $self->{'remove_bimi_headers'} ) ) {
        $self->{'remove_bimi_headers'} = [];
    }
    push @{ $self->{'remove_bimi_headers'} }, $value;
    return;
}

sub envfrom_callback {
    my ( $self, $env_from ) = @_;
    delete $self->{'bimi_header_index'};
    delete $self->{'remove_bimi_headers'};
    $self->{ 'header_added' } = 0;
    return;
}

sub header_callback {
    my ( $self, $header, $value ) = @_;

    # Not sure where this should go in the flow, so it's going here!
    # Which is clearly, or at least probably the wrong place.
    if ( lc $header eq 'bimi-location' ) {
        if ( !exists $self->{'bimi_header_index'} ) {
            $self->{'bimi_header_index'} = 0;
        }
        $self->{'bimi_header_index'} =
        $self->{'bimi_header_index'} + 1;
        $self->remove_bimi_header( $self->{'bimi_header_index'} );
        my $forged_header =
          '(Received BIMI-Location header removed by '
          . $self->get_my_hostname()
          . ')' . "\n"
          . '    '
          . $value;
        $self->append_header( 'X-Received-BIMI-Location',
            $forged_header );
    }

    return if ( $self->is_local_ip_address() );
    return if ( $self->is_trusted_ip_address() );
    return if ( $self->is_authenticated() );
    return if ( $self->{'failmode'} );

    if ( lc $header eq 'bimi-selector' ) {
        if ( exists $self->{'selector'} ) {
            $self->dbgout( 'BIMIFail', 'Multiple BIMI-Selector fields', LOG_INFO );
            my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'bimi' )->safe_set_value( 'fail' );
            $header->add_child( Mail::AuthenticationResults::Header::Comment->new()->safe_set_value( 'multiple BIMI-Selector fields in message' ) );
            $self->add_auth_header( $header );
            $self->metric_count( 'bimi_total', { 'result' => 'fail', 'reason' => 'bad_selector_header' } );
            $self->{ 'header_added' } = 1;
            $self->{'failmode'} = 1;
            return;
        }
        $self->{'selector'} = $value;
    }
    if ( lc $header eq 'from' ) {
        if ( exists $self->{'from_header'} ) {
            $self->dbgout( 'BIMIFail', 'Multiple RFC5322 from fields', LOG_INFO );
            my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'bimi' )->safe_set_value( 'fail' );
            $header->add_child( Mail::AuthenticationResults::Header::Comment->new()->safe_set_value( 'multiple RFC5322 from fields in message' ) );
            $self->add_auth_header( $header );
            $self->metric_count( 'bimi_total', { 'result' => 'fail', 'reason' => 'bad_from_header' } );
            $self->{ 'header_added' } = 1;
            $self->{'failmode'} = 1;
            return;
        }
        $self->{'from_header'} = $value;
    }
    ## ToDo remove/rename existing headers here
    return;
}

sub eom_requires {
    my ($self) = @_;
    my @requires = qw{ DMARC };
    return \@requires;
}

sub eom_callback {
    my ($self) = @_;
    my $config = $self->handler_config();

    # Again, not sure where this should go, so it's going here.
    if ( exists( $self->{'remove_bimi_headers'} ) ) {
        foreach my $header ( reverse @{ $self->{'remove_bimi_headers'} } ) {
            $self->dbgout( 'RemoveBIMILocationHeader', $header, LOG_DEBUG );
            $self->change_header( 'BIMI-Location', $header, q{} );
        }
    }

    return if ( $self->{ 'header_added' } );
    return if ( $self->is_local_ip_address() );
    return if ( $self->is_trusted_ip_address() );
    return if ( $self->is_authenticated() );
    return if ( $self->{'failmode'} );
    eval {
        my $Domain = $self->get_domain_from( $self->{'from_header'} );

        # Rework this to allow for multiple dmarc_result objects as per new DMARC handler
        my $DMARCResults = $self->get_object( 'dmarc_results' );

        if ( ! $DMARCResults ) {

            $self->log_error( 'BIMI Error No DMARC Results object');
            my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'bimi' )->safe_set_value( 'temperror' );
            $header->add_child( Mail::AuthenticationResults::Header::Comment->new()->safe_set_value( 'Internal DMARC error' ) );
            $self->add_auth_header( $header );
            $self->{ 'header_added' } = 1;

        }
        else {
            if ( scalar @$DMARCResults != 1 ) {
                $self->dbgout( 'BIMIFail', 'Multiple DMARC Results', LOG_INFO );
                my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'bimi' )->safe_set_value( 'fail' );
                $header->add_child( Mail::AuthenticationResults::Header::Comment->new()->safe_set_value( 'multiple DMARC results for message' ) );
                $self->add_auth_header( $header );
                $self->metric_count( 'bimi_total', { 'result' => 'fail', 'reason' => 'multiple_dmarc_results' } );
                $self->{ 'header_added' } = 1;
                $self->{'failmode'} = 1;
                return;
            }
            else {
                # If Multiple DMARC results is OK then... foreach my $DMARCResult ( @$DMARCResults ) {
                my $DMARCResult = clone $DMARCResults->[0]; # Clone so we can modify without breaking reporting data

                ## Consider ARC
                # We only have 1 DMARC result so we find the auth results header that it added
                my $selector_arc_pass = 0;
                if ( $DMARCResult->result ne 'pass' ) {
                    my $top_handler = $self->get_top_handler();
                    my @auth_headers;
                    if ( exists( $top_handler->{'auth_headers'} ) ) {
                        @auth_headers = ( @auth_headers, @{ $top_handler->{'auth_headers'} } );
                    }
                    if (@auth_headers) {
                        foreach my $auth_header ( @auth_headers ) {
                            next if $auth_header->key ne 'dmarc';
                            my $arc_aware_result = eval{ $auth_header->search({key=>'policy.arc-aware-result'})->children->[0]->value } // '';
                            $self->handle_exception( $@ );
                            if ( $arc_aware_result eq 'pass' ) {
                                $self->log_error( 'BIMI DMARC ARC pass detected' );
                                $DMARCResult->{result} = $arc_aware_result; # Feels hacky, but does the right thing
                                # Note, we can't check for signness of BIMI-Selector for arc forwarded mail where DKIM context has been lost
                                # When we have a pass by arc we skip the DKIM check for BIMI-Selector
                                $selector_arc_pass = 1;
                            }
                        }
                    }
                }

                my $Selector = $self->{ 'selector' };
                if ( !$Selector ) {
                    $Selector = 'default';
                }
                elsif ( $Selector =~ m/^v=BIMI1;\s+s=(\w+);?/i ) {
                    $Selector = $1;
                    $Selector = lc $Selector;
                    # Was the BIMI-Selector header DKIM Signed?
                    my $selector_was_domain_signed = 0;
                    my $selector_was_org_domain_signed = 0;
                    my $selector_was_third_party_domain_signed = 0;
                    my $OrgDomain = eval{ $self->get_handler('DMARC')->get_dmarc_object()->get_organizational_domain( $Domain ) };
                    $self->handle_exception( $@ );
                    if ( $self->{'selector'} ) {
                        my $dkim_handler = $self->get_handler('DKIM');
                        if ( $dkim_handler->{'has_dkim'} ) {
                            my $dkim_object = $self->get_object('dkim');
                            if ( $dkim_object ) {
                                if ( $dkim_object->signatures() ) {
                                    foreach my $signature ( $dkim_object->signatures() ) {
                                        next if $signature->result ne 'pass';
                                        my @signed_headers = $signature->headerlist;
                                        next if ! grep { lc $_ eq 'bimi-selector' } @signed_headers;
                                        my $signature_domain = $signature->domain;
                                        if ( lc $signature_domain eq lc $Domain ) {
                                            $selector_was_domain_signed = 1;
                                        }
                                        elsif ( lc $signature_domain eq lc $OrgDomain ) {
                                            $selector_was_org_domain_signed = 1;
                                        }
                                        else {
                                            $selector_was_third_party_domain_signed = 1;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    my $Alignment = $selector_was_domain_signed ? 'domain'
                                  : $selector_was_org_domain_signed ? 'orgdomain'
                                  : $selector_arc_pass ? 'arc'
                                  : $selector_was_third_party_domain_signed ? 'thirdparty'
                                  : 'unsigned';
                    if ( $Alignment eq 'unsigned' || $Alignment eq 'thirdparty' ) {
                        $self->log_error( 'BIMI Header DKIM '.$Alignment.' for Selector '.$Selector.' - ignoring' );
                        $Selector = 'default';
                    }

                }
                else {
                    $self->log_error( 'BIMI Invalid Selector Header: ' . $Selector );
                    $Selector = 'default';
                }

                my $BIMI = Mail::BIMI->new(
                    resolver => $self->get_object( 'resolver' ),
                    dmarc_object => $DMARCResult,
                    domain => $Domain,
                    selector => $Selector,
                );
                $self->{'bimi_object'} = $BIMI; # For testing!

                my $Result = $BIMI->result();
                my $AuthResults = $Result->get_authentication_results_object();
                $self->add_auth_header( $AuthResults );
                $self->{ 'header_added' } = 1;
                my $Record = $BIMI->record();
                my $URLList = $Record->locations->location;
                if ( $Result->result() eq 'pass' ) {
                    $self->prepend_header( 'BIMI-Location', join( "\n",
                        'v=BIMI1;',
                        '    l=' . join( ',', @$URLList ) ) );
                }

                $self->metric_count( 'bimi_total', { 'result' => $Result->result() } );
            }
        }

    };
    if ( my $error = $@ ) {
        $self->handle_exception( $error );
        $self->log_error( 'BIMI Error ' . $error );
        if ( ! $self->{ 'header_added' } ) {
            my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'bimi' )->safe_set_value( 'temperror' );
            $self->add_auth_header( $header );
            $self->{ 'header_added' } = 1;
        }
    }

    return;
}

sub close_callback {
    my ( $self ) = @_;
    delete $self->{'selector'};
    delete $self->{'from_header'};
    delete $self->{'failmode'};
    delete $self->{'remove_bimi_headers'};
    delete $self->{'bimi_object'};
    delete $self->{'bimi_header_index'};
    delete $self->{ 'header_added' };
    return;
}

1;

__END__

=head1 NAME

  Authentication Milter - BIMI Module

=head1 DESCRIPTION

Module implementing the BIMI standard checks.

This handler requires the DMARC handler and its dependencies to be installed and active.

=head1 CONFIGURATION

        "BIMI" : {                                      | Config for the BIMI Module
                                                        | Requires DMARC
        },

=head1 SYNOPSIS

=head1 AUTHORS

Marc Bradshaw E<lt>marc@marcbradshaw.netE<gt>

=head1 COPYRIGHT

Copyright 2018

This library is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.

