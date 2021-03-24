package Mail::Milter::Authentication::Handler::BIMI;
use 5.20.0;
use strict;
use warnings;
use Mail::Milter::Authentication::Pragmas;
# ABSTRACT: Handler class for BIMI
# VERSION
use base 'Mail::Milter::Authentication::Handler';
use Mail::BIMI 2;

sub default_config {
    return {
        'bimi_options' => {},
        'rbl_allowlist' => '',
        'rbl_blocklist' => '',
        'rbl_no_evidence_allowlist' => '',
      };
}

sub register_metrics {
    return {
        'bimi_total' => 'The number of emails processed for BIMI',
    };
}

sub setup_callback {
    my ($self) = @_;
    my $config = $self->handler_config();
    my $sanitize_location_header = $config->{sanitize_location_header} // 'yes';
    my $sanitize_indicator_header = $config->{sanitize_indicator_header} // 'silent';
    $self->add_header_to_sanitize_list('bimi-location', $sanitize_location_header eq 'silent') unless $sanitize_location_header eq 'no';
    $self->add_header_to_sanitize_list('bimi-indicator', $sanitize_indicator_header eq 'silent') unless $sanitize_indicator_header eq 'no';
    return;
}

sub envfrom_callback {
    my ( $self, $env_from ) = @_;
    $self->{ 'header_added' } = 0;
}

sub header_callback {
    my ( $self, $header, $value ) = @_;

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
}

sub eom_requires {
    my ($self) = @_;
    my @requires = qw{ DMARC };
    return \@requires;
}

sub eom_callback {
    my ($self) = @_;
    my $config = $self->handler_config();

    if ( $config->{rbl_allowlist} && $config->{rbl_blocklist} ) {
        $self->dbgout( 'BIMI Error', 'Cannot specify both rbl_allowlist and rbl_blocklist', LOG_DEBUG );
        return;
    }

    return if ( $self->{ 'header_added' } );
    return if ( $self->is_local_ip_address() );
    return if ( $self->is_trusted_ip_address() );
    return if ( $self->is_authenticated() );
    return if ( $self->{'failmode'} );
    eval {
        my $Domain = $self->get_domain_from( $self->{'from_header'} );

        my $DMARCResults = $self->get_object( 'dmarc_results' );
        if ( ! $DMARCResults ) {

            my $failure_type = 'temperror';
            my $top_handler = $self->get_top_handler();
            my @auth_headers;
            if ( exists( $top_handler->{'auth_headers'} ) ) {
                @auth_headers = ( @auth_headers, @{ $top_handler->{'auth_headers'} } );
            }
            if (@auth_headers) {
                foreach my $auth_header (@auth_headers) {
                    next unless $auth_header->key eq 'dmarc';
                    if ( $auth_header->value eq 'permerror' ) {
                        $failure_type = 'permerror';
                        last;
                    }
                }
            }

            $self->log_error( 'BIMI Error No DMARC Results object');
            my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'bimi' )->safe_set_value( $failure_type );
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

                my $RelevantSPFResult;
                my $SPFResults = $self->get_object( 'spf_results' );
                if ( $SPFResults ) {
                    foreach my $SPFResult ( $SPFResults->@* ) {
                        next if lc $SPFResult->request->domain ne $Domain;
                        $RelevantSPFResult = $SPFResult;
                    }
                }

                my $Skip;
                if ( $config->{rbl_allowlist} ) {
                    my $OrgDomain = $self->get_object('dmarc')->get_organizational_domain($Domain);
                    unless ( $self->rbl_check_domain( $OrgDomain, $config->{'rbl_allowlist'} ) ) {
                        $self->dbgout( 'BIMISkip', 'Not on allowlist', LOG_INFO );
                        $Skip = 'Local policy; not allowed';
                    }
                }
                elsif ( $config->{rbl_blocklist} ) {
                    my $OrgDomain = $self->get_object('dmarc')->get_organizational_domain($Domain);
                    if ( $self->rbl_check_domain( $OrgDomain, $config->{'rbl_blocklist'} ) ) {
                        $self->dbgout( 'BIMISkip', 'On blocklist', LOG_INFO );
                        $Skip = 'Local policy; blocked';
                    }
                }

                my %Options;
                $Options{options} = $config->{'bimi_options'} if exists $config->{'bimi_options'};
                $Options{resolver} = $self->get_object( 'resolver' );
                $Options{dmarc_object} = $self->get_object('dmarc');
                $Options{spf_object} = $RelevantSPFResult if $RelevantSPFResult;
                $Options{domain} = $Domain;
                $Options{selector} = $Selector;
                my $BIMI = Mail::BIMI->new(%Options);
                $self->{'bimi_object'} = $BIMI; # For testing!

                my $Result;
                my $timeout = $config->{'timeout'} // 5000000;
                eval {
                    $self->set_handler_alarm( $timeout );
                    $Result = $BIMI->result() if ! $Skip;
                };
                if ( my $Error = $@ ) {
                    $self->reset_alarm();
                    my $Type = $self->is_exception_type( $Error );
                    if ( $Type ) {
                        if ( $Type eq 'Timeout' ) {
                            # We have a timeout, is it global or is it ours?
                            if ( $self->get_time_remaining() > 0 ) {
                                # We have time left, but this operation save timed out
                                $Skip = 'Timeout';
                            }
                            else {
                                $self->handle_exception( $Error );
                            }
                        }
                    }
                }

                if ( !$Skip
                     && $config->{rbl_no_evidence_allowlist}
                     && $Result->result eq 'pass'
                     && (
                       !$BIMI->record->authority
                       || !$BIMI->record->authority->vmc
                       || !$BIMI->record->authority->vmc->is_valid
                     )
                ) {
                    my $OrgDomain = $self->get_object('dmarc')->get_organizational_domain($Domain);
                    unless ( $self->rbl_check_domain( $OrgDomain, $config->{'rbl_no_evidence_allowlist'} ) ) {
                        $self->dbgout( 'BIMISkip', 'Not on No Evidence Allowlist', LOG_INFO );
                        $Skip = 'Local policy; not allowed without evidence';
                    }
                }


                if ( $Skip ) {
                    my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'bimi' )->safe_set_value( 'skipped' );
                    $header->add_child( Mail::AuthenticationResults::Header::Comment->new()->safe_set_value( $Skip ) );
                    $self->add_auth_header( $header );
                    $self->{ 'header_added' } = 1;
                    $self->metric_count( 'bimi_total', { 'result' => 'skipped', 'reason' => 'rbl' } );
                }
                else {
                    my $AuthResults = $Result->get_authentication_results_object();
                    $self->add_auth_header( $AuthResults );
                    $self->{ 'header_added' } = 1;
                    my $Record = $BIMI->record();
                    if ( $Result->result() eq 'pass' ) {
                        my $Headers = $Result->headers;
                        if ( $Headers ) {
                            $self->prepend_header( 'BIMI-Location', $Headers->{'BIMI-Location'} ) if exists $Headers->{'BIMI-Location'} ;
                            $self->prepend_header( 'BIMI-Indicator', $Headers->{'BIMI-Indicator'} ) if exists $Headers->{'BIMI-Indicator'} ;
                        }
                    }

                    $self->metric_count( 'bimi_total', { 'result' => $Result->result() } );
                }
                $BIMI->finish;
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
}

sub close_callback {
    my ( $self ) = @_;
    delete $self->{'selector'};
    delete $self->{'from_header'};
    delete $self->{'failmode'};
    delete $self->{'bimi_object'};
    delete $self->{'header_added'};
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
            "bimi_options" : {},                        | Options to pass into Mail::BIMI->new
            "rbl_allowlist" : "",                       | Optional RBL Allow list of allowed org domains
            "rbl_blocklist" : "",                       | Optional RBL Block list of disallowed org domains
                                                        | Allow and Block list cannot both be present
            "rbl_no_evidence_allowlist" : "",           | Optonal RBL Allow list of allowed org domains that do NOT require evidence documents
                                                        | When set, domains not on this list which do not have evidence documents will be 'skipped'
            "timeout" : 5000000,                        | Timeout, in microseconds, to apply to a BIMI record check/fetch, detault 5000000 (5s)
            "sanitize_location_header" : "yes",         | Remove existing BIMI-Location header? yes|no|silent (default yes)
            "sanitize_indicator_header" : "yes",        | Remove existing BIMI-Location header? yes|no|silent (default silent)
        },

