package Mail::Milter::Authentication::Handler::DMARC;
use strict;
use warnings;
use base 'Mail::Milter::Authentication::Handler';
# VERSION

use Data::Dumper;
use English qw{ -no_match_vars };
use Net::IP;
use Sys::Syslog qw{:standard :macros};
use List::MoreUtils qw{ uniq };

use Mail::DMARC::PurePerl 1.20160612;
use Mail::AuthenticationResults::Header::Entry;
use Mail::AuthenticationResults::Header::SubEntry;
use Mail::AuthenticationResults::Header::Comment;

my $PSL_CHECKED_TIME;

sub default_config {
    return {
        'hide_none'      => 0,
        'use_arc'        => 1,
        'hard_reject'    => 0,
        'no_list_reject' => 1,
        'whitelisted'    => [],
        'detect_list_id' => 1,
        'report_skip_to' => [ 'my_report_from_address@example.com' ],
        'no_report'      => 0,
        'config_file'    => '/etc/mail-dmarc.ini',
        'no_reject_disposition' => 'quarantine',
        'no_list_reject_disposition' => 'none',
    };
}

sub grafana_rows {
    my ( $self ) = @_;
    my @rows;
    push @rows, $self->get_json( 'DMARC_metrics' );
    return \@rows;
}

sub is_whitelisted {
    my ( $self ) = @_;
    my $config = $self->handler_config();
    return 0 if not exists( $config->{'whitelisted'} );
    my $top_handler = $self->get_top_handler();
    my $ip_obj = $top_handler->{'ip_object'};
    my $whitelisted = 0;
    foreach my $entry ( @{ $config->{'whitelisted'} } ) {
        # This does not consider dkim/spf results added by a passing arc chain
        # we consider this out of scope at this point.
        if ( $entry =~ /^dnswl:/ ) {
            my ( $dummy, $type, $rbl ) = split( /:/, $entry, 3 );
            if ( $type eq 'spf' ) {
                eval {
                    my $spf = $self->get_handler('SPF');
                    if ( $spf ) {
                        my $got_spf_result = $spf->{'dmarc_result'};
                        if ( $got_spf_result eq 'pass' ) {
                            my $got_spf_domain = $spf->{'dmarc_domain'};
                            if ( $self->rbl_check_domain( $got_spf_domain, $rbl ) ) {
                                $self->dbgout( 'DMARCReject', "Whitelist hit " . $entry, LOG_INFO );
                                $whitelisted = 1;
                            }
                        }
                    }
                };
                $self->handle_exception( $@ );
            }
            elsif ( $type eq 'dkim' ) {
                my $dkim_handler = $self->get_handler('DKIM');
                foreach my $dkim_domain( sort keys %{ $dkim_handler->{'valid_domains'}} ) {
                    if ( $self->rbl_check_domain( $dkim_domain, $rbl ) ) {
                        $self->dbgout( 'DMARCReject', "Whitelist hit " . $entry, LOG_INFO );
                        $whitelisted = 1;
                    }
                }
            }
            elsif ( $type eq 'ip' ) {
                if ( $self->rbl_check_ip( $ip_obj, $rbl ) ) {
                    $self->dbgout( 'DMARCReject', "Whitelist hit " . $entry, LOG_INFO );
                    $whitelisted = 1;
                }
            }
        }
        elsif ( $entry =~ /^dkim:/ ) {
            my ( $dummy, $dkim_domain ) = split( /:/, $entry, 2 );
            my $dkim_handler = $self->get_handler('DKIM');
            if ( exists( $dkim_handler->{'valid_domains'}->{ lc $dkim_domain } ) ) {
                $self->dbgout( 'DMARCReject', "Whitelist hit " . $entry, LOG_INFO );
                $whitelisted = 1;
            }
        }
        elsif ( $entry =~ /^spf:/ ) {
            my ( $dummy, $spf_domain ) = split( /:/, $entry, 2 );
            eval {
                my $spf = $self->get_handler('SPF');
                if ( $spf ) {
                    my $got_spf_result = $spf->{'dmarc_result'};
                    if ( $got_spf_result eq 'pass' ) {
                        my $got_spf_domain = $spf->{'dmarc_domain'};
                        if ( lc $got_spf_domain eq lc $spf_domain ) {
                            $self->dbgout( 'DMARCReject', "Whitelist hit " . $entry, LOG_INFO );
                            $whitelisted = 1;
                        }
                    }
                }
            };
            $self->handle_exception( $@ );
        }
        else {
            my $whitelisted_obj = Net::IP->new($entry);
            my $is_overlap = $ip_obj->overlaps($whitelisted_obj) || 0;
            if (
                   $is_overlap == $IP_A_IN_B_OVERLAP
                || $is_overlap == $IP_B_IN_A_OVERLAP     # Should never happen
                || $is_overlap == $IP_PARTIAL_OVERLAP    # Should never happen
                || $is_overlap == $IP_IDENTICAL
              )
            {
                $self->dbgout( 'DMARCReject', "Whitelist hit " . $entry, LOG_INFO );
                $whitelisted = 1;
            }
        }
        return $whitelisted if $whitelisted;
    }
    return $whitelisted;
}

sub pre_loop_setup {
    my ( $self ) = @_;
    $PSL_CHECKED_TIME = time;
    my $dmarc = Mail::DMARC::PurePerl->new();
    my $config = $self->{'config'};
    if ( exists ( $config->{ 'config_file' } ) ) {
        $self->log_error( 'DMARC config file does not exist' ) if ! exists $config->{ 'config_file' };
        $dmarc->config( $config->{ 'config_file' } );
    }
    my $psl = eval { $dmarc->get_public_suffix_list(); };
    $self->handle_exception( $@ );
    if ( $psl ) {
        $self->{'thischild'}->loginfo( 'DMARC Preloaded PSL' );
    }
    else {
        $self->{'thischild'}->logerror( 'DMARC Could not preload PSL' );
    }
    return;
}

sub pre_fork_setup {
    my ( $self ) = @_;
    my $now = time;
    my $dmarc = Mail::DMARC::PurePerl->new();
    my $config = $self->{'config'};
    if ( exists ( $config->{ 'config_file' } ) ) {
        $self->log_error( 'DMARC config file does not exist' ) if ! exists $config->{ 'config_file' };
        $dmarc->config( $config->{ 'config_file' } );
    }
    my $check_time = 60*10; # Check no more often than every 10 minutes
    if ( $now > $PSL_CHECKED_TIME + $check_time ) {
        $PSL_CHECKED_TIME = $now;
        if ( $dmarc->can( 'check_public_suffix_list' ) ) {
            if ( $dmarc->check_public_suffix_list() ) {
                $self->{'thischild'}->loginfo( 'DMARC PSL file has changed and has been reloaded' );
            }
            else {
                $self->{'thischild'}->loginfo( 'DMARC PSL file has not changed since last loaded' );
            }
        }
        else {
            $self->{'thischild'}->loginfo( 'DMARC PSL file update checking not available' );
        }
    }
    return;
}

sub register_metrics {
    return {
        'dmarc_total' => 'The number of emails processed for DMARC',
    };
}

sub _process_arc_dmarc_for {
    my ( $self, $env_domain_from, $header_domain ) = @_;

    my $config = $self->handler_config();
    my $dmarc = $self->new_dmarc_object();
    $dmarc->source_ip( $self->ip_address() );

    # Set the DMARC Envelope From Domain
    if ( $env_domain_from ne q{} ) {
        eval {
            $dmarc->envelope_from( $env_domain_from );
        };
        if ( my $error = $@ ) {
            $self->handle_exception( $error );
            return;
        }
    }

    # Add the Envelope To
    eval {
        $dmarc->envelope_to( lc $self->get_domain_from( $self->{'env_to'} ) );
    };
    if ( my $error = $@ ) {
        $self->handle_exception( $error );
    }

    # Add the From Header
    eval { $dmarc->header_from( $header_domain ) };
    if ( my $error = $@ ) {
        $self->handle_exception( $error );
        return;
    }

    # Add the SPF Results Object
    eval {
        my $spf = $self->get_handler('SPF');
        if ( $spf ) {

            if ( $spf->{'dmarc_result'} eq 'pass' && lc $spf->{'dmarc_domain'} eq lc $header_domain ) {
                # Have a matching local entry, use it.
                ## TODO take org domains into consideration here
                $dmarc->spf(
                    'domain' => $spf->{'dmarc_domain'},
                    'scope'  => $spf->{'dmarc_scope'},
                    'result' => $spf->{'dmarc_result'},
                );
            }
            elsif ( my $arc_spf = $self->get_handler('ARC')->get_trusted_spf_results() ) {
                # Pull from ARC if we can
                push @$arc_spf, {
                    'domain' => $spf->{'dmarc_domain'},
                    'scope'  => $spf->{'dmarc_scope'},
                    'result' => $spf->{'dmarc_result'},
                };
                $dmarc->spf( $arc_spf );
            }
            else {
                # Nothing else matched, use the local entry anyway
                $dmarc->spf(
                    'domain' => $spf->{'dmarc_domain'},
                    'scope'  => $spf->{'dmarc_scope'},
                    'result' => $spf->{'dmarc_result'},
                );
            }

        }
        else {
            $dmarc->{'spf'} = [];
        }
    };
    if ( my $error = $@ ) {
        $self->handle_exception( $error );
        $dmarc->{'spf'} = [];
    }

    # Add the DKIM Results
    my $dkim_handler = $self->get_handler('DKIM');
    my @dkim_values;
    my $arc_values = $self->get_handler('ARC')->get_trusted_dkim_results();
    if ( $arc_values ) {
        foreach my $arc_value ( @$arc_values ) {
            push @dkim_values, $arc_value;
        }
    }
    $dmarc->{'dkim'} = \@dkim_values;
    # Add the local DKIM object is it exists
    if ( $dkim_handler->{'has_dkim'} ) {
        my $dkim_object = $self->get_object('dkim');
        if ( $dkim_object ) {
            $dmarc->dkim( $dkim_object );
        }
    }

    # Run the Validator
    my $dmarc_result = $dmarc->validate();
    return $dmarc_result;
}

sub _process_dmarc_for {
    my ( $self, $env_domain_from, $header_domain ) = @_;

    my $config = $self->handler_config();

    # Get a fresh DMARC object each time.
    $self->destroy_object('dmarc');
    my $dmarc = $self->get_dmarc_object();
    $dmarc->source_ip( $self->ip_address() );

    # Set the DMARC Envelope From Domain
    if ( $env_domain_from ne q{} ) {
        eval {
            $dmarc->envelope_from( $env_domain_from );
        };
        if ( my $error = $@ ) {
            $self->handle_exception( $error );
            if ( $error =~ /invalid envelope_from at / ) {
                $self->log_error( 'DMARC Invalid envelope from <' . $env_domain_from . '>' );
                $self->metric_count( 'dmarc_total', { 'result' => 'permerror' } );
                my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'dmarc' )->safe_set_value( 'permerror' );
                $header->add_child( Mail::AuthenticationResults::Header::Comment->new()->safe_set_value( 'envelope from invalid' ) );
                $header->add_child( Mail::AuthenticationResults::Header::SubEntry->new()->set_key( 'header.from' )->safe_set_value( $header_domain ) );
                $self->_add_dmarc_header( $header );
            }
            else {
                $self->log_error( 'DMARC Mail From Error for <' . $env_domain_from . '> ' . $error );
                $self->metric_count( 'dmarc_total', { 'result' => 'temperror' } );
                my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'dmarc' )->safe_set_value( 'temperror' );
                $header->add_child( Mail::AuthenticationResults::Header::Comment->new()->safe_set_value( 'envelope from failed' ) );
                $header->add_child( Mail::AuthenticationResults::Header::SubEntry->new()->set_key( 'header.from' )->safe_set_value( $header_domain ) );
                $self->_add_dmarc_header( $header );
            }
            return;
        }
    }

    # Add the Envelope To
    eval {
        $dmarc->envelope_to( lc $self->get_domain_from( $self->{'env_to'} ) );
    };
    if ( my $error = $@ ) {
        $self->handle_exception( $error );
        $self->log_error( 'DMARC Rcpt To Error ' . $error );
    }

    # Add the From Header
    eval { $dmarc->header_from( $header_domain ) };
    if ( my $error = $@ ) {
        $self->handle_exception( $error );
        $self->log_error( 'DMARC Header From Error ' . $error );
        $self->metric_count( 'dmarc_total', { 'result' => 'permerror' } );
        my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'dmarc' )->safe_set_value( 'permerror' );
        $header->add_child( Mail::AuthenticationResults::Header::Comment->new()->safe_set_value( 'from header invalid' ) );
        $header->add_child( Mail::AuthenticationResults::Header::SubEntry->new()->set_key( 'header.from' )->safe_set_value( $header_domain ) );
        $self->_add_dmarc_header( $header );
        return;
    }

    my $have_arc = ( $self->is_handler_loaded( 'ARC' ) );
    if ( $have_arc ) {
        # Does our ARC handler have the necessary methods?
        $have_arc = 0 unless $self->get_handler('ARC')->can( 'get_trusted_arc_authentication_results' );
    }
    $have_arc = 0 if ! $config->{ 'use_arc' };

    # Add the SPF Results Object
    eval {
        my $spf = $self->get_handler('SPF');
        if ( $spf ) {
            $dmarc->spf(
                'domain' => $spf->{'dmarc_domain'},
                'scope'  => $spf->{'dmarc_scope'},
                'result' => $spf->{'dmarc_result'},
            );
        }
        else {
            $dmarc->{'spf'} = [];
        }
    };
    if ( my $error = $@ ) {
        $self->handle_exception( $error );
        $self->log_error( 'DMARC SPF Error: ' . $error );
        $dmarc->{'spf'} = [];
    }

    # Add the DKIM Results
    my $dkim_handler = $self->get_handler('DKIM');
    if ( $dkim_handler->{'failmode'} ) {
        $dmarc->{'dkim'} = [];
    }
    elsif ( $dkim_handler->{'has_dkim'} ) {
        my $dkim_object = $self->get_object('dkim');
        if ( $dkim_object ) {
            $dmarc->dkim( $dkim_object );
        }
        else {
            $dmarc->{'dkim'} = [];
        }
    }
    else {
        $dmarc->{'dkim'} = [];
    }

    # Run the Validator
    my $dmarc_result = $dmarc->validate();

    # ToDo Set multiple dmarc_result objects here
    # this will become relevant when the BIMI handler
    # is production ready.
    $self->set_object('dmarc_result', $dmarc_result, 1 );

    my $dmarc_code   = $dmarc_result->result;
    $self->dbgout( 'DMARCCode', $dmarc_code, LOG_INFO );

    my $dmarc_disposition = eval { $dmarc_result->disposition() };
    if ( my $error = $@ ) {
        $self->handle_exception( $error );
        if ( $dmarc_code ne 'pass' ) {
            $self->log_error( 'DMARCPolicyError ' . $error );
        }
    }
    $self->dbgout( 'DMARCDisposition', $dmarc_disposition, LOG_INFO );
    my $dmarc_disposition_evaluated = $dmarc_disposition;

    my $dmarc_policy = eval{ $dmarc_result->published()->p(); };
    $self->handle_exception( $@ );
    # If we didn't get a result, set to none.
    $dmarc_policy = 'none' if ! $dmarc_policy;
    my $dmarc_sub_policy = eval{ $dmarc_result->published()->sp(); };
    $self->handle_exception( $@ );
    # If we didn't get a result, set to none.
    $dmarc_sub_policy = 'none' if ! $dmarc_sub_policy;
    $self->dbgout( 'DMARCPolicy', "$dmarc_policy $dmarc_sub_policy", LOG_INFO );

    my $policy_override;

    my $arc_aware_result = '';
    # Re-evaluate non passes taking ARC into account if possible.
    if ( $have_arc && $dmarc_code eq 'fail' ) {
        my $arc_result = $self->_process_arc_dmarc_for( $env_domain_from, $header_domain );
        $arc_aware_result = $arc_result->result;
    }

    # Reject mail and/or set policy override reasons
    if ( $dmarc_code eq 'fail' ) {
        # Policy override decisions.
        if ( $arc_aware_result eq 'pass' ) {
            $self->dbgout( 'DMARCReject', "Policy overridden using ARC Chain", LOG_INFO );
            $dmarc_result->disposition('none');
            $dmarc_disposition = 'none';
            $dmarc_result->reason( 'type' => 'trusted_forwarder', 'comment' => 'Policy overriden using trusted ARC chain' );
        }
        elsif ( $self->is_whitelisted() ) {
            $self->dbgout( 'DMARCReject', "Policy reject overridden by whitelist", LOG_INFO );
            $policy_override = 'trusted_forwarder';
            $dmarc_result->reason( 'type' => $policy_override, 'comment' => 'Policy ignored due to local white list' );
            $dmarc_result->disposition('none');
            $dmarc_disposition = 'none';
        }
        elsif ( $config->{'no_list_reject'} && $self->{'is_list'} ) {
            $self->dbgout( 'DMARCReject', "Policy reject overridden for list mail", LOG_INFO );
            $policy_override = 'mailing_list';
            $dmarc_result->reason( 'type' => $policy_override, 'comment' => 'Policy ignored due to local mailing list policy' );
            my $no_list_reject_disposition = $config->{ 'no_list_reject_disposition' } // 'none';
            $dmarc_result->disposition( $no_list_reject_disposition );
            $dmarc_disposition = $no_list_reject_disposition;
        }

        if ( $dmarc_disposition eq 'reject' ) {
            if ( $config->{'hard_reject'} ) {
                $self->reject_mail( '550 5.7.0 DMARC policy violation' );
                $self->dbgout( 'DMARCReject', "Policy reject", LOG_INFO );
            }
            else {
                $policy_override = 'local_policy';
                $dmarc_result->reason( 'type' => $policy_override, 'comment' => 'Reject ignored due to local policy' );
                my $no_reject_disposition = $config->{ 'no_reject_disposition' } // 'quarantine';
                $dmarc_result->disposition( $no_reject_disposition );
                $dmarc_disposition = $no_reject_disposition;
            }
        }
    }

    if ( $dmarc_disposition eq 'quarantine' ) {
        $self->quarantine_mail( 'Quarantined due to DMARC policy' );
    }

    # Add the AR Header
    my @comments;
    if ( !( $config->{'hide_none'} && $dmarc_code eq 'none' ) ) {
        my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'dmarc' )->safe_set_value( $dmarc_code );

        # What comments can we add?
        if ( $dmarc_policy ) {
            push @comments, $self->format_header_entry( 'p', $dmarc_policy );
            $header->add_child( Mail::AuthenticationResults::Header::SubEntry->new()->set_key( 'policy.published-domain-policy' )->safe_set_value( $dmarc_policy ) );
        }
        if ( $dmarc_sub_policy ) {
            push @comments, $self->format_header_entry( 'sp', $dmarc_sub_policy );
            $header->add_child( Mail::AuthenticationResults::Header::SubEntry->new()->set_key( 'policy.published-subdomain-policy' )->safe_set_value( $dmarc_sub_policy ) );
        }
        if ( $config->{'detect_list_id'} && $self->{'is_list'} ) {
            push @comments, 'has-list-id=yes';
        }
        if ( $dmarc_disposition ) {
            push @comments, $self->format_header_entry( 'd', $dmarc_disposition );
            $header->add_child( Mail::AuthenticationResults::Header::SubEntry->new()->set_key( 'policy.applied-disposition' )->safe_set_value( $dmarc_disposition ) );
        }
        if ( $dmarc_disposition_evaluated ) {
            push @comments, $self->format_header_entry( 'd.eval', $dmarc_disposition_evaluated );
            $header->add_child( Mail::AuthenticationResults::Header::SubEntry->new()->set_key( 'policy.evaluated-disposition' )->safe_set_value( $dmarc_disposition_evaluated ) );
        }
        if ( $policy_override ) {
            push @comments, $self->format_header_entry( 'override', $policy_override );
            $header->add_child( Mail::AuthenticationResults::Header::SubEntry->new()->set_key( 'policy.override-reason' )->safe_set_value( $policy_override ) );
        }
        if ( $arc_aware_result ) {
            push @comments, $self->format_header_entry( 'arc_aware_result', $arc_aware_result );
            $header->add_child( Mail::AuthenticationResults::Header::SubEntry->new()->set_key( 'policy.arc-aware-result' )->safe_set_value( $arc_aware_result ) );
        }

        if ( @comments ) {
            $header->add_child( Mail::AuthenticationResults::Header::Comment->new()->safe_set_value( join( ',', @comments ) ) );
        }


        $header->add_child( Mail::AuthenticationResults::Header::SubEntry->new()->set_key( 'header.from' )->safe_set_value( $header_domain ) );
        $self->_add_dmarc_header( $header );
    }

    # Write Metrics
    my $metric_data = {
        'result'           => $dmarc_code,
        'disposition'      => $dmarc_disposition,
        'policy'           => $dmarc_policy,
        'is_list'          => ( $self->{'is_list'}      ? '1' : '0' ),
        'is_whitelisted'   => ( $self->is_whitelisted() ? '1' : '0'),
        'arc_aware_result' => $arc_aware_result,
        'used_arc'         => ( $arc_aware_result ? '1' : '0' ),
    };
    $self->metric_count( 'dmarc_total', $metric_data );

    # Try as best we can to save a report, but don't stress if it fails.
    my $rua = eval { $dmarc_result->published()->rua(); };
    $self->handle_exception( $@ );
    if ($rua) {
        if ( ! $config->{'no_report'} ) {
            if ( ! $self->{'skip_report'} ) {
                eval {
                    $self->dbgout( 'DMARCReportTo', $rua, LOG_INFO );
                    $dmarc->save_aggregate();
                };
                if ( my $error = $@ ) {
                    $self->handle_exception( $error );
                    $self->log_error( 'DMARC Report Error ' . $error );
                }
            }
            else {
                $self->dbgout( 'DMARCReportTo (skipped flag)', $rua, LOG_INFO );
            }
        }
        else {
            $self->dbgout( 'DMARCReportTo (skipped)', $rua, LOG_INFO );
        }
    }

    return;
}

sub get_dmarc_object {
    my ( $self ) = @_;
    my $dmarc = $self->get_object('dmarc');
    if ( $dmarc ) {
        return $dmarc;
    }

    $dmarc = $self->new_dmarc_object();
    $self->set_object('dmarc', $dmarc,1 );
    return $dmarc;
}

sub new_dmarc_object {
    my ( $self ) = @_;

    my $config = $self->{'config'};
    my $dmarc;

    eval {
        $dmarc = Mail::DMARC::PurePerl->new();
        if ( exists ( $config->{ 'config_file' } ) ) {
            $self->log_error( 'DMARC config file does not exist' ) if ! exists $config->{ 'config_file' };
            $dmarc->config( $config->{ 'config_file' } );
        }
        if ( $dmarc->can('set_resolver') ) {
            my $resolver = $self->get_object('resolver');
            $dmarc->set_resolver($resolver);
        }
        if ( $config->{'debug'} && $config->{'logtoerr'} ) {
            $dmarc->verbose(1);
        }
        $self->set_object('dmarc', $dmarc,1 );
    };
    if ( my $error = $@ ) {
        $self->handle_exception( $error );
        $self->log_error( 'DMARC IP Error ' . $error );
        my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'dmarc' )->safe_set_value( 'permerror' );
        $self->add_auth_header( $header );
        $self->metric_count( 'dmarc_total', { 'result' => 'permerror' } );
        $self->{'failmode'} = 1;
    }

    return $dmarc;
}

sub helo_callback {
    my ( $self, $helo_host ) = @_;
    $self->{'helo_name'} = $helo_host;
    return;
}

sub envfrom_requires {
    my ($self) = @_;
    my @requires = qw{ SPF };
    return \@requires;
}

sub envfrom_callback {
    my ( $self, $env_from ) = @_;
    return if ( $self->is_local_ip_address() );
    return if ( $self->is_trusted_ip_address() );
    return if ( $self->is_authenticated() );
    delete $self->{'from_header'};
    $self->{'is_list'}      = 0;
    $self->{'skip_report'}  = 0;
    $self->{'failmode'}     = 0;

    $env_from = q{} if $env_from eq '<>';

    if ( ! $self->is_handler_loaded( 'SPF' ) ) {
        $self->log_error( 'DMARC Config Error: SPF is missing ');
        $self->metric_count( 'dmarc_total', { 'result' => 'error' } );
        $self->{'failmode'} = 1;
        return;
    }
    if ( ! $self->is_handler_loaded( 'DKIM' ) ) {
        $self->log_error( 'DMARC Config Error: DKIM is missing ');
        $self->metric_count( 'dmarc_total', { 'result' => 'error' } );
        $self->{'failmode'} = 1;
        return;
    }

    if ( $env_from ) {
        $self->{ 'env_from' } = $env_from;
    }
    else {
        $self->{ 'env_from' } = q{};
    }

    $self->{ 'from_headers' } = [];

    return;
}

sub check_skip_address {
    my ( $self, $env_to ) = @_;
    $env_to = lc $self->get_address_from( $env_to );
    my $config = $self->handler_config();
    return 0 if not exists( $config->{'report_skip_to'} );
    foreach my $address ( @{ $config->{'report_skip_to'} } ) {
        if ( lc $address eq lc $env_to ) {
            $self->dbgout( 'DMARCReportSkip', 'Skip address detected: ' . $env_to, LOG_INFO );
            $self->{'skip_report'} = 1;
        }
    }
    return;
}

sub envrcpt_callback {
    my ( $self, $env_to ) = @_;
    return if ( $self->is_local_ip_address() );
    return if ( $self->is_trusted_ip_address() );
    return if ( $self->is_authenticated() );

    $self->{ 'env_to' } = $env_to;
    $self->check_skip_address( $env_to );

    return;
}

sub header_callback {
    my ( $self, $header, $value ) = @_;
    return if ( $self->is_local_ip_address() );
    return if ( $self->is_trusted_ip_address() );
    return if ( $self->is_authenticated() );
    return if ( $self->{'failmode'} );

    if ( lc $header eq 'list-id' ) {
        $self->dbgout( 'DMARCListId', 'List ID detected: ' . $value, LOG_INFO );
        $self->{'is_list'} = 1;
    }
    if ( lc $header eq 'list-post' ) {
        $self->dbgout( 'DMARCListId', 'List Post detected: ' . $value, LOG_INFO );
        $self->{'is_list'} = 1;
    }

    if ( lc $header eq 'from' ) {
        if ( exists $self->{'from_header'} ) {
            $self->dbgout( 'DMARCFail', 'Multiple RFC5322 from fields', LOG_INFO );
        }
        $self->{'from_header'} = $value;
        push @{ $self->{ 'from_headers' } }, $value;
    }
    return;
}

sub eom_requires {
    my ($self) = @_;
    my @requires = qw{ DKIM };

    if ( $self->is_handler_loaded( 'ARC' ) ) {
        push @requires, 'ARC';
    }

    return \@requires;
}

sub eom_callback {
    my ($self) = @_;
    my $config = $self->handler_config();

    return if ( $self->is_local_ip_address() );
    return if ( $self->is_trusted_ip_address() );
    return if ( $self->is_authenticated() );
    return if ( $self->{'failmode'} );

    my $env_from = $self->{ 'env_from' };
    my $env_domains_from = $self->get_domains_from($env_from);
    $env_domains_from = [''] if ! @$env_domains_from;

    my $from_headers = $self->{ 'from_headers' };

    # Build a list of all from header domains used
    my @header_domains;
    foreach my $from_header ( @$from_headers ) {
        my $from_header_header_domains = $self->get_domains_from( $from_header );
        foreach my $header_domain ( @$from_header_header_domains ) {
            push @header_domains, $header_domain;
        }
    }

    $self->{ 'dmarc_ar_headers' } = [];
    # There will usually be only one, however this could be a source route
    # so we consider multiples just incase
    foreach my $env_domain_from ( uniq sort @$env_domains_from ) {
        foreach my $header_domain ( uniq sort @header_domains ) {
            eval {
                $self->_process_dmarc_for( $env_domain_from, $header_domain );
            };
            if ( my $error = $@ ) {
                $self->handle_exception( $error );
                if ( $error =~ /invalid header_from at / ) {
                    $self->log_error( 'DMARC Error invalid header_from <' . $self->{'from_header'} . '>' );
                    my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'dmarc' )->safe_set_value( 'permerror' );
                    $header->add_child( Mail::AuthenticationResults::Header::SubEntry->new()->set_key( 'header.from' )->safe_set_value( $header_domain ) );
                    $self->_add_dmarc_header( $header );
                }
                else {
                    $self->log_error( 'DMARC Error ' . $error );
                    my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'dmarc' )->safe_set_value( 'temperror' );
                    $header->add_child( Mail::AuthenticationResults::Header::SubEntry->new()->set_key( 'header.from' )->safe_set_value( $header_domain ) );
                    $self->_add_dmarc_header( $header );
                }
            }
            $self->check_timeout();
        }
    }

    if ( @{ $self->{ 'dmarc_ar_headers' } } ) {
        foreach my $dmarc_header ( @{ $self->_get_unique_dmarc_headers() } ) {
            $self->add_auth_header( $dmarc_header );
        }
    }
    else {
        # We got no headers at all? That's bogus!
        my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'dmarc' )->safe_set_value( 'permerror' );
        $self->add_auth_header( $header );
    }

    delete $self->{ 'dmarc_ar_headers' };

    return;
}

sub can_sort_header {
    my ( $self, $header ) = @_;
    return 1 if $header eq 'dmarc';
    return 0;
}


sub handler_header_sort {
    my ( $self, $pa, $pb ) = @_;

    # ToDo, do this without stringify
    my ( $result_a, $policy_a ) = $pa->as_string() =~ /^dmarc=([a-z]+) .*policy\.applied\-disposition=([a-z]+)/;
    my ( $result_b, $policy_b ) = $pb->as_string() =~ /^dmarc=([a-z]+) .*policy\.applied\-disposition=([a-z]+)/;

    # Fail then None then Pass
    if ( $result_a ne $result_b ) {
        return -1 if $result_a eq 'fail';
        return  1 if $result_b eq 'fail';
        return -1 if $result_a eq 'none';
        return  1 if $result_b eq 'none';
    }

    # Reject then Quarantine then None
    if ( $policy_a ne $policy_b ) {
        return -1 if $policy_a eq 'reject';
        return  1 if $policy_b eq 'reject';
        return -1 if $policy_a eq 'quarantine';
        return  1 if $policy_b eq 'quarantine';
    }

    return $pa cmp $pb;
}

sub _get_unique_dmarc_headers {
    my ( $self ) = @_;

    my $unique_strings = {};
    my @unique_headers;

    # Returns unique headers based on as_string for each header
    foreach my $header ( @{ $self->{ 'dmarc_ar_headers' } } ) {
        my $as_string = $header->as_string();
        next if exists $unique_strings->{ $as_string };
        $unique_strings->{ $as_string } = 1;
        push @unique_headers, $header;
    }

    return \@unique_headers;
}

sub _add_dmarc_header {
    my ( $self, $header ) = @_;
    push @{ $self->{ 'dmarc_ar_headers' } }, $header;
    return;
}

sub close_callback {
    my ( $self ) = @_;
    delete $self->{'helo_name'};
    delete $self->{'env_from'};
    delete $self->{'env_to'};
    delete $self->{'failmode'};
    delete $self->{'skip_report'};
    delete $self->{'is_list'};
    delete $self->{'from_header'};
    delete $self->{'from_heades'};
    $self->destroy_object('dmarc');
    $self->destroy_object('dmarc_result');
    return;
}

1;

__END__

=head1 DESCRIPTION

Module implementing the DMARC standard checks.

This handler requires the SPF and DKIM handlers to be installed and active.

=head1 CONFIGURATION

        "DMARC" : {                                        | Config for the DMARC Module
                                                           | Requires DKIM and SPF
            "hard_reject"           : 0,                   | Reject mail which fails with a reject policy
            "no_reject_disposition" : "quarantine",        | What to report when hard_reject is 0
            "no_list_reject"        : 0,                   | Do not reject mail detected as mailing list
            "no_list_reject_disposition" : "none",         | Disposition to use for mail detected as mailing list (defaults none)
            "whitelisted"           : [                    | A list of ip addresses or CIDR ranges, or dkim domains
                "10.20.30.40",                             | for which we do not want to hard reject mail on fail p=reject
                "dkim:bad.forwarder.com",                  | (valid) DKIM signing domains can also be whitelisted by
                "20.30.40.0/24"                            | having an entry such as "dkim:domain.com"
            ],
            "use_arc"             : 1,                     | Use trusted ARC results if available
            "hide_none"           : 0,                     | Hide auth line if the result is 'none'
            "detect_list_id"      : "1",                   | Detect a list ID and modify the DMARC authentication header
                                                           | to note this, useful when making rules for junking email
                                                           | as mailing lists frequently cause false DMARC failures.
            "report_skip_to"     : [                       | Do not send DMARC reports for emails to these addresses.
                "dmarc@yourdomain.com",                    | This can be used to avoid report loops for email sent to
                "dmarc@example.com"                        | your report from addresses.
            ],
            "no_report"          : "1",                    | If set then we will not attempt to store DMARC reports.
            "config_file"        : "/etc/mail-dmarc.ini"   | Optional path to dmarc config file
        },

