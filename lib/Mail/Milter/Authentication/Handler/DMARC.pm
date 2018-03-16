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
        'hard_reject'    => 0,
        'no_list_reject' => 1,
        'whitelisted'    => [],
        'detect_list_id' => 1,
        'report_skip_to' => [ 'my_report_from_address@example.com' ],
        'no_report'      => 0,
        'config_file'    => '/etc/mail-dmarc.ini',
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
        if ( $entry =~ /^dkim:/ ) {
            my ( $dummy, $dkim_domain ) = split( /:/, $entry, 2 );
            my $dkim_handler = $self->get_handler('DKIM');
            if ( exists( $dkim_handler->{'valid_domains'}->{ lc $dkim_domain } ) ) {
                $self->dbgout( 'DMARCReject', "Whitelist hit " . $entry, LOG_INFO );
                $whitelisted = 1;
            }
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

sub _process_dmarc_for {
    my ( $self, $env_domain_from, $header_domain ) = @_;

    my $config = $self->handler_config();

    # Get a fresh DMARC object each time.
    $self->destroy_object('dmarc');
    my $dmarc = $self->get_dmarc_object();

    # Set the DMARC Envelope From Domain
    if ( $env_domain_from ne q{} ) {
        eval {
            $dmarc->envelope_from( $env_domain_from );
        };
        if ( my $error = $@ ) {
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
        $self->log_error( 'DMARC Rcpt To Error ' . $error );
    }

    # Add the From Header
    eval { $dmarc->header_from( $header_domain ) };
    if ( my $error = $@ ) {
        $self->log_error( 'DMARC Header From Error ' . $error );
        $self->metric_count( 'dmarc_total', { 'result' => 'permerror' } );
        my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'dmarc' )->safe_set_value( 'permerror' );
        $header->add_child( Mail::AuthenticationResults::Header::Comment->new()->safe_set_value( 'from header invalid' ) );
        $header->add_child( Mail::AuthenticationResults::Header::SubEntry->new()->set_key( 'header.from' )->safe_set_value( $header_domain ) );
        $self->_add_dmarc_header( $header );
        return;
    }

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
        if ( $dmarc_code ne 'pass' ) {
            $self->log_error( 'DMARCPolicyError ' . $error );
        }
    }
    $self->dbgout( 'DMARCDisposition', $dmarc_disposition, LOG_INFO );

    my $dmarc_policy = eval{ $dmarc_result->published()->p(); };
    # If we didn't get a result, set to none.
    $dmarc_policy = 'none' if ! $dmarc_policy;
    $self->dbgout( 'DMARCPolicy', $dmarc_policy, LOG_INFO );

    my $policy_override;

    # Reject mail and/or set policy override reasons
    if ( $dmarc_code eq 'fail' && $dmarc_policy eq 'reject' ) {
        if ( $config->{'hard_reject'} ) {
            if ( $config->{'no_list_reject'} && $self->{'is_list'} ) {
                $self->dbgout( 'DMARCReject', "Policy reject overridden for list mail", LOG_INFO );
                $policy_override = 'mailing_list';
                $dmarc_result->reason( 'type' => $policy_override, 'comment' => 'Reject ignored due to local mailing list policy' );
                #$dmarc_result->disposition('none');
                #$dmarc_disposition = 'none';
            }
            elsif ( $self->is_whitelisted() ) {
                $self->dbgout( 'DMARCReject', "Policy reject overridden by whitelist", LOG_INFO );
                $policy_override = 'trusted_forwarder';
                $dmarc_result->reason( 'type' => $policy_override, 'comment' => 'Reject ignored due to local white list' );
                #$dmarc_result->disposition('none');
                #$dmarc_disposition = 'none';
            }
            else {
                $self->reject_mail( '550 5.7.0 DMARC policy violation' );
                $self->dbgout( 'DMARCReject', "Policy reject", LOG_INFO );
            }
        }
        else {
            $policy_override = 'local_policy';
            $dmarc_result->reason( 'type' => $policy_override, 'comment' => 'Reject ignored due to local policy' );
            #$dmarc_result->disposition('none');
            #$dmarc_disposition = 'none';
        }
    }

    # Add the AR Header
    if ( !( $config->{'hide_none'} && $dmarc_code eq 'none' ) ) {
        my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'dmarc' )->safe_set_value( $dmarc_code );

        # What comments can we add?
        my @comments;
        if ( $dmarc_policy ) {
            push @comments, $self->format_header_entry( 'p', $dmarc_policy );
        }
        if ( $config->{'detect_list_id'} && $self->{'is_list'} ) {
            push @comments, 'has-list-id=yes';
        }
        if ( $dmarc_disposition ) {
            push @comments, $self->format_header_entry( 'd', $dmarc_disposition );
        }
        #if ( $policy_override ) {
        #    push @comments, $self->format_header_entry( 'override', $policy_override );
        #}

        if ( @comments ) {
            $header->add_child( Mail::AuthenticationResults::Header::Comment->new()->safe_set_value( join( ',', @comments ) ) );
        }

        $header->add_child( Mail::AuthenticationResults::Header::SubEntry->new()->set_key( 'header.from' )->safe_set_value( $header_domain ) );
        $self->_add_dmarc_header( $header );
    }

    # Write Metrics
    my $metric_data = {
        'result'         => $dmarc_code,
        'disposition'    => $dmarc_disposition,
        'policy'         => $dmarc_policy,
        'is_list'        => ( $self->{'is_list'}      ? '1' : '0' ),
        'is_whitelisted' => ( $self->is_whitelisted() ? '1' : '0'),
    };
    $self->metric_count( 'dmarc_total', $metric_data );

    # Try as best we can to save a report, but don't stress if it fails.
    my $rua = eval { $dmarc_result->published()->rua(); };
    if ($rua) {
        if ( ! $config->{'no_report'} ) {
            if ( ! $self->{'skip_report'} ) {
                eval {
                    $self->dbgout( 'DMARCReportTo', $rua, LOG_INFO );
                    $dmarc->save_aggregate();
                };
                if ( my $error = $@ ) {
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

    my $config = $self->{'config'};

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
        $dmarc->source_ip( $self->ip_address() );
        $self->set_object('dmarc', $dmarc,1 );
    };
    if ( my $error = $@ ) {
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
    $env_domains_from = [''] if ! $env_domains_from;

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
    my ( $result_a, $policy_a ) = $pa->as_string() =~ /^dmarc=([a-z]+) \(p=([a-z]+)/;
    my ( $result_b, $policy_b ) = $pb->as_string() =~ /^dmarc=([a-z]+) \(p=([a-z]+)/;

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

        "DMARC" : {                                      | Config for the DMARC Module
                                                         | Requires DKIM and SPF
            "hard_reject"         : 0,                   | Reject mail which fails with a reject policy
            "no_list_reject"      : 0,                   | Do not reject mail detected as mailing list
            "whitelisted"         : [                    | A list of ip addresses or CIDR ranges, or dkim domains
                "10.20.30.40",                           | for which we do not want to hard reject mail on fail p=reject
                "dkim:bad.forwarder.com",                | (valid) DKIM signing domains can also be whitelisted by
                "20.30.40.0/24"                          | having an entry such as "dkim:domain.com"
            ],
            "hide_none"           : 0,                   | Hide auth line if the result is 'none'
            "detect_list_id"      : "1",                 | Detect a list ID and modify the DMARC authentication header
                                                         | to note this, useful when making rules for junking email
                                                         | as mailing lists frequently cause false DMARC failures.
            "report_skip_to"     : [                     | Do not send DMARC reports for emails to these addresses.
                "dmarc@yourdomain.com",                  | This can be used to avoid report loops for email sent to
                "dmarc@example.com"                      | your report from addresses.
            ],
            "no_report"          : "1",                  | If set then we will not attempt to store DMARC reports.
            "config_file"        : "/etc/mail-dmarc.ini" | Optional path to dmarc config file
        },

