package Mail::Milter::Authentication::Handler::DMARC;
use strict;
use warnings;
use base 'Mail::Milter::Authentication::Handler';
use version; our $VERSION = version->declare('v1.1.0');

use Data::Dumper;
use English qw{ -no_match_vars };
use Net::IP;
use Sys::Syslog qw{:standard :macros};

use Mail::DMARC::PurePerl;

my $PSL_CHECKED_TIME;

sub default_config {
    return {
        'hide_none'           => 0,
        'hard_reject'         => 0,
        'no_list_reject'      => 1,
        'whitelisted_ip_list' => [],
        'detect_list_id'      => 1,
        'report_skip_to'      => [ 'my_report_from_address@example.com' ],
        'no_report'           => 0,
    };
}

sub is_whitelisted_ip_address {
    my ( $self ) = @_;
    my $config = $self->handler_config();
    return 0 if not exists( $config->{'whitelisted_ip_list'} );
    my $top_handler = $self->get_top_handler();
    my $ip_obj = $top_handler->{'ip_object'};
    my $whitelisted = 0;
    foreach my $whitelisted_ip ( @{ $config->{'whitelisted_ip_list'} } ) {
        my $whitelisted_obj = Net::IP->new($whitelisted_ip);
        my $is_overlap = $ip_obj->overlaps($whitelisted_obj) || 0;
        if (
               $is_overlap == $IP_A_IN_B_OVERLAP
            || $is_overlap == $IP_B_IN_A_OVERLAP     # Should never happen
            || $is_overlap == $IP_PARTIAL_OVERLAP    # Should never happen
            || $is_overlap == $IP_IDENTICAL
          )
        {
            $whitelisted = 1;
        }
    }
    return $whitelisted;
}

sub pre_loop_setup {
    my ( $self ) = @_;
    $PSL_CHECKED_TIME = time;
    my $dmarc = Mail::DMARC::PurePerl->new();
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

sub get_dmarc_object {
    my ( $self, $env_from ) = @_;
    my $dmarc = $self->get_object('dmarc');
    if ( $dmarc ) {
        return $dmarc;
    }

    my $config = $self->{'config'};

    eval {
        $dmarc = Mail::DMARC::PurePerl->new();
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
        $self->add_auth_header('dmarc=temperror');
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
    $self->{'failmode'}     = 0;
    $self->{'is_list'}      = 0;
    $self->{'skip_report'}  = 0;
    $self->{'failmode'}     = 0;
    $self->destroy_object('dmarc');

    $env_from = q{} if $env_from eq '<>';

    if ( ! $self->is_handler_loaded( 'SPF' ) ) {
        $self->log_error( 'DMARC Config Error: SPF is missing ');
        $self->{'failmode'} = 1;
        return;
    }
    if ( ! $self->is_handler_loaded( 'DKIM' ) ) {
        $self->log_error( 'DMARC Config Error: DKIM is missing ');
        $self->{'failmode'} = 1;
        return;
    }

    my $dmarc = $self->get_dmarc_object();

    my $domain_from;
    if ( $env_from ) {
        $domain_from = $self->get_domain_from($env_from);
        eval {
            $dmarc->envelope_from($domain_from);
        };
        if ( my $error = $@ ) {
            if ( $error =~ /invalid envelope_from at / ) {
                $self->log_error( 'DMARC Invalid envelope from <' . $domain_from . '>' );
                $self->add_auth_header( 'dmarc=permerror' );
            }
            else {
                $self->log_error( 'DMARC Mail From Error for <' . $domain_from . '> ' . $error );
                $self->add_auth_header('dmarc=temperror');
            }
            $self->{'failmode'} = 1;
            return;
        }
    }

    my $spf_handler = $self->get_handler('SPF');
    if ( $spf_handler->{'failmode'} ) {
        $self->log_error('SPF is in failmode, Skipping DMARC');
        $self->add_auth_header('dmarc=temperror');
        $self->{'failmode'} = 1;
        return;
    }

    eval {
        my $spf = $self->get_handler('SPF');
        $dmarc->spf(
            'domain' => $spf->{'dmarc_domain'},
            'scope'  => $spf->{'dmarc_scope'},
            'result' => $spf->{'dmarc_result'},
        );
    };
    if ( my $error = $@ ) {
        $self->log_error( 'DMARC SPF Error: ' . $error );
        $self->add_auth_header('dmarc=temperror');
    }

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
    return if ( $self->{'failmode'} );
    $self->check_skip_address( $env_to );
    my $dmarc       = $self->get_dmarc_object();
    return if ( $self->{'failmode'} );
    my $envelope_to = $self->get_domain_from($env_to);
    eval { $dmarc->envelope_to($envelope_to) };

    if ( my $error = $@ ) {
        $self->log_error( 'DMARC Rcpt To Error ' . $error );
        $self->add_auth_header('dmarc=temperror');
        $self->{'failmode'} = 1;
        return;
    }

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
    if ( $header eq 'From' ) {
        if ( exists $self->{'from_header'} ) {
            $self->dbgout( 'DMARCFail', 'Multiple RFC5322 from fields', LOG_INFO );
            # ToDo handle this by eveluating DMARC for each field in turn as
            # suggested in the DMARC spec part 5.6.1
            # Currently this does not give reporting feedback to the author domain, this should be changed.
            $self->add_auth_header( 'dmarc=fail (multiple RFC5322 from fields in message)' );
            $self->{'failmode'} = 1;
            return;
        }
        $self->{'from_header'} = $value;
        my $dmarc = $self->get_dmarc_object();
        return if ( $self->{'failmode'} );
        my $header_domain = $self->get_domain_from( $value );
        eval { $dmarc->header_from( $header_domain ) };
        if ( my $error = $@ ) {
            $self->log_error( 'DMARC Header From Error ' . $error );
            $self->add_auth_header('dmarc=temperror');
            $self->{'failmode'} = 1;
            return;
        }
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
    eval {
        my $dmarc = $self->get_dmarc_object();
        return if ( $self->{'failmode'} );
        my $dkim_handler = $self->get_handler('DKIM');
        if ( $dkim_handler->{'failmode'} ) {
            $self->log_error('DKIM is in failmode, Skipping DMARC');
            $self->add_auth_header('dmarc=temperror');
            $self->{'failmode'} = 1;
            return;
        }
        if ( $dkim_handler->{'has_dkim'} ) {
            $dmarc->dkim( $self->get_object('dkim') );
        }
        else {
            # Workaround reporting issue
            $dmarc->{'dkim'} = [];
#           $dmarc->dkim( $empty_dkim );
        }
        my $dmarc_result = $dmarc->validate();
        my $dmarc_code   = $dmarc_result->result;
        $self->dbgout( 'DMARCCode', $dmarc_code, LOG_INFO );

        if ( !( $config->{'hide_none'} && $dmarc_code eq 'none' ) ) {
            my $dmarc_policy;
            if ( $dmarc_code ne 'pass' ) {
                $dmarc_policy = eval { $dmarc_result->disposition() };
                if ( my $error = $@ ) {
                    $self->log_error( 'DMARCPolicyError ' . $error );
                }
                $self->dbgout( 'DMARCPolicy', $dmarc_policy, LOG_INFO );
                if ( $dmarc_code eq 'fail' && $dmarc_policy eq 'reject' ) {
                    if ( $config->{'hard_reject'} ) {
                        if ( $config->{'no_list_reject'} && $self->{'is_list'} ) {
                            $self->dbgout( 'DMARCReject', "Policy reject overridden for list mail", LOG_INFO );
                        }
                        elsif ( $self->is_whitelisted_ip_address() ) {
                            $self->dbgout( 'DMARCReject', "Policy reject overridden for whitelisted ip address", LOG_INFO );
                        }
                        else {
                            $self->reject_mail( '550 5.7.0 DMARC policy violation' );
                            $self->dbgout( 'DMARCReject', "Policy reject", LOG_INFO );
                        }
                    }
                }

            }
            my $dmarc_header = $self->format_header_entry( 'dmarc', $dmarc_code );
            my $is_list_entry = q{};
            if ( $config->{'detect_list_id'} && $self->{'is_list'} ) {
                $is_list_entry = ';has-list-id=yes';
            }
            if ($dmarc_policy) {
                $dmarc_header .= ' ('
                  . $self->format_header_comment(
                    $self->format_header_entry( 'p', $dmarc_policy ) )
                  . $is_list_entry
                . ')';
            }
            $dmarc_header .= ' '
              . $self->format_header_entry( 'header.from',
                $self->get_domain_from( $self->{'from_header'} ) );
            $self->add_auth_header($dmarc_header);
        }

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
    };
    if ( my $error = $@ ) {
        if ( $error =~ /invalid header_from at / ) {
            $self->log_error( 'DMARC Error invalid header_from <' . $self->{'from_header'} . '>' );
            $self->add_auth_header('dmarc=permerror');
        }
        else {
            $self->log_error( 'DMARC Error ' . $error );
            $self->add_auth_header('dmarc=temperror');
        }
        return;
    }
    return;
}

sub close_callback {
    my ( $self ) = @_;
    delete $self->{'helo_name'};
    delete $self->{'failmode'};
    delete $self->{'skip_report'};
    delete $self->{'is_list'};
    delete $self->{'from_header'};
    $self->destroy_object('dmarc');
    return;
}

1;

__END__

=head1 NAME

  Authentication Milter - DMARC Module

=head1 DESCRIPTION

Module implementing the DMARC standard checks.

This handler requires the SPF and DKIM handlers to be installed and active.

=head1 CONFIGURATION

        "DMARC" : {                                     | Config for the DMARC Module
                                                        | Requires DKIM and SPF
            "hard_reject"         : 0,                  | Reject mail which fails with a reject policy
            "no_list_reject"      : 0,                  | Do not reject mail detected as mailing list
            "whitelisted_ip_list" : [                   | A list of ip addresses or CIDR ranges for which
                "1.2.3.4",                              | we do not want to hard reject mail on fail p=reject
                "10.20.30.40"
            ],
            "hide_none"           : 0,                  | Hide auth line if the result is 'none'
            "detect_list_id"      : "1",                | Detect a list ID and modify the DMARC authentication header
                                                        | to note this, useful when making rules for junking email
                                                        | as mailing lists frequently cause false DMARC failures.
            "report_skip_to"     : [                    | Do not send DMARC reports for emails to these addresses.
                "dmarc@yourdomain.com",                 | This can be used to avoid report loops for email sent to
                "dmarc@example.com"                     | your report from addresses.
            ],
            "no_report"          : "1"                  | If set then we will not attempt to store DMARC reports.
        },

=head1 SYNOPSIS

=head1 AUTHORS

Marc Bradshaw E<lt>marc@marcbradshaw.netE<gt>

=head1 COPYRIGHT

Copyright 2015

This library is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.


