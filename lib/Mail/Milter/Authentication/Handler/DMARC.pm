package Mail::Milter::Authentication::Handler::DMARC;
use strict;
use warnings;
use base 'Mail::Milter::Authentication::Handler';
our $VERSION = 0.6;

use Data::Dumper;
use English qw{ -no_match_vars };
use Sys::Syslog qw{:standard :macros};

use Mail::DMARC::PurePerl;

sub get_dmarc_object {
    my ( $self, $env_from ) = @_;
    $self->{'failmode'} = 0;
    $self->{'is_list'}  = 0;
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
        $self->set_object('dmarc',$dmarc);
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
    delete $self->{'is_list'};
    $self->{'failmode'} = 0;
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

    my $domain_from;
    if ( !$env_from ) {
        $domain_from = lc $self->{'helo_name'};
    }
    else {
        $domain_from = $self->get_domain_from($env_from);
    }

    my $dmarc = $self->get_dmarc_object();
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

sub envrcpt_callback {
    my ( $self, $env_to ) = @_;
    return if ( $self->is_local_ip_address() );
    return if ( $self->is_trusted_ip_address() );
    return if ( $self->is_authenticated() );
    return if ( $self->{'failmode'} );
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
        $self->dbgout( 'DMARCListId', 'List detected: ' . $value, LOG_INFO );
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
        eval { $dmarc->header_from_raw( $header . ': ' . $value ) };
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
        $dmarc->dkim( $self->get_object('dkim') );
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
            eval {
                $self->dbgout( 'DMARCReportTo', $rua, LOG_INFO );
                $dmarc->save_aggregate();
            };
            if ( my $error = $@ ) {
                $self->log_error( 'DMARC Report Error ' . $error );
            }
        }
    };
    if ( my $error = $@ ) {
        if ( $error =~ / on an undefined value at /
                or $error =~ / as a HASH ref while /
                or $error =~ / as an ARRAY reference at /
                or $error =~ / as a subroutine ref while /
                or $error =~ / on unblessed reference at /
                or $error =~ /^Cannot convert a reference to /
                or $error =~ /^Not a HASH reference at /
                or $error =~ /^Not a CODE reference at /
                or $error =~ /^Cannot copy to HASH in sassign at /
                or $error =~ /^Cannot copy to ARRAY in sassign at /
                or $error =~ /^Undefined subroutine /
                or $error =~ /^invalid protocol/
                or $error =~ / locate object method /
                or $error =~ /^panic: /
        ) {
            $self->log_error( "PANIC DETECTED: in DMARC method: $error" );
            $self->exit_on_close();
            $self->tempfail_on_error();
            $self->add_auth_header('dmarc=temperror (internal error)');

            # THIS SHOULD NO LONGER BE AN ISSUE

# BEGIN TEMPORARY CODE CORE DUMP
#            open my $core, '>>', "/tmp/authentication_milter.core.$PID";
#            print $core "$error\n\n";
#            print $core Dumper( $self->{'thischild'} );
#            print $core "\n\n";
#            close $core;
# END TEMPORARY CODE CORE DUMP

            $self->destroy_object('dmarc');
            return;
        }
        elsif ( $error =~ /invalid header_from at / ) {
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
    delete $self->{'is_list'};
    delete $self->{'from_header'};
    $self->destroy_object('dmarc');
    return;
}

1;
