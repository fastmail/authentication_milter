package Mail::Milter::Authentication::Handler::DMARC;

use strict;
use warnings;

our $VERSION = 0.5;

use base 'Mail::Milter::Authentication::Handler::Generic';

use Sys::Syslog qw{:standard :macros};

use Mail::DMARC::PurePerl;

sub callbacks {
    return {
        'connect' => undef,
        'helo'    => undef,
        'envfrom' => 40,
        'envrcpt' => 20,
        'header'  => 40,
        'eoh'     => undef,
        'body'    => undef,
        'eom'     => 20,
        'abort'   => undef,
        'close'   => undef,
    };
}

sub envfrom_callback {
    my ( $self, $env_from ) = @_;
    return if ( $self->is_local_ip_address() );
    return if ( $self->is_trusted_ip_address() );
    return if ( $self->is_authenticated() );
    delete $self->{'from_header'};
    $self->{'failmode'} = 0;

    $env_from = q{} if $env_from eq '<>';

    my $domain_from;
    if ( !$env_from ) {
        $domain_from = $self->helo_name();
    }
    else {
        $domain_from = $self->get_domain_from($env_from);
    }

    my $dmarc;
    eval {
        $dmarc = Mail::DMARC::PurePerl->new();
        $dmarc->verbose(1);
        $dmarc->source_ip( $self->ip_address() );
        $self->set_object('dmarc',$dmarc);
    };
    if ( my $error = $@ ) {
        $self->log_error( 'DMARC IP Error ' . $error );
        $self->add_auth_header('dmarc=temperror');
        $self->{'failmode'} = 1;
        return;
    }
    $self->{'is_list'} = 0;
    eval {
        $dmarc->envelope_from($domain_from);
    };
    if ( my $error = $@ ) {
        if ( $error =~ /invalid envelope_from at / ) {
            $self->log_error( 'DMARC Invalid envelope from <' . $domain_from . '>' );
            $self->log_error( 'DMARC Debug Helo: ' . $self->helo_name() );
            $self->log_error( 'DMARC Debug Envfrom: ' . $env_from );
            $self->add_auth_header( 'dmarc=permerror' );
        }
        else {
            $self->log_error( 'DMARC Mail From Error for <' . $domain_from . '> ' . $error );
            $self->log_error( 'DMARC Debug Helo: ' . $self->helo_name() );
            $self->log_error( 'DMARC Debug Envfrom: ' . $env_from );
            $self->add_auth_header('dmarc=temperror');
        }
        $self->{'failmode'} = 1;
        return;
    }
}

sub envrcpt_callback {
    my ( $self, $env_to ) = @_;
    return if ( $self->is_local_ip_address() );
    return if ( $self->is_trusted_ip_address() );
    return if ( $self->is_authenticated() );
    return if ( $self->{'failmode'} );
    my $dmarc       = $self->get_object('dmarc');
    my $envelope_to = $self->get_domain_from($env_to);
    eval { $dmarc->envelope_to($envelope_to) };

    if ( my $error = $@ ) {
        $self->log_error( 'DMARC Rcpt To Error ' . $error );
        $self->add_auth_header('dmarc=temperror');
        $self->{'failmode'} = 1;
        return;
    }
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
        my $dmarc = $self->get_object('dmarc');
        eval { $dmarc->header_from_raw( $header . ': ' . $value ) };
        if ( my $error = $@ ) {
            $self->log_error( 'DMARC Header From Error ' . $error );
            $self->add_auth_header('dmarc=temperror');
            $self->{'failmode'} = 1;
            return;
        }
    }
}

sub eom_callback {
    my ($self) = @_;
    my $CONFIG = $self->module_config();
    return if ( $self->is_local_ip_address() );
    return if ( $self->is_trusted_ip_address() );
    return if ( $self->is_authenticated() );
    return if ( $self->{'failmode'} );
    eval {
        my $dmarc        = $self->get_object('dmarc');
        my $dkim_handler = $self->get_handler('DKIM');
        if ( $dkim_handler->{'failmode'} ) {
            $self->log_error('DKIM is in failmode, Skipping DMARC');
            $self->add_auth_header('dmarc=temperror');
            $self->{'failmode'} = 1;
            return;
        }
        my $dkim = $self->get_object('dkim');
        $dmarc->dkim($dkim);
        my $dmarc_result = $dmarc->validate();
        my $dmarc_code   = $dmarc_result->result;
        $self->dbgout( 'DMARCCode', $dmarc_code, LOG_INFO );
        if ( !( $CONFIG->{'hide_none'} && $dmarc_code eq 'none' ) ) {
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
            if ( $CONFIG->{'detect_list_id'} && $self->{'is_list'} ) {
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
        if ( $error =~ /invalid header_from at / ) {
            $self->log_error( 'DMARC Error invalid header_from' );
            $self->add_auth_header('dmarc=permerror');
        }
        else {
            $self->log_error( 'DMARC Error ' . $error );
            $self->add_auth_header('dmarc=temperror');
        }
        return;
    }
}

1;
