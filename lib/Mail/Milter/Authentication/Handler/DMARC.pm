package Mail::Milter::Authentication::Handler::DMARC;

$VERSION = 0.3;

use strict;
use warnings;

use Mail::Milter::Authentication::Config qw{ get_config };
use Mail::Milter::Authentication::Util;

use Sys::Syslog qw{:standard :macros};

use Mail::DMARC::PurePerl;

my $CONFIG = get_config();

sub envfrom_callback {
    my ( $ctx, $env_from ) = @_;
    my $priv = $ctx->getpriv();
    return if ( !$CONFIG->{'check_dmarc'} );
    return if ( $priv->{'is_local_ip_address'} );
    return if ( $priv->{'is_trusted_ip_address'} );
    return if ( $priv->{'is_authenticated'} );
    delete $priv->{'dmarc.from_header'};
    my $domain_from = get_domain_from($env_from);
    my $dmarc;
    eval {
        $dmarc = Mail::DMARC::PurePerl->new();
        $dmarc->verbose(1);
        $dmarc->source_ip($priv->{'core.ip_address'})
    };
    if ( my $error = $@ ) {
        log_error( $ctx, 'DMARC IP Error ' . $error );
        add_auth_header( $ctx, 'dmarc=temperror' );
        $dmarc = undef;
        return;
    }
    $priv->{'dmarc.is_list'} = 0;
    $priv->{'dmarc.obj'}     = $dmarc;
    eval {
        $dmarc->envelope_from($domain_from);
    };
    if ( my $error = $@ ) {
        log_error( $ctx, 'DMARC Mail From Error ' . $error );
        add_auth_header( $ctx, 'dmarc=temperror' );
        $priv->{'dmarc.obj'} = undef;
        return;
    }
}

sub envrcpt_callback {
    my ( $ctx, $env_to ) = @_;
    my $priv = $ctx->getpriv();
    return if ( !$CONFIG->{'check_dmarc'} );
    return if ( $priv->{'is_local_ip_address'} );
    return if ( $priv->{'is_trusted_ip_address'} );
    return if ( $priv->{'is_authenticated'} );
    if ( my $dmarc = $priv->{'dmarc.obj'} ) {
        my $envelope_to = get_domain_from($env_to);
        eval { $dmarc->envelope_to($envelope_to) };
        if ( my $error = $@ ) {
            log_error( $ctx, 'DMARC Rcpt To Error ' . $error );
            add_auth_header( $ctx, 'dmarc=temperror' );
            $priv->{'dmarc.obj'} = undef;
            return;
        }
    }
}

sub header_callback {
    my ( $ctx, $header, $value ) = @_;
    my $priv = $ctx->getpriv();
    return if ( !$CONFIG->{'check_dmarc'} );
    return if ( $priv->{'is_local_ip_address'} );
    return if ( $priv->{'is_trusted_ip_address'} );
    return if ( $priv->{'is_authenticated'} );
    if ( lc $header eq 'list-id' ) {
        $priv->{'dmarc.is_list'} = 1;
    }
    if ( $header eq 'From' ) {
        if ( exists $priv->{'dmarc.from_header'} ) {
            dbgout( $ctx, 'DMARCFail', 'Multiple RFC5322 from fields', LOG_INFO );
            # ToDo handle this by eveluating DMARC for each field in turn as
            # suggested in the DMARC spec part 5.6.1
            # Currently this does not give reporting feedback to the author domain, this should be changed.
            add_auth_header( $ctx, 'dmarc=fail (multiple RFC5322 from fields in message)' );
            $priv->{'dmarc.obj'} = undef;
            return;
        }
        $priv->{'dmarc.from_header'} = $value;
        if ( my $dmarc = $priv->{'dmarc.obj'} ) {
            eval { $dmarc->header_from_raw( $header . ': ' . $value ) };
            if ( my $error = $@ ) {
                log_error( $ctx, 'DMARC Header From Error ' . $error );
                add_auth_header( $ctx, 'dmarc=temperror' );
                $priv->{'dmarc.obj'} = undef;
                return;
            }
        }
    }
}

sub eom_callback {
    my ( $ctx ) = @_;
    my $priv = $ctx->getpriv();
    return if ( !$CONFIG->{'check_dmarc'} );
    return if ( $priv->{'is_local_ip_address'} );
    return if ( $priv->{'is_trusted_ip_address'} );
    return if ( $priv->{'is_authenticated'} );
    eval {
        if ( my $dmarc = $priv->{'dmarc.obj'} ) {
            my $dkim  = $priv->{'dkim.obj'};
            $dmarc->dkim($dkim);
            my $dmarc_result = $dmarc->validate();
            #$ctx->progress();
            my $dmarc_code   = $dmarc_result->result;
            dbgout( $ctx, 'DMARCCode', $dmarc_code, LOG_INFO );
            if ( ! ( $CONFIG->{'check_dmarc'} == 2 && $dmarc_code eq 'none' ) ) {
                my $dmarc_policy;
                if ( $dmarc_code ne 'pass' ) {
                    $dmarc_policy = eval { $dmarc_result->disposition() };
                    if ( my $error = $@ ) {
                        log_error( $ctx, 'DMARCPolicyError ' . $error );
                    }
                    dbgout( $ctx, 'DMARCPolicy', $dmarc_policy, LOG_INFO );
                }
                my $dmarc_header = format_header_entry( 'dmarc', $dmarc_code );
                my $is_list_entry = q{};
                if ( $CONFIG->{'dmarc_detect_list_id'} && $priv->{'dmarc.is_list'} ) {
                    $is_list_entry = ';has-list-id=yes';
                }
                if ($dmarc_policy) {
                    $dmarc_header .= ' ('
                      . format_header_comment(
                        format_header_entry( 'p', $dmarc_policy ) )
                      . $is_list_entry
                    . ')';
                }
                $dmarc_header .= ' '
                  . format_header_entry( 'header.from',
                    get_domain_from( $priv->{'dmarc.from_header'} ) );
                add_auth_header( $ctx, $dmarc_header );
            }
            eval{
                # Try as best we can to save a report, but don't stress if it fails.
                my $rua = $dmarc_result->published()->rua();
                if ( $rua ) {
                    $dmarc->save_aggregate();
                    dbgout( $ctx, 'DMARCReportTo', $rua, LOG_INFO );
                }
            };
            if ( my $error = $@ ) {
                log_error( $ctx, 'DMARC Report Error ' . $error );
            }
        }
    };
    if ( my $error = $@ ) {
        log_error( $ctx, 'DMARC Error ' . $error );
        add_auth_header( $ctx, 'dmarc=temperror' );
        return;
    }
}

1;
