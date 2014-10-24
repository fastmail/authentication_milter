package Mail::Milter::Authentication::Handler::DMARC;

$VERSION = 0.1;

use strict;
use warnings;

use Mail::Milter::Authentication::Config qw{ get_config };
use Mail::Milter::Authentication::Util;

use Sys::Syslog qw{:standard :macros};

use Mail::DMARC::PurePerl;

my $CONFIG = get_config();

sub get_auth_name {
    my ($ctx) = @_;
    my $name = get_symval( $ctx, '{auth_authen}' );
    return $name;
}

sub envfrom_callback {
    my ( $ctx, $env_from ) = @_;
    my $priv = $ctx->getpriv();
    return if ( !$CONFIG->{'check_dmarc'} );
    return if ( $priv->{'is_local_ip_address'} );
    return if ( $priv->{'is_trusted_ip_address'} );
    return if ( $priv->{'is_authenticated'} );
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
    $priv->{'dmarc_obj'} = $dmarc;
    eval {
        $dmarc->envelope_from($domain_from);
    };
    if ( my $error = $@ ) {
        log_error( $ctx, 'DMARC Mail From Error ' . $error );
        add_auth_header( $ctx, 'dmarc=temperror' );
        $priv->{'dmarc_obj'} = undef;
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
    if ( my $dmarc = $priv->{'dmarc_obj'} ) {
        my $envelope_to = get_domain_from($env_to);
        eval { $dmarc->envelope_to($envelope_to) };
        if ( my $error = $@ ) {
            log_error( $ctx, 'DMARC Rcpt To Error ' . $error );
            add_auth_header( $ctx, 'dmarc=temperror' );
            $priv->{'dmarc_obj'} = undef;
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
    if ( $header eq 'From' ) {
        $priv->{'from_header'} = $value;
        if ( my $dmarc = $priv->{'dmarc_obj'} ) {
            eval { $dmarc->header_from_raw( $header . ': ' . $value ) };
            if ( my $error = $@ ) {
                log_error( $ctx, 'DMARC Header From Error ' . $error );
                add_auth_header( $ctx, 'dmarc=temperror' );
                $priv->{'dmarc_obj'} = undef;
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
        if ( my $dmarc = $priv->{'dmarc_obj'} ) {
            my $dkim  = $priv->{'dkim_obj'};
            $dmarc->dkim($dkim);
            my $dmarc_result = $dmarc->validate();
            #$ctx->progress();
            my $dmarc_code   = $dmarc_result->result;
            dbgout( $ctx, 'DMARCCode', $dmarc_code, LOG_INFO );
            if ( ! ( $CONFIG->{'check_dmarc'} == 2 && $dmarc_code eq 'none' ) ) {
                my $dmarc_policy;
                if ( $dmarc_code ne 'pass' ) {
                    $dmarc_policy = eval { $dmarc_result->evalated->disposition() };
                    dbgout( $ctx, 'DMARCPolicy', $dmarc_policy, LOG_DEBUG );
                }
                my $dmarc_header = format_header_entry( 'dmarc', $dmarc_code );
                if ($dmarc_policy) {
                    $dmarc_header .= ' ('
                      . format_header_comment(
                        format_header_entry( 'p', $dmarc_policy ) )
                      . ')';
                }
                $dmarc_header .= ' '
                  . format_header_entry( 'header.from',
                    get_domain_from( $priv->{'from_header'} ) );
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
        }
    };
    if ( my $error = $@ ) {
        log_error( $ctx, 'DMARC Error ' . $error );
        add_auth_header( $ctx, 'dmarc=temperror' );
        return;
    }
}

1;
