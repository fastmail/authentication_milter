package Mail::Milter::Authentication::Handler::DKIM;

$VERSION = 0.3;

use strict;
use warnings;

use Mail::Milter::Authentication::Config qw{ get_config };
use Mail::Milter::Authentication::Util;

use Sys::Syslog qw{:standard :macros};

use Mail::DKIM::Verifier;

sub envfrom_callback {
    my ( $ctx, $env_from ) = @_;
    my $CONFIG = get_config();
    my $priv = $ctx->getpriv();
    return if ( !$CONFIG->{'check_dkim'} );
    $priv->{'dkim.failmode'} = 0;
    my $dkim;
    eval {
        $dkim = Mail::DKIM::Verifier->new();
    };
    if ( my $error = $@ ) {
        log_error( $ctx, 'DMKIM Setup Error ' . $error );
        add_auth_header( $ctx, 'dkim=temperror' );
        $priv->{'dkim.failmode'} = 1;
    }
    $priv->{'dkim.obj'} = $dkim;
}

sub header_callback {
    my ( $ctx, $header, $value ) = @_;
    my $CONFIG = get_config();
    my $priv = $ctx->getpriv();
    return if ( !$CONFIG->{'check_dkim'} );
    return if ( $priv->{'dkim.failmode'} );
    my $dkim = $priv->{'dkim.obj'};
    my $EOL    = "\015\012";
    my $dkim_chunk = $header . ': ' . $value . $EOL;
    $dkim_chunk =~ s/\015?\012/$EOL/g;
    $dkim->PRINT($dkim_chunk);

    # Add Google signatures to the mix.
    # Is this wise?
    if ( $header eq 'X-Google-DKIM-Signature' ) {
        my $x_dkim_chunk = 'DKIM-Signature: ' . $value . $EOL;
        $x_dkim_chunk =~ s/\015?\012/$EOL/g;
        $dkim->PRINT($x_dkim_chunk);
    }
}

sub eoh_callback {
    my ($ctx) = @_;
    my $CONFIG = get_config();
    my $priv = $ctx->getpriv();
    return if ( !$CONFIG->{'check_dkim'} );
    return if ( $priv->{'dkim.failmode'} );
    my $dkim = $priv->{'dkim.obj'};
    $dkim->PRINT( "\015\012" );
}

sub body_callback {
    my ( $ctx, $body_chunk, $len ) = @_;
    my $CONFIG = get_config();
    my $priv = $ctx->getpriv();
    return if ( !$CONFIG->{'check_dkim'} );
    return if ( $priv->{'dkim.failmode'} );
    my $dkim       = $priv->{'dkim.obj'};
    my $dkim_chunk = $body_chunk;
    my $EOL    = "\015\012";
    $dkim_chunk =~ s/\015?\012/$EOL/g;
    $dkim->PRINT($dkim_chunk);
}

sub eom_callback {
    my ($ctx) = @_;
    my $CONFIG = get_config();
    my $priv = $ctx->getpriv();
    return if ( !$CONFIG->{'check_dkim'} );
    return if ( $priv->{'dkim.failmode'} );
    my $dkim  = $priv->{'dkim.obj'};
    eval {
        $dkim->CLOSE();
        #$ctx->progress();

        my $dkim_result        = $dkim->result;
        my $dkim_result_detail = $dkim->result_detail;

        dbgout( $ctx, 'DKIMResult', $dkim_result_detail, LOG_INFO );

        if ( ! $dkim->signatures ) {
            if ( ! ( $CONFIG->{'check_dkim'} == 2 && $dkim_result eq 'none' ) ) {
                add_auth_header( $ctx,
                    format_header_entry( 'dkim', $dkim_result )
                      . ' (no signatures found)' );
            }
        }
        foreach my $signature ( $dkim->signatures ) {

            dbgout( $ctx, 'DKIMSignatureIdentity', $signature->identity, LOG_DEBUG );
            dbgout( $ctx, 'DKIMSignatureResult',   $signature->result_detail, LOG_DEBUG );
            my $signature_result        = $signature->result();
            my $signature_result_detail = $signature->result_detail();
           
            my $result_comment = q{};
            if ( $signature_result ne 'pass' and $signature_result ne 'none' ) {
              $signature_result_detail =~ /$signature_result \((.*)\)/;
              $result_comment = $1 . '; ';
            }
            if ( ! ( $CONFIG->{'check_dkim'} == 2 && $signature_result eq 'none' ) ) {
                my $otype = ref $signature;
                my $type = $otype eq 'Mail::DKIM::DkSignature' ? 'domainkeys'
                         : $otype eq 'Mail::DKIM::Signature'   ? 'dkim'
                         :                                       'dkim';
                dbgout( $ctx, 'DKIMSignatureType', $type, LOG_DEBUG );

                my $key_data = q{};
                eval {
                    my $key = $signature->get_public_key();
                    $key_data = $key->size() . '-bit ' . $key->type() . ' key';
                };

                if ( $type eq 'domainkeys' ) {
                    ## DEBUGGING
                    my $header = join(
                        q{ },
                        format_header_entry( $type, $signature_result ),
                        '('
                          . format_header_comment(
                              $result_comment
                              . $key_data
                            )
                          . ')',
                        format_header_entry( 'header.d', $signature->domain() ),
                        format_header_entry( 'header.b', substr( $signature->data(), 0, 8 ) ),
                    );
                    add_auth_header( $ctx, $header );
                }
                else {
                    my $header = join(
                        q{ },
                        format_header_entry( $type, $signature_result ),
                        '('
                          . format_header_comment(
                            $result_comment
                            . $key_data
                          )
                          . ')',
                        format_header_entry( 'header.d', $signature->domain() ),
                        format_header_entry( 'header.i', $signature->identity() ),
                        format_header_entry( 'header.b', substr( $signature->data(), 0, 8 ) ),
                    );
                    add_auth_header( $ctx, $header );
                }
            }
        }

        # the alleged author of the email may specify how to handle email
        if ( $CONFIG->{'check_dkim-adsp'} && ( $priv->{'is_local_ip_address'} == 0 ) && ( $priv->{'is_trusted_ip_address'} == 0 ) && ( $priv->{'is_authenticated'} == 0 ) ) {
            foreach my $policy ( $dkim->policies ) {
                my $apply    = $policy->apply($dkim);
                my $string   = $policy->as_string();
                my $location = $policy->location() || q{};
                my $name     = $policy->name();
                my $default  = $policy->is_implied_default_policy();

                my $otype = ref $policy;
                my $type = $otype eq 'Mail::DKIM::AuthorDomainPolicy' ? 'dkim-adsp'
                         : $otype eq 'Mail::DKIM::DkimPolicy'         ? 'x-dkim-ssp'
                         : $otype eq 'Mail::DKIM::DkPolicy'           ? 'x-dkim-dkssp'
                         :                                              'x-dkim-policy';

                dbgout( $ctx, 'DKIMPolicy',         $apply, LOG_DEBUG );
                dbgout( $ctx, 'DKIMPolicyString',   $string, LOG_DEBUG );
                dbgout( $ctx, 'DKIMPolicyLocation', $location, LOG_DEBUG  );
                dbgout( $ctx, 'DKIMPolicyName',     $name, LOG_DEBUG  );
                dbgout( $ctx, 'DKIMPolicyDefault',  $default ? 'yes' : 'no', LOG_DEBUG );

                my $result =
                    $apply eq 'accept'  ? 'pass'
                  : $apply eq 'reject'  ? 'discard'
                  : $apply eq 'neutral' ? 'unknown'
                  :                       'unknown';

                if ( ! ( $CONFIG->{'check_dkim-adsp'} == 2 && $result eq 'none' ) ) {
                    if ( ( ! $default ) or $CONFIG->{'show_default_adsp'} ) {
                        my $comment = '('
                          . format_header_comment( ( $default ? 'default ' : q{} )
                            . "$name policy"
                            . ( $location ? " from $location" : q{} )
#                            . ( $string   ? "; $string"       : q{} )
                          )
                          . ')';

                        my $header = join( q{ },
                            format_header_entry( $type, $result ), $comment, );
                        add_auth_header( $ctx, $header );
                    }
                }
            }
        }
    };
    if ( my $error = $@ ) {
        log_error( $ctx, 'DKIM Error - ' . $error );
        add_auth_header( $ctx, 'dkim=temperror' );
        if ( $CONFIG->{'check_dmarc'} ) {
            add_auth_header( $ctx, 'dmarc=temperror' );
            $priv->{'dkim.failmode'} = 1;
        }
    }
}

1;
