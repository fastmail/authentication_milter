package Mail::Milter::Authentication::Handler;

$VERSION = 0.1;

use strict;
use warnings;

use Mail::Milter::Authentication;
use Mail::Milter::Authentication::Util;
use Mail::Milter::Authentication::Config qw{ get_config };

use Mail::Milter::Authentication::Auth;
use Mail::Milter::Authentication::IPRev;
use Mail::Milter::Authentication::LocalIP;
use Mail::Milter::Authentication::PTR;
use Mail::Milter::Authentication::SPF;
use Mail::Milter::Authentication::TrustedIP;

use Mail::DKIM::Verifier;
use Mail::DMARC::PurePerl;

use Sys::Syslog qw{:standard :macros};
use Sendmail::PMilter qw { :all };
use Socket;

my $CONFIG = get_config();

sub connect_callback {
    # On Connect
    my ( $ctx, $hostname, $sockaddr_in ) = @_;
    dbgout( $ctx, 'CALLBACK', 'Connect', LOG_DEBUG );
    my $priv = {};
    $ctx->setpriv($priv);
    
    $priv->{ 'is_authenticated' }    = 0;

    eval {
        my ( $port, $iaddr, $ip_address );

        # Process the connecting IP Address
        my $ip_length = length( $sockaddr_in );
        if ( $ip_length eq 16 ) {
            ( $port, $iaddr ) = sockaddr_in($sockaddr_in);
            $ip_address = inet_ntoa($iaddr);
        }
        elsif ( $ip_length eq 28 ) {
            ( $port, $iaddr ) = sockaddr_in6($sockaddr_in);
            $ip_address = Socket::inet_ntop(AF_INET6, $iaddr);
        }
        else {
            ## TODO something better here - this should never happen
            log_error( $ctx, 'Unknown IP address format');
            $ip_address = q{};
        }
        $priv->{'ip_address'} = $ip_address;
        dbgout( $ctx, 'ConnectFrom', $ip_address, LOG_DEBUG );

        Mail::Milter::Authentication::TrustedIP::connect_callback( $ctx, $hostname, $sockaddr_in );
        Mail::Milter::Authentication::LocalIP::connect_callback( $ctx, $hostname, $sockaddr_in );
        Mail::Milter::Authentication::IPRev::connect_callback( $ctx, $hostname, $sockaddr_in );

    };
    if ( my $error = $@ ) {
        log_error( $ctx, 'Connect callback error ' . $error );
    }

    return SMFIS_CONTINUE;
}

sub helo_callback {
    # On HELO
    my ( $ctx, $helo_host ) = @_;
    dbgout( $ctx, 'CALLBACK', 'Helo', LOG_DEBUG );
    my $priv = $ctx->getpriv();
    $helo_host = q{} if not $helo_host;
    eval {
        if ( ! exists( $priv->{'helo_name'} ) ) {
            # Ignore any further HELOs from this connection
            $priv->{'helo_name'} = $helo_host;
            dbgout( $ctx, 'HeloFrom', $helo_host, LOG_DEBUG );
            
            Mail::Milter::Authentication::PTR::helo_callback( $ctx, $helo_host );

        }
    };
    if ( my $error = $@ ) {
        log_error( $ctx, 'HELO callback error ' . $error );
    }

    return SMFIS_CONTINUE;
}

sub envfrom_callback {
    # On MAILFROM
    #...
    my ( $ctx, $env_from ) = @_;
    dbgout( $ctx, 'CALLBACK', 'EnvFrom', LOG_DEBUG );
    my $priv = $ctx->getpriv();

    # Reset private data for this MAIL transaction
    delete $priv->{'auth_headers'};
    delete $priv->{'mail_from'};
    delete $priv->{'from_header'};
    delete $priv->{'auth_result_header_index'};
    delete $priv->{'remove_auth_headers'};
    delete $priv->{'auth_headers'};
    delete $priv->{'pre_headers'};
    delete $priv->{'add_headers'};

    $env_from = q{} if not $env_from;

    eval {

        my $dkim;
        if ( $CONFIG->{'check_dkim'} ) {
            eval {
                $dkim = Mail::DKIM::Verifier->new();
            };
            if ( my $error = $@ ) {
                log_error( $ctx, 'DMKIM Setup Error ' . $error );
                add_auth_header( $ctx, 'dkim=temperror' );
                $dkim = undef;
            }
            $priv->{'dkim_obj'} = $dkim;
        }

        my $dmarc;
        if ( $CONFIG->{'check_dmarc'} && ( $priv->{'is_local_ip_address'} == 0 ) && ( $priv->{'is_trusted_ip_address'} == 0 ) && ( $priv->{'is_authenticated'} == 0 ) ) {
            eval {
                $dmarc = Mail::DMARC::PurePerl->new();
                $dmarc->verbose(1);
                $dmarc->source_ip($priv->{'ip_address'})
            };
            if ( my $error = $@ ) {
                log_error( $ctx, 'DMARC IP Error ' . $error );
                add_auth_header( $ctx, 'dmarc=temperror' );
                $dmarc = undef;
            }
            $priv->{'dmarc_obj'} = $dmarc;
        }

        Mail::Milter::Authentication::SPF::envfrom_callback( $ctx, $env_from );
        Mail::Milter::Authentication::Auth::envfrom_callback( $ctx, $env_from );

        $priv->{'mail_from'} = $env_from || q{};
        dbgout( $ctx, 'EnvelopeFrom', $env_from, LOG_DEBUG );
        if ( $CONFIG->{'check_dmarc'} && ( $priv->{'is_local_ip_address'} == 0 ) && ( $priv->{'is_trusted_ip_address'} == 0 ) && ( $priv->{'is_authenticated'} == 0 ) ) {
            if ( my $dmarc = $priv->{'dmarc_obj'} ) {
                my $domain_from = get_domain_from($env_from);
                eval { $dmarc->envelope_from($domain_from) };
                if ( my $error = $@ ) {
                    log_error( $ctx, 'DMARC Mail From Error ' . $error );
                    add_auth_header( $ctx, 'dmarc=temperror' );
                    $priv->{'dmarc_obj'} = undef;
                }
            }
        }
    };
    if ( my $error = $@ ) {
        log_error( $ctx, 'Env From callback error ' . $error );
    }

    return SMFIS_CONTINUE;
}

sub envrcpt_callback {
    # On RCPTTO
    #...
    my ( $ctx, $env_to ) = @_;
    dbgout( $ctx, 'CALLBACK', 'EnvRcpt', LOG_DEBUG );
    my $priv = $ctx->getpriv();
    $env_to = q{} if not $env_to;
    eval {
        my $envelope_to = get_domain_from($env_to);
        dbgout( $ctx, 'EnvelopeTo', $env_to, LOG_DEBUG );
        if ( $CONFIG->{'check_dmarc'} && ( $priv->{'is_local_ip_address'} == 0 ) && ( $priv->{'is_trusted_ip_address'} == 0 ) && ( $priv->{'is_authenticated'} == 0 ) ) {
            if ( my $dmarc = $priv->{'dmarc_obj'} ) {
                eval { $dmarc->envelope_to($envelope_to) };
                if ( my $error = $@ ) {
                    log_error( $ctx, 'DMARC Rcpt To Error ' . $error );
                    add_auth_header( $ctx, 'dmarc=temperror' );
                    $priv->{'dmarc_obj'} = undef;
                }
            }
        }
    };
    if ( my $error = $@ ) {
        log_error( $ctx, 'Rcpt To callback error ' . $error );
    }

    return SMFIS_CONTINUE;
}

sub header_callback {
    # On Each Header
    my ( $ctx, $header, $value ) = @_;
    dbgout( $ctx, 'CALLBACK', 'Header', LOG_DEBUG );
    my $priv = $ctx->getpriv();
    $value = q{} if not $value;
    eval {
        if ( $header eq 'From' ) {
            $priv->{'from_header'} = $value;
            if ( $CONFIG->{'check_dmarc'} && ( $priv->{'is_local_ip_address'} == 0 ) && ( $priv->{'is_trusted_ip_address'} == 0 ) && ( $priv->{'is_authenticated'} == 0 ) ) {
                if ( my $dmarc = $priv->{'dmarc_obj'} ) {
                    eval { $dmarc->header_from_raw( $header . ': ' . $value ) };
                    if ( my $error = $@ ) {
                        log_error( $ctx, 'DMARC Header From Error ' . $error );
                        add_auth_header( $ctx, 'dmarc=temperror' );
                        $priv->{'dmarc_obj'} = undef;
                    }
                }
            }
        }

        if ( $CONFIG->{'check_dkim'} ) {
            my $dkim = $priv->{'dkim_obj'};

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

        # Check for and remove rogue auth results headers from untrusted IP Addresses
        if ( $priv->{'is_trusted_ip_address'} == 0 ) {
            if ( $header eq 'Authentication-Results' ) {
                if ( !exists $priv->{'auth_result_header_index'} ) {
                    $priv->{'auth_result_header_index'} = 0;
                }
                $priv->{'auth_result_header_index'} =
                  $priv->{'auth_result_header_index'} + 1;
                my ($domain_part) = $value =~ /(.*);/;
                $domain_part =~ s/ +//g;
                if ( is_hostname_mine( $ctx, $domain_part ) ) {
                    remove_auth_header( $ctx, $priv->{'auth_result_header_index'} );
                    my $forged_header = '(The following Authentication Results header was removed by ' . get_my_hostname($ctx) . "\n"
                                      . '    as the supplied domain conflicted with its own)' . "\n"
                                      . '    ' . $value;
                    append_header( $ctx, 'X-Invalid-Authentication-Results', $forged_header );
                }
            }
        }

        dbgout( $ctx, 'Header', $header . ': ' . $value, LOG_DEBUG );
    };
    if ( my $error = $@ ) {
        log_error( $ctx, 'Header callback error ' . $error );
    }
    return SMFIS_CONTINUE;
}

sub eoh_callback {
    # On End of headers
    my ($ctx) = @_;
    dbgout( $ctx, 'CALLBACK', 'EOH', LOG_DEBUG );
    my $priv = $ctx->getpriv();

    eval {
        if ( $CONFIG->{'check_dkim'} ) {
            my $dkim = $priv->{'dkim_obj'};
            $dkim->PRINT( "\015\012" );
        }

        Mail::Milter::Authentication::SPF::eoh_callback( $ctx );
    };
    if ( my $error = $@ ) {
        log_error( $ctx, 'EOH callback error ' . $error );
    }
    dbgoutwrite($ctx);
    return SMFIS_CONTINUE;
}

sub body_callback {
    # On each body chunk
    my ( $ctx, $body_chunk, $len ) = @_;
    dbgout( $ctx, 'CALLBACK', 'Body', LOG_DEBUG );
    my $priv = $ctx->getpriv();

    eval {
        if ( $CONFIG->{'check_dkim'} ) {
            my $dkim       = $priv->{'dkim_obj'};
            my $dkim_chunk = $body_chunk;
            my $EOL    = "\015\012";
            $dkim_chunk =~ s/\015?\012/$EOL/g;
            $dkim->PRINT($dkim_chunk);
        }
    };
    if ( my $error = $@ ) {
        log_error( $ctx, 'Body callback error ' . $error );
    }
    dbgoutwrite($ctx);
    return SMFIS_CONTINUE;
}

sub eom_callback {
    # On End of Message
    my ($ctx) = @_;
    dbgout( $ctx, 'CALLBACK', 'EOM', LOG_DEBUG );
    my $priv = $ctx->getpriv();

    eval {
        dkim_dmarc_check($ctx);
    };
    if ( my $error = $@ ) {
        log_error( $ctx, 'EOM callback error ' . $error );
    }
    add_headers($ctx);
    dbgoutwrite($ctx);
    return SMFIS_ACCEPT;
}

sub abort_callback {
    # On any out of our control abort
    my ($ctx) = @_;
    dbgout( $ctx, 'CALLBACK', 'Abort', LOG_DEBUG );
    dbgoutwrite($ctx);
    return SMFIS_CONTINUE;
}

sub close_callback {
    # On end of connection
    my ($ctx) = @_;
    dbgout( $ctx, 'CALLBACK', 'Close', LOG_DEBUG );
    dbgoutwrite($ctx);
    $ctx->setpriv(undef);
    return SMFIS_CONTINUE;
}

sub dkim_dmarc_check {
    my ($ctx) = @_;
    my $priv = $ctx->getpriv();

    if ( $CONFIG->{'check_dkim'} ) {
        my $dkim  = $priv->{'dkim_obj'};
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

                my $key = $signature->get_public_key();
                dbgout( $ctx, 'DKIMSignatureIdentity', $signature->identity, LOG_DEBUG );
                dbgout( $ctx, 'DKIMSignatureResult',   $signature->result_detail, LOG_DEBUG );
                my $signature_result = $signature->result();
                
                if ( ! ( $CONFIG->{'check_dkim'} == 2 && $signature_result eq 'none' ) ) {
                    my $otype = ref $signature;
                    my $type = $otype eq 'Mail::DKIM::DkSignature' ? 'domainkeys'
                             : $otype eq 'Mail::DKIM::Signature'   ? 'dkim'
                             :                                       'dkim';
                    dbgout( $ctx, 'DKIMSignatureType', $type, LOG_DEBUG );
                    if ( $type eq 'domainkeys' ) {
                        ## DEBUGGING
                        my $header = join(
                            q{ },
                            format_header_entry( $type, $signature_result ),
                            '('
                              . format_header_comment(
                                $key->size() . '-bit ' . $key->type() . ' key'
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
                                $key->size() . '-bit ' . $key->type() . ' key'
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
#                                . ( $string   ? "; $string"       : q{} )
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
            log_error( $ctx, 'DKIM Error ' . $error );
            add_auth_header( $ctx, 'dkim=temperror' );
            if ( $CONFIG->{'check_dmarc'} ) {
                add_auth_header( $ctx, 'dmarc=temperror' );
            }
            return;
        }

        if ( $CONFIG->{'check_dmarc'} && ( $priv->{'is_local_ip_address'} == 0 ) && ( $priv->{'is_trusted_ip_address'} == 0 ) && ( $priv->{'is_authenticated'} == 0 ) ) {
            eval {
                if ( my $dmarc = $priv->{'dmarc_obj'} ) {
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
    }
}

1;
