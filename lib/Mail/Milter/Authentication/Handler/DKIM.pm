package Mail::Milter::Authentication::Handler::DKIM;
use 5.20.0;
use strict;
use warnings;
use Mail::Milter::Authentication::Pragmas;
# ABSTRACT: Handler class for DKIM
# VERSION
use base 'Mail::Milter::Authentication::Handler';
use Mail::DKIM 1.20200513.1;
use Mail::DKIM::DNS;
use Mail::DKIM::KeyValueList;
use Mail::DKIM::Verifier;

sub default_config {
    return {
        'hide_none'         => 0,
        'hide_domainkeys'   => 0,
        'check_adsp'        => 1,
        'show_default_adsp' => 0,
        'adsp_hide_none'    => 0,
        'extra_properties'  => 0,
        'no_strict'         => 0,
    };
}

sub grafana_rows {
    my ( $self ) = @_;
    my @rows;
    push @rows, $self->get_json( 'DKIM_metrics' );
    return \@rows;
}

sub register_metrics {
    return {
        'dkim_total' => 'The number of emails processed for DKIM',
        'dkim_signatures' => 'The number of signatures processed for DKIM',
    };
}

sub envfrom_callback {
    my ( $self, $env_from )  = @_;
    $self->{'failmode'}      = 0;
    $self->{'headers'}       = [];
    $self->{'has_dkim'}      = 0;
    $self->{'valid_domains'} = {};
    $self->{'carry'}         = q{};
    $self->destroy_object('dkim');
}

sub show_domainkeys {
    my ( $self ) = @_;
    my $config = $self->handler_config();
    return 1 if ! exists $config->{'hide_domainkeys'};
    return 0 if $config->{'hide_domainkeys'};
    return 1;
}

sub header_callback {
    my ( $self, $header, $value, $original ) = @_;
    return if ( $self->{'failmode'} );
    my $EOL        = "\015\012";
    my $dkim_chunk = $original . $EOL;
    $dkim_chunk =~ s/\015?\012/$EOL/g;
    push @{$self->{'headers'}} , $dkim_chunk;

    if ( lc($header) eq 'dkim-signature' ) {
        $self->{'has_dkim'} = 1;

        my $parsed = eval{ Mail::DKIM::KeyValueList->parse( $value ) };
        $self->handle_exception( $@ );
        if ( $parsed ) {
            my $domain = $parsed->get_tag('d');
            my $selector = $parsed->get_tag('s');
            if ( $selector && $domain ) {
                my $resolver = $self->get_object('resolver');
                my $lookup = $selector.'._domainkey.'.$domain;
                eval{ $resolver->bgsend( $lookup, 'TXT' ) };
                $self->handle_exception( $@ );
                $self->dbgout( 'DNSEarlyLookup', "$lookup TXT", LOG_DEBUG );
                $lookup = '_adsp._domainkey.'.$domain;
                eval{ $resolver->bgsend( $lookup, 'TXT' ) };
                $self->handle_exception( $@ );
                $self->dbgout( 'DNSEarlyLookup', "$lookup TXT", LOG_DEBUG );
            }
        }
    }
    if ( lc($header) eq 'domainkey-signature' ) {
        $self->{'has_dkim'} = 1 if $self->show_domainkeys();
    }
}

sub eoh_callback {
    my ($self) = @_;
    return if ( $self->{'failmode'} );
    my $config = $self->handler_config();

    if ( $self->{'has_dkim'} == 0 ) {
        $self->metric_count( 'dkim_total', { 'result' => 'none' } );
        $self->dbgout( 'DKIMResult', 'No DKIM headers', LOG_INFO );
        if ( !( $config->{'hide_none'} ) ) {
            my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'dkim' )->safe_set_value( 'none' );
            $header->add_child( Mail::AuthenticationResults::Header::Comment->new()->safe_set_value( 'no signatures found' ) );
            $self->add_auth_header( $header );
        }
        delete $self->{'headers'};
    }
    else {

        my $dkim;
        eval {
            my $UseStrict = 1;
            if ( $config->{ 'no_strict' } ) {
                $UseStrict = 0;
            }
            $dkim = Mail::DKIM::Verifier->new( 'Strict' => $UseStrict );
            my $resolver = $self->get_object('resolver');
            Mail::DKIM::DNS::resolver($resolver);
            $self->set_object('dkim', $dkim, 1);
        };
        if ( my $error = $@ ) {
            $self->handle_exception( $error );
            $self->log_error( 'DKIM Setup Error ' . $error );
            $self->{'failmode'} = 1;
            $self->_check_error( $error );
            $self->metric_count( 'dkim_total', { 'result' => 'error' } );
            delete $self->{'headers'};
            return;
        }

        eval {
            $dkim->PRINT( join q{},
                @{ $self->{'headers'} },
                "\015\012",
            );
        };
        if ( my $error = $@ ) {
            $self->handle_exception( $error );
            $self->log_error( 'DKIM Headers Error ' . $error );
            $self->{'failmode'} = 1;
            $self->_check_error( $error );
            $self->metric_count( 'dkim_total', { 'result' => 'error' } );
        }

        delete $self->{'headers'};
    }

    $self->{'carry'} = q{};
}

sub body_callback {
    my ( $self, $body_chunk ) = @_;
    return if ( $self->{'failmode'} );
    return if ( $self->{'has_dkim'} == 0 );
    my $EOL = "\015\012";

    my $dkim_chunk;
    if ( $self->{'carry'} ne q{} ) {
        $dkim_chunk = $self->{'carry'} . $body_chunk;
        $self->{'carry'} = q{};
    }
    else {
        $dkim_chunk = $body_chunk;
    }

    if ( substr( $dkim_chunk, -1 ) eq "\015" ) {
        $self->{'carry'} = "\015";
        $dkim_chunk = substr( $dkim_chunk, 0, -1 );
    }

    $dkim_chunk =~ s/\015?\012/$EOL/g;

    my $dkim = $self->get_object('dkim');
    eval {
        $dkim->PRINT( $dkim_chunk );
    };
    if ( my $error = $@ ) {
        $self->handle_exception( $error );
        $self->log_error( 'DKIM Body Error ' . $error );
        $self->{'failmode'} = 1;
        $self->_check_error( $error );
        $self->metric_count( 'dkim_total', { 'result' => 'error' } );
    }
}

sub eom_callback {
    my ($self) = @_;

    return if ( $self->{'has_dkim'} == 0 );
    return if ( $self->{'failmode'} );

    my $config = $self->handler_config();

    my $dkim = $self->get_object('dkim');

    eval {
        $dkim->PRINT( $self->{'carry'} );
        $dkim->CLOSE();
        $self->check_timeout();

        my $dkim_result        = $dkim->result;
        my $dkim_result_detail = $dkim->result_detail;

        $self->metric_count( 'dkim_total', { 'result' => $dkim_result } );

        $self->dbgout( 'DKIMResult', $dkim_result_detail, LOG_INFO );

        if ( !$dkim->signatures() ) {
            if ( !( $config->{'hide_none'} && $dkim_result eq 'none' ) ) {
                my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'dkim' )->safe_set_value( $dkim_result );
                $header->add_child( Mail::AuthenticationResults::Header::Comment->new()->safe_set_value( 'no signatures found' ) );
                $self->add_auth_header( $header );
            }
        }
        foreach my $signature ( $dkim->signatures() ) {

            my $otype = ref $signature;
            my $type =
                $otype eq 'Mail::DKIM::DkSignature' ? 'domainkeys'
              : $otype eq 'Mail::DKIM::Signature'   ? 'dkim'
              :                                       'dkim';
            $self->dbgout( 'DKIMSignatureType', $type, LOG_DEBUG );

            $self->dbgout( 'DKIMSignatureDomain', $signature->domain, LOG_DEBUG );
            $self->dbgout( 'DKIMSignatureIdentity', $signature->identity, LOG_DEBUG );
            $self->dbgout( 'DKIMSignatureResult',   $signature->result_detail, LOG_DEBUG );
            my $signature_result        = $signature->result();
            my $signature_result_detail = $signature->result_detail();

            if ( $signature_result eq 'pass' ) {
                $self->{'valid_domains'}->{ lc $signature->domain } = 1;
            }

            if ( $signature_result eq 'invalid' ) {
                if ( $signature_result_detail =~ /DNS query timeout for (.*) at / ) {
                    my $timeout_domain = $1;
                    $self->log_error( "TIMEOUT DETECTED: in DKIM result: $timeout_domain" );
                    $signature_result_detail = "DNS query timeout for $timeout_domain";
                }
            }

            my $result_comment = q{};
            if ( $signature_result ne 'pass' and $signature_result ne 'none' ) {
                $signature_result_detail =~ /$signature_result \((.*)\)/;
                if ( $1 ) {
                    $result_comment = $1 . ', ';
                }
            }
            if (
                !(
                    $config->{'hide_none'} && $signature_result eq 'none'
                )
              )
            {

                my $key_size = 0;
                my $key_type = q{};
                my $selector = eval{ $signature->selector } || q{};
                eval {
                    my $key = $signature->get_public_key();
                    $key_size = $key->size();
                    $key_type = $key->type();
                };

                my $hash_algorithm   = eval { $signature->hash_algorithm(); };
                my $canonicalization = eval { $signature->canonicalization(); };

                my $key_data = $key_size . '-bit ' . $key_type . ' key ' . $hash_algorithm;

                $self->metric_count( 'dkim_signatures', {
                    'type'             => $type,
                    'result'           => $signature_result,
                    'key_size'         => $key_size,
                    'key_type'         => $key_type,
                    'hash_algorithm'   => $hash_algorithm,
                    'canonicalization' => $canonicalization,
                } );

                if ( $type eq 'domainkeys' ) {
                    if ( $self->show_domainkeys() ) {
                        my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( $type )->safe_set_value( $signature_result );
                        $header->add_child( Mail::AuthenticationResults::Header::Comment->new()->safe_set_value( $result_comment . $key_data ) );
                        $header->add_child( Mail::AuthenticationResults::Header::SubEntry->new()->set_key( 'header.d' )->safe_set_value( $signature->domain() ) );
                        $header->add_child( Mail::AuthenticationResults::Header::SubEntry->new()->set_key( 'header.b' )->safe_set_value( substr( $signature->data(), 0, 8 ) ) );
                        if ( $config->{'extra_properties'} ) {
                            $header->add_child( Mail::AuthenticationResults::Header::SubEntry->new()->set_key( 'x-bits' )->safe_set_value( $key_size ) );
                            $header->add_child( Mail::AuthenticationResults::Header::SubEntry->new()->set_key( 'x-keytype' )->safe_set_value( $key_type ) );
                            $header->add_child( Mail::AuthenticationResults::Header::SubEntry->new()->set_key( 'x-algorithm' )->safe_set_value( $hash_algorithm ) );
                            $header->add_child( Mail::AuthenticationResults::Header::SubEntry->new()->set_key( 'x-selector' )->safe_set_value( $selector ) );
                        }
                        $self->add_auth_header($header);
                    }
                }
                else {
                    my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( $type )->safe_set_value( $signature_result );
                    $header->add_child( Mail::AuthenticationResults::Header::Comment->new()->safe_set_value( $result_comment . $key_data ) );
                    $header->add_child( Mail::AuthenticationResults::Header::SubEntry->new()->set_key( 'header.d' )->safe_set_value( $signature->domain() ) );
                    $header->add_child( Mail::AuthenticationResults::Header::SubEntry->new()->set_key( 'header.i' )->safe_set_value( $signature->identity() ) );
                    $header->add_child( Mail::AuthenticationResults::Header::SubEntry->new()->set_key( 'header.b' )->safe_set_value( substr( $signature->data(), 0, 8 ) ) );
                    $header->add_child( Mail::AuthenticationResults::Header::SubEntry->new()->set_key( 'header.a' )->safe_set_value( $key_type . '-' . $hash_algorithm ) );
                    $header->add_child( Mail::AuthenticationResults::Header::SubEntry->new()->set_key( 'header.s' )->safe_set_value( $selector ) );
                    if ( $config->{'extra_properties'} ) {
                        $header->add_child( Mail::AuthenticationResults::Header::SubEntry->new()->set_key( 'x-bits' )->safe_set_value( $key_size ) );
                    }
                    $self->add_auth_header($header);
                }
            }
            $self->check_timeout();
        }

        # the alleged author of the email may specify how to handle email
        if (   $config->{'check_adsp'}
            && ( $self->is_local_ip_address() == 0 )
            && ( $self->is_trusted_ip_address() == 0 )
            && ( $self->is_authenticated() == 0 ) )
        {
            POLICY:
            foreach my $policy ( $dkim->policies() ) {
                my $apply    = $policy->apply($dkim);
                my $string   = $policy->as_string();
                my $location = $policy->location() || q{};
                my $name     = $policy->name();
                my $default  = $policy->is_implied_default_policy();

                my $otype = ref $policy;
                my $type =
                    $otype eq 'Mail::DKIM::AuthorDomainPolicy' ? 'dkim-adsp'
                  : $otype eq 'Mail::DKIM::DkimPolicy'         ? 'x-dkim-ssp'
                  : $otype eq 'Mail::DKIM::DkPolicy'           ? 'x-dkim-dkssp'
                  :   'x-dkim-policy';

                $self->dbgout( 'DKIMPolicy',         $apply,                  LOG_DEBUG );
                $self->dbgout( 'DKIMPolicyString',   $string,                 LOG_DEBUG );
                $self->dbgout( 'DKIMPolicyLocation', $location,               LOG_DEBUG );
                $self->dbgout( 'DKIMPolicyName',     $name,                   LOG_DEBUG );
                $self->dbgout( 'DKIMPolicyDefault',  $default ? 'yes' : 'no', LOG_DEBUG );

                next POLICY if ( ( $type eq 'x-dkim-dkssp' ) && ( ! $self->show_domainkeys() ) );

                my $result =
                    $apply eq 'accept'  ? 'pass'
                  : $apply eq 'reject'  ? 'discard'
                  : $apply eq 'neutral' ? 'unknown'
                  :                       'unknown';

                if ( ! ( $config->{'adsp_hide_none'} && $result eq 'none' ) ) {
                    if ( ( ! $default ) or $config->{'show_default_adsp'} ) {
                        my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( $type )->safe_set_value( $result );
                        my $comment = ( $default ? 'default ' : q{} )
                                    . "$name policy"
                                    . ( $location ? " from $location" : q{} )
#                                   . ( $string   ? ", $string"       : q{} )
                        ;
                        $header->add_child( Mail::AuthenticationResults::Header::Comment->new()->safe_set_value( $comment ) );
                        $self->add_auth_header( $header );
                    }
                }
                $self->check_timeout();
            }
        }
    };
    if ( my $error = $@ ) {
        $self->handle_exception( $error );

        # Also in DMARC module
        $self->log_error( 'DKIM EOM Error ' . $error );
        $self->{'failmode'} = 1;
        $self->_check_error( $error );
        $self->metric_count( 'dkim_total', { 'result' => 'error' } );
        return;
    }
}

sub close_callback {
    my ( $self ) = @_;
    delete $self->{'failmode'};
    delete $self->{'headers'};
    delete $self->{'body'};
    delete $self->{'carry'};
    delete $self->{'has_dkim'};
    delete $self->{'valid_domains'};
    $self->destroy_object('dkim');
}

sub _check_error {
    my ( $self, $error ) = @_;
    if ( $error =~ /^DNS error: query timed out/
            or $error =~ /^DNS query timeout/
    ){
        $self->log_error( 'Temp DKIM Error - ' . $error );
        my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'dkim' )->safe_set_value( 'temperror' );
        $header->add_child( Mail::AuthenticationResults::Header::Comment->new()->safe_set_value( 'dns timeout' ) );
        $self->add_auth_header( $header );
    }
    elsif ( $error =~ /^DNS error: SERVFAIL/ ){
        $self->log_error( 'Temp DKIM Error - ' . $error );
        my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'dkim' )->safe_set_value( 'temperror' );
        $header->add_child( Mail::AuthenticationResults::Header::Comment->new()->safe_set_value( 'dns servfail' ) );
        $self->add_auth_header( $header );
    }
    elsif ( $error =~ /^no domain to fetch policy for$/
            or $error =~ /^policy syntax error$/
            or $error =~ /^empty domain label/
            or $error =~ /^invalid name /
    ){
        $self->log_error( 'Perm DKIM Error - ' . $error );
        my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'dkim' )->safe_set_value( 'permerror' );
        $header->add_child( Mail::AuthenticationResults::Header::Comment->new()->safe_set_value( 'syntax or domain error' ) );
        $self->add_auth_header( $header );
    }
    else {
        $self->exit_on_close( 'Unexpected DKIM Error - ' . $error );
        my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'dkim' )->safe_set_value( 'temperror' );
        $self->add_auth_header( $header );
        # Fill these in as they occur, but for unknowns err on the side of caution
        # and tempfail/exit
        $self->tempfail_on_error();
    }
}

1;

__END__

=head1 DESCRIPTION

Module for validation of DKIM and DomainKeys signatures, and application of ADSP policies.

=head1 CONFIGURATION

        "DKIM" : {                                      | Config for the DKIM Module
            "hide_none"         : 0,                    | Hide auth line if the result is 'none'
            "hide_domainkeys"   : 0,                    | Hide any DomainKeys results
            "check_adsp"        : 1,                    | Also check for ADSP
            "show_default_adsp" : 0,                    | Show the default ADSP result
            "adsp_hide_none"    : 0,                    | Hide auth ADSP if the result is 'none'
            "extra_properties"  : 0                     | Add extra properties (not to rfc) relating to key and selector
            "no_strict"         : 0,                    | Ignore rfc 8301 security considerations (not recommended
        },

