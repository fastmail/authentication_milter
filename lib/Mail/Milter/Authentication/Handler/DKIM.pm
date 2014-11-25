package Mail::Milter::Authentication::Handler::DKIM;

use strict;
use warnings;

our $VERSION = 0.3;

use base 'Mail::Milter::Authentication::Handler::Generic';

use Mail::Milter::Authentication::Config qw{ get_config };
use Mail::Milter::Authentication::Util;

use Sys::Syslog qw{:standard :macros};

use Mail::DKIM::Verifier;

sub envfrom_callback {
    my ( $self, $env_from ) = @_;
    my $CONFIG = get_config();
    my $priv = $self->{'ctx'}->getpriv();
    return if ( !$CONFIG->{'check_dkim'} );
    $priv->{'dkim.failmode'} = 0;
    my $dkim;
    eval {
        $dkim = Mail::DKIM::Verifier->new();
    };
    if ( my $error = $@ ) {
        $self->log_error( 'DMKIM Setup Error ' . $error );
        add_auth_header( $self->{'ctx'}, 'dkim=temperror' );
        $priv->{'dkim.failmode'} = 1;
    }
    $priv->{'dkim.obj'} = $dkim;
}

sub header_callback {
    my ( $self, $header, $value ) = @_;
    my $CONFIG = get_config();
    my $priv = $self->{'ctx'}->getpriv();
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
    my ($self) = @_;
    my $CONFIG = get_config();
    my $priv = $self->{'ctx'}->getpriv();
    return if ( !$CONFIG->{'check_dkim'} );
    return if ( $priv->{'dkim.failmode'} );
    my $dkim = $priv->{'dkim.obj'};
    $dkim->PRINT( "\015\012" );
}

sub body_callback {
    my ( $self, $body_chunk, $len ) = @_;
    my $CONFIG = get_config();
    my $priv = $self->{'ctx'}->getpriv();
    return if ( !$CONFIG->{'check_dkim'} );
    return if ( $priv->{'dkim.failmode'} );
    my $dkim       = $priv->{'dkim.obj'};
    my $dkim_chunk = $body_chunk;
    my $EOL    = "\015\012";
    $dkim_chunk =~ s/\015?\012/$EOL/g;
    $dkim->PRINT($dkim_chunk);
}

sub eom_callback {
    my ($self) = @_;
    my $CONFIG = get_config();
    my $priv = $self->{'ctx'}->getpriv();
    return if ( !$CONFIG->{'check_dkim'} );
    return if ( $priv->{'dkim.failmode'} );
    my $dkim  = $priv->{'dkim.obj'};
    eval {
        $dkim->CLOSE();
        #$ctx->progress();

        my $dkim_result        = $dkim->result;
        my $dkim_result_detail = $dkim->result_detail;

        $self->dbgout( 'DKIMResult', $dkim_result_detail, LOG_INFO );

        if ( ! $dkim->signatures ) {
            if ( ! ( $CONFIG->{'check_dkim'} == 2 && $dkim_result eq 'none' ) ) {
                add_auth_header( $self->{'ctx'},
                    format_header_entry( 'dkim', $dkim_result )
                      . ' (no signatures found)' );
            }
        }
        foreach my $signature ( $dkim->signatures ) {

            $self->dbgout( 'DKIMSignatureIdentity', $signature->identity, LOG_DEBUG );
            $self->dbgout( 'DKIMSignatureResult',   $signature->result_detail, LOG_DEBUG );
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
                $self->dbgout( 'DKIMSignatureType', $type, LOG_DEBUG );

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
                    add_auth_header( $self->{'ctx'}, $header );
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
                    add_auth_header( $self->{'ctx'}, $header );
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

                $self->dbgout( 'DKIMPolicy',         $apply, LOG_DEBUG );
                $self->dbgout( 'DKIMPolicyString',   $string, LOG_DEBUG );
                $self->dbgout( 'DKIMPolicyLocation', $location, LOG_DEBUG  );
                $self->dbgout( 'DKIMPolicyName',     $name, LOG_DEBUG  );
                $self->dbgout( 'DKIMPolicyDefault',  $default ? 'yes' : 'no', LOG_DEBUG );

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
                        add_auth_header( $self->{'ctx'}, $header );
                    }
                }
            }
        }
    };
    if ( my $error = $@ ) {
        $self->log_error( 'DKIM Error - ' . $error );
        add_auth_header( $self->{'ctx'}, 'dkim=temperror' );
        $priv->{'dkim.failmode'} = 1;
    }
}

1;
