package Mail::Milter::Authentication::Handler::XGoogleDKIM;
use strict;
use warnings;
use base 'Mail::Milter::Authentication::Handler';
use version; our $VERSION = version->declare('v1.1.4');

use Data::Dumper;
use English qw{ -no_match_vars };
use Sys::Syslog qw{:standard :macros};

use Mail::DKIM;
use Mail::DKIM::Verifier;
use Mail::DKIM::DNS;

sub default_config {
    return {
        'hide_none'         => 0,
    };
}

sub grafana_rows {
    my ( $self ) = @_;
    my @rows;
    push @rows, $self->get_json( 'XGoogleDKIM_metrics' );
    return \@rows;
}

sub register_metrics {
    return {
        'xgoogledkim_total'      => 'The number of emails processed for X-Google-DKIM',
    };
}

sub envfrom_callback {
    my ( $self, $env_from ) = @_;
    $self->{'failmode'}     = 0;
    $self->{'headers'}      = [];
    $self->{'has_dkim'}     = 0;
    $self->{'carry'}        = q{};
    $self->destroy_object('xgdkim');
    return;
}

sub header_callback {
    my ( $self, $header, $value ) = @_;
    return if ( $self->{'failmode'} );
    my $EOL        = "\015\012";
    my $dkim_chunk = $header . ': ' . $value . $EOL;
    $dkim_chunk =~ s/\015?\012/$EOL/g;

    if ( lc($header) eq 'dkim-signature' ) {
        $dkim_chunk = 'X-Orig-' . $dkim_chunk;
    }
    if ( lc($header) eq 'domainkey-signature' ) {
        $dkim_chunk = 'X-Orig-' . $dkim_chunk;
    }
    push @{$self->{'headers'}} , $dkim_chunk;

    # Add Google signatures to the mix.
    # Is this wise?
    if ( $header eq 'X-Google-DKIM-Signature' ) {
        my $x_dkim_chunk = 'DKIM-Signature: ' . $value . $EOL;
        $x_dkim_chunk =~ s/\015?\012/$EOL/g;
        push @{$self->{'headers'}} , $x_dkim_chunk;
        $self->{'has_dkim'} = 1;
    }

    return;
}

sub eoh_callback {
    my ($self) = @_;
    return if ( $self->{'failmode'} );
    my $config = $self->handler_config();

    if ( $self->{'has_dkim'} == 0 ) {
        $self->metric_count( 'xgoogledkim_total', { 'result' => 'none' } );
        $self->dbgout( 'XGoogleDKIMResult', 'No X-Google-DKIM headers', LOG_INFO );
        if ( !( $config->{'hide_none'} ) ) {
            $self->add_auth_header(
                $self->format_header_entry( 'x-google-dkim', 'none' )
                . ' (no signatures found)' );
        }
        delete $self->{'headers'};
    }
    else {

        my $dkim;
        eval {
            $dkim = Mail::DKIM::Verifier->new();
            # The following requires Mail::DKIM > 0.4
            if ( $Mail::DKIM::VERSION >= 0.4 ) {
                my $resolver = $self->get_object('resolver');
                Mail::DKIM::DNS::resolver($resolver);
            }
            $self->set_object('xgdkim', $dkim, 1);
        };
        if ( my $error = $@ ) {
            $self->log_error( 'XGoogleDKIM Setup Error ' . $error );
            $self->_check_error( $error );
            $self->metric_count( 'xgoogledkim_total', { 'result' => 'error' } );
            $self->{'failmode'} = 1;
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
            $self->log_error( 'XGoogleDKIM Headers Error ' . $error );
            $self->_check_error( $error );
            $self->metric_count( 'xgoogledkim_total', { 'result' => 'error' } );
            $self->{'failmode'} = 1;
        }

        delete $self->{'headers'};
    }

    $self->{'carry'} = q{};

    return;
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

    my $dkim = $self->get_object('xgdkim');
    eval {
        $dkim->PRINT( $dkim_chunk );
    };
    if ( my $error = $@ ) {
        $self->log_error( 'XGoogleDKIM Body Error ' . $error );
        $self->_check_error( $error );
        $self->metric_count( 'xgoogledkim_total', { 'result' => 'error' } );
        $self->{'failmode'} = 1;
    }
    return;
}

sub eom_callback {
    my ($self) = @_;

    return if ( $self->{'has_dkim'} == 0 );
    return if ( $self->{'failmode'} );

    my $config = $self->handler_config();

    my $dkim = $self->get_object('xgdkim');

    eval {
        $dkim->PRINT( $self->{'carry'} );
        $dkim->CLOSE();

        my $dkim_result        = $dkim->result;
        my $dkim_result_detail = $dkim->result_detail;
        
        $self->metric_count( 'xgoogledkim_total', { 'result' => $dkim_result } );

        $self->dbgout( 'XGoogleDKIMResult', $dkim_result_detail, LOG_INFO );

        if ( !$dkim->signatures() ) {
            if ( !( $config->{'hide_none'} && $dkim_result eq 'none' ) ) {
                $self->add_auth_header(
                    $self->format_header_entry( 'x-google-dkim', $dkim_result )
                      . ' (no signatures found)' );
            }
        }
        foreach my $signature ( $dkim->signatures() ) {

            my $otype = ref $signature;
            my $type =
                $otype eq 'Mail::DKIM::DkSignature' ? 'domainkeys'
              : $otype eq 'Mail::DKIM::Signature'   ? 'dkim'
              :                                       'dkim';
            $self->dbgout( 'XGoogleDKIMSignatureType', $type, LOG_DEBUG );

            $self->dbgout( 'XGoogleDKIMSignatureIdentity', $signature->identity, LOG_DEBUG );
            $self->dbgout( 'XGoogleDKIMSignatureResult',   $signature->result_detail, LOG_DEBUG );
            my $signature_result        = $signature->result();
            my $signature_result_detail = $signature->result_detail();

            if ( $signature_result eq 'invalid' ) {
                if ( $signature_result_detail =~ /DNS query timeout for (.*) at / ) {
                    my $timeout_domain = $1;
                    $self->log_error( "TIMEOUT DETECTED: in XGoogleDKIM result: $timeout_domain" );
                    $signature_result_detail = "DNS query timeout for $timeout_domain";
                }
            }

            my $result_comment = q{};
            if ( $signature_result ne 'pass' and $signature_result ne 'none' ) {
                $signature_result_detail =~ /$signature_result \((.*)\)/;
                if ( $1 ) {
                    $result_comment = $1 . '; ';
                }
            }
            if (
                !(
                    $config->{'hide_none'} && $signature_result eq 'none'
                )
              )
            {

                my $key_data = q{};
                eval {
                    my $key = $signature->get_public_key();
                    $key_data = $key->size() . '-bit ' . $key->type() . ' key';
                };

                my $header = join(
                    q{ },
                    $self->format_header_entry( 'x-google-dkim', $signature_result ),
                    '('
                      . $self->format_header_comment(
                        $result_comment
                        . $key_data
                      )
                      . ')',
                    $self->format_header_entry( 'header.d', $signature->domain() ),
                    $self->format_header_entry( 'header.i', $signature->identity() ),
                    $self->format_header_entry( 'header.b', substr( $signature->data(), 0, 8 ) ),
                );
                $self->add_auth_header($header);
            }
        }

    };
    if ( my $error = $@ ) {

        # Also in DMARC module
        $self->log_error( 'XGoogleDKIM EOM Error ' . $error );
        $self->_check_error( $error );
        $self->metric_count( 'xgoogledkim_total', { 'result' => 'error' } );
        $self->{'failmode'} = 1;
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
    $self->destroy_object('xgdkim');
    return;
}

sub _check_error {
    my ( $self, $error ) = @_;
    if ( $error =~ /^DNS error: query timed out/
            or $error =~ /^DNS query timeout/
    ){
        $self->log_error( 'Temp XGoogleDKIM Error - ' . $error );
        $self->add_auth_header('x-google-dkim=temperror (dns timeout)');
    }
    elsif ( $error =~ /^no domain to fetch policy for$/
            or $error =~ /^policy syntax error$/
            or $error =~ /^empty domain label/
            or $error =~ /^invalid name /
    ){
        $self->log_error( 'Perm XGoogleDKIM Error - ' . $error );
        $self->add_auth_header('x-google-dkim=permerror (syntax or domain error)');
    }
    else {
        $self->log_error( 'Unexpected XGoogleDKIM Error - ' . $error );
        $self->add_auth_header('x-google-dkim=temperror');
        # Fill these in as they occur, but for unknowns err on the side of caution
        # and tempfail/exit
        $self->exit_on_close();
        $self->tempfail_on_error();
    }
    return;
}

1;

__END__

=head1 NAME

  Authentication-Milter - X Google DKIM Module

=head1 DESCRIPTION

Module for validation of X-Google-DKIM signatures.

=head1 CONFIGURATION

        "XGoogleDKIM" : {                               | Config for the X-Google-DKIM Module
            "hide_none"         : 0,                    | Hide auth line if the result is 'none'
        },

=head1 SYNOPSIS

=head1 AUTHORS

Marc Bradshaw E<lt>marc@marcbradshaw.netE<gt>

=head1 COPYRIGHT

Copyright 2017

This library is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.


