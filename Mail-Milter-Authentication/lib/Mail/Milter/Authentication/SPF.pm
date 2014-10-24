package Mail::Milter::Authentication::SPF;

$VERSION = 0.1;

use strict;
use warnings;

use Mail::Milter::Authentication::Config qw{ get_config };
use Mail::Milter::Authentication::Util;

use Sys::Syslog qw{:standard :macros};

use Mail::SPF;

my $CONFIG = get_config();

sub spf_check {
    my ($ctx) = @_;

    my $priv = $ctx->getpriv();

    my $spf_server = $priv->{'spf_obj'};

    my $scope = 'mfrom';

    my $identity = get_address_from( $priv->{'mail_from'} );
    my $domain   = get_domain_from($identity);

    if ( !$identity ) {
        $identity = $priv->{'helo_name'};
        $domain   = $identity;
        $scope    = 'helo';
    }

    eval {
        my $spf_request = Mail::SPF::Request->new(
            'versions'      => [1],
            'scope'         => $scope,
            'identity'      => $identity,
            'ip_address'    => $priv->{'ip_address'},
            'helo_identity' => $priv->{'helo_name'},
        );

        my $spf_result = $spf_server->process($spf_request);
        #$ctx->progress();

        my $result_code = $spf_result->code();

        my $auth_header = join( q{ },
            format_header_entry( 'spf',           $result_code ),
            format_header_entry( 'smtp.mailfrom', get_address_from( $priv->{'mail_from'} ) ),
            format_header_entry( 'smtp.helo',     $priv->{'helo_name'} ),
        );
        if ( ! ( $CONFIG->{'check_spf'} == 2 && $result_code eq 'none' ) ) {
            add_auth_header( $ctx, $auth_header );
        }

        if ( $CONFIG->{'check_dmarc'} && ( $priv->{'is_local_ip_address'} == 0 ) && ( $priv->{'is_trusted_ip_address'} == 0 ) && ( $priv->{'is_authenticated'} == 0 ) ) {
            if ( my $dmarc = $priv->{'dmarc_obj'} ) {
                $dmarc->spf(
                    'domain' => $domain,
                    'scope'  => $scope,
                    'result' => $result_code,
                );
            }
        }

        dbgout( $ctx, 'SPFCode', $result_code, LOG_INFO );

        if ( ! ( $CONFIG->{'check_spf'} == 2 && $result_code eq 'none' ) ) {
            my $result_header = $spf_result->received_spf_header();
            my ( $header, $value ) = $result_header =~ /(.*): (.*)/;
            prepend_header( $ctx, $header, $value );
            dbgout( $ctx, 'SPFHeader', $result_header, LOG_DEBUG );
        }
    };
    if ( my $error = $@ ) {
        log_error( $ctx, 'SPF Error ' . $error );
        add_auth_header( $ctx, 'spf=temperror' );
    }

    return;
}

sub senderid_check {
    my ($ctx) = @_;

    my $priv = $ctx->getpriv();

    my $spf_server = $priv->{'spf_obj'};

    my $scope = 'pra';

    my $identity = get_address_from( $priv->{'from_header'} );

    eval {
        my $spf_request = Mail::SPF::Request->new(
            'versions'      => [2],
            'scope'         => $scope,
            'identity'      => $identity,
            'ip_address'    => $priv->{'ip_address'},
            'helo_identity' => $priv->{'helo_name'},
        );

        my $spf_result = $spf_server->process($spf_request);
        #$ctx->progress();

        my $result_code = $spf_result->code();
        dbgout( $ctx, 'SenderIdCode', $result_code, LOG_INFO );

        if ( ! ( $CONFIG->{'check_senderid'} == 2 && $result_code eq 'none' ) ) {
            my $auth_header = format_header_entry( 'senderid', $result_code );
            add_auth_header( $ctx, $auth_header );
#my $result_local  = $spf_result->local_explanation;
#my $result_auth   = $spf_result->can( 'authority_explanation' ) ? $spf_result->authority_explanation() : '';
            my $result_header = $spf_result->received_spf_header();
            my ( $header, $value ) = $result_header =~ /(.*): (.*)/;
            prepend_header( $ctx, $header, $value );
            dbgout( $ctx, 'SPFHeader', $result_header, LOG_DEBUG );
        }
    };
    if ( my $error = $@ ) {
        log_error( $ctx, 'SENDERID Error ' . $error );
        add_auth_header( $ctx, 'senderid=temperror' );
        return;
    }

    return;
}

sub envfrom_callback {
    # On MAILFROM
    #...
    my ( $ctx, $env_from ) = @_;
    my $priv = $ctx->getpriv();
    my $spf_server;
    return if ( !$CONFIG->{'check_spf'} );
    return if ( $priv->{'is_local_ip_address'} );
    return if ( $priv->{'is_trusted_ip_address'} );
    return if ( $priv->{'is_authenticated'} );
    eval {
        $spf_server =
          Mail::SPF::Server->new( 'hostname' => get_my_hostname($ctx) );
    };
    if ( my $error = $@ ) {
        log_error( $ctx, 'SPF Setup Error ' . $error );
        add_auth_header( $ctx, 'spf=temperror' );
        $spf_server = undef;
    }
    $priv->{'spf_obj'} = $spf_server;
    
    spf_check($ctx);
}

sub eoh_callback {
    my ($ctx) = @_;
    dbgout( $ctx, 'CALLBACK', 'EOH', LOG_DEBUG );
    my $priv = $ctx->getpriv();
    return if ( !$CONFIG->{'check_senderid'} );
    return if ( $priv->{'is_local_ip_address'} );
    return if ( $priv->{'is_trusted_ip_address'} );
    return if ( $priv->{'is_authenticated'} );

    senderid_check($ctx);
}

1;
