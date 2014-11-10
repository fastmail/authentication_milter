package Mail::Milter::Authentication::Handler::SenderID;

$VERSION = 0.2;

use strict;
use warnings;

use Mail::Milter::Authentication::Config qw{ get_config };
use Mail::Milter::Authentication::Util;

use Sys::Syslog qw{:standard :macros};

use Mail::SPF;

my $CONFIG = get_config();

sub envfrom_callback {
    my ( $ctx, $env_from ) = @_;
    my $priv = $ctx->getpriv();
    return if ( !$CONFIG->{'check_senderid'} );
    return if ( $priv->{'is_local_ip_address'} );
    return if ( $priv->{'is_trusted_ip_address'} );
    return if ( $priv->{'is_authenticated'} );
    delete $priv->{'senderid.from_header'};
}

sub header_callback {
    my ( $ctx, $header, $value ) = @_;
    my $priv = $ctx->getpriv();
    return if ( !$CONFIG->{'check_senderid'} );
    return if ( $priv->{'is_local_ip_address'} );
    return if ( $priv->{'is_trusted_ip_address'} );
    return if ( $priv->{'is_authenticated'} );
    if ( $header eq 'From' ) {
        $priv->{'senderid.from_header'} = $value;
    }
}

sub eoh_callback {
    my ($ctx) = @_;
    my $priv = $ctx->getpriv();
    return if ( !$CONFIG->{'check_senderid'} );
    return if ( $priv->{'is_local_ip_address'} );
    return if ( $priv->{'is_trusted_ip_address'} );
    return if ( $priv->{'is_authenticated'} );

    my $spf_server;
    eval {
        $spf_server =
          Mail::SPF::Server->new( 'hostname' => get_my_hostname($ctx) );
    };
    if ( my $error = $@ ) {
        log_error( $ctx, 'SenderID Setup Error ' . $error );
        add_auth_header( $ctx, 'senderid=temperror' );
        return;
    }

    my $scope = 'pra';

    my $identity = get_address_from( $priv->{'senderid.from_header'} );

    eval {
        my $spf_request = Mail::SPF::Request->new(
            'versions'      => [2],
            'scope'         => $scope,
            'identity'      => $identity,
            'ip_address'    => $priv->{'core.ip_address'},
            'helo_identity' => $priv->{'core.helo_name'},
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
}

1;
