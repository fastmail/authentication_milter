package Mail::Milter::Authentication::Handler::SPF;

use strict;
use warnings;

our $VERSION = 0.5;

use base 'Mail::Milter::Authentication::Handler::Generic';

use Sys::Syslog qw{:standard :macros};

use Mail::SPF;

sub callbacks {
    return {
        'connect' => undef,
        'helo'    => undef,
        'envfrom' => 50,
        'envrcpt' => undef,
        'header'  => undef,
        'eoh'     => undef,
        'body'    => undef,
        'eom'     => undef,
        'abort'   => undef,
        'close'   => undef,
    };
}

sub envfrom_callback {

    # On MAILFROM
    #...
    my ( $self, $env_from ) = @_;
    my $CONFIG = $self->module_config();
    return if ( $self->is_local_ip_address() );
    return if ( $self->is_trusted_ip_address() );
    return if ( $self->is_authenticated() );

    my $spf_server = $self->get_object('spf_server');
    if ( ! $spf_server ) {
        eval {
            $spf_server = Mail::SPF::Server->new( 'hostname' => $self->get_my_hostname() );
        };
        if ( my $error = $@ ) {
            $self->log_error( 'SPF Setup Error ' . $error );
            $self->add_auth_header('spf=temperror');
            return;
        }
        $self->set_object('spf_server',$spf_server);
    }


    my $scope = 'mfrom';

    $env_from = q{} if $env_from eq '<>';

    my $identity;
    my $domain;
    if ( !$env_from ) {
        $identity = $self->helo_name();
        $domain   = $identity;
        $scope    = 'helo';
    }
    else {
        $identity = $self->get_address_from($env_from);
        $domain   = $self->get_domain_from($identity);
    }

    if ( !$identity ) {
        $identity = $self->helo_name();
        $domain   = $identity;
        $scope    = 'helo';
    }

    eval {
        my $spf_request = Mail::SPF::Request->new(
            'versions'      => [1],
            'scope'         => $scope,
            'identity'      => $identity,
            'ip_address'    => $self->ip_address(),
            'helo_identity' => $self->helo_name(),
        );

        my $spf_result = $spf_server->process($spf_request);

        my $result_code = $spf_result->code();

        my $auth_header = join( q{ },
            $self->format_header_entry( 'spf',           $result_code ),
            $self->format_header_entry( 'smtp.mailfrom', $self->get_address_from( $env_from ) ),
            $self->format_header_entry( 'smtp.helo',     $self->helo_name() ),
        );
        if ( !( $CONFIG->{'hide_none'} && $result_code eq 'none' ) ) {
            $self->add_auth_header($auth_header);
        }

        if ( my $dmarc = $self->get_object('dmarc')
            && ( $self->is_local_ip_address() == 0 )
            && ( $self->is_trusted_ip_address() == 0 )
            && ( $self->is_authenticated() == 0 ) )
        {
            $dmarc->spf(
                'domain' => $domain,
                'scope'  => $scope,
                'result' => $result_code,
            );
        }

        $self->dbgout( 'SPFCode', $result_code, LOG_INFO );

        if ( !( $CONFIG->{'skip_none'} && $result_code eq 'none' ) ) {
            my $result_header = $spf_result->received_spf_header();
            my ( $header, $value ) = $result_header =~ /(.*): (.*)/;
            $self->prepend_header( $header, $value );
            $self->dbgout( 'SPFHeader', $result_header, LOG_DEBUG );
        }
    };
    if ( my $error = $@ ) {
        $self->log_error( 'SPF Error ' . $error );
        $self->add_auth_header('spf=temperror');
    }

}

1;
