use strict;
use warnings;

package Mail::Milter::Authentication::Handler::SPF;
use base 'Mail::Milter::Authentication::Handler';
our $VERSION = 0.5;

use Sys::Syslog qw{:standard :macros};

use Mail::SPF;

sub helo_callback {
    my ( $self, $helo_host ) = @_;
    $self->{'failmode'} = 0;
    $self->{'helo_name'} = $helo_host;
}

sub envfrom_callback {

    # On MAILFROM
    #...
    my ( $self, $env_from ) = @_;
    my $config = $self->handler_config();
    return if ( $self->is_local_ip_address() );
    return if ( $self->is_trusted_ip_address() );
    return if ( $self->is_authenticated() );

    my $spf_server = $self->get_object('spf_server');
    if ( ! $spf_server ) {
        eval {
            my $resolver = $self->get_object('resolver');
            $spf_server = Mail::SPF::Server->new(
                'hostname'     => $self->get_my_hostname(),
                'dns_resolver' => $resolver,
            );
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
        $identity = $self->{'helo_name'};
        $domain   = $identity;
        $scope    = 'helo';
    }
    else {
        $identity = $self->get_address_from($env_from);
        $domain   = $self->get_domain_from($identity);
    }

    if ( !$identity ) {
        $identity = $self->{'helo_name'};
        $domain   = $identity;
        $scope    = 'helo';
    }

    eval {
        my $spf_request = Mail::SPF::Request->new(
            'versions'      => [1],
            'scope'         => $scope,
            'identity'      => $identity,
            'ip_address'    => $self->ip_address(),
            'helo_identity' => $self->{'helo_name'},
        );

        my $spf_result = $spf_server->process($spf_request);

        my $result_code = $spf_result->code();

        my $auth_header = join( q{ },
            $self->format_header_entry( 'spf',           $result_code ),
            $self->format_header_entry( 'smtp.mailfrom', $self->get_address_from( $env_from ) ),
            $self->format_header_entry( 'smtp.helo',     $self->{'helo_name'} ),
        );
        if ( !( $config->{'hide_none'} && $result_code eq 'none' ) ) {
            $self->add_auth_header($auth_header);
        }

        # Set for DMARC
        $self->{'dmarc_domain'} = $domain;
        $self->{'dmarc_scope'}  = $scope;
        $self->{'dmarc_result'} = $result_code;

        $self->dbgout( 'SPFCode', $result_code, LOG_INFO );

        if ( !( $config->{'skip_none'} && $result_code eq 'none' ) ) {
            my $result_header = $spf_result->received_spf_header();
            my ( $header, $value ) = $result_header =~ /(.*): (.*)/;
            $self->prepend_header( $header, $value );
            $self->dbgout( 'SPFHeader', $result_header, LOG_DEBUG );
        }
    };
    if ( my $error = $@ ) {
        $self->log_error( 'SPF Error ' . $error );
        $self->add_auth_header('spf=temperror');
        $self->{'failmode'} = 1;
    }

}

sub close_callback {
    my ( $self ) = @_;
    delete $self->{'dmarc_domain'};
    delete $self->{'dmarc_scope'};
    delete $self->{'dmarc_result'};
    delete $self->{'failmode'};
    delete $self->{'helo_name'};
}

1;
