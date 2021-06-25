package Mail::Milter::Authentication::Handler::SPF;
use 5.20.0;
use strict;
use warnings;
use Mail::Milter::Authentication::Pragmas;
# ABSTRACT: Handler class for SPF
# VERSION
use base 'Mail::Milter::Authentication::Handler';
use Mail::SPF;
use Net::IP;

sub default_config {
    return {
        'hide_received-spf_header' => 0,
        'hide_none'                => 0,
        'best_guess'               => 0,
    };
}

sub grafana_rows {
    my ( $self ) = @_;
    my @rows;
    push @rows, $self->get_json( 'SPF_metrics' );
    return \@rows;
}

sub setup_callback {
    my ( $self ) = @_;

    $self->set_object_maker( 'spf_server' , sub {
        my ( $self, $name ) = @_;
        my $thischild = $self->{'thischild'};
        $self->dbgout( 'Object created', $name, LOG_DEBUG );
        my $object;
        eval {
            my $resolver = $self->get_object('resolver');
            $object = Mail::SPF::Server->new(
                'hostname'     => $self->get_my_hostname(),
                'dns_resolver' => $resolver,
            );
        };
        if ( my $error = $@ ) {
            $self->handle_exception( $error );
            $self->log_error( 'SPF Object Setup Error ' . $error );
        }
        $thischild->{'object'}->{$name} = {
            'object'  => $object,
            'destroy' => 0,
        };
    });
}

sub register_metrics {
    return {
        'spf_total'      => 'The number of emails processed for SPF',
    };
}

sub wrap_header {
    my ( $self, $value ) = @_;
    $value =~ s/ /\n    /;
    $value =~ s/\) /\)\n    /;
    $value =~ s/; /;\n    /g;
    return $value;
}

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
    $self->{'env_from'} = $env_from;
    delete $self->{'ip_header'};

    if ( ! $config->{'ip_from_header'} ) {
        $self->_process_spf();
    }
}

sub header_callback {
    my ( $self, $header, $value, $original ) = @_;
    my $config = $self->handler_config();
    return if ! $config->{'ip_from_header'};
    if ( lc $header eq $config->{'ip_from_header'} ) {
        my $ip_obj = eval{ Net::IP->new( $value ) };
        $self->{'ip_header'} = $ip_obj;
    }
}

sub eoh_callback {
    my ($self) = @_;
    my $config = $self->handler_config();
    return if ! $config->{'ip_from_header'};
    $self->_process_spf();
}

sub _process_spf {
    my ( $self ) = @_;

    my $config = $self->handler_config();
    return if ( $self->is_local_ip_address() );
    return if ( $self->is_trusted_ip_address() );
    return if ( $self->is_authenticated() );

    my $env_from = $self->{'env_from'};

    my $spf_server = $self->get_object('spf_server');
    if ( ! $spf_server ) {
        $self->log_error( 'SPF Setup Error' );
        $self->metric_count( 'spf_total', { 'result' => 'error' } );
        my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'spf' )->safe_set_value( 'temperror' );
        $self->add_auth_header($header);
        return;
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
        my $ip_address = $self->{'ip_header'} ? $self->{'ip_header'}->ip() : $self->ip_address();

        my $spf_request = Mail::SPF::Request->new(
            'versions'      => [1],
            'scope'         => $scope,
            'identity'      => $identity,
            'ip_address'    => $ip_address,
            'helo_identity' => $self->{'helo_name'},
        );

        my $spf_result = $spf_server->process($spf_request);
        my $spf_results = $self->get_object('spf_results');
        $spf_results = [] if ! $spf_results;
        push @$spf_results, $spf_result;
        $self->set_object('spf_results',$spf_results,1);

        my $result_code = $spf_result->code();

        # Best Guess SPF based on org domain
        # ToDo report this in both metrics and AR header
        my $auth_domain;
        if ( $result_code eq 'none' ) {
            if ( $config->{'best_guess'} ) {
                if ( $self->is_handler_loaded( 'DMARC' ) ) {
                    my $dmarc_handler = $self->get_handler('DMARC');
                    my $dmarc_object = $dmarc_handler->get_dmarc_object();
                    if ( $domain ) {
                        my $org_domain = eval{ $dmarc_object->get_organizational_domain( $domain ); };
                        $self->handle_exception( $@ );
                        if ( $org_domain ne $domain ) {
                            $auth_domain = $org_domain;
                            $spf_request = Mail::SPF::Request->new(
                                'versions'         => [1],
                                'scope'            => $scope,
                                'identity'         => $identity,
                                'authority_domain' => $org_domain,
                                'ip_address'       => $ip_address,
                                'helo_identity'    => $self->{'helo_name'},
                            );
                            $spf_result = $spf_server->process($spf_request);
                            my $spf_results = $self->get_object('spf_results');
                            $spf_results = [] if ! $spf_results;
                            push @$spf_results, $spf_result;
                            $self->set_object('spf_results',$spf_results,1);
                            $result_code = $spf_result->code();
                        }
                    }
                }
            }
        }

        $self->metric_count( 'spf_total', { 'result' => $result_code } );

        my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'spf' )->safe_set_value( $result_code );
        if ( $auth_domain ) {
            $header->add_child( Mail::AuthenticationResults::Header::SubEntry->new()->set_key( 'policy.authdomain' )->safe_set_value( $auth_domain ) );
        }
        $header->add_child( Mail::AuthenticationResults::Header::SubEntry->new()->set_key( 'smtp.mailfrom' )->safe_set_value( $self->get_address_from( $env_from ) ) );
        $header->add_child( Mail::AuthenticationResults::Header::SubEntry->new()->set_key( 'smtp.helo' )->safe_set_value( $self->{ 'helo_name' } ) );
        if ( !( $config->{'hide_none'} && $result_code eq 'none' ) ) {
            $self->add_auth_header($header);
        }

        # Set for DMARC
        $self->{'dmarc_domain'} = $domain;
        $self->{'dmarc_scope'}  = $scope;
        $self->{'dmarc_result'} = $result_code;

        $self->dbgout( 'SPFCode', $result_code, LOG_INFO );

        if ( !( $config->{'hide_received-spf_header'} ) ) {
            if ( !( $config->{'hide_none'} && $result_code eq 'none' ) ) {
                my $result_header = $spf_result->received_spf_header();
                my ( $header, $value ) = split( ': ', $result_header, 2 );
                $value = $self->wrap_header( $value );
                $self->prepend_header( $header, $value );
                $self->dbgout( 'SPFHeader', $result_header, LOG_DEBUG );
            }
        }
    };
    if ( my $error = $@ ) {
        $self->handle_exception( $error );
        $self->log_error( 'SPF Error ' . $error );
        $self->{'failmode'} = 1;
        my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'spf' )->safe_set_value( 'temperror' );
        $self->add_auth_header($header);
        $self->metric_count( 'spf_total', { 'result' => 'error' } );
    }
}

sub close_callback {
    my ( $self ) = @_;
    delete $self->{'dmarc_domain'};
    delete $self->{'dmarc_scope'};
    delete $self->{'dmarc_result'};
    delete $self->{'failmode'};
    delete $self->{'helo_name'};
    delete $self->{'env_from'};
    delete $self->{'ip_header'};
    $self->destroy_object('spf_results');
}

1;

__END__

=head1 DESCRIPTION

Implements the SPF standard checks.

=head1 CONFIGURATION

        "SPF" : {                                       | Config for the SPF Module
            "hide_received-spf_header" : 0,             | Do not add the "Received-SPF" header
            "hide_none"                : 0,             | Hide auth line if the result is 'none'
                                                        | if not hidden at all
            "best_guess"               : 0              | Fallback to Org domain for SPF checks
                                                        | if result is none.
        },

