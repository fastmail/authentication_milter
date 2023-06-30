package Mail::Milter::Authentication::Handler::SPF;
use 5.20.0;
use strict;
use warnings;
use Mail::Milter::Authentication::Pragmas;
# ABSTRACT: Handler class for SPF
# VERSION
use base 'Mail::Milter::Authentication::Handler';
use Mail::SPF;

sub default_config {
    return {
        'hide_received-spf_header' => 0,
        'hide_none'                => 0,
        'best_guess'               => 0,
        'spfu_detection'           => 0,
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
    return if ( $self->is_local_ip_address() );
    return if ( $self->is_trusted_ip_address() );
    return if ( $self->is_authenticated() );

    if ( $config->{'spfu_detection'} ) {
        $self->{'spfu_from_domain'} = '';
        $self->{'spfu_chain'}       = [];
    }
    delete $self->{'spf_header'};
    delete $self->{'spf_metric'};

    my $spf_server = $self->get_object('spf_server');
    if ( ! $spf_server ) {
        $self->log_error( 'SPF Setup Error' );
        $self->{ 'spf_metric' } = 'error';
        my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'spf' )->safe_set_value( 'temperror' );
        $self->{'spf_header'} = $header;
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
        my $spf_request = Mail::SPF::Request->new(
            'versions'      => [1],
            'scope'         => $scope,
            'identity'      => $identity,
            'ip_address'    => $self->ip_address(),
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
                                'ip_address'       => $self->ip_address(),
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

        $self->{ 'spf_metric' } = $result_code;

        my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'spf' )->safe_set_value( $result_code );
        if ( $auth_domain ) {
            $header->add_child( Mail::AuthenticationResults::Header::SubEntry->new()->set_key( 'policy.authdomain' )->safe_set_value( $auth_domain ) );
        }
        $header->add_child( Mail::AuthenticationResults::Header::SubEntry->new()->set_key( 'smtp.mailfrom' )->safe_set_value( $self->get_address_from( $env_from ) ) );
        $header->add_child( Mail::AuthenticationResults::Header::SubEntry->new()->set_key( 'smtp.helo' )->safe_set_value( $self->{ 'helo_name' } ) );
        if ( !( $config->{'hide_none'} && $result_code eq 'none' ) ) {
            $self->{'spf_header'} = $header;
        }

        # Set for DMARC
        $self->{'dmarc_domain'} = $domain;
        $self->{'dmarc_scope'}  = $scope;
        $self->{'dmarc_result'} = $result_code;

        $self->dbgout( 'SPFCode', $result_code, LOG_DEBUG );

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
        $self->{'spf_header'} = $header;
        $self->{'spf_metric'} = 'error';
    }
}

sub header_callback {
    my ( $self, $header, $value ) = @_;

    return unless exists $self->{'spfu_chain'};
    return unless $self->{'dmarc_result'} eq 'pass';

    my $lc_header = lc $header;

    if ( $lc_header eq 'from') {
        my $spfu_from_domain = lc $self->get_address_from($value);
        $spfu_from_domain = $self->get_domain_from($spfu_from_domain) if $spfu_from_domain =~ /\@/;
        $self->{'spfu_from_domain'} = $spfu_from_domain;

        return;
    }

    if ( $lc_header eq 'received-spf' ||
         $lc_header eq 'x-ms-exchange-authentication-results' ||
         $lc_header eq 'arc-authentication-results' ||
         $lc_header =~ 'authentication-results$'
    ) {
        push $self->{'spfu_chain'}->@*, { header => $header, value => $value };
    }
}

sub eoh_callback {
    my ($self) = @_;
    if ( $self->{'spf_header'} ) {
        eval {
            $self->spfu_checks();
        };
        $self->handle_exception( $@ );
        $self->add_auth_header($self->{'spf_header'});
    }
    $self->metric_count( 'spf_total', { 'result' => $self->{'spf_metric'} } ) if $self->{'spf_metric'};
}

sub spfu_checks {
    my ($self) = @_;

    return unless exists $self->{'spfu_chain'};
    return unless exists $self->{'spfu_from_domain'};
    return unless $self->{'dmarc_result'} eq 'pass';
    my $dmarc_object;
    if ( $self->is_handler_loaded( 'DMARC' ) ) {
        my $dmarc_handler = $self->get_handler('DMARC');
        $dmarc_object = $dmarc_handler->get_dmarc_object();
    }

    my $spfu_from_domain = $self->{'spfu_from_domain'};
    my $dmarc_domain = $self->{'dmarc_domain'};
    if ($dmarc_object) {
        # Work with org domain if possible
        $dmarc_domain = $dmarc_object->get_organizational_domain( $dmarc_domain );
        $spfu_from_domain = $dmarc_object->get_organizational_domain( $spfu_from_domain );
    }

    return unless lc $dmarc_domain eq $spfu_from_domain;

    ENTRY:
    for my $chain_entry ( reverse $self->{'spfu_chain'}->@* ) {
        last ENTRY if $self->{'spfu_detected'};
        my $header = lc $chain_entry->{'header'};
        my $value  =    $chain_entry->{'value'};

        # Check for a Received-SPF we can parse
        if ( $header eq 'received-spf' ) {
            # We can parse the domain from the comment in most cases
            # Received-SPF: Fail (protection.outlook.com: domain of ups.com does not designate 23.26.253.8 as permitted sender) receiver=protection.outlook.com; client-ip=23.26.253.8; helo=fa83.windbound.org.uk;
            my $lc_value = lc $value;
            next ENTRY unless $lc_value =~ /^fail /;
            my ($for_value) = $lc_value =~ /^.*: domain of (\S+) .*/;
            next ENTRY unless $for_value;
            my $failed_domain = lc $self->get_address_from($for_value);
            $failed_domain = $self->get_domain_from($failed_domain) if $failed_domain =~ /\@/;
            print "$for_value ***  $failed_domain";
            $failed_domain = $dmarc_object->get_organizational_domain( $failed_domain ) if $dmarc_object;
            print "$failed_domain ******** $spfu_from_domain\n\n\n";
            if ( $failed_domain eq $spfu_from_domain ) {
                $self->{'spfu_detected'} = 1; # suspicious...
            }

            next ENTRY;
        }

        # Check for Authentication-Results style headers
        # NOTE, We look for ARC-Authentication-Results but do
        # not verify ARC here, this is used as a negative signal
        # so forgery will not be of benefit
        my $ar_object;
        if ( $header eq 'x-ms-exchange-authentication-results' ) {
            # We can parse this slightly nonstandard format into an object
            $ar_object = eval{ Mail::AuthenticationResults->parser()->parse( $value ) };
            $self->handle_exception( $@ );
            unless ( $ar_object ) {
                # Try again with a synthesized authserv id (this is often missing)
                $ar_object = eval{ Mail::AuthenticationResults->parser()->parse( "authserv.example.com; $value" ) };
                $self->handle_exception( $@ );
            }
        } elsif ( $header eq 'arc-authentication-results' ) {
            # We can parse this into an object, remove the instance
            my ($null, $arc_value) = split ';', $value, 2;
            $arc_value =~ s/^ +//;
            $ar_object = eval{ Mail::AuthenticationResults->parser()->parse( $arc_value ) };
            $self->handle_exception( $@ );
        } elsif ( $header =~ 'authentication-results$' ) {
            # We can parse this into an object, best effort with subtypes
            $ar_object = eval{ Mail::AuthenticationResults->parser()->parse( $value ) };
            $self->handle_exception( $@ );
        }
        next ENTRY unless $ar_object; # We didn't find one we could parse

        eval {
            my $spf_fail_entries = $ar_object->search({ 'isa' => 'entry', 'key' => 'spf', 'value' => 'fail' })->children();
            for my $spf_fail_entry ($spf_fail_entries->@*) {
                my $mailfrom_domain_entries = $spf_fail_entry->search({ 'isa' => 'subentry', 'key' => 'smtp.mailfrom'})->children();
                # should be only 1, but let's iterate anyway
                for my $mailfrom_domain_entry ($mailfrom_domain_entries->@*) {
                    my $mailfrom_domain = $mailfrom_domain_entry->value();
                    $mailfrom_domain = $dmarc_object->get_organizational_domain( $mailfrom_domain ) if $dmarc_object;
                    if ( lc $mailfrom_domain eq $spfu_from_domain ) {
                        $self->{'spfu_detected'} = 1; # suspicious...
                    }
                }
            }

        };
        $self->handle_exception( $@ );

    }

    if ( $self->{'spfu_detected'} ) {
        my $config = $self->handler_config();
        $self->{'spf_metric'} = 'spf_upgrade';
        if ( $config->{'spfu_detection'} == 1 ) {
            $self->{'dmarc_result'} = 'fail';
            $self->{'spf_header'}->safe_set_value( 'fail' );
            $self->{'spf_header'}->add_child( Mail::AuthenticationResults::Header::Comment->new()->safe_set_value( 'spf pass downgraded due to suspicious path' ) );
        }
        else {
            $self->{'spf_header'}->add_child( Mail::AuthenticationResults::Header::Comment->new()->safe_set_value( 'warning: aligned spf fail in history' ) );
        }
    }
}

sub close_callback {
    my ( $self ) = @_;
    delete $self->{'spfu_from_domain'};
    delete $self->{'spfu_chain'};
    delete $self->{'spfu_detected'};
    delete $self->{'spf_header'};
    delete $self->{'spf_metric'};
    delete $self->{'dmarc_domain'};
    delete $self->{'dmarc_scope'};
    delete $self->{'dmarc_result'};
    delete $self->{'failmode'};
    delete $self->{'helo_name'};
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
            "best_guess"               : 0,             | Fallback to Org domain for SPF checks
                                                        | if result is none.
            "spfu_detection"           : 0              | Add some mitigation for SPF upgrade attacks
                                                        | 0 = off (default)
                                                        | 1 = mitigate
                                                        | 2 = report only (any value other than 1)
        },

