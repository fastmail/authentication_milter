package Mail::Milter::Authentication::Handler::Sanitize;
use 5.20.0;
use strict;
use warnings;
use Mail::Milter::Authentication::Pragmas;
# ABSTRACT: Handler class for Removing headers
# VERSION
use base 'Mail::Milter::Authentication::Handler';
use List::MoreUtils qw{ uniq };

sub default_config {
    return {
        'hosts_to_remove' => [ 'example.com', 'example.net' ],
        'remove_headers'  => 'yes',
        'extra_auth_results_types' => ['X-Authentication-Results'],
    };
}

sub grafana_rows {
    my ( $self ) = @_;
    my @rows;
    push @rows, $self->get_json( 'Sanitize_metrics' );
    return \@rows;
}

sub register_metrics {
    return {
        'sanitize_remove_total' => 'The number Authentication Results headers removed',
    };
}

sub is_hostname_mine {
    my ( $self, $check_hostname ) = @_;
    my $config = $self->handler_config();

    return 0 if ! defined $check_hostname;

    if ( exists( $config->{'hosts_to_remove'} ) ) {
        foreach my $remove_hostname ( @{ $config->{'hosts_to_remove'} } ) {
            if ( $check_hostname =~ m/^(.*\.)?\Q${remove_hostname}\E$/i ) {
                return 1;
            }
        }
    }

    my $hostname = $self->get_my_hostname();
    my ($check_for) = $hostname =~ /^[^\.]+\.(.*)/;
    if ( $check_hostname =~ m/^(.*\.)?\Q${check_for}\E$/i ) {
        return 1;
    }

    my $authserv_id = $self->get_my_authserv_id();
    if ( fc( $check_hostname ) eq fc( $authserv_id ) ) {
        return 1;
    }

    return 0;
}

sub remove_auth_header {
    my ( $self, $index, $type ) = @_;
    $self->metric_count( 'sanitize_remove_total', {'header'=>$type} );
    if ( !exists( $self->{'remove_auth_headers'}->{$type} ) ) {
        $self->{'remove_auth_headers'}->{$type} = [];
    }
    push @{ $self->{'remove_auth_headers'}->{$type} }, $index;
}

{
    my $headers_to_remove = {
        'x-disposition-quarantine' => { silent => 1 },
    };

    sub add_header_to_sanitize_list {
        my ( $self, $header, $silent ) = @_;
        $headers_to_remove->{lc $header} = { silent => $silent };
    }

    sub get_headers_to_remove {
        my ( $self ) = @_;
        my @headers = sort keys $headers_to_remove->%*;
        return \@headers;
    }

    sub get_remove_header_settings {
        my ($self, $key) = @_;
        return $headers_to_remove->{lc $key};
    }
}

sub envfrom_callback {
    my ( $self, $env_from ) = @_;
    $self->{'auth_result_header_index'} = {};
    $self->{'remove_auth_headers'} = {};

    my $headers = {};
    foreach my $header ( sort @{ $self->get_headers_to_remove() } ) {
        $headers->{ lc $header } = {
            'index'  => 0,
            'silent' => $self->get_remove_header_settings($header)->{silent},
        };
    }
    $self->{'header_hash'} = $headers;
}

sub header_callback {
    my ( $self, $header, $value ) = @_;
    my $config = $self->handler_config();

    return if ( $self->is_trusted_ip_address() );
    return if ( lc $config->{'remove_headers'} eq 'no' );

    my @types = ('Authentication-Results');
    if ( exists $config->{extra_auth_results_types} ) {
        push @types, $config->{extra_auth_results_types}->@*;
    }
    for my $type (uniq sort @types) {

        # Sanitize Authentication-Results headers
        if ( lc $header eq lc $type ) {
            if ( !exists $self->{'auth_result_header_index'}->{$type} ) {
                $self->{'auth_result_header_index'}->{$type} = 0;
            }
            $self->{'auth_result_header_index'}->{$type} =
              $self->{'auth_result_header_index'}->{$type} + 1;

            my $authserv_id = '';
            eval {
                my $parsed = Mail::AuthenticationResults::Parser->new()->parse($value);
                $authserv_id = $parsed->value()->value();
            };
            if ( my $error = $@ ) {
                $self->handle_exception($error);
                $self->log_error("Error parsing existing Authentication-Results header: $error");
            }

            my $remove = 0;
            my $silent = lc $config->{'remove_headers'} eq 'silent';
            if ( $authserv_id ) {
                $remove = $self->is_hostname_mine($authserv_id);
            }
            else {
                # We couldn't parse the authserv_id, removing this header is the safest option
                # Add to X-Received headers for analysis later
                $remove = 1;
                $silent = 0;
            }

            if ( $remove ) {
                $self->remove_auth_header( $self->{'auth_result_header_index'}->{$type}, $type );
                if ( ! $silent ) {
                    my $forged_header =
                      '(Received '.$type.' header removed by '
                      . $self->get_my_hostname()
                      . ')' . "\n"
                      . '    '
                      . $value;
                    $self->append_header( 'X-Received-'.$type,
                        $forged_header );
                }
            }
        }
    }

    # Sanitize other headers
    foreach my $remove_header ( sort @{ $self->get_headers_to_remove() } ) {
        next if ( lc $remove_header ne lc $header );
        $self->{'header_hash'}->{ lc $header }->{'index'} = $self->{'header_hash'}->{ lc $header }->{'index'} + 1;
        $self->metric_count( 'sanitize_remove_total', {'header'=> lc $header} );

        if ( ! $self->{'header_hash'}->{ lc $header }->{'silent'} ) {
            my $forged_header =
              '(Received ' . $remove_header . ' header removed by '
              . $self->get_my_hostname()
              . ')' . "\n"
              . '    '
              . $value;
            $self->append_header( 'X-Received-' . $remove_header,
                $forged_header );
        }
    }
}

sub eom_callback {
    my ($self) = @_;
    my $config = $self->handler_config();
    return if ( lc $config->{'remove_headers'} eq 'no' );

    if ( exists( $self->{'remove_auth_headers'} ) ) {
        foreach my $type ( sort keys $self->{'remove_auth_headers'}->%* ) {
            foreach my $index ( reverse @{ $self->{'remove_auth_headers'}->{$type} } ) {
                $self->dbgout( 'RemoveAuthHeader', "$type $index", LOG_DEBUG );
                $self->change_header( $type, $index, q{} );
            }
       }
    }

    foreach my $remove_header ( sort @{ $self->get_headers_to_remove() } ) {
        my $max_index = $self->{'header_hash'}->{ lc $remove_header }->{'index'};
        if ( $max_index ) {
            for ( my $index = $max_index; $index > 0; $index-- ) {
                $self->dbgout( 'RemoveHeader', "$remove_header $index", LOG_DEBUG );
                $self->change_header( $remove_header, $index, q{} );
            }
        }
    }
}

sub close_callback {
    my ( $self ) = @_;
    delete $self->{'remove_auth_headers'};
    delete $self->{'auth_result_header_index'};
    delete $self->{'header_hash'};
}

1;

__END__

=head1 DESCRIPTION

Remove unauthorized (forged) Authentication-Results headers from processed email.

=head1 CONFIGURATION

        "Sanitize" : {                                  | Config for the Sanitize Module
                                                        | Remove conflicting Auth-results headers from inbound mail
            "hosts_to_remove" : [                       | Hostnames (including subdomains thereof) for which we
                "example.com",                          | want to remove existing authentication results headers.
                "example.net"
            ],
            "remove_headers" : "yes",                   | Remove headers with conflicting host names (as defined above)
                                                        | "no" : do not remove
                                                        | "yes" : remove and add a header for each one
                                                        | "silent" : remove silently
                                                        | Does not run for trusted IP address connections

            "extra_auth_results_types" : [              | List of extra Authentication-Results style headers which we
                "X-Authentication-Results",             | want to treat as Authentication-Results and sanitize.
            ],
        }

