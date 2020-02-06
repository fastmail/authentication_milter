package Mail::Milter::Authentication::Handler::Sanitize;
use 5.20.0;
use strict;
use warnings;
use Mail::Milter::Authentication::Pragmas;
# ABSTRACT: Handler class for Removing headers
# VERSION
use base 'Mail::Milter::Authentication::Handler';

sub default_config {
    return {
        'hosts_to_remove' => [ 'example.com', 'example.net' ],
        'remove_headers'  => 'yes',
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

    my $hostname = $self->get_my_hostname();
    my ($check_for) = $hostname =~ /^[^\.]+\.(.*)/;

    if ( exists( $config->{'hosts_to_remove'} ) ) {
        foreach my $remove_hostname ( @{ $config->{'hosts_to_remove'} } ) {
            if (
                substr( lc $check_hostname, ( 0 - length($remove_hostname) ) ) eq
                lc $remove_hostname )
            {
                return 1;
            }
        }
    }

    if (
        substr( lc $check_hostname, ( 0 - length($check_for) ) ) eq
        lc $check_for )
    {
        return 1;
    }
    return 0;
}

sub remove_auth_header {
    my ( $self, $index ) = @_;
    $self->metric_count( 'sanitize_remove_total', {'header'=>'authentication-results'} );
    if ( !exists( $self->{'remove_auth_headers'} ) ) {
        $self->{'remove_auth_headers'} = [];
    }
    push @{ $self->{'remove_auth_headers'} }, $index;
    return;
}

sub get_headers_to_remove {
    my ( $self ) = @_;
    my @headers = qw{ X-Disposition-Quarantine };
    return \@headers;
}

sub envfrom_callback {
    my ( $self, $env_from ) = @_;
    delete $self->{'auth_result_header_index'};
    delete $self->{'remove_auth_headers'};

    my $headers = {};
    foreach my $header ( sort @{ $self->get_headers_to_remove() } ) {
        $headers->{ lc $header } = {
            'index'  => 0,
            'silent' => 1,
        };
    }
    $self->{'header_hash'} = $headers;

    return;
}

sub header_callback {
    my ( $self, $header, $value ) = @_;
    my $config = $self->handler_config();

    return if ( $self->is_trusted_ip_address() );
    return if ( lc $config->{'remove_headers'} eq 'no' );

    # Sanitize Authentication-Results headers
    if ( lc $header eq 'authentication-results' ) {
        if ( !exists $self->{'auth_result_header_index'} ) {
            $self->{'auth_result_header_index'} = 0;
        }
        $self->{'auth_result_header_index'} =
          $self->{'auth_result_header_index'} + 1;
        my ($domain_part) = $value =~ /^([^;]*);/;
        $domain_part =~ s/ +//g;
        if ( $self->is_hostname_mine($domain_part) ) {
            $self->remove_auth_header( $self->{'auth_result_header_index'} );
            if ( lc $config->{'remove_headers'} ne 'silent' ) {
                my $forged_header =
                  '(Received Authentication-Results header removed by '
                  . $self->get_my_hostname()
                  . ')' . "\n"
                  . '    '
                  . $value;
                $self->append_header( 'X-Received-Authentication-Results',
                    $forged_header );
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

    return;
}

sub eom_callback {
    my ($self) = @_;
    my $config = $self->handler_config();
    return if ( lc $config->{'remove_headers'} eq 'no' );

    if ( exists( $self->{'remove_auth_headers'} ) ) {
        foreach my $index ( reverse @{ $self->{'remove_auth_headers'} } ) {
            $self->dbgout( 'RemoveAuthHeader', $index, LOG_DEBUG );
            $self->change_header( 'Authentication-Results', $index, q{} );
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

    return;
}

sub close_callback {
    my ( $self ) = @_;
    delete $self->{'remove_auth_headers'};
    delete $self->{'auth_result_header_index'};
    delete $self->{'header_hash'};
    return;
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
            "remove_headers" : "yes"                    | Remove headers with conflicting host names (as defined above)
                                                        | "no" : do not remove
                                                        | "yes" : remove and add a header for each one
                                                        | "silent" : remove silently
                                                        | Does not run for trusted IP address connections
        }

