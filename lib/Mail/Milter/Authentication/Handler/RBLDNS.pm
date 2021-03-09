package Mail::Milter::Authentication::Handler::RBLDNS;
use 5.20.0;
use strict;
use warnings;
use Mail::Milter::Authentication::Pragmas;
# ABSTRACT: Handler class for RBLDNS checks
# VERSION
use base 'Mail::Milter::Authentication::Handler';

sub default_config {
    return {
        'list1' => {
            'base_url' => 'list1.example.com',
            'default_state' => 'clean',
            'add_authresults' => 1,
            'add_header' => 'X-List1',
            'states' => {
                '127.0.0.2' => 'foo',
                '127.0.0.3' => 'bar',
                '*' => 'baz',
            }
        },
        'list2' => {
            'base_url' => 'list2.example.com',
            'default_state' => 'clean',
            'add_header' => 'X-List2',
            'states' => {
                '127.0.0.2' => 'foo',
                '127.0.0.3' => 'bar',
                '*' => 'baz',
            }
        },
    }
}

#sub grafana_rows {
#    my ( $self ) = @_;
#    my @rows;
#    push @rows, $self->get_json( 'RBLDNS_metrics' );
#    return \@rows;
#}

sub register_metrics {
    return {
        'rbldns_total' => 'The number of emails processed for RBL DNS',
    };
}

sub setup_callback {
    my ($self) = @_;
    my $config = $self->handler_config();
    foreach my $rbl ( sort keys $config->%* ) {
        $self->add_header_to_sanitize_list(lc $config->{$rbl}->{add_header}) if $config->{$rbl}->{add_header};
    }
    return;
}

sub connect_callback {
    my ( $self, $hostname, $ip ) = @_;
    my $config = $self->handler_config();

    my @states;

    foreach my $rbl ( sort keys $config->%* ) {
        my $rbl_config = $config->{$rbl};

        my $state = 'unknown';
        my $rbl_check = $self->rbl_check_ip( $ip, $rbl_config->{base_url} );

        if ( ! $rbl_check ) {
            $state = $rbl_config->{default_state};
        }
        elsif ( exists( $rbl_config->{states}->{$rbl_check} ) ) {
            $state = $rbl_config->{states}->{$rbl_check};
        }
        elsif ( exists( $rbl_config->{states}->{'*'} ) ) {
            $state = $rbl_config->{states}->{'*'};
        }

        $self->dbgout( 'RBLDNS', "$rbl:$rbl_check:$state", LOG_DEBUG );
        if ( $rbl_config->{add_authresults} ) {
            my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key($rbl)->safe_set_value( $state );
            $self->add_c_auth_header( $header );
        }
        if ( $rbl_config->{add_header} ) {
            push @states, [ $rbl_config->{add_header}, $state ];
        }
        $self->metric_count( 'rbldns_total', { rbl => $rbl, result => $state } );
    }
    $self->{'states'} = \@states;

    return;
}

sub eoh_callback {
    my ( $self ) = @_;
    foreach my $add_state ( $self->{states}->@* ) {
        $self->prepend_header( $add_state->@* );
    }
    return;
}

sub close_callback {
    my ( $self ) = @_;
    delete $self->{'states'};
    return;
}

1;

__END__

=head1 NAME

  Authentication Milter - RBLDNS Module

=head1 DESCRIPTION

Check email using RBL Lookup.

=head1 CONFIGURATION

        "RBLDNS" : {                                    | Config for the RBLDNS Module
            "key1" : {                                  | Name of lookup, will be used as Authentication-Results: key
                "base_url" : "foo.rbldns.com",          | RBLDNS to lookup against
                "default_state" : "bar",                | State to use when not listed
                "add_authresults" : 1,                  | Boolean, add authresults header for this lookup
                "add_header" : "X-RBLFoo",              | Header to be added for this lookup
                "states" : {                            | Mapping of dns results to states
                    "127.0.0.1" : "pass",               | Result to add for IP...
                    "127.0.0.2" : "maybe",              | Result to add for IP...
                    "*" : "baz"                         | Wildcard result to add for any other IP results
                }
            },
            "key2" : {                                  | Any additional lookups
                ...
            }
        },

