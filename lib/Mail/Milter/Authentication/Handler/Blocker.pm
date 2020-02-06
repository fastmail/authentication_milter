package Mail::Milter::Authentication::Handler::Blocker;
use 5.20.0;
use strict;
use warnings;
use Mail::Milter::Authentication::Pragmas;
# ABSTRACT: Block mail based on simple rules
# VERSION
use base 'Mail::Milter::Authentication::Handler';
use TOML;

sub register_metrics {
    return {
      'blocker_total' => 'The number of emails blocked by blocker',
    };
}

sub _load_blocker_config_file {
    my ( $self, $filename ) = @_;
    my $blocker_config = {};
    if ( -e $filename ) {
        open ( my $inf, '<', $filename );
        my $body = do { local $/; <$inf> };
        close $inf;
        my ( $data, $error ) = from_toml( $body );
        if ( $error ) {
            $self->log_error( 'Invalid blocker toml file - ' . $error );
        }
        else {
            $blocker_config = $data;
        }
    }
    else {
        open ( my $outf, '>', $filename ); ## no critic
        print $outf qq(
# Authentication Milter Blocker quick config
#
# id for metrics and must be unique
# callbacks are connect,helo,envfrom,envrcpt,header
# value is applied as a regex
# percent is a percentage of matches to apply the block to
# with is the full SMTP reject string to send, 4xx or 5xx and MUST have an extended code 5.x.x or 4.x.x
# until (optional) is a unixtime after which the block will expire
#
# Example
#
# [flood]
# callback = "connect"
# value = "192\.168\.0\.1"
# with = "451 4.7.28 flood policy violation (HOTtest)"
# percent = 100
# until = 1573514783
#
# [rule2]
# callback = "connect"
# ...
);
        close $outf;
    }
    return $blocker_config;
}

sub _load_blocker_config {
    my ( $self ) = @_;
    my $config = $self->handler_config();
    return $self->{'blocker_config'} if exists $self->{'blocker_config'};

    my %blocker_config = map {
        %{ $self->_load_blocker_config_file( $_ ) }, ## no critic
    } ( @{$config->{ 'blocker_configs' } } );

    $self->{'blocker_config'} = \%blocker_config;
    return \%blocker_config;
}

sub _test_blocker {
    my ( $self, $callback, $value ) = @_;

    my $blocker_config = $self->_load_blocker_config();
    foreach my $key ( sort keys %$blocker_config ) {
        my $item = $blocker_config->{$key};
        next if $item->{'callback'} ne $callback;
        next if $item->{'until'} && $item->{'until'} < time;
        my $value_regex = $item->{'value'};
        if ( $value =~ /$value_regex/ ) {
            if ( rand(100) > $item->{'percent'} ) {
                $self->dbgout( 'Blocker', 'sampled_out ' . $key, LOG_INFO );
                $self->metric_count( 'blocker_total', { 'result' => 'sampled_out', 'id' => $key } );
            }
            elsif ( $item->{'with'} =~ /^5/ ) {
                $self->dbgout( 'Blocker', 'reject ' . $key, LOG_INFO );
                $self->metric_count( 'blocker_total', { 'result' => 'reject', 'id' => $key } );
                $self->reject_mail( $item->{'with'} );
            }
            elsif ( $item->{'with'} =~ /^4/ ) {
                $self->dbgout( 'Blocker', 'defer ' . $key, LOG_INFO );
                $self->metric_count( 'blocker_total', { 'result' => 'defer', 'id' => $key } );
                $self->defer_mail( $item->{'with'} );
            }
            else {
                $self->log_error( 'Invalid blocker entry with ' . $item->{'with'} );
            }
        }
    }
}

sub default_config {
    return {
        'blocker_configs' => [ '/tmpfs/authmilter-blocker.toml' ],
    };
}

sub connect_callback {
    my ( $self, $hostname, $ip ) = @_;
    $self->_test_blocker( 'connect', $ip->ip );
}

sub helo_callback {
    my ( $self, $helo_host ) = @_;
    $self->_test_blocker( 'helo', $helo_host );
}

sub envfrom_callback {
    my ( $self, $env_from ) = @_;
    $self->_test_blocker( 'envfrom', $env_from );
}

sub envrcpt_callback {
    my ( $self, $env_to ) = @_;
    $self->_test_blocker( 'envrcpt', $env_to );
}

sub header_callback {
    my ( $self, $header, $value ) = @_;
    $self->_test_blocker( 'header', "$header: $value" );
}

sub close_callback {
    my ($self) = @_;
    delete $self->{'blocker_config'};
}

1;

__END__

=head1 DESCRIPTION

Defer/Reject mail based on simple rules.

=head1 CONFIGURATION

        "Blocker" : {                                                       |
            'blocker_configs' => [ '/tmpfs/authmilter-blocker.toml' ],      | A list of blocker configs to test against.
        }                                                                   |

