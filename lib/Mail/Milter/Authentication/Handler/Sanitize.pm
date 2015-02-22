package Mail::Milter::Authentication::Handler::Sanitize;
use strict;
use warnings;
use base 'Mail::Milter::Authentication::Handler';
our $VERSION = 0.8;

use Sys::Syslog qw{:standard :macros};

sub is_hostname_mine {
    my ( $self, $check_hostname ) = @_;
    my $config = $self->handler_config();

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
    my ( $self, $value ) = @_;
    if ( !exists( $self->{'remove_auth_headers'} ) ) {
        $self->{'remove_auth_headers'} = [];
    }
    push @{ $self->{'remove_auth_headers'} }, $value;
    return;
}

sub envfrom_callback {
    my ( $self, $env_from ) = @_;
    delete $self->{'auth_result_header_index'};
    delete $self->{'remove_auth_headers'};
    return;
}

sub header_callback {
    my ( $self, $header, $value ) = @_;
    my $config = $self->handler_config();
    return if ( $self->is_trusted_ip_address() );
    return if ( lc $config->{'remove_headers'} eq 'no' );
    if ( $header eq 'Authentication-Results' ) {
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
    return;
}

sub eom_callback {
    my ($self) = @_;
    my $config = $self->handler_config();
    return if ( lc $config->{'remove_headers'} eq 'no' );
    if ( exists( $self->{'remove_auth_headers'} ) ) {
        foreach my $header ( reverse @{ $self->{'remove_auth_headers'} } ) {
            $self->dbgout( 'RemoveAuthHeader', $header, LOG_DEBUG );
            $self->change_header( 'Authentication-Results', $header, q{} );
        }
    }
    return;
}

sub close_callback {
    my ( $self ) = @_;
    delete $self->{'remove_auth_headers'};
    delete $self->{'auth_result_header_index'};
    return;
}

1;
