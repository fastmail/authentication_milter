package Mail::Milter::Authentication::Handler::Auth;
use 5.20.0;
use strict;
use warnings;
use Mail::Milter::Authentication::Pragmas;
use base 'Mail::Milter::Authentication::Handler';
# VERSION

use Sys::Syslog qw{:standard :macros};
use Mail::AuthenticationResults::Header::Entry;
use Mail::AuthenticationResults::Header::SubEntry;
use Mail::AuthenticationResults::Header::Comment;

sub default_config {
    return {};
}

sub grafana_rows {
    my ( $self ) = @_;
    my @rows;
    push @rows, $self->get_json( 'Auth_metrics' );
    return \@rows;
}

sub register_metrics {
    return {
        'authenticated_connect_total' => 'The number of connections from an authenticated host',
    };
}

sub pre_loop_setup {
    my ( $self ) = @_;
    my $protocol = Mail::Milter::Authentication::Config::get_config()->{'protocol'};
    if ( $protocol ne 'milter' ) {
        warn 'The Auth handler only works with the milter protocol';
    }
    return;
}

sub get_auth_name {
    my ($self) = @_;
    my $name = $self->get_symbol('{auth_authen}');
    return $name;
}

sub connect_callback {
    my ( $self, $hostname, $ip ) = @_;
    $self->{'is_authenticated'} = 0;
    return;
}

sub envfrom_callback {
    my ( $self, $env_from ) = @_;
    my $auth_name = $self->get_auth_name();
    if ($auth_name) {
        $self->dbgout( 'AuthenticatedAs', $auth_name, LOG_INFO );
        # Clear the current auth headers ( iprev and helo may already be added )
        # ToDo is this a good idea?
        my $top_handler = $self->get_top_handler();
        $top_handler->{'c_auth_headers'} = [];
        $top_handler->{'auth_headers'}   = [];
        $self->{'is_authenticated'}       = 1;
        $self->metric_count( 'authenticated_connect_total' );
        my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'auth' )->safe_set_value( 'pass' );
        $self->add_auth_header( $header );
    }
    return;
}

sub close_callback {
    my ( $self ) = @_;
    delete $self->{'is_authenticated'};
    return;
}

1;

__END__

=head1 DESCRIPTION

Module which identifies email that was sent via an authenticated connection.

=head1 CONFIGURATION

No configuration options exist for this handler.

