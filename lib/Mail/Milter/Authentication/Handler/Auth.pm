package Mail::Milter::Authentication::Handler::Auth;

use strict;
use warnings;

our $VERSION = 0.5;

use base 'Mail::Milter::Authentication::Handler::Generic';

use Sys::Syslog qw{:standard :macros};

sub get_auth_name {
    my ($self) = @_;
    my $name = $self->get_symbol('{auth_authen}');
    return $name;
}

sub connect_callback {
    my ( $self, $hostname, $sockaddr_in ) = @_;
    $self->{'is_authenticated'} = 0;
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
        $self->add_auth_header('auth=pass');
    }
}

sub close_callback {
    my ( $self ) = @_;
    delete $self->{'is_authenticated'};
}

1;
