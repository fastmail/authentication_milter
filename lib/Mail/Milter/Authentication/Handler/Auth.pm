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

sub envfrom_requires {
    my ($self) = @_;
    my @requires = qw{ Core };
    return \@requires;
}

sub envfrom_callback {
    my ( $self, $env_from ) = @_;
    my $auth_name = $self->get_auth_name();
    if ($auth_name) {
        $self->dbgout( 'AuthenticatedAs', $auth_name, LOG_INFO );

        # Clear the current auth headers ( iprev and helo are already added )
        my $core_handler = $self->get_handler('Core');
        $core_handler->{'c_auth_headers'} = [];
        $core_handler->{'auth_headers'}   = [];
        $self->{'is_authenticated'}       = 1;
        $self->add_auth_header('auth=pass');
    }
}

1;
