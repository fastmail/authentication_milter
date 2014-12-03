package Mail::Milter::Authentication::Handler::Auth;

use strict;
use warnings;

our $VERSION = 0.4;

use base 'Mail::Milter::Authentication::Handler::Generic';

use Sys::Syslog qw{:standard :macros};

sub callbacks {
    return {
        'connect' => 20,
        'helo'    => undef,
        'envfrom' => 30,
        'envrcpt' => undef,
        'header'  => undef,
        'eoh'     => undef,
        'body'    => undef,
        'eom'     => undef,
        'abort'   => undef,
        'close'   => undef,
    };
}

sub get_auth_name {
    my ($self) = @_;
    my $name = $self->get_symval('{auth_authen}');
    return $name;
}

sub connect_callback {
    my ( $self, $hostname, $sockaddr_in ) = @_;
    $self->{'is_authenticated'} = 0;
}

sub envfrom_callback {
    my ( $self, $env_from ) = @_;
    my $CONFIG = $self->config();
    return if ( !$CONFIG->{'check_auth'} );
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
