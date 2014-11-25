package Mail::Milter::Authentication::Handler::Auth;

use strict;
use warnings;

our $VERSION = 0.3;

use base 'Mail::Milter::Authentication::Handler::Generic';

use Mail::Milter::Authentication::Config qw{ get_config };
use Mail::Milter::Authentication::Util;

use Sys::Syslog qw{:standard :macros};

sub get_auth_name {
    my ($self) = @_;
    my $name = get_symval( $self->{'ctx'}, '{auth_authen}' );
    return $name;
}

sub connect_callback {
    my ( $self, $hostname, $sockaddr_in ) = @_;
    my $priv = $self->{'ctx'}->getpriv();
    $priv->{ 'is_authenticated' } = 0;
} 

sub envfrom_callback {
    my ( $self, $env_from ) = @_;
    my $CONFIG = get_config();
    my $priv = $self->{'ctx'}->getpriv();
    return if ( !$CONFIG->{'check_auth'} );
    my $auth_name = $self->get_auth_name();
    if ( $auth_name ) {
        $self->dbgout( 'AuthenticatedAs', $auth_name, LOG_INFO );
        # Clear the current auth headers ( iprev and helo are already added )
        $priv->{'core.c_auth_headers'} = [];
        $priv->{'core.auth_headers'} = [];
        $priv->{'is_authenticated'} = 1;
        add_auth_header( $self->{'ctx'}, 'auth=pass' );
    }
}

1;
