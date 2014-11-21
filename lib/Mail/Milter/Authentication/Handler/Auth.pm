package Mail::Milter::Authentication::Handler::Auth;

use strict;
use warnings;

our $VERSION = 0.3;

use Mail::Milter::Authentication::Config qw{ get_config };
use Mail::Milter::Authentication::Util;

use Sys::Syslog qw{:standard :macros};

sub get_auth_name {
    my ($ctx) = @_;
    my $name = get_symval( $ctx, '{auth_authen}' );
    return $name;
}

sub connect_callback {
    my ( $ctx, $hostname, $sockaddr_in ) = @_;
    my $priv = $ctx->getpriv();
    $priv->{ 'is_authenticated' } = 0;
} 

sub envfrom_callback {
    my ( $ctx, $env_from ) = @_;
    my $CONFIG = get_config();
    my $priv = $ctx->getpriv();
    return if ( !$CONFIG->{'check_auth'} );
    my $auth_name = get_auth_name( $ctx );
    if ( $auth_name ) {
        dbgout( $ctx, 'AuthenticatedAs', $auth_name, LOG_INFO );
        # Clear the current auth headers ( iprev and helo are already added )
        $priv->{'core.c_auth_headers'} = [];
        $priv->{'core.auth_headers'} = [];
        $priv->{'is_authenticated'} = 1;
        add_auth_header( $ctx, 'auth=pass' );
    }
}

1;
