package Mail::Milter::Authentication::Handler::Sanitize;

$VERSION = 0.2;

use strict;
use warnings;

use Mail::Milter::Authentication::Config qw{ get_config };
use Mail::Milter::Authentication::Util;

use Sys::Syslog qw{:standard :macros};

my $CONFIG = get_config();

sub remove_auth_header {
    my ( $ctx, $value ) = @_;
    my $priv = $ctx->getpriv();
    if ( !exists( $priv->{'saniize.remove_auth_headers'} ) ) {
        $priv->{'sanitize.remove_auth_headers'} = [];
    }
    push @{ $priv->{'sanitize.remove_auth_headers'} }, $value;
}
    
sub envfrom_callback {
    my ( $ctx, $env_from ) = @_;
    my $priv = $ctx->getpriv();
    delete $priv->{'sanitize.auth_result_header_index'};
    delete $priv->{'sanitize.remove_auth_headers'};
}

sub header_callback {
    my ( $ctx, $header, $value ) = @_;
    my $priv = $ctx->getpriv();
    return if ( $priv->{'is_trusted_ip_address'} ); 
    return if ( lc $CONFIG->{'remove_headers'} eq 'no' ) ;
    if ( $header eq 'Authentication-Results' ) {
        if ( !exists $priv->{'sanitize.auth_result_header_index'} ) {
            $priv->{'sanitize.auth_result_header_index'} = 0;
        }
        $priv->{'sanitize.auth_result_header_index'} =
          $priv->{'sanitize.auth_result_header_index'} + 1;
        my ($domain_part) = $value =~ /(.*);/;
        $domain_part =~ s/ +//g;
        if ( is_hostname_mine( $ctx, $domain_part ) ) {
            remove_auth_header( $ctx, $priv->{'sanitize.auth_result_header_index'} );
            if ( lc $CONFIG->{'remove_headers'} ne 'silent' ) {
                my $forged_header = '(The following Authentication Results header was removed by ' . get_my_hostname($ctx) . "\n"
                                  . '    as the supplied domain conflicted with its own)' . "\n"
                                  . '    ' . $value;
                append_header( $ctx, 'X-Invalid-Authentication-Results', $forged_header );
            }
        }
    }
}

sub eom_callback {
    my ( $ctx ) = @_;
    my $priv = $ctx->getpriv();
    return if ( lc $CONFIG->{'remove_headers'} eq 'no' ) ;
    if ( exists( $priv->{'sanitize.remove_auth_headers'} ) ) {
        foreach my $header ( reverse @{ $priv->{'sanitize.remove_auth_headers'} } ) {
            dbgout( $ctx, 'RemoveAuthHeader', $header, LOG_DEBUG );
            $ctx->chgheader( 'Authentication-Results', $header, q{} );
        }
    }
}

1;
