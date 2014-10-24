package Mail::Milter::Authentication::Sanitize;

$VERSION = 0.1;

use strict;
use warnings;

use Mail::Milter::Authentication::Config qw{ get_config };
use Mail::Milter::Authentication::Util;

use Sys::Syslog qw{:standard :macros};

my $CONFIG = get_config();

sub remove_auth_header {
    my ( $ctx, $value ) = @_;
    my $priv = $ctx->getpriv();
    if ( !exists( $priv->{'remove_auth_headers'} ) ) {
        $priv->{'remove_auth_headers'} = [];
    }
    push @{ $priv->{'remove_auth_headers'} }, $value;
}

sub header_callback {
    my ( $ctx, $header, $value ) = @_;
    my $priv = $ctx->getpriv();
    return if ( $priv->{'is_trusted_ip_address'} ); 
    if ( $header eq 'Authentication-Results' ) {
        if ( !exists $priv->{'auth_result_header_index'} ) {
            $priv->{'auth_result_header_index'} = 0;
        }
        $priv->{'auth_result_header_index'} =
          $priv->{'auth_result_header_index'} + 1;
        my ($domain_part) = $value =~ /(.*);/;
        $domain_part =~ s/ +//g;
        if ( is_hostname_mine( $ctx, $domain_part ) ) {
            remove_auth_header( $ctx, $priv->{'auth_result_header_index'} );
            my $forged_header = '(The following Authentication Results header was removed by ' . get_my_hostname($ctx) . "\n"
                              . '    as the supplied domain conflicted with its own)' . "\n"
                              . '    ' . $value;
            append_header( $ctx, 'X-Invalid-Authentication-Results', $forged_header );
        }
    }
}

sub eom_callback {
    my ( $ctx ) = @_;
    my $priv = $ctx->getpriv();
    if ( exists( $priv->{'remove_auth_headers'} ) ) {
        foreach my $header ( reverse @{ $priv->{'remove_auth_headers'} } ) {
            dbgout( $ctx, 'RemoveAuthHeader', $header, LOG_DEBUG );
            $ctx->chgheader( 'Authentication-Results', $header, q{} );
        }
    }
}

1;
