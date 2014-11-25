package Mail::Milter::Authentication::Handler::Sanitize;

use strict;
use warnings;

our $VERSION = 0.3;

use base 'Mail::Milter::Authentication::Handler::Generic';

use Sys::Syslog qw{:standard :macros};

sub remove_auth_header {
    my ( $self, $value ) = @_;
    my $priv = $self->{'ctx'}->getpriv();
    if ( !exists( $priv->{'saniize.remove_auth_headers'} ) ) {
        $priv->{'sanitize.remove_auth_headers'} = [];
    }
    push @{ $priv->{'sanitize.remove_auth_headers'} }, $value;
}
    
sub envfrom_callback {
    my ( $self, $env_from ) = @_;
    my $priv = $self->{'ctx'}->getpriv();
    delete $priv->{'sanitize.auth_result_header_index'};
    delete $priv->{'sanitize.remove_auth_headers'};
}

sub header_callback {
    my ( $self, $header, $value ) = @_;
    my $CONFIG = $self->config();
    my $priv = $self->{'ctx'}->getpriv();
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
        if ( $self->is_hostname_mine( $domain_part ) ) {
            $self->remove_auth_header( $priv->{'sanitize.auth_result_header_index'} );
            if ( lc $CONFIG->{'remove_headers'} ne 'silent' ) {
                my $forged_header = '(The following Authentication Results header was removed by ' . $self->get_my_hostname() . "\n"
                                  . '    as the supplied domain conflicted with its own)' . "\n"
                                  . '    ' . $value;
                $self->append_header( 'X-Invalid-Authentication-Results', $forged_header );
            }
        }
    }
}

sub eom_callback {
    my ( $self ) = @_;
    my $CONFIG = $self->config();
    my $priv = $self->{'ctx'}->getpriv();
    return if ( lc $CONFIG->{'remove_headers'} eq 'no' ) ;
    if ( exists( $priv->{'sanitize.remove_auth_headers'} ) ) {
        foreach my $header ( reverse @{ $priv->{'sanitize.remove_auth_headers'} } ) {
            $self->dbgout( 'RemoveAuthHeader', $header, LOG_DEBUG );
            $self->{'ctx'}->chgheader( 'Authentication-Results', $header, q{} );
        }
    }
}

1;
