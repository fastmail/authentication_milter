package Mail::Milter::Authentication::Handler::IPRev;

$VERSION = 0.1;

use strict;
use warnings;

use Mail::Milter::Authentication::Config qw{ get_config };
use Mail::Milter::Authentication::Util;
use Net::DNS;
use Net::IP;
use Sys::Syslog qw{:standard :macros};

my $CONFIG = get_config();

sub connect_callback {
    my ( $ctx, $hostname, $sockaddr_in ) = @_;
    my $priv = $ctx->getpriv();
    return if ( !$CONFIG->{'check_iprev'} );
    return if ( $priv->{'is_local_ip_address'} );
    return if ( $priv->{'is_trusted_ip_address'} );
    return if ( $priv->{'is_authenticated'} );
    my $ip_address = $priv->{'core.ip_address'};
    my $i1 = Net::IP->new( $ip_address );

    my $resolver = Net::DNS::Resolver->new;

    my $domain;
    my $result;

    # We do not consider multiple PTR records,
    # as this is not a recomended setup
    my $packet = $resolver->query( $ip_address, 'PTR' );
    #$ctx->progress();
    if ($packet) {
        foreach my $rr ( $packet->answer ) {
            next unless $rr->type eq "PTR";
            $domain = $rr->rdatastr;
        }
    }
    else {
        log_error( $ctx,
                'DNS PTR query failed for '
              . $ip_address
              . ' with '
              . $resolver->errorstring );
    }

    my $a_error;
    if ($domain) {
        my $packet = $resolver->query( $domain, 'A' );
        #$ctx->progress();
        if ($packet) {
          APACKET:
            foreach my $rr ( $packet->answer ) {
                next unless $rr->type eq "A";
                my $address = $rr->rdatastr;
                my $i2 = Net::IP->new( $address );    
        	my $is_overlap = $i1->overlaps( $i2 ) || 0;
                if ( $is_overlap == $IP_IDENTICAL ) {
                    $result = 'pass';
                    last APACKET;
                }
            }
        }
        else {
            # Don't log this right now, might be an AAAA only host.
            $a_error = 
                  'DNS A query failed for '
                  . $domain
                  . ' with '
                  . $resolver->errorstring;
        }
    }

    if ( $domain && !$result ) {
        my $packet = $resolver->query( $domain, 'AAAA' );
        #$ctx->progress();
        if ($packet) {
          APACKET:
            foreach my $rr ( $packet->answer ) {
                next unless $rr->type eq "AAAA";
                my $address = $rr->rdatastr;
                my $i2 = Net::IP->new( $address );    
        	my $is_overlap = $i1->overlaps( $i2 ) || 0;
                if ( $is_overlap == $IP_IDENTICAL ) {
                    $result = 'pass';
                    last APACKET;
                }
            }
        }
        else {
            # Log A errors now, as they become relevant if AAAA also fails.
            log_error( $ctx, $a_error ) if $a_error;
            log_error( $ctx,
                    'DNS AAAA query failed for '
                  . $domain
                  . ' with '
                  . $resolver->errorstring );
        }
    }

    if ( !$result ) {
        $result = 'fail';
    }

    if ( !$domain ) {
        $result = 'fail';
        $domain = 'NOT FOUND';
    }

    $domain =~ s/\.$//;

    if ( $result eq 'pass' ) {
        $priv->{'iprev.verified_ptr'} = $domain;
    }

    dbgout( $ctx, 'IPRevCheck', $result, LOG_DEBUG );
    my $header =
        format_header_entry( 'iprev', $result ) . ' '
      . format_header_entry( 'policy.iprev', $ip_address ) . ' ' . '('
      . format_header_comment($domain) . ')';
    add_c_auth_header( $ctx, $header );

}

1;
