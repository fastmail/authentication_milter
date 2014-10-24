package Mail::Milter::Authentication::IPRev;

$VERSION = 0.1;

use strict;
use warnings;

use Mail::Milter::Authentication::Config;

use Net::DNS;
use Net::IP;

my $CONFIG = Mail::Milter::Authentication::Config::get_config();

sub iprev_check {
    my ($ctx) = @_;

    my $priv = $ctx->getpriv();

    my $ip_address = $priv->{'ip_address'};
    my $i1 = new Net::IP( $ip_address );

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
                my $i2 = new Net::IP( $address );    
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
                my $i2 = new Net::IP( $address );    
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
        $priv->{'verified_ptr'} = $domain;
    }

    dbgout( $ctx, 'IPRevCheck', $result, LOG_DEBUG );
    my $header =
        format_header_entry( 'iprev', $result ) . ' '
      . format_header_entry( 'policy.iprev', $ip_address ) . ' ' . '('
      . format_header_comment($domain) . ')';
    add_c_auth_header( $ctx, $header );

}

sub connect_callback {
    my ( $ctx, $hostname, $sockaddr_in ) = @_;
    my $priv = $ctx->getpriv();
    $priv->{ 'is_trusted_ip_address' } = 0;
    if ( $CONFIG->{'check_iprev'} && ( $priv->{'is_local_ip_address'} == 0 ) && ( $priv->{'is_trusted_ip_address'} == 0 ) && ( $priv->{'is_authenticated'} == 0 ) ) {
        iprev_check($ctx);
    }
}

1;
