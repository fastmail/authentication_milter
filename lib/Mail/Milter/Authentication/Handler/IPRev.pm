package Mail::Milter::Authentication::Handler::IPRev;
use 5.20.0;
use strict;
use warnings;
use Mail::Milter::Authentication::Pragmas;
# ABSTRACT: Handler class for IPRev
# VERSION
use base 'Mail::Milter::Authentication::Handler';
use Net::DNS;
use Net::IP;

sub default_config {
    return {};
}

sub register_metrics {
    return {
        'iprev_total' => 'The number of emails processed for IPRev',
    };
}

sub grafana_rows {
    my ( $self ) = @_;
    my @rows;
    push @rows, $self->get_json( 'IPRev_metrics' );
    return \@rows;
}

sub _dns_error {
    my ( $self, $type, $data, $error ) = @_;
    if ( $error eq 'NXDOMAIN' ) {
        $self->dbgout( "DNS $type  Lookup", "$data gave $error", LOG_DEBUG );
    }
    elsif ( $error eq 'NOERROR' ) {
        $self->dbgout( "DNS $type  Lookup", "$data gave $error", LOG_DEBUG );
    }
    else {
        # Could be SERVFAIL or something else
        $self->log_error(
            'DNS ' . $type . ' query failed for '
          . $data
          . ' with '
          . $error );
    }
}

sub connect_requires {
    my ($self) = @_;
    my @requires = qw{ LocalIP TrustedIP };
    return \@requires;
}

sub connect_callback {
    my ( $self, $hostname, $ip ) = @_;
    return if ( $self->is_local_ip_address() );
    return if ( $self->is_trusted_ip_address() );
    my $ip_address = $self->ip_address();
    my $i1         = $ip;
    my $resolver = $self->get_object('resolver');

    my $lookup_limit = 10;
    # Make this a config item

    my $ptr_list = {};
    my @error_list;

    my @cname_hosts;

    my $packet = $resolver->query( $ip_address, 'PTR' );
    $lookup_limit--;
    if ($packet) {
        foreach my $rr ( $packet->answer ) {
            if ( $rr->type eq "CNAME" ) {
                push @cname_hosts, $rr->rdatastr;
                push @error_list, 'Found CNAME in PTR response';
            }
            if ( $rr->type eq "PTR" ) {
                $ptr_list->{ $rr->rdatastr } = [];
            }
        }
    }

    if ( $resolver->errorstring() ) {
        $self->_dns_error( 'PTR', $ip_address, $resolver->errorstring );
        push @error_list, 'Error ' . $resolver->errorstring() . " looking up $ip_address PTR" if ( $resolver->errorstring() ne 'unknown error or no error' );
    }

    foreach my $cname_host ( @cname_hosts ) {
        my $packet = $resolver->query( $cname_host, 'PTR' );
        $lookup_limit--;
        if ($packet) {
            foreach my $rr ( $packet->answer ) {
                #if ( $rr->type eq "CNAME" ) {
                # NO! We only follow the first level CNAMES
                # Because anything more is probably busted anyway
                #}
                if ( $rr->type eq "PTR" ) {
                    $ptr_list->{ $rr->rdatastr } = [];
                }
            }
        }
        if ( $resolver->errorstring() ) {
            $self->_dns_error( 'PTR', $cname_host, $resolver->errorstring );
            push @error_list, 'Error ' . $resolver->errorstring() . " looking up $cname_host PTR" if ( $resolver->errorstring() ne 'unknown error or no error' );
        }
        last; # Because multiple CNAMES for a given record is also busted
    }

    if ( ! keys %$ptr_list ) {
        push @error_list, "NOT FOUND";
    }

    my @lookup_list = sort keys %$ptr_list;
    DOMAINLOOKUP:
    foreach my $domain ( @lookup_list ) {
        my $ip_list = [];
        my $cname;

        if ( $ip_address =~ /:/ ) {
            # We are living in the future!

            my $errors6;
            my $errors4;
            ( $lookup_limit, $ip_list, $errors6, $cname ) = $self->_address_for_domain( 'AAAA', $domain, $lookup_limit );
            if ( $cname ) {
                push @error_list, 'Found CNAME in AAAA response';
                ( $lookup_limit, $ip_list, $errors6, $cname ) = $self->_address_for_domain( 'AAAA', $cname, $lookup_limit );
                if ( ! @$ip_list ) {
                    ( $lookup_limit, $ip_list, $errors6, $cname ) = $self->_address_for_domain( 'A', $cname, $lookup_limit );
                }
            }
            if ( ! @$ip_list ) {
                # We got nothing, try ip4
                ( $lookup_limit, $ip_list, $errors4, $cname ) = $self->_address_for_domain( 'A', $domain, $lookup_limit );
                if ( $cname ) {
                    push @error_list, 'Found CNAME in A response';
                    ( $lookup_limit, $ip_list, $errors6, $cname ) = $self->_address_for_domain( 'AAAA', $cname, $lookup_limit );
                    if ( ! @$ip_list ) {
                        ( $lookup_limit, $ip_list, $errors6, $cname ) = $self->_address_for_domain( 'A', $cname, $lookup_limit );
                    }
                }
            }
            if ( ! @$ip_list ) {
                foreach my $error ( @$errors4 ) {
                    push @error_list, "Error $error looking up $domain A";
                }
                foreach my $error ( @$errors6 ) {
                    push @error_list, "Error $error looking up $domain AAAA";
                }
            }

        }
        else {

            my $errors6;
            my $errors4;
            ( $lookup_limit, $ip_list, $errors4, $cname ) = $self->_address_for_domain( 'A', $domain, $lookup_limit );
            if ( $cname ) {
                push @error_list, 'Found CNAME in A response';
                ( $lookup_limit, $ip_list, $errors6, $cname ) = $self->_address_for_domain( 'A', $cname, $lookup_limit );
                if ( ! @$ip_list ) {
                    ( $lookup_limit, $ip_list, $errors6, $cname ) = $self->_address_for_domain( 'AAAA', $cname, $lookup_limit );
                }
            }
            if ( ! @$ip_list ) {
                # We got nothing, try ip6
                ( $lookup_limit, $ip_list, $errors6, $cname ) = $self->_address_for_domain( 'AAAA', $domain, $lookup_limit );
                if ( $cname ) {
                    push @error_list, 'Found CNAME in AAAA response';
                    ( $lookup_limit, $ip_list, $errors6, $cname ) = $self->_address_for_domain( 'A', $cname, $lookup_limit );
                    if ( ! @$ip_list ) {
                        ( $lookup_limit, $ip_list, $errors6, $cname ) = $self->_address_for_domain( 'AAAA', $cname, $lookup_limit );
                    }
                }
            }
            if ( ! @$ip_list ) {
                foreach my $error ( @$errors4 ) {
                    push @error_list, "Error $error looking up $domain A" if ( $resolver->errorstring() ne 'unknown error or no error' );
                }
                foreach my $error ( @$errors6 ) {
                    push @error_list, "Error $error looking up $domain AAAA" if ( $resolver->errorstring() ne 'unknown error or no error' );
                }
            }

        }

        $ptr_list->{ $domain } = $ip_list;

    }

    my @match_list;
    foreach my $domain ( sort keys %$ptr_list ) {
        foreach my $address ( sort @{ $ptr_list->{ $domain } } ) {
            my $i2 = Net::IP->new($address);
            my $is_overlap = $i1->overlaps($i2) || 0;
            if ( $is_overlap == $IP_IDENTICAL ) {
                $domain =~ s/\.$//;
                push @match_list, $domain;
            }
        }
    }

    if ( ! @match_list ) {
        # Failed to match IP against looked up domains
        my $comment = join( ',', @error_list );
        $self->dbgout( 'IPRevCheck', "fail - $comment", LOG_DEBUG );
        my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'iprev' )->safe_set_value( 'fail' );
        $header->add_child( Mail::AuthenticationResults::Header::SubEntry->new()->set_key( 'smtp.remote-ip' )->safe_set_value( $ip_address ) );
        $header->add_child( Mail::AuthenticationResults::Header::Comment->new()->safe_set_value( $comment ) );
        $self->add_c_auth_header($header);
        $self->metric_count( 'iprev_total', { 'result' => 'fail'} );
    }
    else {
        # We have a pass
        my $comment = join( ',', @match_list );
        $self->{'verified_ptr'} = $comment;
        $self->dbgout( 'IPRevCheck', "pass - $comment", LOG_DEBUG );
        my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'iprev' )->safe_set_value( 'pass' );
        $header->add_child( Mail::AuthenticationResults::Header::SubEntry->new()->set_key( 'smtp.remote-ip' )->safe_set_value( $ip_address ) );
        $header->add_child( Mail::AuthenticationResults::Header::Comment->new()->safe_set_value( $comment ) );
        $self->add_c_auth_header($header);
        $self->metric_count( 'iprev_total', { 'result' => 'pass'} );
    }
}

sub _address_for_domain {
    my ( $self, $type, $domain, $lookup_limit ) = @_;

    my @fwd_errors;
    my @ip_list;
    my $cname;

    my $resolver = $self->get_object('resolver');

    $lookup_limit--;
    if ( $lookup_limit <= 0 ) {
        return ( 0, \@ip_list, [ 'Lookup limit reached' ] );
    }
    my $packet = $resolver->query( $domain, $type );

    if ($packet) {
        foreach my $rr ( $packet->answer ) {
            if (  lc $rr->type eq 'cname' ) {
                $cname = $rr->rdatastr;
                # Multiple CNAMES are broken, but we don't check for that
                # We just take the last one we found
            }
            if ( lc $rr->type eq lc $type ) {
                push @ip_list, $rr->rdatastr;
            }
        }
    }

    if ( $resolver->errorstring() ) {
        $self->_dns_error( $type, $domain, $resolver->errorstring );
        push @fwd_errors, 'Error ' . $resolver->errorstring() . " looking up $domain $type";
    }

    return ( $lookup_limit, \@ip_list, \@fwd_errors, $cname );
}

sub close_callback {
    my ( $self ) = @_;
    delete $self->{'verified_ptr'};
}

1;

__END__

=head1 DESCRIPTION

Check reverse IP lookups.

=head1 CONFIGURATION

No configuration options exist for this handler.

