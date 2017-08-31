package Mail::Milter::Authentication::Handler::IPRev;
use strict;
use warnings;
use base 'Mail::Milter::Authentication::Handler';
use version; our $VERSION = version->declare('v1.1.3');

use Net::DNS;
use Net::IP;
use Sys::Syslog qw{:standard :macros};

sub default_config {
    return {};
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
    return;
}

sub connect_requires {
    my ($self) = @_;
    my @requires = qw{ LocalIP TrustedIP Auth };
    return \@requires;
}

sub connect_callback {
    my ( $self, $hostname, $ip ) = @_;
    return if ( $self->is_local_ip_address() );
    return if ( $self->is_trusted_ip_address() );
    return if ( $self->is_authenticated() );
    my $ip_address = $self->ip_address();
    my $i1         = $ip;
    my $resolver = $self->get_object('resolver');

    my $lookup_limit = 10;
    # Make this a config item

    my $ptr_list = {};
    my @error_list;

    my $packet = $resolver->query( $ip_address, 'PTR' );
    $lookup_limit--;
    if ($packet) {
        foreach my $rr ( $packet->answer ) {
            next unless $rr->type eq "PTR";
            $ptr_list->{ $rr->rdatastr } = [];
        }
    }

    if ( $resolver->errorstring() ) {
        $self->_dns_error( 'PTR', $ip_address, $resolver->errorstring );
        push @error_list, 'Error ' . $resolver->errorstring() . " looking up $ip_address PTR";
    }

    if ( ! keys %$ptr_list ) {
        push @error_list, "NOT FOUND";
    }

    DOMAINLOOKUP:
    foreach my $domain ( sort keys %$ptr_list ) {

        my $ip_list = [];

        if ( $ip_address =~ /:/ ) {
            # We are living in the future!

            my $errors6;
            my $errors4;
            ( $lookup_limit, $ip_list, $errors6 ) = $self->_address_for_domain( 'AAAA', $domain, $lookup_limit );
            if ( ! @$ip_list ) {
                # We got nothing, try ip4
                ( $lookup_limit, $ip_list, $errors4 ) = $self->_address_for_domain( 'A', $domain, $lookup_limit );
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
            ( $lookup_limit, $ip_list, $errors4 ) = $self->_address_for_domain( 'A', $domain, $lookup_limit );
            if ( ! @$ip_list ) {
                # We got nothing, try ip6
                ( $lookup_limit, $ip_list, $errors6 ) = $self->_address_for_domain( 'AAAA', $domain, $lookup_limit );
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
        my $header =
            $self->format_header_entry( 'iprev',        'fail' ) . ' '
          . $self->format_header_entry( 'policy.iprev', $ip_address ) . ' ' . '('
          . $self->format_header_comment($comment) . ')';
        $self->add_c_auth_header($header);
    }
    else {
        # We have a pass
        my $comment = join( ',', @match_list );
        $self->{'verified_ptr'} = $comment;
        $self->dbgout( 'IPRevCheck', "pass - $comment", LOG_DEBUG );
        my $header =
            $self->format_header_entry( 'iprev',        'pass' ) . ' '
          . $self->format_header_entry( 'policy.iprev', $ip_address ) . ' ' . '('
          . $self->format_header_comment($comment) . ')';
        $self->add_c_auth_header($header);
    }

    return;
}

sub _address_for_domain {
    my ( $self, $type, $domain, $lookup_limit ) = @_;

    my @fwd_errors;
    my @ip_list;

    my $resolver = $self->get_object('resolver');

    $lookup_limit--;
    if ( $lookup_limit <= 0 ) {
        return ( 0, \@ip_list, [ 'Lookup limit reached' ] );
    }
    my $packet = $resolver->query( $domain, $type );

    if ($packet) {
        foreach my $rr ( $packet->answer ) {
            next unless $rr->type eq $type;
            my $address = $rr->rdatastr;
            push @ip_list, $address;
        }
    }

    if ( $resolver->errorstring() ) {
        $self->_dns_error( $type, $domain, $resolver->errorstring );
        push @fwd_errors, 'Error ' . $resolver->errorstring() . " looking up $domain $type";
    }

    return ( $lookup_limit, \@ip_list, \@fwd_errors );
}

sub close_callback {
    my ( $self ) = @_;
    delete $self->{'verified_ptr'};
    return;
}

1;

__END__

=head1 NAME

  Authentication-Milter - IPRev Module

=head1 DESCRIPTION

Check reverse IP lookups.

=head1 CONFIGURATION

No configuration options exist for this handler.

=head1 SYNOPSIS

=head1 AUTHORS

Marc Bradshaw E<lt>marc@marcbradshaw.netE<gt>

=head1 COPYRIGHT

Copyright 2017

This library is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.


