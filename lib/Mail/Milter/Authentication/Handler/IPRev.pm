package Mail::Milter::Authentication::Handler::IPRev;
use strict;
use warnings;
use base 'Mail::Milter::Authentication::Handler';
use version; our $VERSION = version->declare('v1.1.2');

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
    my $domain;
    my $result;
    my $detail;

    # We do not consider multiple PTR records,
    # as this is not a recomended setup
    my $packet = $resolver->query( $ip_address, 'PTR' );
    if ($packet) {
        foreach my $rr ( $packet->answer ) {
            next unless $rr->type eq "PTR";
            $domain = $rr->rdatastr;
        }
    }
    else {
        $self->_dns_error( 'PTR', $ip_address, $resolver->errorstring );
    }

    my $a_error = q{};
    if ($domain) {
        my $packet = $resolver->query( $domain, 'A' );
        if ($packet) {
          APACKET:
            foreach my $rr ( $packet->answer ) {
                next unless $rr->type eq "A";
                my $address    = $rr->rdatastr;
                my $i2         = Net::IP->new($address);
                my $is_overlap = $i1->overlaps($i2) || 0;
                if ( $is_overlap == $IP_IDENTICAL ) {
                    $result = 'pass';
                    last APACKET;
                }
            }
        }
        else {
            # Don't log this right now, might be an AAAA only host.
            $a_error = $resolver->errorstring;
        }


        if ( $a_error eq 'NXDOMAIN' ) {
            $self->_dns_error( 'A', $domain, $a_error );
            $detail = 'NXDOMAIN';
        }
        else {
            if ( !$result ) {
                my $packet = $resolver->query( $domain, 'AAAA' );
                if ($packet) {
                  APACKET:
                    foreach my $rr ( $packet->answer ) {
                        next unless $rr->type eq "AAAA";
                        my $address    = $rr->rdatastr;
                        my $i2         = Net::IP->new($address);
                        my $is_overlap = $i1->overlaps($i2) || 0;
                        if ( $is_overlap == $IP_IDENTICAL ) {
                            $result = 'pass';
                            last APACKET;
                        }
                    }
                }
                else {
                    # Log A errors now, as they become relevant if AAAA also fails.
                    $self->_dns_error( 'A', $domain, $a_error ) if $a_error;
                    $self->_dns_error( 'AAAA', $domain, $resolver->errorstring );
                }
            }
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
        $self->{'verified_ptr'} = $domain;
    }

    my $comment = $domain;
    $comment .= " $detail" if $detail;

    $self->dbgout( 'IPRevCheck', $result, LOG_DEBUG );
    my $header =
        $self->format_header_entry( 'iprev',        $result ) . ' '
      . $self->format_header_entry( 'policy.iprev', $ip_address ) . ' ' . '('
      . $self->format_header_comment($comment) . ')';
    $self->add_c_auth_header($header);

    return;
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


