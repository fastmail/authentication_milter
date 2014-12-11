package Mail::Milter::Authentication::Handler::ReturnOK;

use strict;
use warnings;

our $VERSION = 0.5;

use base 'Mail::Milter::Authentication::Handler::Generic';

use Net::DNS;
use Sys::Syslog qw{:standard :macros};

sub _check_address {
    my ( $self, $address, $type ) = @_;

    my $resolver = $self->get_object('resolver');
 
    my $email = $self->get_address_from( $address );

    if ( ! $email ) {
        $self->log_error( "ReturnOK: No Address for $type" );
    }

    my $domain = $self->get_domain_from( $email );

    if ( ! $domain ) {
        $self->log_error( "ReturnOK: No Domain for $type from $address" );
    }

    my $result = 'fail';
    my @details;

    push @details, "type=$type";

    my $has_mx   = 0;
    my $has_a    = 0;
    my $has_aaaa = 0;
    my $packet;

    $packet = $resolver->query( $domain, 'MX' );
    if ($packet) {
        foreach my $rr ( $packet->answer ) {
            next unless $rr->type eq "MX";
            $has_mx = 1;
            $result = 'pass';
            last;
        }
    }
    else {
        my $error = $resolver->errorstring;
        if ( $error ) {
            push @details, $self->format_header_entry('mx.error', $error);
        }
        else {
            push @details, 'mx.error=none';
        }
    }

    if ( ! $has_mx ) {
        $packet = $resolver->query( $domain, 'A' );
        if ($packet) {
            foreach my $rr ( $packet->answer ) {
                next unless $rr->type eq "A";
                $has_a = 1;
                $result = 'warn';
                last;
            }
        }
        else {
            my $error = $resolver->errorstring;
            if ( $error ) {
                push @details, $self->format_header_entry('a.error', $error);
            }
            else {
                push @details, 'a.error=none';
            }
        }

        $packet = $resolver->query( $domain, 'AAAA' );
        if ($packet) {
            foreach my $rr ( $packet->answer ) {
                next unless $rr->type eq "AAAA";
                $has_a = 1;
                $result = 'warn';
                last;
            }
        }
        else {
            my $error = $resolver->errorstring;
            if ( $error ) {
                push @details, $self->format_header_entry('aaaa.error', $error);
            }
            else {
                push @details, 'aaaa.error=none';
            }
        }
    }

    $self->dbgout( 'ReturnOKCheck', "$type: $result", LOG_DEBUG );
    my $header = join( ' ',
        $self->format_header_entry( 'x-returnok', $result ),
        @details,
    );
    
    $self->add_auth_header($header);

}

sub envfrom_callback {
    my ( $self, $env_from ) = @_;
    $env_from = q{} if $env_from eq '<>';
    $self->_check_address( $env_from, 'smtp' );
}

sub header_callback {
    my ( $self, $header, $value ) = @_;
    if ( $header eq 'From' ) {
        $self->_check_address( $value, 'header' );
    }
}

1;
