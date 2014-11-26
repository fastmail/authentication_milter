package Mail::Milter::Authentication::Protocol;

use strict;
use warnings;

our $VERSION = 0.4;

use Sendmail::PMilter qw { :all };

sub smfis_continue {
    return SMFIS_CONTINUE;
}

sub write_packet {
    my ( $self, $type, $data ) = @_;
    my $ctx = $self->{'ctx'};
    $ctx->write_packet( $type, $data );
}

sub add_header {
    my ( $self, $key, $value ) = @_;
    my $ctx = $self->{'ctx'};
    $ctx->addheader( $key, $value );
}

sub insert_header {
    my ( $self, $index, $key, $value ) = @_;
    $self->write_packet( 'i',
        pack( 'N', $index )
        . $key
        . "\0"
        . $value
        . "\0"
    );
}

sub chgheader {
    my ( $self, $key, $index, $value ) = @_;
    my $ctx = $self->{'ctx'};
    $ctx->chgheader( $key, $index, $value );
}

sub get_symval {
    my ( $self, $key ) = @_;
    my $ctx = $self->{'ctx'};
    my $val = $ctx->getsymval($key);
    return $val if defined($val);

    # We didn't find it?
    # PMilter::Context fails to get the queue id from postfix as it is
    # not searching symbols for the correct code. Rewrite this here.
    # Intend to patch PMilter to fix this.
    my $symbols = $ctx->{'symbols'};    ## Internals, here be dragons!
    foreach my $code ( keys %{$symbols} ) {
        $val = $symbols->{$code}->{$key};
        return $val if defined($val);
    }
    return;
}


1;
