package Mail::Milter::Authentication::Protocol;

use strict;
use warnings;

our $VERSION = 0.4;

use Mail::Milter::Authentication::Constants qw { :all };

sub smfis_continue {
    return SMFIS_CONTINUE;
}

sub write_packet {
    my ( $self, $type, $data ) = @_;
    my $wire = $self->{'wire'};
    $wire->write_packet( $type, $data );
}

sub add_header {
    my ( $self, $key, $value ) = @_;
    my $wire = $self->{'wire'};
    $wire->add_header( $key, $value );
}

sub insert_header {
    my ( $self, $index, $key, $value ) = @_;
    my $wire = $self->{'wire'};
    $wire->insert_header( $index, $key, $value );
}

## TODO rename chgheader in code to change_header
sub chgheader {
    my ( $self, $key, $index, $value ) = @_;
    my $wire = $self->{'wire'};
    $wire->change_header( $key, $index, $value );
}

1;
