package Mail::Milter::Authentication::Protocol;

use strict;
use warnings;

our $VERSION = 0.4;

use Mail::Milter::Authentication::Config qw{ get_config };
use Mail::Milter::Authentication::Constants qw { :all };

sub smfis_continue {
    return SMFIS_CONTINUE;
}

sub smfis_tempfail {
    return SMFIS_TEMPFAIL;
}

sub smfis_reject {
    return SMFIS_REJECT;
}

sub smfis_discard {
    return SMFIS_DISCARD;
}

sub smfis_accept {
    return SMFIS_ACCEPT;
}

sub write_packet {
    my ( $self, $type, $data ) = @_;
    my $wire = $self->{'wire'};
    $wire->write_packet( $type, $data );
}

sub add_header {
    my ( $self, $key, $value ) = @_;
    my $wire = $self->{'wire'};
    my $CONFIG = get_config();
    return if $CONFIG->{'dryrun'};
    $wire->add_header( $key, $value );
}

sub insert_header {
    my ( $self, $index, $key, $value ) = @_;
    my $wire = $self->{'wire'};
    my $CONFIG = get_config();
    return if $CONFIG->{'dryrun'};
    $wire->insert_header( $index, $key, $value );
}

sub change_header {
    my ( $self, $key, $index, $value ) = @_;
    my $wire = $self->{'wire'};
    my $CONFIG = get_config();
    return if $CONFIG->{'dryrun'};
    $wire->change_header( $key, $index, $value );
}

1;
