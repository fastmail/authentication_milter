package Mail::Milter::Authentication::Parser;
use strict;
use warnings;
use version; our $VERSION = version->declare('v1.1.7');

sub new {
    my ( $class, $auth_headers ) = @_;
    my $self = {};
    bless $self, $class;

    my @structured_headers;
    foreach my $auth_header ( sort @$auth_headers ) {
        my $acting_on;
        $self->_parse_auth_header( \$acting_on, $auth_header );
        push @structured_headers, $acting_on;
    }
    $self->{ 'structured_headers' } = \@structured_headers;

    return $self;
}

sub _parse_auth_header {
    my ($self,$acting_on,$header) = @_;

    # class entry/comment
    # key
    # value
    # children

    my $key;
    my $value;

    ( $key, $value, $header ) = $self->_parse_auth_header_entry( $header );
    ${$acting_on}->{ 'class' } = 'entry';
    ${$acting_on}->{ 'key' }   = $key;
    ${$acting_on}->{ 'value' } = $value;
    ${$acting_on}->{ 'children' } = [];

    $header = q{} if ! $header;

    my @children;

    my $comment_on = $acting_on;

    while ( length($header) > 0 ) {
        $header =~ s/^\s+//;
        if ( $header =~ /^\(/ ) {
            # We have a comment
            my $comment;
            ( $comment, $header ) = $self->_parse_auth_header_comment( $header );
            my $entry = {
                'class' => 'comment',
                'value' => $comment,
            };
            push @{ ${$comment_on}->{ 'children' } }, $entry;
        }
        else {
            # We have another entry
            ( $key, $value, $header ) = $self->_parse_auth_header_entry( $header );
            my $entry = {
                'class'    => 'entry',
                'key'      => $key,
                'value'    => $value,
                'children' => [],
            };
            $comment_on = \$entry;
            push @{ ${$acting_on}->{ 'children' } }, $entry;
        }
        $header = q{} if ! $header;
    }

    return;
}

sub _parse_auth_header_comment {
    my ($self,$remain) = @_;
    my $value = q{};
    my $depth = 0;

    while ( length $remain > 0 ) {
        my $first = substr( $remain,0,1 );
        $remain   = substr( $remain,1 );
        $value .= $first;
        if ( $first eq '(' ) {
            $depth++;
        }
        elsif ( $first eq ')' ) {
            $depth--;
            last if $depth == 0;
        }
    }

    $value =~ s/^\(//;
    $value =~ s/\)$//;

    return($value,$remain);
}

sub _parse_auth_header_entry {
    my ($self,$remain) = @_;
    my $key;
    my $value;
    ( $key, $remain )   = split( '=', $remain, 2 );
    $remain = q{} if ! defined $remain;
    ( $value, $remain ) = split( ' ', $remain, 2 );

    return ($key,$value,$remain);
}

1;
