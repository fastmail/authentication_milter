#!/usr/bin/perl

use strict;
use warnings;
use Net::DNS;
use Data::Dumper;

my $domain = $ARGV[0];

my $resolver = Net::DNS::Resolver->new();

my $queries = [
  [ q{}, 'A' ],
  [ q{}, 'NS' ],
  [ q{}, 'AAAA' ],
  [ q{}, 'MX' ],
  [ '_dmarc.', 'TXT' ],
  [ q{}, 'TXT' ],
];

foreach my $query ( @$queries ) {
    my $domain_part = $query->[0] . $domain;
    my $type_part   = $query->[1];
    $resolver->query( $domain_part, $type_part );
}

print Dumper( $resolver->get_static_data() );

1;

package # hide from pause
    Net::DNS::Resolver;

use MIME::Base64;

my $static_data = {};
sub get_static_data {
    return $static_data;
}

sub send { ## no critic
    my ( $self ) = shift;
    my @args = @_;
    return $self->cache_lookup( 'send', @args );
}

sub query {
    my ( $self ) = shift;
    my @args = @_;
    return $self->cache_lookup( 'query', @args );
}

sub search {
    my ( $self ) = shift;
    my @args = @_;
    return $self->cache_lookup( 'search', @args );
}

sub cache_lookup {
    my $self = shift;
    my $type = shift;
    my @args = @_;
    my $key = join(":" , $type, @args);
    my $return;

    if ( $type eq 'search' ) {
        $return = $self->SUPER::search(@args);
    }
    elsif ( $type eq 'send' ) {
        $return = $self->SUPER::send(@args);
    }
    elsif ( $type eq 'query' ) {
        $return = $self->SUPER::query(@args);
    }
    else {
        die "Unknown lookup type $type\n";
    }

    {
        my $string = q{};
        if ( $return ) {
            $string = encode_base64( $return->data(), q{} );
        }
        $static_data->{ $key } = [ $string, $self->errorstring() ];
    }

    return $return;
}


1;

