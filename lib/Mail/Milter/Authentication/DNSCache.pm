package Mail::Milter::Authentication::DNSCache;

use strict;
use warnings;

our $VERSION = 0.5;

# Package to override Net::DNS::Resolver and add cache features

1;

package Net::DNS::Resolver;

use strict;
use warnings;

use Mail::Milter::Authentication::Config qw{ get_config };

sub new {
    my $class = shift;
    my $self = $class->SUPER::new( @_ );

    my $CONFIG = get_config();

    $self->{'cache_data'}    = {};
    $self->{'cache_timeout'} = $CONFIG->{'dns_cache_timeout'} || 240;
    return $self;
}

sub send {
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

sub cache_cleanup {
    my ($self) = @_;
    my $cache_data    = $self->{'cache_data'};
    my $cache_timeout = $self->{'cache_timeout'};
    foreach my $key ( keys %{$cache_data} ) {
        my $cached = $cache_data->{$key};
        if ( $cached->{'stamp'} < time - $cache_timeout ) {
            delete $cache_data->{$key};
        }
    }
}

sub cache_lookup {
    my $self = shift;
    my $type = shift;
    my @args = @_;
    my $key = join(":" , $type, @args);
    my $cache_data    = $self->{'cache_data'};
    my $cache_timeout = $self->{'cache_timeout'};
    $self->cache_cleanup();
    my $return;
    if ( exists ( $cache_data->{$key} ) ) {
        my $cached = $cache_data->{$key};
        my $data  = $cached->{'data'};
        my $error = $cached->{'error'};
        $self->errorstring( $error );
        return $data;
    }
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
    my $cacheable;
    if ( $return ) { $cacheable = 1; }
    if ( $self->errorstring eq 'NOERROR'  ) { $cacheable = 1; }
    if ( $self->errorstring eq 'NXDOMAIN' ) { $cacheable = 1; }
    
    if ( $cacheable ) {
        $cache_data->{$key} = {
            'stamp' => time,
            'data'  => $return,
            'error' => $self->errorstring,
        };
    }
    return $return;
}

1;

__END__

=head1 NAME

Mail::Milter::Authentication::DNSCache - DNS Cache methods for Authentication Milter

=head1 DESCRIPTION

Methods in the Net::DNS::Resolver namespace to implement a basic cache of
DNS lookups.

=head1 SYNOPSIS

A basic cache of successful lookups made by the resolver.

=head1 CONSTRUCTOR

=over

=item I<new()>

New instance of object, please see Net::DNS::Resolver for details

=back

=head1 METHODS

=over

=item I<send()>

Override send method with a cache

=item I<query()>

Override query method with a cache

=item I<search()>

Override search method with a cache

=item I<cache_cleanup()>

Remove old items from the cache

=item I<cache_lookup($type,@args)>

Perform a lookup (send, query, or search) and cache the results

=item I<child_init_hook()>

Hook which runs after forking, sets up per process items.

=item I<process_request()>

Hook which runs for each request, sets up per request items and processes the request.

=back

=head1 DEPENDENCIES

  Net::DNS::Resolver

=head1 AUTHORS

Marc Bradshaw E<lt>marc@marcbradshaw.netE<gt>

=head1 COPYRIGHT

Copyright 2014

This library is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.

