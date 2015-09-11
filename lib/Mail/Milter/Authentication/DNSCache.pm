package Mail::Milter::Authentication::DNSCache;
use strict;
use warnings;
use version; our $VERSION = version->declare('v1.0.2');

# Package to override Net::DNS::Resolver and add cache features

1;

package # hide from pause
    Net::DNS::Resolver;

use JSON;
use Data::Dumper;
use MIME::Base64;

## no critic [Subroutines::RequireArgUnpacking]

{
    my $global_cached_data   = {};
    my $global_cached_errors = {};
    my $global_errors_index  = 0;

    sub new {
        my $class = shift;
        my %args = @_;
        my $self = $class->SUPER::new( @_ );

        $self->{'cached_data'}         = $global_cached_data;
        $self->{'cached_errors'}       = $global_cached_errors;
        $self->{'cached_errors_index'} = $global_errors_index;
        $self->{'cache_timeout'}       = $args{'cache_timeout'}     || 120;
        $self->{'cache_error_limit'}   = $args{'cache_error_limit'} || 3;
        $self->{'static_cache'}        = $args{'static_cache'}      || undef;
        return $self;
    }
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

sub cache_cleanup {
    my ($self) = @_;
    return if $self->{'cache_timeout'} == 0;
    my $cached_data   = $self->{'cached_data'};
    my $cached_errors = $self->{'cached_errors'};
    my $cache_timeout = $self->{'cache_timeout'};
    foreach my $key ( keys %{$cached_errors} ) {
        my $cached = $cached_errors->{$key};
        if ( $cached->{'stamp'} < time - $cache_timeout ) {
            delete $cached_errors->{$key};
        }
    }
    foreach my $key ( keys %{$cached_data} ) {
        my $cached = $cached_data->{$key};
        if ( $cached->{'stamp'} < time - $cache_timeout ) {
            delete $cached_data->{$key};
        }
    }
    return;
}

sub cache_lookup {
    my $self = shift;
    my $type = shift;
    my @args = @_;
    my $key = join(":" , $type, @args);
    my $cached_errors = $self->{'cached_errors'};
    my $cached_data   = $self->{'cached_data'};
    my $cache_timeout = $self->{'cache_timeout'};
    my $static_cache  = $self->{'static_cache'};

    $self->cache_cleanup();

    my $return;

    if ( exists ( $cached_data->{$key} ) ) {
        my $cached = $cached_data->{$key};
        my $data   = $cached->{'data'};
        my $error  = $cached->{'error'};
        $self->errorstring( $error );
        return $data;
    }

    if ( exists ( $static_cache->{$key} ) ) {
        my $packet = $static_cache->{$key}->[0];
        my $error  = $static_cache->{$key}->[1];
        my $data   = decode_base64( $packet );
        my $return_packet = Net::DNS::Packet->new( \$data );
        $self->errorstring( $error );

        # Cache the object.
        if ( $self->{'cache_timeout'} != 0 ) {
            $cached_data->{$key} = {
                'stamp' => time + 31536000,
                'data'  => $return_packet,
                'error' => $error,
            };
        }

        return $return_packet;
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

    if ( $self->{'cache_timeout'} != 0 ) {

        if ( ! $cacheable ) {
            my $errors_found = 0;
            foreach my $item ( keys %{$cached_errors} ) {
                my $cached = $cached_errors->{$item};
                if ( $cached->{'key'} eq $key ) {
                    $errors_found++;
                }
            }
            $cacheable = 1 if $errors_found > $self->{'cache_error_limit'};
        }
    
        if ( $cacheable ) {
            $cached_data->{$key} = {
                'stamp' => time,
                'data'  => $return,
                'error' => $self->errorstring,
            };

## This block can be used to generate a static cache entry for
## entry into the config.
#            {
#                my $string = q{};
#                if ( $return ) {
#                    $string = encode_base64( $return->data(), q{} );
#                }
#                my $static_data = join( q{},
#                    '        ',
#                    '"',
#                    $key,
#                    '" : [ "',
#                    $string,
#                    '", "',
#                    $self->errorstring(),
#                    '" ],',
#                    "\n",
#                );
#                warn $static_data;
#            }

        }
        else {
            $cached_errors->{ $self->{'cached_errors_index'}++ } = {
                'key'   => $key,
                'stamp' => time,
                'data'  => $return,
                'error' => $self->errorstring,
            };
        }

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

=item I<new( %ARGS )>

New instance of object, please see Net::DNS::Resolver for details

=over

=item cache_timeout

Number of seconds a cached result will be valid for.

Default 120

=item cache_error_limit

Unsuccessful results are not immediately cached, however if we have greater than cache_error_limit
lookups for a given record within the cache_timeout time we will cache an unsuccessful result and
return that for subsequent lookups within the cache_timeout time.

Default 3

=back

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

Copyright 2015

This library is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.

