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

