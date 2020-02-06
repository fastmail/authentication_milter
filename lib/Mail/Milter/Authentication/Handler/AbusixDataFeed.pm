package Mail::Milter::Authentication::Handler::AbusixDataFeed;
use 5.20.0;
use strict;
use warnings;
use Mail::Milter::Authentication::Pragmas;
use base 'Mail::Milter::Authentication::Handler';
# ABSTRACT: Send data to Abusix
## VERSION

use English qw{ -no_match_vars };
use Sys::Syslog qw{:standard :macros};
use Mail::DataFeed::Abusix;

sub default_config {
    return {
        'feed_name' => 'name_of_feed',
        'feed_dest' => 'server:port',
        'feed_key'  => 'this_is_a_secret',
        'listening_port' => '25',
    };
}

sub helo_callback {
    my ( $self, $helo_host ) = @_;
    $self->{'helo_name'} = $helo_host;
    return;
}

sub envfrom_callback {
    my ($self, $from) = @_;
    my $config = $self->handler_config();

    $self->{ 'abusix_feed' } = Mail::DataFeed::Abusix->new(
        'feed_name' => $config->{ 'feed_name' },
        'feed_dest' => $config->{ 'feed_dest' },
        'feed_key'  => $config->{ 'feed_key' },
    );
    $self->{ 'abusix_feed' }->mail_from_domain( $self->get_domain_from( $from ) );
    $self->{ 'abusix_feed' }->helo( $self->{ 'helo_name' } );
    $self->{ 'abusix_feed' }->port( $config->{ 'listening_port' } );
    $self->{ 'abusix_feed' }->ip_address( $self->ip_address() );

    delete $self->{ 'first_received' };

    my $resolver = $self->get_object('resolver');
    my @rdns;
    my $packet = $resolver->query( $self->ip_address(), 'PTR' );
    if ($packet) {
        foreach my $rr ( $packet->answer ) {
            # We do not consider CNAMES here
            if ( $rr->type eq "PTR" ) {
                my $rdatastr = $rr->rdatastr;
                $rdatastr =~ s/\r//g;
                $rdatastr =~ s/\n//g;
                push @rdns, $rdatastr;
            }
        }
    }
    $self->{ 'abusix_feed' }->reverse_dns( join( ',', @rdns ) );

    return;
}

sub header_callback {
    my ( $self, $header, $value ) = @_;
    return if defined $self->{ 'first_received' };
    return if lc $header ne 'received';
    my $protocol = Mail::Milter::Authentication::Config::get_config()->{'protocol'};
    return if $protocol ne 'smtp';

    $self->{ 'first_received' } = $value;
    return;
}

sub eoh_callback {
    my ( $self ) = @_;
    if ( $self->is_handler_loaded('TLS') ) {
        $self->{ 'abusix_feed' }->used_tls( $self->is_encrypted() || 0 ); # Explicit 0 over undef if TLS handler is loaded
    }
    $self->{ 'abusix_feed' }->used_auth( $self->is_authenticated() );
    if ( defined $self->{ 'first_received' } ) {
        my $used_smtp  = $self->{ 'first_received' } =~ / with SMTP/;
        my $used_esmtp = $self->{ 'first_received' } =~ / with ESMTP/;
        if ( $used_smtp xor $used_esmtp ) {
            # Filters line noise!
            $self->{ 'abusix_feed' }->used_esmtp( 1 ) if $used_esmtp;
            $self->{ 'abusix_feed' }->used_esmtp( 0 ) if $used_smtp;
        }
    }
    $self->{ 'abusix_feed' }->send();
    return;
}


sub close_callback {
    my ( $self ) = @_;

    delete $self->{'helo_name'};
    delete $self->{'abusix_feed'};
    delete $self->{ 'first_received' };
    return;
}

1;

__END__

=head1 NAME

  Authentication Milter - AbusixDataFeed Module

=head1 DESCRIPTION

  Send data back to Abusix

=head1 CONFIGURATION

        "AbusixDataFeed" : {
            "feed_name"        : "id",
            "feed_dest"        : "server:port",
            "feed_key"         : "secret",
            "listening_port"   : "25"
        },

=head1 SYNOPSIS

=head1 AUTHORS

Marc Bradshaw E<lt>marc@marcbradshaw.netE<gt>

=head1 COPYRIGHT

Copyright 2018

This library is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.



