package Mail::Milter::Authentication::Handler::AbusixDataFeed;
use 5.20.0;
use strict;
use warnings;
use Mail::Milter::Authentication::Pragmas;
# ABSTRACT: Handler class for sending data to Abusix
# VERSION
use base 'Mail::Milter::Authentication::Handler';
use Mail::DataFeed::Abusix 1.20200617.1;

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
}

sub dequeue_callback {
    my ($self) = @_;
    my $config = $self->handler_config();
    my $dequeue_list = $self->get_dequeue_list('abusix_datafeed');
    foreach my $id ( $dequeue_list->@* ) {
        eval {
            my $feed = $self->get_dequeue($id);
            if ( $feed ) {
                my $api = Mail::DataFeed::Abusix->new( $feed->%* );
                $api->send;
            }
            else {
                $self->log_error("AbusixDataFeed Report dequeue failed for $id");
            }
        };
        if ( my $Error = $@ ) {
            $self->handle_exception( $Error );
            $self->log_error( 'AbusixDataFeed Sending Error ' . $Error );
        }
        $self->delete_dequeue($id);
    }
}

sub envfrom_callback {
    my ($self, $from) = @_;
    my $config = $self->handler_config();

    $self->{ 'abusix_feed' } = {
        feed_name => $config->{ 'feed_name' },
        feed_dest => $config->{ 'feed_dest' },
        feed_key => $config->{ 'feed_key' },
        mail_from_domain => $self->get_domain_from( $from ),
        helo => $self->{ 'helo_name' },
        port => $config->{ 'listening_port' },
        ip_address => $self->ip_address(),
        time => time(),
    };

    delete $self->{ 'first_received' };

    my $resolver = $self->get_object('resolver');
    my @rdns;
    my $packet = $resolver->query( $self->ip_address(), 'PTR' );
    if ($packet) {
        foreach my $rr ( $packet->answer ) {
            # We do not consider CNAMES here
            if ( $rr->type eq "PTR" ) {
                my $rdstring = $rr->rdstring;
                $rdstring =~ s/\r//g;
                $rdstring =~ s/\n//g;
                push @rdns, $rdstring;
            }
        }
    }

    $self->{ 'abusix_feed' }->{'reverse_dns'} = join( ',', @rdns );
}

sub header_callback {
    my ( $self, $header, $value ) = @_;
    return if defined $self->{ 'first_received' };
    return if lc $header ne 'received';
    my $protocol = Mail::Milter::Authentication::Config::get_config()->{'protocol'};
    return if $protocol ne 'smtp';

    $self->{ 'first_received' } = $value;
}

sub eoh_callback {
    my ( $self ) = @_;
    if ( $self->is_handler_loaded('TLS') ) {
        $self->{ 'abusix_feed' }->{'used_tls'} = $self->is_encrypted() || 0; # Explicit 0 over undef if TLS handler is loaded
    }
    $self->{ 'abusix_feed' }->{'used_auth'} = $self->is_authenticated();
    if ( defined $self->{ 'first_received' } ) {
        my $used_smtp  = $self->{ 'first_received' } =~ / with SMTP/;
        my $used_esmtp = $self->{ 'first_received' } =~ / with ESMTP/;
        if ( $used_smtp xor $used_esmtp ) {
            # Filters line noise!
            $self->{ 'abusix_feed' }->{'used_esmtp'} = 1 if $used_esmtp;
            $self->{ 'abusix_feed' }->{'used_esmtp'} = 0 if $used_smtp;
        }
    }
    $self->add_dequeue('abusix_datafeed',$self->{'abusix_feed'});
}


sub close_callback {
    my ( $self ) = @_;

    delete $self->{'helo_name'};
    delete $self->{'abusix_feed'};
    delete $self->{ 'first_received' };
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



