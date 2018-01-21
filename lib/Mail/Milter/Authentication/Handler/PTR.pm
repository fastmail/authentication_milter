package Mail::Milter::Authentication::Handler::PTR;
use strict;
use warnings;
use base 'Mail::Milter::Authentication::Handler';
use version; our $VERSION = version->declare('v1.1.7');

use Sys::Syslog qw{:standard :macros};
use Mail::AuthenticationResults::Header::Entry;
use Mail::AuthenticationResults::Header::SubEntry;
use Mail::AuthenticationResults::Header::Comment;

sub default_config {
    return {};
}

sub grafana_rows {
    my ( $self ) = @_;
    my @rows;
    push @rows, $self->get_json( 'PTR_metrics' );
    return \@rows;
}

sub register_metrics {
    return {
        'ptr_total' => 'The number of emails processed for PTR',
    };
}

sub helo_callback {

    # On HELO
    my ( $self, $helo_host ) = @_;
    return if ( $self->is_local_ip_address() );
    return if ( $self->is_trusted_ip_address() );
    return if ( $self->is_authenticated() );

    if ( ! $self->is_handler_loaded( 'IPRev' ) ) {
        $self->log_error( 'PTR Config Error: IPRev is missing ');
        return;
    }

    my $iprev_handler = $self->get_handler('IPRev');
    my $domains =
      exists( $iprev_handler->{'verified_ptr'} )
      ? $iprev_handler->{'verified_ptr'}
      : q{};

    my $found_match = 0;

    foreach my $domain ( split ',', $domains ) {
        if ( lc $domain eq lc $helo_host ) {
            $found_match = 1;
        }
    }

    my $result = $found_match ? 'pass' : 'fail';
    $self->dbgout( 'PTRMatch', $result, LOG_DEBUG );
    my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'x-ptr' )->safe_set_value( $result );
    $header->add_child( Mail::AuthenticationResults::Header::SubEntry->new()->set_key( 'x-ptr-helo' )->safe_set_value( $helo_host ) );
    $header->add_child( Mail::AuthenticationResults::Header::SubEntry->new()->set_key( 'x-ptr-lookup' )->safe_set_value( $domains ) );
    $self->add_c_auth_header( $header );
    $self->metric_count( 'ptr_total', { 'result' => $result} );

    return;
}

1;

__END__

=head1 NAME

  Authentication-Milter - PTR Module

=head1 DESCRIPTION

Check DNS PTR Records match.

This handler requires the IPRev handler to be installed and active.

=head1 CONFIGURATION

No configuration options exist for this handler.

=head1 SYNOPSIS

=head1 AUTHORS

Marc Bradshaw E<lt>marc@marcbradshaw.netE<gt>

=head1 COPYRIGHT

Copyright 2017

This library is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.


