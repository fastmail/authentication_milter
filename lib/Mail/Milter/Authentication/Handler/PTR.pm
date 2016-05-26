package Mail::Milter::Authentication::Handler::PTR;
use strict;
use warnings;
use base 'Mail::Milter::Authentication::Handler';
use version; our $VERSION = version->declare('v1.1.0');

use Sys::Syslog qw{:standard :macros};

sub default_config {
    return {};
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
    my $domain =
      exists( $iprev_handler->{'verified_ptr'} )
      ? $iprev_handler->{'verified_ptr'}
      : q{};

    if ( lc $domain eq lc $helo_host ) {
        $self->dbgout( 'PTRMatch', 'pass', LOG_DEBUG );
        $self->add_c_auth_header(
                $self->format_header_entry( 'x-ptr',        'pass' ) . q{ }
              . $self->format_header_entry( 'x-ptr-helo',   $helo_host ) . q{ }
              . $self->format_header_entry( 'x-ptr-lookup', $domain ) );
    }
    else {
        $self->dbgout( 'PTRMatch', 'fail', LOG_DEBUG );
        $self->add_c_auth_header(
                $self->format_header_entry( 'x-ptr',        'fail' ) . q{ }
              . $self->format_header_entry( 'x-ptr-helo',   $helo_host ) . q{ }
              . $self->format_header_entry( 'x-ptr-lookup', $domain ) );
    }
    return;
}

1;

__END__

=head1 NAME

  Authentication Milter - PTR Module

=head1 DESCRIPTION

Check DNS PTR Records match.

This handler requires the IPRev handler to be installed and active.

=head1 CONFIGURATION

No configuration options exist for this handler.

=head1 SYNOPSIS

=head1 AUTHORS

Marc Bradshaw E<lt>marc@marcbradshaw.netE<gt>

=head1 COPYRIGHT

Copyright 2015

This library is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.


