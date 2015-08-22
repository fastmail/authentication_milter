package Mail::Milter::Authentication::Handler::AddID;
use strict;
use warnings;
use base 'Mail::Milter::Authentication::Handler';
use version; our $VERSION = version->declare('v1.0.0');

use Sys::Syslog qw{:standard :macros};

sub default_config {
    return {};
}

sub eom_callback {

    # On HELO
    my ( $self, $helo_host ) = @_;
    $self->append_header('X-Authentication-Milter','Header added by Authentication Milter');
    return;
}

1;

__END__

=head1 NAME

  Authentication Milter - AddID Module

=head1 DESCRIPTION

Simple module which adds a header to all email processed.

This is meant as an example only.

=head1 CONFIGURATION

No configuration options exist for this handler.

=head1 SYNOPSIS

=head1 AUTHORS

Marc Bradshaw E<lt>marc@marcbradshaw.netE<gt>

=head1 COPYRIGHT

Copyright 2015

This library is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.


