package Mail::Milter::Authentication::Handler::Auth;
use strict;
use warnings;
use base 'Mail::Milter::Authentication::Handler';
use version; our $VERSION = version->declare('v1.1.1');

use Sys::Syslog qw{:standard :macros};

sub default_config {
    return {};
}

sub pre_loop_setup {
    my ( $self ) = @_;
    my $protocol = Mail::Milter::Authentication::Config::get_config()->{'protocol'};
    if ( $protocol ne 'milter' ) {
        warn 'The Auth handler only works with the milter protocol';
    }
    return;
}

sub get_auth_name {
    my ($self) = @_;
    my $name = $self->get_symbol('{auth_authen}');
    return $name;
}

sub connect_callback {
    my ( $self, $hostname, $ip ) = @_;
    $self->{'is_authenticated'} = 0;
    return;
}

sub envfrom_callback {
    my ( $self, $env_from ) = @_;
    my $auth_name = $self->get_auth_name();
    if ($auth_name) {
        $self->dbgout( 'AuthenticatedAs', $auth_name, LOG_INFO );
        # Clear the current auth headers ( iprev and helo may already be added )
        # ToDo is this a good idea?
        my $top_handler = $self->get_top_handler();
        $top_handler->{'c_auth_headers'} = [];
        $top_handler->{'auth_headers'}   = [];
        $self->{'is_authenticated'}       = 1;
        $self->add_auth_header('auth=pass');
    }
    return;
}

sub close_callback {
    my ( $self ) = @_;
    delete $self->{'is_authenticated'};
    return;
}

1;

__END__

=head1 NAME

  Authentication Milter - Auth Module

=head1 DESCRIPTION

Module which identifies email that was sent via an authenticated connection.

=head1 CONFIGURATION

No configuration options exist for this handler.

=head1 SYNOPSIS

=head1 AUTHORS

Marc Bradshaw E<lt>marc@marcbradshaw.netE<gt>

=head1 COPYRIGHT

Copyright 2015

This library is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.


