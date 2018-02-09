package Mail::Milter::Authentication::Tester::HandlerTester;

use strict;
use warnings;

use Carp;
use Clone qw{ clone };
use English qw{ -no_match_vars };
use Mail::AuthenticationResults::Header;
use Mail::AuthenticationResults::Header::AuthServID;
use Mail::Milter::Authentication;
use Mail::Milter::Authentication::Config qw{ get_config default_config };
use Mail::Milter::Authentication::Constants qw{ :all };
use Mail::Milter::Authentication::Protocol::Milter;
use Mail::Milter::Authentication::Protocol::SMTP;
use Module::Load;
use Net::DNS::Resolver::Mock;
use Net::IP;

sub new {
    my ( $class, $args ) = @_;
    my $self = {};

    $self->{ 'snapshots' } = {};

    foreach my $arg ( qw{ prefix zonefile } ) {
        $self->{ $arg } = $args->{ $arg } // croak "Missing arg $arg";
    }

    $Mail::Milter::Authentication::Config::PREFIX = $self->{ 'prefix' };
    my $config = get_config();

    my $Resolver = Net::DNS::Resolver::Mock->new();
    $Resolver->zonefile_read( $self->{ 'zonefile' } );
    $Mail::Milter::Authentication::Handler::TestResolver = $Resolver;

    # Setup a new authentication milter object
    my $authmilter = Mail::Milter::Authentication->new();
    $authmilter->{'metric'} = Mail::Milter::Authentication::Metric->new();
    $authmilter->{'config'} = $config;

    # Pretend to be SMTP based
    push @Mail::Milter::Authentication::ISA, 'Mail::Milter::Authentication::Protocol::SMTP';

    # Setup a fake server object
    $authmilter->{ 'server' }->{ 'ppid' } = $PID;

    # Load handlers
    foreach my $name ( @{$config->{'load_handlers'}} ) {
        $authmilter->load_handler( $name );

        my $package = "Mail::Milter::Authentication::Handler::$name";
        my $object = $package->new( $authmilter );
        if ( $object->can( 'pre_loop_setup' ) ) {
            $object->pre_loop_setup();
        }
        if ( $object->can( 'register_metrics' ) ) {
            $authmilter->{'metric'}->register_metrics( $object->register_metrics() );
        }

    }

    # Init handlers

    my $callbacks_list = {};
    my $callbacks      = {};
    my $handler        = {};
    my $object         = {};
    my $object_maker   = {};
    my $count          = 0;

    $authmilter->{'callbacks_list'} = $callbacks_list;
    $authmilter->{'callbacks'}      = $callbacks;
    $authmilter->{'count'}          = $count;
    $authmilter->{'handler'}        = $handler;
    $authmilter->{'object'}         = $object;
    $authmilter->{'object_maker'}   = $object_maker;

    $authmilter->setup_handlers();

    $self->{ 'authmilter' } = $authmilter;

    bless $self, $class;

    $self->handler()->top_setup_callback();

    return $self;
}

sub snapshot {
    my ( $self, $name ) = @_;
    my $snapshot = clone( $self->{ 'authmilter' } );
    $self->{ 'snapshots' }->{ $name } = $snapshot;
    return;
}

sub switch {
    my ( $self, $name ) = @_;
    croak 'unknown snapshot' if ! exists ( $self->{ 'snapshots' }->{ $name } );
    my $snapshot = clone( $self->{ 'snapshots' }->{ $name } );
    $self->{ 'authmilter' } = $snapshot;
    return;
}

sub handler {
    my ( $self ) = @_;
    return $self->{ 'authmilter' }->{ 'handler' }->{ '_Handler' };
}

sub connect {
    my ( $self, $name, $ip ) = @_;
    my $authmilter = $self->{ 'authmilter' };
    return $self->handler()->top_connect_callback( $name, Net::IP->new( $ip ) );
}

sub helo {
    my ( $self, $helo ) = @_;
    return $self->handler()->top_helo_callback( $helo );
}

sub mailfrom {
    my ( $self, $from ) = @_;
    return $self->handler()->top_envfrom_callback( $from );
}

sub rcptto {
    my ( $self, $to ) = @_;
    return $self->handler()->top_envrcpt_callback( $to );
}

sub header {
    my ( $self, $key, $value ) = @_;
    return $self->handler()->top_header_callback( $key, $value );
}

sub end_of_headers {
    my ( $self ) = @_;
    return $self->handler()->top_eoh_callback();
}

sub body {
    my ( $self, $body ) = @_;
    return $self->handler()->top_body_callback( $body );
}

sub end_of_message {
    my ( $self ) = @_;
    return $self->handler()->top_eom_callback();
}

sub close {
    my ( $self ) = @_;
    return $self->handler()->top_close_callback();
}

sub get_return {
    my ( $self ) = @_;
    return $self->handler()->get_return();
}

sub get_reject_mail {
    my ( $self ) = @_;
    return $self->handler()->get_reject_mail();
}

sub servername {
    my ( $self ) = @_;
    return 'handlertester.test.authmilter.org';
}

sub get_authresults_header {
    my ( $self ) = @_;
    # Build a Mail::AuthenticationReslts object
    my $c_auth_headers = clone( $self->handler()->{ 'c_auth_headers'} ) // [];
    my $auth_headers = clone( $self->handler()->{ 'auth_headers'} ) // [];
    my @added_ar_headers = ( @{ $c_auth_headers }, @{ $auth_headers } );
    my $header = Mail::AuthenticationResults::Header->new()->set_value( Mail::AuthenticationResults::Header::AuthServID->new()->set_value( $self->servername() ) );
    foreach my $ar_header ( @added_ar_headers ) {
        $header->add_child( $ar_header );
    }
    return $header;
}

1;

__END__

=head1 NAME

Mail::Milter::Authentication::Tester::HandlerTester - Test harness for testing Authentication Milter Handlers

=head1 DESCRIPTION

Make testing of Authentication Milter Handler modules easier.

=head1 SYNOPSIS

Emulates an Authentication Milter environment with methods for testing Handlers.

Can snapshot and restore state at any point.

=head1 CONSTRUCTOR

=over

=item new( $args )

Instantiate a new HandlerTester object.

$args is a hashref with the following required entries.

=over

=item prefix

The Prefix path containing the authentication milter config file

=item zonefile

A zonefile for use with Net::DNS::Resolver::Mock

=back

=back

=head1 METHODS

=over

=item snapshot( $name )

Save a snapshot with the given name

=item switch( $name )

Restore state from the given snapshot

=item handler()

Returns the Handler object

=item connect( $name, $ip )

Call the connect callbacks with the given data.

Returns the value of get_return()

=item helo( $name )

Call the helo callbacks with the given data.

Returns the value of get_return();

=item mailfrom( $email )

Call the envfrom callbacks with the given data.

Returns the value of get_return();

=item rcptto( $email )

Call the envrcpt callbacks with the given data.

Returns the value of get_return();

=item header( $key, $value )

Call the header callbacks with the given data.

Returns the value of get_return()

=item end_of_headers()

Call the end_of_headers callbacks.

Returns the value of get_return()

=item body( $body_chunk )

Call the body callbacks with the given data.

Returns the value of get_return()

=item end_of_message()

Call the eom callbacks.

Returns the value of get_return()

=item close()

Call the close callbacks.

Returns the value of get_return()

=item get_return()

Returns the value of get_return() from the current handler object.

=item get_reject_mail()

Returns the value of get_reject_mail() from the current handler object.

=item servername()

Returns a dummy authservid servername.

=item get_authresults_header()

Returns a Mail::AuthenticationResults::Header object representing the authentication results
header which would be added to the message.

=back

=head1 DEPENDENCIES

  Carp
  Clone
  Mail::AuthenticationResults::Header
  Mail::AuthenticationResults::Header::AuthServID
  Mail::Milter::Authentication
  Mail::Milter::Authentication::Protocol::Milter
  Mail::Milter::Authentication::Protocol::SMTP
  Mail::Milter::Authentication::Config
  Module::Load
  Net::DNS::Resolver::Mock

=head1 AUTHORS

Marc Bradshaw E<lt>marc@marcbradshaw.netE<gt>

=head1 COPYRIGHT

Copyright 2018

This library is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.

