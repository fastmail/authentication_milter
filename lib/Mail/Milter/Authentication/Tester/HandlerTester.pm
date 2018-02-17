package Mail::Milter::Authentication::Tester::HandlerTester;

use strict;
use warnings;

use Carp;
use Clone qw{ clone };
use English qw{ -no_match_vars };
use Mail::AuthenticationResults::Header;
use Mail::AuthenticationResults::Header::AuthServID;
use Mail::Milter::Authentication;
use Mail::Milter::Authentication::Config qw{ set_config get_config default_config };
use Mail::Milter::Authentication::Constants qw{ :all };
use Mail::Milter::Authentication::Protocol::Milter;
use Mail::Milter::Authentication::Protocol::SMTP;
use Module::Load;
use Net::DNS::Resolver::Mock;
use Net::IP;

sub _build_config_smtp {
    my ( $self, $handler_config ) = @_;

    my $config = {

        '_is_test'                        => 1,
        'debug'                           => 1,
        'dryrun'                          => 0,
        'logtoerr'                        => 1,
        'error_log'                       => 'tmp/smtp.err',
        'connection'                      => 'unix:tmp/authentication_milter_test.sock',
        'umask'                           => '0000',
        'connect_timeout'                 => 55,
        'command_timeout'                 => 55,
        'content_timeout'                 => 595,
        'tempfail_on_error'               => 1,
        'tempfail_on_error_authenticated' => 1,
        'tempfail_on_error_local'         => 1,
        'tempfail_on_error_trusted'       => 1,

        'metric_connection'               => 'unix:tmp/authentication_milter_test_metrics.sock',
        'metric_umask'                    => '0000',

        'protocol' => 'smtp',
        'smtp' => {
            'sock_type' => 'unix',
            'sock_path' => 'tmp/authentication_milter_smtp_out.sock',
            'pipeline_limit' => '4',
        },

        'handlers' => $handler_config,

    };

    return $config;
}

sub _build_config_milter {
    my ( $self, $handler_config ) = @_;

    my $config = {

        '_is_test'                        => 1,
        'debug'                           => 1,
        'dryrun'                          => 0,
        'logtoerr'                        => 1,
        'error_log'                       => 'tmp/milter.err',
        'connection'                      => 'unix:tmp/authentication_milter_test.sock',
        'umask'                           => '0000',
        'connect_timeout'                 => 55,
        'command_timeout'                 => 55,
        'content_timeout'                 => 595,
        'tempfail_on_error'               => 1,
        'tempfail_on_error_authenticated' => 1,
        'tempfail_on_error_local'         => 1,
        'tempfail_on_error_trusted'       => 1,

        'metric_connection'               => 'unix:tmp/authentication_milter_test_metrics.sock',
        'metric_umask'                    => '0000',

        'protocol' => 'milter',

        'handlers' => $handler_config,

    };

    return $config;
}

sub new {
    my ( $class, $args ) = @_;
    my $self = {};
    bless $self, $class;

    $self->{ 'snapshots' } = {};

    foreach my $arg ( qw{ prefix zonefile zonedata } ) {
        $self->{ $arg } = $args->{ $arg } if exists $args->{ $arg };
    }

    croak 'prefix must be supplies' if ! exists $self->{ 'prefix' };
    croak 'zonefile or zonedata cannot both be supplied' if ( exists $self->{ 'zonefile' } ) && ( exists $self->{ 'zonedata' });
    $self->{ 'zonedata' } = q{} if ( ! exists $self->{ 'zonefile' } ) && ( ! exists $self->{ 'zonedata' });

    my $protocol = $args->{ 'protocol' } // 'smtp';

    if ( exists( $args->{ 'handler_config' } ) ) {
        if ( $protocol eq 'smtp' ) {
            set_config( $self->_build_config_smtp( $args->{ 'handler_config' } ) );
        }
        else {
            set_config( $self->_build_config_milter( $args->{ 'handler_config' } ) );
        }
    }

    $Mail::Milter::Authentication::Config::PREFIX = $self->{ 'prefix' };
    my $config = get_config();

    my $Resolver = Net::DNS::Resolver::Mock->new();
    $Resolver->zonefile_read( $self->{ 'zonefile' } ) if exists $self->{ 'zonefile' };
    $Resolver->zonefile_parse( $self->{ 'zonedata' } ) if exists $self->{ 'zonedata' };
    $Mail::Milter::Authentication::Handler::TestResolver = $Resolver;

    # Setup a new authentication milter object
    my $authmilter = Mail::Milter::Authentication->new();
    $authmilter->{'metric'} = Mail::Milter::Authentication::Metric->new();
    $authmilter->{'config'} = $config;

    # if ( $protocol eq 'smtp' ) {
        push @Mail::Milter::Authentication::ISA, 'Mail::Milter::Authentication::Protocol::SMTP';
        #}
        #else {
        #push @Mail::Milter::Authentication::ISA, 'Mail::Milter::Authentication::Protocol::Milter';
        #}

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

    $self->handler()->top_setup_callback();

    $self->snapshot( '_new' );

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

sub abort {
    my ( $self ) = @_;
    return $self->handler()->top_abort_callback();
}

sub addheader {
    my ( $self ) = @_;
    return $self->handler()->top_addheader_callback();
}

sub run {
    my ( $self, $args ) = @_;

    $self->switch( '_new' );

    my $returncode;
    $returncode = $self->connect( $args->{ 'connect_name' }, $args->{ 'connect_ip' } );
    die 'connect' if ( $returncode != SMFIS_CONTINUE );
    $returncode = $self->helo( $args->{ 'helo' } );
    die 'helo' if ( $returncode != SMFIS_CONTINUE );
    $returncode = $self->mailfrom( $args->{ 'mailfrom' } );
    die 'mailfrom' if ( $returncode != SMFIS_CONTINUE );
    foreach my $rcptto ( @{ $args->{ 'rcptto' } } ) {
        $returncode = $self->rcptto( $rcptto );
        die 'rcptto ' . $rcptto if ( $returncode != SMFIS_CONTINUE );
    }

    my $body = $args->{ 'body' };
    $body =~ s/\r?\n/\n/g;

    my @lines = split( /\n/, $body );

    # Process headers
    my $buffer = q{};
    while ( my $line = shift @lines ) {
        chomp $line;
        last if $line eq q{};

        if ( $line =~ /^\s/ ) {
            $buffer .= "\n" . $line;
        }
        else {
            if ( $buffer ) {
                my ( $key, $value ) = split( ':', $buffer, 2 );
                $key =~ s/\s+$//;
                $value =~ s/^\s+//;
                $returncode = $self->header( $key, $value );
                die "header $key: $value" if ( $returncode != SMFIS_CONTINUE );
            }
            $buffer = $line;
        }

    }
    if ( $buffer ) {
        my ( $key, $value ) = split( $buffer, ':', 2 );
        $key =~ s/\s+$//;
        $value =~ s/^\s+//;
        $returncode = $self->header( $key, $value );
        die "header $key: $value" if ( $returncode != SMFIS_CONTINUE );
    }

    $returncode = $self->end_of_headers();
    die 'eoh' if ( $returncode != SMFIS_CONTINUE );

    $returncode = $self->body( join( "\n", @lines) );
    die 'body' if ( $returncode != SMFIS_CONTINUE );

    $returncode = $self->end_of_message();
    die 'body' if ( $returncode != SMFIS_CONTINUE );

    $self->addheader();
    #    $self->close();

    return;
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

$args is a hashref with the following entries.

=over

=item prefix

Required

The Prefix path containing the authentication milter config file(s). This should contain
all configuration files required for your test, the main authentication_milter.json file
can be overridden by the handler_config option (see below).

This location should, for example, contain a valid mail-dmarc.ini for any tests using
the DMARC handler.

=item handler_config

If present, the config will be built from a generic default SMTP environment, with the given
HASHREF substituted as the Handler configuration. This eliminates the need to have a config file
for each handler configuration you wish to test.

=item zonedata

The zonefile data for use with Net::DNS::Resolver::Mock

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

=item abort()

Call the abort callbacks.

=item addheader()

Call the addheader callbacks.

=item run( $args )

Run with a given set of data as defined in $args hashref.

Dies if the mail would be rejected.

Arguments of $args are.

=over

=item connect_name

The name of the connecting server.

=item connect_ip

The ip address of the connecting server.

=item helo

The helo string.

=item mailfrom

The envelope MAILFROM address.

=item rcptto

Arrayref of the envelope RCPTTO addresses.

=item body

The email body.

=back

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

