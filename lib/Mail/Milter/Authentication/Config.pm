package Mail::Milter::Authentication::Config;
# ABSTRACT: Load config files for Authentication Milter
use strict;
use warnings;
# VERSION

use Mail::Milter::Authentication;
use Module::Load;
use Module::Loaded;

use Exporter qw{ import };
our @EXPORT_OK = qw{
  get_config
  set_config
  default_config
};

use JSON;

=head1 DESCRIPTION

Load in configuration data.

=head1 SYNOPSIS

Load in the configuration data, does some processing on handlers loaded before returning
config to the caller.

If the $Mail::Milter::Authentication::Config::PREFIX variable is set then the config file
will be read from the supplied directory rather than /etc/

=cut

our $PREFIX = '/etc';
our $IDENT  = 'authentication_milter';
my  $CONFIG;

=func I<default_config()>

Return a default configuration including defaults from handler modules.

This is not the default config used by the system if no config is present, rather it is the config
which is presented to the user as an example default config when using the help feature.

=cut

sub default_config {
    my $config = {
        'debug'                           => 0,
        'dryrun'                          => 0,
        'logtoerr'                        => 0,
        'error_log'                       => '/var/log/authentication_milter.err',
        'connection'                      => 'inet:12345@localhost',
        'umask'                           => '0000',
        'runas'                           => 'nobody',
        'rungroup'                        => 'nogroup',
        'listen_backlog'                  => 20,
        'min_children'                    => 20,
        'max_children'                    => 200,
        'min_spare_children'              => 10,
        'max_spare_children'              => 20,
        'max_requests_per_child'          => 200,
        'protocol'                        => 'milter',
        'connect_timeout'                 => 30,
        'command_timeout'                 => 30,
        'content_timeout'                 => 300,
        'addheader_timeout'               => 30,
        'dns_timeout'                     => 10,
        'dns_retry'                       => 2,
        'tempfail_on_error'               => '1',
        'tempfail_on_error_authenticated' => '0',
        'tempfail_on_error_local'         => '0',
        'tempfail_on_error_trusted'       => '0',
        'milter_quarantine'               => '0',
        'ip_map'                          => {},
        'handlers'                        => {}
    };

    my $installed_handlers = Mail::Milter::Authentication::get_installed_handlers();
    foreach my $handler ( @$installed_handlers ) {
        my $handler_module = 'Mail::Milter::Authentication::Handler::' . $handler;
        load $handler_module;
        if ( $handler_module->can( 'default_config' ) ) {
            $config->{'handlers'}->{ $handler } = $handler_module->default_config();
        }
        else {
            $config->{'handlers'}->{ $handler } = {};
        }
    }

    return $config;

}

=func I<set_config( $config )>

Set the config hashref, primarily used for testing.

=cut

sub set_config {
    my ( $config ) = @_;

    my @load_handlers = keys %{ $config->{'handlers'} };
    @load_handlers = grep { ! /^\!/ } @load_handlers;
    $config->{'load_handlers'} = \@load_handlers;

    my $protocol = $config->{'protocol'} || 'milter';
    $config->{'protocol'} = $protocol;
    $CONFIG = $config;

    return;
}

=func I<load_file( $file )>

Internal function used to load the config from /etc/authentication_milter.json

=cut

sub load_file {
    my ( $file ) = @_;

    if ( !-e $file ) {
        die "Could not find configuration file $file";
    }

    my $text;
    {
        open my $cf, '<',
          $file || die "Could not open configuration file $file";
        my @t = <$cf>;
        close $cf;
        $text = join( q{}, @t );
    }

    my $json = JSON->new();
    $json->relaxed(1);
    my $data = $json->decode($text)
      || die "Error parsing config file $file";

    return $data;
}

=func I<process_config()>

Process the loaded config with the callback if required.

This is the name of a Module to load, the process_config method of the instantiated object
will be called with $config as the argument.g

    package ConfigProcessor;

    sub new {
        ...
    }

    sub process_config {
        my ( $self, $config ) = @_;
        return;
    }

    1;

=cut

sub process_config {

    if ( exists( $CONFIG->{ '_external_callback_processor' } ) ) {
        if ( $CONFIG->{ '_external_callback_processor' }->can( 'process_config' ) ) {
            $CONFIG->{ '_external_callback_processor' }->process_config( $CONFIG );
        }
    }

    return $CONFIG;
}

=func I<get_config()>

Return the config hashref, load from file(s) if required.

=cut

sub get_config {

    if ( $CONFIG ) {
        return process_config();
    }

    my $file = $PREFIX . '/authentication_milter.json';

    my $config = load_file( $file );

    my $folder = $PREFIX . '/authentication_milter.d';
    if ( -d $folder ) {
        my $dh;
        opendir $dh, $folder;
        my @config_files =
            sort
            grep { $_ =~ /\.json$/ }
            grep { not $_ =~ /^\./ }
            readdir($dh);
        closedir $dh;
        foreach my $file ( @config_files ) {
            $file =~ /(^.*)\.json$/;
            my $handler = $1;
            ## ToDo Consider what to do if config already exists in .json config
            $config->{'handlers'}->{$handler} = load_file( join( '/', $folder, $file ) );
        }
    }

    my @load_handlers = keys %{ $config->{'handlers'} };
    @load_handlers = grep { ! /^\!/ } @load_handlers;
    $config->{'load_handlers'} = \@load_handlers;

    my $protocol = $config->{'protocol'} || 'milter';
    $config->{'protocol'} = $protocol;

    # Have we specified an external callback processor?
    if ( exists( $config->{ 'external_callback_processor' } ) ) {
        # Try and load the handler
        my $handler = $config->{ 'external_callback_processor' };
        if ( ! is_loaded ( $handler ) ) {
            eval {
                no strict 'refs'; ## no critic;
                load $handler;
                $config->{ '_external_callback_processor' } = $handler->new();
            };
            if ( my $error = $@ ) {
                delete $config->{ 'external_callback_processor' };
                warn "Error loading external callback processor module: $error";
            }
        }
    }

    $CONFIG = $config;

    return process_config();

}

1;
