package Mail::Milter::Authentication::Config;
use strict;
use warnings;
use version; our $VERSION = version->declare('v1.1.0');

use Mail::Milter::Authentication;
use Module::Load;

use Exporter qw{ import };
our @EXPORT_OK = qw{
  get_config
  default_config
};

use JSON;

our $PREFIX = '/etc';

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
        'dns_timeout'                     => 10,
        'dns_retry'                       => 2,
        'tempfail_on_error'               => '1',
        'tempfail_on_error_authenticated' => '0',
        'tempfail_on_error_local'         => '0',
        'tempfail_on_error_trusted'       => '0',
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

sub get_config {

    my $file = $PREFIX . '/authentication_milter.json';

    my $config = load_file( $file );

    my $folder = $PREFIX . '/authentication_milter.d';
    if ( -d $folder ) {
        my $dh;
        opendir $dh, $folder;
        my @config_files =
            sort
            grep { $_ =~ /\.json/ }
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

    return $config;

}

1;

__END__

=head1 NAME

Mail::Milter::Authentication::Config - Load config files for Authentication Milter

=head1 DESCRIPTION

Load in configuration data.

=head1 SYNOPSIS

Load in the configuration data, does some processing on handlers loaded before returning
config to the caller.

If the $Mail::Milter::Authentication::Config::PREFIX variable is set then the config file
will be read from the supplied directory rather than /etc/

=head1 FUNCTIONS

=over

=item I<default_config()>

Return a default configuration including defaults from handler modules.

=item I<load_file()>

Internal function used to load the config from /etc/authentication_milter.json

=item I<get_config()>

Return the config hashref, load from file(s) if required.

=back

=head1 DEPENDENCIES

  JSON

=head1 AUTHORS

Marc Bradshaw E<lt>marc@marcbradshaw.netE<gt>

=head1 COPYRIGHT

Copyright 2015

This library is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.

