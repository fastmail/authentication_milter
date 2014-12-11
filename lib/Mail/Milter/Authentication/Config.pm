package Mail::Milter::Authentication::Config;

use strict;
use warnings;

our $VERSION = 0.5;

use Exporter qw{ import };
our @EXPORT_OK = qw{
  get_config
};

use JSON;

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
    my $data = $json->decode($text)
      || die "Error parsing config file $file";

    return $data;
}

{
    my $CONFIG;

    sub get_config {

        return $CONFIG if $CONFIG;

        my $file = '/etc/authentication_milter.json';

        $CONFIG = load_file( $file );

        my $folder = '/etc/authentication_milter.d';
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
                $CONFIG->{'handlers'}->{$handler} = load_file( join( '/', $folder, $file ) );
            }
        }

        my @load_handlers = keys %{ $CONFIG->{'handlers'} };
        @load_handlers = grep { ! /^\!/ } @load_handlers;
        $CONFIG->{'load_handlers'} = \@load_handlers;

        return $CONFIG;

    }

}

1;
