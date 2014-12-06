package Mail::Milter::Authentication::Config;

use strict;
use warnings;

our $VERSION = 0.5;

use Exporter qw{ import };
our @EXPORT_OK = qw{
  get_config
};

use JSON;

{
    my $CONFIG;

    sub get_config {

        return $CONFIG if $CONFIG;

        my $file = '/etc/authentication_milter.json';
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

        my $json   = JSON->new();
        $CONFIG = $json->decode($text)
          || die "Error parsing config file $file";

        my @standard_handlers = qw{ Core };
        my @load_handlers = keys %{ $CONFIG->{'handlers'} };
        @load_handlers = grep { ! /^\!/ } @load_handlers;
        @load_handlers = ( @standard_handlers, @load_handlers );
        $CONFIG->{'load_handlers'} = \@load_handlers;

        return $CONFIG;

    }

}

1;
