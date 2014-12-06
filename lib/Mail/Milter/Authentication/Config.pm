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

        # Sanity Checks
        if ( $CONFIG->{'check_dmarc'} ) {
            if ( not $CONFIG->{'check_dkim'} ) {
                die 'dmarc checks require dkim to be enabled';
            }
            if ( not $CONFIG->{'check_spf'} ) {
                die 'dmarc checks require spf to be enabled';
            }
        }
        if ( $CONFIG->{'check_ptr'} ) {
            if ( not $CONFIG->{'check_iprev'} ) {
                die 'ptr checks require iprev to be enabled';
            }
        }

        my @standard_modules = qw{ Core };
        my @load_modules = keys %{ $CONFIG->{'modules'} };
        @standard_modules = ( @standard_modules, @load_modules );
        $CONFIG->{'load_modules'} = \@standard_modules;

        return $CONFIG;

    }

}

1;
