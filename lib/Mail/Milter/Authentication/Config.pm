package Mail::Milter::Authentication::Config;

$VERSION = 0.2;

use strict;
use warnings;

use Exporter qw{ import };
our @EXPORT_OK = qw{
    get_config
};

use JSON;

my $CONFIG;

sub get_config {

    return $CONFIG if $CONFIG;

    my $file = '/etc/authentication_milter.json';
    if ( ! -e $file ) {
        die "Could not find configuration file $file";
    }

    my $text;
    {
        open my $cf, '<', $file || die "Could not open configuration file $file";
        my @t = <$cf>;
        close $cf;
        $text = join( q{}, @t );
    }

    my $json = JSON->new();
    my $CONFIG = $json->decode( $text ) || die "Error parsing config file $file";

    # Samity Checks
    if ( $CONFIG->{'check_dmarc'} ) {
        if ( not $CONFIG->{'check_dkim'} ) { die 'dmarc checks require dkim to be enabled'; } ;
        if ( not $CONFIG->{'check_spf'} )  { die 'dmarc checks require spf to be enabled'; } ;
    }
    if ( $CONFIG->{'check_ptr'} ) {
        if ( not $CONFIG->{'check_iprev'} ) { die 'ptr checks require iprev to be enabled'; } ;
    }
    return $CONFIG;

}

1;
