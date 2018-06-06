package Mail::Milter::Authentication::HTDocs;
use strict;
use warnings;
# VERSION

## TODO a better way to do this
my @whitelist = qw{ /css/normalize.css /css/skeleton.css /css/authmilter.css };

sub get_file {
    my ( $self, $file ) = @_;

    my $whitelisted = grep { $_ eq $file } @whitelist;
    return if ! $whitelisted;

    my $basefile = __FILE__;
    $basefile =~ s/HTDocs\.pm$/htdocs/;
    $basefile .= $file;
    if ( ! -e $basefile ) {
        return;
    }
    open my $InF, '<', $basefile;
    my @Content = <$InF>;
    close $InF;
    return join( q{}, @Content );
}

sub new {
    my ( $class ) = @_;
    my $self = {};
    bless $self, $class;
    return $self;
}

1;
