package Mail::Milter::Authentication::HTDocs;
use strict;
use warnings;
# VERSION

=head1 DESCRIPTION

Load and serve static files via the in-build http server.

=cut

=constructor I<new()>

Return a new instance of this class

=cut

sub new {
    my ( $class ) = @_;
    my $self = {};
    bless $self, $class;
    return $self;
}

=method I<get_whitelist()>

Return an arrayref of valid URLs/Filenames whih are allowed to be served.

=cut

sub get_whitelist {
    my ( $self ) = @_;

    my @whitelist = qw{ /css/normalize.css /css/skeleton.css /css/authmilter.css };
    return \@whitelist;
}

=method I<get_file( $file )>

Return a full HTTP response for the given filename, or null if it does not exist.

=cut

sub get_file {
    my ( $self, $file ) = @_;

    my $whitelisted = grep { $_ eq $file } @{ $self->get_whitelist() };
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

1;
