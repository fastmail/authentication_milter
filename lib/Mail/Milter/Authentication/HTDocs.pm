package Mail::Milter::Authentication::HTDocs;
use 5.20.0;
use strict;
use warnings;
use Mail::Milter::Authentication::Pragmas;
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
    my ( $self, $path ) = @_;

    my @whitelist;

    if ( opendir( my $dh, join( '/', $self->get_basedir(), $path ) ) ) {
        while ( my $file = readdir( $dh ) ) {
            next if $file =~ /^\./;
            my $full_path = join( '/', $self->get_basedir(), $path, $file );
            if ( -f $full_path ) {
                push @whitelist, join( '/', $path, $file );
            }
            if ( -d $full_path ) {
                @whitelist = ( @whitelist, @{ $self->get_whitelist( join ( '/', $path, $file ) ) } );
            }
        }
    }

    return \@whitelist;
}

=method I<get_basedir()>

Return the base directory for htdocs files

=cut

sub get_basedir {
    my ( $self ) = @_;
    my $basedir = __FILE__;
    $basedir =~ s/HTDocs\.pm$/htdocs/;
    return $basedir;
}

=method I<get_file( $file )>

Return a full HTTP response for the given filename, or null if it does not exist.

=cut

sub get_file {
    my ( $self, $file ) = @_;

    my $whitelisted = grep { $_ eq $file } @{ $self->get_whitelist( '' ) };
    return if ! $whitelisted;

    my $basefile = $self->get_basedir();
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
