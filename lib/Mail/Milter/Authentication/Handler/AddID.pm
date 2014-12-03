package Mail::Milter::Authentication::Handler::AddID;

use strict;
use warnings;

our $VERSION = 0.4;

use base 'Mail::Milter::Authentication::Handler::Generic';

use Sys::Syslog qw{:standard :macros};

sub callbacks {
    return {
        'connect' => undef,
        'helo'    => undef,
        'envfrom' => undef,
        'envrcpt' => undef,
        'header'  => undef,
        'eoh'     => undef,
        'body'    => undef,
        'eom'     => 5,
        'abort'   => undef,
        'close'   => undef,
    };
}

sub eom_callback {

    # On HELO
    my ( $self, $helo_host ) = @_;
    my $CONFIG = $self->config();
    $self->append_header('X-Authentication-Milter','Header added by Authentication Milter');
}

1;
