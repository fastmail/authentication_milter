package Mail::Milter::Authentication::Handler::AddID;

use strict;
use warnings;

our $VERSION = 0.5;

use base 'Mail::Milter::Authentication::Handler';

use Sys::Syslog qw{:standard :macros};

sub eom_callback {

    # On HELO
    my ( $self, $helo_host ) = @_;
    my $CONFIG = $self->config();
    $self->append_header('X-Authentication-Milter','Header added by Authentication Milter');
}

1;
