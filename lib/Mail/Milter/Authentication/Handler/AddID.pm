use strict;
use warnings;

package Mail::Milter::Authentication::Handler::AddID;
use base 'Mail::Milter::Authentication::Handler';
our $VERSION = 0.5;

use Sys::Syslog qw{:standard :macros};

sub eom_callback {

    # On HELO
    my ( $self, $helo_host ) = @_;
    $self->append_header('X-Authentication-Milter','Header added by Authentication Milter');
    return;
}

1;
