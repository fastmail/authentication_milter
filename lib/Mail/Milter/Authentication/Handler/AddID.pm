package Mail::Milter::Authentication::Handler::AddID;
use strict;
use warnings;
use base 'Mail::Milter::Authentication::Handler';
use version; our $VERSION = version->declare('v0.1.0');

use Sys::Syslog qw{:standard :macros};

sub eom_callback {

    # On HELO
    my ( $self, $helo_host ) = @_;
    $self->append_header('X-Authentication-Milter','Header added by Authentication Milter');
    return;
}

1;
