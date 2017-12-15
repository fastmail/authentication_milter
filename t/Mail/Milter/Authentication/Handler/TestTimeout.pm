package Mail::Milter::Authentication::Handler::TestTimeout;

use strict;
use warnings;
use base 'Mail::Milter::Authentication::Handler';
use version; our $VERSION = version->declare('v1.1.5');

use Data::Dumper;
use English qw{ -no_match_vars };
use Sys::Syslog qw{:standard :macros};

sub _timeout {
    alarm ( 1 );
    sleep 10;
    return;
}


sub connect_callback { return _timeout(); }
sub helo_callback { return  _timeout(); }
sub envfrom_callback { return _timeout(); }
sub envrcpt_callback { return _timeout(); }
sub header_callback { return _timeout(); }
sub eoh_callback { return _timeout(); }
sub body_callback { return _timeout(); }
sub eom_callback { return _timeout(); }
sub abort_callback { return _timeout(); }
sub close_callback { return _timeout(); }

1;
