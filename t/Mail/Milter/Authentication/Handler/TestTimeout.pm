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
}


sub connect_callback { _timeout(); }
sub helo_callback {  _timeout(); }
sub envfrom_callback { _timeout(); }
sub envrcpt_callback { _timeout(); }
sub header_callback { _timeout(); }
sub eoh_callback { _timeout(); }
sub body_callback { _timeout(); }
sub eom_callback { _timeout(); }
sub abort_callback { _timeout(); }
sub close_callback { _timeout(); }

1;
