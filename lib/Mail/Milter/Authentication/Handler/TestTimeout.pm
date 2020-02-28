package Mail::Milter::Authentication::Handler::TestTimeout;
use 5.20.0;
use strict;
use warnings;
use Mail::Milter::Authentication::Pragmas;
# ABSTRACT: Timeout Tester
# VERSION
use base 'Mail::Milter::Authentication::Handler';

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
