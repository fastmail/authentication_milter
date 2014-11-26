package Mail::Milter::Authentication::Util;

use strict;
use warnings;

our $VERSION = 0.4;

use Sys::Syslog qw{:standard :macros};

use Exporter qw{ import };
our @EXPORT = qw{
    loginfo
};

sub loginfo {
    my ( $line ) = @_;
    warn "$line\n";
    openlog('authentication_milter', 'pid', LOG_MAIL);
    setlogmask(   LOG_MASK(LOG_ERR)
                | LOG_MASK(LOG_INFO)
    );
    syslog( LOG_INFO, $line);
    closelog();
}


1;
