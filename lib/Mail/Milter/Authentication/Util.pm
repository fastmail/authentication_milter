package Mail::Milter::Authentication::Util;

use strict;
use warnings;

our $VERSION = 0.5;

use English;
use Sys::Syslog qw{:standard :macros};

use Mail::Milter::Authentication::Config qw{ get_config };

use Exporter qw{ import };
our @EXPORT = qw{
  logerror
  loginfo
  logdebug
};

sub logerror {
    my ($line) = @_;
    warn "$PID: $line\n";
    openlog( 'authentication_milter', 'pid', LOG_MAIL );
    setlogmask( LOG_MASK(LOG_ERR) );
    syslog( LOG_ERR, $line );
    closelog();
}

sub loginfo {
    my ($line) = @_;
    warn "$PID: $line\n";
    openlog( 'authentication_milter', 'pid', LOG_MAIL );
    setlogmask( LOG_MASK(LOG_INFO) );
    syslog( LOG_INFO, $line );
    closelog();
}

sub logdebug {
    my ($line) = @_;
    warn "$PID: $line\n";
    my $CONFIG = get_config();
    if ( $CONFIG->{'debug'} ) {
        openlog( 'authentication_milter', 'pid', LOG_MAIL );
        setlogmask( LOG_MASK(LOG_DEBUG) );
        syslog( LOG_DEBUG, $line );
        closelog();
    }
}

1;
