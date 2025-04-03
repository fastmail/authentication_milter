package Mail::Milter::Authentication::Handler::Logger;
use 5.20.0;
use strict;
use warnings;
use Mail::Milter::Authentication::Pragmas;
# ABSTRACT: Handler class for logging of headerss
# VERSION
use base 'Mail::Milter::Authentication::Handler';

use Sys::Syslog qw{:standard :macros};

sub default_config {
    return {
        connect => 0,
        helo    => 0,
        envfrom => 0,
        envrcpt => 0,
        header  => [
          'from',
          'to',
          'message-id',
        ],
    };
}

sub connect_callback {
    my ( $self, $hostname, $ip ) = @_;
    my $config = $self->handler_config();
    return if ! $config->{connect};
    $self->dbgout( 'Logger', 'Connection host: ' . $hostname, LOG_INFO );
    $self->dbgout( 'Logger', 'Connection IP: ' . $ip->short(), LOG_INFO );
    return;
}

sub helo_callback {
    my ( $self, $helo_host ) = @_;
    my $config = $self->handler_config();
    return if ! $config->{helo};
    $self->dbgout( 'Logger', 'HELO: ' . $helo_host, LOG_INFO );
    return;
}

sub envfrom_callback {
    my ( $self, $env_from ) = @_;
    my $config = $self->handler_config();
    return if ! $config->{envfrom};
    $self->dbgout( 'Logger', 'MAIL FROM: ' . $env_from, LOG_INFO );
    return;
}

sub envrcpt_callback {
    my ( $self, $env_to ) = @_;
    my $config = $self->handler_config();
    return if ! $config->{envrcpt};
    $self->dbgout( 'Logger', 'RCPT TO: ' . $env_to, LOG_INFO );
    return;
}

sub header_callback {
    my ( $self, $header, $value ) = @_;
    my $config = $self->handler_config();
    return if ! $config->{header};
    my @wanted = map { lc $_ } sort $config->{header}->@*;
    if ( grep { $_ eq lc( $header ) } @wanted ) {
        $self->dbgout( 'Logger', 'Header: ' . $header . ': ' . $value, LOG_INFO );
    }
    return;
}

1;

__END__

=head1 DESCRIPTION

Log things

=head1 CONFIGURATION

        "Logger" : {                                    |
          "connect" : 1,                                | Log connection details
          "helo"    : 1,                                | Log HELO details
          "envfrom" : 1,                                | Log Mail From details
          "envrcpt" : 1,                                | Log Mail To details
          "header" : [                                  | List of headers to log
            "From",
            "To",
            "Message-Id",
          ]
        }

