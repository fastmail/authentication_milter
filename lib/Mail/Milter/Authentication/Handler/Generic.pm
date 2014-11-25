package Mail::Milter::Authentication::Handler::Generic;

use strict;
use warnings;

our $VERSION = 0.3;

use Mail::Milter::Authentication::Config qw{ get_config };
use Mail::Milter::Authentication::Util;

use Sys::Syslog qw{:standard :macros};

sub new {
    my ( $class, $ctx ) = @_;
    my $self = {
        'ctx' => $ctx,
    };
    bless $self, $class;
    return $self;
}

sub dbgout {
    my ( $self, $key, $value, $priority ) = @_;
    my $ctx = $self->{'ctx'};
    warn "$key: $value\n";
    my $priv = $ctx->getpriv();
    if ( !exists( $priv->{'core.dbgout'} ) ) {
        $priv->{'core.dbgout'} = [];
    }
    push @{ $priv->{'core.dbgout'} },
      {
        'priority'   => $priority || LOG_INFO,
        'key'        => $key || q{},
        'value'      => $value || q{},
      };
}

sub log_error {
    my ( $self, $error ) = @_;
    $self->dbgout( 'ERROR', $error, LOG_ERR );
}

1;
