package Mail::Milter::Authentication::ObjectBroker;

use strict;
use warnings;

our $VERSION = 0.4;

use Mail::Milter::Authentication;
use Mail::Milter::Authentication::Handler;
use Mail::Milter::Authentication::Handler::Generic;
use Mail::Milter::Authentication::Handler::Auth;
use Mail::Milter::Authentication::Handler::Core;
use Mail::Milter::Authentication::Handler::DKIM;
use Mail::Milter::Authentication::Handler::DMARC;
use Mail::Milter::Authentication::Handler::IPRev;
use Mail::Milter::Authentication::Handler::LocalIP;
use Mail::Milter::Authentication::Handler::PTR;
use Mail::Milter::Authentication::Handler::Sanitize;
use Mail::Milter::Authentication::Handler::SenderID;
use Mail::Milter::Authentication::Handler::SPF;
use Mail::Milter::Authentication::Handler::TrustedIP;

sub connect_callback {
    my @args = @_;
    my $ctx  = shift @args;
    # Core Handler Object Setup
    my $priv    = {};
    my $handler = Mail::Milter::Authentication::Handler->new( $ctx );
    $priv->{'handler_object'} = $handler;
    $ctx->setpriv($priv);
    # Sub Handlers Object Setup
    $handler->set_handler( 'generic',   Mail::Milter::Authentication::Handler::Generic->new( $ctx ) );
    $handler->set_handler( 'auth',      Mail::Milter::Authentication::Handler::Auth->new( $ctx ) );
    $handler->set_handler( 'core',      Mail::Milter::Authentication::Handler::Core->new( $ctx ) );
    $handler->set_handler( 'dkim',      Mail::Milter::Authentication::Handler::DKIM->new( $ctx ) );
    $handler->set_handler( 'dmarc',     Mail::Milter::Authentication::Handler::DMARC->new( $ctx ) );
    $handler->set_handler( 'iprev',     Mail::Milter::Authentication::Handler::IPRev->new( $ctx ) );
    $handler->set_handler( 'localip',   Mail::Milter::Authentication::Handler::LocalIP->new( $ctx ) );
    $handler->set_handler( 'ptr',       Mail::Milter::Authentication::Handler::PTR->new( $ctx ) );
    $handler->set_handler( 'sanitize',  Mail::Milter::Authentication::Handler::Sanitize->new( $ctx ) );
    $handler->set_handler( 'senderid',  Mail::Milter::Authentication::Handler::SenderID->new( $ctx ) );
    $handler->set_handler( 'spf',       Mail::Milter::Authentication::Handler::SPF->new( $ctx ) );
    $handler->set_handler( 'trustedip', Mail::Milter::Authentication::Handler::TrustedIP->new( $ctx ) );
    return $handler->connect_callback( @args );
}

sub helo_callback {
    my @args    = @_;
    my $ctx     = shift @args;
    my $priv    = $ctx->getpriv();
    my $handler = $priv->{'handler_object'};
    return $handler->helo_callback(@args);
}
sub envfrom_callback {
    my @args    = @_;
    my $ctx     = shift @args;
    my $priv    = $ctx->getpriv();
    my $handler = $priv->{'handler_object'};
    return $handler->envfrom_callback(@args);
}

sub envrcpt_callback {
    my @args    = @_;
    my $ctx     = shift @args;
    my $priv    = $ctx->getpriv();
    my $handler = $priv->{'handler_object'};
    return $handler->envrcpt_callback(@args);
}

sub header_callback {
    my @args    = @_;
    my $ctx     = shift @args;
    my $priv    = $ctx->getpriv();
    my $handler = $priv->{'handler_object'};
    return $handler->header_callback(@args);
}

sub eoh_callback {
    my @args    = @_;
    my $ctx     = shift @args;
    my $priv    = $ctx->getpriv();
    my $handler = $priv->{'handler_object'};
    return $handler->eoh_callback(@args);
}

sub body_callback {
    my @args    = @_;
    my $ctx     = shift @args;
    my $priv    = $ctx->getpriv();
    my $handler = $priv->{'handler_object'};
    return $handler->body_callback(@args);
}

sub eom_callback {
    my @args    = @_;
    my $ctx     = shift @args;
    my $priv    = $ctx->getpriv();
    my $handler = $priv->{'handler_object'};
    return $handler->eom_callback(@args);
}

sub abort_callback {
    my @args    = @_;
    my $ctx     = shift @args;
    my $priv    = $ctx->getpriv();
    my $handler = $priv->{'handler_object'};
    return $handler->abort_callback(@args);
}

sub close_callback {
    my @args    = @_;
    my $ctx     = shift @args;
    my $priv    = $ctx->getpriv();
    my $handler = $priv->{'handler_object'};
    my $return_value = $handler->close_callback(@args);

    # Destroy handlers
    $handler->destroy_handler( 'generic' );
    $handler->destroy_handler( 'auth' );
    $handler->destroy_handler( 'core' );
    $handler->destroy_handler( 'dkim' );
    $handler->destroy_handler( 'dmarc' );
    $handler->destroy_handler( 'iprev' );
    $handler->destroy_handler( 'localip' );
    $handler->destroy_handler( 'ptr' );
    $handler->destroy_handler( 'sanitize' );
    $handler->destroy_handler( 'senderid' );
    $handler->destroy_handler( 'spf' );
    $handler->destroy_handler( 'trustedip' );
    delete $priv->{'handler_object'}; 

    return $return_value;
}

1;
