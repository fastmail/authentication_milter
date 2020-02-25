package Mail::Milter::Authentication::Pragmas;
use 5.20.0;
use strict;
use warnings;
# ABSTRACT: Setup system wide pragmas
# VERSION
use base 'Exporter';
require feature;
use open ':std', ':encoding(UTF-8)';
use Import::Into;

use Mail::Milter::Authentication::Constants;
use Mail::Milter::Authentication::Config;
use Carp;
use Clone;
use English;
use JSON;
use Module::Load;
use Module::Loaded;
use Mail::AuthenticationResults 1.20200108;
use Mail::AuthenticationResults::Header;
use Mail::AuthenticationResults::Header::AuthServID;
use Mail::AuthenticationResults::Header::Comment;
use Mail::AuthenticationResults::Header::Entry;
use Mail::AuthenticationResults::Header::SubEntry;


sub import {
  strict->import();
  warnings->import();
  feature->import($_)               for ( qw{ postderef signatures } );
  warnings->unimport($_)            for ( qw{ experimental::postderef experimental::signatures } );

  Mail::Milter::Authentication::Config->import::into(scalar caller,qw{ set_config get_config });
  Mail::Milter::Authentication::Constants->import::into(scalar caller);

  Carp->import::into(scalar caller);
  Clone->import::into(scalar caller,qw{ clone });
  English->import::into(scalar caller);
  JSON->import::into(scalar caller);
  Module::Load->import::into(scalar caller);
  Module::Loaded->import::into(scalar caller);
}

1;
