package Mail::Milter::Authentication::App::Blocker::Pragmas;
# ABSTRACT: Setup system wide pragmas
# VERSION
use 5.20.0;
use strict;
use warnings;
require feature;

use open ':std', ':encoding(UTF-8)';

sub import {
  strict->import();
  warnings->import();
  feature->import($_) for ( qw{ postderef signatures } );
  warnings->unimport($_) for ( qw{ experimental::postderef experimental::signatures } );
}

1;
