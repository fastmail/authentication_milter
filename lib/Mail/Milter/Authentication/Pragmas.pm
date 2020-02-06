package Mail::Milter::Authentication::Pragmas;
use 5.20.0;
use strict;
use warnings;
# ABSTRACT: Setup system wide pragmas
# VERSION
require feature;

use open ':std', ':encoding(UTF-8)';

sub import {
  strict->import();
  warnings->import();
  feature->import($_) for ( qw{ postderef signatures } );
  warnings->unimport($_) for ( qw{ experimental::postderef experimental::signatures } );
}

1;
