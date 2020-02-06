package Mail::Milter::Authentication::App::Blocker::App::Command::add;
use 5.20.0;
use strict;
use warnings;
# ABSTRACT: Command to add a block to a given file
# VERSION
use Mail::Milter::Authentication::App::Blocker::Pragmas;
use Mail::Milter::Authentication::App::Blocker::App -command;
use TOML;
use Text::Table;
use Date::Manip::Date;

sub abstract { 'Add a block to a given file' }
sub description { 'Add a block to a given toml file' };

sub opt_spec {
  return (
    [ 'file=s', 'Config file to operate on' ],
    [ 'id=s', 'ID of the block to add' ],
    [ 'callback=s', 'callback stage of the block to add' ],
    [ 'value=s', 'value of the block to add' ],
    [ 'with=s', 'SMTP result of the block to add' ],
    [ 'percent=s', 'percent of the mail to block' ],
    [ 'until=s', 'time of block expiry' ],
  );
}

sub validate_args($self,$opt,$args) {
  # no args allowed but options!
  $self->usage_error('Must supply a filename') if ( !$opt->{file} );
  $self->usage_error('Supplied filename does not exist') if ( ! -e $opt->{file} );
  $self->usage_error('Must supply an id') if ( !$opt->{id} );

  $self->usage_error('Must supply a callback') if ( !$opt->{callback} );
  my @valid_callbacks = ( qw{ connect helo envfrom envrcpt header });
  unless ( grep { $opt->{callback} eq $_ } @valid_callbacks ) {
    $self->usage_error('Callback must be one of '.join(', ',@valid_callbacks));
  }

  $self->usage_error('Must supply a value') if ( !$opt->{value} );

  $self->usage_error('Must supply a with') if ( !$opt->{with} );
  my ( $rcode, $xcode, $message ) = split( ' ', $opt->{with}, 3 );
  if ($rcode !~ /^[4|5]\d\d$/ || $xcode !~ /^[4|5]\.\d+\.\d+$/ || substr($rcode, 0, 1) ne substr($xcode, 0, 1)) {
    $self->usage_error('With is invalid, please use extended return code format');
  }

  $self->usage_error('Must supply a percent') if ( ! defined $opt->{percent} );
  $self->usage_error('Percent must be a number') if ( ! ($opt->{percent} =~ /^\d+$/) );
  $self->usage_error('Percent must be a number between 0 and 100') if ( ( $opt->{percent} < 0 ) || ( $opt->{percent} > 100 ) );

  if ( $opt->{until} ) {
    my $dmdate = Date::Manip::Date->new;
    if ( !$dmdate->parse($opt->{until}) ) {
      $opt->{until} = $dmdate->secs_since_1970_GMT();
    }
    else {
      $self->usage_error('Could not parse until date');
    }
  }
  else {
    $opt->{until} = 0;
  }

  $self->usage_error('No args allowed') if @$args;
}

sub execute($self,$opt,$args) {

  open ( my $inf, '<', $opt->{file} );
  my $body = do { local $/; <$inf> };
  close $inf;
  my ( $data, $error ) = from_toml( $body );

  if ( $error ) {
    say 'Error parsing file';
    say $error;
    exit 1;
  }

  if ( exists $data->{$opt->{id}} ) {
    say 'The given ID already exists in that file';
    exit 1;
  }

  $data->{$opt->{id}} = {
    callback => $opt->{callback},
    value => $opt->{value},
    with => $opt->{with},
    percent => $opt->{percent},
    until => $opt->{until},
  };

  open my $outf, '>', $opt->{file};
  print $outf to_toml($data);
  close $outf;

  say 'Block added and file saved';

}

1;


