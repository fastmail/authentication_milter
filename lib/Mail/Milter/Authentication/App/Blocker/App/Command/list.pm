package Mail::Milter::Authentication::App::Blocker::App::Command::list;
# ABSTRACT: Command to list current blocks for a given file
# VERSION
use 5.20.0;
use Mail::Milter::Authentication::App::Blocker::Pragmas;
use Mail::Milter::Authentication::App::Blocker::App -command;
use TOML;
use Text::Table;

sub abstract { 'List current blocks in a given file' }
sub description { 'Parse a toml file and list the current blocks' }

sub opt_spec {
  return (
    [ 'file=s@', 'Config files to operate on' ],
  );
}

sub validate_args($self,$opt,$args) {
  # no args allowed but options!
  $self->usage_error('Must supply a filename') if ( !$opt->{file} );
  foreach my $file ( $opt->{file}->@* ) {
    $self->usage_error('Supplied filename does not exist') if ( ! -e $file );
  }
  $self->usage_error('No args allowed') if @$args;
}

sub execute($self,$opt,$args) {

  foreach my $file ( $opt->{file}->@* ) {

    say "In file $file";
    say '';

    open ( my $inf, '<', $file );
    my $body = do { local $/; <$inf> };
    close $inf;
    my ( $data, $error ) = from_toml( $body );

    if ( $error ) {
      say 'Error parsing file';
      say $error;
      exit 1;
    }

    my $tb = Text::Table->new(
      'Id',
      'Callback',
      'Value',
      'With',
      'Percent',
    );

    foreach my $key ( sort keys $data->%* ) {
      $tb->add(
        $key,
        $data->{$key}->{callback},
        $data->{$key}->{value},
        $data->{$key}->{with},
        $data->{$key}->{percent},
      );
    }

    print $tb->title;
    print $tb->rule('-');
    print $tb->body;
    say '';
  }
}

1;
