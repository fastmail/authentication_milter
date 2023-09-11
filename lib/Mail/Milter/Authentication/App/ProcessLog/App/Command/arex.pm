package Mail::Milter::Authentication::App::ProcessLog::App::Command::arex;
use 5.20.0;
use strict;
use warnings;
use Mail::Milter::Authentication::Pragmas;
# ABSTRACT: Command to convert an authentication milter arex log back into an A-R header
# VERSION
use Mail::Milter::Authentication::App::ProcessLog::App -command;
use JSON::XS;
use Mail::AuthenticationResults 2.20230112;
use Mail::AuthenticationResults::Parser;
use Mail::AuthenticationResults::Header;

sub abstract { 'Convert ARex format log lines into Authentication-Results format ' }
sub description { 'Read ARex format line(s) and output standard Authentication-Results headers' }
sub usage_desc { "%c arex %o [<log_file>] [<log_file>]" }

sub opt_spec {
  return (
  [ 'combine|c',
      'Combine multiple headers per log entry into one',
      { default => 0 } ],
  [ 'fold_at|a=s',
      'Column to fold returned headers at',
      { default => 99999 } ],
  [ 'indent_by|b=s',
      'How many spaces to indent folders headers by', ],
  [ 'indent_style|s=s',
      'Indent/folding style (none/entry/subentry/full)' ],
  [ 'space|p=s',
      'Number of blank lines between results',
      { default => 0 } ],
  );
}

sub bad_number($value) {
  return 0 unless defined $value;
  return 0 if $value =~ /^\d+$/;
  return 1;
}

sub validate_args($self,$opt,$args) {

  if ($opt->{indent_style}) {
    $self->usage_error('Unknown indent style')
      unless $opt->{indent_style} eq 'none'
          || $opt->{indent_style} eq 'entry'
          || $opt->{indent_style} eq 'subentry'
          || $opt->{indent_style} eq 'full';
  }

  $self->usage_error('indent_by must be numeric') if bad_number($opt->{indent_by});
  $self->usage_error('space must be numeric') if bad_number($opt->{space});
  $self->usage_error('fold_at must be numeric') if bad_number($opt->{fold_at});

  if (@$args) {
    for my $filename (@$args) {
      $self->usage_error("File $filename does not exist or is unreadable")
        unless -f $filename && -r $filename;
    }
  }
}

sub formatted_object($self, $opt, $object) {
  $object->set_fold_at($opt->fold_at) if $opt->fold_at;
  $object->set_indent_by($opt->indent_by) if $opt->indent_by;
  $object->set_indent_style($opt->indent_style) if $opt->indent_style;
  return $object->as_string;
}

sub execute($self, $opt, $args) {
  if (@$args == 0) {
    $self->parse_file(\*STDIN, $opt, $args);
  } else {
    for my $filename (@$args) {
      open my $file, '<', $filename;
      $self->parse_file($file, $opt, $args);
      close $file;
    }
  }
}

sub parse_file($self, $file, $opt, $args) {
  state $j = JSON::XS->new;

  LINE: for my $line (<$file>) {
    $line =~ s/^.* ARex: //;
    my $parser = Mail::AuthenticationResults::Parser->new;
    my $hashref = eval{ $j->decode($line) };
    unless ($hashref) {
      print "Error decoding line.\n";
      next LINE;
    }

    my $object;
    AR: for my $ar ( $hashref->{ar}->@* ) {
      my $type = $ar->{type};
      {
        no warnings;

        unless ($opt->combine) {
          # If we are not combining entries, just output this one.
          $object = $parser->_from_hashref($ar->{payload});
          print "$type: ".$self->formatted_object($opt, $object)."\n";
          next AR;
        }

        # When combining, add to the current object if we have one, or create
        # a new one if we do not.
        if ($object) {
          $object->copy_children_from($parser->_from_hashref($ar->{payload}));
        } else {
          $object = $parser->_from_hashref($ar->{payload});
        }
      }
    }
  
    # When combining, output the combined object here.
    print "Authentication-Results: ".$self->formatted_object($opt, $object)."\n"
      if $opt->combine;

    # And add a bunch of spacers if/as requested
    print "\n" x $opt->space;
  }
}

1;


