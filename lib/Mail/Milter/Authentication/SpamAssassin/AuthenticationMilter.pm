package Mail::Milter::Authentication::SpamAssassin::AuthenticationMilter;
use strict;
use warnings;
use feature qw(postderef);
no warnings qw(experimental::postderef); ## no critic
# VERSION

=head1 DESCRIPTION

Process Authentication-Results in Spam Assassin

=cut

use Mail::SpamAssassin::Plugin;
our @ISA = qw(Mail::SpamAssassin::Plugin);

use Mail::AuthenticationResults 1.20180923;
use Mail::AuthenticationResults::Parser;
use Mail::AuthenticationResults::Header::Group;

=constructor I<new()>

Create a SpamAssassin plugin which subclasses this class

package AuthenticationMilter;
use lib '/Users/marcbradshaw/git/authentication_milter/lib/';
use base 'Mail::Milter::Authentication::SpamAssassin::AuthenticationMilter';
1;

Load that pluigin into SpamAssassin and set the authserv-id for the headers
we should be checking

loadplugin AuthenticationMilter AuthenticationMilter.pm
authentication_results_authserv_id .example.com

=cut

sub new {
  my ($class, $mailsa) = @_;
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsa);
  bless ($self, $class);
  $self->register_eval_rule('authentication_results_dmarc_list_override');
  $self->register_eval_rule('authentication_results_has_key_value');
  $self->register_eval_rule('authentication_results_spf_fail');
  return $self;
}

=method I<parse_config()>

SpamAssassin plugin method to handle config entries

=cut

sub parse_config {
  my ( $self, $opts ) = @_;
  if ($opts->{key} eq 'authentication_results_authserv_id') {
    my $authserv_id = quotemeta( $opts->{value} );
    $self->{'authserv-id'} = $authserv_id;
    return 1;
  }
  return 0;
}

sub _get_authentication_results_objects {
  my ( $self, $per_msg_status ) = @_;
  my @objects;

  if ( exists ( $per_msg_status->{'_authmilter_authentication_results_objects'} ) ) {
    return $per_msg_status->{'_authmilter_authentication_results_objects'};
  }

  my $group = Mail::AuthenticationResults::Header::Group->new();

  my $headers = $per_msg_status->get('Authentication-Results');
  chomp $headers;
  foreach my $header ( split "\n", $headers ) {

    my $parsed = eval{ Mail::AuthenticationResults::Parser->new()->parse( $header ) };
    next if ! $parsed;
    $group->add_child( $parsed );
  }
  $per_msg_status->{'_authmilter_authentication_results_objects'} = $group;

  return $per_msg_status->{'_authmilter_authentication_results_objects'};
}

sub _get_authentication_results_objects_for_authserv_id {
  my ( $self, $per_msg_status ) = @_;
  my $header_objects = $self->_get_authentication_results_objects($per_msg_status);
  my $authserv_id = $self->{'authserv-id'};
  return $header_objects->search({ isa => 'header', authserv_id => qr{$authserv_id$} });
}

sub _get_authentication_results_objects_for_key_value {
  my ( $self, $per_msg_status, $key, $value ) = @_;
  return $self->_get_authentication_results_objects_for_authserv_id($per_msg_status)->search({ isa => 'entry', key => $key, value => $value });
}

sub _get_authentication_results_objects_for_key {
  my ( $self, $per_msg_status, $key ) = @_;
  return $self->_get_authentication_results_objects_for_authserv_id($per_msg_status)->search({ isa => 'entry', key => $key });
}

sub _entry_has_key {
  # return a count of the subentries with given key
  my ( $self, $authentication_results_object, $key ) = @_;
  return scalar $authentication_results_object->search({ isa => 'subentry', key => $key })->children()->@*;
}

sub _entry_has_key_value {
  # return a count of the subentries with given key and value
  my ( $self, $authentication_results_object, $key, $value ) = @_;
  return scalar $authentication_results_object->search({ isa => 'subentry', key => $key, value => $value })->children()->@*;
}

=method I<authentication_results_has_key_value( $key, $value )>

eval method, returns true if there is an authentication-results entry with the
given key and value.

header PTR_FAIL eval:authentication_results_has_key_value('x-ptr','fail')
score PTR_FAIL 1

header IPREV_FAIL eval:authentication_results_has_key_value('iprev','fail')
score IPREV_FAIL 1

header RETURN_FAIL eval:authentication_results_has_key_value('x-return-mx','fail')
RETURN_FAIL 2

header RETURN_WARN eval:authentication_results_has_key_value('x-return-mx','warn')
RETURN_WARN 1

header __SPF_ERROR eval:authentication_results_has_key_value('spf','error')
header __SPF_PERMERROR eval:authentication_results_has_key_value('spf','permerror')
header __SPF_TEMPERROR eval:authentication_results_has_key_value('spf','temperror')
meta SPF_ERROR __SPF_ERROR || __SPF_PERMERROR || __SPF_TEMPERROR
score SPF_ERROR 1

=cut

sub authentication_results_has_key_value {
  # Returns true if there was a failing sligned-from entry in the results
  my ( $self, $per_msg_status, $key, $value ) = @_;
  return 1 if ( scalar $self->_get_authentication_results_objects_for_key_value($per_msg_status,$key,$value)->children()->@* > 0 );
  return 0;
}

# Aligned From x-aligned-from
# Possible values: error null null_smtp null_header pass domain_pass orgdomain_pass fail

sub _authentication_results_spf_fail_sub {
  my ( $self, $per_msg_status, $spf_objects, $domain ) = @_;
  # Can we override a given domain fail with another spf result in the set.
  # Return 0 (fail) if we cannot, or 1 (pass) if we can.

  if ( $domain =~ /\@/ ) {
    $domain =~ s/^.*\@//;
  }
  my $domainregex = quotemeta( $domain );

  return 1 if scalar
    $spf_objects->search({ isa => 'entry', key => 'spf', value => qr{^(?!fail)}, has => [{ isa => 'subentry', key => 'smtp.mailfrom', value => qr{\@$domainregex$} }] })->children()->@*;
  return 1 if scalar
    $spf_objects->search({ isa => 'entry', key => 'spf', value => qr{^(?!fail)}, has => [{ isa => 'subentry', key => 'smtp.helo', value => $domain }] })->children()->@*;
  return 1 if scalar
    $spf_objects->search({ isa => 'entry', key => 'spf', value => qr{^(?!fail)}, has => [{ isa => 'subentry', key => 'policy.authdomain', value => $domain }] })->children()->@*;

  return 0;
}

=method I<authentication_results_spf_fail()>

eval method, returns true if there is an authentication-results entry for an spf fail
which does not also have a non fail entry for the same domain (as for example, would happen
when a trusted ARC forwarded adds a pass).

header SPF_FAIL eval:authentication_results_spf_fail()
score SPF_FAIL 1

=cut

sub authentication_results_spf_fail {
  # De we have any spf fail entries which do not have a corresponding pass entry (from for example, an arc override)
  my ( $self, $per_msg_status ) = @_;
  my $pass = 1;
  my $spf_objects = $self->_get_authentication_results_objects_for_key($per_msg_status,'spf');
  foreach my $header_object ( $spf_objects->children()->@* ) {
    next unless $header_object->value() eq 'fail';
    if ( my $authdomain = eval{ $header_object->search({ isa => 'subentry', key => 'policy.authdomain' })->children()->[0]->value() } ) {
      $pass = $pass && $self->_authentication_results_spf_fail_sub( $per_msg_status, $spf_objects, $authdomain );
    }
    elsif ( my $mailfrom = eval{ $header_object->search({ isa => 'subentry', key => 'smtp.mailfrom' })->children()->[0]->value() } ) {
        $pass = $pass && $self->_authentication_results_spf_fail_sub( $per_msg_status, $spf_objects, $mailfrom );
    }
    elsif ( my $helo = eval{ $header_object->search({ isa => 'subentry', key => 'smtp.helo' })->children()->[0]->value() } ) {
      $pass = $pass && $self->_authentication_results_spf_fail_sub( $per_msg_status, $spf_objects, $helo );
    }
    else {
      $pass = 0;
    }
  }
  return !$pass;
}

=method I<authentication_results_dmarc_list_override()>

eval method, returns true if there was a DMARC override for a failing reject/quarantine policy due
to detecting a list with a simple header check? (not a whitelist or arc)

header DMARC_LIST_OVERRIDE eval:authentication_results_dmarc_list_override()
score DMARC_LIST_OVERRIDE 2

DMARC Reject should be handled on the border, if not then we class this as a local policy override to quarantine.

DMARC Quarantine is handled by the X-Disposition-Quarantine: header

header DMARC_QUARANTINE X-Disposition-Quarantine =~ /\S/
score DMARC_QUARANTINE 10.0

=cut

sub authentication_results_dmarc_list_override {
  my ( $self, $per_msg_status ) = @_;
  foreach my $header_object ( $self->_get_authentication_results_objects_for_key($per_msg_status,'dmarc')->children()->@* ) {
    next unless $header_object->value() eq 'fail';
    next unless $self->_entry_has_key_value( $header_object, 'policy.arc-aware-result',      'fail' );
    next unless $self->_entry_has_key_value( $header_object, 'policy.applied-disposition',   'none' );
    next unless $self->_entry_has_key_value( $header_object, 'policy.override-reason',       'mailing_list' );
    next if     $self->_entry_has_key_value( $header_object, 'policy.evaluated-disposition', 'none' );
    return 1;
  }
  return 0;
}

1;
