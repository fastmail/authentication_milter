#!/usr/bin/env perl

use strict;
use warnings;
use lib 't';

use Test::More;

eval{ require Mail::SpamAssassin; };
if ( $@ ) {
    plan skip_all => 'Mail::SpamAssassin not present';
    done_testing();
}

my $config = <<EOM;
loadplugin Mail::SpamAssassin::Plugin::Check

loadplugin Mail::Milter::Authentication::SpamAssassin::AuthenticationMilter lib/Mail/Milter/Authentication/SpamAssassin/AuthenticationMilter.pm
authentication_results_authserv_id .example.com

header TEST_DMARC_LIST_OVERRIDE eval:authentication_results_dmarc_list_override()
score TEST_DMARC_LIST_OVERRIDE 2

header TEST_PTR_FAIL eval:authentication_results_has_key_value('x-ptr','fail')
score TEST_PTR_FAIL 1

header TEST_IPREV_FAIL eval:authentication_results_has_key_value('iprev','fail')
score TEST_IPREV_FAIL 1

header TEST_SPF_FAIL eval:authentication_results_spf_fail()
score TEST_SPF_FAIL 1
meta SPF_FAIL TEST_SPF_FAIL

EOM

my $sa = Mail::SpamAssassin->new({
    'config_text' => $config,
});

my $body = <<EOM;
Authentication-Results: mx4.example.com;
    arc=none (no signatures found);
    dkim=none (no signatures found);
    dmarc=fail policy.published-domain-policy=reject
      policy.published-subdomain-policy=none
      policy.applied-disposition=none
      policy.evaluated-disposition=reject
      policy.override-reason=mailing_list policy.arc-aware-result=fail
      (p=reject,sp=none,has-list-id=yes,d=quarantine,d.eval=reject,override=local_policy,arc_aware_result=fail)
      header.from=example.net;
    iprev=pass policy.iprev=1.2.3.4 (test.example.org);
    spf=fail smtp.mailfrom=marc\@example.net
      smtp.helo=example.org;
    spf=pass smtp.mailfrom=marc\@example.net
    x-aligned-from=pass (Address match);
    x-cm=none score=0;
    x-ptr=fail smtp.helo=example.org
      policy.ptr=test.example.org;
    dmarc=pass policy.published-domain-policy=reject
      policy.published-subdomain-policy=none
      policy.applied-disposition=quarantine
      policy.evaluated-disposition=reject
      policy.override-reason=local_policy policy.arc-aware-result=fail
      (p=reject,sp=none,has-list-id=yes,d=quarantine,d.eval=reject,override=local_policy,arc_aware_result=fail)
      header.from=example.org;
    x-return-mx=pass header.domain=example.net policy.is_org=yes
      (MX Record found);
    x-return-mx=pass smtp.domain=example.net policy.is_org=yes
      (MX Record found);
    x-vs=clean score=10 state=0
From: test\@example.co.uk
Subject: Test

This is a test
EOM

my $status = $sa->check_message_text( $body );
my @tags = split( ',', $status->get_names_of_tests_hit() );

is( grep( /TEST_DMARC_LIST_OVERRIDE/, @tags ), 1, 'DMARC Override found' );
is( grep( /TEST_PTR_FAIL/, @tags ), 1, 'PTR Fail found' );
is( grep( /TEST_IPREV_FAIL/, @tags ), 0, 'IPRev Fail not found' );
is( grep( /TEST_SPF_FAIL/, @tags ), 0, 'SPF Fail found pass' );

$body = <<EOM;
Authentication-Results: mx4.example.com;
    arc=none (no signatures found);
    dkim=none (no signatures found);
    dmarc=fail policy.published-domain-policy=reject
      policy.published-subdomain-policy=none
      policy.applied-disposition=none
      policy.evaluated-disposition=reject
      policy.override-reason=trusted_forwarded policy.arc-aware-result=pass
      (p=reject,sp=none,has-list-id=yes,d=quarantine,d.eval=reject,override=local_policy,arc_aware_result=fail)
      header.from=example.net;
    iprev=pass policy.iprev=1.2.3.4 (test.example.org);
    spf=fail smtp.mailfrom=marc\@example.net
      smtp.helo=example.org;
    spf=pass smtp.mailfrom=marc\@example.org
    x-aligned-from=pass (Address match);
    x-cm=none score=0;
    x-ptr=fail smtp.helo=example.org
      policy.ptr=test.example.org;
    dmarc=pass policy.published-domain-policy=reject
      policy.published-subdomain-policy=none
      policy.applied-disposition=quarantine
      policy.evaluated-disposition=reject
      policy.override-reason=local_policy policy.arc-aware-result=fail
      (p=reject,sp=none,has-list-id=yes,d=quarantine,d.eval=reject,override=local_policy,arc_aware_result=fail)
      header.from=example.org;
    x-return-mx=pass header.domain=example.net policy.is_org=yes
      (MX Record found);
    x-return-mx=pass smtp.domain=example.net policy.is_org=yes
      (MX Record found);
    x-vs=clean score=10 state=0
From: test\@example.co.uk
Subject: Test

This is a test
EOM

$status = $sa->check_message_text( $body );
@tags = split( ',', $status->get_names_of_tests_hit() );

is( grep( /TEST_DMARC_LIST_OVERRIDE/, @tags ), 0, 'DMARC Override not found' );
is( grep( /TEST_SPF_FAIL/, @tags ), 1, 'SPF Fail found' );

done_testing();

