package TestAlignedFromHandler;

use Test::More;

use Mail::Milter::Authentication::Tester::HandlerTester;
use Mail::Milter::Authentication::Constants qw{ :all };

# Common subs for testing the Aligned From handler in different configurations

sub test_dmarc {
    my ( $tester ) = @_;
    # Org domain pass cases
    subtest 'Org domains with DMARC enabled' => sub {
        test($tester,{ 'name' => 'org pass 1', 'mailfrom' => 'test@test.example.com', 'from' => 'From: test@example.com', 'result' => 'orgdomain_pass', 'comment' => 'Domain org match' });
        test($tester,{ 'name' => 'org pass 2', 'mailfrom' => 'test@example.com', 'from' => 'From: test@test.example.com', 'result' => 'orgdomain_pass', 'comment' => 'Domain org match' });
        test($tester,{ 'name' => 'org pass 3', 'mailfrom' => 'test@test2.example.com', 'from' => 'From: test@test.example.com', 'result' => 'orgdomain_pass', 'comment' => 'Domain org match' });
        test($tester,{ 'name' => 'fail', 'mailfrom' => 'test@test.example.net', 'from' => 'From: test@test.example.com', 'result' => 'fail', 'comment' => '' });
    };
}

sub test_no_dmarc {
    my ( $tester ) = @_;
    # Org domain pass cases
    subtest 'Org domains with DMARC disabled' => sub {
        test($tester,{ 'name' => 'org pass 1', 'mailfrom' => 'test@test.example.com', 'from' => 'From: test@example.com', 'result' => 'fail', 'comment' => '' });
        test($tester,{ 'name' => 'org pass 2', 'mailfrom' => 'test@example.com', 'from' => 'From: test@test.example.com', 'result' => 'fail', 'comment' => '' });
        test($tester,{ 'name' => 'org pass 3', 'mailfrom' => 'test@test2.example.com', 'from' => 'From: test@test.example.com', 'result' => 'fail', 'comment' => '' });
        test($tester,{ 'name' => 'fail', 'mailfrom' => 'test@test.example.net', 'from' => 'From: test@test.example.com', 'result' => 'fail', 'comment' => '' });
    };
}

sub test_dmarc_or_not {
    my ( $tester ) = @_;

    # Pass cases
    subtest 'Simple pass casse' => sub{
        test($tester,{ 'name' => 'simple pass', 'mailfrom' => 'test@example.com', 'from' => 'From: test@example.com', 'result' => 'pass', 'comment' => 'Address match' });
        test($tester,{ 'name' => 'header lower case', 'mailfrom' => 'test@example.com', 'from' => 'from: test@example.com', 'result' => 'pass', 'comment' => 'Address match' });
        test($tester,{ 'name' => 'header upper case', 'mailfrom' => 'test@example.com', 'from' => 'FROM: test@example.com', 'result' => 'pass', 'comment' => 'Address match' });
    };

    # Domain pass
    subtest 'Domain pass cases' => sub{
        test($tester,{ 'name' => 'domain pass', 'mailfrom' => 'test@example.com', 'from' => 'From: test2@example.com', 'result' => 'domain_pass', 'comment' => 'Domain match' });
    };

    # No domains at all
    subtest 'No domains' => sub{
        test($tester,{ 'name' => 'no domains', 'mailfrom' => '', 'from' => 'X-Null: Nothing', 'result' => 'null', 'comment' => 'No domains found'  });
    };

    # Envelope variations
    subtest 'Variations on envelope' => sub{
        test($tester,{ 'name' => '<> in envelope', 'mailfrom' => '<test@example.com>', 'from' => 'From: test@example.com', 'result' => 'pass', 'comment' => 'Address match' });
        test($tester,{ 'name' => 'null envelope', 'mailfrom' => '', 'from' => 'From: test@example.com', 'result' => 'null_smtp', 'comment' => 'No envelope domain' });
        test($tester,{ 'name' => 'null <> envelope', 'mailfrom' => '<>', 'from' => 'From: test@example.com', 'result' => 'null_smtp', 'comment' => 'No envelope domain' });
        test($tester,{ 'name' => 'multiple envelope address in <>', 'mailfrom' => '<test@example.com> <test2@example.com>', 'from' => 'From: test@example.com', 'result' => 'error', 'comment' => 'Multiple addresses in envelope' });
        test($tester,{ 'name' => 'multiple envelope address', 'mailfrom' => 'test@example.com test2@example.com', 'from' => 'From: test@example.com', 'result' => 'error', 'comment' => 'Multiple addresses in envelope' });
        test($tester,{ 'name' => 'multiple envelope domain', 'mailfrom' => 'test@example.com test@example.net', 'from' => 'From: test@example.com', 'result' => 'error', 'comment' => 'Multiple addresses in envelope' });
    };

    # Header variations
    subtest 'Variations on header' => sub {
        test($tester,{ 'name' => 'no from headers', 'mailfrom' => 'test@example.com', 'from' => 'X-Null: Nothing', 'result' => 'null_header', 'comment' => 'No header domain' });
        test($tester,{ 'name' => 'null from header', 'mailfrom' => 'test@example.com', 'from' => "From: ", 'result' => 'null_header', 'comment' => 'No header domain' });
        test($tester,{ 'name' => 'multiple from headers', 'mailfrom' => 'test@example.com', 'from' => "From: test\@example.com\nFrom: test\@example.com", 'result' => 'error', 'comment' => 'Multiple addresses in header' });
        test($tester,{ 'name' => 'multiple from headers domains', 'mailfrom' => 'test@example.com', 'from' => "From: test\@example.com\nFrom: test\@example.net", 'result' => 'error', 'comment' => 'Multiple addresses in header' });
        test($tester,{ 'name' => 'multiple from addresses match last', 'mailfrom' => 'test@example.com', 'from' => "From: test2\@example.com test\@example.com", 'result' => 'pass', 'comment' => 'Address match' });
        test($tester,{ 'name' => 'multiple from addresses match first', 'mailfrom' => 'test@example.com', 'from' => "From: test\@example.com test2\@example.com", 'result' => 'domain_pass', 'comment' => 'Domain match' });
        test($tester,{ 'name' => 'multiple from addresses domains', 'mailfrom' => 'test@example.com', 'from' => "From: test\@example.com test\@example.net", 'result' => 'error', 'comment' => 'Multiple addresses in header' });
    };

}

sub test {
    my ( $tester, $args ) = @_;

    $tester->run({
        'connect_ip' => '1.2.3.4',
        'connect_name' => 'mx.example.com',
        'helo' => 'mx.example.com',
        'mailfrom' => $args->{ 'mailfrom' },
        'rcptto' => [ 'test@example.net' ],
        'body' => $args->{ 'from' } . '
To: test@example.net
Subject: This is a test

Testing',
});

    my $header = $tester->get_authresults_header()->search({ 'key' => 'x-aligned-from' });
    #print Dumper $header;
    my $result = eval{ $header->children()->[0]->value(); };
    is( scalar @{ $header->children() }, 1, '1 Entry' );
    my $comment = eval{ $header->search({ 'isa' => 'comment' })->children()->[0]->value(); } // q{};

    is( $result, $args->{ 'result' }, $args->{ 'name' } . ' result' );
    is( $comment, $args->{ 'comment' }, $args->{ 'name' } .' comment' );

    return;
}


1;

