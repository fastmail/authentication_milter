package AuthenticationMilter::Handler;

use strict;
use warnings;

use Email::Address;
use Mail::DKIM::Verifier;
use Mail::DMARC::PurePerl;
use Mail::SPF;
use Net::DNS;
use Net::IP;
use Sendmail::PMilter qw { :all };
use Socket;
use Sys::Syslog qw{:standard :macros};

## TODO
# Check auth and report
# Skip some checks if connection is auth

my $CONFIG = {
    'check_spf'       => 1,
    'check_dkim'      => 1,
    'check_dkim-adsp' => 1,
    'check_dmarc'     => 1,
    'check_ptr'       => 1,
    'check_iprev'     => 1,
    'check_senderid'  => 1,
};

# If AUTHENTICATED do not check spf dkim-adsp dmarc ptr iprev or senderid
# If LOCAL         do not check spf dkim-adsp dmarc ptr iprev or senderid

if ( $CONFIG->{'check_dmarc'} ) {
    if ( not $CONFIG->{'check_dkim'} ) { die 'dmarc checks require dkim to be enabled'; } ;
    if ( not $CONFIG->{'check_spf'} )  { die 'dmarc checks require spf to be enabled'; } ;
}
if ( $CONFIG->{'check_ptr'} ) {
    if ( not $CONFIG->{'check_iprev'} ) { die 'ptr checks require iprev to be enabled'; } ;
}

sub get_auth_name {
    my ($ctx) = @_;
    my $name = get_symval( $ctx, '{auth_authen}' );
    return $name;
}

sub get_my_hostname {
    my ($ctx) = @_;
    my $hostname = get_symval( $ctx, 'j' );
    return $hostname;
}

sub is_local_ip_address {
    my ( $ctx, $ip_address ) = @_;
    my $ip = new Net::IP( $ip_address );
    my $ip_type = $ip->iptype();
    my $type_map = {
        'PRIVATE'              => 1,
        'SHARED'               => 1,
        'LOOPBACK'             => 1,
        'LINK-LOCAL'           => 1,
        'RESERVED'             => 1,
        'TEST-NET'             => 0,
        '6TO4-RELAY'           => 0,
        'MULTICAST'            => 0,
        'BROADCAST'            => 0,
        'UNSPECIFIED'          => 0,
        'IPV4MAP'              => 0,
        'DISCARD'              => 0,
        'GLOBAL-UNICAST'       => 0,
        'TEREDO'               => 0,
        'BMWG'                 => 0,
        'DOCUMENTATION'        => 0,
        'ORCHID'               => 0,
        '6TO4'                 => 0,
        'UNIQUE-LOCAL-UNICAST' => 1,
        'LINK-LOCAL-UNICAST'   => 1,
    };
    dbgout( $ctx, 'IPAddress', "Address $ip_address detected as type $ip_type", LOG_DEBUG );
    return $type_map->{ $ip_type } || 0;
}

sub is_hostname_mine {
    my ( $ctx, $check_hostname ) = @_;
    my $hostname = get_my_hostname($ctx);
    my ($check_for) = $hostname =~ /^[^\.]+\.(.*)/;
    if (
        substr( lc $check_hostname, ( 0 - length($check_for) ) ) eq
        lc $check_for )
    {
        return 1;
    }
}

sub get_symval {
    my ( $ctx, $key ) = @_;
    my $val = $ctx->getsymval( $key );
    return $val if defined( $val );
    # We didn't find it?
    # PMilter::Context fails to get the queue id from postfix as it is
    # not searching symbols for the correct code. Rewrite this here.
    my $symbols = $ctx->{'symbols'}; ## Internals, here be dragons!
    foreach my $code ( keys $symbols ) {
        $val = $symbols->{$code}->{$key};
        return $val if defined( $val );
    }
    return undef;
}

sub get_domain_from {
    my ($address) = @_;
    $address = get_address_from($address);
    my $domain = 'localhost.localdomain';
    $address =~ s/<//g;
    $address =~ s/>//g;
    if ( $address =~ /\@/ ) {
        ($domain) = $address =~ /.*\@(.*)/;
    }
    return $domain;
}

sub get_address_from {
    my ($address) = @_;
    my @addresses = Email::Address->parse($address);
    if (@addresses) {
        my $first = $addresses[0];
        return $first->address();
    }
    else {
        # We couldn't parse, so just run with it and hope for the best
        return $address;
    }
}

sub format_ctext {
    # Return ctext (but with spaces intact)
    my ($text) = @_;
    $text =~ s/\t/ /g;
    $text =~ s/\n/ /g;
    $text =~ s/\r/ /g;
    $text =~ s/\(/ /g;
    $text =~ s/\)/ /g;
    $text =~ s/\\/ /g;
    return $text;
}

sub format_ctext_no_space {
    my ($text) = @_;
    $text = format_ctext($text);
    $text =~ s/ //g;
    return $text;
}

sub format_header_comment {
    my ($comment) = @_;
    $comment = format_ctext($comment);
    return $comment;
}

sub format_header_entry {
    my ( $key, $value ) = @_;
    $key   = format_ctext_no_space($key);
    $value = format_ctext_no_space($value);
    my $string = $key . '=' . $value;
    return $string;
}

sub connect_callback {
    # On Connect
    my ( $ctx, $hostname, $sockaddr_in ) = @_;
    my $priv = {};
    $ctx->setpriv($priv);
    
    $priv->{ 'is_local_ip_address' } = 0;
    $priv->{ 'is_authenticated' }    = 0;

    eval {
        my ( $port, $iaddr, $ip_address );
        my $ip_length = length( $sockaddr_in );
        if ( $ip_length eq 16 ) {
            ( $port, $iaddr ) = sockaddr_in($sockaddr_in);
            $ip_address = inet_ntoa($iaddr);
        }
        elsif ( $ip_length eq 28 ) {
            ( $port, $iaddr ) = sockaddr_in6($sockaddr_in);
            $ip_address = Socket::inet_ntop(AF_INET6, $iaddr);
        }
        else {
            die 'Unknown IP address format';
        }
        $priv->{'ip_address'} = $ip_address;
        dbgout( $ctx, 'ConnectFrom', $ip_address, LOG_DEBUG );

        if ( is_local_ip_address( $ctx, $ip_address ) ) {
            $priv->{ 'is_local_ip_address' } = 1;
        }

        my $dkim;
        if ( $CONFIG->{'check_dkim'} ) {
            $dkim = Mail::DKIM::Verifier->new();
            $priv->{'dkim_obj'} = $dkim;
        }

        my $dmarc;
        if ( $CONFIG->{'check_dmarc'} && ( $priv->{'is_local_ip_address'} == 0 ) && ( $priv->{'is_authenticated'} == 0 ) ) {
            $dmarc = Mail::DMARC::PurePerl->new();
            eval { $dmarc->source_ip($ip_address) };
            if ( my $error = $@ ) {
                log_error( $ctx, 'DMARC IP Error ' . $error );
            }
            $priv->{'dmarc_obj'} = $dmarc;
        }

        my $spf_server;
        if ( $CONFIG->{'check_spf'} && ( $priv->{'is_local_ip_address'} == 0 ) && ( $priv->{'is_authenticated'} == 0 ) ) {
            $spf_server =
              Mail::SPF::Server->new( 'hostname' => get_my_hostname($ctx) );
            $priv->{'spf_obj'} = $spf_server;
        }

        if ( $CONFIG->{'check_iprev'} && ( $priv->{'is_local_ip_address'} == 0 ) && ( $priv->{'is_authenticated'} == 0 ) ) {
            iprev_check($ctx);
        }
    };
    if ( my $error = $@ ) {
        log_error( $ctx, 'Connect callback error ' . $error );
    }

    return SMFIS_CONTINUE;
}

sub helo_callback {
    # On HELO
    my ( $ctx, $helo_host ) = @_;
    my $priv = $ctx->getpriv();
    $helo_host = q{} if not $helo_host;
    eval {
        $priv->{'helo_name'} = $helo_host;
        dbgout( $ctx, 'HeloFrom', $helo_host, LOG_DEBUG );
        if ( $CONFIG->{'check_ptr'} && ( $priv->{'is_local_ip_address'} == 0 ) && ( $priv->{'is_authenticated'} == 0 ) ) {
            helo_check($ctx);
        }
    };
    if ( my $error = $@ ) {
        log_error( $ctx, 'HELO callback error ' . $error );
    }

    return SMFIS_CONTINUE;
}

sub envfrom_callback {
    # On MAILFROM
    #...
    my ( $ctx, $env_from ) = @_;
    my $priv = $ctx->getpriv();
    $env_from = q{} if not $env_from;

    eval {
        my $auth_name = get_auth_name( $ctx );
        if ( $auth_name ) {
            dbgout( $ctx, 'AuthenticatedAs', $auth_name, LOG_INFO );
            # Clear the current auth headers ( iprev and helo are already added )
            #$priv->{'pre_headers'} = [];
            #$priv->{'add_headers'} = [];
            $priv->{'auth_headers'} = [];
            add_auth_header( $ctx, 'auth=pass' );
        }
        $priv->{'mail_from'} = $env_from || q{};
        dbgout( $ctx, 'EnvelopeFrom', $env_from, LOG_DEBUG );
        if ( $CONFIG->{'check_dmarc'} && ( $priv->{'is_local_ip_address'} == 0 ) && ( $priv->{'is_authenticated'} == 0 ) ) {
            my $dmarc       = $priv->{'dmarc_obj'};
            my $domain_from = get_domain_from($env_from);
            eval { $dmarc->envelope_from($domain_from) };
            if ( my $error = $@ ) {
                log_error( $ctx, 'DMARC Mail From Error ' . $error );
            }
        }
        if ( $CONFIG->{'check_spf'} && ( $priv->{'is_local_ip_address'} == 0 ) && ( $priv->{'is_authenticated'} == 0 ) ) {
            spf_check($ctx);
        }
    };
    if ( my $error = $@ ) {
        log_error( $ctx, 'Env From callback error ' . $error );
    }

    return SMFIS_CONTINUE;
}

sub envrcpt_callback {
    # On RCPTTO
    #...
    my ( $ctx, $env_to ) = @_;
    my $priv = $ctx->getpriv();
    $env_to = q{} if not $env_to;
    eval {
        my $envelope_to = get_domain_from($env_to);
        dbgout( $ctx, 'EnvelopeTo', $env_to, LOG_DEBUG );
        if ( $CONFIG->{'check_dmarc'} && ( $priv->{'is_local_ip_address'} == 0 ) && ( $priv->{'is_authenticated'} == 0 ) ) {
            my $dmarc = $priv->{'dmarc_obj'};
            eval { $dmarc->envelope_to($envelope_to) };
            if ( my $error = $@ ) {
                log_error( $ctx, 'DMARC Rcpt To Error ' . $error );
            }
        }
    };
    if ( my $error = $@ ) {
        log_error( $ctx, 'Rcpt To callback error ' . $error );
    }

    return SMFIS_CONTINUE;
}

sub header_callback {
    # On Each Header
    my ( $ctx, $header, $value ) = @_;
    my $priv = $ctx->getpriv();
    $value = q{} if not $value;
    eval {
        if ( $header eq 'From' ) {
            $priv->{'from_header'} = $value;
            if ( $CONFIG->{'check_dmarc'} && ( $priv->{'is_local_ip_address'} == 0 ) && ( $priv->{'is_authenticated'} == 0 ) ) {
                my $dmarc = $priv->{'dmarc_obj'};
                eval { $dmarc->header_from_raw( $header . ': ' . $value ) };
                if ( my $error = $@ ) {
                    log_error( $ctx, 'DMARC Header From Error ' . $error );
                }
            }
        }

        if ( $CONFIG->{'check_dkim'} ) {
            my $dkim = $priv->{'dkim_obj'};

            my $EOL    = "\015\012";
            my $dkim_chunk = $header . ': ' . $value . $EOL;
            $dkim_chunk =~ s/\015?\012/$EOL/g;
            $dkim->PRINT($dkim_chunk);

            # Add Google signatures to the mix.
            # Is this wise?
            if ( $header eq 'X-Google-DKIM-Signature' ) {
                my $x_dkim_chunk = 'DKIM-Signature: ' . $value . $EOL;
                $x_dkim_chunk =~ s/\015?\012/$EOL/g;
                $dkim->PRINT($x_dkim_chunk);
            }
        }

        # Check for and remove rogue auth results headers
        if ( $header eq 'Authentication-Results' ) {
            if ( !exists $priv->{'auth_result_header_index'} ) {
                $priv->{'auth_result_header_index'} = 0;
            }
            $priv->{'auth_result_header_index'} =
              $priv->{'auth_result_header_index'} + 1;
            my ($domain_part) = $value =~ /(.*);/;
            $domain_part =~ s/ +//g;
            if ( is_hostname_mine( $ctx, $domain_part ) ) {
                remove_auth_header( $ctx, $priv->{'auth_result_header_index'} );
                my $forged_header = '(The following Authentication Results header was removed by ' . get_my_hostname($ctx) . "\n"
                                  . '    as the supplied domain conflicted with its own)' . "\n"
                                  . '    ' . $value;
                append_header( $ctx, 'X-Invalid-Authentication-Results', $forged_header );
            }
        }

        dbgout( $ctx, 'Header', $header . ': ' . $value, LOG_DEBUG );
    };
    if ( my $error = $@ ) {
        log_error( $ctx, 'Header callback error ' . $error );
    }

    return SMFIS_CONTINUE;
}

sub eoh_callback {
    # On End of headers
    my ($ctx) = @_;
    my $priv = $ctx->getpriv();

    eval {
        if ( $CONFIG->{'check_dkim'} ) {
            my $dkim = $priv->{'dkim_obj'};
            $dkim->PRINT( "\015\012" );
        }
        if ( $CONFIG->{'check_senderid'} && ( $priv->{'is_local_ip_address'} == 0 ) && ( $priv->{'is_authenticated'} == 0 ) ) {
            senderid_check($ctx);
        }
    };
    if ( my $error = $@ ) {
        log_error( $ctx, 'EOH callback error ' . $error );
    }
    return SMFIS_CONTINUE;
}

sub body_callback {
    # On each body chunk
    my ( $ctx, $body_chunk, $len ) = @_;
    my $priv = $ctx->getpriv();

    eval {
        if ( $CONFIG->{'check_dkim'} ) {
            my $dkim       = $priv->{'dkim_obj'};
            my $dkim_chunk = $body_chunk;
            my $EOL    = "\015\012";
            $dkim_chunk =~ s/\015?\012/$EOL/g;
            $dkim->PRINT($dkim_chunk);
        }
    };
    if ( my $error = $@ ) {
        log_error( $ctx, 'Body callback error ' . $error );
    }

    return SMFIS_CONTINUE;
}

sub eom_callback {
    # On End of Message
    my ($ctx) = @_;
    my $priv = $ctx->getpriv();

    eval {
        my $queue_id = get_symval( $ctx, 'i' );
        $priv->{'queue_id'} = $queue_id || q{--};
        dkim_dmarc_check($ctx);
        add_headers($ctx);
    };
    if ( my $error = $@ ) {
        log_error( $ctx, 'EOM callback error ' . $error );
    }
    return SMFIS_ACCEPT;
}

sub abort_callback {
    # On any out of our control abort
    my ($ctx) = @_;
    dbgout( $ctx, 'ABORT', 'Abort called', LOG_DEBUG );
    return SMFIS_CONTINUE;
}

sub close_callback {
    # On end of connection
    my ($ctx) = @_;
    dbgout( $ctx, 'CLOSE', 'Close called', LOG_DEBUG );
    dbgoutwrite($ctx);
    $ctx->setpriv(undef);
    return SMFIS_CONTINUE;
}

sub log_error {
    my ( $ctx, $error ) = @_;
    dbgout( $ctx, 'ERROR', $error, LOG_ERR );
    warn $error;
}

sub add_headers {
    my ($ctx) = @_;
    my $priv = $ctx->getpriv();

    if ( exists( $priv->{'remove_auth_headers'} ) ) {
        foreach my $header ( reverse @{ $priv->{'remove_auth_headers'} } ) {
            dbgout( $ctx, 'RemoveAuthHeader', $header, LOG_DEBUG );
            $ctx->chgheader( 'Authentication-Results', $header, q{} );
        }
    }

    my $header = get_my_hostname($ctx);
    if ( exists( $priv->{'auth_headers'} ) ) {
        $header .= ";\n    ";
        $header .= join( ";\n    ", sort @{ $priv->{'auth_headers'} } );
    }
    else {
        $header .= '; none';
    }

    prepend_header( $ctx, 'Authentication-Results', $header );

    if ( exists( $priv->{'pre_headers'} ) ) {
        foreach my $header ( @{ $priv->{'pre_headers'} } ) {
            dbgout( $ctx, 'PreHeader',
                $header->{'field'} . ': ' . $header->{'value'}, LOG_INFO );
            ## No support for this in Sendmail::PMilter
            ## so we shall write the packet manually.
            $ctx->write_packet( 'i',
                    "\0\0\0\0"
                  . $header->{'field'} . "\0"
                  . $header->{'value'}
                  . "\0" );
        }
    }

    if ( exists( $priv->{'add_headers'} ) ) {
        foreach my $header ( @{ $priv->{'add_headers'} } ) {
            dbgout( $ctx, 'AddHeader',
                $header->{'field'} . ': ' . $header->{'value'}, LOG_INFO );
            $ctx->addheader( $header->{'field'}, $header->{'value'} );
        }
    }
}

sub prepend_header {
    my ( $ctx, $field, $value ) = @_;
    my $priv = $ctx->getpriv();
    if ( !exists( $priv->{'pre_headers'} ) ) {
        $priv->{'pre_headers'} = [];
    }
    push @{ $priv->{'pre_headers'} },
      {
        'field' => $field,
        'value' => $value,
      };
}

sub remove_auth_header {
    my ( $ctx, $value ) = @_;
    my $priv = $ctx->getpriv();
    if ( !exists( $priv->{'remove_auth_headers'} ) ) {
        $priv->{'remove_auth_headers'} = [];
    }
    push @{ $priv->{'remove_auth_headers'} }, $value;
}

sub add_auth_header {
    my ( $ctx, $value ) = @_;
    my $priv = $ctx->getpriv();
    if ( !exists( $priv->{'auth_headers'} ) ) {
        $priv->{'auth_headers'} = [];
    }
    push @{ $priv->{'auth_headers'} }, $value;
}

sub append_header {
    my ( $ctx, $field, $value ) = @_;
    my $priv = $ctx->getpriv();
    if ( !exists( $priv->{'add_headers'} ) ) {
        $priv->{'add_headers'} = [];
    }
    push @{ $priv->{'add_headers'} },
      {
        'field' => $field,
        'value' => $value,
      };
}

sub helo_check {
    my ($ctx) = @_;
    my $priv = $ctx->getpriv();

    my $domain =
      exists( $priv->{'verified_ptr'} ) ? $priv->{'verified_ptr'} : q{};
    my $helo_name = $priv->{'helo_name'};

    if ( $domain eq $helo_name ) {
        add_auth_header( $ctx,
                format_header_entry( 'x-ptr', 'pass' ) . q{ }
              . format_header_entry( 'x-ptr-helo',   $helo_name ) . q{ }
              . format_header_entry( 'x-ptr-lookup', $domain ) );
    }
    else {
        add_auth_header( $ctx,
                format_header_entry( 'x-ptr', 'fail' ) . q{ }
              . format_header_entry( 'x-ptr-helo',   $helo_name ) . q{ }
              . format_header_entry( 'x-ptr-lookup', $domain ) );
    }

}

sub dkim_dmarc_check {
    my ($ctx) = @_;
    my $priv = $ctx->getpriv();

    if ( $CONFIG->{'check_dkim'} ) {
        my $dkim  = $priv->{'dkim_obj'};
        my $dmarc = $priv->{'dmarc_obj'};

        $dkim->CLOSE();

        my $dkim_result        = $dkim->result;
        my $dkim_result_detail = $dkim->result_detail;

        add_auth_header( $ctx,
            format_header_entry( 'dkim', $dkim_result )
              . ' (overall validation result)' );

        dbgout( $ctx, 'DKIMResult', $dkim_result_detail, LOG_INFO );

        $priv->{'dkim_result_code'} = $dkim_result;

        # there might be multiple signatures, what is the result per signature?
        foreach my $signature ( $dkim->signatures ) {

            my $key = $signature->get_public_key();
            dbgout( $ctx, 'DKIMSignatureIdentity', $signature->identity, LOG_DEBUG );
            dbgout( $ctx, 'DKIMSignatureResult',   $signature->result_detail, LOG_DEBUG );

            my $header = join(
                q{ },
                format_header_entry( 'dkim', $dkim_result ),
                '('
                  . format_header_comment(
                    $key->size() . '-bit ' . $key->type() . ' key'
                  )
                  . ')',
                format_header_entry( 'header.d', $signature->domain() ),
                format_header_entry( 'header.i', $signature->identity() ),
            );

            add_auth_header( $ctx, $header );

        }

        # the alleged author of the email may specify how to handle email
        if ( $CONFIG->{'check_dkim-adsp'} && ( $priv->{'is_local_ip_address'} == 0 ) && ( $priv->{'is_authenticated'} == 0 ) ) {
            foreach my $policy ( $dkim->policies ) {
                my $apply    = $policy->apply($dkim);
                my $string   = $policy->as_string();
                my $location = $policy->location() || q{};
                my $name     = $policy->name();
                my $default  = $policy->is_implied_default_policy();

                dbgout( $ctx, 'DKIMPolicy',         $apply, LOG_DEBUG );
                dbgout( $ctx, 'DKIMPolicyString',   $string, LOG_DEBUG );
                dbgout( $ctx, 'DKIMPolicyLocation', $location, LOG_DEBUG  );
                dbgout( $ctx, 'DKIMPolicyName',     $name, LOG_DEBUG  );
                dbgout( $ctx, 'DKIMPolicyDefault',  $default ? 'yes' : 'no', LOG_DEBUG );

                my $result =
                    $apply eq 'accept'  ? 'pass'
                  : $apply eq 'reject'  ? 'discard'
                  : $apply eq 'neutral' ? 'unknown'
                  :                       'unknown';

                my $comment = '('
                  . format_header_comment( ( $default ? 'default ' : q{} )
                    . "$name policy"
                    . ( $location ? " from $location" : q{} )
#                    . ( $string   ? "; $string"       : q{} )
                  )
                  . ')';

                my $header = join( q{ },
                    format_header_entry( 'dkim-adsp', $result ), $comment, );
                add_auth_header( $ctx, $header );
            }
        }

        if ( $CONFIG->{'check_dmarc'} && ( $priv->{'is_local_ip_address'} == 0 ) && ( $priv->{'is_authenticated'} == 0 ) ) {

            $dmarc->dkim($dkim);
            my $dmarc_result = $dmarc->validate();
            my $dmarc_code   = $dmarc_result->result;
            dbgout( $ctx, 'DMARCCode', $dmarc_code, LOG_INFO );
            my $dmarc_policy;
            if ( $dmarc_code ne 'pass' ) {
                $dmarc_policy = eval { $dmarc_result->evalated->disposition() };
                dbgout( $ctx, 'DMARCPolicy', $dmarc_policy, LOG_DEBUG );
            }
            my $dmarc_header = format_header_entry( 'dmarc', $dmarc_code );
            if ($dmarc_policy) {
                $dmarc_header .= ' ('
                  . format_header_comment(
                    format_header_entry( 'p', $dmarc_policy ) )
                  . ')';
            }
            $dmarc_header .= ' '
              . format_header_entry( 'header.from',
                get_domain_from( $priv->{'from_header'} ) );
            add_auth_header( $ctx, $dmarc_header );

        }
    }
}

sub iprev_check {
    my ($ctx) = @_;

    my $priv = $ctx->getpriv();

    my $ip_address = $priv->{'ip_address'};

    my $resolver = Net::DNS::Resolver->new;

    my $domain;
    my $result;

    # We do not consider multiple PTR records,
    # as this is not a recomended setup
    my $packet = $resolver->query( $ip_address, 'PTR' );
    if ($packet) {
        foreach my $rr ( $packet->answer ) {
            next unless $rr->type eq "PTR";
            $domain = $rr->rdatastr;
        }
    }
    else {
        log_error( $ctx,
                'DNS PTR query failed for '
              . $ip_address
              . ' with '
              . $resolver->errorstring );
    }

    my $a_error;
    if ($domain) {
        my $packet = $resolver->query( $domain, 'A' );
        if ($packet) {
          APACKET:
            foreach my $rr ( $packet->answer ) {
                next unless $rr->type eq "A";
                my $address = $rr->rdatastr;
                if ( $address eq $ip_address ) {
                    $result = 'pass';
                    last APACKET;
                }
            }
        }
        else {
            # Don't log this right now, might be an AAAA only host.
            $a_error = 
                  'DNS A query failed for '
                  . $domain
                  . ' with '
                  . $resolver->errorstring;
        }
    }

    if ( $domain && !$result ) {
        my $packet = $resolver->query( $domain, 'AAAA' );
        if ($packet) {
          APACKET:
            foreach my $rr ( $packet->answer ) {
                next unless $rr->type eq "AAAA";
                my $address = $rr->rdatastr;
                if ( $address eq $ip_address ) {
                    $result = 'pass';
                    last APACKET;
                }
            }
        }
        else {
            # Log A errors now, as they become relevant if AAAA also fails.
            log_error( $ctx, $a_error ) if $a_error;
            log_error( $ctx,
                    'DNS AAAA query failed for '
                  . $domain
                  . ' with '
                  . $resolver->errorstring );
        }
    }

    if ( !$result ) {
        $result = 'fail';
    }

    if ( !$domain ) {
        $result = 'fail';
        $domain = 'NOT FOUND';
    }

    $domain =~ s/\.$//;

    if ( $result eq 'pass' ) {
        $priv->{'verified_ptr'} = $domain;
    }

    my $header =
        format_header_entry( 'iprev', $result ) . ' '
      . format_header_entry( 'policy.iprev', $ip_address ) . ' ' . '('
      . format_header_comment($domain) . ')';
    add_auth_header( $ctx, $header );

}

sub senderid_check {
    my ($ctx) = @_;

    my $priv = $ctx->getpriv();

    my $spf_server = $priv->{'spf_obj'};

    my $scope = 'pra';

    my $identity = get_address_from( $priv->{'from_header'} );

    my $spf_request = Mail::SPF::Request->new(
        'versions'      => [2],
        'scope'         => $scope,
        'identity'      => $identity,
        'ip_address'    => $priv->{'ip_address'},
        'helo_identity' => $priv->{'helo_name'},
    );

    my $spf_result = $spf_server->process($spf_request);

    my $result_code = $spf_result->code();
    $priv->{'spf_result_code'} = $result_code;

    my $auth_header = format_header_entry( 'senderid', $result_code );
    add_auth_header( $ctx, $auth_header );

    dbgout( $ctx, 'SenderIdCode', $result_code, LOG_INFO );

#my $result_local  = $spf_result->local_explanation;
#my $result_auth   = $spf_result->can( 'authority_explanation' ) ? $spf_result->authority_explanation() : '';

    my $result_header = $spf_result->received_spf_header();
    my ( $header, $value ) = $result_header =~ /(.*): (.*)/;

    prepend_header( $ctx, $header, $value );
    dbgout( $ctx, 'SPFHeader', $result_header, LOG_DEBUG );

    return;
}

sub spf_check {
    my ($ctx) = @_;

    my $priv = $ctx->getpriv();

    my $spf_server = $priv->{'spf_obj'};

    my $scope = 'mfrom';

    my $identity = get_address_from( $priv->{'mail_from'} );
    my $domain   = get_domain_from($identity);

    if ( !$identity ) {
        $identity = $priv->{'helo_name'};
        $domain   = $identity;
        $scope    = 'helo';
    }

    my $spf_request = Mail::SPF::Request->new(
        'versions'      => [1],
        'scope'         => $scope,
        'identity'      => $identity,
        'ip_address'    => $priv->{'ip_address'},
        'helo_identity' => $priv->{'helo_name'},
    );

    my $spf_result = $spf_server->process($spf_request);

    my $result_code = $spf_result->code();
    $priv->{'spf_result_code'} = $result_code;

    my $auth_header = join( q{ },
        format_header_entry( 'spf',           $result_code ),
        format_header_entry( 'smtp.mailfrom', get_address_from( $priv->{'mail_from'} ) ),
        format_header_entry( 'smtp.helo',     $priv->{'helo_name'} ),
    );
    add_auth_header( $ctx, $auth_header );

    if ( $CONFIG->{'check_dmarc'} && ( $priv->{'is_local_ip_address'} == 0 ) && ( $priv->{'is_authenticated'} == 0 ) ) {
        my $dmarc = $priv->{'dmarc_obj'};
        $dmarc->spf(
            'domain' => $domain,
            'scope'  => $scope,
            'result' => $result_code,
        );
    }

    dbgout( $ctx, 'SPFCode', $result_code, LOG_INFO );

    my $result_header = $spf_result->received_spf_header();
    my ( $header, $value ) = $result_header =~ /(.*): (.*)/;

    prepend_header( $ctx, $header, $value );
    dbgout( $ctx, 'SPFHeader', $result_header, LOG_DEBUG );

    return;
}

sub dbgout {
    my ( $ctx, $key, $value, $priority ) = @_;

    my $priv = $ctx->getpriv();
    if ( !exists( $priv->{'dbgout'} ) ) {
        $priv->{'dbgout'} = [];
    }
    push @{ $priv->{'dbgout'} },
      {
        'priority'   => $priority || LOG_INFO,
        'key'        => $key || q{},
        'value'      => $value || q{},
      };
}

sub dbgoutwrite {
    my ($ctx) = @_;
    my $priv  = $ctx->getpriv();
    return if not $priv;
    eval {
        openlog('authentication_milter', 'pid', LOG_MAIL);
        setlogmask(   LOG_MASK(LOG_ERR)
#                    | LOG_MASK(LOG_DEBUG)
                    | LOG_MASK(LOG_INFO)
        );
        my $queue_id = $priv->{'queue_id'} || q{--};
        if ( exists( $priv->{'dbgout'} ) ) {
            foreach my $entry ( @{ $priv->{'dbgout'} } ) {
                my $key      = $entry->{'key'};
                my $value    = $entry->{'value'};
                my $priority = $entry->{'priority'};
                my $line = "$queue_id: $key: $value";
                syslog($priority, $line);
            }
        }
        closelog();
    };
}

1;
