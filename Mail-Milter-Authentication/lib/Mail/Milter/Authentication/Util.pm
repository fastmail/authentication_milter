package Mail::Milter::Authentication::Util;

$VERSION = 0.1;

use strict;
use warnings;

use Sys::Syslog qw{:standard :macros};
use Email::Address;

use Exporter qw{ import };
our @EXPORT = qw{
    get_symval
    get_domain_from
    get_address_from
    format_ctext
    format_ctext_no_space
    format_header_comment
    format_header_entry
    log_error
    add_headers
    prepend_header
    remove_auth_header
    add_auth_header
    add_c_auth_header
    append_header
    dbgout
    dbgoutwrite
    get_my_hostname
    is_hostname_mine
};

use Mail::Milter::Authentication::Config qw{ get_config };
my $CONFIG = get_config();

sub get_symval {
    my ( $ctx, $key ) = @_;
    my $val = $ctx->getsymval( $key );
    return $val if defined( $val );
    # We didn't find it?
    # PMilter::Context fails to get the queue id from postfix as it is
    # not searching symbols for the correct code. Rewrite this here.
    # Intend to patch PMilter to fix this.
    my $symbols = $ctx->{'symbols'}; ## Internals, here be dragons!
    foreach my $code ( keys %{$symbols} ) {
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

sub log_error {
    my ( $ctx, $error ) = @_;
    dbgout( $ctx, 'ERROR', $error, LOG_ERR );
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
    my @auth_headers;
    if ( exists( $priv->{'c_auth_headers'} ) ) {
        @auth_headers = @{$priv->{'c_auth_headers'}};
    }
    if ( exists( $priv->{'auth_headers'} ) ) {
        @auth_headers = ( @auth_headers, @{$priv->{'auth_headers'}} );
    }
    if ( @auth_headers ) {
        $header .= ";\n    ";
        $header .= join( ";\n    ", sort @auth_headers );
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
            #  Intend to patch PMilter to fix this
            my $index = 1;
            $ctx->write_packet( 'i',
                    pack( 'N', $index )
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

sub add_c_auth_header {
    # Connection wide auth headers
    my ( $ctx, $value ) = @_;
    my $priv = $ctx->getpriv();
    if ( !exists( $priv->{'c_auth_headers'} ) ) {
        $priv->{'c_auth_headers'} = [];
    }
    push @{ $priv->{'c_auth_headers'} }, $value;
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

sub dbgout {
    my ( $ctx, $key, $value, $priority ) = @_;
    warn "$key: $value\n";
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
                    | LOG_MASK(LOG_INFO)
#                    | LOG_MASK(LOG_DEBUG)
        );
        my $queue_id = get_symval( $ctx, 'i' ) || q{--};
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
        $priv->{'dbgout'} = undef;
    };
}

sub get_my_hostname {
    my ($ctx) = @_;
    my $hostname = get_symval( $ctx, 'j' );
    return $hostname;
}

sub is_hostname_mine {
    my ( $ctx, $check_hostname ) = @_;

    my $hostname = get_my_hostname($ctx);
    my ($check_for) = $hostname =~ /^[^\.]+\.(.*)/;

    if ( exists ( $CONFIG->{'hosts_to_remove'} ) ) {
        foreach my $remove_hostname ( @{ $CONFIG->{'hosts_to_remove'} } ) {
            if (
                substr( lc $check_hostname, ( 0 - length($remove_hostname) ) ) eq
                lc $remove_hostname )
            {
                return 1;
            }
        }
    }

    if (
        substr( lc $check_hostname, ( 0 - length($check_for) ) ) eq
        lc $check_for )
    {
        return 1;
    }
}

1;
