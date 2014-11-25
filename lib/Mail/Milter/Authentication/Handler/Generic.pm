package Mail::Milter::Authentication::Handler::Generic;

use strict;
use warnings;

our $VERSION = 0.3;

use Mail::Milter::Authentication::Config qw{ get_config };

use Email::Address;
use Sys::Syslog qw{:standard :macros};

sub new {
    my ( $class, $ctx ) = @_;
    my $self = {
        'ctx'    => $ctx,
        'config' => get_config(),
    };
    bless $self, $class;
    return $self;
}

sub config {
    my ( $self ) = @_;
    return $self->{'config'};
}

sub format_ctext {
    # Return ctext (but with spaces intact)
    my ($self,$text) = @_;
    $text =~ s/\t/ /g;
    $text =~ s/\n/ /g;
    $text =~ s/\r/ /g;
    $text =~ s/\(/ /g;
    $text =~ s/\)/ /g;
    $text =~ s/\\/ /g;
    return $text;
}

sub format_ctext_no_space {
    my ($self,$text) = @_;
    $text = $self->format_ctext($text);
    $text =~ s/ //g;
    return $text;
}

sub format_header_comment {
    my ($self,$comment) = @_;
    $comment = $self->format_ctext($comment);
    return $comment;
}

sub format_header_entry {
    my ( $self,$key, $value ) = @_;
    $key   = $self->format_ctext_no_space($key);
    $value = $self->format_ctext_no_space($value);
    my $string = $key . '=' . $value;
    return $string;
}

sub get_domain_from {
    my ($self,$address) = @_;
    $address = $self->get_address_from($address);
    my $domain = 'localhost.localdomain';
    $address =~ s/<//g;
    $address =~ s/>//g;
    if ( $address =~ /\@/ ) {
        ($domain) = $address =~ /.*\@(.*)/;
    }
    return lc $domain;
}

sub get_address_from {
    my ($self,$address) = @_;
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


sub get_my_hostname {
    my ($self) = @_;
    return $self->get_symval( 'j' );
}

sub is_hostname_mine {
    my ( $self, $check_hostname ) = @_;
    my $ctx = $self->{'ctx'};
    my $CONFIG = $self->config();

    my $hostname = $self->get_my_hostname();
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

sub get_symval {
    my ( $self, $key ) = @_;
    my $ctx = $self->{'ctx'};
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
    return;
}

sub dbgout {
    my ( $self, $key, $value, $priority ) = @_;
    my $ctx = $self->{'ctx'};
    warn "$key: $value\n";
    my $priv = $ctx->getpriv();
    if ( !exists( $priv->{'core.dbgout'} ) ) {
        $priv->{'core.dbgout'} = [];
    }
    push @{ $priv->{'core.dbgout'} },
      {
        'priority'   => $priority || LOG_INFO,
        'key'        => $key || q{},
        'value'      => $value || q{},
      };
}

sub log_error {
    my ( $self, $error ) = @_;
    $self->dbgout( 'ERROR', $error, LOG_ERR );
}

sub dbgoutwrite {
    my ($self) = @_;
    my $ctx = $self->{'ctx'};
    my $priv  = $ctx->getpriv();
    return if not $priv;
    eval {
        openlog('authentication_milter', 'pid', LOG_MAIL);
        setlogmask(   LOG_MASK(LOG_ERR)
                    | LOG_MASK(LOG_INFO)
#                    | LOG_MASK(LOG_DEBUG)
        );
        my $queue_id = $self->get_symval( $ctx, 'i' ) || q{--};
        if ( exists( $priv->{'core.dbgout'} ) ) {
            foreach my $entry ( @{ $priv->{'core.dbgout'} } ) {
                my $key      = $entry->{'key'};
                my $value    = $entry->{'value'};
                my $priority = $entry->{'priority'};
                my $line = "$queue_id: $key: $value";
                syslog($priority, $line);
            }
        }
        closelog();
        $priv->{'core.dbgout'} = undef;
    };
}

sub add_headers {
    my ($self) = @_;
    my $ctx = $self->{'ctx'};
    my $priv = $ctx->getpriv();

    my $header = $self->get_my_hostname();
    my @auth_headers;
    if ( exists( $priv->{'core.c_auth_headers'} ) ) {
        @auth_headers = @{$priv->{'core.c_auth_headers'}};
    }
    if ( exists( $priv->{'core.auth_headers'} ) ) {
        @auth_headers = ( @auth_headers, @{$priv->{'core.auth_headers'}} );
    }
    if ( @auth_headers ) {
        $header .= ";\n    ";
        $header .= join( ";\n    ", sort @auth_headers );
    }
    else {
        $header .= '; none';
    }

    $self->prepend_header( 'Authentication-Results', $header );

    if ( exists( $priv->{'core.pre_headers'} ) ) {
        foreach my $header ( @{ $priv->{'core.pre_headers'} } ) {
            $self->dbgout('PreHeader',
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

    if ( exists( $priv->{'core.add_headers'} ) ) {
        foreach my $header ( @{ $priv->{'core.add_headers'} } ) {
            $self->dbgout( 'AddHeader',
                $header->{'field'} . ': ' . $header->{'value'}, LOG_INFO );
            $ctx->addheader( $header->{'field'}, $header->{'value'} );
        }
    }
}

sub prepend_header {
    my ( $self, $field, $value ) = @_;
    my $ctx = $self->{'ctx'};
    my $priv = $ctx->getpriv();
    if ( !exists( $priv->{'core.pre_headers'} ) ) {
        $priv->{'core.pre_headers'} = [];
    }
    push @{ $priv->{'core.pre_headers'} },
      {
        'field' => $field,
        'value' => $value,
      };
}


sub add_auth_header {
    my ( $self, $value ) = @_;
    my $ctx = $self->{'ctx'};
    my $priv = $ctx->getpriv();
    if ( !exists( $priv->{'core.auth_headers'} ) ) {
        $priv->{'core.auth_headers'} = [];
    }
    push @{ $priv->{'core.auth_headers'} }, $value;
}

sub add_c_auth_header {
    # Connection wide auth headers
    my ( $self, $value ) = @_;
    my $ctx = $self->{'ctx'};
    my $priv = $ctx->getpriv();
    if ( !exists( $priv->{'core.c_auth_headers'} ) ) {
        $priv->{'core.c_auth_headers'} = [];
    }
    push @{ $priv->{'core.c_auth_headers'} }, $value;
}

sub append_header {
    my ( $self, $field, $value ) = @_;
    my $ctx = $self->{'ctx'};
    my $priv = $ctx->getpriv();
    if ( !exists( $priv->{'core.add_headers'} ) ) {
        $priv->{'core.add_headers'} = [];
    }
    push @{ $priv->{'core.add_headers'} },
      {
        'field' => $field,
        'value' => $value,
      };
}

1;
