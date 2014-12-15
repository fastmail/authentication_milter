package Mail::Milter::Authentication::Handler;

use strict;
use warnings;

our $VERSION = 0.5;

use Email::Address;
use English;
use MIME::Base64;
use Net::DNS::Resolver;
use Socket;
use Sys::Syslog qw{:standard :macros};
use Sys::Hostname;

use Mail::Milter::Authentication::DNSCache;
use Mail::Milter::Authentication::Constants qw { :all };

sub new {
    my ( $class, $protocol ) = @_;
    my $self = {
        'protocol'   => $protocol,
    };
    bless $self, $class;
    return $self;
}

# Top Level Callbacks

sub top_connect_callback {

    # On Connect
    my ( $self, $hostname, $sockaddr_in ) = @_;
    $self->status('connect');
    $self->dbgout( 'CALLBACK', 'Connect', LOG_DEBUG );
    $self->set_return( $self->smfis_continue() );
    my $CONFIG = $self->config();
    eval {
        local $SIG{'ALRM'};
        if ( $CONFIG->{'connect_timeout'} ) {
            $SIG{'ALRM'} = sub{ die "Timeout\n" };
            alarm( $CONFIG->{'connect_timeout'} );
        }

        # Process the connecting IP Address
        my ( $port, $iaddr, $ip_address );
        if ( length ( $sockaddr_in ) == 0 ) {
            $self->log_error('Unknown IP address format NULL');
            $ip_address = q{};
            # Could potentially fail here, connection is likely bad anyway.
        }
        else {
            my $family = sockaddr_family($sockaddr_in);
            if ( $family == AF_INET ) {
                ( $port, $iaddr ) = sockaddr_in($sockaddr_in);
                $ip_address = inet_ntoa($iaddr);
            }
            elsif ( $family == AF_INET6 ) {
                ( $port, $iaddr ) = sockaddr_in6($sockaddr_in);
                $ip_address = Socket::inet_ntop( AF_INET6, $iaddr );
            }
            else {
                ## TODO something better here - this should never happen
                $self->log_error('Unknown IP address format - ' . encode_base64($sockaddr_in,q{}) );
                $ip_address = q{};
            }
        }
        $self->{'ip_address'} = $ip_address;
        $self->dbgout( 'ConnectFrom', $ip_address, LOG_DEBUG );

        my $callbacks = $self->get_callbacks( 'connect' );
        foreach my $handler ( @$callbacks ) {
            $self->get_handler($handler)->connect_callback( $hostname, $sockaddr_in );
        }
        alarm(0);
    };
    if ( my $error = $@ ) {
        $self->log_error( 'Connect callback error ' . $error );
        $self->exit_on_close();
        $self->tempfail_on_error();
    }
    $self->status('postconnect');
    return $self->get_return();
}

sub top_helo_callback {

    # On HELO
    my ( $self, $helo_host ) = @_;
    $self->status('helo');
    $self->dbgout( 'CALLBACK', 'Helo', LOG_DEBUG );
    $self->set_return( $self->smfis_continue() );
    $helo_host = q{} if not $helo_host;
    my $CONFIG = $self->config();
    eval {
        local $SIG{'ALRM'};
        if ( $CONFIG->{'command_timeout'} ) {
            $SIG{'ALRM'} = sub{ die "Timeout\n" };
            alarm( $CONFIG->{'command_timeout'} );
        }

        # Take only the first HELO from a connection
        if ( !( $self->{'helo_name'} ) ) {
            $self->{'helo_name'} = $helo_host;
            my $callbacks = $self->get_callbacks( 'helo' );
            foreach my $handler ( @$callbacks ) {
                $self->get_handler($handler)->helo_callback($helo_host);
            }
        }

        alarm(0);
    };
    if ( my $error = $@ ) {
        $self->log_error( 'HELO callback error ' . $error );
        $self->exit_on_close();
        $self->tempfail_on_error();
    }
    $self->status('posthelo');
    return $self->get_return();
}

sub top_envfrom_callback {

    # On MAILFROM
    #...
    my ( $self, $env_from ) = @_;
    $self->status('envfrom');
    $self->dbgout( 'CALLBACK', 'EnvFrom', LOG_DEBUG );
    $self->set_return( $self->smfis_continue() );
    $env_from = q{} if not $env_from;
    my $CONFIG = $self->config();
    eval {
        local $SIG{'ALRM'};
        if ( $CONFIG->{'command_timeout'} ) {
            $SIG{'ALRM'} = sub{ die "Timeout\n" };
            alarm( $CONFIG->{'command_timeout'} );
        }

        # Reset private data for this MAIL transaction
        delete $self->{'auth_headers'};
        delete $self->{'pre_headers'};
        delete $self->{'add_headers'};

        my $callbacks = $self->get_callbacks( 'envfrom' );
        foreach my $handler ( @$callbacks ) {
            $self->get_handler($handler)->envfrom_callback($env_from);
        }
        alarm(0);
    };
    if ( my $error = $@ ) {
        $self->log_error( 'Env From callback error ' . $error );
        $self->exit_on_close();
        $self->tempfail_on_error();
    }
    $self->status('postenvfrom');
    return $self->get_return();
}

sub top_envrcpt_callback {

    # On RCPTTO
    #...
    my ( $self, $env_to ) = @_;
    $self->status('envrcpt');
    $self->dbgout( 'CALLBACK', 'EnvRcpt', LOG_DEBUG );
    $self->set_return( $self->smfis_continue() );
    $env_to = q{} if not $env_to;
    my $CONFIG = $self->config();
    eval {
        local $SIG{'ALRM'};
        if ( $CONFIG->{'command_timeout'} ) {
            $SIG{'ALRM'} = sub{ die "Timeout\n" };
            alarm( $CONFIG->{'command_timeout'} );
        }
        my $callbacks = $self->get_callbacks( 'envrcpt' );
        foreach my $handler ( @$callbacks ) {
            $self->get_handler($handler)->envrcpt_callback($env_to);
        }
        alarm(0);
    };
    if ( my $error = $@ ) {
        $self->log_error( 'Rcpt To callback error ' . $error );
        $self->exit_on_close();
        $self->tempfail_on_error();
    }
    $self->status('postenvrcpt');
    return $self->get_return();
}

sub top_header_callback {

    # On Each Header
    my ( $self, $header, $value ) = @_;
    $self->status('header');
    $self->dbgout( 'CALLBACK', 'Header', LOG_DEBUG );
    $self->set_return( $self->smfis_continue() );
    $value = q{} if not $value;
    my $CONFIG = $self->config();
    eval {
        local $SIG{'ALRM'};
        if ( $CONFIG->{'content_timeout'} ) {
            $SIG{'ALRM'} = sub{ die "Timeout\n" };
            alarm( $CONFIG->{'content_timeout'} );
        }
        my $callbacks = $self->get_callbacks( 'header' );
        foreach my $handler ( @$callbacks ) {
            $self->get_handler($handler)->header_callback( $header, $value );
        }
        alarm(0);
    };
    if ( my $error = $@ ) {
        $self->log_error( 'Header callback error ' . $error );
        $self->exit_on_close();
        $self->tempfail_on_error();
    }
    $self->status('postheader');
    return $self->get_return();
}

sub top_eoh_callback {

    # On End of headers
    my ($self) = @_;
    $self->status('eoh');
    $self->dbgout( 'CALLBACK', 'EOH', LOG_DEBUG );
    $self->set_return( $self->smfis_continue() );
    my $CONFIG = $self->config();
    eval {
        local $SIG{'ALRM'};
        if ( $CONFIG->{'content_timeout'} ) {
            $SIG{'ALRM'} = sub{ die "Timeout\n" };
            alarm( $CONFIG->{'content_timeout'} );
        }
        my $callbacks = $self->get_callbacks( 'eoh' );
        foreach my $handler ( @$callbacks ) {
            $self->get_handler($handler)->eoh_callback();
        }
        alarm(0);
    };
    if ( my $error = $@ ) {
        $self->log_error( 'EOH callback error ' . $error );
        $self->exit_on_close();
        $self->tempfail_on_error();
    }
    $self->dbgoutwrite();
    $self->status('posteoh');
    return $self->get_return();
}

sub top_body_callback {

    # On each body chunk
    my ( $self, $body_chunk ) = @_;
    $self->status('body');
    $self->dbgout( 'CALLBACK', 'Body', LOG_DEBUG );
    $self->set_return( $self->smfis_continue() );
    my $CONFIG = $self->config();
    eval {
        local $SIG{'ALRM'};
        if ( $CONFIG->{'content_timeout'} ) {
            $SIG{'ALRM'} = sub{ die "Timeout\n" };
            alarm( $CONFIG->{'content_timeout'} );
        }
        my $callbacks = $self->get_callbacks( 'body' );
        foreach my $handler ( @$callbacks ) {
            $self->get_handler($handler)->body_callback( $body_chunk );
        }
        alarm(0);
    };
    if ( my $error = $@ ) {
        $self->log_error( 'Body callback error ' . $error );
        $self->exit_on_close();
        $self->tempfail_on_error();
    }
    $self->dbgoutwrite();
    $self->status('postbody');
    return $self->get_return();
}

sub top_eom_callback {

    # On End of Message
    my ($self) = @_;
    $self->status('eom');
    $self->dbgout( 'CALLBACK', 'EOM', LOG_DEBUG );
    $self->set_return( $self->smfis_continue() );
    my $CONFIG = $self->config();
    eval {
        local $SIG{'ALRM'};
        if ( $CONFIG->{'content_timeout'} ) {
            $SIG{'ALRM'} = sub{ die "Timeout\n" };
            alarm( $CONFIG->{'content_timeout'} );
        }
        my $callbacks = $self->get_callbacks( 'eom' );
        foreach my $handler ( @$callbacks ) {
            $self->get_handler($handler)->eom_callback();
        }
        alarm(0);
    };
    if ( my $error = $@ ) {
        $self->log_error( 'EOM callback error ' . $error );
        $self->exit_on_close();
        $self->tempfail_on_error();
    }
    $self->add_headers();
    $self->dbgoutwrite();
    $self->status('posteom');
    return $self->get_return();
}

sub top_abort_callback {

    # On any out of our control abort
    my ($self) = @_;
    $self->status('abort');
    $self->dbgout( 'CALLBACK', 'Abort', LOG_DEBUG );
    $self->set_return( $self->smfis_continue() );
    my $CONFIG = $self->config();
    eval {
        local $SIG{'ALRM'};
        if ( $CONFIG->{'command_timeout'} ) {
            $SIG{'ALRM'} = sub{ die "Timeout\n" };
            alarm( $CONFIG->{'command_timeout'} );
        }
        my $callbacks = $self->get_callbacks( 'abort' );
        foreach my $handler ( @$callbacks ) {
            $self->get_handler($handler)->abort_callback();
        }
        alarm(0);
    };
    if ( my $error = $@ ) {
        $self->log_error( 'Abort callback error ' . $error );
        $self->exit_on_close();
        $self->tempfail_on_error();
    }
    $self->dbgoutwrite();
    $self->status('postabort');
    return $self->get_return();
}

sub top_close_callback {

    # On end of connection
    my ($self) = @_;
    $self->status('close');
    $self->dbgout( 'CALLBACK', 'Close', LOG_DEBUG );
    $self->set_return( $self->smfis_continue() );
    my $CONFIG = $self->config();
    eval {
        local $SIG{'ALRM'};
        if ( $CONFIG->{'content_timeout'} ) {
            $SIG{'ALRM'} = sub{ die "Timeout\n" };
            alarm( $CONFIG->{'content_timeout'} );
        }
        my $callbacks = $self->get_callbacks( 'close' );
        foreach my $handler ( @$callbacks ) {
            $self->get_handler($handler)->close_callback();
        }
        alarm(0);
    };
    if ( my $error = $@ ) {
        $self->log_error( 'Close callback error ' . $error );
        $self->exit_on_close();
        $self->tempfail_on_error();
    }
    delete $self->{'helo_name'};
    delete $self->{'c_auth_headers'};
    delete $self->{'auth_headers'};
    delete $self->{'pre_headers'};
    delete $self->{'add_headers'};
    delete $self->{'ip_address'};
    $self->dbgoutwrite();
    $self->status('postclose');
    return $self->get_return();
}



# Other methods

sub status {
    my ($self, $status) = @_;
    my $count = $self->{'protocol'}->{'count'};
    if ( $status ) {
        $PROGRAM_NAME = '[authentication_milter:processing:' . $status . '(' . $count . ')]';
    }
    else {
        $PROGRAM_NAME = '[authentication_milter:processing(' . $count . ')]';
    }
}

sub config {
    my ($self) = @_;
    return $self->{'protocol'}->{'config'};
}

sub handler_config {
    my ($self) = @_;
    my $type = $self->handler_type();
    return if ! $type;
    if ( $self->is_handler_loaded( $type ) ) {
        my $CONFIG = $self->config();
        return $CONFIG->{'handlers'}->{$type};
    }
    return;
}

sub handler_type {
    my ($self) = @_;
    my $type = ref $self;
    if ( $type eq 'Mail::Milter::Authentication::Handler' ) {
        return 'Handler';
    }
    elsif ( $type =~ /^Mail::Milter::Authentication::Handler::(.*)/ ) {
        my $handler_type = $1;
        return $handler_type;
    }
    else {
        return undef;
    }
}

sub set_return {
    my ( $self, $return ) = @_;
    my $top_handler = $self->get_top_handler();
    $top_handler->{'return_code'} = $return;
}

sub get_return {
    my ( $self ) = @_;
    my $top_handler = $self->get_top_handler();
    return $top_handler->{'return_code'};
}

sub get_top_handler {
    my ($self) = @_;
    my $protocol   = $self->{'protocol'};
    my $object = $protocol->{'handler'}->{'_Handler'};
    return $object;
}

sub is_handler_loaded {
    my ( $self, $name ) = @_;
    my $CONFIG = $self->config();
    if ( exists ( $CONFIG->{'handlers'}->{$name} ) ) {
        return 1;
    }
    return 0;
}

sub get_handler {
    my ( $self, $name ) = @_;
    my $protocol = $self->{'protocol'};
    my $object   = $protocol->{'handler'}->{$name};
    return $object;
}


sub get_callbacks {
    my ( $self, $callback ) = @_;
    my $protocol = $self->{'protocol'};
    return $protocol->{'callbacks_list'}->{$callback};
}

sub get_object {
    my ( $self, $name ) = @_;
    my $protocol = $self->{'protocol'};
    my $object   = $protocol->{'object'}->{$name};
    if ( ! $object ) {

        if ( $name eq 'resolver' ) {
            my $CONFIG = $self->config();
            my $timeout = $CONFIG->{'dns_timeout'} || 8;
            my $cache_timeout = $CONFIG->{'dns_cache_timeout'} || 240;
            $object = Net::DNS::Resolver->new(
                'udp_timeout'   => $timeout,
                'tcp_timeout'   => $timeout,
                'cache_timeout' => $cache_timeout,
                'retry'         => 2,
            );
            $object->udppacketsize(1240);
            $object->persistent_udp(1);
            $protocol->{'object'}->{$name} = $object;
        }

    }
    return $object;
}

sub set_object {
    my ( $self, $name, $object ) = @_;
    my $protocol = $self->{'protocol'};
    $protocol->{'object'}->{$name} = $object;
}

sub destroy_object {
    my ( $self, $name ) = @_;
    my $protocol = $self->{'protocol'};
    delete $protocol->{'object'}->{$name};
}

sub destroy_all_objects {
    # Unused!
    my ( $self ) = @_;
    my $protocol = $self->{'protocol'};
    foreach my $name ( keys %{ $protocol->{'object'} } )
    {
        $self->destroy_object( $name );
    }
}

sub exit_on_close {
    my ( $self ) = @_;
    my $top_handler = $self->get_top_handler();
    $top_handler->{'exit_on_close'} = 1;
}

sub clear_symbols {
    my ( $self ) = @_;
    my $top_handler = $self->get_top_handler();

    my $connect_symbols;
    if ( exists ( $top_handler->{'symbols'} ) ) {
        if ( exists ( $top_handler->{'symbols'}->{'C'} ) ) {
            $connect_symbols = $top_handler->{'symbols'}->{'C'};
        }
    }

    delete $top_handler->{'symbols'};

    if ( $connect_symbols ) {
        $top_handler->{'symbols'} = {
            'C' => $connect_symbols,
        };
    }

}

sub set_symbol {
    my ( $self, $code, $key, $value ) = @_;
    my $top_handler = $self->get_top_handler();
    if ( ! exists ( $top_handler->{'symbols'} ) ) {
        $top_handler->{'symbols'} = {};
    }
    if ( ! exists ( $top_handler->{'symbols'}->{$code} ) ) {
        $top_handler->{'symbols'}->{$code} = {};
    }
    $top_handler->{'symbols'}->{$code}->{$key} = $value;;
}

sub get_symbol {
    my ( $self, $searchkey ) = @_;
    my $top_handler = $self->get_top_handler();
    my $symbols = $top_handler->{'symbols'} || {};
    foreach my $code ( keys %{$symbols} ) {
        my $subsymbols = $symbols->{$code};
        foreach my $key ( keys %{$subsymbols} ) {
            if ( $searchkey eq $key ) {
                return $subsymbols->{$key};
            }
        }
    }
    return;
}

sub tempfail_on_error {
    my ( $self ) = @_;
    my $CONFIG = $self->config();
    if ( $self->is_authenticated() ) {
        $self->set_return( $self->smfis_tempfail() ) if $CONFIG->{'tempfail_on_error_authenticated'};
    }
    elsif ( $self->is_local_ip_address() ) {
        $self->set_return( $self->smfis_tempfail() ) if $CONFIG->{'tempfail_on_error_local'};
    }
    elsif ( $self->is_trusted_ip_address() ) {
        $self->set_return( $self->smfis_tempfail() ) if $CONFIG->{'tempfail_on_error_trusted'};
    }
    else {
        $self->set_return( $self->smfis_tempfail() ) if $CONFIG->{'tempfail_on_error'};
    }
}



# Common calls into other Handlers

sub is_local_ip_address {
    my ($self) = @_;
    return 0 if ! $self->is_handler_loaded('LocalIP');
    return $self->get_handler('LocalIP')->{'is_local_ip_address'};
}

sub is_trusted_ip_address {
    my ($self) = @_;
    return 0 if ! $self->is_handler_loaded('TrustedIP');
    return $self->get_handler('TrustedIP')->{'is_trusted_ip_address'};
}

sub is_authenticated {
    my ($self) = @_;
    return 0 if ! $self->is_handler_loaded('Auth');
    return $self->get_handler('Auth')->{'is_authenticated'};
}

sub ip_address {
    my ($self) = @_;
    my $top_handler = $self->get_top_handler();
    return $top_handler->{'ip_address'};
}



# Header formatting and data methods

sub format_ctext {

    # Return ctext (but with spaces intact)
    my ( $self, $text ) = @_;
    $text =~ s/\t/ /g;
    $text =~ s/\n/ /g;
    $text =~ s/\r/ /g;
    $text =~ s/\(/ /g;
    $text =~ s/\)/ /g;
    $text =~ s/\\/ /g;
    return $text;
}

sub format_ctext_no_space {
    my ( $self, $text ) = @_;
    $text = $self->format_ctext($text);
    $text =~ s/ //g;
    return $text;
}

sub format_header_comment {
    my ( $self, $comment ) = @_;
    $comment = $self->format_ctext($comment);
    return $comment;
}

sub format_header_entry {
    my ( $self, $key, $value ) = @_;
    $key   = $self->format_ctext_no_space($key);
    $value = $self->format_ctext_no_space($value);
    my $string = $key . '=' . $value;
    return $string;
}

sub get_domain_from {
    my ( $self, $address ) = @_;
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
    my ( $self, $address ) = @_;
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
    my $hostname = $self->get_symbol('j');
    if ( ! $hostname ) {
        $hostname = $self->get_symbol('{rcpt_host}');
    }
    if ( ! $hostname ) { # Fallback
        $hostname = hostname;
    }
    return $hostname;
}



# Logging

sub dbgout {
    my ( $self, $key, $value, $priority ) = @_;
    my $queue_id = $self->get_symbol('i') || q{--};
    warn "$PID: $queue_id: $key: $value\n";
    my $top_handler = $self->get_top_handler();
    if ( !exists( $top_handler->{'dbgout'} ) ) {
        $top_handler->{'dbgout'} = [];
    }
    push @{ $top_handler->{'dbgout'} },
      {
        'priority' => $priority || LOG_INFO,
        'key'      => $key      || q{},
        'value'    => $value    || q{},
      };
}

sub log_error {
    my ( $self, $error ) = @_;
    $self->dbgout( 'ERROR', $error, LOG_ERR );
}

sub dbgoutwrite {
    my ($self) = @_;
    eval {
        openlog('authentication_milter', 'pid', LOG_MAIL);
        my $CONFIG = $self->config();
        if ( $CONFIG->{'debug'} ) {
            setlogmask(   LOG_MASK(LOG_ERR)
                        | LOG_MASK(LOG_INFO)
                        | LOG_MASK(LOG_DEBUG)
            );
        }
        else {
            setlogmask(   LOG_MASK(LOG_ERR)
                        | LOG_MASK(LOG_INFO)
            );
        }
        my $queue_id = $self->get_symbol('i') || q{--};
        my $top_handler = $self->get_top_handler();
        if ( exists( $top_handler->{'dbgout'} ) ) {
            foreach my $entry ( @{ $top_handler->{'dbgout'} } ) {
                my $key      = $entry->{'key'};
                my $value    = $entry->{'value'};
                my $priority = $entry->{'priority'};
                my $line     = "$queue_id: $key: $value";
                syslog( $priority, $line );
            }
        }
        closelog();
        delete $top_handler->{'dbgout'};
    };
}



# Header handling

sub add_headers {
    my ($self) = @_;

    my $header = $self->get_my_hostname();
    my @auth_headers;
    my $top_handler = $self->get_top_handler();
    if ( exists( $top_handler->{'c_auth_headers'} ) ) {
        @auth_headers = @{ $top_handler->{'c_auth_headers'} };
    }
    if ( exists( $top_handler->{'auth_headers'} ) ) {
        @auth_headers = ( @auth_headers, @{ $top_handler->{'auth_headers'} } );
    }
    if (@auth_headers) {
        $header .= ";\n    ";
        $header .= join( ";\n    ", sort @auth_headers );
    }
    else {
        $header .= '; none';
    }

    $self->prepend_header( 'Authentication-Results', $header );

    if ( exists( $top_handler->{'pre_headers'} ) ) {
        foreach my $header ( @{ $top_handler->{'pre_headers'} } ) {
            $self->dbgout( 'PreHeader',
                $header->{'field'} . ': ' . $header->{'value'}, LOG_INFO );
            $self->insert_header( 1, $header->{'field'}, $header->{'value'} );
        }
    }

    if ( exists( $top_handler->{'add_headers'} ) ) {
        foreach my $header ( @{ $top_handler->{'add_headers'} } ) {
            $self->dbgout( 'AddHeader',
                $header->{'field'} . ': ' . $header->{'value'}, LOG_INFO );
            $self->add_header( $header->{'field'}, $header->{'value'} );
        }
    }
}

sub prepend_header {
    my ( $self, $field, $value ) = @_;
    my $top_handler = $self->get_top_handler();
    if ( !exists( $top_handler->{'pre_headers'} ) ) {
        $top_handler->{'pre_headers'} = [];
    }
    push @{ $top_handler->{'pre_headers'} },
      {
        'field' => $field,
        'value' => $value,
      };
}

sub add_auth_header {
    my ( $self, $value ) = @_;
    my $top_handler = $self->get_top_handler();
    if ( !exists( $top_handler->{'auth_headers'} ) ) {
        $top_handler->{'auth_headers'} = [];
    }
    push @{ $top_handler->{'auth_headers'} }, $value;
}

sub add_c_auth_header {

    # Connection wide auth headers
    my ( $self, $value ) = @_;
    my $top_handler = $self->get_top_handler();
    if ( !exists( $top_handler->{'c_auth_headers'} ) ) {
        $top_handler->{'c_auth_headers'} = [];
    }
    push @{ $top_handler->{'c_auth_headers'} }, $value;
}

sub append_header {
    my ( $self, $field, $value ) = @_;
    my $top_handler = $self->get_top_handler();
    if ( !exists( $top_handler->{'add_headers'} ) ) {
        $top_handler->{'add_headers'} = [];
    }
    push @{ $top_handler->{'add_headers'} },
      {
        'field' => $field,
        'value' => $value,
      };
}



# Lower level methods

sub smfis_continue {
    return SMFIS_CONTINUE;
}

sub smfis_tempfail {
    return SMFIS_TEMPFAIL;
}

sub smfis_reject {
    return SMFIS_REJECT;
}

sub smfis_discard {
    return SMFIS_DISCARD;
}

sub smfis_accept {
    return SMFIS_ACCEPT;
}



sub write_packet {
    my ( $self, $type, $data ) = @_;
    my $protocol = $self->{'protocol'};
    $protocol->write_packet( $type, $data );
}

sub add_header {
    my ( $self, $key, $value ) = @_;
    my $protocol = $self->{'protocol'};
    my $CONFIG = $self->config();
    return if $CONFIG->{'dryrun'};
    $protocol->add_header( $key, $value );
}

sub insert_header {
    my ( $self, $index, $key, $value ) = @_;
    my $protocol = $self->{'protocol'};
    my $CONFIG = $self->config();
    return if $CONFIG->{'dryrun'};
    $protocol->insert_header( $index, $key, $value );
}

sub change_header {
    my ( $self, $key, $index, $value ) = @_;
    my $protocol = $self->{'protocol'};
    my $CONFIG = $self->config();
    return if $CONFIG->{'dryrun'};
    $protocol->change_header( $key, $index, $value );
}

1;
