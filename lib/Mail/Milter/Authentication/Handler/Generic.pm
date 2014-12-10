package Mail::Milter::Authentication::Handler::Generic;

use strict;
use warnings;

use English;

our $VERSION = 0.5;

use base 'Mail::Milter::Authentication::Protocol';

use Email::Address;
use English;
use Module::Load;
use Sys::Syslog qw{:standard :macros};
use Sys::Hostname;

sub callbacks {
    return {};
}

sub new {
    my ( $class, $wire ) = @_;
    my $self = {
        'wire'   => $wire,
    };
    bless $self, $class;
    return $self;
}

sub status {
    my ($self, $status) = @_;
    my $count = $self->{'wire'}->{'count'};
    if ( $status ) {
        $PROGRAM_NAME = '[authentication_milter:processing:' . $status . '(' . $count . ')]';
    }
    else {
        $PROGRAM_NAME = '[authentication_milter:processing(' . $count . ')]';
    }
}

sub config {
    my ($self) = @_;
    return $self->{'wire'}->{'config'};
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
    my $wire   = $self->{'wire'};
    my $object = $wire->{'handler'};
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
    my $top_handler = $self->get_top_handler();
    my $object      = $top_handler->{'handler'}->{$name};
    return $object;
}

sub setup_handler {
    my ( $self, $name ) = @_;

    ## TODO error handling here
    $self->dbgout( 'Load Module', "$name", LOG_DEBUG );
    my $package = "Mail::Milter::Authentication::Handler::$name";
    load $package;
    my $object = $package->new( $self->{'wire'} );

    my $top_handler = $self->get_top_handler();
    $top_handler->{'handler'}->{$name} = $object;
    
    my $callbacks = $object->callbacks();
    foreach my $callback ( keys %{$callbacks} ) {
        my $priority = $callbacks->{$callback};
        if ( $priority ) {
            $self->register_callback( $name, $callback, $priority );
        }
    }
}

sub register_callback {
    my ( $self, $name, $callback, $priority ) = @_;
    $self->dbgout( 'Register Callback', "$name:$callback:$priority", LOG_DEBUG );
    my $top_handler = $self->get_top_handler();
    if ( ! exists $top_handler->{'callbacks'} ) {
        $top_handler->{'callbacks'} = {};
    }
    if ( ! exists $top_handler->{'callbacks'}->{$callback} ) {
        $top_handler->{'callbacks'}->{$callback} = [];
    }
    push @{ $top_handler->{'callbacks'}->{$callback} }, { 'name' => $name, 'priority' => $priority };
}

sub get_callbacks {
    my ( $self, $callback ) = @_;
    my $top_handler = $self->get_top_handler();
   
    if ( ! exists $top_handler->{'callbacks'}->{$callback} ) {
        $top_handler->{'callbacks'}->{$callback} = [];
    }
    
    my @callbacks;
    my $callbacks_ref;
    $callbacks_ref = $top_handler->{'callbacks'}->{$callback};
    @callbacks = sort { $a->{'priority'} cmp $b->{'priority'} } @{$callbacks_ref};
    @callbacks = map { $_->{'name'} } @callbacks;
    return \@callbacks;
}

sub destroy_handler {
    my ( $self, $name ) = @_;
    my $top_handler = $self->get_top_handler();
    # Remove some back references
    delete $top_handler->{'handler'}->{$name}->{'wire'};
    # Remove reference to handler
    delete $top_handler->{'handler'}->{$name};
}

sub get_object {
    my ( $self, $name ) = @_;
    my $top_handler = $self->get_top_handler();
    my $object      = $top_handler->{'object'}->{$name};
    if ( ! $object ) {
        my $CONFIG = $self->config();
        my $timeout = $CONFIG->{'dns_timeout'} || 8;
        if ( $name eq 'resolver' ) {
            $object = Net::DNS::Resolver->new(
                'udp_timeout' => $timeout,
                'tcp_timeout' => $timeout,
                'retry'       => 2,
            );
            $object->udppacketsize(1240);
            $object->persistent_udp(1);
        }
    }
    return $object;
}

sub set_object {
    my ( $self, $name, $object ) = @_;
    my $top_handler = $self->get_top_handler();
    $top_handler->{'object'}->{$name} = $object;
}

sub destroy_object {
    my ( $self, $name ) = @_;
    my $top_handler = $self->get_top_handler();
    delete $top_handler->{'object'}->{$name};
}

sub destroy_all_objects {
    my ( $self ) = @_;
    my $top_handler = $self->get_top_handler();
    foreach my $name ( keys %{ $top_handler->{'object'} } )
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
    my $core_handler = $self->get_handler('Core');
    return $core_handler->{'ip_address'};
}

sub helo_name {
    my ($self) = @_;
    my $core_handler = $self->get_handler('Core');
    return $core_handler->{'helo_name'};
}

sub mail_from {
    my ($self) = @_;
    my $core_handler = $self->get_handler('Core');
    return $core_handler->{'mail_from'};
}

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

sub dbgout {
    my ( $self, $key, $value, $priority ) = @_;
    my $queue_id = $self->get_symbol('i') || q{--};
    warn "$PID: $queue_id: $key: $value\n";
    my $core_handler = $self->get_handler('Core');
    if ( !exists( $core_handler->{'dbgout'} ) ) {
        $core_handler->{'dbgout'} = [];
    }
    push @{ $core_handler->{'dbgout'} },
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
        my $core_handler = $self->get_handler('Core');
        if ( exists( $core_handler->{'dbgout'} ) ) {
            foreach my $entry ( @{ $core_handler->{'dbgout'} } ) {
                my $key      = $entry->{'key'};
                my $value    = $entry->{'value'};
                my $priority = $entry->{'priority'};
                my $line     = "$queue_id: $key: $value";
                syslog( $priority, $line );
            }
        }
        closelog();
        delete $core_handler->{'dbgout'};
    };
}

sub add_headers {
    my ($self) = @_;

    my $header = $self->get_my_hostname();
    my @auth_headers;
    my $core_handler = $self->get_handler('Core');
    if ( exists( $core_handler->{'c_auth_headers'} ) ) {
        @auth_headers = @{ $core_handler->{'c_auth_headers'} };
    }
    if ( exists( $core_handler->{'auth_headers'} ) ) {
        @auth_headers = ( @auth_headers, @{ $core_handler->{'auth_headers'} } );
    }
    if (@auth_headers) {
        $header .= ";\n    ";
        $header .= join( ";\n    ", sort @auth_headers );
    }
    else {
        $header .= '; none';
    }

    $self->prepend_header( 'Authentication-Results', $header );

    if ( exists( $core_handler->{'pre_headers'} ) ) {
        foreach my $header ( @{ $core_handler->{'pre_headers'} } ) {
            $self->dbgout( 'PreHeader',
                $header->{'field'} . ': ' . $header->{'value'}, LOG_INFO );
            $self->insert_header( 1, $header->{'field'}, $header->{'value'} );
        }
    }

    if ( exists( $core_handler->{'add_headers'} ) ) {
        foreach my $header ( @{ $core_handler->{'add_headers'} } ) {
            $self->dbgout( 'AddHeader',
                $header->{'field'} . ': ' . $header->{'value'}, LOG_INFO );
            $self->add_header( $header->{'field'}, $header->{'value'} );
        }
    }
}

sub prepend_header {
    my ( $self, $field, $value ) = @_;
    my $core_handler = $self->get_handler('Core');
    if ( !exists( $core_handler->{'pre_headers'} ) ) {
        $core_handler->{'pre_headers'} = [];
    }
    push @{ $core_handler->{'pre_headers'} },
      {
        'field' => $field,
        'value' => $value,
      };
}

sub add_auth_header {
    my ( $self, $value ) = @_;
    my $core_handler = $self->get_handler('Core');
    if ( !exists( $core_handler->{'auth_headers'} ) ) {
        $core_handler->{'auth_headers'} = [];
    }
    push @{ $core_handler->{'auth_headers'} }, $value;
}

sub add_c_auth_header {

    # Connection wide auth headers
    my ( $self, $value ) = @_;
    my $core_handler = $self->get_handler('Core');
    if ( !exists( $core_handler->{'c_auth_headers'} ) ) {
        $core_handler->{'c_auth_headers'} = [];
    }
    push @{ $core_handler->{'c_auth_headers'} }, $value;
}

sub append_header {
    my ( $self, $field, $value ) = @_;
    my $core_handler = $self->get_handler('Core');
    if ( !exists( $core_handler->{'add_headers'} ) ) {
        $core_handler->{'add_headers'} = [];
    }
    push @{ $core_handler->{'add_headers'} },
      {
        'field' => $field,
        'value' => $value,
      };
}

1;
