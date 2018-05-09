package Mail::Milter::Authentication::Handler::ARC;
use strict;
use warnings;
use Mail::Milter::Authentication 2;
use base 'Mail::Milter::Authentication::Handler';
# VERSION
# ABSTRACT: Authentication Milter Module for validation of ARC signatures
use Data::Dumper;
use English qw{ -no_match_vars };
use Sys::Syslog qw{:standard :macros};

use Mail::DKIM 0.50;
use Mail::DKIM::DNS;
use Mail::DKIM::TextWrap;
use Mail::DKIM::ARC::Signer;
use Mail::DKIM::ARC::Verifier;
use Mail::AuthenticationResults::Header::Entry;
use Mail::AuthenticationResults::Header::SubEntry;
use Mail::AuthenticationResults::Header::Comment;

sub default_config {
    return {
        'hide_none'         => 0,
        'arcseal_domain'    => undef,
        'arcseal_selector'  => undef,
        'arcseal_algorithm' => 'rsa-sha256',
        'arcseal_key'       => undef,
        'arcseal_keyfile'   => undef,
        'arcseal_headers'   => undef,
    };
}

sub grafana_rows {
    my ( $self ) = @_;
    my @rows;
    push @rows, $self->get_json( 'ARC_metrics' );
    return \@rows;
}

sub register_metrics {
    return {
        'arc_total' => 'The number of emails processed for ARC',
        'arc_signatures' => 'The number of signatures processed for ARC',
        'arcseal_total' => 'The number of ARC seals added',
    };
}

sub envfrom_callback {
    my ( $self, $env_from )  = @_;
    $self->{'failmode'}      = 0;
    $self->{'headers'}       = [];
    $self->{'body'}          = [];
    $self->{'has_arc'}       = 0;
    $self->{'valid_domains'} = {};
    $self->{'carry'}         = q{};
    $self->destroy_object('arc');
    return;
}

sub header_callback {
    my ( $self, $header, $value ) = @_;
    my $EOL        = "\015\012";
    my $arc_chunk = $header . ': ' . $value . $EOL;
    $arc_chunk =~ s/\015?\012/$EOL/g;
    push @{$self->{'headers'}} , $arc_chunk;

    if ( lc($header) eq 'arc-authentication-results' ) {
        $self->{'has_arc'} = 1;
    }

    if ( lc($header) eq 'arc-seal' ) {
        $self->{'has_arc'} = 1;
    }

    if ( lc($header) eq 'arc-message-signature' ) {
        $self->{'has_arc'} = 1;
    }

    return;
}

sub eoh_callback {
    my ($self) = @_;
    my $config = $self->handler_config();

    $self->{'carry'} = q{};

    if ($config->{arcseal_domain} and
        $config->{arcseal_selector} and
        ($config->{arcseal_key} || $config->{arcseal_keyfile}))
    {
        $self->{has_arcseal} = 1;
    }

    unless ($self->{'has_arc'}) {
        $self->metric_count( 'arc_total', { 'result' => 'none' } );
        $self->dbgout( 'ARCResult', 'No ARC headers', LOG_INFO );
        unless ($config->{'hide_none'}) {
            my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'arc' )->safe_set_value( 'none' );
            $header->add_child( Mail::AuthenticationResults::Header::Comment->new()->safe_set_value( 'no signatures found' ) );
            $self->add_auth_header( $header );
        }
        $self->{arc_result} = 'none';
        delete $self->{headers} unless $self->{has_arcseal};
        return;
    }

    my $arc;
    eval {
        $arc = Mail::DKIM::ARC::Verifier->new();
        # The following requires Mail::DKIM > 0.4
        my $resolver = $self->get_object('resolver');
        Mail::DKIM::DNS::resolver($resolver);
        $self->set_object('arc', $arc, 1);
    };
    if ( my $error = $@ ) {
        $self->log_error( 'ARC Setup Error ' . $error );
        die $error if $error =~ /Timeout/;
        $self->_check_error( $error );
        $self->metric_count( 'arc_total', { 'result' => 'error' } );
        $self->{'failmode'} = 1;
        $self->{arc_result} = 'fail'; # XXX - handle tempfail better
        delete $self->{headers} unless $self->{has_arcseal};
        return;
    }

    eval {
        $arc->PRINT( join q{},
            @{ $self->{'headers'} },
            "\015\012",
        );
    };
    if ( my $error = $@ ) {
        $self->log_error( 'ARC Headers Error ' . $error );
        die $error if $error =~ /Timeout/;
        $self->_check_error( $error );
        $self->metric_count( 'arc_total', { 'result' => 'error' } );
        $self->{'failmode'} = 1;
        $self->{arc_result} = 'fail'; # XXX - handle tempfail better
        delete $self->{headers} unless $self->{has_arcseal};
        return;
    }
}

sub body_callback {
    my ( $self, $body_chunk ) = @_;
    my $EOL = "\015\012";

    my $arc_chunk;
    if ( $self->{'carry'} ne q{} ) {
        $arc_chunk = $self->{'carry'} . $body_chunk;
        $self->{'carry'} = q{};
    }
    else {
        $arc_chunk = $body_chunk;
    }

    if ( substr( $arc_chunk, -1 ) eq "\015" ) {
        $self->{'carry'} = "\015";
        $arc_chunk = substr( $arc_chunk, 0, -1 );
    }

    $arc_chunk =~ s/\015?\012/$EOL/g;
    push @{$self->{body}}, $arc_chunk if $self->{has_arcseal};

    if ($self->{has_arc} and not $self->{failmode}) {
        my $arc = $self->get_object('arc');
        eval {
            $arc->PRINT( $arc_chunk );
        };
        if ( my $error = $@ ) {
            $self->log_error( 'ARC Body Error ' . $error );
            die $error if $error =~ /Timeout/;
            $self->_check_error( $error );
            $self->metric_count( 'arc_total', { 'result' => 'error' } );
            $self->{'failmode'} = 1;
            $self->{arc_result} = 'fail'; # XXX - handle tempfail better
            delete $self->{headers} unless $self->{has_arcseal};
        }
    }
}

sub eom_callback {
    my ($self) = @_;

    push @{$self->{body}}, $self->{carry} if ($self->{carry} and $self->{has_arcseal});

    # the rest of eom is only used for arc, not arcseal
    return unless $self->{'has_arc'};
    return if $self->{'failmode'};

    my $config = $self->handler_config();

    my $arc = $self->get_object('arc');

    eval {
        $arc->PRINT( $self->{'carry'} );
        $arc->CLOSE();

        my $arc_result        = $arc->result;
        my $arc_result_detail = $arc->result_detail;

        $self->metric_count( 'arc_total', { 'result' => $arc_result } );

        $self->dbgout( 'ARCResult', $arc_result_detail, LOG_INFO );

        my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'arc' )->safe_set_value( $arc_result );

        my @items;
        foreach my $signature ( @{ $arc->{signatures} } ) {
            my $type =
                ref($signature) eq 'Mail::DKIM::ARC::Seal'             ? 'as'
              : ref($signature) eq 'Mail::DKIM::ARC::MessageSignature' ? 'ams'
              : ref($signature);
            push @items,
                "$type."
              . ( $signature->instance()      || '' )       . '.'
              . ( $signature->domain()        || '(none)' ) . '='
              . ( $signature->result_detail() || '?' );
        }

        if ( @items ) {
            my $header_comment = Mail::AuthenticationResults::Header::Comment->new();
            my $header_comment_text = join( ', ', @items );
            # Try set_value first (required for potential nested comment), if this fails then
            # set using safe_set_value
            eval { $header_comment->set_value( $header_comment_text ); };
            if ( my $error = $@ ) {
                die $error if $error =~ /Timeout/;
                $header_comment->safe_set_value( $header_comment_text );
            }
            $header->add_child( $header_comment );
        }

        $self->add_auth_header( $header );

        $self->{arc_result} = $arc_result;
    };
    if ( my $error = $@ ) {
        $self->log_error( 'ARC EOM Error ' . $error );
        die $error if $error =~ /Timeout/;
        $self->_check_error( $error );
        $self->metric_count( 'arc_total', { 'result' => 'error' } );
        $self->{'failmode'} = 1;
        $self->{arc_result} = 'fail';
    }
}

sub close_callback {
    my ( $self ) = @_;
    delete $self->{'failmode'};
    delete $self->{'headers'};
    delete $self->{'body'};
    delete $self->{'carry'};
    delete $self->{'has_arc'};
    delete $self->{'valid_domains'};
    $self->destroy_object('arc');
    return;
}

sub _check_error {
    my ( $self, $error ) = @_;
    if ( $error =~ /^DNS error: query timed out/
            or $error =~ /^DNS query timeout/
    ){
        $self->log_error( 'Temp ARC Error - ' . $error );
        my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'arc' )->safe_set_value( 'temperror' );
        $header->add_child( Mail::AuthenticationResults::Header::Comment->new()->safe_set_value( 'dns timeout' ) );
        $self->add_auth_header( $header );
    }
    elsif ( $error =~ /^DNS error: SERVFAIL/ ){
        $self->log_error( 'Temp ARC Error - ' . $error );
        my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'arc' )->safe_set_value( 'temperror' );
        $header->add_child( Mail::AuthenticationResults::Header::Comment->new()->safe_set_value( 'dns servfail' ) );
        $self->add_auth_header( $header );
    }
    elsif ( $error =~ /^no domain to fetch policy for$/
            or $error =~ /^policy syntax error$/
            or $error =~ /^empty domain label/
            or $error =~ /^invalid name /
    ){
        $self->log_error( 'Perm ARC Error - ' . $error );
        my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'arc' )->safe_set_value( 'permerror' );
        $header->add_child( Mail::AuthenticationResults::Header::Comment->new()->safe_set_value( 'syntax or domain error' ) );
        $self->add_auth_header( $header );
    }
    else {
        $self->log_error( 'Unexpected ARC Error - ' . $error );
        my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'arc' )->safe_set_value( 'temperror' );
        $self->add_auth_header( $header );
        # Fill these in as they occur, but for unknowns err on the side of caution
        # and tempfail/exit
        $self->exit_on_close();
        $self->tempfail_on_error();
    }
    return;
}

sub _fmtheader {
    my $header = shift;
    my $value = $header->{value};
    $value =~ s/\015?\012/\015\012/gs;  # make sure line endings are right
    return "$header->{field}: $value\015\012";
}

sub addheader_callback {
    my $self = shift;
    my $handler = shift;

    return unless $self->{has_arcseal};

    my $config = $self->handler_config();

    eval {
        my %KeyOpts;
        if ($config->{arcseal_keyfile}) {
            $KeyOpts{KeyFile} = $config->{arcseal_keyfile};
        }
        else {
            $KeyOpts{Key} = Mail::DKIM::PrivateKey->load(
                            Data => $config->{arcseal_key});
        }
        my $arcseal = Mail::DKIM::ARC::Signer->new(
            Algorithm => $config->{arcseal_algorithm},
            Domain => $config->{arcseal_domain},
            SrvId => $self->get_my_hostname(),
            Selector =>  $config->{arcseal_selector},
            Headers => $config->{arcseal_headers},
            # chain value is arc_result from previous seal validation
            Chain => $self->{arc_result},
            Timestamp => time(),
            %KeyOpts,
        );

        # pre-headers from handler (reversed as they will add in reverse)
        foreach my $header (reverse @{$handler->{pre_headers} || []}) {
            $arcseal->PRINT(_fmtheader($header));
        }

        # then all the original headers: XXX - this doesn't deal with
        # the change_header command,  but only sanitize uses that.
        # It would be a massive pain to make that work consistently,
        # as it would need to modify the already cached headers in
        # each handler with the current architecture
        foreach my $chunk (@{$self->{headers} || []}) {
            $arcseal->PRINT($chunk);
        }

        # post-headers from handler (these are in order)
        foreach my $header (@{$handler->{add_headers} || []}) {
            $arcseal->PRINT(_fmtheader($header));
        }

        # finish header block with a blank line
        $arcseal->PRINT("\015\012");

        # all the body chunks
        foreach my $chunk (@{$self->{body}}) {
            $arcseal->PRINT($chunk);
        }

        # and we're done
        $arcseal->CLOSE;

        my $arcseal_result = $arcseal->result();
        my $arcseal_result_detail = $arcseal->result_detail();

        $self->metric_count( 'arcseal_total', { 'result' => $arcseal_result } );

        $self->dbgout( 'ARCSealResult', $arcseal_result_detail, LOG_INFO );

        # we need to extract the headers from ARCSeal and re-format them
        # back to the format that pre_headers expects
        my $headers = $arcseal->as_string();
        my @list;

        my $current_header = q{};
        my $current_value  = q{};
        foreach my $header_line ( (split ( /\015?\012/, $headers ) ) ) {
            if ( $header_line =~ /^\s/ ) {
                # Line begins with whitespace, add to previous header
                $header_line =~ s/^\s+/    /; # for consistency
                $current_value .= "\n" . $header_line;
            }
            else {
                # This is a brand new header!
                if ( $current_header ne q{} ) {
                    # We have a cached header, add it now.
                    push @list, { 'field' => $current_header, 'value' => $current_value };
                    $current_value = q{};
                }
                ( $current_header, $current_value ) = split ( ':', $header_line, 2 );
                $current_value =~ s/^ +//;
            }
        }
        if ( $current_header ne q{} ) {
            # We have a cached header, add it now.
            push @list, { 'field' => $current_header, 'value' => $current_value };
            $current_value = q{};
        }

        # these will prepend in reverse
        push @{$handler->{pre_headers}}, reverse @list;
    };

    if ( my $error = $@ ) {
        $self->log_error( 'ARCSeal Error ' . $error );
        die $error if $error =~ /Timeout/;
        $self->metric_count( 'arcseal_total', { 'result' => 'error' } );
        return;
    }
}

1;

__END__

=head1 DESCRIPTION

Module for validation of ARC signatures

=head1 CONFIGURATION

        "ARC" : {                                       | Config for the ARC Module
            "hide_none"         : 0,                    | Hide auth line if the result is 'none'
            "arcseal_domain"    : "example.com",        | Domain to sign ARC Seal with (not sealed if blank)
            "arcseal_selector"  => undef,               | Selector to use for ARC Seal (not sealed if blank)
            "arcseal_algorithm" => 'rsa-sha256',        | Algorithm to use on ARC Seal (default rsa-sha256)
            "arcseal_key"       => undef,               | Key (base64) string to sign ARC Seal with; or
            "arcseal_keyfile"   => undef,               | File containing ARC Seal key
            "arcseal_headers"   => undef,               | Additional headers to cover in ARC-Message-Signature
        },

