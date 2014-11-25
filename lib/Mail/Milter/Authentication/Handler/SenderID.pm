package Mail::Milter::Authentication::Handler::SenderID;

use strict;
use warnings;

our $VERSION = 0.3;

use base 'Mail::Milter::Authentication::Handler::Generic';

use Sys::Syslog qw{:standard :macros};

use Mail::SPF;

sub envfrom_callback {
    my ( $self, $env_from ) = @_;
    my $CONFIG = $self->config();
    return if ( !$CONFIG->{'check_senderid'} );
    return if ( $self->is_local_ip_address() );
    return if ( $self->is_trusted_ip_address() );
    return if ( $self->is_authenticated() );
    delete $self->{'from_header'};
}

sub header_callback {
    my ( $self, $header, $value ) = @_;
    my $CONFIG = $self->config();
    return if ( !$CONFIG->{'check_senderid'} );
    return if ( $self->is_local_ip_address() );
    return if ( $self->is_trusted_ip_address() );
    return if ( $self->is_authenticated() );
    if ( $header eq 'From' ) {
        $self->{'from_header'} = $value;
    }
}

sub eoh_callback {
    my ($self) = @_;
    my $CONFIG = $self->config();
    return if ( !$CONFIG->{'check_senderid'} );
    return if ( $self->is_local_ip_address() );
    return if ( $self->is_trusted_ip_address() );
    return if ( $self->is_authenticated() );

    my $spf_server;
    eval {
        $spf_server =
          Mail::SPF::Server->new( 'hostname' => $self->get_my_hostname() );
    };
    if ( my $error = $@ ) {
        $self->log_error( 'SenderID Setup Error ' . $error );
        $self->add_auth_header( 'senderid=temperror' );
        return;
    }

    my $scope = 'pra';

    my $identity = $self->get_address_from( $self->{'from_header'} );


    eval {
        my $spf_request = Mail::SPF::Request->new(
            'versions'      => [2],
            'scope'         => $scope,
            'identity'      => $identity,
            'ip_address'    => $self->ip_address(),
            'helo_identity' => $self->helo_name(),
        );

        my $spf_result = $spf_server->process($spf_request);
        #$self->{'ctx'}->progress();

        my $result_code = $spf_result->code();
        $self->dbgout( 'SenderIdCode', $result_code, LOG_INFO );

        if ( ! ( $CONFIG->{'check_senderid'} == 2 && $result_code eq 'none' ) ) {
            my $auth_header = $self->format_header_entry( 'senderid', $result_code );
            $self->add_auth_header( $auth_header );
#my $result_local  = $spf_result->local_explanation;
#my $result_auth   = $spf_result->can( 'authority_explanation' ) ? $spf_result->authority_explanation() : '';
            my $result_header = $spf_result->received_spf_header();
            my ( $header, $value ) = $result_header =~ /(.*): (.*)/;
            $self->prepend_header( $header, $value );
            $self->dbgout( 'SPFHeader', $result_header, LOG_DEBUG );
        }
    };
    if ( my $error = $@ ) {
        $self->log_error( 'SENDERID Error ' . $error );
        $self->add_auth_header( 'senderid=temperror' );
        return;
    }
}

1;
