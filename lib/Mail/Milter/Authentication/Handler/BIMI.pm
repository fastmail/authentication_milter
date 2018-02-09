package Mail::Milter::Authentication::Handler::BIMI;
use strict;
use warnings;
use base 'Mail::Milter::Authentication::Handler';
use version; our $VERSION = version->declare('v1.1.2');

# ABSTRACT: BIMI handler for authentication milter

use English qw{ -no_match_vars };
use Mail::BIMI;
use Sys::Syslog qw{:standard :macros};
use Mail::AuthenticationResults::Header::Entry;
use Mail::AuthenticationResults::Header::SubEntry;
use Mail::AuthenticationResults::Header::Comment;

sub default_config {
    return {
    };
}

sub register_metrics {
    return {
        'bimi_total' => 'The number of emails processed for BIMI',
        'bimi_removed_total' => 'The number BIMI-Location headers removed',
    };
}

sub remove_bimi_header {
    my ( $self, $value ) = @_;
    $self->metric_count( 'bimi_remove_total' );
    if ( !exists( $self->{'remove_bimi_headers'} ) ) {
        $self->{'remove_bimi_headers'} = [];
    }
    push @{ $self->{'remove_bimi_headers'} }, $value;
    return;
}

sub envfrom_callback {
    my ( $self, $env_from ) = @_;
    delete $self->{'bimi_header_index'};
    delete $self->{'remove_bimi_headers'};
    return;
}

sub header_callback {
    my ( $self, $header, $value ) = @_;

    # Not sure where this should go in the flow, so it's going here!
    # Which is clearly, or at least probably the wrong place.
    if ( lc $header eq 'bimi-location' ) {
        if ( !exists $self->{'bimi_header_index'} ) {
            $self->{'bimi_header_index'} = 0;
        }
        $self->{'bimi_header_index'} =
        $self->{'bimi_header_index'} + 1;
        $self->remove_bimi_header( $self->{'bimi_header_index'} );
        my $forged_header =
          '(Received BIMI-Location header removed by '
          . $self->get_my_hostname()
          . ')' . "\n"
          . '    '
          . $value;
        $self->append_header( 'X-Received-BIMI-Location',
            $forged_header );
    }

    return if ( $self->is_local_ip_address() );
    return if ( $self->is_trusted_ip_address() );
    return if ( $self->is_authenticated() );
    return if ( $self->{'failmode'} );

    if ( lc $header eq 'bimi-selector' ) {
        if ( exists $self->{'selector'} ) {
            $self->dbgout( 'BIMIFail', 'Multiple BIMI-Selector fields', LOG_INFO );
            my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'bimi' )->safe_set_value( 'fail' );
            $header->add_child( Mail::AuthenticationResults::Header::Comment->new()->safe_set_value( 'multiple BIMI-Selector fields in message' ) );
            $self->add_auth_header( $header );
            $self->metric_count( 'bimi_total', { 'result' => 'fail', 'reason' => 'bad_selector_header' } );
            $self->{'failmode'} = 1;
            return;
        }
        $self->{'selector'} = $value;
    }
    if ( lc $header eq 'from' ) {
        if ( exists $self->{'from_header'} ) {
            $self->dbgout( 'BIMIFail', 'Multiple RFC5322 from fields', LOG_INFO );
            my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'bimi' )->safe_set_value( 'fail' );
            $header->add_child( Mail::AuthenticationResults::Header::Comment->new()->safe_set_value( 'multiple RFC5322 from fields in message' ) );
            $self->add_auth_header( $header );
            $self->metric_count( 'bimi_total', { 'result' => 'fail', 'reason' => 'bad_from_header' } );
            $self->{'failmode'} = 1;
            return;
        }
        $self->{'from_header'} = $value;
    }
    ## ToDo remove/rename existing headers here
    return;
}

sub eom_requires {
    my ($self) = @_;
    my @requires = qw{ DMARC };
    return \@requires;
}

sub eom_callback {
    my ($self) = @_;
    my $config = $self->handler_config();

    # Again, not sure where this should go, so it's going here.
    if ( exists( $self->{'remove_bimi_headers'} ) ) {
        foreach my $header ( reverse @{ $self->{'remove_bimi_headers'} } ) {
            $self->dbgout( 'RemoveBIMILocationHeader', $header, LOG_DEBUG );
            $self->change_header( 'BIMI-Location', $header, q{} );
        }
    }

    return if ( $self->is_local_ip_address() );
    return if ( $self->is_trusted_ip_address() );
    return if ( $self->is_authenticated() );
    return if ( $self->{'failmode'} );
    eval {
        my $Domain = $self->get_domain_from( $self->{'from_header'} );
        my $Selector = $self->{ 'selector' } || 'default';
        $Selector = lc $Selector;
        my $BIMI = Mail::BIMI->new();

        # Rework this to allow for multiple dmarc_result objects as per new DMARC handler
        my $DMARCResult = $self->get_object( 'dmarc_result' );

        if ( ! $DMARCResult ) {
            $self->log_error( 'BIMI Error No DMARC Results object');
            my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'bimi' )->safe_set_value( 'temperror' );
            $header->add_child( Mail::AuthenticationResults::Header::Comment->new()->safe_set_value( 'Internal DMARC error' ) );
            $self->add_auth_header( $header );
            return;
        }

        $BIMI->set_resolver( $self->get_object( 'resolver' ) );
        $BIMI->set_dmarc_object( $DMARCResult );
        $BIMI->set_from_domain( $Domain );
        $BIMI->set_selector( $Selector );
        $BIMI->validate();

        my $Result = $BIMI->result();
        my $AuthResults = $Result->get_authentication_results_object();
        $self->add_auth_header( $AuthResults );
        my $Record = $BIMI->record();
        my $URLList = $Record->url_list();
        if ( $Result->result() eq 'pass' ) {
            $self->prepend_header( 'BIMI-Location', join( "\n",
                'v=BIMI1;',
                '    l=' . join( ',', @$URLList ) ) );
        }

        $self->metric_count( 'bimi_total', { 'result' => $Result->result() } );

    };
    if ( my $error = $@ ) {
        $self->log_error( 'BIMI Error ' . $error );
        my $header = Mail::AuthenticationResults::Header::Entry->new()->set_key( 'bimi' )->safe_set_value( 'temperror' );
        $self->add_auth_header( $header );
        return;
    }
    return;
}

sub close_callback {
    my ( $self ) = @_;
    delete $self->{'selector'};
    delete $self->{'from_header'};
    delete $self->{'failmode'};
    delete $self->{'remove_bimi_headers'};
    delete $self->{'bimi_header_index'};
    return;
}

1;

__END__

=head1 NAME

  Authentication Milter - BIMI Module

=head1 DESCRIPTION

Module implementing the BIMI standard checks.

This handler requires the DMARC handler and its dependencies to be installed and active.

=head1 CONFIGURATION

        "BIMI" : {                                      | Config for the BIMI Module
                                                        | Requires DMARC
        },

=head1 SYNOPSIS

=head1 AUTHORS

Marc Bradshaw E<lt>marc@marcbradshaw.netE<gt>

=head1 COPYRIGHT

Copyright 2018

This library is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.

