package Mail::Milter::Authentication::Protocol::SMTP;
use strict;
use warnings;
our $VERSION = 0.6;

use English qw{ -no_match_vars };
use Digest::MD5 qw{ md5_base64 };
use Net::IP;

use Mail::Milter::Authentication::Constants qw{ :all };

sub protocol_process_request {
    my ( $self ) = @_;
   
    my $socket = $self->{'socket'};

    $self->{'smtp'} = {
        'fwd_helo_host' => q{},
        'helo_host'     => q{},
        'has_connected' => 0,
        'has_data'      => 0,
        'connect_ip'    => $self->{'server'}->{'peeraddr'},
        'connect_host'  => $self->{'server'}->{'peeraddr'}, ## TODO Lookup Name Here
    };

    my $smtp = $self->{'smtp'};

    my $server_name = 'server.example.com';
    my $handler = $self->{'handler'}->{'_Handler'};

    # Get connect host and Connect IP from the connection here!

    print $socket "220 $server_name ESMTP AuthenticationMilter\r\n";

    $handler->set_symbol( 'C', 'j', $server_name );
    $handler->set_symbol( 'C', '{rcpt_host}', $server_name );

    my $queue_id = md5_base64( "Authentication Milter Client $PID " . time() );
    $handler->set_symbol( 'C', 'i', $queue_id );

    COMMAND:
    while ( 1 ) {

        my $command = <$socket> || last COMMAND;
        $command =~ s/\r?\n$//;

        $self->logdebug( "receive command $command" );

        my $returncode = SMFIS_CONTINUE;

        if ( $command =~ /^EHLO/ ) {
            if ( $smtp->{'has_data'} ) {
                print $socket "501 Out of Order\r\n";
                last COMMAND;
            }
            $smtp->{'helo_host'} = substr( $command,5 );
            print $socket "250-$server_name\r\n";
            print $socket "250-XFORWARD NAME ADDR PROTO HELO\r\n";
            print $socket "250 8BITMIME\r\n";
        }
        elsif ( $command =~ /^HELO/ ) {
            if ( $smtp->{'has_data'} ) {
                print $socket "501 Out of Order\r\n";
                last COMMAND;
            }
            $smtp->{'helo_host'} = substr( $command,5 );
            print $socket "250 $server_name Hi " . $smtp->{'helo_host'} . "\r\n";
        }
        elsif ( $command =~ /^XFORWARD/ ) {
            if ( $smtp->{'has_data'} ) {
                print $socket "503 Out of Order\r\n";
                last COMMAND;
            }
            my $xdata = substr( $command,9 );
            foreach my $entry ( split( q{ }, $xdata ) ) {
                my ( $key, $value ) = split( '=', $entry, 2 );
                if ( $key eq 'NAME' ) {
                    $smtp->{'connect_host'} = $value;
                }
                elsif ( $key eq 'ADDR' ) {
                    $smtp->{'connect_ip'} = $value;
                }
                elsif ( $key eq 'HELO' ) {
                    $smtp->{'fwd_helo_host'} = $value;
                }
                else {
                    # NOP
                    ### log it here though
                }
            }
            print $socket "250 Ok\r\n";
        }
        elsif ( $command =~ /^MAIL FROM:/ ) {
            if ( $smtp->{'has_data'} ) {
                print $socket "503 Out of Order\r\n";
                last COMMAND;
            }
            # Do connect callback here, because of XFORWARD
            if ( ! $smtp->{'has_connected'} ) {
                $returncode = $handler->top_connect_callback( $smtp->{'connect_host'}, Net::IP->new( $smtp->{'connect_ip'} ) );
                if ( $returncode == SMFIS_CONTINUE ) {
                    $returncode = $handler->top_helo_callback( $smtp->{'helo_host'} );
                    if ( $returncode == SMFIS_CONTINUE ) {
                        $smtp->{'has_connected'} = 1;
                        my $envfrom = substr( $command,11 );
                        $returncode = $handler->top_envfrom_callback( $envfrom );
                        if ( $returncode == SMFIS_CONTINUE ) {
                            print $socket "250 Ok\r\n";
                        }
                        else {
                            print $socket "451 That's not right\r\n";
                        }
                    }
                    else { 
                        print $socket "451 That's not right\r\n";
                    }
                }
                else { 
                    print $socket "451 That's not right\r\n";
                }
            } 
            else { 
                my $envfrom = substr( $command,11 );
                $returncode = $handler->top_envfrom_callback( $envfrom );
                if ( $returncode == SMFIS_CONTINUE ) {
                    print $socket "250 Ok\r\n";
                }
                else {
                    print $socket "451 That's not right\r\n";
                }
            }
        }
        elsif ( $command =~ /^RCPT TO:/ ) {
            if ( $smtp->{'has_data'} ) {
                print $socket "503 Out of Order\r\n";
                last COMMAND;
            }
            my $envrcpt = substr( $command,9 );
            $returncode = $handler->top_envrcpt_callback( $envrcpt );
            if ( $returncode == SMFIS_CONTINUE ) {
                print $socket "250 Ok\r\n";
            }
            else {
                print $socket "451 That's not right\r\n";
            }
        }
        elsif ( $command =~ /^DATA/ ) {
            if ( $smtp->{'has_data'} ) {
                print $socket "503 One at a time please\r\n";
                last COMMAND;
            }
            $smtp->{'has_data'} = 1;
            print $socket "354 Send body\r\n";
            DATA:
            while ( my $dataline = <$socket> ) {
                $dataline =~ s/\r?\n$//;
                # Don't forget to deal with encoded . in the message text
                last DATA if $dataline eq '.';
            }
            #$returncode = $handler->top_header_callback( '', '' );
            #$returncode = $handler->top_eoh_callback();
            #$returncode = $handler->top_body_callback( '' );
            #$returncode = $handler->top_eom_callback();
            if ( $returncode == SMFIS_CONTINUE ) {
                print $socket "250 Queued as $queue_id\r\n";
            }
            else { 
                print $socket "451 That's not right\r\n";
            }

        }
        elsif ( $command =~ /^QUIT/ ){
            print $socket "221 Bye\n";
            last COMMAND;
        }
        else {
            print $socket "502 I don't understand\r\n";
        }

    }

    # Setup Header arrays

    # Process commands
    
    # Process header results
    
    # Pass on to destination
    
}

sub add_header {
}

sub change_header {
}

sub insert_header {
}

1;

__END__

=head1 NAME

Mail::Milter::Authentication::Protocol::SMTP - SMTP protocol specific methods

=head1 DESCRIPTION

A PERL implemtation of email authentication standards rolled up into a single easy to use milter.

=head1 SYNOPSIS

Subclass of Net::Server::PreFork for bringing up the main server process for authentication_milter.

Please see Net::Server docs for more detail of the server code.

=head1 METHODS

=over

=item I<protocol_process_command( $command, $buffer )>

Process the command from the SMTP protocol stream.

=item I<add_header( $header, $value )>

Add a header

=item I<change_header( $header, $index, $value )>

Change a header

=item I<insert_header( $index, $key, $value )>

Insert a header

=back

=head1 DEPENDENCIES

  English
  Digest::MD5
  Net::IP

=head1 AUTHORS

Marc Bradshaw E<lt>marc@marcbradshaw.netE<gt>

=head1 COPYRIGHT

Copyright 2015

This library is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.


