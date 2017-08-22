package Mail::Milter::Authentication::Constants;
use strict;
use warnings;
use base 'Exporter';
use version; our $VERSION = version->declare('v1.1.3');

## no critic [Modules::ProhibitAutomaticExportation]

use constant SMFIA_UNKNOWN      => 'U';
use constant SMFIA_UNIX         => 'L';
use constant SMFIA_INET         => '4';
use constant SMFIA_INET6        => '6';

use constant SMFIC_ABORT        => 'A';
use constant SMFIC_BODY         => 'B';
use constant SMFIC_CONNECT      => 'C';
use constant SMFIC_MACRO        => 'D';
use constant SMFIC_BODYEOB      => 'E';
use constant SMFIC_HELO         => 'H';
use constant SMFIC_HEADER       => 'L';
use constant SMFIC_MAIL         => 'M';
use constant SMFIC_EOH          => 'N';
use constant SMFIC_OPTNEG       => 'O';
use constant SMFIC_RCPT         => 'R';
use constant SMFIC_QUIT         => 'Q';
use constant SMFIC_DATA         => 'T';
use constant SMFIC_UNKNOWN      => 'U';

use constant SMFIR_ADDRCPT      => '+';
use constant SMFIR_DELRCPT      => '-';
use constant SMFIR_ACCEPT       => 'a';
use constant SMFIR_REPLBODY     => 'b';
use constant SMFIR_CONTINUE     => 'c';
use constant SMFIR_DISCARD      => 'd';
use constant SMFIR_ADDHEADER    => 'h';
use constant SMFIR_INSHEADER    => 'i';
use constant SMFIR_CHGHEADER    => 'm';
use constant SMFIR_PROGRESS     => 'p';
use constant SMFIR_QUARANTINE   => 'q';
use constant SMFIR_REJECT       => 'r';
use constant SMFIR_SETSENDER    => 's';
use constant SMFIR_TEMPFAIL     => 't';
use constant SMFIR_REPLYCODE    => 'y';

use constant SMFIP_NOCONNECT    => 0x01;
use constant SMFIP_NOHELO       => 0x02;
use constant SMFIP_NOMAIL       => 0x04;
use constant SMFIP_NORCPT       => 0x08;
use constant SMFIP_NOBODY       => 0x10;
use constant SMFIP_NOHDRS       => 0x20;
use constant SMFIP_NOEOH        => 0x40;
use constant SMFIP_NONE         => 0x7F;

use constant SMFIS_CONTINUE     => 100;
use constant SMFIS_REJECT       => 101;
use constant SMFIS_DISCARD      => 102;
use constant SMFIS_ACCEPT       => 103;
use constant SMFIS_TEMPFAIL     => 104;

use constant SMFIF_ADDHDRS      => 0x01;
use constant SMFIF_CHGBODY      => 0x02;
use constant SMFIF_ADDRCPT      => 0x04;
use constant SMFIF_DELRCPT      => 0x08;
use constant SMFIF_CHGHDRS      => 0x10;
use constant SMFIF_MODBODY      => SMFIF_CHGBODY;
use constant SMFIF_QUARANTINE   => 0x20;
use constant SMFIF_SETSENDER    => 0x40;

use constant SMFI_V1_ACTS       => SMFIF_ADDHDRS|SMFIF_CHGBODY|SMFIF_ADDRCPT|SMFIF_DELRCPT;
use constant SMFI_V2_ACTS       => SMFI_V1_ACTS|SMFIF_CHGHDRS;
use constant SMFI_CURR_ACTS     => SMFI_V2_ACTS;

our @EXPORT = qw(
    SMFIA_UNKNOWN
    SMFIA_UNIX
    SMFIA_INET
    SMFIA_INET6
    SMFIC_ABORT
    SMFIC_BODY
    SMFIC_CONNECT
    SMFIC_MACRO
    SMFIC_BODYEOB
    SMFIC_HELO
    SMFIC_HEADER
    SMFIC_MAIL
    SMFIC_EOH
    SMFIC_OPTNEG
    SMFIC_RCPT
    SMFIC_QUIT
    SMFIC_DATA
    SMFIC_UNKNOWN
    SMFIR_ADDRCPT
    SMFIR_DELRCPT
    SMFIR_ACCEPT
    SMFIR_REPLBODY
    SMFIR_CONTINUE
    SMFIR_DISCARD
    SMFIR_ADDHEADER
    SMFIR_INSHEADER
    SMFIR_CHGHEADER
    SMFIR_PROGRESS
    SMFIR_QUARANTINE
    SMFIR_REJECT
    SMFIR_SETSENDER
    SMFIR_TEMPFAIL
    SMFIR_REPLYCODE
    SMFIP_NOCONNECT
    SMFIP_NOHELO
    SMFIP_NOMAIL
    SMFIP_NORCPT
    SMFIP_NOBODY
    SMFIP_NOHDRS
    SMFIP_NOEOH
    SMFIP_NONE
    SMFIS_CONTINUE
    SMFIS_REJECT
    SMFIS_DISCARD
    SMFIS_ACCEPT
    SMFIS_TEMPFAIL
    SMFIF_ADDHDRS
    SMFIF_CHGBODY
    SMFIF_ADDRCPT
    SMFIF_DELRCPT
    SMFIF_CHGHDRS
    SMFIF_MODBODY
    SMFIF_QUARANTINE
    SMFIF_SETSENDER
    SMFI_V1_ACTS
    SMFI_V2_ACTS
    SMFI_CURR_ACTS
);
our @EXPORT_OK = ( @EXPORT );
our %EXPORT_TAGS = ( 'all' => [ @EXPORT_OK ] );


1;

__END__

=head1 NAME

Mail::Milter::Authentication::Constants - Constant declarations

=head1 DESCRIPTION

Exports useful constants.

=head1 SYNOPSIS

Constants defined here are used in the sendmail milter protocol.

=head1 FUNCTIONS

none

=head1 DEPENDENCIES

none

=head1 AUTHORS

Marc Bradshaw E<lt>marc@marcbradshaw.netE<gt>

=head1 COPYRIGHT

Copyright 2017

This library is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.


