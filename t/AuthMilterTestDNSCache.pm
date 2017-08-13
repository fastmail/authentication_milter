package AuthMilterTestDNSCache;
use strict;
use warnings;
use version; our $VERSION = version->declare('v1.1.0');

use base 'Net::DNS::Resolver';

use Net::DNS::Packet;
use Net::DNS::Question;
use Net::DNS::ZoneFile;

sub load_zonefile {
    my ( $self, $zonefile ) = @_;
    $self->{ 'zonefile' } = Net::DNS::ZoneFile->read( $zonefile );
    return;
}

sub send {
    my ( $self, $name, $type ) = @_;

    $name =~ s/\.$//;

    my $FakeZone = $self->{ 'zonefile' };

    my $origname = $name;
    if ( lc $type eq 'ptr' ) {
        if ( index( $name,' .in-addr.arpa' )  == -1 ) {
            $name = join( '.', reverse( split( /\./, $name ) ) );
            $name .= '.in-addr.arpa';
        }
    }

    my $Packet = Net::DNS::Packet->new();
    $Packet->push( 'question' => Net::DNS::Question->new( $origname, $type, 'IN' ) );
    foreach my $Item ( @$FakeZone ) {
        my $itemname = $Item->name();
        my $itemtype = $Item->type();
        if ( ( lc $itemname eq lc $name ) && ( lc $itemtype eq lc $type ) ) {
            $Packet->push( 'answer' => $Item );
        }
    }
    $Packet->{ 'answerfrom' } = '127.0.0.1';
    $Packet->{ 'status' } = 33152;
    return $Packet;
}

1;
