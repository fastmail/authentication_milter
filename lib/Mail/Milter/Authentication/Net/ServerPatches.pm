package Mail::Milter::Authentication::Net::ServerPatches;
use 5.20.0;
use strict;
use warnings;
use Mail::Milter::Authentication::Pragmas;
# ABSTRACT: Patches to Net::Server::PreFork
# VERSION
use base 'Net::Server::PreFork';
use POSIX qw(EINTR);
use SUPER;
use Socket qw(AF_INET AF_UNIX SOCK_DGRAM SOCK_STREAM);

=method I<run_child()>

Patches to the Net::Server run_child method

=cut

sub run_child {
    my $self = shift;

    my $config = $self->{config} || get_config();
    return $self->SUPER unless $config->{'patch_net_server'};

    my $prop = $self->{'server'};

    $SIG{'INT'} = $SIG{'TERM'} = $SIG{'QUIT'} = sub {
        $self->child_finish_hook;
        exit;
    };
    $SIG{'PIPE'} = 'IGNORE';
    $SIG{'CHLD'} = 'DEFAULT';
    $SIG{'HUP'}  = sub {
        if (! $prop->{'connected'}) {
            $self->child_finish_hook;
            exit;
        }
        $prop->{'SigHUPed'} = 1;
    };

    # Open in child at start
    if ($prop->{'serialize'} eq 'flock') {
        open $prop->{'lock_fh'}, ">", $prop->{'lock_file'}
            or $self->fatal("Couldn't open lock file \"$prop->{'lock_file'}\"[$!]");
        # With flock() serialization, make things HUP safe
        pipe($prop->{'SigHUPReadPipe'}, $prop->{'SigHUPWritePipe'});
        $prop->{'select'}->add($prop->{'SigHUPReadPipe'});
        $SIG{'HUP'}  = sub { $prop->{'SigHUPed'} = 1; syswrite $prop->{'SigHUPWritePipe'}, "1" if !$prop->{SigHUPWriten}++; };
    }

    $self->log(4, "Child Preforked ($$)");

    delete @{ $prop }{qw(children tally last_start last_process)};

    $self->child_init_hook;
    my $write = $prop->{'_WRITE'};

    while ($self->accept()) {
        $prop->{'connected'} = 1;
        print $write "$$ processing\n";

        my $ok = eval { $self->run_client_connection; 1 };
        if (! $ok) {
            print $write "$$ exiting\n";
            die $@;
        }

        last if $self->done;

        $prop->{'connected'} = 0;
        print $write "$$ waiting\n";
    }

    $self->child_finish_hook;

    print $write "$$ exiting\n";
    exit;
}

=method I<accept()>

Patches to the Net::Server accept method

=cut

sub accept { ## no critic
    my $self = shift;

    my $config = $self->{config} || get_config();
    return $self->SUPER unless $config->{'patch_net_server'};

    my $prop = $self->{'server'};

    if ($prop->{'serialize'} eq 'flock') {
        while (! flock $prop->{'lock_fh'}, Fcntl::LOCK_EX()) {
            return undef if $prop->{'SigHUPed'}; ## no critic
            next if $! == EINTR;
            $self->fatal("Couldn't get lock on file \"$prop->{'lock_file'}\" [$!]");
        }
        my $v = $self->super_accept();
        flock $prop->{'lock_fh'}, Fcntl::LOCK_UN();
        return $v;
    } elsif ($prop->{'serialize'} eq 'semaphore') {
        $prop->{'sem'}->op(0, -1, IPC::SysV::SEM_UNDO()) or $self->fatal("Semaphore Error [$!]");
        my $v = $self->super_accept();
        $prop->{'sem'}->op(0, 1, IPC::SysV::SEM_UNDO()) or $self->fatal("Semaphore Error [$!]");
        return $v;
    } elsif ($prop->{'serialize'} eq 'pipe') {
        my $waiting = $prop->{'_WAITING'};
        scalar <$waiting>; # read one line - kernel says who gets it
        my $v = $self->super_accept();
        print { $prop->{'_READY'} } "Next!\n";
        return $v;
    } else {
        my $v = $self->super_accept();
        return $v;
    }
}

=method I<super_accept()>

Patches to the Net::Server accept method

=cut

sub super_accept {
    my $self = shift;
    my $prop = $self->{'server'};

    my $sock = undef;
    my $retries = 30;
    while ($retries--) {
        if ($prop->{'multi_port'}) { # with more than one port, use select to get the next one
            return 0 if $prop->{'_HUP'};
            ($sock, my $hup) = $self->accept_multi_port; # keep trying for the rest of retries
            return 0 if $hup || $prop->{'_HUP'};
            if ($self->can_read_hook($sock)) {
                $retries++;
                next;
            }
        } else {
            $sock = $prop->{'sock'}->[0]; # single port is bound - just accept
        }
        $self->fatal("Received a bad sock!") if ! defined $sock;

        if (SOCK_DGRAM == $sock->getsockopt(Socket::SOL_SOCKET(), Socket::SO_TYPE())) { # receive a udp packet
            $prop->{'client'}   = $sock;
            $prop->{'udp_true'} = 1;
            $prop->{'udp_peer'} = $sock->recv($prop->{'udp_data'}, $sock->NS_recv_len, $sock->NS_recv_flags);

        } else { # blocking accept per proto
            delete $prop->{'udp_true'};
            $prop->{'client'} = $sock->accept();
        }

        return 0 if $prop->{'_HUP'};
        return 1 if $prop->{'client'};

        $self->log(2,"Accept failed with $retries tries left: $!");
        sleep(1);
    }

    $self->log(1,"Ran out of accept retries!");
    return undef; ## no critic
}

=method I<accep_multi_portt()>

Patches to the Net::Server accept_multi_port method

=cut

sub accept_multi_port {
    my $self = shift;

    my $config = $self->{config} || get_config();
    return $self->SUPER unless $config->{'patch_net_server'};

    my $prop = $self->{'server'};
    while (1) {
      my @waiting = $prop->{'select'}->can_read();
      next if !@waiting && $! == EINTR;
      return (undef, 1) if grep { fileno($_) == fileno($prop->{'SigHUPReadPipe'}) } @waiting;
      return (undef, 0) if ! @waiting;
      return ($waiting[rand @waiting], 0);
    }
}

1;

