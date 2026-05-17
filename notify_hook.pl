#!/usr/bin/env perl
#
# notify_hook.pl - Booby-trap executables to alert on unauthorized use.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

use strict;
use warnings;

# A list of patterns (regex) for callers that should NOT trigger alerts.
my @CALLER_WHITELIST;

my @INTERPRETERS = qw(/bin/bash /usr/bin/perl);

###############################################################################
# EDIT THE SUB BELOW TO CHANGE THE NOTIFICATION METHOD
###############################################################################
sub notify_callback {
    my ($msg_text) = @_;
    # signal-cli is available at https://github.com/AsamK/signal-cli
    # Set it up first if you want to use this!
    system("signal-cli", "--config", "/opt/signal-cli-0.6.0/.config", "-u",
           "+33XXXXXXXXX", "send", "+33XXXXXXXXX", "-m", $msg_text);
}
###############################################################################

# ---------------------------------------------------------------------------

sub get_caller {
    my $pid = getppid();
    open my $fh, '<', "/proc/$pid/cmdline" or return undef;
    local $/ = "\x00";
    my @cmdline = <$fh>;
    close $fh;
    return undef unless @cmdline;

    # First element is the interpreter or binary
    my $interp = $cmdline[0];
    $interp =~ s/\x00$//;

    # If the caller is an interpreter, find the script name
    if (grep { $interp eq $_ } @INTERPRETERS) {
        for my $arg (@cmdline[1..$#cmdline]) {
            $arg =~ s/\x00$//;
            return $arg if -e $arg;
        }
    }
    return $interp;
}

sub get_origin {
    return $ENV{SSH_CONNECTION} ? (split /\s+/, $ENV{SSH_CONNECTION})[0] : undef;
}

sub get_hostname {
    open my $fh, '<', '/etc/hostname' or return undef;
    chomp(my $host = <$fh>);
    close $fh;
    return $host;
}

sub find_original_command {
    my ($command) = @_;
    for my $dir (split /:/, $ENV{PATH}) {
        next if $dir =~ m{/local/};
        my $path = "$dir/$command";
        return $path if -e $path;
    }
    print STDERR "-bash: $command: command not found\n";
    return undef;
}

sub daemonize_and_notify {
    my ($message) = @_;

    # First fork
    my $pid = fork();
    return if $pid > 0;        # Parent returns
    die "Cannot fork: $!" unless defined $pid;

    chdir '/';
    setsid();
    umask(0);

    # Second fork
    $pid = fork();
    exit(0) if $pid > 0;       # First child exits
    exit(1) unless defined $pid;

    # Second child sends notification
    notify_callback($message);
    exit(0);
}

# ---------------------------------------------------------------------------

sub main {
    my $caller = get_caller();
    my $notify = 1;

    if ($caller) {
        for my $re (@CALLER_WHITELIST) {
            if ($caller =~ /$re/) {
                $notify = 0;
                last;
            }
        }
    }

    my $program  = (split /\//, $0)[-1];

    if ($notify) {
        my $hostname = get_hostname();
        my $origin   = get_origin();
        my $message  = "Warning: $program command invoked";

        $message .= " on $hostname"              if $hostname;
        $message .= " by $ENV{USER}";
        $message .= " from $origin"              if $origin;
        $message .= " ($caller)"                 if $caller;

        daemonize_and_notify($message);
    }

    my $command = find_original_command($program);
    return unless $command && -e $command;

    my @args = ($command);
    push @args, @ARGV if @ARGV;
    system(@args);
}

main() unless $ENV{FFPL_NO_RUN} || caller;
1;
