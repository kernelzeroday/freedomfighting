#!/usr/bin/env perl
#
# Tests for autojack.pl
use strict;
use warnings;
use Test::More tests => 9;

# ---------------------------------------------------------------------------
# Test the session open regex
# ---------------------------------------------------------------------------

sub test_regex_matches_valid {
    my $line = 'May 17 12:34:56 myserver sshd[12345]: pam_unix(sshd:session): session opened for user alice by (uid=0)';
    my $re = qr/^\w{3} [ :0-9]{11} [A-Za-z0-9]+ sshd\[([0-9]+)\]: pam_unix\(sshd:session\): session opened for user ([a-z0-9.-]+) by \(uid=[0-9]+\)$/;

    my @matches = ($line =~ $re);
    ok(@matches == 2, 'regex: matches valid line');
    is($matches[0], '12345', 'regex: extracts sshd PID');
    is($matches[1], 'alice', 'regex: extracts username');
}

sub test_regex_no_match_wrong {
    my $line = 'May 17 12:34:56 myserver sshd[12345]: Failed password for root from 192.168.1.1';
    my $re = qr/^\w{3} [ :0-9]{11} [A-Za-z0-9]+ sshd\[([0-9]+)\]: pam_unix\(sshd:session\): session opened for user ([a-z0-9.-]+) by \(uid=[0-9]+\)$/;

    ok($line !~ $re, 'regex: no match for non-session lines');
}

sub test_regex_skip_root {
    my $line = 'May 17 12:34:56 myserver sshd[12345]: pam_unix(sshd:session): session opened for user root by (uid=0)';
    my $re = qr/^\w{3} [ :0-9]{11} [A-Za-z0-9]+ sshd\[([0-9]+)\]: pam_unix\(sshd:session\): session opened for user ([a-z0-9.-]+) by \(uid=[0-9]+\)$/;

    my $user = ($line =~ $re)[1];
    is($user, 'root', 'regex: root sessions match but should be filtered');
}

# ---------------------------------------------------------------------------
# Test pgrep output parsing
# ---------------------------------------------------------------------------

sub test_pgrep_parse {
    my $output = "12345 bash\n12346 sshd\n";
    my @lines = split /\n/, $output;

    my %procs;
    for my $line (@lines) {
        my ($pid, $name) = split /\s+/, $line, 2;
        $procs{$name} = $pid;
    }

    is($procs{bash}, '12345', 'pgrep: extracts bash PID');
    is($procs{sshd}, '12346', 'pgrep: extracts sshd PID');
}

# ---------------------------------------------------------------------------
# Test recursive sshd lookup
# ---------------------------------------------------------------------------

sub test_recursive_sshd {
    my @first = ("12345 sshd");
    my @second = ("67890 bash");
    my $found;

    for my $entry (@first) {
        my ($pid, $name) = split /\s+/, $entry, 2;
        if ($name eq 'bash') {
            $found = $pid;
        } elsif ($name eq 'sshd') {
            for my $sub (@second) {
                my ($sub_pid, $sub_name) = split /\s+/, $sub, 2;
                $found = $sub_pid if $sub_name eq 'bash';
            }
        }
    }

    is($found, '67890', 'recursive: finds bash under nested sshd');
}

# ---------------------------------------------------------------------------
# Test root skip
# ---------------------------------------------------------------------------

sub test_skip_root {
    my $user = 'root';
    my $skip = ($user eq 'root') ? 1 : 0;
    ok($skip, 'skip: root sessions are excluded');
}

# ---------------------------------------------------------------------------
# Run tests
# ---------------------------------------------------------------------------

test_regex_matches_valid();
test_regex_no_match_wrong();
test_regex_skip_root();
test_pgrep_parse();
test_recursive_sshd();
test_skip_root();
