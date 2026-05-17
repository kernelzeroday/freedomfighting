#!/usr/bin/env perl
#
# Tests for nojail.pl
use strict;
use warnings;
use Test::More;
use File::Basename qw(dirname);
use Cwd qw(abs_path);

local $ENV{FFPL_NO_RUN} = 1;
my $script = abs_path(dirname(__FILE__) . '/../../nojail.pl');

my $load_ok = do $script;
if ($@) {
    plan skip_all => "Skip: $@";
    exit 0;
}
plan tests => 11;

sub test_random_string {
    my @chars = ('a'..'z', '0'..'9');
    my $s1 = join '', map { $chars[rand @chars] } 1 .. 10;
    my $s2 = join '', map { $chars[rand @chars] } 1 .. 10;
    is(length $s1, 10, 'random: correct length');
    isnt($s1, $s2, 'random: different strings');
}

sub test_utmp_pack_unpack {
    my $data = pack 's x2 i Z32 Z4 Z32 Z256 s2 i3 x36',
        7, 12345, 'pts/0', 'ts/0', 'root', '192.168.1.1', (0) x 2, (0, 1500000000, 0);
    is(length $data, 384, 'utmp: 384 bytes');
    my ($type, $pid, $line, $id, $user, $host) =
        unpack 's x2 i Z32 Z4 Z32 Z256', $data;
    is($type, 7, 'utmp: type correct');
    is($user, 'root', 'utmp: user correct');
    is($host, '192.168.1.1', 'utmp: host correct');
}

sub test_lastlog_pack_unpack {
    my $data = pack 'i Z32 Z256', 1500000000, 'pts/0', '10.0.0.1';
    is(length $data, 292, 'lastlog: 292 bytes');
    my ($time, $line, $host) = unpack 'i Z32 Z256', $data;
    is($time, 1500000000, 'lastlog: timestamp');
    is($host, '10.0.0.1', 'lastlog: host');
}

sub test_log_detection {
    my $line  = "Jan 1 12:00:00 sshd[1234]: Failed password from 192.168.1.1";
    my $clean = "Jan 1 12:00:00 sshd[1234]: Failed password from 10.0.0.1";
    ok($line  =~ /\Q192.168.1.1\E/, 'log: detects IP');
    ok($clean !~ /\Q192.168.1.1\E/, 'log: clean line passes');
}

test_random_string();
test_utmp_pack_unpack();
test_lastlog_pack_unpack();
test_log_detection();
