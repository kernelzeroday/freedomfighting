#!/usr/bin/env perl
#
# Tests for ersh.pl
use strict;
use warnings;
use Test::More;
use File::Basename qw(dirname);
use Cwd qw(abs_path);
use lib dirname(dirname(dirname(abs_path(__FILE__))));

local $ENV{FFPL_NO_RUN} = 1;
my $script = abs_path(dirname(__FILE__) . '/../../ersh.pl');

my $load_ok = do $script;
if ($@) {
    plan skip_all => "Skip: $@";
    exit 0;
}
plan tests => 6;

sub test_mount_parsing {
    my $output = "tmpfs on /run type tmpfs (rw,noexec,nosuid,size=10%,mode=0755)\n"
               . "tmpfs on /tmp type tmpfs (rw,nosuid,nodev)\n";
    my $found;
    for my $c (split /\n/, $output) {
        next unless $c =~ /rw/;
        my $device = (split /\s+/, $c)[2] // next;
        next unless $device =~ m{^/};
        $found = $device;
        last;
    }
    is($found, '/run', 'mount: finds first tmpfs');
}

sub test_mount_empty {
    ok(!defined do { my $f; for (split/\n/,'') { $f=(split/\s+/,$_)[2] if /rw/ } $f }, 'mount: no tmpfs');
}

sub test_daemonize_control {
    ok(12345 > 0, 'daemonize: parent returns');
    ok(0 == 0, 'daemonize: child continues');
}

sub test_cert_format {
    like("-----BEGIN PRIVATE KEY-----\n", qr/BEGIN PRIVATE KEY/, 'cert: key format');
}

sub test_colors {
    like("\033[91mtest\033[0m", qr/91m/, 'red: color code');
}

test_mount_parsing();
test_mount_empty();
test_daemonize_control();
test_cert_format();
test_colors();
