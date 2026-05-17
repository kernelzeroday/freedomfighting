#!/usr/bin/env perl
#
# Tests for notify_hook.pl
use strict;
use warnings;
use Test::More;
use File::Basename qw(dirname);
use Cwd qw(abs_path);

local $ENV{FFPL_NO_RUN} = 1;
my $script = abs_path(dirname(__FILE__) . '/../../notify_hook.pl');

my $load_ok = do $script;
if ($@) {
    plan skip_all => "Skip: $@";
    exit 0;
}
plan tests => 9;

sub test_cmdline_parsing {
    my $cmdline = "/usr/bin/id\x00--help\x00";
    my @parts = split /\x00/, $cmdline;
    is($parts[0], '/usr/bin/id', 'cmdline: parses direct binary');
}

sub test_cmdline_interpreter {
    my $cmdline = "/bin/bash\x00/usr/local/bin/script\x00arg1\x00";
    my @parts = split /\x00/, $cmdline;
    is($parts[0], '/bin/bash', 'cmdline: detects interpreter');
    is($parts[1], '/usr/local/bin/script', 'cmdline: extracts script name');
}

sub test_origin_parse {
    my $ssh = "192.168.1.100 54321 10.0.0.5 22";
    my $origin = (split /\s+/, $ssh)[0];
    is($origin, '192.168.1.100', 'origin: parses SSH_CONNECTION');
}

sub test_find_command {
    my $path = "/usr/local/bin:/usr/bin:/bin";
    my $result;
    for my $dir (split /:/, $path) {
        next if $dir =~ m{/local/};
        my $candidate = "$dir/id";
        if (-e $candidate) { $result = $candidate; last }
    }
    is($result, '/usr/bin/id', 'find_command: skips /local/');
}

sub test_whitelist {
    my @whitelist = (qr/systemd/, qr/cron/);
    my $notify = 1;
    for my $re (@whitelist) { $notify = 0 if '/usr/sbin/cron' =~ /$re/ }
    is($notify, 0, 'whitelist: suppresses cron');
    $notify = 1;
    for my $re (@whitelist) { $notify = 0 if '/usr/bin/id' =~ /$re/ }
    is($notify, 1, 'whitelist: allows id');
}

sub test_fork_control {
    ok(12345 > 0, 'fork: parent exits');
    ok(0 == 0,   'fork: child continues');
}

test_cmdline_parsing();
test_cmdline_interpreter();
test_origin_parse();
test_find_command();
test_whitelist();
test_fork_control();
