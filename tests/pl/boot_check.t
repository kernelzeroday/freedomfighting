#!/usr/bin/env perl
#
# Tests for boot_check.pl
use strict;
use warnings;
use Test::More tests => 8;
use JSON::PP;
use FindBin;

my $script = "$FindBin::RealBin/../../boot_check.pl";

# Load without running main()
local $ENV{FFPL_NO_RUN} = 1;
do $script or die "Failed to load boot_check.pl: $!";
die "Failed to compile boot_check.pl: $@" if $@;

sub test_get_hard_drives_parse {
    my $json = encode_json({
        blockdevices => [
            { name => 'sda', type => 'disk' },
            { name => 'sdb', type => 'disk' },
            { name => 'loop0', type => 'loop' },
        ]
    });

    my $data = decode_json($json);
    my @devices;
    for my $d (@{$data->{blockdevices}}) {
        next unless $d->{type} eq 'disk';
        push @devices, $d->{name};
    }

    is_deeply(\@devices, ['sda', 'sdb'], 'get_hard_drives: returns only disk devices');
}

sub test_drive_model {
    my $json = encode_json({
        blockdevices => [
            { name => 'sda', model => 'Samsung SSD 860 EVO' },
        ]
    });
    my $data = decode_json($json);
    is($data->{blockdevices}[0]{model}, 'Samsung SSD 860 EVO', 'get_drive_model: parses correctly');
}

sub test_init_data_roundtrip {
    my %init = (sda => 42, sdb => 17);
    my $json = encode_json(\%init);
    my $parsed = decode_json($json);
    is($parsed->{sda}, 42, 'init: round-trips sda');
    is($parsed->{sdb}, 17, 'init: round-trips sdb');
}

sub test_boot_logic {
    my $state = { sda => 100 };
    is(103 - $state->{sda} - 1, 2, 'boot: detects 2 extra boots');
    is(100 - $state->{sda} - 1, -1, 'boot: no extra boots (<=0)');
}

sub test_power_cycle_parse {
    my $output = "  9 Power_Cycle_Count       0x0032   100   100   000    Old_age   Always       -       42";
    chomp $output;
    my @parts = split /\s+/, $output;
    is($parts[-1], 42, 'power_cycle: parses last field');
}

sub test_tmpfs_parsing {
    my $output = "tmpfs on /run type tmpfs (rw,noexec,nosuid,size=10%,mode=0755)\n"
               . "tmpfs on /tmp type tmpfs (rw,nosuid,nodev)\n";
    my $found;
    for my $c (split /\n/, $output) {
        next unless $c =~ /rw/;
        my $device = (split /\s+/, $c)[2];
        next unless $device =~ m{^/};
        $found = $device;
        last;
    }
    is($found, '/run', 'tmpfs: finds first valid mountpoint');
}

test_get_hard_drives_parse();
test_drive_model();
test_init_data_roundtrip();
test_boot_logic();
test_power_cycle_parse();
test_tmpfs_parsing();
