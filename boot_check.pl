#!/usr/bin/env perl
#
# boot_check.pl - Detect evil maid attacks by monitoring hard drive power cycles.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

use strict;
use warnings;
use JSON::PP;
use File::Basename;

use constant BOOT_COUNT_FILE => '/root/.boot_check';

# ---------------------------------------------------------------------------
# Prerequisites check
# ---------------------------------------------------------------------------

sub check_prerequisites {
    if ($> != 0) {
        print STDERR "[!] Error: This script must be run as root!\n";
        exit 1;
    }

    for my $cmd (qw/smartctl lsblk dialog/) {
        system("command -v $cmd >/dev/null 2>&1");
        if ($? != 0) {
            print STDERR "[!] Error: $cmd is not installed on this machine!\n";
            exit 1;
        }
    }
}

# ---------------------------------------------------------------------------
# Hardware data gathering
# ---------------------------------------------------------------------------

sub get_hard_drives {
    my $output = `lsblk -d -J 2>/dev/null`;
    return () unless $output;
    my $data = eval { decode_json($output) };
    return () unless $data && ref $data eq 'HASH';

    my @devices;
    for my $d (@{$data->{blockdevices} || []}) {
        next unless $d->{type} eq 'disk';
        push @devices, $d->{name};
    }
    return @devices;
}

sub get_drive_model {
    my ($device) = @_;
    my $output = `lsblk -S -J 2>/dev/null`;
    return "/dev/$device" unless $output;
    my $data = eval { decode_json($output) };
    return "/dev/$device" unless $data && ref $data eq 'HASH';

    for my $d (@{$data->{blockdevices} || []}) {
        return $d->{model} if $d->{name} eq $device;
    }
    return "/dev/$device";
}

sub get_power_cycle_count {
    my ($device) = @_;
    my $output = `smartctl /dev/$device -a 2>/dev/null | grep -i 'Power_Cycle_Count'`;
    chomp $output;
    my @parts = split /\s+/, $output;
    return $parts[-1] || 0;
}

# ---------------------------------------------------------------------------
# Display functions
# ---------------------------------------------------------------------------

sub dialog {
    my ($text, $width) = @_;
    $width ||= 50;
    return unless $text;

    system("sleep 5 ; chvt 2");

    my $lines_needed = 5 + int(length($text) / ($width - 4));

    open my $oldrc, '<', '/dev/null' or die;
    local *STDIN = *$oldrc;

    my $pid = open(my $dialog_in, '|-');
    if (defined $pid) {
        print $dialog_in "screen_color = (CYAN,RED,ON)\n";
        close $dialog_in;
    }

    system("OLDDIALOGRC=\$DIALOGRC; " .
           "export DIALOGRC=/dev/stdin; " .
           "dialog --clear --msgbox \"$text\" $lines_needed 50; " .
           "export DIALOGRC=\$OLDDIALOGRC");

    print "[\033[0;31m!\033[0m] Press [\033[0;31mCTRL+ALT+F7\033[0m] to go back to the desktop.\n";
    system("chvt 7");
}

# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------

sub initialize {
    my $status = system("systemctl --quiet is-enabled boot_check.service");
    if ($status != 0) {
        print "[\033[0;31m!\033[0m] \033[0;31mError: Boot Check is not enabled in systemd!\033[0m\n";
        return;
    }

    my %init_data;
    for my $device (get_hard_drives()) {
        $init_data{$device} = get_power_cycle_count($device);
    }

    open my $fh, '>', BOOT_COUNT_FILE or die "Cannot write " . BOOT_COUNT_FILE . ": $!";
    print $fh encode_json(\%init_data);
    close $fh;
    chmod 0600, BOOT_COUNT_FILE;
    print "[\033[0;32m*\033[0m] \033[0;32mBoot Check initialized successfully.\033[0m\n";
}

# ---------------------------------------------------------------------------
# Program logic
# ---------------------------------------------------------------------------

sub check_boot_count {
    open my $fh, '<', BOOT_COUNT_FILE or die "Cannot read " . BOOT_COUNT_FILE . ": $!";
    local $/;
    my $json = <$fh>;
    close $fh;
    my $state = decode_json($json);

    for my $device (get_hard_drives()) {
        unless (exists $state->{$device}) {
            dialog("Error: no existing data for $device. Please remove " .
                   BOOT_COUNT_FILE . " and initialize this script again.");
            next;
        }

        my $count = get_power_cycle_count($device);
        my $number_of_boots = $count - $state->{$device} - 1;

        if ($number_of_boots <= 0) {
            $state->{$device} = $count;
        } else {
            my $model = get_drive_model($device);
            my $s = $number_of_boots > 1 ? "s" : "";
            dialog("Warning: $model was started ${number_of_boots} time${s} since the last check!");
            $state->{$device} = $count;
        }
    }

    open $fh, '>', BOOT_COUNT_FILE or die "Cannot write " . BOOT_COUNT_FILE . ": $!";
    print $fh encode_json($state);
    close $fh;
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

sub main {
    check_prerequisites();

    if (!-e BOOT_COUNT_FILE) {
        initialize();
    } else {
        check_boot_count();
    }
}

main() unless $ENV{FFPL_NO_RUN} || caller;
1;
