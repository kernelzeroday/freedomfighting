#!/usr/bin/env perl
#
# listurl.pl - Multi-threaded web crawler to map a site's URLs.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

use strict;
use warnings;

# CPAN dependencies
use LWP::UserAgent;
use HTML::TreeBuilder;
use HTTP::Cookies;
use URI;
use threads;
use Thread::Queue;
use Getopt::Long qw(:config bundling);
use POSIX qw(strftime);

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

my $MAX_DEPTH     = 3;
my $THREADS       = 10;
my $URL           = undef;
my $EXTERNAL      = 0;
my $SUBDOMAINS    = 0;
my @COOKIES;
my $EXCLUDE_REGEXP = undef;
my $SHOW_REGEXP    = undef;
my $NO_CERT_CHECK  = 0;
my $OUTPUT_FILE    = undef;
my $VERBOSE        = 0;

my @IGNORED_EXTENSIONS = qw(.pdf .jpg .jpeg .png .gif .doc .docx .eps .wav);
my $USER_AGENT_STR = 'Mozilla/5.0 (Windows NT 5.1; rv:5.0.1) Gecko/20100101 Firefox/5.0.1';

my $PRINT_QUEUE;

# ---------------------------------------------------------------------------
# Pretty printing
# ---------------------------------------------------------------------------

sub red     { "\033[92m$_[0]\033[0m" }
sub orange  { "\033[93m$_[0]\033[0m" }
sub green   { "\033[92m$_[0]\033[0m" }
sub error   { "[" . red("!") . "] " . red("Error: $_[0]") }
sub warning { "[" . orange("*") . "] Warning: $_[0]" }
sub success { "[" . green("*") . "] " . green($_[0]) }
sub info    { "[ ] $_[0]" }

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

package InputParameter;
sub new {
    my ($class, $name, $value, $param_type) = @_;
    bless { name => $name, value => $value, type => uc($param_type) }, $class;
}
sub str {
    my $self = shift;
    return "$self->{name} ($self->{type})";
}
sub equals {
    my ($self, $other) = @_;
    return ref $other && $self->{name} eq $other->{name};
}

package GrabbedURL;
sub new {
    my ($class, $url, $method) = @_;
    $method ||= 'GET';
    die "ValueError" unless defined $url;
    bless { url => $url, method => uc($method), parameters => undef }, $class;
}
sub str {
    my $self = shift;
    my $m = $self->{method};
    my $pad = $m eq 'GET' ? ' ' : '';
    if ($self->{parameters}) {
        my @params = map { $_->str() } @{$self->{parameters}};
        return "[$m] ${pad}$self->{url} - params = " . join(', ', @params);
    }
    return "[$m] ${pad}$self->{url}";
}
sub equals {
    my ($self, $other) = @_;
    return ref $other && $self->{url} eq $other->{url} && $self->{method} eq $other->{method};
}
sub hash {
    my $self = shift;
    return $self->str();
}

package main;

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

sub parse_arguments {
    Getopt::Long::Configure('bundling');
    my $help = 0;
    GetOptions(
        'max-depth|m=i'     => \$MAX_DEPTH,
        'threads|t=i'       => \$THREADS,
        'url|u=s'           => \$URL,
        'external|e'        => \$EXTERNAL,
        'subdomains|d'      => \$SUBDOMAINS,
        'cookie|c=s'        => \@COOKIES,
        'exclude-regexp|r=s' => \$EXCLUDE_REGEXP,
        'show-regexp|s=s'   => \$SHOW_REGEXP,
        'no-certificate-check|n' => \$NO_CERT_CHECK,
        'output-file|o=s'   => \$OUTPUT_FILE,
        'verbose|v+'        => \$VERBOSE,
        'help|h'            => \$help,
    ) or exit 1;

    if ($help || !$URL) {
        print "Usage: $0 --url URL [options]\n";
        print "  --max-depth|-m INT    Maximum crawl depth (default 3)\n";
        print "  --threads|-t INT      Number of threads (default 10)\n";
        print "  --url|-u URL          Starting URL (required)\n";
        print "  --external|-e         Follow external links\n";
        print "  --subdomains|-d       Include subdomains\n";
        print "  --cookie|-c KEY=VAL   Add a cookie (may repeat)\n";
        print "  --exclude-regexp|-r   Regex to exclude URLs\n";
        print "  --show-regexp|-s      Regex to filter display\n";
        print "  --no-certificate-check|-n  Skip SSL verification\n";
        print "  --output-file|-o FILE Write results to file\n";
        print "  --verbose|-v          Increase verbosity\n";
        exit 1 unless $URL;
    }

    if ($OUTPUT_FILE && -e $OUTPUT_FILE) {
        print error("$OUTPUT_FILE already exists! Aborting.\n");
        exit 1;
    }
}

# ---------------------------------------------------------------------------
# URL processing
# ---------------------------------------------------------------------------

sub create_agent {
    my $ua = LWP::UserAgent->new(
        agent      => $USER_AGENT_STR,
        ssl_opts   => { verify_hostname => !$NO_CERT_CHECK },
        cookie_jar => HTTP::Cookies->new(),
    );
    for my $c (@COOKIES) {
        if ((my $count = ($c =~ tr/=//)) != 1) {
            print error("Input cookie should be in the form key=value (received: $c)!\n");
            exit 1;
        }
        my ($key, $val) = split /=/, $c, 2;
        # HTTP::Cookies will set these on actual requests via the jar
    }
    return $ua;
}

sub process_url {
    my ($url, $parent_url) = @_;
    my $parent_uri = URI->new($parent_url);

    # Normalize relative URLs
    unless ($url =~ m{^https?://}i || $url =~ m{^//}) {
        $url = $parent_uri->scheme . '://' . $parent_uri->host . $url;
        $url = URI->new_abs($url, $parent_url)->as_string;
    }

    my $uri = URI->new($url);

    # External / subdomain check
    my $parent_host = $parent_uri->host;
    my $uri_host    = $uri->host;
    unless ($EXTERNAL || $uri_host eq $parent_host ||
            ($SUBDOMAINS && $uri_host =~ /\Q$parent_host\E$/)) {
        $PRINT_QUEUE->enqueue(info("Ignoring a link to external URL $uri_host.\n")) if $VERBOSE > 1;
        return undef;
    }

    return undef unless $uri->scheme =~ /^https?$/;

    # Remove fragment
    $url =~ s/#.*//;

    # Check ignored extensions
    if ($url =~ /\.([^.\/]+)$/) {
        my $ext = lc(".$1");
        if (grep { $ext eq $_ } @IGNORED_EXTENSIONS) {
            $PRINT_QUEUE->enqueue(info("Ignoring $url.\n")) if $VERBOSE > 1;
            return undef;
        }
    }

    # Check exclude regex
    if ($EXCLUDE_REGEXP && $url =~ /$EXCLUDE_REGEXP/) {
        $PRINT_QUEUE->enqueue(info("Ignoring $url due to the regular expression.\n")) if $VERBOSE > 1;
        return undef;
    }

    return $url;
}

sub extract_urls {
    my ($page_data, $page_url) = @_;
    my @urls;

    my $tree = HTML::TreeBuilder->new;
    $tree->parse($page_data);
    $tree->eof();

    # <a href> links
    for my $link ($tree->find('a')) {
        my $href = $link->attr('href');
        next unless defined $href;
        my $processed = process_url($href, $page_url);
        next unless defined $processed;
        push @urls, GrabbedURL->new($processed);
    }

    # <form action> links
    for my $form ($tree->find('form')) {
        my $action = $form->attr('action');
        next unless defined $action;
        my $processed = process_url($action, $page_url);
        next unless defined $processed;

        my $method = uc($form->attr('method') || 'GET');
        my $gu = GrabbedURL->new($processed, $method);

        my @params;
        for my $inp ($form->find('input')) {
            my $name = $inp->attr('name');
            next unless defined $name;
            my $type = $inp->attr('type') || 'text';
            my $value = $inp->attr('value') || '';
            push @params, InputParameter->new($name, $value, $type);
        }
        $gu->{parameters} = \@params if @params;
        push @urls, $gu;
    }

    $tree->delete();
    return @urls;
}

# ---------------------------------------------------------------------------
# Requester thread
# ---------------------------------------------------------------------------

sub requester_thread {
    my ($input_queue, $output_queue) = @_;
    my $ua = create_agent();

    while (1) {
        my $url_item = $input_queue->dequeue_nb();
        last unless defined $url_item;

        $PRINT_QUEUE->enqueue(info("Requesting $url_item->{url}\n")) if $VERBOSE > 0;

        my $response;
        if ($url_item->{method} eq 'GET') {
            $response = $ua->get($url_item->{url});
        } else {
            $response = $ua->post($url_item->{url});
        }

        unless ($response->is_success) {
            $PRINT_QUEUE->enqueue(error("Could not obtain " . $url_item->str() .
                                        " (HTTP error code: " . $response->code . ")\n"));
            next;
        }

        my @urls = extract_urls($response->decoded_content, $url_item->{url});
        for my $u (@urls) {
            $output_queue->enqueue($u);
        }
    }
}

# ---------------------------------------------------------------------------
# Printer thread
# ---------------------------------------------------------------------------

sub printer_thread {
    my $pq = shift;
    while (1) {
        my $msg = $pq->dequeue();
        last unless defined $msg;
        print $msg;
    }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

sub main {
    parse_arguments();

    # Cannot use threads in a reasonable way for this without making
    # the script structure much more complex. Instead, we use a
    # single-threaded worker approach with forked processes or
    # just use a non-threaded iterative approach.
    #
    # For simplicity and portability, we implement a threaded
    # crawler. If threads are not available, fall back to single-thread mode.

    my $input_queue  = Thread::Queue->new();
    my $output_queue = Thread::Queue->new();
    $PRINT_QUEUE     = Thread::Queue->new();

    # Start printer thread
    threads->create('printer_thread', $PRINT_QUEUE)->detach();

    # Seed with initial URL
    $input_queue->enqueue(GrabbedURL->new($URL));
    my %found_urls;
    $found_urls{GrabbedURL->new($URL)->hash()} = GrabbedURL->new($URL);

    # Initial synchronous request to get first batch
    {
        my $ua = create_agent();
        my $response = $ua->get($URL);
        if ($response->is_success) {
            my @urls = extract_urls($response->decoded_content, $URL);
            for my $u (@urls) {
                $output_queue->enqueue($u);
            }
        }
    }

    for my $depth (1 .. $MAX_DEPTH) {
        $PRINT_QUEUE->enqueue(success("Started crawling at depth $depth.\n"));

        # Collect URLs from output queue
        my %round_urls;
        while (defined(my $u = $output_queue->dequeue_nb())) {
            $round_urls{$u->hash()} = $u;
        }

        # Add new URLs to input queue
        for my $key (keys %round_urls) {
            unless (exists $found_urls{$key}) {
                $input_queue->enqueue($round_urls{$key});
            }
        }
        while (my ($k, $v) = each %round_urls) { $found_urls{$k} = $v; }

        # Spawn worker threads for this round
        my @threads;
        for (1 .. $THREADS) {
            push @threads, threads->create('requester_thread', $input_queue, $output_queue);
        }
        $_->join() for @threads;
    }

    # Print results
    my @sorted = sort { $a->{url} cmp $b->{url} } values %found_urls;

    if (scalar(keys %found_urls) <= 1) {
        $PRINT_QUEUE->enqueue(error("No URLs were found.\n"));
    } elsif (!$OUTPUT_FILE) {
        $PRINT_QUEUE->enqueue(success("URLs discovered:\n"));
        for my $u (@sorted) {
            next if $SHOW_REGEXP && $u->{url} !~ /$SHOW_REGEXP/;
            $PRINT_QUEUE->enqueue($u->str() . "\n");
        }
    } else {
        open my $fh, '>', $OUTPUT_FILE or die "Cannot write $OUTPUT_FILE: $!";
        for my $u (@sorted) {
            next if $SHOW_REGEXP && $u->{url} !~ /$SHOW_REGEXP/;
            print $fh $u->str() . "\n";
        }
        close $fh;
        $PRINT_QUEUE->enqueue(success("Discovered URLs were written to $OUTPUT_FILE.\n"));
    }

    # Signal printer thread to stop
    $PRINT_QUEUE->enqueue(undef);
}

main() unless $ENV{FFPL_NO_RUN} || caller;
1;
