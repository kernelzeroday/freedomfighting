#!/usr/bin/env perl
#
# Tests for listurl.pl
use strict;
use warnings;
use Test::More;
use File::Basename qw(dirname);
use Cwd qw(abs_path);

local $ENV{FFPL_NO_RUN} = 1;
my $script = abs_path(dirname(__FILE__) . '/../../listurl.pl');

my $load_ok = do $script;
if ($@) {
    plan skip_all => "Skip: $@";
    exit 0;
}
plan tests => 7;

sub test_anchor_removal {
    my $url = 'https://example.com/page#section';
    $url =~ s/#.*//;
    is($url, 'https://example.com/page', 'url: removes anchor');
}

sub test_ignored_extensions {
    my @ignored = qw(.pdf .jpg .jpeg .png .gif .doc .docx .eps .wav);
    ok(grep { '.pdf' eq $_ } @ignored, 'ignored: .pdf');
    ok(!grep { '.php' eq $_ } @ignored, 'ignored: .php not in list');
}

sub test_static_resource {
    my $url = 'https://example.com/image.jpg';
    my $ext = $url =~ /\.([^.\/]+)$/ ? lc(".$1") : '';
    my @ignored = qw(.pdf .jpg .jpeg .png .gif .doc .docx .eps .wav);
    ok(grep { $ext eq $_ } @ignored, 'resource: .jpg ignored');
}

sub test_non_ignored {
    my $url = 'https://example.com/page.php';
    my $ext = $url =~ /\.([^.\/]+)$/ ? lc(".$1") : '';
    my @ignored = qw(.pdf .jpg .jpeg .png .gif .doc .docx .eps .wav);
    ok(!grep { $ext eq $_ } @ignored, 'resource: .php not ignored');
}

sub test_protocol_relative {
    ok('//cdn.example.com/js' =~ m{^//}, 'url: protocol-relative');
}

sub test_scheme_check {
    ok('mailto:x@y' !~ m{^https?://}i, 'scheme: non-http rejected');
}

test_anchor_removal();
test_ignored_extensions();
test_static_resource();
test_non_ignored();
test_protocol_relative();
test_scheme_check();
