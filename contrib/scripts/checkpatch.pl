#!/usr/bin/perl -n

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Copyright 2018 Red Hat, Inc.

# $ perldoc checkpatch.pl for eye-pleasing view of the manual:

=head1 NAME

checkpatch.pl - check for common mistakes

=head1 SYNOPSIS

checkpatch.pl [<file> ...]

=head1 DESCRIPTION

B<checkpatch.pl> checks source files or patches for common mistakes.

=head1 OPTIONS

=over 4

=item B<< <file> >>

A C source file or an unified diff.

=back

=cut

use strict;
use warnings;

chomp;

our $is_patch;
our $is_file;
our $is_commit_message;

our $seen_error;
our $line;		# Current line
our $check_line;	# Complain if errors are found on this line

our @functions_seen;
our $type;
our $filename;
our $line_no;
our $indent;
our $check_is_todo;

sub new_hunk
{
	$type = undef;
	$indent = undef;
}

sub new_file
{
	$check_is_todo = 1;
	$filename = shift;
	@functions_seen = ();
}

my $header = $ENV{'NM_CHECKPATCH_HEADER'};

sub complain
{
	my $message = shift;
	my $plain_message = shift;

	return unless $check_line;

	if (defined($header)) {
		warn "$header\n";
		undef $header;
	}

	if ($plain_message) {
		warn "$message\n";
	} else {
		warn "$filename:$line_no: $message:\n";
		warn "> $line\n\n";
	}
	$seen_error = 1;
}

sub check_commit
{
	my $commit = shift;
	my $required = shift;
	my $commit_id;
	my $commit_message;

	if ($commit =~ /^([0-9a-f]{5,})\b/) {
		$commit_id = $1;
	} else {
		return unless $required;
	}

	if ($commit_id and not system 'git rev-parse --git-dir >/dev/null 2>/dev/null') {
		$commit_message = `git log --abbrev=12 --pretty=format:"%h ('%s')" -1 "$commit_id" 2>/dev/null`;
		complain "Commit '$commit_id' does not seem to exist" unless $commit_message;
	}

	$commit_message //= "<12 hex digits> ('<commit subject>')";
	complain "Refer to the commit id properly: $commit_message" unless $commit =~ /^[0-9a-f]{12} \('/;
}

if ($is_patch) {
	# This is a line of an unified diff
	if (/^@@.*\+(\d+)/) {
		$line_no = $1 - 1;
		new_hunk;
		next;
	}
	if (/^\+\+\+ (b\/)?(.*)/) {
		new_file ($2);
		next;
	}
	s/^([ \+])(.*)/$2/ or next;
	$line_no++;
	$check_line = $1 eq '+';
	$line = $2;
} elsif ($is_file) {
	$line_no = $.;
	$. = 0 if eof;
	# This is a line from full C file
	$check_line = 1;
	$line = $_;
} elsif ($is_commit_message) {
	$line_no++;
	$filename = '(commit message)';
	$check_line = 1;
	$line = $_;
	/^---$/ and $is_commit_message = 0;
	/^Fixes: *(.*)/ and check_commit ($1, 1);
	/This reverts commit/ and next;
	/cherry picked from/ and next;
	/\bcommit (.*)/ and check_commit ($1, 0);
	next;
} else {
	# We don't handle these yet
	/^diff --cc/ and exit 0;
	$filename = '';
	$line_no = 1;
	# We don't know if we're dealing with a patch or a C file yet
	$is_commit_message = 1 if /^From \S/;
	$is_file = 1 if /^#/;
	$is_patch = 1 if /^---/;
	next;
}

if ($is_file and $filename ne $ARGV) {
	new_file ($ARGV);
	new_hunk;
}

if ($filename !~ /\.[ch]$/) {
	if ($check_is_todo) {
		complain("Resolve todo list \"$filename\" first\n", 1) if $filename =~ /^TODO.txt$/;
		$check_is_todo = 0;
	}
	next;
}

next if $filename =~ /\/nm-[^\/]+-enum-types\.[ch]$/;
next if $filename =~ /\bsrc\/systemd\//
	and not $filename =~ /\/sd-adapt\//
	and not $filename =~ /\/nm-/;
next if $filename =~ /\/(n-acd|c-list|c-siphash|n-dhcp4)\//;

complain ('Tabs are only allowed at the beginning of a line') if $line =~ /[^\t]\t/;
complain ('Trailing whitespace') if $line =~ /[ \t]$/;
complain ('Don\'t use glib typedefs for char/short/int/long/float/double') if $line =~ /\bg(char|short|int|long|float|double)\b/;
complain ("Don't use \"$1 $2\" instead of \"$2 $1\"") if $line =~ /\b(char|short|int|long) +(unsigned|signed)\b/;
complain ("Don't use \"unsigned int\" but just use \"unsigned\"") if $line =~ /\b(unsigned) +(int)\b/;
complain ("Please use LGPL2+ for new files") if $is_patch and $line =~ /under the terms of the GNU General Public License/;
complain ("Don't use space inside elvis operator ?:") if $line =~ /\?[\t ]+:/;
complain ("Don't add Emacs editor formatting hints to source files") if $line_no == 1 and $line =~ /-\*-.+-\*-/;
complain ("XXX marker are reserved for development while work-in-progress. Use TODO or FIXME comment instead?") if $line =~ /\bXXX\b/;
complain ("This gtk-doc annotation looks wrong") if $line =~ /\*.*\( *(transfer-(none|container|full)|allow none) *\) *(:|\()/;
complain ("Prefer nm_assert() or g_return*() to g_assert*()") if $line =~ /g_assert/ and not $filename =~ /\/tests\//;

new_hunk if $_ eq '';
my ($this_indent) = /^(\s*)/;
if (defined $indent) {
	my $this_tabs_before_spaces = length $1 if $this_indent =~ /^(\t*) +/;
	my $tabs_before_spaces = length $1 if $indent =~ /^(\t*) +/;

	complain ("Bad indentation")
		if $this_indent =~ /^$indent\t+ +/
		or (defined $tabs_before_spaces and defined $this_tabs_before_spaces
			and $this_tabs_before_spaces != $tabs_before_spaces);
}
$indent = $this_indent if $_ ne '';

# Further on we process stuff without comments.
$_ = $line;
s/\s*\/\*.*\*\///;
s/\s*\/\*.*//;
s/\s*\/\/.*//;
/^\s* \* / and next;

if (/^typedef*/) {
	# We expect the { on the same line as the typedef. Otherwise it
	# looks too much like a function declaration
	complain ('Unexpected line break following a typedef') unless /[;{,]$/;
	next;
} elsif (/^[A-Za-z_][A-Za-z0-9_ ]*\*?$/ and /[a-z]/) {
	# A function type
	$type = $_;
	next;
} elsif ($type and /^([A-Za-z_][A-Za-z0-9_]*)(\s*)\(/) {
	my @order = qw/^get_property$ ^set_property$ (?<!_iface|_class)_init$ ^constructor$
		^constructed$ _new$ ^dispose$ ^finalize$ _class_init$/;
	my @following = ();
	my @tmp = ();

	# A function name
	my $name = $1;
	complain ('A single space should follow the function name') unless $2 eq ' ';

	# Determine which function must not be preceding this one
	foreach my $func (reverse @order) {
		if ($name =~ /$func/) {
			@following = @tmp;
			last;
		}
		push @tmp, $func;
	}

	# Check if an out-of-order function was seen
	foreach my $func (@following) {
		my @wrong = grep { /$func/ } @functions_seen;
		complain (join (', ', map { "'$_'" } @wrong)." should follow '$name'") if @wrong;
	}

	push @functions_seen, $1;
	$type = undef;
	next;
}

if ($type) {
	# We've seen what looked like a type in a function declaration,
	# but the function declaration didn't follow.
	if ($type =~ /^(struct|union)/ and $line eq '{') {
		complain ("Brace should be one the same line as the '$type' declaration");
	} else {
		complain ("Expected a function declaration following '$type', but found something else");
	}
	$type = undef;
}

END {
	if ($seen_error) {
		warn "The patch does not validate.\n" if $is_patch;
		warn "The file does not validate.\n" if $is_file;
		$? = 1
	}
};

=head1 EXAMPLES

=over

=item B<checkpatch.pl hello.c>

Check a single file.

=item B<git diff --cached |checkpatch.pl>

Check the currently staged changes.

=item B<git format-patch -U65535 --stdout -1 |contrib/scripts/checkpatch.pl || :>

A F<.git/hooks/post-commit> oneliner that, wisely, tolerates failures while
still providing advice. The large line context allows helps checkpatch.pl
get a better idea about the changes in context of code that does not change.

=back

=head1 BUGS

Proabably too many.

=head1 SEE ALSO

F<CONTRIBUTING>

=head1 COPYRIGHT

Copyright 2018 Red Hat

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

=head1 AUTHOR

Lubomir Rintel C<lkundrak@v3.sk>

=cut
