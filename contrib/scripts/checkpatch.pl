#!/usr/bin/perl -n
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2018,2021 Red Hat, Inc.
#

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
our $expect_spdx;
our $subdir;

sub new_hunk
{
	$type = undef;
	$indent = undef;
}

sub new_file
{
	$expect_spdx = 0;
	$check_is_todo = 1;
	$filename = $subdir // '';
	$filename .= shift;
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
	/^(Reverts|Fixes): *(.*)/ and check_commit ($2, 1);
	/This reverts commit/ and next;
	/cherry picked from/ and next;
	/^git-subtree-dir: (.*)/ and $subdir = "$1/";
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
next if $filename =~ /\b(shared|src)\/systemd\//
	and not $filename =~ /\/sd-adapt\//
	and not $filename =~ /\/nm-/;
next if $filename =~ /\/(n-acd|c-list|c-siphash|n-dhcp4)\//;

$expect_spdx = 1 if $line_no == 1;
$expect_spdx = 0 if $line =~ /SPDX-License-Identifier/;
complain ('Missing a SPDX-License-Identifier') if $line_no == 2 and $expect_spdx;

complain ('Tabs are only allowed at the beginning of a line') if $line =~ /[^\t]\t/;
complain ('Trailing whitespace') if $line =~ /[ \t]$/;
complain ('Don\'t use glib typedefs for char/short/int/long/float/double') if $line =~ /\bg(char|short|int|long|float|double)\b/;
complain ("Don't use \"$1 $2\" instead of \"$2 $1\"") if $line =~ /\b(char|short|int|long) +(unsigned|signed)\b/;
complain ("Don't use \"unsigned int\" but just use \"unsigned\"") if $line =~ /\b(unsigned) +(int)\b/;
complain ("Please use LGPL-2.1-or-later SPDX tag for new files") if $is_patch and $line =~ /SPDX-License-Identifier/ and not /LGPL-2.1-or-later/;
complain ("Use a SPDX-License-Identifier instead of Licensing boilerplate") if $is_patch and $line =~ /under the terms of/;
complain ("Don't use space inside elvis operator ?:") if $line =~ /\?[\t ]+:/;
complain ("Don't add Emacs editor formatting hints to source files") if $line_no == 1 and $line =~ /-\*-.+-\*-/;
complain ("XXX marker are reserved for development while work-in-progress. Use TODO or FIXME comment instead?") if $line =~ /\bXXX\b/;
complain ("This gtk-doc annotation looks wrong") if $line =~ /\*.*\( *(transfer-(none|container|full)|allow none) *\) *(:|\()/;
complain ("Prefer nm_assert() or g_return*() to g_assert*()") if $line =~ /g_assert/ and (not $filename =~ /\/tests\//) and (not $filename =~ /\/nm-test-/);
complain ("Use gs_free_error with GError variables") if $line =~ /\bgs_free\b +GError *\*/;
complain ("Initialize GError variables to NULL, if you pass them on") if $line =~ /\bGError +\*([a-z0-9_]+);/;
complain ("Don't use strcmp/g_strcmp0 unless you need to sort. Consider nm_streq()/nm_streq0(),NM_IN_STRSET() for testing equality") if $line =~ /\b(strcmp|g_strcmp0)\b/;
complain ("Don't use API that uses the numeric source id. Instead, use GSource and API like nm_g_idle_add(), nm_g_idle_add_source(), nm_clear_g_source_inst(), etc.") if $line =~ /\b(g_idle_add|g_idle_add_full|g_timeout_add|g_timeout_add_seconds|g_source_remove|nm_clear_g_source)\b/;
complain ("Prefer g_snprintf() over snprintf() (for consistency)") if $line =~ /\b(snprintf)\b/;
complain ("Prefer nm_str_hash()/nm_direct_hash() over g_str_hash()/g_direct_hash(). Those use siphash24") if $line =~ /\b(g_str_hash|g_direct_hash)\b/;
complain ("Don't use g_direct_equal() for hash tables, pass NULL for pointer equality which avoids the function call") if $line =~ /\b(g_direct_equal)\b/;
complain ("Prefer nm_pint_hash()/nm_pint64_hash()/nm_pdouble_hash() over g_int_hash()/g_int64_hash()/g_double_hash(). Those use siphash24") if $line =~ /\b(g_int_hash|g_int64_hash|g_double_hash)\b/;
complain ("Prefer nm_pint_equal()/nm_pint64_equal()/nm_pdouble_equal() over g_int_equal()/g_int64_equal()/g_double_equal(). Those names mirror our nm_p*_hash() functions") if $line =~ /\b(g_int_equal|g_int64_equal|g_double_equal)\b/;
complain ("Avoid g_clear_pointer() and use nm_clear_pointer() (or nm_clear_g_free(), g_clear_object(), etc.)") if $line =~ /\b(g_clear_pointer)\b/;
complain ("Define setting properties with _nm_setting_property_define_direct_*() API") if $line =~ /g_param_spec_/ and $filename =~ /\/libnm-core-impl\/nm-setting/;
complain ("Use nm_g_array_{index,first,last,index_p}() instead of g_array_index(), as it nm_assert()s for valid element size and out-of-bound access") if $line =~ /\bg_array_index\b/;
complain ("Use spaces instead of tabs") if $line =~ /\t/;
complain ("Prefer implementing private pointers via _NM_GET_PRIVATE() or _NM_GET_PRIVATE_PTR() (the latter, if the private data has an opqaue pointer in the header file)") if $line =~ /\b(g_type_class_add_private|G_TYPE_INSTANCE_GET_PRIVATE)\b/;
complain ("Don't use close()/g_close(). Instead, use nm_close() (or nm_close_with_error()).") if $line =~ /\b(close|g_close)\b *\(/;
complain ("Use nm_memdup() instead of g_memdup(). The latter has a size argument of type guint") if $line =~ /\bg_memdup\b/;

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
	complain ('No space between function name and arguments') unless $2 eq '';

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

Copyright (C) 2018,2021 Red Hat

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

=head1 AUTHOR

Lubomir Rintel C<lkundrak@v3.sk>

=cut
