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

checkpatch.pl - emulate a serial modem

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

our $seen_error;
our $line;		# Current line
our $check_line;	# Complain if errors are found on this line

our @functions_seen;
our $type;
our $filename;
our $line_no;

sub new_hunk
{
	$type = undef;
}

sub new_file
{
	$filename = shift;
	@functions_seen = ();
}

sub complain
{
	my $message = shift;

	return unless $check_line;
	warn "$filename:$line_no: $message:\n";
	warn "> $line\n\n";
	$seen_error = 1;
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
	/^([ \+])(.*)/ or next;
	$line_no++;
	$check_line = $1 eq '+';
	$line = $2;
} elsif ($is_file) {
	$line_no = $.;
	$. = 0 if eof;
	# This is a line from full C file
	$check_line = 1;
	$line = $_;
} else {
	# We don't handle these yet
	/^diff --cc/ and exit 0;
	# We don't know if we're dealing with a patch or a C file yet
	/^#/ and $is_file = 1;
	/^---/ and $is_patch = 1;
	$filename = '';
	next;
}

if ($is_file and $filename ne $ARGV) {
	new_file ($ARGV);
	new_hunk;
}

next unless $filename =~ /\.[ch]$/;
next if $filename =~ /\/nm-[^\/]+-enum-types\.[ch]$/;

complain ('Tabs are only allowed at the beginning of a line') if $line =~ /[^\t]\t/;
complain ('Trailing whitespace') if $line =~ /[ \t]$/;
complain ('Don\'t use glib typedefs for char/short/int/long/float/double') if $line =~ /\bg(char|short|int|long|float|double)\b/;
complain ("Don't use \"$1 $2\" instead of \"$2 $1\"") if $line =~ /\b(char|short|int|long) +(unsigned|signed)\b/;
complain ("Don't use \"unsigned int\" but just use \"unsigned\"") if $line =~ /\b(unsigned) +(int)\b/;

# Further on we process stuff without comments.
$_ = $line;
s/\s*\/\*.*\*\///;
s/\s*\/\*.*//;
s/\s*\/\/.*//;
/^\s* \* / and next;
new_hunk if $_ eq '';

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
