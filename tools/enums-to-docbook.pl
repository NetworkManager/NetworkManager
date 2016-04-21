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
#
# Copyright 2016 Red Hat, Inc.
#

# This tool formats enums along with their Gtk-Doc comments from a header
# file and produces a Docbook refentry suitable for inclusion in the D-Bus
# API rederence documentation.
#
# The output differs from Gtk-Doc: only enums are considered and are
# printed along with the values that are need to stay stable.

use strict;
use warnings;

our $name;
our $desc;
our $choice;
our @choices;
our $val;

BEGIN {
my $id = shift @ARGV or die "Missing ID";
my $nm = shift @ARGV or die "Missing title";
print <<END;
<?xml version='1.0'?>
<?xml-stylesheet type="text/xsl" href="http://docbook.sourceforge.net/release/xsl/current/xhtml/docbook.xsl"?>
<!DOCTYPE refentry PUBLIC "-//OASIS//DTD DocBook XML V4.2//EN" "http://www.oasis-open.org/docbook/xml/4.2/docbookx.dtd">

<refentry id="$id">
  <refmeta>
    <refentrytitle role="top_of_page" id="$id.top_of_page">$nm</refentrytitle>
    <manvolnum>3</manvolnum>
    <refmiscinfo>$nm</refmiscinfo>
  </refmeta>
  <refnamediv>
    <refname>$nm</refname>
    <refpurpose></refpurpose>
  </refnamediv>

END
}

# Increment a value keeping the format (e.g. 0x000666 is incremented to 0x000667,
# while 9 becomes 10.
sub inc
{
	my $val = shift;

	if ($val =~ /^\d+$/) {
		my $len = length $val;
		return sprintf "%0${len}d", $val + 1;
	} elsif ($val =~ /^0x(.+)$/) {
		my $len = length $1;
		return sprintf "0x%0${len}x", hex ($1) + 1;
	}
	die "'$val' used in previous enum value can not be incremented";
}

# The Gtk-Doc to docbook translation happens here. We don't support
# everything Gtk-Doc does.
sub fmt
{
	$_ = shift;
	s/\#([^\s\.]+)/<link linkend="$1">$1<\/link>/gm;
	s/\s*(.*)/<para>$1<\/para>/gm;
	$_;
}

chomp;

if (/^\/\*\*$/) {
	# Start of a documentation comment
	$name = '';
	$desc = '';
	$choice = undef;
	@choices = ();
} elsif (/^ \* (.+):$/) {
	# The name
	die "Duplicate name '$1': already processing '$name'" if $name;
	$name = $1;
} elsif (/^ \* @(\S+):\s+(.*)$/) {
	# The enum choice documentation
	$choice = $1;
	die "Documentation for '$1' already seen" if grep { $_->[0] eq $choice } @choices;
	push @choices, [ $choice, $2 ]
} elsif (/^ \*\s+(.*)$/) {
	# Text. Either a choice documentation, a description or continuation of either
	if (defined $choice) {
		my ($this) = grep { $_->[0] eq $choice } @choices;
		$this->[1] .= " $1";
	} elsif (defined $desc) {
		$desc .= " " if $desc;
		$desc .= $1;
	}
} elsif (/^ \*$/) {
	# A separator line. Either starts the description or breaks a paragraph.
	$desc .= "\n" if $desc;
	$choice = undef;
} elsif (/^ \*+\/$/) {
	# End of the doc comment
	$choice = undef;
} elsif (/^typedef enum/) {
	# Start of an enum
	$val = 0;
} elsif (/^\s+(\S+)\s+=\s+([^,\s]+)/) {
	# A choice with a literal value
	next unless @choices;
	die "Saw enum value '$1', but didn't see start of enum before" unless defined $val;
	$val = $2;
	my ($this) = grep { $_->[0] eq $1 } @choices;
	die "Documentation for value '$1' missing" unless $this;
	$this->[2] = "= <literal>$val</literal>";
} elsif (/^\s+([^,\s]+),?$/) {
	# A choice without a literal value
	next unless @choices;
	die "Saw enum value '$1', but didn't see start of enum before" unless defined $val;
	my ($this) = grep { $_->[0] eq $1 } @choices;
	die "Documentation for value '$1' missing" unless $this;
	$val = inc $val;
	$this->[2] = "= <literal>$val</literal>";
} elsif (/^\} ([^;]+);/) {
	# End of an enum
	next unless defined $name;
	die "Name of the enum '$1' different than documented '$name'" if $1 ne $name;

	@choices = grep { $_->[0] !~ /_LAST$/ } @choices;
	foreach (@choices) {
		die "'$_->[0]' documented, but not present in enum" unless defined $_->[2]
	}

	$desc = fmt $desc;
	print <<END;
  <refsect2 id="$name" role="enum">
    <title>enum $name</title>
    <indexterm zone="$name">
      <primary>$name</primary>
    </indexterm>
    <para>$desc</para>
    <refsect3 role="enum_members">
      <title>Values</title>
      <informaltable role="enum_members_table" pgwide="1" frame="none">
        <tgroup cols="4">
          <colspec colname="enum_members_name" colwidth="300px" />
          <colspec colname="enum_members_value" colwidth="100px"/>
          <colspec colname="enum_members_description" />
          <tbody>
END
	foreach (@choices) {
		my ($name, $desc, $val) = map { fmt $_ } @$_;
		print <<END; }
            <row role="constant">
              <entry role="enum_member_name">$name</entry>
              <entry role="enum_member_value">$val</entry>
              <entry role="enum_member_description">$desc</entry>
            </row>
END
	print <<END;
          </tbody>
        </tgroup>
      </informaltable>
    </refsect3>
  </refsect2>

END

	$name = undef;
	$desc = undef;
	$choice = undef;
	$val = undef;
	@choices = ();
} else {
	# Only care about other lines if we're parsing an enum
	next unless $val;
	s/\/\*.*\*\///g;
	die "Unexpected input '$_' while parsing enum" unless /^\s*$/;
}

END {
print <<END;
</refentry>
END
}
