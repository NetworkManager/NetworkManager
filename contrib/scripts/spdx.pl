#!/usr/bin/perl
# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2019 Lubomir Rintel

use strict;
use warnings;

sub escape
{
	$_ = shift;
	s/\s+$//g;
	# Don't ask me
	s/\s+/[\\\/\\s\\*#-]\*/g;
	# I have no idea
	return "\\s*$_([\\s\\*]*\\*|[\\s-]*-|[\\s#]*#)";
	# Sorry
}

my $GPL2 = escape <<'EOL';
This (program )?is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2( of the License)?, or
\(at your option\) any later version.
EOL

my $LGPL2 = escape <<'EOL';
This (library|program) is free software; you can redistribute it and/or
modify it under the terms of the GNU (Lesser|Library) General Public
License as published by the Free Software Foundation; either
version 2 of the License, or \(at your option\) any later version.
EOL

my $WARRANTY1 = escape <<'EOL';
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
EOL

my $TAIL1 = escape <<'EOL';
You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
EOL

my $TAIL2 = escape <<'EOL';
You should have received a copy of the GNU (Lesser )?General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
EOL

my $TAIL3 = escape <<'EOL';
This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.
EOL

my $TAIL4 = escape <<'EOL';
You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the
Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
Boston, MA 02110-1301 USA.
EOL

foreach my $filename (@ARGV) {
	next if $filename =~ /\.xml$/
		or $filename =~ /\bm4\//
		or $filename =~ /\bCOPYING/;
	next if $filename =~ /\b(src|shared)\/systemd\//
		and not $filename =~ /\/sd-adapt\//
		and not $filename =~ /\/nm-/;
	next if $filename =~ /\/(n-acd|c-list|c-rbtree|c-stdaux|c-siphash|n-dhcp4)\//;

	open (my $file, '<', $filename) or die "$filename: $!";
	my $content = join '', <$file>;
	my $spdx = '';

	if ($content =~ s/$GPL2//g) {
		$spdx = 'SPDX-License-Identifier: GPL-2.0+';
	} elsif ($content =~ s/$LGPL2//g) {
		$spdx = 'SPDX-License-Identifier: LGPL-2.1+';
	} else {
		warn $filename;
	}
	$content =~ s/$WARRANTY1//g;
	$content =~ s/$TAIL1//g;
	$content =~ s/$TAIL2//g;
	$content =~ s/$TAIL3//g;
	$content =~ s/$TAIL4//g;
	if ($spdx) {
		if ($content =~ /^(#![^\n]+[\/ ](perl|python|ruby|sh)[^\n]*\n)(.*)/s) {
			$content = "$1# $spdx\n$3";
		} elsif ($content =~ /^(#![^\n]+lua[^\n]*\n)(.*)/s) {
			$content = "$1-- $spdx\n$2";
		} elsif ($content =~ /^(#![^\n]+gjs[^\n]*\n)(.*)/s) {
			$content = "$1// $spdx\n$2";
		} elsif ($filename =~ /\.(h|c|cpp)(\.in)?$/) {
			$content = "// $spdx\n$content";
		} else {
			die $filename;
		}
	}
	open ($file, '>', $filename) or die "$filename: $!";
	print $file $content;
}
