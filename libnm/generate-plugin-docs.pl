#!/usr/bin/env perl
# vim: ft=perl ts=2 sts=2 sw=2 et ai
# -*- Mode: perl; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-

#
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
# Copyright 2014 Red Hat, Inc.
#

#
# The script parses nm-setting-*.c files and extracts documentation related
# to setting plugins. The documentation is in a simple format of lines
# "keyword: value". The documentation is enclosed between tags
# ---<plugin-name>--- and ---end---
# Recognized keywords are:
# "property: "     - property name
# "variable: "     - name of the variable used by the plugin
# "format: "       - format of the value in 'keyfile' plugin
# "default: "      - default value when variable is not used
# "values: "       - allowed values (e.g. for enumerations)
# "example: "      - example(s)
# "description: "  - description text
# Value is an arbitrary string that can span over multiple lines.
#
# ifcfg-rh specifics:
#  - mark NM extension variables with (+), e.g. variable: UUID(+)
#

use strict;
use warnings;
use v5.10;

# global variables
my @keywords = ("property", "variable", "format", "values", "default", "example", "description");
my @data;
my $fo;

(scalar @ARGV >= 3) or die "Usage: $0 <plugin> <output-xml-file> <srcfiles>\n";
my ($plugin, $output, (@source_files)) = @ARGV;
my $start_tag = "---$plugin---\\s*\$";
my $end_tag   = '---end---';

# open output file
open $fo, '>', $output or die "Can't open $output: $!";

# write XML header
write_header();

# write generated documentation for each setting
foreach my $c_file (@source_files) {
  my $setting_name = get_setting_name($c_file);
  if ($setting_name) {
    write_item("<setting name=\"$setting_name\">");
    scan_doc_comments($c_file, $start_tag, $end_tag);
    write_item("</setting>");
  }
}

# write XML footer
write_footer();

# close output file
close $fo;


### --- subroutines --- ###

# get setting name from NM_SETTING_*_SETTING_NAME constant in C header file
sub get_setting_name {
  my $path = $_[0];
  $path =~ s/c$/h/;  # use header file to find out setting name
  open my $fh, '<', $path or die "Can't open $path: $!";
  while (my $line = <$fh>) {
    if ($line =~ /NM_SETTING_.+SETTING_NAME\s+\"(\S+)\"/) {
      return $1;
    }
  }
}

# scan source setting file for documentation tags and write them to XML
sub scan_doc_comments {
  my($setting_file, $start, $end) = @_;
  open my $fi, '<', $setting_file or die "Can't open $setting_file: $!";
  while (<$fi>) {
    if (/$start/ .. /$end/) {
      next if /$start/;
      if (/$end/) {
        process_data();
      } else {
        push @data, $_;
      }
      next;
    }
    # ignore text not inside marks
  }
  close $fi;
}

# process plugin property documentation comments
sub process_data {
  return if not @data;
  my $kwd_pat = join("|", @keywords);
  my %parsed_data;
  my $this_key;

  foreach (@data) {
    if (/^\s*\**\s+($kwd_pat):\s+(.*?)\s*$/) {
      $this_key = $1;
      $parsed_data{$this_key} = "$2\n";
    } elsif (/^\s*\**\s+(.*?)\s*$/) {
      die "Extra mess in a comment: $_" unless $this_key;
      $parsed_data{$this_key} .= "$1\n";
    }
  }

  # now write a line into the XML
  my $name   = $parsed_data{property}    // "";
  my $var    = $parsed_data{variable}    // $name;  # fallback to "property: "
  my $format = $parsed_data{format}      // "";
  my $values = $parsed_data{values}      // "";
  my $def    = $parsed_data{default}     // "";
  my $exam   = $parsed_data{example}     // "";
  my $desc   = $parsed_data{description} // "";

  chomp($name, $var, $format, $values, $def, $exam, $desc);
  escape_xml_chars($name, $var, $format, $values, $def, $exam, $desc);
  my $foo = sprintf("<property name=\"%s\" variable=\"%s\" format=\"%s\" values=\"%s\" ".
                    "default=\"%s\" example=\"%s\" description=\"%s\"/>",
                    $name, $var, $format, $values, $def, $exam, $desc);
  write_item($foo);
  @data = ();
}

# - XML handling -
sub write_header {
  (my $header =
    qq{<?xml version=\"1.0\"?>
       <!DOCTYPE nm-$plugin-docs [
       ]>

       <nm-$plugin-docs>
  }) =~ s/^ {7}//mg;
  print {$fo} $header;
}

sub write_footer {
  my $footer = "</nm-$plugin-docs>";
  print {$fo} $footer;
}

sub write_item {
  my $str = join("", @_);
  print {$fo} $str, "\n";
}

sub escape_xml_chars {
  # http://en.wikipedia.org/wiki/List_of_XML_and_HTML_character_entity_references#Predefined%5Fentities%5Fin%5FXML
  foreach my $val (@_) {
    $val =~ s/&/&amp;/sg;
    $val =~ s/</&lt;/sg;
    $val =~ s/>/&gt;/sg;
    $val =~ s/"/&quot;/sg;
    $val =~ s/'/&apos;/sg;
  }
}

