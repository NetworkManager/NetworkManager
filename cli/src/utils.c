/* nmcli - command-line tool to control NetworkManager
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2010 Red Hat, Inc.
 */

#include <stdio.h>
#include <string.h>

#include <glib.h>

#include "utils.h"

int
matches (const char *cmd, const char *pattern)
{
	int len = strlen (cmd);
	if (len > strlen (pattern))
		return -1;
	return memcmp (pattern, cmd, len);
}

int
next_arg (int *argc, char ***argv)
{
	if (*argc <= 1) {
		return -1;
	}
	else {
		(*argc)--;
		(*argv)++;
	}
	return 0;
}

void
print_table_header (const char *name, ...)
{
	va_list ap;
	GString *str;
	char *col, *line = NULL;
	int col_width, width1, width2, table_width = 0;

	str = g_string_new (NULL);

	va_start (ap, name);
	while ((col = va_arg (ap, char *)) != NULL) {
		col_width = va_arg (ap, int);
		width1 = strlen (col);
		width2 = g_utf8_strlen (col, -1);  /* Width of the string (in screen colums) */
		g_string_append_printf (str, "%-*s", col_width + width1 - width2, col);
		g_string_append_c (str, ' ');  /* Column separator */
		table_width += col_width + width1 - width2 + 1;
	}
	va_end (ap);

	if (table_width <= 0)
		table_width = g_utf8_strlen (name, -1) + 4;

	/* Print the table header */
	line = g_strnfill (table_width, '=');
	printf ("%s\n", line);
	width1 = strlen (name);
	width2 = g_utf8_strlen (name, -1);
	printf ("%*s\n", (table_width + width2)/2 + width1 - width2, name);
	printf ("%s\n", line);
	if (str->len > 0) {
		g_string_truncate (str, str->len-1);  /* Chop off last column separator */
		printf ("%s\n", str->str);
		g_free (line);
		line = g_strnfill (table_width, '-');
		printf ("%s\n", line);
	}

	g_free (line);
	g_string_free (str, TRUE);
}

void
print_table_line (int indent, ...)
{
	va_list ap;
	GString *str;
	char *col, *indent_str;
	int col_width, width1, width2;

	str = g_string_new (NULL);

	va_start (ap, indent);
	while ((col = va_arg (ap, char *)) != NULL) {
		col_width = va_arg (ap, int);
		width1 = strlen (col);
		width2 = g_utf8_strlen (col, -1);  /* Width of the string (in screen colums) */
		g_string_append_printf (str, "%-*s", col_width + width1 - width2, col);
		g_string_append_c (str, ' ');  /* Column separator */
	}
	va_end (ap);

	/* Print the line */
	if (str->len > 0)
	{
		g_string_truncate (str, str->len-1);  /* Chop off last column separator */
		if (indent > 0) {
			indent_str = g_strnfill (indent, ' ');
			g_string_prepend (str,  indent_str);
			g_free (indent_str);
		}
		printf ("%s\n", str->str);
	}

	g_string_free (str, TRUE);
}

