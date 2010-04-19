/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
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
 * Copyright (C) 2004 - 2010 Red Hat, Inc.
 */

#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <ctype.h>

#include "nm-policy-hosts.h"
#include "nm-logging.h"

gboolean
nm_policy_hosts_find_token (const char *line, const char *token)
{
	const char *start = line, *p = line;

	g_return_val_if_fail (line != NULL, FALSE);
	g_return_val_if_fail (token != NULL, FALSE);
	g_return_val_if_fail (strlen (token) > 0, FALSE);

	/* Walk through the line to find the next whitespace character */
	while (p <= line + strlen (line)) {
		if (isblank (*p) || (*p == '\0')) {
			/* Token starts with 'start' and ends with 'end' */
			if ((p > start) && *start && (p - start == strlen (token)) && !strncmp (start, token, (p - start)))
				return TRUE; /* found */

			/* not found; advance start and continue looking */
			start = p + 1;
		}
		p++;
	}

	return FALSE;
}

static gboolean
is_local_mapping (const char *str, const char *hostname)
{
	return (   !strncmp (str, "127.0.0.1", strlen ("127.0.0.1"))
	        && nm_policy_hosts_find_token (str, hostname ? hostname : "localhost"));
}

GString *
nm_policy_get_etc_hosts (const char **lines,
                         gsize existing_len,
                         const char *hostname,
                         const char *fallback_hostname,
                         GError **error)
{
	GString *contents = NULL;
	const char **line;
	gboolean found_host_nonlocal = FALSE;
	gboolean found_host = FALSE;
	gboolean found_localhost = FALSE;
	gboolean initial_comments = TRUE;
	gboolean added = FALSE;

	g_return_val_if_fail (lines != NULL, FALSE);
	g_return_val_if_fail (hostname != NULL, FALSE);

	/* /etc/hosts needs at least two things:
	 *
	 * 1) current hostname mapped to any address
	 * 2) 'localhost' mapped to 127.0.0.1
	 *
	 * If both these conditions exist in /etc/hosts, we don't need to bother
	 * updating the file.
	 */

	/* Look for the two cases from above */
	for (line = lines; lines && *line; line++) {
		if (strlen (*line) && (*line[0] != '#')) {
			if (nm_policy_hosts_find_token (*line, hostname)) {
				if (!is_local_mapping (*line, "localhost")) {
					/* hostname is not on a 127.0.0.1 line or the line does not
					 * contain 'localhost'.
					 */
					found_host_nonlocal = TRUE;
				}
				found_host = TRUE;
			}

			if (is_local_mapping (*line, "localhost")) {
				/* a 127.0.0.1 line containing 'localhost' */
				found_localhost = TRUE;
			}
		}

		if (found_localhost && found_host)
			return NULL;  /* No update required */
	}

	contents = g_string_sized_new (existing_len ? existing_len + 100 : 200);
	if (!contents) {
		g_set_error_literal (error, 0, 0, "not enough memory");
		return NULL;
	}

	/* Construct the new hosts file; replace any 127.0.0.1 entry that is at the
	 * beginning of the file or right after initial comments and contains
	 * the string 'localhost'.  If there is no 127.0.0.1 entry at the beginning
	 * or after initial comments that contains 'localhost', add one there
	 * and ignore any other 127.0.0.1 entries that contain 'localhost'.
	 */
	for (line = lines, initial_comments = TRUE; lines && *line; line++) {
		gboolean add_line = TRUE;

		/* This is the first line after the initial comments */
		if (strlen (*line) && initial_comments && (*line[0] != '#')) {
			initial_comments = FALSE;

			/* If some other line contained the hostname but not 'localhost',
			 * make a simple localhost mapping and assume the user knows what
			 * they are doing with their manual hostname entry.  Otherwise if
			 * the hostname wasn't found somewhere else, add it to the localhost
			 * mapping line to make sure it's mapped to something.
			 */
			if (found_host_nonlocal)
				g_string_append (contents, "127.0.0.1");
			else
				g_string_append_printf (contents, "127.0.0.1\t%s", hostname);

			if (strcmp (hostname, fallback_hostname)) {
				g_string_append_printf (contents, "\t%s", fallback_hostname);
				/* Don't add a standalone 'localhost.localdomain' 127 mapping */
				if (is_local_mapping (*line, fallback_hostname))
					add_line = FALSE;
			}

			g_string_append (contents, "\tlocalhost\n");
			added = TRUE;

			/* Don't add the original line if it is a 'localhost' mapping */
			if (is_local_mapping (*line, "localhost"))
				add_line = FALSE;
		}

		if (add_line) {
			g_string_append (contents, *line);
			/* Only append the new line if this isn't the last line in the file */
			if (*(line+1))
				g_string_append_c (contents, '\n');
		}
	}

	/* Hmm, /etc/hosts was empty for some reason */
	if (!added) {
		g_string_append (contents, "# Do not remove the following line, or various programs\n");
		g_string_append (contents, "# that require network functionality will fail.\n");
		g_string_append_printf (contents, "127.0.0.1\t%s\tlocalhost\n", fallback_hostname);
	}

	return contents;
}

gboolean
nm_policy_hosts_update_etc_hosts (const char *hostname,
                                  const char *fallback_hostname,
                                  gboolean *out_changed)
{
	char *contents = NULL;
	char **lines = NULL;
	GError *error = NULL;
	GString *new_contents = NULL;
	gsize contents_len = 0;
	gboolean success = FALSE;

	g_return_val_if_fail (hostname != NULL, FALSE);
	g_return_val_if_fail (out_changed != NULL, FALSE);

	if (!g_file_get_contents (SYSCONFDIR "/hosts", &contents, &contents_len, &error)) {
		nm_log_warn (LOGD_DNS, "couldn't read " SYSCONFDIR "/hosts: (%d) %s",
		             error ? error->code : 0,
		             (error && error->message) ? error->message : "(unknown)");
		g_clear_error (&error);
		return FALSE;
	}

	/* Get the new /etc/hosts contents */
	lines = g_strsplit_set (contents, "\n\r", 0);
	new_contents = nm_policy_get_etc_hosts ((const char **) lines,
	                                        contents_len,
	                                        hostname,
	                                        fallback_hostname,
	                                        &error);
	g_strfreev (lines);
	g_free (contents);

	if (new_contents) {
		nm_log_info (LOGD_DNS, "Updating /etc/hosts with new system hostname");

		g_clear_error (&error);
		/* And actually update /etc/hosts */
		if (!g_file_set_contents (SYSCONFDIR "/hosts", new_contents->str, -1, &error)) {
			nm_log_warn (LOGD_DNS, "couldn't update " SYSCONFDIR "/hosts: (%d) %s",
			             error ? error->code : 0,
			             (error && error->message) ? error->message : "(unknown)");
			g_clear_error (&error);
		} else {
			success = TRUE;
			*out_changed = TRUE;
		}

		g_string_free (new_contents, TRUE);
	} else if (!error) {
		/* No change required */
		success = TRUE;
	} else {
		nm_log_warn (LOGD_DNS, "couldn't read " SYSCONFDIR "/hosts: (%d) %s",
		             error->code, error->message ? error->message : "(unknown)");
		g_clear_error (&error);
	}

	return success;
}

