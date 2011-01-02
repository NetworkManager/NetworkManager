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

#include <config.h>
#include <string.h>

#include "nm-policy-hosts.h"
#include "nm-logging.h"

#define ADDED_TAG "# Added by NetworkManager"

GString *
nm_policy_get_etc_hosts (const char *contents, gsize contents_len)
{
	char **lines = NULL, **iter;
	GString *new_contents = NULL;

	if (contents_len == 0 || !strstr (contents, ADDED_TAG))
		return NULL;

	new_contents = g_string_sized_new (contents_len);

	/* Remove "# Added ..." lines */
	lines = g_strsplit_set (contents, "\n\r", -1);
	for (iter = lines; iter && *iter; iter++) {
		if (!strstr (*iter, ADDED_TAG)) {
			g_string_append (new_contents, *iter);
			g_string_append_c (new_contents, '\n');
		}
	}
	g_strfreev (lines);

	/* Remove last blank line at end of file, if one exists; this is
	 * an artifact of how g_strsplit_set() works.
	 */
	if (   (new_contents->len > 2)
	    && (new_contents->str[new_contents->len - 1] == '\n'))
		g_string_truncate (new_contents, new_contents->len - 1);

	return new_contents;
}

/* remove any leftover "# Added by NetworkManager" lines */
void
nm_policy_hosts_clean_etc_hosts (void)
{
	char *contents = NULL;
	gsize contents_len = 0;
	GError *error = NULL;
	GString *new;

	if (!g_file_get_contents (SYSCONFDIR "/hosts", &contents, &contents_len, &error)) {
		nm_log_warn (LOGD_DNS, "couldn't read " SYSCONFDIR "/hosts: (%d) %s",
		             error ? error->code : 0,
		             (error && error->message) ? error->message : "(unknown)");
		g_clear_error (&error);
		return;
	}

	new = nm_policy_get_etc_hosts (contents, contents_len);
	if (new && new->len) {
		nm_log_info (LOGD_DNS, "Cleaning leftovers from /etc/hosts");

		g_clear_error (&error);
		if (!g_file_set_contents (SYSCONFDIR "/hosts", new->str, -1, &error)) {
			nm_log_dbg (LOGD_DNS, "couldn't update " SYSCONFDIR "/hosts: (%d) %s",
			            error ? error->code : 0,
			            (error && error->message) ? error->message : "(unknown)");
			g_clear_error (&error);
		}
	}

	if (new)
		g_string_free (new, TRUE);
}

