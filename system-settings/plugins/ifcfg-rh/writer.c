/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager system settings service - keyfile plugin
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
 * Copyright (C) 2009 Red Hat, Inc.
 */

#include <ctype.h>
#include <string.h>
#include <nm-setting-connection.h>
#include <nm-setting-wired.h>
#include <nm-setting-wireless.h>

#include "common.h"
#include "shvar.h"
#include "writer.h"

static void
write_connection_setting (NMSettingConnection *s_con, shvarFile *ifcfg)
{
	char *tmp;

	svSetValue (ifcfg, "NAME", nm_setting_connection_get_id (s_con));
	svSetValue (ifcfg, "UUID", nm_setting_connection_get_uuid (s_con));
	svSetValue (ifcfg, "ONBOOT",
	            nm_setting_connection_get_autoconnect (s_con) ? "yes" : "no");
	tmp = g_strdup_printf ("%llu", nm_setting_connection_get_timestamp (s_con));
	svSetValue (ifcfg, "LAST_CONNECTION", tmp);
	g_free (tmp);
}

static char *
escape_id (const char *id)
{
	char *escaped = g_strdup (id);
	char *p = escaped;

	/* Escape random stuff */
	while (*p) {
		if (*p == ' ')
			*p = '_';
		else if (*p == '/')
			*p = '-';
		else if (*p == '\\')
			*p = '-';
	}

	return escaped;
}

gboolean
write_connection (NMConnection *connection,
                  const char *ifcfg_dir,
                  const char *filename,
                  const char *keyfile,
                  GError **error)
{
	NMSettingConnection *s_con;
	gboolean success = FALSE;
	shvarFile *ifcfg = NULL;
	char *ifcfg_name = NULL;
	const char *type;

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	if (!s_con) {
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "Missing '%s' setting", NM_SETTING_CONNECTION_SETTING_NAME);
		return FALSE;
	}

	if (filename) {
		/* For existing connections, 'filename' should be full path to ifcfg file */
		ifcfg = svNewFile (filename);
		ifcfg_name = g_strdup (filename);
	} else {
		char *escaped;

		escaped = escape_id (nm_setting_connection_get_id (s_con));
		ifcfg_name = g_strdup_printf (IFCFG_DIR "/ifcfg-%s", escaped);
		ifcfg = svCreateFile (ifcfg_name);
		g_free (escaped);
	}

	if (!ifcfg) {
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "Failed to open/create ifcfg file '%s'", ifcfg_name);
		goto out;
	}

	type = nm_setting_connection_get_connection_type (s_con);
	if (!type) {
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "Missing connection type!");
		goto out;
	}

	if (!strcmp (type, NM_SETTING_WIRED_SETTING_NAME)) {
	} else if (!strcmp (type, NM_SETTING_WIRELESS_SETTING_NAME)) {
	} else {
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "Can't write connection type '%s'", type);
		goto out;
	}

	write_connection_setting (s_con, ifcfg);


out:
	g_free (ifcfg_name);
	return success;
}

