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
 * Copyright (C) 2015 Red Hat, Inc.
 */

#include "config.h"

#include <sys/stat.h>
#include <string.h>

#include "reader.h"

#include "nm-default.h"
#include "nm-keyfile-internal.h"
#include "NetworkManagerUtils.h"

static const char *
_fmt_warn (const char *group, NMSetting *setting, const char *property_name, const char *message, char **out_message)
{
	const char *setting_name = setting ? nm_setting_get_name (setting) : NULL;

	if (group) {
		char *res;

		if (setting_name) {
			if (property_name && !strcmp (group, setting_name))
				res = g_strdup_printf ("%s.%s: %s", group, property_name, message);
			else if (property_name)
				res = g_strdup_printf ("%s/%s.%s: %s", group, setting_name, property_name, message);
			else if (!strcmp (group, setting_name))
				res = g_strdup_printf ("%s: %s", group, message);
			else
				res = g_strdup_printf ("%s/%s: %s", group, setting_name, message);
		} else
			res = g_strdup_printf ("%s: %s", group, message);
		*out_message = res;
		return res;
	} else
		return message;
}

static gboolean
_handler_read (GKeyFile *keyfile,
               NMConnection *connection,
               NMKeyfileReadType type,
               void *type_data,
               void *user_data,
               GError **error)
{
	if (type == NM_KEYFILE_READ_TYPE_WARN) {
		NMKeyfileReadTypeDataWarn *warn_data = type_data;
		NMLogLevel level;
		char *message_free = NULL;

		if (warn_data->severity > NM_KEYFILE_WARN_SEVERITY_WARN)
			level = LOGL_ERR;
		else if (warn_data->severity >= NM_KEYFILE_WARN_SEVERITY_WARN)
			level = LOGL_WARN;
		else if (warn_data->severity == NM_KEYFILE_WARN_SEVERITY_INFO_MISSING_FILE)
			level = LOGL_WARN;
		else
			level = LOGL_INFO;

		nm_log (level, LOGD_SETTINGS, "keyfile: %s",
		        _fmt_warn (warn_data->group, warn_data->setting,
		                   warn_data->property_name, warn_data->message,
		                   &message_free));
		g_free (message_free);
		return TRUE;
	}
	return FALSE;
}

NMConnection *
nm_keyfile_plugin_connection_from_file (const char *filename, GError **error)
{
	GKeyFile *key_file;
	struct stat statbuf;
	NMConnection *connection = NULL;
	GError *verify_error = NULL;

	if (stat (filename, &statbuf) != 0 || !S_ISREG (statbuf.st_mode)) {
		g_set_error_literal (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		                     "File did not exist or was not a regular file");
		return NULL;
	}

	if (statbuf.st_mode & 0077) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "File permissions (%o) were insecure",
		             statbuf.st_mode);
		return NULL;
	}

	if (!NM_FLAGS_HAS (nm_utils_get_testing (), NM_UTILS_TEST_NO_KEYFILE_OWNER_CHECK)) {
		if (statbuf.st_uid != 0) {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "File owner (%o) is insecure",
			             statbuf.st_mode);
			return NULL;
		}
	}

	key_file = g_key_file_new ();
	if (!g_key_file_load_from_file (key_file, filename, G_KEY_FILE_NONE, error))
		goto out;

	connection = nm_keyfile_read (key_file, filename, NULL, _handler_read, NULL, error);
	if (!connection)
		goto out;

	/* Normalize and verify the connection */
	if (!nm_connection_normalize (connection, NULL, NULL, &verify_error)) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "invalid connection: %s",
		             verify_error->message);
		g_clear_error (&verify_error);
		g_object_unref (connection);
		connection = NULL;
	}

out:
	g_key_file_free (key_file);
	return connection;
}

