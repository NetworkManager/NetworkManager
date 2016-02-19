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
 * Copyright (C) 2008 Novell, Inc.
 * Copyright (C) 2008 - 2012 Red Hat, Inc.
 */

#include "nm-default.h"

#include <string.h>
#include <glib/gstdio.h>

#include "nm-dbus-interface.h"
#include "nm-setting-connection.h"
#include "nm-utils.h"

#include "nm-settings-plugin.h"
#include "nm-keyfile-connection.h"
#include "reader.h"
#include "writer.h"
#include "utils.h"

G_DEFINE_TYPE (NMKeyfileConnection, nm_keyfile_connection, NM_TYPE_SETTINGS_CONNECTION)

NMKeyfileConnection *
nm_keyfile_connection_new (NMConnection *source,
                           const char *full_path,
                           GError **error)
{
	GObject *object;
	NMConnection *tmp;
	const char *uuid;
	gboolean update_unsaved = TRUE;

	g_assert (source || full_path);

	/* If we're given a connection already, prefer that instead of re-reading */
	if (source)
		tmp = g_object_ref (source);
	else {
		tmp = nm_keyfile_plugin_connection_from_file (full_path, error);
		if (!tmp)
			return NULL;

		uuid = nm_connection_get_uuid (NM_CONNECTION (tmp));
		if (!uuid) {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "Connection in file %s had no UUID", full_path);
			g_object_unref (tmp);
			return NULL;
		}

		/* If we just read the connection from disk, it's clearly not Unsaved */
		update_unsaved = FALSE;
	}

	object = (GObject *) g_object_new (NM_TYPE_KEYFILE_CONNECTION,
	                                   NM_SETTINGS_CONNECTION_FILENAME, full_path,
	                                   NULL);

	/* Update our settings with what was read from the file */
	if (!nm_settings_connection_replace_settings (NM_SETTINGS_CONNECTION (object),
	                                              tmp,
	                                              update_unsaved,
	                                              NULL,
	                                              error)) {
		g_object_unref (object);
		object = NULL;
	}

	g_object_unref (tmp);
	return (NMKeyfileConnection *) object;
}

static void
commit_changes (NMSettingsConnection *connection,
                NMSettingsConnectionCommitReason commit_reason,
                NMSettingsConnectionCommitFunc callback,
                gpointer user_data)
{
	char *path = NULL;
	GError *error = NULL;

	if (!nm_keyfile_plugin_write_connection (NM_CONNECTION (connection),
	                                         nm_settings_connection_get_filename (connection),
	                                         NM_FLAGS_ALL (commit_reason,   NM_SETTINGS_CONNECTION_COMMIT_REASON_USER_ACTION
	                                                                      | NM_SETTINGS_CONNECTION_COMMIT_REASON_ID_CHANGED),
	                                         &path,
	                                         &error)) {
		callback (connection, error, user_data);
		g_clear_error (&error);
		return;
	}

	/* Update the filename if it changed */
	if (   path
	    && g_strcmp0 (path, nm_settings_connection_get_filename (connection)) != 0) {
		gs_free char *old_path = g_strdup (nm_settings_connection_get_filename (connection));

		nm_settings_connection_set_filename (connection, path);
		if (old_path) {
			nm_log_info (LOGD_SETTINGS, "keyfile: update "NM_KEYFILE_CONNECTION_LOG_FMT" and rename from \"%s\"",
			             NM_KEYFILE_CONNECTION_LOG_ARG (connection),
			             old_path);
		} else {
			nm_log_info (LOGD_SETTINGS, "keyfile: update "NM_KEYFILE_CONNECTION_LOG_FMT" and persist connection",
			             NM_KEYFILE_CONNECTION_LOG_ARG (connection));
		}
	} else {
		nm_log_info (LOGD_SETTINGS, "keyfile: update "NM_KEYFILE_CONNECTION_LOG_FMT,
		             NM_KEYFILE_CONNECTION_LOG_ARG (connection));
	}

	g_free (path);

	NM_SETTINGS_CONNECTION_CLASS (nm_keyfile_connection_parent_class)->commit_changes (connection,
	                                                                                   commit_reason,
	                                                                                   callback,
	                                                                                   user_data);
}

static void 
do_delete (NMSettingsConnection *connection,
           NMSettingsConnectionDeleteFunc callback,
           gpointer user_data)
{
	const char *path;

	path = nm_settings_connection_get_filename (connection);
	if (path)
		g_unlink (path);

	NM_SETTINGS_CONNECTION_CLASS (nm_keyfile_connection_parent_class)->delete (connection,
	                                                                           callback,
	                                                                           user_data);
}

/* GObject */

static void
nm_keyfile_connection_init (NMKeyfileConnection *connection)
{
}

static void
nm_keyfile_connection_class_init (NMKeyfileConnectionClass *keyfile_connection_class)
{
	NMSettingsConnectionClass *settings_class = NM_SETTINGS_CONNECTION_CLASS (keyfile_connection_class);

	/* Virtual methods */
	settings_class->commit_changes = commit_changes;
	settings_class->delete = do_delete;
}
