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

#include "nms-keyfile-connection.h"

#include <glib/gstdio.h>

#include "nm-dbus-interface.h"
#include "nm-setting-connection.h"
#include "nm-utils.h"

#include "settings/nm-settings-plugin.h"

#include "nms-keyfile-reader.h"
#include "nms-keyfile-writer.h"
#include "nms-keyfile-utils.h"

/*****************************************************************************/

struct _NMSKeyfileConnection {
	NMSettingsConnection parent;
};

struct _NMSKeyfileConnectionClass {
	NMSettingsConnectionClass parent;
};

G_DEFINE_TYPE (NMSKeyfileConnection, nms_keyfile_connection, NM_TYPE_SETTINGS_CONNECTION)

/*****************************************************************************/

static gboolean
commit_changes (NMSettingsConnection *connection,
                NMConnection *new_connection,
                NMSettingsConnectionCommitReason commit_reason,
                NMConnection **out_reread_connection,
                char **out_logmsg_change,
                GError **error)
{
	gs_free char *path = NULL;
	gs_unref_object NMConnection *reread = NULL;
	gboolean reread_same = FALSE;

	nm_assert (out_reread_connection && !*out_reread_connection);
	nm_assert (!out_logmsg_change || !*out_logmsg_change);

	if (!nms_keyfile_writer_connection (new_connection,
	                                    TRUE,
	                                    nm_settings_connection_get_filename (connection),
	                                    NM_FLAGS_ALL (commit_reason,   NM_SETTINGS_CONNECTION_COMMIT_REASON_USER_ACTION
	                                                                 | NM_SETTINGS_CONNECTION_COMMIT_REASON_ID_CHANGED),
	                                    &path,
	                                    &reread,
	                                    &reread_same,
	                                    error))
		return FALSE;

	if (!nm_streq0 (path, nm_settings_connection_get_filename (connection))) {
		gs_free char *old_path = g_strdup (nm_settings_connection_get_filename (connection));

		nm_settings_connection_set_filename (connection, path);
		if (old_path) {
			NM_SET_OUT (out_logmsg_change,
			            g_strdup_printf ("keyfile: update "NMS_KEYFILE_CONNECTION_LOG_FMT" and rename from \"%s\"",
			                             NMS_KEYFILE_CONNECTION_LOG_ARG (connection),
			                             old_path));
		} else {
			NM_SET_OUT (out_logmsg_change,
			            g_strdup_printf ("keyfile: update "NMS_KEYFILE_CONNECTION_LOG_FMT" and persist connection",
			                             NMS_KEYFILE_CONNECTION_LOG_ARG (connection)));
		}
	} else {
		NM_SET_OUT (out_logmsg_change,
		            g_strdup_printf ("keyfile: update "NMS_KEYFILE_CONNECTION_LOG_FMT,
		                             NMS_KEYFILE_CONNECTION_LOG_ARG (connection)));
	}

	if (reread && !reread_same)
		*out_reread_connection = g_steal_pointer (&reread);

	return TRUE;
}

static gboolean
delete (NMSettingsConnection *connection,
        GError **error)
{
	const char *path;

	path = nm_settings_connection_get_filename (connection);
	if (path)
		g_unlink (path);
	return TRUE;
}

/*****************************************************************************/

static void
nms_keyfile_connection_init (NMSKeyfileConnection *connection)
{
}

NMSKeyfileConnection *
nms_keyfile_connection_new (NMConnection *source,
                            const char *full_path,
                            const char *profile_dir,
                            GError **error)
{
	GObject *object;
	NMConnection *tmp;
	const char *uuid;
	gboolean update_unsaved = TRUE;

	nm_assert (source || full_path);
	nm_assert (!full_path || full_path[0] == '/');
	nm_assert (!profile_dir || profile_dir[0] == '/');

	/* If we're given a connection already, prefer that instead of re-reading */
	if (source)
		tmp = g_object_ref (source);
	else {
		tmp = nms_keyfile_reader_from_file (full_path, profile_dir, error);
		if (!tmp)
			return NULL;

		uuid = nm_connection_get_uuid (tmp);
		if (!uuid) {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "Connection in file %s had no UUID", full_path);
			g_object_unref (tmp);
			return NULL;
		}

		/* If we just read the connection from disk, it's clearly not Unsaved */
		update_unsaved = FALSE;
	}

	object = g_object_new (NMS_TYPE_KEYFILE_CONNECTION,
	                       NM_SETTINGS_CONNECTION_FILENAME, full_path,
	                       NULL);

	/* Update our settings with what was read from the file */
	if (!nm_settings_connection_update (NM_SETTINGS_CONNECTION (object),
	                                    tmp,
	                                    update_unsaved
	                                      ? NM_SETTINGS_CONNECTION_PERSIST_MODE_UNSAVED
	                                      : NM_SETTINGS_CONNECTION_PERSIST_MODE_KEEP_SAVED,
	                                    NM_SETTINGS_CONNECTION_COMMIT_REASON_NONE,
	                                    NULL,
	                                    error)) {
		g_object_unref (object);
		object = NULL;
	}

	g_object_unref (tmp);
	return (NMSKeyfileConnection *) object;
}

static void
nms_keyfile_connection_class_init (NMSKeyfileConnectionClass *keyfile_connection_class)
{
	NMSettingsConnectionClass *settings_class = NM_SETTINGS_CONNECTION_CLASS (keyfile_connection_class);

	settings_class->commit_changes = commit_changes;
	settings_class->delete = delete;
}
