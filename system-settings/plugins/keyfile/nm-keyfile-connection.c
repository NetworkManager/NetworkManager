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
 * Copyright (C) 2008 - 2010 Red Hat, Inc.
 */

#include <string.h>
#include <glib/gstdio.h>
#include <NetworkManager.h>
#include <nm-setting-connection.h>
#include <nm-utils.h>

#include "nm-system-config-interface.h"
#include "nm-dbus-glib-types.h"
#include "nm-keyfile-connection.h"
#include "reader.h"
#include "writer.h"
#include "common.h"

G_DEFINE_TYPE (NMKeyfileConnection, nm_keyfile_connection, NM_TYPE_SYSCONFIG_CONNECTION)

#define NM_KEYFILE_CONNECTION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_KEYFILE_CONNECTION, NMKeyfileConnectionPrivate))

typedef struct {
	char *path;
} NMKeyfileConnectionPrivate;

NMKeyfileConnection *
nm_keyfile_connection_new (const char *full_path,
                           NMConnection *source,
                           GError **error)
{
	GObject *object;
	NMKeyfileConnectionPrivate *priv;
	NMSettingConnection *s_con;
	NMConnection *tmp;

	g_return_val_if_fail (full_path != NULL, NULL);

	/* If we're given a connection already, prefer that instead of re-reading */
	if (source)
		tmp = g_object_ref (source);
	else {
		tmp = connection_from_file (full_path, error);
		if (!tmp)
			return NULL;
	}

	object = (GObject *) g_object_new (NM_TYPE_KEYFILE_CONNECTION, NULL);
	if (!object) {
		g_object_unref (tmp);
		return NULL;
	}

	priv = NM_KEYFILE_CONNECTION_GET_PRIVATE (object);
	priv->path = g_strdup (full_path);

	/* Update our settings with what was read from the file */
	nm_sysconfig_connection_replace_settings (NM_SYSCONFIG_CONNECTION (object), tmp, NULL);
	g_object_unref (tmp);

	/* if for some reason the connection didn't have a UUID, add one */
	s_con = (NMSettingConnection *) nm_connection_get_setting (NM_CONNECTION (object), NM_TYPE_SETTING_CONNECTION);
	if (s_con && !nm_setting_connection_get_uuid (s_con)) {
		GError *write_error = NULL;
		char *uuid;

		uuid = nm_utils_uuid_generate ();
		g_object_set (s_con, NM_SETTING_CONNECTION_UUID, uuid, NULL);
		g_free (uuid);

		if (!write_connection (NM_CONNECTION (object), KEYFILE_DIR, 0, 0, NULL, &write_error)) {
			PLUGIN_WARN (KEYFILE_PLUGIN_NAME,
			             "Couldn't update connection %s with a UUID: (%d) %s",
			             nm_setting_connection_get_id (s_con),
			             write_error ? write_error->code : -1,
			             (write_error && write_error->message) ? write_error->message : "(unknown)");
			g_propagate_error (error, write_error);
		}
	}

	return NM_KEYFILE_CONNECTION (object);
}

const char *
nm_keyfile_connection_get_path (NMKeyfileConnection *self)
{
	g_return_val_if_fail (NM_IS_KEYFILE_CONNECTION (self), NULL);

	return NM_KEYFILE_CONNECTION_GET_PRIVATE (self)->path;
}

static void
commit_changes (NMSysconfigConnection *connection,
                NMSysconfigConnectionCommitFunc callback,
                gpointer user_data)
{
	NMKeyfileConnectionPrivate *priv = NM_KEYFILE_CONNECTION_GET_PRIVATE (connection);
	char *path = NULL;
	GError *error = NULL;

	if (!write_connection (NM_CONNECTION (connection), KEYFILE_DIR, 0, 0, &path, &error)) {
		callback (connection, error, user_data);
		g_clear_error (&error);
		return;
	}

	if (g_strcmp0 (priv->path, path)) {
		/* Update the filename if it changed */
		g_free (priv->path);
		priv->path = path;
	} else
		g_free (path);

	NM_SYSCONFIG_CONNECTION_CLASS (nm_keyfile_connection_parent_class)->commit_changes (connection,
	                                                                                    callback,
	                                                                                    user_data);
}

static void 
do_delete (NMSysconfigConnection *connection,
           NMSysconfigConnectionDeleteFunc callback,
           gpointer user_data)
{
	NMKeyfileConnectionPrivate *priv = NM_KEYFILE_CONNECTION_GET_PRIVATE (connection);

	g_unlink (priv->path);

	NM_SYSCONFIG_CONNECTION_CLASS (nm_keyfile_connection_parent_class)->delete (connection,
	                                                                            callback,
	                                                                            user_data);
}

/* GObject */

static void
nm_keyfile_connection_init (NMKeyfileConnection *connection)
{
}

static void
finalize (GObject *object)
{
	NMKeyfileConnectionPrivate *priv = NM_KEYFILE_CONNECTION_GET_PRIVATE (object);

	nm_connection_clear_secrets (NM_CONNECTION (object));

	g_free (priv->path);

	G_OBJECT_CLASS (nm_keyfile_connection_parent_class)->finalize (object);
}

static void
nm_keyfile_connection_class_init (NMKeyfileConnectionClass *keyfile_connection_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (keyfile_connection_class);
	NMSysconfigConnectionClass *sysconfig_class = NM_SYSCONFIG_CONNECTION_CLASS (keyfile_connection_class);

	g_type_class_add_private (keyfile_connection_class, sizeof (NMKeyfileConnectionPrivate));

	/* Virtual methods */
	object_class->finalize     = finalize;
	sysconfig_class->commit_changes = commit_changes;
	sysconfig_class->delete = do_delete;
}
