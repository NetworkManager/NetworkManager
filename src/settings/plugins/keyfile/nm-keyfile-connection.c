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

G_DEFINE_TYPE (NMKeyfileConnection, nm_keyfile_connection, NM_TYPE_SETTINGS_CONNECTION)

#define NM_KEYFILE_CONNECTION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_KEYFILE_CONNECTION, NMKeyfileConnectionPrivate))

typedef struct {
	char *path;
} NMKeyfileConnectionPrivate;

NMKeyfileConnection *
nm_keyfile_connection_new (NMConnection *source,
                           const char *full_path,
                           GError **error)
{
	GObject *object;
	NMKeyfileConnectionPrivate *priv;
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
			g_set_error (error, KEYFILE_PLUGIN_ERROR, 0,
			             "Connection in file %s had no UUID", full_path);
			g_object_unref (tmp);
			return NULL;
		}

		/* If we just read the connection from disk, it's clearly not Unsaved */
		update_unsaved = FALSE;
	}

	object = (GObject *) g_object_new (NM_TYPE_KEYFILE_CONNECTION, NULL);

	priv = NM_KEYFILE_CONNECTION_GET_PRIVATE (object);
	priv->path = g_strdup (full_path);

	/* Update our settings with what was read from the file */
	if (!nm_settings_connection_replace_settings (NM_SETTINGS_CONNECTION (object),
	                                              tmp,
	                                              update_unsaved,
	                                              error)) {
		g_object_unref (object);
		object = NULL;
	}

	g_object_unref (tmp);
	return (NMKeyfileConnection *) object;
}

const char *
nm_keyfile_connection_get_path (NMKeyfileConnection *self)
{
	g_return_val_if_fail (NM_IS_KEYFILE_CONNECTION (self), NULL);

	return NM_KEYFILE_CONNECTION_GET_PRIVATE (self)->path;
}

void
nm_keyfile_connection_set_path (NMKeyfileConnection *self, const char *path)
{
	NMKeyfileConnectionPrivate *priv;

	g_return_if_fail (NM_IS_KEYFILE_CONNECTION (self));
	g_return_if_fail (path != NULL);

	priv = NM_KEYFILE_CONNECTION_GET_PRIVATE (self);
	g_free (priv->path);
	priv->path = g_strdup (path);
}

static void
commit_changes (NMSettingsConnection *connection,
                NMSettingsConnectionCommitFunc callback,
                gpointer user_data)
{
	NMKeyfileConnectionPrivate *priv = NM_KEYFILE_CONNECTION_GET_PRIVATE (connection);
	char *path = NULL;
	GError *error = NULL;

	if (!nm_keyfile_plugin_write_connection (NM_CONNECTION (connection),
	                                         priv->path,
	                                         &path,
	                                         &error)) {
		callback (connection, error, user_data);
		g_clear_error (&error);
		return;
	}

	/* Update the filename if it changed */
	if (path) {
		g_free (priv->path);
		priv->path = path;
	}

	NM_SETTINGS_CONNECTION_CLASS (nm_keyfile_connection_parent_class)->commit_changes (connection,
	                                                                                   callback,
	                                                                                   user_data);
}

static void 
do_delete (NMSettingsConnection *connection,
           NMSettingsConnectionDeleteFunc callback,
           gpointer user_data)
{
	NMKeyfileConnectionPrivate *priv = NM_KEYFILE_CONNECTION_GET_PRIVATE (connection);

	if (priv->path)
		g_unlink (priv->path);

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
	NMSettingsConnectionClass *settings_class = NM_SETTINGS_CONNECTION_CLASS (keyfile_connection_class);

	g_type_class_add_private (keyfile_connection_class, sizeof (NMKeyfileConnectionPrivate));

	/* Virtual methods */
	object_class->finalize     = finalize;
	settings_class->commit_changes = commit_changes;
	settings_class->delete = do_delete;
}
