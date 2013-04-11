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
 * Copyright (C) 2012 Red Hat, Inc.
 */

#include <string.h>
#include <glib/gstdio.h>
#include <NetworkManager.h>
#include <nm-setting-connection.h>
#include <nm-utils.h>

#include "nm-system-config-interface.h"
#include "nm-dbus-glib-types.h"
#include "nm-example-connection.h"
#include "common.h"

/* GObject boilerplate; this object is a subclass of NMSettingsConnection
 * which is specified by the NM_TYPE_SETTINGS_CONNECTION bit here.  That
 * in turn is a subclass of NMConnection, so it ends up that NMExampleConnection
 * is a subclass of NMConnection too.
 */
G_DEFINE_TYPE (NMExampleConnection, nm_example_connection, NM_TYPE_SETTINGS_CONNECTION)

#define NM_EXAMPLE_CONNECTION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_EXAMPLE_CONNECTION, NMExampleConnectionPrivate))

/* Object private instance data */
typedef struct {
	char *path;
} NMExampleConnectionPrivate;


/* Creates a new object which encapsulates an on-disk connection and any
 * plugin-specific operations or data.
 */
NMExampleConnection *
nm_example_connection_new (const char *full_path,
                           NMConnection *source,
                           GError **error)
{
	GObject *object;
	NMExampleConnectionPrivate *priv;
	NMConnection *tmp;
	const char *uuid;

	g_return_val_if_fail (full_path != NULL, NULL);

	/* If we're given a connection already, prefer that instead of re-reading */
	if (source)
		tmp = g_object_ref (source);
	else {
		/* Read the data offdisk and translate it into a simple NMConnection object */
		tmp = connection_from_file (full_path, error);
		if (!tmp)
			return NULL;
	}

	/* Actually create the new NMExampleConnection object */
	object = (GObject *) g_object_new (NM_TYPE_EXAMPLE_CONNECTION, NULL);
	priv = NM_EXAMPLE_CONNECTION_GET_PRIVATE (object);
	priv->path = g_strdup (full_path);

	/* Update our settings with what was read from the file or what got passed
	 * in as a source NMConnection.
	 */
	if (!nm_settings_connection_replace_settings (NM_SETTINGS_CONNECTION (object),
	                                              tmp,
	                                              TRUE,
	                                              error)) {
		g_object_unref (object);
		object = NULL;
		goto out;
	}

	/* Make sure we have a UUID; just a sanity check */
	uuid = nm_connection_get_uuid (NM_CONNECTION (object));
	if (!uuid) {
		g_set_error (error, EXAMPLE_PLUGIN_ERROR, 0,
		             "Connection in file %s had no UUID", full_path);
		g_object_unref (object);
		object = NULL;
	}

out:
	g_object_unref (tmp);
	return (NMExampleConnection *) object;
}

const char *
nm_example_connection_get_path (NMExampleConnection *self)
{
	g_return_val_if_fail (NM_IS_EXAMPLE_CONNECTION (self), NULL);

	/* Simple accessor that returns the file path from our private instance data */
	return NM_EXAMPLE_CONNECTION_GET_PRIVATE (self)->path;
}

static void
commit_changes (NMSettingsConnection *connection,
                NMSettingsConnectionCommitFunc callback,
                gpointer user_data)
{
	NMExampleConnectionPrivate *priv = NM_EXAMPLE_CONNECTION_GET_PRIVATE (connection);
	char *path = NULL;
	GError *error = NULL;

	/* Write the new connection data out to disk.  This function passes
	 * back the path of the file it wrote out so that we know what that
	 * path is if the connection is a completely new one.
	 */
	if (!write_connection (NM_CONNECTION (connection), priv->path, &path, &error)) {
		callback (connection, error, user_data);
		g_clear_error (&error);
		return;
	}

	/* Update the filename if it changed */
	if (path) {
		g_free (priv->path);
		priv->path = path;
	}

	/* Chain up to parent for generic commit stuff */
	NM_SETTINGS_CONNECTION_CLASS (nm_example_connection_parent_class)->commit_changes (connection,
	                                                                                   callback,
	                                                                                   user_data);
}

static void 
do_delete (NMSettingsConnection *connection,
           NMSettingsConnectionDeleteFunc callback,
           gpointer user_data)
{
	NMExampleConnectionPrivate *priv = NM_EXAMPLE_CONNECTION_GET_PRIVATE (connection);

	g_unlink (priv->path);

	/* Chain up to parent for generic deletion stuff */
	NM_SETTINGS_CONNECTION_CLASS (nm_example_connection_parent_class)->delete (connection,
	                                                                           callback,
	                                                                           user_data);
}

/**************************************************************/

static void
nm_example_connection_init (NMExampleConnection *connection)
{
}

static void
finalize (GObject *object)
{
	NMExampleConnectionPrivate *priv = NM_EXAMPLE_CONNECTION_GET_PRIVATE (object);

	/* Zero out any secrets so we don't leave them in memory */
	nm_connection_clear_secrets (NM_CONNECTION (object));

	g_free (priv->path);

	G_OBJECT_CLASS (nm_example_connection_parent_class)->finalize (object);
}

static void
nm_example_connection_class_init (NMExampleConnectionClass *keyfile_connection_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (keyfile_connection_class);
	NMSettingsConnectionClass *settings_class = NM_SETTINGS_CONNECTION_CLASS (keyfile_connection_class);

	/* Tells GObject to allocate and zero our instance data pointer */
	g_type_class_add_private (keyfile_connection_class, sizeof (NMExampleConnectionPrivate));

	/* Overrides of various superclass methods */
	object_class->finalize = finalize;
	settings_class->commit_changes = commit_changes;
	settings_class->delete = do_delete;
}
