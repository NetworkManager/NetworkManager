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
 * Copyright (C) 2008 Red Hat, Inc.
 */

#include <string.h>
#include <glib/gstdio.h>
#include <NetworkManager.h>
#include <nm-settings.h>
#include <nm-setting-connection.h>
#include <nm-utils.h>

#include "nm-dbus-glib-types.h"
#include "nm-keyfile-connection.h"
#include "reader.h"
#include "writer.h"

G_DEFINE_TYPE (NMKeyfileConnection, nm_keyfile_connection, NM_TYPE_SYSCONFIG_CONNECTION)

#define NM_KEYFILE_CONNECTION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_KEYFILE_CONNECTION, NMKeyfileConnectionPrivate))

typedef struct {
	char *filename;
} NMKeyfileConnectionPrivate;

enum {
	PROP_0,
	PROP_FILENAME,

	LAST_PROP
};

NMKeyfileConnection *
nm_keyfile_connection_new (const char *filename)
{
	g_return_val_if_fail (filename != NULL, NULL);

	return (NMKeyfileConnection *) g_object_new (NM_TYPE_KEYFILE_CONNECTION,
	                                             NM_KEYFILE_CONNECTION_FILENAME, filename,
	                                             NULL);
}

const char *
nm_keyfile_connection_get_filename (NMKeyfileConnection *self)
{
	g_return_val_if_fail (NM_IS_KEYFILE_CONNECTION (self), NULL);

	return NM_KEYFILE_CONNECTION_GET_PRIVATE (self)->filename;
}

static gboolean
update (NMExportedConnection *exported,
        GHashTable *new_settings,
        GError **error)
{
	NMKeyfileConnectionPrivate *priv = NM_KEYFILE_CONNECTION_GET_PRIVATE (exported);
	gboolean success;

	success = NM_EXPORTED_CONNECTION_CLASS (nm_keyfile_connection_parent_class)->update (exported, new_settings, error);
	if (success) {
		NMConnection *connection;
		char *filename = NULL;

		connection = nm_exported_connection_get_connection (exported);
		success = nm_connection_replace_settings (connection, new_settings, error);
		if (success) {
			success = write_connection (connection, KEYFILE_DIR, 0, 0, &filename, error);
			if (success && filename && strcmp (priv->filename, filename)) {
				/* Update the filename if it changed */
				g_free (priv->filename);
				priv->filename = filename;
			} else
				g_free (filename);
		}
	}

	return success;
}

static gboolean
do_delete (NMExportedConnection *exported, GError **err)
{
	NMKeyfileConnectionPrivate *priv = NM_KEYFILE_CONNECTION_GET_PRIVATE (exported);
	gboolean success;

	success = NM_EXPORTED_CONNECTION_CLASS (nm_keyfile_connection_parent_class)->do_delete (exported, err);

	if (success)
		g_unlink (priv->filename);

	return success;
}

/* GObject */

static void
nm_keyfile_connection_init (NMKeyfileConnection *connection)
{
}

static GObject *
constructor (GType type,
		   guint n_construct_params,
		   GObjectConstructParam *construct_params)
{
	GObject *object;
	NMKeyfileConnectionPrivate *priv;
	NMConnection *wrapped;
	NMSettingConnection *s_con;

	object = G_OBJECT_CLASS (nm_keyfile_connection_parent_class)->constructor (type, n_construct_params, construct_params);

	if (!object)
		return NULL;

	priv = NM_KEYFILE_CONNECTION_GET_PRIVATE (object);

	if (!priv->filename) {
		g_warning ("Keyfile file name not provided.");
		goto err;
	}

	wrapped = connection_from_file (priv->filename);
	if (!wrapped)
		goto err;

	/* if for some reason the connection didn't have a UUID, add one */
	s_con = (NMSettingConnection *) nm_connection_get_setting (wrapped, NM_TYPE_SETTING_CONNECTION);
	if (s_con && !nm_setting_connection_get_uuid (s_con)) {
		GError *error = NULL;
		char *uuid;

		uuid = nm_utils_uuid_generate ();
		g_object_set (s_con, NM_SETTING_CONNECTION_UUID, uuid, NULL);
		g_free (uuid);

		if (!write_connection (wrapped, KEYFILE_DIR, 0, 0, NULL, &error)) {
			g_warning ("Couldn't update connection %s with a UUID: (%d) %s",
			           nm_setting_connection_get_id (s_con), error ? error->code : 0,
			           error ? error->message : "unknown");
			g_error_free (error);
		}
	}

	g_object_set (object, NM_EXPORTED_CONNECTION_CONNECTION, wrapped, NULL);
	g_object_unref (wrapped);

	return object;

 err:
	g_object_unref (object);

	return NULL;
}

static void
finalize (GObject *object)
{
	NMKeyfileConnectionPrivate *priv = NM_KEYFILE_CONNECTION_GET_PRIVATE (object);

	g_free (priv->filename);

	G_OBJECT_CLASS (nm_keyfile_connection_parent_class)->finalize (object);
}

static void
set_property (GObject *object, guint prop_id,
		    const GValue *value, GParamSpec *pspec)
{
	NMKeyfileConnectionPrivate *priv = NM_KEYFILE_CONNECTION_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_FILENAME:
		/* Construct only */
		priv->filename = g_value_dup_string (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
get_property (GObject *object, guint prop_id,
		    GValue *value, GParamSpec *pspec)
{
	NMKeyfileConnectionPrivate *priv = NM_KEYFILE_CONNECTION_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_FILENAME:
		g_value_set_string (value, priv->filename);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_keyfile_connection_class_init (NMKeyfileConnectionClass *keyfile_connection_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (keyfile_connection_class);
	NMExportedConnectionClass *connection_class = NM_EXPORTED_CONNECTION_CLASS (keyfile_connection_class);

	g_type_class_add_private (keyfile_connection_class, sizeof (NMKeyfileConnectionPrivate));

	/* Virtual methods */
	object_class->constructor  = constructor;
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize     = finalize;

	connection_class->update       = update;
	connection_class->do_delete    = do_delete;

	/* Properties */
	g_object_class_install_property
		(object_class, PROP_FILENAME,
		 g_param_spec_string (NM_KEYFILE_CONNECTION_FILENAME,
						  "FileName",
						  "File name",
						  NULL,
						  G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
}
