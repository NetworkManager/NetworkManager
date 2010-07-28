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
#include <nm-setting-connection.h>
#include <nm-utils.h>
#include <nm-settings-connection-interface.h>

#include "nm-dbus-glib-types.h"
#include "nm-keyfile-connection.h"
#include "reader.h"
#include "writer.h"

static NMSettingsConnectionInterface *parent_settings_connection_iface;

static void settings_connection_interface_init (NMSettingsConnectionInterface *klass);

G_DEFINE_TYPE_EXTENDED (NMKeyfileConnection, nm_keyfile_connection, NM_TYPE_SYSCONFIG_CONNECTION, 0,
                        G_IMPLEMENT_INTERFACE (NM_TYPE_SETTINGS_CONNECTION_INTERFACE,
                                               settings_connection_interface_init))

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
update (NMSettingsConnectionInterface *connection,
	    NMSettingsConnectionInterfaceUpdateFunc callback,
	    gpointer user_data)
{
	NMKeyfileConnectionPrivate *priv = NM_KEYFILE_CONNECTION_GET_PRIVATE (connection);
	char *filename = NULL;
	GError *error = NULL;

	if (!write_connection (NM_CONNECTION (connection), KEYFILE_DIR, 0, 0, &filename, &error)) {
		callback (connection, error, user_data);
		g_clear_error (&error);
		return FALSE;
	}

	if (g_strcmp0 (priv->filename, filename)) {
		/* Update the filename if it changed */
		g_free (priv->filename);
		priv->filename = filename;
	} else
		g_free (filename);

	return parent_settings_connection_iface->update (connection, callback, user_data);
}

static gboolean 
do_delete (NMSettingsConnectionInterface *connection,
	       NMSettingsConnectionInterfaceDeleteFunc callback,
	       gpointer user_data)
{
	NMKeyfileConnectionPrivate *priv = NM_KEYFILE_CONNECTION_GET_PRIVATE (connection);

	g_unlink (priv->filename);

	return parent_settings_connection_iface->delete (connection, callback, user_data);
}

/* GObject */

static void
settings_connection_interface_init (NMSettingsConnectionInterface *iface)
{
	parent_settings_connection_iface = g_type_interface_peek_parent (iface);
	iface->update = update;
	iface->delete = do_delete;
}

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
	NMSettingConnection *s_con;
	NMConnection *tmp;

	object = G_OBJECT_CLASS (nm_keyfile_connection_parent_class)->constructor (type, n_construct_params, construct_params);

	if (!object)
		return NULL;

	priv = NM_KEYFILE_CONNECTION_GET_PRIVATE (object);

	g_assert (priv->filename);

	tmp = connection_from_file (priv->filename);
	if (!tmp) {
		g_object_unref (object);
		return NULL;
	}
	
	nm_sysconfig_connection_update (NM_SYSCONFIG_CONNECTION (object), tmp, FALSE, NULL);
	g_object_unref (tmp);

	/* if for some reason the connection didn't have a UUID, add one */
	s_con = (NMSettingConnection *) nm_connection_get_setting (NM_CONNECTION (object), NM_TYPE_SETTING_CONNECTION);
	if (s_con && !nm_setting_connection_get_uuid (s_con)) {
		GError *error = NULL;
		char *uuid;

		uuid = nm_utils_uuid_generate ();
		g_object_set (s_con, NM_SETTING_CONNECTION_UUID, uuid, NULL);
		g_free (uuid);

		if (!write_connection (NM_CONNECTION (object), KEYFILE_DIR, 0, 0, NULL, &error)) {
			g_warning ("Couldn't update connection %s with a UUID: (%d) %s",
			           nm_setting_connection_get_id (s_con),
			           error ? error->code : 0,
			           (error && error->message) ? error->message : "unknown");
			g_error_free (error);
		}
	}

	return object;
}

static void
finalize (GObject *object)
{
	NMKeyfileConnectionPrivate *priv = NM_KEYFILE_CONNECTION_GET_PRIVATE (object);

	nm_connection_clear_secrets (NM_CONNECTION (object));

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

	g_type_class_add_private (keyfile_connection_class, sizeof (NMKeyfileConnectionPrivate));

	/* Virtual methods */
	object_class->constructor  = constructor;
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize     = finalize;

	/* Properties */
	g_object_class_install_property
		(object_class, PROP_FILENAME,
		 g_param_spec_string (NM_KEYFILE_CONNECTION_FILENAME,
						  "FileName",
						  "File name",
						  NULL,
						  G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
}
