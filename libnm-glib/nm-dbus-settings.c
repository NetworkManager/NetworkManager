/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * libnm_glib -- Access network status & information from glib applications
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2008 Novell, Inc.
 */

#include <string.h>
#include <NetworkManager.h>
#include <nm-connection.h>

#include "nm-dbus-settings.h"
#include "nm-settings-bindings.h"

G_DEFINE_TYPE (NMDBusSettings, nm_dbus_settings, NM_TYPE_SETTINGS)

#define NM_DBUS_SETTINGS_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DBUS_SETTINGS, NMDBusSettingsPrivate))

typedef struct {
	DBusGConnection *dbus_connection;
	NMConnectionScope scope;
	DBusGProxy *settings_proxy;
	DBusGProxy *dbus_proxy;

	GHashTable *connections;

	gboolean disposed;
} NMDBusSettingsPrivate;

enum {
	PROP_0,
	PROP_DBUS_CONNECTION,
	PROP_SCOPE,

	LAST_PROP
};

NMDBusSettings *
nm_dbus_settings_new (DBusGConnection *dbus_connection)
{
	g_return_val_if_fail (dbus_connection != NULL, NULL);

	return (NMDBusSettings *) g_object_new (NM_TYPE_DBUS_SETTINGS,
									NM_DBUS_SETTINGS_DBUS_CONNECTION, dbus_connection,
									NM_DBUS_SETTINGS_SCOPE, NM_CONNECTION_SCOPE_USER,
									NULL);
}

NMDBusConnection *
nm_dbus_settings_get_connection_by_path (NMDBusSettings *self, const char *path)
{
	g_return_val_if_fail (NM_IS_DBUS_SETTINGS (self), NULL);
	g_return_val_if_fail (path != NULL, NULL);

	return g_hash_table_lookup (NM_DBUS_SETTINGS_GET_PRIVATE (self)->connections, path);
}

static void
connection_removed_cb (NMExportedConnection *exported, gpointer user_data)
{
	NMDBusSettingsPrivate *priv = NM_DBUS_SETTINGS_GET_PRIVATE (user_data);
	NMConnection *connection;

	connection = nm_exported_connection_get_connection (exported);
	g_hash_table_remove (priv->connections, nm_connection_get_path (connection));
}

static void
new_connection_cb (DBusGProxy *proxy,
                   const char *path,
                   gpointer user_data)
{
	NMDBusSettingsPrivate *priv = NM_DBUS_SETTINGS_GET_PRIVATE (user_data);
	NMDBusConnection *connection;

	connection = nm_dbus_connection_new (priv->dbus_connection, priv->scope, path);
	if (connection) {
		g_signal_connect (connection, "removed",
					   G_CALLBACK (connection_removed_cb),
					   user_data);

		g_hash_table_insert (priv->connections, g_strdup (path), connection);
		nm_settings_signal_new_connection (NM_SETTINGS (user_data),
									NM_EXPORTED_CONNECTION (connection));
	}
}

static void
fetch_connections_done (DBusGProxy *proxy,
				    GPtrArray *connections,
				    GError *err,
				    gpointer user_data)
{
	if (!err) {
		int i;

		for (i = 0; i < connections->len; i++) {
			char *path = g_ptr_array_index (connections, i);

			new_connection_cb (proxy, path, user_data);
			g_free (path);
		}

		g_ptr_array_free (connections, TRUE);
	} else {
		g_warning ("Could not retrieve dbus connections: %s.", err->message);
		g_error_free (err);
	}
}

static void
settings_proxy_destroyed (gpointer data, GObject *destroyed_object)
{
	NM_DBUS_SETTINGS_GET_PRIVATE (data)->settings_proxy = NULL;
}

static gboolean
fetch_connections (gpointer data)
{
	NMDBusSettingsPrivate *priv = NM_DBUS_SETTINGS_GET_PRIVATE (data);
	DBusGProxyCall *call;

	if (!priv->settings_proxy) {
		const char *service = (priv->scope == NM_CONNECTION_SCOPE_SYSTEM) ? 
			NM_DBUS_SERVICE_SYSTEM_SETTINGS : NM_DBUS_SERVICE_USER_SETTINGS;

		priv->settings_proxy = dbus_g_proxy_new_for_name (priv->dbus_connection,
												service,
												NM_DBUS_PATH_SETTINGS,
												NM_DBUS_IFACE_SETTINGS);

		g_object_weak_ref (G_OBJECT (priv->settings_proxy), settings_proxy_destroyed, data);

		dbus_g_proxy_add_signal (priv->settings_proxy, "NewConnection",
		                         DBUS_TYPE_G_OBJECT_PATH,
		                         G_TYPE_INVALID);

		dbus_g_proxy_connect_signal (priv->settings_proxy, "NewConnection",
		                             G_CALLBACK (new_connection_cb),
		                             data,
		                             NULL);
	}

	call = org_freedesktop_NetworkManagerSettings_list_connections_async (priv->settings_proxy,
															fetch_connections_done,
															data);

	return FALSE;
}

static void
hash_values_to_slist (gpointer key, gpointer data, gpointer user_data)
{
	GSList **list = (GSList **) user_data;

	*list = g_slist_prepend (*list, data);
}

static GSList *
list_connections (NMSettings *settings)
{
	GSList *list = NULL;

	g_return_val_if_fail (NM_IS_DBUS_SETTINGS (settings), NULL);

	g_hash_table_foreach (NM_DBUS_SETTINGS_GET_PRIVATE (settings)->connections, hash_values_to_slist, &list);

	return list;
}

static void
remove_one_connection (gpointer key, gpointer value, gpointer user_data)
{
	nm_exported_connection_signal_removed (NM_EXPORTED_CONNECTION (value));
}

static gboolean
remove_connections (gpointer data)
{
	NMDBusSettings *self = NM_DBUS_SETTINGS (data);
	NMDBusSettingsPrivate *priv = NM_DBUS_SETTINGS_GET_PRIVATE (self);

	g_hash_table_foreach (priv->connections, remove_one_connection, NULL);

	return FALSE;
}

static void
name_owner_changed (DBusGProxy *proxy,
				const char *name,
				const char *old_owner,
				const char *new_owner,
				gpointer user_data)
{
	if (!strcmp (name, NM_DBUS_SERVICE_SYSTEM_SETTINGS)) {
		if (new_owner && strlen (new_owner) > 0)
			g_idle_add (fetch_connections, user_data);
		else
			g_idle_add (remove_connections, user_data);
	}
}

/* GObject stuff */

static void
nm_dbus_settings_init (NMDBusSettings *settings)
{
	NMDBusSettingsPrivate *priv = NM_DBUS_SETTINGS_GET_PRIVATE (settings);

	priv->connections = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_object_unref);
}

static GObject *
constructor (GType type,
		   guint n_construct_params,
		   GObjectConstructParam *construct_params)
{
	GObject *object;
	NMDBusSettingsPrivate *priv;

	object = G_OBJECT_CLASS (nm_dbus_settings_parent_class)->constructor (type, n_construct_params, construct_params);

	if (!object)
		return NULL;

	priv = NM_DBUS_SETTINGS_GET_PRIVATE (object);

	if (!priv->dbus_connection) {
		g_warning ("DBus connection not provided.");
		goto err;
	}

	if (priv->scope == NM_CONNECTION_SCOPE_UNKNOWN) {
		g_warning ("Connection scope not provided.");
		goto err;
	}

	priv->dbus_proxy = dbus_g_proxy_new_for_name (priv->dbus_connection,
										 "org.freedesktop.DBus",
										 "/org/freedesktop/DBus",
										 "org.freedesktop.DBus");

	dbus_g_proxy_add_signal (priv->dbus_proxy, "NameOwnerChanged",
						G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
						G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->dbus_proxy,
						    "NameOwnerChanged",
						    G_CALLBACK (name_owner_changed),
						    object, NULL);

	g_idle_add (fetch_connections, object);

	return object;

 err:
	g_object_unref (object);

	return NULL;
}

static void
dispose (GObject *object)
{
	NMDBusSettingsPrivate *priv = NM_DBUS_SETTINGS_GET_PRIVATE (object);

	if (priv->disposed)
		return;

	priv->disposed = TRUE;

	if (priv->connections)
		g_hash_table_destroy (priv->connections);

	if (priv->dbus_proxy)
		g_object_unref (priv->dbus_proxy);

	if (priv->settings_proxy)
		g_object_unref (priv->settings_proxy);

	dbus_g_connection_unref (priv->dbus_connection);

	G_OBJECT_CLASS (nm_dbus_settings_parent_class)->dispose (object);
}

static void
set_property (GObject *object, guint prop_id,
		    const GValue *value, GParamSpec *pspec)
{
	NMDBusSettingsPrivate *priv = NM_DBUS_SETTINGS_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_DBUS_CONNECTION:
		/* Construct only */
		priv->dbus_connection = dbus_g_connection_ref ((DBusGConnection *) g_value_get_boxed (value));
		break;
	case PROP_SCOPE:
		priv->scope = (NMConnectionScope) g_value_get_uint (value);
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
	NMDBusSettingsPrivate *priv = NM_DBUS_SETTINGS_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_DBUS_CONNECTION:
		g_value_set_boxed (value, priv->dbus_connection);
		break;
	case PROP_SCOPE:
		g_value_set_uint (value, priv->scope);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_dbus_settings_class_init (NMDBusSettingsClass *dbus_settings_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (dbus_settings_class);
	NMSettingsClass *settings_class = NM_SETTINGS_CLASS (dbus_settings_class);

	g_type_class_add_private (dbus_settings_class, sizeof (NMDBusSettingsPrivate));

	/* Virtual methods */
	object_class->constructor = constructor;
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->dispose = dispose;

	settings_class->list_connections = list_connections;

	/* Properties */
	g_object_class_install_property
		(object_class, PROP_DBUS_CONNECTION,
		 g_param_spec_boxed (NM_DBUS_SETTINGS_DBUS_CONNECTION,
						 "DBusGConnection",
						 "DBusGConnection",
						 DBUS_TYPE_G_CONNECTION,
						 G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property
		(object_class, PROP_SCOPE,
		 g_param_spec_uint (NM_DBUS_SETTINGS_SCOPE,
						"Scope",
						"NMConnection scope",
						NM_CONNECTION_SCOPE_UNKNOWN,
						NM_CONNECTION_SCOPE_USER,
						NM_CONNECTION_SCOPE_USER,
						G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
}
