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
 * Copyright (C) 2008 Red Hat, Inc.
 */

#include <string.h>
#include <NetworkManager.h>
#include <nm-dbus-glib-types.h>
#include "nm-dbus-connection.h"
#include "nm-exported-connection-bindings.h"
#include "nm-utils.h"

G_DEFINE_TYPE (NMDBusConnection, nm_dbus_connection, NM_TYPE_EXPORTED_CONNECTION)

#define NM_DBUS_CONNECTION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DBUS_CONNECTION, NMDBusConnectionPrivate))

typedef struct {
	DBusGConnection *dbus_connection;
	NMConnectionScope scope;
	char *path;

	DBusGProxy *proxy;

	gboolean disposed;
} NMDBusConnectionPrivate;

enum {
	PROP_0,
	PROP_BUS,
	PROP_SCOPE,
	PROP_PATH,

	LAST_PROP
};

NMDBusConnection *
nm_dbus_connection_new (DBusGConnection *dbus_connection,
				    NMConnectionScope scope,
				    const char *path)
{
	g_return_val_if_fail (dbus_connection != NULL, NULL);
	g_return_val_if_fail (scope != NM_CONNECTION_SCOPE_UNKNOWN, NULL);
	g_return_val_if_fail (path != NULL, NULL);

	return (NMDBusConnection *) g_object_new (NM_TYPE_DBUS_CONNECTION,
									  NM_DBUS_CONNECTION_BUS, dbus_connection,
									  NM_DBUS_CONNECTION_SCOPE, scope,
									  NM_DBUS_CONNECTION_PATH, path,
									  NULL);
}

static GHashTable *
get_settings (NMExportedConnection *exported)
{
	return nm_connection_to_hash (nm_exported_connection_get_connection (exported));
}

static gboolean
update (NMExportedConnection *exported, GHashTable *new_settings, GError **err)
{
	NMDBusConnectionPrivate *priv = NM_DBUS_CONNECTION_GET_PRIVATE (exported);

	return org_freedesktop_NetworkManagerSettings_Connection_update (priv->proxy, new_settings, err);
}

static gboolean
delete (NMExportedConnection *exported, GError **err)
{
	NMDBusConnectionPrivate *priv = NM_DBUS_CONNECTION_GET_PRIVATE (exported);

	return org_freedesktop_NetworkManagerSettings_Connection_delete (priv->proxy, err);
}

static void
connection_updated_cb (DBusGProxy *proxy, GHashTable *settings, gpointer user_data)
{
	NMExportedConnection *exported = NM_EXPORTED_CONNECTION (user_data);
	NMConnection *wrapped;

	wrapped = nm_exported_connection_get_connection (exported);
	if (nm_connection_replace_settings (wrapped, settings))
		nm_exported_connection_signal_updated (exported, settings);
	else
		nm_exported_connection_signal_removed (exported);
}

static void
connection_removed_cb (DBusGProxy *proxy, gpointer user_data)
{
	nm_exported_connection_signal_removed (NM_EXPORTED_CONNECTION (user_data));
}

/* GObject */

static void
nm_dbus_connection_init (NMDBusConnection *connection)
{
}

static GObject *
constructor (GType type,
		   guint n_construct_params,
		   GObjectConstructParam *construct_params)
{
	GObject *object;
	NMDBusConnectionPrivate *priv;
	NMConnection *wrapped;
	const char *service;
	GHashTable *settings = NULL;
	GError *error = NULL;

	object = G_OBJECT_CLASS (nm_dbus_connection_parent_class)->constructor (type, n_construct_params, construct_params);

	if (!object)
		return NULL;

	priv = NM_DBUS_CONNECTION_GET_PRIVATE (object);

	if (!priv->dbus_connection) {
		nm_warning ("DBusGConnection not provided.");
		goto err;
	}

	if (!priv->path)
		nm_warning ("DBus path not provided.");

	service = (priv->scope == NM_CONNECTION_SCOPE_SYSTEM) ?
		NM_DBUS_SERVICE_SYSTEM_SETTINGS : NM_DBUS_SERVICE_USER_SETTINGS;

	priv->proxy = dbus_g_proxy_new_for_name (priv->dbus_connection,
									 service,
									 priv->path,
									 NM_DBUS_IFACE_SETTINGS_CONNECTION);

	if (!org_freedesktop_NetworkManagerSettings_Connection_get_settings (priv->proxy, &settings, &error)) {
		nm_warning ("Can not retrieve settings: %s", error->message);
		g_error_free (error);
		goto err;
	}

	wrapped = nm_connection_new_from_hash (settings, &error);
	g_hash_table_destroy (settings);

	if (!wrapped) {
		nm_warning ("Invalid connection: '%s' / '%s' invalid: %d",
		            g_type_name (nm_connection_lookup_setting_type_by_quark (error->domain)),
		            error->message,
		            error->code);
		g_error_free (error);
		goto err;
	}

	nm_connection_set_scope (wrapped, priv->scope);
	nm_connection_set_path (wrapped, priv->path);

	g_object_set (object, NM_EXPORTED_CONNECTION_CONNECTION, wrapped, NULL);
	g_object_unref (wrapped);

	dbus_g_proxy_add_signal (priv->proxy, "Updated",
						DBUS_TYPE_G_MAP_OF_MAP_OF_VARIANT,
						G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->proxy, "Updated",
						    G_CALLBACK (connection_updated_cb),
						    object, NULL);

	dbus_g_proxy_add_signal (priv->proxy, "Removed", G_TYPE_INVALID, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->proxy, "Removed",
						    G_CALLBACK (connection_removed_cb),
						    object, NULL);

	return object;

 err:
	g_object_unref (object);

	return NULL;
}

static void
dispose (GObject *object)
{
	NMDBusConnectionPrivate *priv = NM_DBUS_CONNECTION_GET_PRIVATE (object);

	if (priv->disposed)
		return;

	priv->disposed = TRUE;

	g_object_unref (priv->proxy);
	dbus_g_connection_unref (priv->dbus_connection);

	G_OBJECT_CLASS (nm_dbus_connection_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMDBusConnectionPrivate *priv = NM_DBUS_CONNECTION_GET_PRIVATE (object);

	g_free (priv->path);

	G_OBJECT_CLASS (nm_dbus_connection_parent_class)->finalize (object);
}

static void
set_property (GObject *object, guint prop_id,
		    const GValue *value, GParamSpec *pspec)
{
	NMDBusConnectionPrivate *priv = NM_DBUS_CONNECTION_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_BUS:
		/* Construct only */
		priv->dbus_connection = dbus_g_connection_ref ((DBusGConnection *) g_value_get_boxed (value));
		break;
	case PROP_SCOPE:
		/* Construct only */
		priv->scope = (NMConnectionScope) g_value_get_uint (value);
		break;
	case PROP_PATH:
		/* Construct only */
		priv->path = g_value_dup_string (value);
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
	NMDBusConnectionPrivate *priv = NM_DBUS_CONNECTION_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_BUS:
		g_value_set_boxed (value, priv->dbus_connection);
		break;
	case PROP_SCOPE:
		g_value_set_uint (value, priv->scope);
		break;
	case PROP_PATH:
		g_value_set_string (value, priv->path);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_dbus_connection_class_init (NMDBusConnectionClass *dbus_connection_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (dbus_connection_class);
	NMExportedConnectionClass *connection_class = NM_EXPORTED_CONNECTION_CLASS (dbus_connection_class);

	g_type_class_add_private (dbus_connection_class, sizeof (NMDBusConnectionPrivate));

	/* Virtual methods */
	object_class->constructor  = constructor;
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->dispose      = dispose;
	object_class->finalize     = finalize;

	connection_class->get_settings = get_settings;
	connection_class->update       = update;
	connection_class->delete       = delete;

	/* Properties */
	g_object_class_install_property
		(object_class, PROP_BUS,
		 g_param_spec_boxed (NM_DBUS_CONNECTION_BUS,
						 "DBusGConnection",
						 "DBusGConnection",
						 DBUS_TYPE_G_CONNECTION,
						 G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property
		(object_class, PROP_SCOPE,
		 g_param_spec_uint (NM_DBUS_CONNECTION_SCOPE,
						"Scope",
						"NMConnection scope",
						NM_CONNECTION_SCOPE_UNKNOWN,
						NM_CONNECTION_SCOPE_USER,
						NM_CONNECTION_SCOPE_UNKNOWN,
						G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property
		(object_class, PROP_PATH,
		 g_param_spec_string (NM_DBUS_CONNECTION_PATH,
						  "DBus path",
						  "DBus path",
						  NULL,
						  G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
}
