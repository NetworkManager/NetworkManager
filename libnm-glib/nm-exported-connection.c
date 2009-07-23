/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager system settings service
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
 * (C) Copyright 2008 Novell, Inc.
 * (C) Copyright 2008 - 2009 Red Hat, Inc.
 */

#include <NetworkManager.h>
#include <dbus/dbus-glib-lowlevel.h>

#include "nm-exported-connection.h"
#include "nm-settings-connection-interface.h"

static gboolean impl_exported_connection_get_settings (NMExportedConnection *connection,
                                                       GHashTable **settings,
                                                       GError **error);

static void impl_exported_connection_update (NMExportedConnection *connection,
                                             GHashTable *new_settings,
                                             DBusGMethodInvocation *context);

static void impl_exported_connection_delete (NMExportedConnection *connection,
                                             DBusGMethodInvocation *context);

static void impl_exported_connection_get_secrets (NMExportedConnection *connection,
                                                  const gchar *setting_name,
                                                  const gchar **hints,
                                                  gboolean request_new,
                                                  DBusGMethodInvocation *context);

#include "nm-exported-connection-glue.h"

G_DEFINE_TYPE (NMExportedConnection, nm_exported_connection, NM_TYPE_CONNECTION)

#define NM_EXPORTED_CONNECTION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), \
                                               NM_TYPE_EXPORTED_CONNECTION, \
                                               NMExportedConnectionPrivate))

typedef struct {
	DBusGConnection *bus;
	gboolean disposed;
} NMExportedConnectionPrivate;

enum {
	PROP_0,
	PROP_BUS,

	LAST_PROP
};


/**************************************************************/

void
nm_exported_connection_export (NMExportedConnection *self)
{
	NMExportedConnectionPrivate *priv;
	static guint32 ec_counter = 0;
	char *path;

	g_return_if_fail (self != NULL);
	g_return_if_fail (NM_IS_EXPORTED_CONNECTION (self));

	priv = NM_EXPORTED_CONNECTION_GET_PRIVATE (self);

	/* Don't allow exporting twice */
	g_return_if_fail (nm_connection_get_path (NM_CONNECTION (self)) == NULL);

	path = g_strdup_printf ("%s/%u", NM_DBUS_PATH_SETTINGS, ec_counter++);
	nm_connection_set_path (NM_CONNECTION (self), path);
	dbus_g_connection_register_g_object (priv->bus, path, G_OBJECT (self));
	g_free (path);
}

static GHashTable *
real_get_settings (NMExportedConnection *self, GError **error)
{
	NMConnection *no_secrets;
	GHashTable *settings;

	/* Secrets should *never* be returned by the GetSettings method, they
	 * get returned by the GetSecrets method which can be better
	 * protected against leakage of secrets to unprivileged callers.
	 */
	no_secrets = nm_connection_duplicate (NM_CONNECTION (self));
	g_assert (no_secrets);
	nm_connection_clear_secrets (no_secrets);
	settings = nm_connection_to_hash (no_secrets);
	g_assert (settings);
	g_object_unref (no_secrets);

	return settings;
}

/**************************************************************/

static gboolean
impl_exported_connection_get_settings (NMExportedConnection *self,
                                       GHashTable **settings,
                                       GError **error)
{
	/* Must always be implemented */
	g_assert (NM_EXPORTED_CONNECTION_GET_CLASS (self)->get_settings);
	*settings = NM_EXPORTED_CONNECTION_GET_CLASS (self)->get_settings (self, error);
	return *settings ? TRUE : FALSE;
}

static void
impl_exported_connection_update (NMExportedConnection *self,
                                 GHashTable *new_settings,
                                 DBusGMethodInvocation *context)
{
	NMConnection *tmp;
	GError *error = NULL;

	/* Check if the settings are valid first */
	tmp = nm_connection_new_from_hash (new_settings, &error);
	if (!tmp) {
		g_assert (error);
		dbus_g_method_return_error (context, error);
		g_error_free (error);
		return;
	}
	g_object_unref (tmp);

	if (NM_EXPORTED_CONNECTION_GET_CLASS (self)->update)
		NM_EXPORTED_CONNECTION_GET_CLASS (self)->update (self, new_settings, context);
	else {
		error = g_error_new (0, 0, "%s: %s:%d update() unimplemented", __func__, __FILE__, __LINE__);
		dbus_g_method_return_error (context, error);
		g_error_free (error);
	}
}

static void
impl_exported_connection_delete (NMExportedConnection *self,
                                 DBusGMethodInvocation *context)
{
	GError *error = NULL;

	if (NM_EXPORTED_CONNECTION_GET_CLASS (self)->delete)
		NM_EXPORTED_CONNECTION_GET_CLASS (self)->delete (self, context);
	else {
		error = g_error_new (0, 0, "%s: %s:%d delete() unimplemented", __func__, __FILE__, __LINE__);
		dbus_g_method_return_error (context, error);
		g_error_free (error);
	}
}

static void
impl_exported_connection_get_secrets (NMExportedConnection *self,
                                      const gchar *setting_name,
                                      const gchar **hints,
                                      gboolean request_new,
                                      DBusGMethodInvocation *context)
{
	GError *error = NULL;

	if (NM_EXPORTED_CONNECTION_GET_CLASS (self)->get_secrets)
		NM_EXPORTED_CONNECTION_GET_CLASS (self)->get_secrets (self, setting_name, hints, request_new, context);
	else {
		error = g_error_new (0, 0, "%s: %s:%d get_secrets() unimplemented", __func__, __FILE__, __LINE__);
		dbus_g_method_return_error (context, error);
		g_error_free (error);
	}
}

/**************************************************************/

/**
 * nm_exported_connection_new:
 * @bus: a valid and connected D-Bus connection
 * @scope: the Connection scope (either user or system)
 * @path: the D-Bus path of the connection as exported by the settings service
 *  indicated by @scope
 *
 * Creates a new object representing the remote connection.
 *
 * Returns: the new exported connection object on success, or %NULL on failure
 **/
NMExportedConnection *
nm_exported_connection_new (DBusGConnection *bus,
                            NMConnectionScope scope)
{
	g_return_val_if_fail (bus != NULL, NULL);
	g_return_val_if_fail (scope != NM_CONNECTION_SCOPE_UNKNOWN, NULL);

	return (NMExportedConnection *) g_object_new (NM_TYPE_EXPORTED_CONNECTION,
	                                              NM_EXPORTED_CONNECTION_BUS, bus,
	                                              NM_CONNECTION_SCOPE, scope,
	                                              NULL);
}

static GObject *
constructor (GType type,
             guint n_construct_params,
             GObjectConstructParam *construct_params)
{
	GObject *object;
	NMExportedConnectionPrivate *priv;

	object = G_OBJECT_CLASS (nm_exported_connection_parent_class)->constructor (type, n_construct_params, construct_params);
	if (!object)
		return NULL;

	priv = NM_EXPORTED_CONNECTION_GET_PRIVATE (object);
	g_assert (priv->bus);

	return object;
}

static void
nm_exported_connection_init (NMExportedConnection *self)
{
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMExportedConnectionPrivate *priv = NM_EXPORTED_CONNECTION_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_BUS:
		/* Construct only */
		priv->bus = dbus_g_connection_ref ((DBusGConnection *) g_value_get_boxed (value));
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
	NMExportedConnectionPrivate *priv = NM_EXPORTED_CONNECTION_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_BUS:
		g_value_set_boxed (value, priv->bus);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
dispose (GObject *object)
{
	NMExportedConnectionPrivate *priv = NM_EXPORTED_CONNECTION_GET_PRIVATE (object);

	if (!priv->disposed) {
		priv->disposed = TRUE;
		dbus_g_connection_unref (priv->bus);
	}

	G_OBJECT_CLASS (nm_exported_connection_parent_class)->dispose (object);
}

static void
nm_exported_connection_class_init (NMExportedConnectionClass *class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (class);

	g_type_class_add_private (class, sizeof (NMExportedConnectionPrivate));

	/* Virtual methods */
	object_class->dispose = dispose;
	object_class->constructor = constructor;
	object_class->get_property = get_property;
	object_class->set_property = set_property;

	class->get_settings = real_get_settings;

	/**
	 * NMExportedConnection:bus:
	 *
	 * The %DBusGConnection which this object is exported on
	 **/
	g_object_class_install_property (object_class, PROP_BUS,
	                                 g_param_spec_boxed (NM_EXPORTED_CONNECTION_BUS,
	                                                     "Bus",
	                                                     "Bus",
	                                                     DBUS_TYPE_G_CONNECTION,
	                                                     G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (class),
	                                 &dbus_glib_nm_exported_connection_object_info);
}
