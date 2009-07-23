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

#include "nm-settings-service.h"
#include "nm-settings-interface.h"
#include "nm-exported-connection.h"

static gboolean impl_settings_list_connections (NMSettingsService *self,
                                                GPtrArray **connections,
                                                GError **error);

static void impl_settings_add_connection (NMSettingsService *self,
                                          GHashTable *settings,
                                          DBusGMethodInvocation *context);

#include "nm-settings-glue.h"

static void settings_interface_init (NMSettingsInterface *class);

G_DEFINE_TYPE_EXTENDED (NMSettingsService, nm_settings_service, G_TYPE_OBJECT, G_TYPE_FLAG_ABSTRACT,
                        G_IMPLEMENT_INTERFACE (NM_TYPE_SETTINGS_INTERFACE, settings_interface_init))

#define NM_SETTINGS_SERVICE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), \
                                            NM_TYPE_SETTINGS_SERVICE, \
                                            NMSettingsServicePrivate))

typedef struct {
	DBusGConnection *bus;
	NMConnectionScope scope;
	gboolean exported;

	gboolean disposed;
} NMSettingsServicePrivate;

enum {
	PROP_0,
	PROP_BUS,
	PROP_SCOPE,

	LAST_PROP
};


/**************************************************************/

void
nm_settings_service_export (NMSettingsService *self)
{
	NMSettingsServicePrivate *priv;

	g_return_if_fail (self != NULL);
	g_return_if_fail (NM_IS_SETTINGS_SERVICE (self));

	priv = NM_SETTINGS_SERVICE_GET_PRIVATE (self);

	g_return_if_fail (priv->bus != NULL);

	/* Don't allow exporting twice */
	g_return_if_fail (priv->exported == FALSE);

	dbus_g_connection_register_g_object (priv->bus,
	                                     NM_DBUS_PATH_SETTINGS,
	                                     G_OBJECT (self));
	priv->exported = TRUE;
}

/**************************************************************/

static GSList *
list_connections (NMSettingsInterface *settings)
{
	/* Must always be implemented */
	g_assert (NM_SETTINGS_SERVICE_GET_CLASS (settings)->list_connections);
	return NM_SETTINGS_SERVICE_GET_CLASS (settings)->list_connections (NM_SETTINGS_SERVICE (settings));
}

static gboolean
impl_settings_list_connections (NMSettingsService *self,
                                GPtrArray **connections,
                                GError **error)
{
	GSList *list = NULL, *iter;

	list = list_connections (NM_SETTINGS_INTERFACE (self));
	*connections = g_ptr_array_sized_new (g_slist_length (list) + 1);
	for (iter = list; iter; iter = g_slist_next (iter)) {
		g_ptr_array_add (*connections,
		                 g_strdup (nm_connection_get_path (NM_CONNECTION (iter->data))));
	}
	g_slist_free (list);
	return TRUE;
}

static NMSettingsConnectionInterface *
get_connection_by_path (NMSettingsInterface *settings, const char *path)
{
	NMExportedConnection *connection;

	/* Must always be implemented */
	g_assert (NM_SETTINGS_SERVICE_GET_CLASS (settings)->get_connection_by_path);
	connection = NM_SETTINGS_SERVICE_GET_CLASS (settings)->get_connection_by_path (NM_SETTINGS_SERVICE (settings), path);
	return (NMSettingsConnectionInterface *) connection;
}

NMExportedConnection *
nm_settings_service_get_connection_by_path (NMSettingsService *self,
                                            const char *path)
{
	g_return_val_if_fail (self != NULL, NULL);
	g_return_val_if_fail (NM_IS_SETTINGS_SERVICE (self), NULL);

	return (NMExportedConnection *) get_connection_by_path (NM_SETTINGS_INTERFACE (self), path);
}

static void
impl_settings_add_connection (NMSettingsService *self,
                              GHashTable *settings,
                              DBusGMethodInvocation *context)
{
	NMConnection *tmp;
	GError *error = NULL;

	/* Check if the settings are valid first */
	tmp = nm_connection_new_from_hash (settings, &error);
	if (!tmp) {
		g_assert (error);
		dbus_g_method_return_error (context, error);
		g_error_free (error);
		return;
	}
	g_object_unref (tmp);

	if (NM_SETTINGS_SERVICE_GET_CLASS (self)->add_connection)
		NM_SETTINGS_SERVICE_GET_CLASS (self)->add_connection (self, settings, context);
	else {
		error = g_error_new (NM_SETTINGS_INTERFACE_ERROR,
		                     NM_SETTINGS_INTERFACE_ERROR_INTERNAL_ERROR,
		                     "%s: %s:%d add_connection() not implemented",
		                     __func__, __FILE__, __LINE__);
		dbus_g_method_return_error (context, error);
		g_error_free (error);
	}
}

/**************************************************************/

static void
settings_interface_init (NMSettingsInterface *iface)
{
	/* interface implementation */
	iface->list_connections = list_connections;
	iface->get_connection_by_path = get_connection_by_path;
}

static GObject *
constructor (GType type,
             guint n_construct_params,
             GObjectConstructParam *construct_params)
{
	GObject *object;

	object = G_OBJECT_CLASS (nm_settings_service_parent_class)->constructor (type, n_construct_params, construct_params);
	if (object)
		g_assert (NM_SETTINGS_SERVICE_GET_PRIVATE (object)->scope != NM_CONNECTION_SCOPE_UNKNOWN);
	return object;
}

static void
nm_settings_service_init (NMSettingsService *self)
{
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMSettingsServicePrivate *priv = NM_SETTINGS_SERVICE_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_BUS:
		/* Construct only */
		priv->bus = dbus_g_connection_ref ((DBusGConnection *) g_value_get_boxed (value));
		break;
	case PROP_SCOPE:
		/* Construct only */
		priv->scope = g_value_get_uint (value);
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
	NMSettingsServicePrivate *priv = NM_SETTINGS_SERVICE_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_BUS:
		g_value_set_boxed (value, priv->bus);
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
dispose (GObject *object)
{
	NMSettingsServicePrivate *priv = NM_SETTINGS_SERVICE_GET_PRIVATE (object);

	if (!priv->disposed) {
		priv->disposed = TRUE;
		dbus_g_connection_unref (priv->bus);
	}

	G_OBJECT_CLASS (nm_settings_service_parent_class)->dispose (object);
}

static void
nm_settings_service_class_init (NMSettingsServiceClass *class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (class);

	g_type_class_add_private (class, sizeof (NMSettingsServicePrivate));

	/* Virtual methods */
	object_class->dispose = dispose;
	object_class->constructor = constructor;
	object_class->get_property = get_property;
	object_class->set_property = set_property;

	/**
	 * NMSettingsService:bus:
	 *
	 * The %DBusGConnection which this object is exported on
	 **/
	g_object_class_install_property (object_class, PROP_BUS,
	                                 g_param_spec_boxed (NM_SETTINGS_SERVICE_BUS,
	                                                     "Bus",
	                                                     "Bus",
	                                                     DBUS_TYPE_G_CONNECTION,
	                                                     G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
	/**
	 * NMSettingsService:scope:
	 *
	 * The capabilities of the device.
	 **/
	g_object_class_install_property (object_class, PROP_SCOPE,
	                                 g_param_spec_uint (NM_SETTINGS_SERVICE_SCOPE,
	                                                    "Scope",
	                                                    "Scope",
	                                                    NM_CONNECTION_SCOPE_USER,
	                                                    NM_CONNECTION_SCOPE_SYSTEM,
	                                                    NM_CONNECTION_SCOPE_USER,
	                                                    G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (class),
	                                 &dbus_glib_nm_settings_object_info);
}
