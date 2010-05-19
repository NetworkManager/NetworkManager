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
 * Copyright (C) 2007 - 2010 Red Hat, Inc.
 * Copyright (C) 2008 Novell, Inc.
 */

#include <string.h>

#include "NetworkManager.h"
#include "nm-active-connection.h"
#include "nm-object-private.h"
#include "nm-types-private.h"
#include "nm-device.h"
#include "nm-connection.h"

#include "nm-active-connection-bindings.h"

G_DEFINE_TYPE (NMActiveConnection, nm_active_connection, NM_TYPE_OBJECT)

#define NM_ACTIVE_CONNECTION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_ACTIVE_CONNECTION, NMActiveConnectionPrivate))

static gboolean demarshal_devices (NMObject *object, GParamSpec *pspec, GValue *value, gpointer field);


typedef struct {
	gboolean disposed;
	DBusGProxy *proxy;

	char *service_name;
	NMConnectionScope scope;
	char *connection;
	char *specific_object;
	GPtrArray *devices;
	NMActiveConnectionState state;
	gboolean is_default;
	gboolean is_default6;
} NMActiveConnectionPrivate;

enum {
	PROP_0,
	PROP_SERVICE_NAME,
	PROP_CONNECTION,
	PROP_SPECIFIC_OBJECT,
	PROP_DEVICES,
	PROP_STATE,
	PROP_DEFAULT,
	PROP_DEFAULT6,

	LAST_PROP
};

#define DBUS_PROP_SERVICE_NAME "ServiceName"
#define DBUS_PROP_CONNECTION "Connection"
#define DBUS_PROP_SPECIFIC_OBJECT "SpecificObject"
#define DBUS_PROP_DEVICES "Devices"
#define DBUS_PROP_STATE "State"
#define DBUS_PROP_DEFAULT "Default"
#define DBUS_PROP_DEFAULT6 "Default6"

/**
 * nm_active_connection_new:
 * @connection: the #DBusGConnection
 * @path: the DBus object path of the device
 *
 * Creates a new #NMActiveConnection.
 *
 * Returns: a new active connection
 **/
GObject *
nm_active_connection_new (DBusGConnection *connection, const char *path)
{
	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (path != NULL, NULL);

	return g_object_new (NM_TYPE_ACTIVE_CONNECTION,
						 NM_OBJECT_DBUS_CONNECTION, connection,
						 NM_OBJECT_DBUS_PATH, path,
						 NULL);
}

static NMConnectionScope
get_scope_for_service_name (const char *service_name)
{
	if (service_name && !strcmp (service_name, NM_DBUS_SERVICE_USER_SETTINGS))
		return NM_CONNECTION_SCOPE_USER;
	else if (service_name && !strcmp (service_name, NM_DBUS_SERVICE_SYSTEM_SETTINGS))
		return NM_CONNECTION_SCOPE_SYSTEM;

	return NM_CONNECTION_SCOPE_UNKNOWN;
}

/**
 * nm_active_connection_get_service_name:
 * @connection: a #NMActiveConnection
 *
 * Gets the service name of the active connection.
 *
 * Returns: the service name. This is the internal string used by the
 * connection, and must not be modified.
 **/
const char *
nm_active_connection_get_service_name (NMActiveConnection *connection)
{
	NMActiveConnectionPrivate *priv;

	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (connection), NULL);

	priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (connection);
	if (!priv->service_name) {
		priv->service_name = _nm_object_get_string_property (NM_OBJECT (connection),
		                                                    NM_DBUS_INTERFACE_ACTIVE_CONNECTION,
		                                                    DBUS_PROP_SERVICE_NAME);
		priv->scope = get_scope_for_service_name (priv->service_name);
	}

	return priv->service_name;
}

/**
 * nm_active_connection_get_scope:
 * @connection: a #NMActiveConnection
 *
 * Gets the scope of the active connection.
 *
 * Returns: the connection's scope
 **/
NMConnectionScope
nm_active_connection_get_scope (NMActiveConnection *connection)
{
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (connection), NM_CONNECTION_SCOPE_UNKNOWN);

	/* Make sure service_name and scope are up-to-date */
	nm_active_connection_get_service_name (connection);
	return NM_ACTIVE_CONNECTION_GET_PRIVATE (connection)->scope;
}

/**
 * nm_active_connection_get_connection:
 * @connection: a #NMActiveConnection
 *
 * Gets the #NMConnection<!-- -->'s DBus object path.
 *
 * Returns: the object path of the #NMConnection inside of #NMActiveConnection.
 * This is the internal string used by the connection, and must not be modified.
 **/
const char *
nm_active_connection_get_connection (NMActiveConnection *connection)
{
	NMActiveConnectionPrivate *priv;

	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (connection), NULL);

	priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (connection);
	if (!priv->connection) {
		priv->connection = _nm_object_get_string_property (NM_OBJECT (connection),
		                                                  NM_DBUS_INTERFACE_ACTIVE_CONNECTION,
		                                                  DBUS_PROP_CONNECTION);
	}

	return priv->connection;
}

/**
 * nm_active_connection_get_specific_object:
 * @connection: a #NMActiveConnection
 *
 * Gets the "specific object" used at the activation.
 *
 * Returns: the specific object's DBus path. This is the internal string used by the
 * connection, and must not be modified.
 **/
const char *
nm_active_connection_get_specific_object (NMActiveConnection *connection)
{
	NMActiveConnectionPrivate *priv;

	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (connection), NULL);

	priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (connection);
	if (!priv->specific_object) {
		priv->specific_object = _nm_object_get_string_property (NM_OBJECT (connection),
		                                                       NM_DBUS_INTERFACE_ACTIVE_CONNECTION,
		                                                       DBUS_PROP_SPECIFIC_OBJECT);
	}

	return priv->specific_object;
}

/**
 * nm_active_connection_get_devices:
 * @connection: a #NMActiveConnection
 *
 * Gets the #NMDevice<!-- -->s used for the active connections.
 *
 * Returns: the #GPtrArray containing #NMDevice<!-- -->s.
 * This is the internal copy used by the connection, and must not be modified.
 **/
const GPtrArray *
nm_active_connection_get_devices (NMActiveConnection *connection)
{
	NMActiveConnectionPrivate *priv;
	GValue value = { 0, };

	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (connection), NULL);

	priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (connection);
	if (priv->devices)
		return handle_ptr_array_return (priv->devices);

	if (!_nm_object_get_property (NM_OBJECT (connection),
	                             NM_DBUS_INTERFACE_ACTIVE_CONNECTION,
	                             DBUS_PROP_DEVICES,
	                             &value)) {
		return NULL;
	}

	demarshal_devices (NM_OBJECT (connection), NULL, &value, &priv->devices);
	g_value_unset (&value);

	return handle_ptr_array_return (priv->devices);
}

/**
 * nm_active_connection_get_state:
 * @connection: a #NMActiveConnection
 *
 * Gets the active connection's state.
 *
 * Returns: the state
 **/
NMActiveConnectionState
nm_active_connection_get_state (NMActiveConnection *connection)
{
	NMActiveConnectionPrivate *priv;

	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (connection), NM_ACTIVE_CONNECTION_STATE_UNKNOWN);

	priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (connection);
	if (!priv->state) {
		priv->state = _nm_object_get_uint_property (NM_OBJECT (connection),
		                                           NM_DBUS_INTERFACE_ACTIVE_CONNECTION,
		                                           DBUS_PROP_STATE);
	}

	return priv->state;
}

/**
 * nm_active_connection_get_default:
 * @connection: a #NMActiveConnection
 *
 * Whether the active connection is the default IPv4 one (that is, is used for
 * the default IPv4 route and DNS information).
 *
 * Returns: %TRUE if the active connection is the default IPv4 connection
 **/
gboolean
nm_active_connection_get_default (NMActiveConnection *connection)
{
	NMActiveConnectionPrivate *priv;

	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (connection), FALSE);

	priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (connection);
	if (!priv->is_default) {
		priv->is_default = _nm_object_get_boolean_property (NM_OBJECT (connection),
		                                                    NM_DBUS_INTERFACE_ACTIVE_CONNECTION,
		                                                    DBUS_PROP_DEFAULT);
	}

	return priv->is_default;
}

/**
 * nm_active_connection_get_default6:
 * @connection: a #NMActiveConnection
 *
 * Whether the active connection is the default IPv6 one (that is, is used for
 * the default IPv6 route and DNS information).
 *
 * Returns: %TRUE if the active connection is the default IPv6 connection
 **/
gboolean
nm_active_connection_get_default6 (NMActiveConnection *connection)
{
	NMActiveConnectionPrivate *priv;

	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (connection), FALSE);

	priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (connection);
	if (!priv->is_default6) {
		priv->is_default6 = _nm_object_get_boolean_property (NM_OBJECT (connection),
		                                                     NM_DBUS_INTERFACE_ACTIVE_CONNECTION,
		                                                     DBUS_PROP_DEFAULT6);
	}

	return priv->is_default6;
}

static void
nm_active_connection_init (NMActiveConnection *ap)
{
}

static void
dispose (GObject *object)
{
	NMActiveConnectionPrivate *priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (object);

	if (priv->disposed) {
		G_OBJECT_CLASS (nm_active_connection_parent_class)->dispose (object);
		return;
	}

	priv->disposed = TRUE;

	if (priv->devices) {
		g_ptr_array_foreach (priv->devices, (GFunc) g_object_unref, NULL);
		g_ptr_array_free (priv->devices, TRUE);
	}
	g_object_unref (priv->proxy);

	G_OBJECT_CLASS (nm_active_connection_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMActiveConnectionPrivate *priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (object);

	g_free (priv->service_name);
	g_free (priv->connection);
	g_free (priv->specific_object);

	G_OBJECT_CLASS (nm_active_connection_parent_class)->finalize (object);
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMActiveConnection *self = NM_ACTIVE_CONNECTION (object);

	switch (prop_id) {
	case PROP_SERVICE_NAME:
		g_value_set_string (value, nm_active_connection_get_service_name (self));
		break;
	case PROP_CONNECTION:
		g_value_set_boxed (value, nm_active_connection_get_connection (self));
		break;
	case PROP_SPECIFIC_OBJECT:
		g_value_set_boxed (value, nm_active_connection_get_specific_object (self));
		break;
	case PROP_DEVICES:
		g_value_set_boxed (value, nm_active_connection_get_devices (self));
		break;
	case PROP_STATE:
		g_value_set_uint (value, nm_active_connection_get_state (self));
		break;
	case PROP_DEFAULT:
		g_value_set_boolean (value, nm_active_connection_get_default (self));
		break;
	case PROP_DEFAULT6:
		g_value_set_boolean (value, nm_active_connection_get_default6 (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static gboolean
demarshal_devices (NMObject *object, GParamSpec *pspec, GValue *value, gpointer field)
{
	DBusGConnection *connection;

	connection = nm_object_get_connection (object);
	if (!_nm_object_array_demarshal (value, (GPtrArray **) field, connection, nm_device_new))
		return FALSE;

	_nm_object_queue_notify (object, NM_ACTIVE_CONNECTION_DEVICES);
	return TRUE;
}

static gboolean
demarshal_service (NMObject *object, GParamSpec *pspec, GValue *value, gpointer field)
{
	NMActiveConnectionPrivate *priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (object);

	if (_nm_object_demarshal_generic (object, pspec, value, field)) {
		priv->scope = get_scope_for_service_name (priv->service_name);
		return TRUE;
	}
	return FALSE;
}

static void
register_for_property_changed (NMActiveConnection *connection)
{
	NMActiveConnectionPrivate *priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (connection);
	const NMPropertiesChangedInfo property_changed_info[] = {
		{ NM_ACTIVE_CONNECTION_SERVICE_NAME,        demarshal_service,           &priv->service_name },
		{ NM_ACTIVE_CONNECTION_CONNECTION,          _nm_object_demarshal_generic, &priv->connection },
		{ NM_ACTIVE_CONNECTION_SPECIFIC_OBJECT,     _nm_object_demarshal_generic, &priv->specific_object },
		{ NM_ACTIVE_CONNECTION_DEVICES,             demarshal_devices,           &priv->devices },
		{ NM_ACTIVE_CONNECTION_STATE,               _nm_object_demarshal_generic, &priv->state },
		{ NM_ACTIVE_CONNECTION_DEFAULT,             _nm_object_demarshal_generic, &priv->is_default },
		{ NM_ACTIVE_CONNECTION_DEFAULT6,            _nm_object_demarshal_generic, &priv->is_default6 },
		{ NULL },
	};

	_nm_object_handle_properties_changed (NM_OBJECT (connection),
	                                     priv->proxy,
	                                     property_changed_info);
}

static GObject*
constructor (GType type,
			 guint n_construct_params,
			 GObjectConstructParam *construct_params)
{
	NMObject *object;
	NMActiveConnectionPrivate *priv;

	object = (NMObject *) G_OBJECT_CLASS (nm_active_connection_parent_class)->constructor (type,
																	  n_construct_params,
																	  construct_params);
	if (!object)
		return NULL;

	priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (object);

	priv->proxy = dbus_g_proxy_new_for_name (nm_object_get_connection (object),
									    NM_DBUS_SERVICE,
									    nm_object_get_path (object),
									    NM_DBUS_INTERFACE_ACTIVE_CONNECTION);

	register_for_property_changed (NM_ACTIVE_CONNECTION (object));

	return G_OBJECT (object);
}


static void
nm_active_connection_class_init (NMActiveConnectionClass *ap_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (ap_class);

	g_type_class_add_private (ap_class, sizeof (NMActiveConnectionPrivate));

	/* virtual methods */
	object_class->constructor = constructor;
	object_class->get_property = get_property;
	object_class->dispose = dispose;
	object_class->finalize = finalize;

	/* properties */

	/**
	 * NMActiveConnection:service-name:
	 *
	 * The service name of the active connection.
	 **/
	g_object_class_install_property
		(object_class, PROP_SERVICE_NAME,
		 g_param_spec_string (NM_ACTIVE_CONNECTION_SERVICE_NAME,
						  "Service Name",
						  "Service Name",
						  NULL,
						  G_PARAM_READABLE));

	/**
	 * NMActiveConnection:connection:
	 *
	 * The connection's path of the active connection.
	 **/
	g_object_class_install_property
		(object_class, PROP_CONNECTION,
		 g_param_spec_string (NM_ACTIVE_CONNECTION_CONNECTION,
						      "Connection",
						      "Connection",
						      NULL,
						      G_PARAM_READABLE));

	/**
	 * NMActiveConnection:specific-object:
	 *
	 * The specific object's path of the active connection.
	 **/
	g_object_class_install_property
		(object_class, PROP_SPECIFIC_OBJECT,
		 g_param_spec_string (NM_ACTIVE_CONNECTION_SPECIFIC_OBJECT,
						      "Specific object",
						      "Specific object",
						      NULL,
						      G_PARAM_READABLE));

	/**
	 * NMActiveConnection:device:
	 *
	 * The devices (#NMDevice) of the active connection.
	 **/
	g_object_class_install_property
		(object_class, PROP_DEVICES,
		 g_param_spec_boxed (NM_ACTIVE_CONNECTION_DEVICES,
						       "Devices",
						       "Devices",
						       NM_TYPE_OBJECT_ARRAY,
						       G_PARAM_READABLE));

	/**
	 * NMActiveConnection:state:
	 *
	 * The state of the active connection.
	 **/
	g_object_class_install_property
		(object_class, PROP_STATE,
		 g_param_spec_uint (NM_ACTIVE_CONNECTION_STATE,
							  "State",
							  "State",
							  NM_ACTIVE_CONNECTION_STATE_UNKNOWN,
							  NM_ACTIVE_CONNECTION_STATE_ACTIVATED,
							  NM_ACTIVE_CONNECTION_STATE_UNKNOWN,
							  G_PARAM_READABLE));

	/**
	 * NMActiveConnection:default:
	 *
	 * Whether the active connection is the default IPv4 one.
	 **/
	g_object_class_install_property
		(object_class, PROP_DEFAULT,
		 g_param_spec_boolean (NM_ACTIVE_CONNECTION_DEFAULT,
							   "Default",
							   "Is the default IPv4 active connection",
							   FALSE,
							   G_PARAM_READABLE));

	/**
	 * NMActiveConnection:default6:
	 *
	 * Whether the active connection is the default IPv6 one.
	 **/
	g_object_class_install_property
		(object_class, PROP_DEFAULT6,
		 g_param_spec_boolean (NM_ACTIVE_CONNECTION_DEFAULT6,
							   "Default6",
							   "Is the default IPv6 active connection",
							   FALSE,
							   G_PARAM_READABLE));
}
