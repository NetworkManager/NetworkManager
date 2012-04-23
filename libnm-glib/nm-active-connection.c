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
 * Copyright (C) 2007 - 2011 Red Hat, Inc.
 * Copyright (C) 2008 Novell, Inc.
 */

#include <string.h>

#include "NetworkManager.h"
#include "nm-active-connection.h"
#include "nm-object-private.h"
#include "nm-types-private.h"
#include "nm-device.h"
#include "nm-device-private.h"
#include "nm-connection.h"
#include "nm-vpn-connection.h"
#include "nm-glib-compat.h"

static GType _nm_active_connection_type_for_path (DBusGConnection *connection,
                                                  const char *path);
static void  _nm_active_connection_type_for_path_async (DBusGConnection *connection,
                                                        const char *path,
                                                        NMObjectTypeCallbackFunc callback,
                                                        gpointer user_data);

G_DEFINE_TYPE_WITH_CODE (NMActiveConnection, nm_active_connection, NM_TYPE_OBJECT,
                         _nm_object_register_type_func (g_define_type_id,
                                                        _nm_active_connection_type_for_path,
                                                        _nm_active_connection_type_for_path_async);
                         )

#define NM_ACTIVE_CONNECTION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_ACTIVE_CONNECTION, NMActiveConnectionPrivate))

typedef struct {
	DBusGProxy *proxy;

	char *connection;
	char *uuid;
	char *specific_object;
	GPtrArray *devices;
	NMActiveConnectionState state;
	gboolean is_default;
	gboolean is_default6;
	char *master;
} NMActiveConnectionPrivate;

enum {
	PROP_0,
	PROP_CONNECTION,
	PROP_UUID,
	PROP_SPECIFIC_OBJECT,
	PROP_DEVICES,
	PROP_STATE,
	PROP_DEFAULT,
	PROP_DEFAULT6,
	PROP_MASTER,

	LAST_PROP
};

#define DBUS_PROP_CONNECTION "Connection"
#define DBUS_PROP_UUID "Uuid"
#define DBUS_PROP_SPECIFIC_OBJECT "SpecificObject"
#define DBUS_PROP_DEVICES "Devices"
#define DBUS_PROP_STATE "State"
#define DBUS_PROP_DEFAULT "Default"
#define DBUS_PROP_DEFAULT6 "Default6"
#define DBUS_PROP_MASTER "Master"

/**
 * nm_active_connection_new:
 * @connection: the #DBusGConnection
 * @path: the DBus object path of the device
 *
 * Creates a new #NMActiveConnection.
 *
 * Returns: (transfer full): a new active connection
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

static GType
_nm_active_connection_type_for_path (DBusGConnection *connection,
                                     const char *path)
{
	DBusGProxy *proxy;
	GError *error = NULL;
	GValue value = {0,};
	GType type;

	proxy = dbus_g_proxy_new_for_name (connection,
	                                   NM_DBUS_SERVICE,
	                                   path,
	                                   "org.freedesktop.DBus.Properties");
	if (!proxy) {
		g_warning ("%s: couldn't create D-Bus object proxy.", __func__);
		return G_TYPE_INVALID;
	}

	/* Have to create an NMVPNConnection if it's a VPN connection, otherwise
	 * a plain NMActiveConnection.
	 */
	if (dbus_g_proxy_call (proxy,
	                       "Get", &error,
	                       G_TYPE_STRING, NM_DBUS_INTERFACE_ACTIVE_CONNECTION,
	                       G_TYPE_STRING, "Vpn",
	                       G_TYPE_INVALID,
	                       G_TYPE_VALUE, &value, G_TYPE_INVALID)) {
		if (g_value_get_boolean (&value))
			type = NM_TYPE_VPN_CONNECTION;
		else
			type = NM_TYPE_ACTIVE_CONNECTION;
	} else {
		g_warning ("Error in getting active connection 'Vpn' property: (%d) %s",
		           error->code, error->message);
		g_error_free (error);
		type = G_TYPE_INVALID;
	}

	g_object_unref (proxy);
	return type;
}

typedef struct {
	DBusGConnection *connection;
	NMObjectTypeCallbackFunc callback;
	gpointer user_data;
} NMActiveConnectionAsyncData;

static void
async_got_type (DBusGProxy *proxy, DBusGProxyCall *call, gpointer user_data)
{
	NMActiveConnectionAsyncData *async_data = user_data;
	GValue value = G_VALUE_INIT;
	const char *path = dbus_g_proxy_get_path (proxy);
	GError *error = NULL;
	GType type;

	if (dbus_g_proxy_end_call (proxy, call, &error,
	                           G_TYPE_VALUE, &value,
	                           G_TYPE_INVALID)) {
		if (g_value_get_boolean (&value))
			type = NM_TYPE_VPN_CONNECTION;
		else
			type = NM_TYPE_ACTIVE_CONNECTION;
	} else {
		g_warning ("%s: could not read properties for %s: %s", __func__, path, error->message);
		type = G_TYPE_INVALID;
	}

	async_data->callback (type, async_data->user_data);

	g_object_unref (proxy);
	g_slice_free (NMActiveConnectionAsyncData, async_data);
}

static void
_nm_active_connection_type_for_path_async (DBusGConnection *connection,
                                           const char *path,
                                           NMObjectTypeCallbackFunc callback,
                                           gpointer user_data)
{
	NMActiveConnectionAsyncData *async_data;
	DBusGProxy *proxy;

	async_data = g_slice_new (NMActiveConnectionAsyncData);
	async_data->connection = connection;
	async_data->callback = callback;
	async_data->user_data = user_data;

	proxy = dbus_g_proxy_new_for_name (connection, NM_DBUS_SERVICE, path,
	                                   "org.freedesktop.DBus.Properties");
	dbus_g_proxy_begin_call (proxy, "Get",
	                         async_got_type, async_data, NULL,
	                         G_TYPE_STRING, NM_DBUS_INTERFACE_ACTIVE_CONNECTION,
	                         G_TYPE_STRING, "Vpn",
	                         G_TYPE_INVALID);
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
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (connection), NULL);

	_nm_object_ensure_inited (NM_OBJECT (connection));
	return NM_ACTIVE_CONNECTION_GET_PRIVATE (connection)->connection;
}

/**
 * nm_active_connection_get_uuid:
 * @connection: a #NMActiveConnection
 *
 * Gets the #NMConnection<!-- -->'s UUID.
 *
 * Returns: the UUID of the #NMConnection that backs the #NMActiveConnection.
 * This is the internal string used by the connection, and must not be modified.
 **/
const char *
nm_active_connection_get_uuid (NMActiveConnection *connection)
{
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (connection), NULL);

	_nm_object_ensure_inited (NM_OBJECT (connection));
	return NM_ACTIVE_CONNECTION_GET_PRIVATE (connection)->uuid;
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
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (connection), NULL);

	_nm_object_ensure_inited (NM_OBJECT (connection));
	return NM_ACTIVE_CONNECTION_GET_PRIVATE (connection)->specific_object;
}

/**
 * nm_active_connection_get_devices:
 * @connection: a #NMActiveConnection
 *
 * Gets the #NMDevice<!-- -->s used for the active connections.
 *
 * Returns: (element-type NMClient.Device): the #GPtrArray containing #NMDevice<!-- -->s.
 * This is the internal copy used by the connection, and must not be modified.
 **/
const GPtrArray *
nm_active_connection_get_devices (NMActiveConnection *connection)
{
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (connection), NULL);

	_nm_object_ensure_inited (NM_OBJECT (connection));
	return handle_ptr_array_return (NM_ACTIVE_CONNECTION_GET_PRIVATE (connection)->devices);
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
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (connection), NM_ACTIVE_CONNECTION_STATE_UNKNOWN);

	_nm_object_ensure_inited (NM_OBJECT (connection));
	return NM_ACTIVE_CONNECTION_GET_PRIVATE (connection)->state;
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
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (connection), FALSE);

	_nm_object_ensure_inited (NM_OBJECT (connection));
	return NM_ACTIVE_CONNECTION_GET_PRIVATE (connection)->is_default;
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
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (connection), FALSE);

	_nm_object_ensure_inited (NM_OBJECT (connection));
	return NM_ACTIVE_CONNECTION_GET_PRIVATE (connection)->is_default6;
}

/**
 * nm_active_connection_get_master:
 * @connection: a #NMActiveConnection
 *
 * Gets the path to the master #NMDevice of the connection.
 *
 * Returns: the path of the master #NMDevice of the #NMActiveConnection.
 * This is the internal string used by the connection, and must not be modified.
 **/
const char *
nm_active_connection_get_master (NMActiveConnection *connection)
{
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (connection), NULL);

	_nm_object_ensure_inited (NM_OBJECT (connection));
	return NM_ACTIVE_CONNECTION_GET_PRIVATE (connection)->master;
}

static void
nm_active_connection_init (NMActiveConnection *ap)
{
}

static void
dispose (GObject *object)
{
	NMActiveConnectionPrivate *priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (object);

	if (priv->devices) {
		g_ptr_array_foreach (priv->devices, (GFunc) g_object_unref, NULL);
		g_ptr_array_free (priv->devices, TRUE);
		priv->devices = NULL;
	}

	g_clear_object (&priv->proxy);

	G_OBJECT_CLASS (nm_active_connection_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMActiveConnectionPrivate *priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (object);

	g_free (priv->connection);
	g_free (priv->uuid);
	g_free (priv->specific_object);
	g_free (priv->master);

	G_OBJECT_CLASS (nm_active_connection_parent_class)->finalize (object);
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMActiveConnection *self = NM_ACTIVE_CONNECTION (object);

	_nm_object_ensure_inited (NM_OBJECT (object));

	switch (prop_id) {
	case PROP_CONNECTION:
		g_value_set_string (value, nm_active_connection_get_connection (self));
		break;
	case PROP_UUID:
		g_value_set_string (value, nm_active_connection_get_uuid (self));
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
	case PROP_MASTER:
		g_value_set_string (value, nm_active_connection_get_master (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
register_properties (NMActiveConnection *connection)
{
	NMActiveConnectionPrivate *priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (connection);
	const NMPropertiesInfo property_info[] = {
		{ NM_ACTIVE_CONNECTION_CONNECTION,          &priv->connection },
		{ NM_ACTIVE_CONNECTION_UUID,                &priv->uuid },
		{ NM_ACTIVE_CONNECTION_SPECIFIC_OBJECT,     &priv->specific_object },
		{ NM_ACTIVE_CONNECTION_DEVICES,             &priv->devices, NULL, NM_TYPE_DEVICE },
		{ NM_ACTIVE_CONNECTION_STATE,               &priv->state },
		{ NM_ACTIVE_CONNECTION_DEFAULT,             &priv->is_default },
		{ NM_ACTIVE_CONNECTION_DEFAULT6,            &priv->is_default6 },
		{ NM_ACTIVE_CONNECTION_MASTER,              &priv->master },

		/* not tracked after construction time */
		{ "vpn", NULL },

		{ NULL },
	};

	_nm_object_register_properties (NM_OBJECT (connection),
	                                priv->proxy,
	                                property_info);
}

static void
constructed (GObject *object)
{
	NMActiveConnectionPrivate *priv;

	G_OBJECT_CLASS (nm_active_connection_parent_class)->constructed (object);

	priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (object);

	priv->proxy = dbus_g_proxy_new_for_name (nm_object_get_connection (NM_OBJECT (object)),
									    NM_DBUS_SERVICE,
									    nm_object_get_path (NM_OBJECT (object)),
									    NM_DBUS_INTERFACE_ACTIVE_CONNECTION);

	register_properties (NM_ACTIVE_CONNECTION (object));
}


static void
nm_active_connection_class_init (NMActiveConnectionClass *ap_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (ap_class);

	g_type_class_add_private (ap_class, sizeof (NMActiveConnectionPrivate));

	/* virtual methods */
	object_class->constructed = constructed;
	object_class->get_property = get_property;
	object_class->dispose = dispose;
	object_class->finalize = finalize;

	/* properties */

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
	 * NMActiveConnection:uuid:
	 *
	 * The active connection's UUID
	 **/
	g_object_class_install_property
		(object_class, PROP_UUID,
		 g_param_spec_string (NM_ACTIVE_CONNECTION_UUID,
						      "UUID",
						      "UUID",
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
							  NM_ACTIVE_CONNECTION_STATE_DEACTIVATING,
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

	/**
	 * NMActiveConnection:master:
	 *
	 * The path of the master device if one exists.
	 **/
	g_object_class_install_property
		(object_class, PROP_MASTER,
		 g_param_spec_string (NM_ACTIVE_CONNECTION_MASTER,
						      "Master",
						      "Path of the master device",
						      NULL,
						      G_PARAM_READABLE));
}
