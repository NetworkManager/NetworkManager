/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
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
 * Copyright 2007 - 2014 Red Hat, Inc.
 * Copyright 2008 Novell, Inc.
 */

#include "nm-default.h"

#include <string.h>

#include "NetworkManager.h"
#include "nm-active-connection.h"
#include "nm-object-private.h"
#include "nm-types-private.h"
#include "nm-device.h"
#include "nm-device-private.h"
#include "nm-connection.h"
#include "nm-vpn-connection.h"
#include "nm-dbus-helpers-private.h"

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
	char *id;
	char *uuid;
	char *type;
	char *specific_object;
	GPtrArray *devices;
	NMActiveConnectionState state;
	gboolean is_default;
	NMIP4Config *ip4_config;
	NMDHCP4Config *dhcp4_config;
	gboolean is_default6;
	NMIP6Config *ip6_config;
	NMDHCP6Config *dhcp6_config;
	gboolean is_vpn;
	char *master;
} NMActiveConnectionPrivate;

enum {
	PROP_0,
	PROP_CONNECTION,
	PROP_ID,
	PROP_UUID,
	PROP_TYPE,
	PROP_SPECIFIC_OBJECT,
	PROP_DEVICES,
	PROP_STATE,
	PROP_DEFAULT,
	PROP_IP4_CONFIG,
	PROP_DHCP4_CONFIG,
	PROP_DEFAULT6,
	PROP_IP6_CONFIG,
	PROP_DHCP6_CONFIG,
	PROP_VPN,
	PROP_MASTER,

	LAST_PROP
};

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
	GValue value = G_VALUE_INIT;
	GType type;

	proxy = _nm_dbus_new_proxy_for_connection (connection, path, DBUS_INTERFACE_PROPERTIES);
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
		g_warning ("Error in getting active connection 'Vpn' property: %s",
		           error->message);
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

	proxy = _nm_dbus_new_proxy_for_connection (connection, path, DBUS_INTERFACE_PROPERTIES);
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
 * Gets the #NMConnection's DBus object path.  This is often used with
 * nm_remote_settings_get_connection_by_path() to retrieve the
 * #NMRemoteConnection object that describes the connection.
 *
 * Returns: the object path of the #NMConnection which this #NMActiveConnection
 * is an active instance of.  This is the internal string used by the
 * connection, and must not be modified.
 **/
const char *
nm_active_connection_get_connection (NMActiveConnection *connection)
{
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (connection), NULL);

	_nm_object_ensure_inited (NM_OBJECT (connection));
	return NM_ACTIVE_CONNECTION_GET_PRIVATE (connection)->connection;
}

/**
 * nm_active_connection_get_id:
 * @connection: a #NMActiveConnection
 *
 * Gets the #NMConnection's ID.
 *
 * Returns: the ID of the #NMConnection that backs the #NMActiveConnection.
 * This is the internal string used by the connection, and must not be modified.
 *
 * Since: 0.9.10
 **/
const char *
nm_active_connection_get_id (NMActiveConnection *connection)
{
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (connection), NULL);

	_nm_object_ensure_inited (NM_OBJECT (connection));
	return NM_ACTIVE_CONNECTION_GET_PRIVATE (connection)->id;
}

/**
 * nm_active_connection_get_uuid:
 * @connection: a #NMActiveConnection
 *
 * Gets the #NMConnection's UUID.
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
 * nm_active_connection_get_connection_type:
 * @connection: a #NMActiveConnection
 *
 * Gets the #NMConnection's type.
 *
 * Returns: the type of the #NMConnection that backs the #NMActiveConnection.
 * This is the internal string used by the connection, and must not be modified.
 *
 * Since: 0.9.10
 **/
const char *
nm_active_connection_get_connection_type (NMActiveConnection *connection)
{
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (connection), NULL);

	_nm_object_ensure_inited (NM_OBJECT (connection));
	return NM_ACTIVE_CONNECTION_GET_PRIVATE (connection)->type;
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
 * Gets the #NMDevices used for the active connections.
 *
 * Returns: (element-type NMDevice): the #GPtrArray containing #NMDevices.
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
 * nm_active_connection_get_ip4_config:
 * @connection: an #NMActiveConnection
 *
 * Gets the current #NMIP4Config associated with the #NMActiveConnection.
 *
 * Returns: (transfer none): the #NMIP4Config, or %NULL if the
 *   connection is not in the %NM_ACTIVE_CONNECTION_STATE_ACTIVATED
 *   state.
 *
 * Since: 0.9.10
 **/
NMIP4Config *
nm_active_connection_get_ip4_config (NMActiveConnection *connection)
{
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (connection), NULL);

	_nm_object_ensure_inited (NM_OBJECT (connection));
	return NM_ACTIVE_CONNECTION_GET_PRIVATE (connection)->ip4_config;
}

/**
 * nm_active_connection_get_dhcp4_config:
 * @connection: an #NMActiveConnection
 *
 * Gets the current #NMDHCP4Config (if any) associated with the
 * #NMActiveConnection.
 *
 * Returns: (transfer none): the #NMDHCP4Config, or %NULL if the
 *   connection does not use DHCP, or is not in the
 *   %NM_ACTIVE_CONNECTION_STATE_ACTIVATED state.
 *
 * Since: 0.9.10
 **/
NMDHCP4Config *
nm_active_connection_get_dhcp4_config (NMActiveConnection *connection)
{
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (connection), NULL);

	_nm_object_ensure_inited (NM_OBJECT (connection));
	return NM_ACTIVE_CONNECTION_GET_PRIVATE (connection)->dhcp4_config;
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
 * nm_active_connection_get_ip6_config:
 * @connection: an #NMActiveConnection
 *
 * Gets the current #NMIP6Config associated with the #NMActiveConnection.
 *
 * Returns: (transfer none): the #NMIP6Config, or %NULL if the
 *   connection is not in the %NM_ACTIVE_CONNECTION_STATE_ACTIVATED
 *   state.
 *
 * Since: 0.9.10
 **/
NMIP6Config *
nm_active_connection_get_ip6_config (NMActiveConnection *connection)
{
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (connection), NULL);

	_nm_object_ensure_inited (NM_OBJECT (connection));
	return NM_ACTIVE_CONNECTION_GET_PRIVATE (connection)->ip6_config;
}

/**
 * nm_active_connection_get_dhcp6_config:
 * @connection: an #NMActiveConnection
 *
 * Gets the current #NMDHCP6Config (if any) associated with the
 * #NMActiveConnection.
 *
 * Returns: (transfer none): the #NMDHCP6Config, or %NULL if the
 *   connection does not use DHCPv6, or is not in the
 *   %NM_ACTIVE_CONNECTION_STATE_ACTIVATED state.
 *
 * Since: 0.9.10
 **/
NMDHCP6Config *
nm_active_connection_get_dhcp6_config (NMActiveConnection *connection)
{
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (connection), NULL);

	_nm_object_ensure_inited (NM_OBJECT (connection));
	return NM_ACTIVE_CONNECTION_GET_PRIVATE (connection)->dhcp6_config;
}

/**
 * nm_active_connection_get_vpn:
 * @connection: a #NMActiveConnection
 *
 * Whether the active connection is a VPN connection.
 *
 * Returns: %TRUE if the active connection is a VPN connection
 *
 * Since: 0.9.10
 **/
gboolean
nm_active_connection_get_vpn (NMActiveConnection *connection)
{
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (connection), FALSE);

	_nm_object_ensure_inited (NM_OBJECT (connection));
	return NM_ACTIVE_CONNECTION_GET_PRIVATE (connection)->is_vpn;
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
		g_ptr_array_set_free_func (priv->devices, g_object_unref);
		g_ptr_array_free (priv->devices, TRUE);
		priv->devices = NULL;
	}

	g_clear_object (&priv->ip4_config);
	g_clear_object (&priv->dhcp4_config);
	g_clear_object (&priv->ip6_config);
	g_clear_object (&priv->dhcp6_config);

	g_clear_object (&priv->proxy);

	G_OBJECT_CLASS (nm_active_connection_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMActiveConnectionPrivate *priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (object);

	g_free (priv->connection);
	g_free (priv->id);
	g_free (priv->uuid);
	g_free (priv->type);
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
	case PROP_ID:
		g_value_set_string (value, nm_active_connection_get_id (self));
		break;
	case PROP_UUID:
		g_value_set_string (value, nm_active_connection_get_uuid (self));
		break;
	case PROP_TYPE:
		g_value_set_string (value, nm_active_connection_get_connection_type (self));
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
	case PROP_IP4_CONFIG:
		g_value_set_object (value, nm_active_connection_get_ip4_config (self));
		break;
	case PROP_DHCP4_CONFIG:
		g_value_set_object (value, nm_active_connection_get_dhcp4_config (self));
		break;
	case PROP_DEFAULT6:
		g_value_set_boolean (value, nm_active_connection_get_default6 (self));
		break;
	case PROP_IP6_CONFIG:
		g_value_set_object (value, nm_active_connection_get_ip6_config (self));
		break;
	case PROP_DHCP6_CONFIG:
		g_value_set_object (value, nm_active_connection_get_dhcp6_config (self));
		break;
	case PROP_VPN:
		g_value_set_boolean (value, nm_active_connection_get_vpn (self));
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
		{ NM_ACTIVE_CONNECTION_ID,                  &priv->id },
		{ NM_ACTIVE_CONNECTION_UUID,                &priv->uuid },
		{ NM_ACTIVE_CONNECTION_TYPE,                &priv->type },
		{ NM_ACTIVE_CONNECTION_SPECIFIC_OBJECT,     &priv->specific_object },
		{ NM_ACTIVE_CONNECTION_DEVICES,             &priv->devices, NULL, NM_TYPE_DEVICE },
		{ NM_ACTIVE_CONNECTION_STATE,               &priv->state },
		{ NM_ACTIVE_CONNECTION_DEFAULT,             &priv->is_default },
		{ NM_ACTIVE_CONNECTION_IP4_CONFIG,          &priv->ip4_config, NULL, NM_TYPE_IP4_CONFIG },
		{ NM_ACTIVE_CONNECTION_DHCP4_CONFIG,        &priv->dhcp4_config, NULL, NM_TYPE_DHCP4_CONFIG },
		{ NM_ACTIVE_CONNECTION_DEFAULT6,            &priv->is_default6 },
		{ NM_ACTIVE_CONNECTION_IP6_CONFIG,          &priv->ip6_config, NULL, NM_TYPE_IP6_CONFIG },
		{ NM_ACTIVE_CONNECTION_DHCP6_CONFIG,        &priv->dhcp6_config, NULL, NM_TYPE_DHCP6_CONFIG },
		{ NM_ACTIVE_CONNECTION_VPN,                 &priv->is_vpn },
		{ NM_ACTIVE_CONNECTION_MASTER,              &priv->master },

		{ NULL },
	};

	_nm_object_register_properties (NM_OBJECT (connection),
	                                priv->proxy,
	                                property_info);
}

static void
constructed (GObject *object)
{
	NMActiveConnectionPrivate *priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (object);

	G_OBJECT_CLASS (nm_active_connection_parent_class)->constructed (object);

	priv->proxy = _nm_object_new_proxy (NM_OBJECT (object), NULL, NM_DBUS_INTERFACE_ACTIVE_CONNECTION);
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
		 g_param_spec_string (NM_ACTIVE_CONNECTION_CONNECTION, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMActiveConnection:id:
	 *
	 * The active connection's ID
	 *
	 * Since: 0.9.10
	 **/
	g_object_class_install_property
		(object_class, PROP_ID,
		 g_param_spec_string (NM_ACTIVE_CONNECTION_ID, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMActiveConnection:uuid:
	 *
	 * The active connection's UUID
	 **/
	g_object_class_install_property
		(object_class, PROP_UUID,
		 g_param_spec_string (NM_ACTIVE_CONNECTION_UUID, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMActiveConnection:type:
	 *
	 * The active connection's type
	 *
	 * Since: 0.9.10
	 **/
	g_object_class_install_property
		(object_class, PROP_TYPE,
		 g_param_spec_string (NM_ACTIVE_CONNECTION_TYPE, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMActiveConnection:specific-object:
	 *
	 * The specific object's path of the active connection.
	 **/
	g_object_class_install_property
		(object_class, PROP_SPECIFIC_OBJECT,
		 g_param_spec_string (NM_ACTIVE_CONNECTION_SPECIFIC_OBJECT, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMActiveConnection:device:
	 *
	 * The devices (#NMDevice) of the active connection.
	 **/
	g_object_class_install_property
		(object_class, PROP_DEVICES,
		 g_param_spec_boxed (NM_ACTIVE_CONNECTION_DEVICES, "", "",
		                     NM_TYPE_OBJECT_ARRAY,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));

	/**
	 * NMActiveConnection:state:
	 *
	 * The state of the active connection.
	 **/
	g_object_class_install_property
		(object_class, PROP_STATE,
		 g_param_spec_uint (NM_ACTIVE_CONNECTION_STATE, "", "",
		                    NM_ACTIVE_CONNECTION_STATE_UNKNOWN,
		                    NM_ACTIVE_CONNECTION_STATE_DEACTIVATING,
		                    NM_ACTIVE_CONNECTION_STATE_UNKNOWN,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMActiveConnection:default:
	 *
	 * Whether the active connection is the default IPv4 one.
	 **/
	g_object_class_install_property
		(object_class, PROP_DEFAULT,
		 g_param_spec_boolean (NM_ACTIVE_CONNECTION_DEFAULT, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMActiveConnection:ip4-config:
	 *
	 * The #NMIP4Config of the connection.
	 *
	 * Since: 0.9.10
	 **/
	g_object_class_install_property
		(object_class, PROP_IP4_CONFIG,
		 g_param_spec_object (NM_ACTIVE_CONNECTION_IP4_CONFIG, "", "",
		                      NM_TYPE_IP4_CONFIG,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMActiveConnection:dhcp4-config:
	 *
	 * The #NMDHCP4Config of the connection.
	 *
	 * Since: 0.9.10
	 **/
	g_object_class_install_property
		(object_class, PROP_DHCP4_CONFIG,
		 g_param_spec_object (NM_ACTIVE_CONNECTION_DHCP4_CONFIG, "", "",
		                      NM_TYPE_DHCP4_CONFIG,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMActiveConnection:default6:
	 *
	 * Whether the active connection is the default IPv6 one.
	 **/
	g_object_class_install_property
		(object_class, PROP_DEFAULT6,
		 g_param_spec_boolean (NM_ACTIVE_CONNECTION_DEFAULT6, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMActiveConnection:ip6-config:
	 *
	 * The #NMIP6Config of the connection.
	 *
	 * Since: 0.9.10
	 **/
	g_object_class_install_property
		(object_class, PROP_IP6_CONFIG,
		 g_param_spec_object (NM_ACTIVE_CONNECTION_IP6_CONFIG, "", "",
		                      NM_TYPE_IP6_CONFIG,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMActiveConnection:dhcp6-config:
	 *
	 * The #NMDHCP6Config of the connection.
	 *
	 * Since: 0.9.10
	 **/
	g_object_class_install_property
		(object_class, PROP_DHCP6_CONFIG,
		 g_param_spec_object (NM_ACTIVE_CONNECTION_DHCP6_CONFIG, "", "",
		                      NM_TYPE_DHCP6_CONFIG,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMActiveConnection:vpn:
	 *
	 * Whether the active connection is a VPN connection.
	 *
	 * Since: 0.9.10
	 **/
	g_object_class_install_property
		(object_class, PROP_VPN,
		 g_param_spec_boolean (NM_ACTIVE_CONNECTION_VPN, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMActiveConnection:master:
	 *
	 * The path of the master device if one exists.
	 **/
	g_object_class_install_property
		(object_class, PROP_MASTER,
		 g_param_spec_string (NM_ACTIVE_CONNECTION_MASTER, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));
}
