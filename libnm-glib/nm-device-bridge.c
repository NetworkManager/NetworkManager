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
 * Copyright 2012 Red Hat, Inc.
 */

#include "nm-default.h"

#include <string.h>
#include <netinet/ether.h>

#include "nm-setting-connection.h"
#include "nm-setting-bridge.h"
#include "nm-utils.h"

#include "nm-device-bridge.h"
#include "nm-device-private.h"
#include "nm-object-private.h"
#include "nm-types.h"

G_DEFINE_TYPE (NMDeviceBridge, nm_device_bridge, NM_TYPE_DEVICE)

#define NM_DEVICE_BRIDGE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_BRIDGE, NMDeviceBridgePrivate))

typedef struct {
	DBusGProxy *proxy;

	char *hw_address;
	gboolean carrier;
	GPtrArray *slaves;
} NMDeviceBridgePrivate;

enum {
	PROP_0,
	PROP_HW_ADDRESS,
	PROP_CARRIER,
	PROP_SLAVES,

	LAST_PROP
};

/**
 * nm_device_bridge_error_quark:
 *
 * Registers an error quark for #NMDeviceBridge if necessary.
 *
 * Returns: the error quark used for #NMDeviceBridge errors.
 *
 * Since: 0.9.8
 **/
GQuark
nm_device_bridge_error_quark (void)
{
	static GQuark quark = 0;

	if (G_UNLIKELY (quark == 0))
		quark = g_quark_from_static_string ("nm-device-bridge-error-quark");
	return quark;
}

/**
 * nm_device_bridge_new:
 * @connection: the #DBusGConnection
 * @path: the DBus object path of the device
 *
 * Creates a new #NMDeviceBridge.
 *
 * Returns: (transfer full): a new device
 *
 * Since: 0.9.8
 **/
GObject *
nm_device_bridge_new (DBusGConnection *connection, const char *path)
{
	GObject *device;

	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (path != NULL, NULL);

	device = g_object_new (NM_TYPE_DEVICE_BRIDGE,
	                       NM_OBJECT_DBUS_CONNECTION, connection,
	                       NM_OBJECT_DBUS_PATH, path,
	                       NULL);
	_nm_object_ensure_inited (NM_OBJECT (device));
	return device;
}

/**
 * nm_device_bridge_get_hw_address:
 * @device: a #NMDeviceBridge
 *
 * Gets the hardware (MAC) address of the #NMDeviceBridge
 *
 * Returns: the hardware address. This is the internal string used by the
 * device, and must not be modified.
 *
 * Since: 0.9.8
 **/
const char *
nm_device_bridge_get_hw_address (NMDeviceBridge *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_BRIDGE (device), NULL);

	_nm_object_ensure_inited (NM_OBJECT (device));
	return NM_DEVICE_BRIDGE_GET_PRIVATE (device)->hw_address;
}

/**
 * nm_device_bridge_get_carrier:
 * @device: a #NMDeviceBridge
 *
 * Whether the device has carrier.
 *
 * Returns: %TRUE if the device has carrier
 *
 * Since: 0.9.8
 **/
gboolean
nm_device_bridge_get_carrier (NMDeviceBridge *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_BRIDGE (device), FALSE);

	_nm_object_ensure_inited (NM_OBJECT (device));
	return NM_DEVICE_BRIDGE_GET_PRIVATE (device)->carrier;
}

/**
 * nm_device_bridge_get_slaves:
 * @device: a #NMDeviceBridge
 *
 * Gets the devices currently slaved to @device.
 *
 * Returns: (element-type NMDevice): the #GPtrArray containing
 * #NMDevices that are slaves of @device. This is the internal
 * copy used by the device, and must not be modified.
 *
 * Since: 0.9.8
 **/
const GPtrArray *
nm_device_bridge_get_slaves (NMDeviceBridge *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_BRIDGE (device), FALSE);

	_nm_object_ensure_inited (NM_OBJECT (device));
	return handle_ptr_array_return (NM_DEVICE_BRIDGE_GET_PRIVATE (device)->slaves);
}

static gboolean
connection_compatible (NMDevice *device, NMConnection *connection, GError **error)
{
	NMSettingConnection *s_con;
	NMSettingBridge *s_bridge;
	const char *ctype, *dev_iface_name, *bridge_iface_name;

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);

	ctype = nm_setting_connection_get_connection_type (s_con);
	if (strcmp (ctype, NM_SETTING_BRIDGE_SETTING_NAME) != 0) {
		g_set_error (error, NM_DEVICE_BRIDGE_ERROR, NM_DEVICE_BRIDGE_ERROR_NOT_BRIDGE_CONNECTION,
		             "The connection was not a bridge connection.");
		return FALSE;
	}

	s_bridge = nm_connection_get_setting_bridge (connection);
	if (!s_bridge) {
		g_set_error (error, NM_DEVICE_BRIDGE_ERROR, NM_DEVICE_BRIDGE_ERROR_INVALID_BRIDGE_CONNECTION,
		             "The connection was not a valid bridge connection.");
		return FALSE;
	}

	dev_iface_name = nm_device_get_iface (device);
	bridge_iface_name = nm_setting_bridge_get_interface_name (s_bridge);
	if (g_strcmp0 (dev_iface_name, bridge_iface_name) != 0) {
		g_set_error (error, NM_DEVICE_BRIDGE_ERROR, NM_DEVICE_BRIDGE_ERROR_INTERFACE_MISMATCH,
		             "The interfaces of the device and the connection didn't match.");
		return FALSE;
	}

	/* FIXME: check ports? */

	return NM_DEVICE_CLASS (nm_device_bridge_parent_class)->connection_compatible (device, connection, error);
}

static GType
get_setting_type (NMDevice *device)
{
	return NM_TYPE_SETTING_BRIDGE;
}

static const char *
get_hw_address (NMDevice *device)
{
	return nm_device_bridge_get_hw_address (NM_DEVICE_BRIDGE (device));
}

/***********************************************************/

static void
nm_device_bridge_init (NMDeviceBridge *device)
{
	_nm_device_set_device_type (NM_DEVICE (device), NM_DEVICE_TYPE_BRIDGE);
}

static void
register_properties (NMDeviceBridge *device)
{
	NMDeviceBridgePrivate *priv = NM_DEVICE_BRIDGE_GET_PRIVATE (device);
	const NMPropertiesInfo property_info[] = {
		{ NM_DEVICE_BRIDGE_HW_ADDRESS, &priv->hw_address },
		{ NM_DEVICE_BRIDGE_CARRIER,    &priv->carrier },
		{ NM_DEVICE_BRIDGE_SLAVES,     &priv->slaves, NULL, NM_TYPE_DEVICE },
		{ NULL },
	};

	_nm_object_register_properties (NM_OBJECT (device),
	                                priv->proxy,
	                                property_info);
}

static void
constructed (GObject *object)
{
	NMDeviceBridgePrivate *priv = NM_DEVICE_BRIDGE_GET_PRIVATE (object);

	G_OBJECT_CLASS (nm_device_bridge_parent_class)->constructed (object);

	priv->proxy = _nm_object_new_proxy (NM_OBJECT (object), NULL, NM_DBUS_INTERFACE_DEVICE_BRIDGE);
	register_properties (NM_DEVICE_BRIDGE (object));
}

static void
dispose (GObject *object)
{
	NMDeviceBridgePrivate *priv = NM_DEVICE_BRIDGE_GET_PRIVATE (object);

	g_clear_object (&priv->proxy);

	if (priv->slaves) {
		g_ptr_array_set_free_func (priv->slaves, g_object_unref);
		g_ptr_array_free (priv->slaves, TRUE);
		priv->slaves = NULL;
	}

	G_OBJECT_CLASS (nm_device_bridge_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMDeviceBridgePrivate *priv = NM_DEVICE_BRIDGE_GET_PRIVATE (object);

	g_free (priv->hw_address);

	G_OBJECT_CLASS (nm_device_bridge_parent_class)->finalize (object);
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMDeviceBridge *device = NM_DEVICE_BRIDGE (object);

	_nm_object_ensure_inited (NM_OBJECT (object));

	switch (prop_id) {
	case PROP_HW_ADDRESS:
		g_value_set_string (value, nm_device_bridge_get_hw_address (device));
		break;
	case PROP_CARRIER:
		g_value_set_boolean (value, nm_device_bridge_get_carrier (device));
		break;
	case PROP_SLAVES:
		g_value_set_boxed (value, nm_device_bridge_get_slaves (device));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_device_bridge_class_init (NMDeviceBridgeClass *bridge_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (bridge_class);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (bridge_class);

	g_type_class_add_private (bridge_class, sizeof (NMDeviceBridgePrivate));

	/* virtual methods */
	object_class->constructed = constructed;
	object_class->dispose = dispose;
	object_class->finalize = finalize;
	object_class->get_property = get_property;
	device_class->connection_compatible = connection_compatible;
	device_class->get_setting_type = get_setting_type;
	device_class->get_hw_address = get_hw_address;

	/* properties */

	/**
	 * NMDeviceBridge:hw-address:
	 *
	 * The hardware (MAC) address of the device.
	 *
	 * Since: 0.9.8
	 **/
	g_object_class_install_property
		(object_class, PROP_HW_ADDRESS,
		 g_param_spec_string (NM_DEVICE_BRIDGE_HW_ADDRESS, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceBridge:carrier:
	 *
	 * Whether the device has carrier.
	 *
	 * Since: 0.9.8
	 **/
	g_object_class_install_property
		(object_class, PROP_CARRIER,
		 g_param_spec_boolean (NM_DEVICE_BRIDGE_CARRIER, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceBridge:slaves:
	 *
	 * The devices (#NMDevice) slaved to the bridge device.
	 *
	 * Since: 0.9.8
	 **/
	g_object_class_install_property
		(object_class, PROP_SLAVES,
		 g_param_spec_boxed (NM_DEVICE_BRIDGE_SLAVES, "", "",
		                     NM_TYPE_OBJECT_ARRAY,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));
}
