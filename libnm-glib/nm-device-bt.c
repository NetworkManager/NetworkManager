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
 * Copyright 2007 - 2008 Novell, Inc.
 * Copyright 2007 - 2012 Red Hat, Inc.
 */

#include "nm-default.h"

#include <string.h>
#include <netinet/ether.h>

#include "nm-setting-connection.h"
#include "nm-setting-bluetooth.h"

#include "nm-device-bt.h"
#include "nm-device-private.h"
#include "nm-object-private.h"

G_DEFINE_TYPE (NMDeviceBt, nm_device_bt, NM_TYPE_DEVICE)

#define NM_DEVICE_BT_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_BT, NMDeviceBtPrivate))

typedef struct {
	DBusGProxy *proxy;

	char *hw_address;
	char *name;
	guint32 bt_capabilities;
} NMDeviceBtPrivate;

enum {
	PROP_0,
	PROP_HW_ADDRESS,
	PROP_NAME,
	PROP_BT_CAPABILITIES,

	LAST_PROP
};

/**
 * nm_device_bt_error_quark:
 *
 * Registers an error quark for #NMDeviceBt if necessary.
 *
 * Returns: the error quark used for #NMDeviceBt errors.
 **/
GQuark
nm_device_bt_error_quark (void)
{
	static GQuark quark = 0;

	if (G_UNLIKELY (quark == 0))
		quark = g_quark_from_static_string ("nm-device-bt-error-quark");
	return quark;
}

/**
 * nm_device_bt_new:
 * @connection: the #DBusGConnection
 * @path: the DBus object path of the device
 *
 * Creates a new #NMDeviceBt.
 *
 * Returns: (transfer full): a new device
 **/
GObject *
nm_device_bt_new (DBusGConnection *connection, const char *path)
{
	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (path != NULL, NULL);

	return g_object_new (NM_TYPE_DEVICE_BT,
	                     NM_OBJECT_DBUS_CONNECTION, connection,
	                     NM_OBJECT_DBUS_PATH, path,
	                     NULL);
}

/**
 * nm_device_bt_get_hw_address:
 * @device: a #NMDeviceBt
 *
 * Gets the hardware (MAC) address of the #NMDeviceBt
 *
 * Returns: the hardware address. This is the internal string used by the
 * device, and must not be modified.
 **/
const char *
nm_device_bt_get_hw_address (NMDeviceBt *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_BT (device), NULL);

	_nm_object_ensure_inited (NM_OBJECT (device));
	return NM_DEVICE_BT_GET_PRIVATE (device)->hw_address;
}

/**
 * nm_device_bt_get_name:
 * @device: a #NMDeviceBt
 *
 * Gets the name of the #NMDeviceBt.
 *
 * Returns: the name of the device
 **/
const char *
nm_device_bt_get_name (NMDeviceBt *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_BT (device), NULL);

	_nm_object_ensure_inited (NM_OBJECT (device));
	return NM_DEVICE_BT_GET_PRIVATE (device)->name;
}

/**
 * nm_device_bt_get_capabilities:
 * @device: a #NMDeviceBt
 *
 * Returns the Bluetooth device's usable capabilities.
 *
 * Returns: a combination of #NMBluetoothCapabilities
 **/
NMBluetoothCapabilities
nm_device_bt_get_capabilities (NMDeviceBt *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_BT (device), NM_BT_CAPABILITY_NONE);

	_nm_object_ensure_inited (NM_OBJECT (device));
	return NM_DEVICE_BT_GET_PRIVATE (device)->bt_capabilities;
}

static NMBluetoothCapabilities
get_connection_bt_type (NMConnection *connection)
{
	NMSettingBluetooth *s_bt;
	const char *bt_type;

	s_bt = nm_connection_get_setting_bluetooth (connection);
	if (!s_bt)
		return NM_BT_CAPABILITY_NONE;

	bt_type = nm_setting_bluetooth_get_connection_type (s_bt);
	g_assert (bt_type);

	if (!strcmp (bt_type, NM_SETTING_BLUETOOTH_TYPE_DUN))
		return NM_BT_CAPABILITY_DUN;
	else if (!strcmp (bt_type, NM_SETTING_BLUETOOTH_TYPE_PANU))
		return NM_BT_CAPABILITY_NAP;

	return NM_BT_CAPABILITY_NONE;
}

static gboolean
connection_compatible (NMDevice *device, NMConnection *connection, GError **error)
{
	NMSettingConnection *s_con;
	NMSettingBluetooth *s_bt;
	const char *ctype;
	const GByteArray *mac;
	const char *hw_str;
	struct ether_addr *hw_mac;
	NMBluetoothCapabilities dev_caps;
	NMBluetoothCapabilities bt_type;

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);

	ctype = nm_setting_connection_get_connection_type (s_con);
	if (strcmp (ctype, NM_SETTING_BLUETOOTH_SETTING_NAME) != 0) {
		g_set_error (error, NM_DEVICE_BT_ERROR, NM_DEVICE_BT_ERROR_NOT_BT_CONNECTION,
		             "The connection was not a Bluetooth connection.");
		return FALSE;
	}

	s_bt = nm_connection_get_setting_bluetooth (connection);
	if (!s_bt) {
		g_set_error (error, NM_DEVICE_BT_ERROR, NM_DEVICE_BT_ERROR_INVALID_BT_CONNECTION,
		             "The connection was not a valid Bluetooth connection.");
		return FALSE;
	}

	/* Check BT address */
	hw_str = nm_device_bt_get_hw_address (NM_DEVICE_BT (device));
	if (hw_str) {
		hw_mac = ether_aton (hw_str);
		if (!hw_mac) {
			g_set_error (error, NM_DEVICE_BT_ERROR, NM_DEVICE_BT_ERROR_INVALID_DEVICE_MAC,
			             "Invalid device MAC address.");
			return FALSE;
		}
		mac = nm_setting_bluetooth_get_bdaddr (s_bt);
		if (mac && hw_mac && memcmp (mac->data, hw_mac->ether_addr_octet, ETH_ALEN)) {
			g_set_error (error, NM_DEVICE_BT_ERROR, NM_DEVICE_BT_ERROR_MAC_MISMATCH,
			             "The MACs of the device and the connection didn't match.");
			return FALSE;
		}
	}

	dev_caps = nm_device_bt_get_capabilities (NM_DEVICE_BT (device));
	bt_type = get_connection_bt_type (connection);
	if (!(bt_type & dev_caps)) {
		g_set_error (error, NM_DEVICE_BT_ERROR, NM_DEVICE_BT_ERROR_MISSING_DEVICE_CAPS,
		             "The device missed BT capabilities required by the connection.");
		return FALSE;
	}

	return NM_DEVICE_CLASS (nm_device_bt_parent_class)->connection_compatible (device, connection, error);
}

static GType
get_setting_type (NMDevice *device)
{
	return NM_TYPE_SETTING_BLUETOOTH;
}

static const char *
get_hw_address (NMDevice *device)
{
	return nm_device_bt_get_hw_address (NM_DEVICE_BT (device));
}

/************************************************************/

static void
nm_device_bt_init (NMDeviceBt *device)
{
	_nm_device_set_device_type (NM_DEVICE (device), NM_DEVICE_TYPE_BT);
}

static void
register_properties (NMDeviceBt *device)
{
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (device);
	const NMPropertiesInfo property_info[] = {
		{ NM_DEVICE_BT_HW_ADDRESS,   &priv->hw_address },
		{ NM_DEVICE_BT_NAME,         &priv->name },
		{ NM_DEVICE_BT_CAPABILITIES, &priv->bt_capabilities },
		{ NULL },
	};

	_nm_object_register_properties (NM_OBJECT (device),
	                                priv->proxy,
	                                property_info);
}

static void
constructed (GObject *object)
{
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (object);

	G_OBJECT_CLASS (nm_device_bt_parent_class)->constructed (object);

	priv->proxy = _nm_object_new_proxy (NM_OBJECT (object), NULL, NM_DBUS_INTERFACE_DEVICE_BLUETOOTH);
	register_properties (NM_DEVICE_BT (object));
}

static void
dispose (GObject *object)
{
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (object);

	g_clear_object (&priv->proxy);

	G_OBJECT_CLASS (nm_device_bt_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (object);

	g_free (priv->hw_address);
	g_free (priv->name);

	G_OBJECT_CLASS (nm_device_bt_parent_class)->finalize (object);
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMDeviceBt *device = NM_DEVICE_BT (object);

	_nm_object_ensure_inited (NM_OBJECT (object));

	switch (prop_id) {
	case PROP_HW_ADDRESS:
		g_value_set_string (value, nm_device_bt_get_hw_address (device));
		break;
	case PROP_NAME:
		g_value_set_string (value, nm_device_bt_get_name (device));
		break;
	case PROP_BT_CAPABILITIES:
		g_value_set_uint (value, nm_device_bt_get_capabilities (device));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_device_bt_class_init (NMDeviceBtClass *bt_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (bt_class);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (bt_class);

	g_type_class_add_private (bt_class, sizeof (NMDeviceBtPrivate));

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
	 * NMDeviceBt:hw-address:
	 *
	 * The hardware (MAC) address of the device.
	 **/
	g_object_class_install_property
		(object_class, PROP_HW_ADDRESS,
		 g_param_spec_string (NM_DEVICE_BT_HW_ADDRESS, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceBt:name:
	 *
	 * The name of the bluetooth device.
	 **/
	g_object_class_install_property
		(object_class, PROP_NAME,
		 g_param_spec_string (NM_DEVICE_BT_NAME, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceBt:bt-capabilities:
	 *
	 * The device's bluetooth capabilities, a combination of #NMBluetoothCapabilities.
	 **/
	g_object_class_install_property
		(object_class, PROP_BT_CAPABILITIES,
		 g_param_spec_uint (NM_DEVICE_BT_CAPABILITIES, "", "",
		                    NM_BT_CAPABILITY_NONE, G_MAXUINT32, NM_BT_CAPABILITY_NONE,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

}
