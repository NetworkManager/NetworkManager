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
 * Copyright (C) 2007 - 2008 Novell, Inc.
 * Copyright (C) 2007 - 2009 Red Hat, Inc.
 */

#include "nm-device-bt.h"
#include "nm-device-private.h"
#include "nm-object-private.h"

#include "nm-device-bt-bindings.h"

G_DEFINE_TYPE (NMDeviceBt, nm_device_bt, NM_TYPE_DEVICE)

#define NM_DEVICE_BT_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_BT, NMDeviceBtPrivate))

typedef struct {
	DBusGProxy *proxy;

	char *hw_address;
	char *name;
	guint32 bt_capabilities;
	gboolean bt_capabilities_valid;

	gboolean disposed;
} NMDeviceBtPrivate;

enum {
	PROP_0,
	PROP_HW_ADDRESS,
	PROP_NAME,
	PROP_BT_CAPABILITIES,

	LAST_PROP
};

#define DBUS_PROP_HW_ADDRESS      "HwAddress"
#define DBUS_PROP_NAME            "Name"
#define DBUS_PROP_BT_CAPABILITIES "BtCapabilities"

/**
 * nm_device_bt_new:
 * @connection: the #DBusGConnection
 * @path: the DBus object path of the device
 *
 * Creates a new #NMDeviceBt.
 *
 * Returns: a new device
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
	NMDeviceBtPrivate *priv;

	g_return_val_if_fail (NM_IS_DEVICE_BT (device), NULL);

	priv = NM_DEVICE_BT_GET_PRIVATE (device);
	if (!priv->hw_address) {
		priv->hw_address = _nm_object_get_string_property (NM_OBJECT (device),
		                                                   NM_DBUS_INTERFACE_DEVICE_BLUETOOTH,
		                                                   DBUS_PROP_HW_ADDRESS);
	}

	return priv->hw_address;
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
	NMDeviceBtPrivate *priv;

	g_return_val_if_fail (NM_IS_DEVICE_BT (device), NULL);

	priv = NM_DEVICE_BT_GET_PRIVATE (device);
	if (!priv->name) {
		priv->name = _nm_object_get_string_property (NM_OBJECT (device),
		                                             NM_DBUS_INTERFACE_DEVICE_BLUETOOTH,
		                                             DBUS_PROP_NAME);
	}

	return priv->name;
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
	NMDeviceBtPrivate *priv;

	g_return_val_if_fail (NM_IS_DEVICE_BT (device), NM_BT_CAPABILITY_NONE);

	priv = NM_DEVICE_BT_GET_PRIVATE (device);
	if (!priv->bt_capabilities_valid) {
		priv->bt_capabilities = _nm_object_get_uint_property (NM_OBJECT (device),
		                                                      NM_DBUS_INTERFACE_DEVICE_BLUETOOTH,
		                                                      DBUS_PROP_BT_CAPABILITIES);
		priv->bt_capabilities_valid = TRUE;
	}

	return priv->bt_capabilities;
}

static void
nm_device_bt_init (NMDeviceBt *device)
{
}

static void
register_for_property_changed (NMDeviceBt *device)
{
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (device);
	const NMPropertiesChangedInfo property_changed_info[] = {
		{ NM_DEVICE_BT_HW_ADDRESS,   _nm_object_demarshal_generic, &priv->hw_address },
		{ NM_DEVICE_BT_NAME,         _nm_object_demarshal_generic, &priv->name },
		{ NM_DEVICE_BT_CAPABILITIES, _nm_object_demarshal_generic, &priv->bt_capabilities },
		{ NULL },
	};

	_nm_object_handle_properties_changed (NM_OBJECT (device),
	                                     priv->proxy,
	                                     property_changed_info);
}

static GObject*
constructor (GType type,
			 guint n_construct_params,
			 GObjectConstructParam *construct_params)
{
	GObject *object;

	object = G_OBJECT_CLASS (nm_device_bt_parent_class)->constructor (type,
	                                                                  n_construct_params,
	                                                                  construct_params);
	if (object) {
			NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (object);

		priv->proxy = dbus_g_proxy_new_for_name (nm_object_get_connection (NM_OBJECT (object)),
		                                         NM_DBUS_SERVICE,
		                                         nm_object_get_path (NM_OBJECT (object)),
		                                         NM_DBUS_INTERFACE_DEVICE_BLUETOOTH);

		register_for_property_changed (NM_DEVICE_BT (object));
	}

	return object;
}

static void
dispose (GObject *object)
{
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (object);

	if (priv->disposed) {
		G_OBJECT_CLASS (nm_device_bt_parent_class)->dispose (object);
		return;
	}
	priv->disposed = TRUE;

	g_object_unref (priv->proxy);

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
nm_device_bt_class_init (NMDeviceBtClass *device_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (device_class);

	g_type_class_add_private (device_class, sizeof (NMDeviceBtPrivate));

	/* virtual methods */
	object_class->constructor = constructor;
	object_class->dispose = dispose;
	object_class->finalize = finalize;
	object_class->get_property = get_property;

	/* properties */

	/**
	 * NMDeviceBt:hw-address:
	 *
	 * The hardware (MAC) address of the device.
	 **/
	g_object_class_install_property
		(object_class, PROP_HW_ADDRESS,
		 g_param_spec_string (NM_DEVICE_BT_HW_ADDRESS,
		                      "MAC Address",
		                      "Hardware MAC address",
		                      NULL,
		                      G_PARAM_READABLE));

	/**
	 * NMDeviceBt:name:
	 *
	 * The name of the bluetooth device.
	 **/
	g_object_class_install_property
		(object_class, PROP_NAME,
		 g_param_spec_string (NM_DEVICE_BT_NAME,
		                      "Name",
		                      "Device name",
		                      NULL,
		                      G_PARAM_READABLE));

	/**
	 * NMDeviceBt:bt-capabilities:
	 *
	 * The device's bluetooth capabilities, a combination of #NMBluetoothCapabilities.
	 **/
	g_object_class_install_property
		(object_class, PROP_BT_CAPABILITIES,
		 g_param_spec_uint (NM_DEVICE_BT_CAPABILITIES,
		                    "BtCapabilities",
		                    "Bluetooth capabilities",
		                    NM_BT_CAPABILITY_NONE, G_MAXUINT32, NM_BT_CAPABILITY_NONE,
		                    G_PARAM_READABLE));

}

