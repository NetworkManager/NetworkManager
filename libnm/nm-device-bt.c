// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2007 - 2008 Novell, Inc.
 * Copyright (C) 2007 - 2012 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-device-bt.h"

#include "nm-setting-connection.h"
#include "nm-setting-bluetooth.h"
#include "nm-utils.h"
#include "nm-object-private.h"
#include "nm-enum-types.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE (
	PROP_NAME,
	PROP_BT_CAPABILITIES,
);

typedef struct {
	char *name;
	guint32 bt_capabilities;
} NMDeviceBtPrivate;

struct _NMDeviceBt {
	NMDevice parent;
	NMDeviceBtPrivate _priv;
};

struct _NMDeviceBtClass {
	NMDeviceClass parent;
};

G_DEFINE_TYPE (NMDeviceBt, nm_device_bt, NM_TYPE_DEVICE)

#define NM_DEVICE_BT_GET_PRIVATE(self) _NM_GET_PRIVATE(self, NMDeviceBt, NM_IS_DEVICE_BT, NMObject, NMDevice)

/*****************************************************************************/

/**
 * nm_device_bt_get_hw_address:
 * @device: a #NMDeviceBt
 *
 * Gets the hardware (MAC) address of the #NMDeviceBt
 *
 * Returns: the hardware address. This is the internal string used by the
 * device, and must not be modified.
 *
 * Deprecated: 1.24 use nm_device_get_hw_address() instead.
 **/
const char *
nm_device_bt_get_hw_address (NMDeviceBt *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_BT (device), NULL);

	return nm_device_get_hw_address (NM_DEVICE (device));
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
	NMSettingBluetooth *s_bt;
	const char *hw_addr, *setting_addr;
	NMBluetoothCapabilities dev_caps;
	NMBluetoothCapabilities bt_type;

	if (!NM_DEVICE_CLASS (nm_device_bt_parent_class)->connection_compatible (device, connection, error))
		return FALSE;

	if (   !nm_connection_is_type (connection, NM_SETTING_BLUETOOTH_SETTING_NAME)
	    || !(s_bt = nm_connection_get_setting_bluetooth (connection))) {
		g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
		             _("The connection was not a Bluetooth connection."));
		return FALSE;
	}

	if (nm_streq0 (nm_setting_bluetooth_get_connection_type (s_bt), NM_SETTING_BLUETOOTH_TYPE_NAP)) {
		g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
		             _("The connection is of Bluetooth NAP type."));
		return FALSE;
	}

	/* Check BT address */
	hw_addr = nm_device_get_hw_address (device);
	if (hw_addr) {
		if (!nm_utils_hwaddr_valid (hw_addr, ETH_ALEN)) {
			g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_FAILED,
			                     _("Invalid device Bluetooth address."));
			return FALSE;
		}
		setting_addr = nm_setting_bluetooth_get_bdaddr (s_bt);
		if (setting_addr && !nm_utils_hwaddr_matches (setting_addr, -1, hw_addr, -1)) {
			g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
			                     _("The Bluetooth addresses of the device and the connection didn't match."));
			return FALSE;
		}
	}

	dev_caps = nm_device_bt_get_capabilities (NM_DEVICE_BT (device));
	bt_type = get_connection_bt_type (connection);
	if (!(bt_type & dev_caps)) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
		                     _("The device is lacking Bluetooth capabilities required by the connection."));
		return FALSE;
	}

	return TRUE;
}

static GType
get_setting_type (NMDevice *device)
{
	return NM_TYPE_SETTING_BLUETOOTH;
}

/*****************************************************************************/

static void
nm_device_bt_init (NMDeviceBt *device)
{
}

static void
finalize (GObject *object)
{
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (object);

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
	case PROP_NAME:
		g_value_set_string (value, nm_device_bt_get_name (device));
		break;
	case PROP_BT_CAPABILITIES:
		g_value_set_flags (value, nm_device_bt_get_capabilities (device));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

const NMLDBusMetaIface _nml_dbus_meta_iface_nm_device_bluetooth = NML_DBUS_META_IFACE_INIT_PROP (
	NM_DBUS_INTERFACE_DEVICE_BLUETOOTH,
	nm_device_bt_get_type,
	NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_HIGH,
	NML_DBUS_META_IFACE_DBUS_PROPERTIES (
		NML_DBUS_META_PROPERTY_INIT_U   ("BtCapabilities", PROP_BT_CAPABILITIES, NMDeviceBt, _priv.bt_capabilities                    ),
		NML_DBUS_META_PROPERTY_INIT_FCN ("HwAddress",      0,                    "s",        _nm_device_notify_update_prop_hw_address ),
		NML_DBUS_META_PROPERTY_INIT_S   ("Name",           PROP_NAME,            NMDeviceBt, _priv.name                               ),
	),
);

static void
nm_device_bt_class_init (NMDeviceBtClass *bt_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (bt_class);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (bt_class);

	object_class->get_property = get_property;
	object_class->finalize     = finalize;

	device_class->connection_compatible = connection_compatible;
	device_class->get_setting_type      = get_setting_type;

	/**
	 * NMDeviceBt:name:
	 *
	 * The name of the bluetooth device.
	 **/
	obj_properties[PROP_NAME] =
	    g_param_spec_string (NM_DEVICE_BT_NAME, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMDeviceBt:bt-capabilities:
	 *
	 * The device's bluetooth capabilities, a combination of #NMBluetoothCapabilities.
	 **/
	obj_properties[PROP_BT_CAPABILITIES] =
	    g_param_spec_flags (NM_DEVICE_BT_CAPABILITIES, "", "",
	                        NM_TYPE_BLUETOOTH_CAPABILITIES,
	                        NM_BT_CAPABILITY_NONE,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);

	_nml_dbus_meta_class_init_with_properties (object_class, &_nml_dbus_meta_iface_nm_device_bluetooth);
}
