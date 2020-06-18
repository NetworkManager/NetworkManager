// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2012 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-device-vlan.h"

#include "nm-setting-connection.h"
#include "nm-setting-vlan.h"
#include "nm-setting-wired.h"
#include "nm-utils.h"
#include "nm-object-private.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE (
	PROP_CARRIER,
	PROP_PARENT,
	PROP_VLAN_ID,
);

typedef struct {
	NMLDBusPropertyO parent;
	guint32 vlan_id;
	bool carrier;
} NMDeviceVlanPrivate;

struct _NMDeviceVlan {
	NMDevice parent;
	NMDeviceVlanPrivate _priv;
};

struct _NMDeviceVlanClass {
	NMDeviceClass parent;
};

G_DEFINE_TYPE (NMDeviceVlan, nm_device_vlan, NM_TYPE_DEVICE)

#define NM_DEVICE_VLAN_GET_PRIVATE(self) _NM_GET_PRIVATE(self, NMDeviceVlan, NM_IS_DEVICE_VLAN, NMObject, NMDevice)

/*****************************************************************************/

/**
 * nm_device_vlan_get_hw_address: (skip)
 * @device: a #NMDeviceVlan
 *
 * Gets the hardware (MAC) address of the #NMDeviceVlan
 *
 * Returns: the hardware address. This is the internal string used by the
 * device, and must not be modified.
 *
 * Deprecated: 1.24: Use nm_device_get_hw_address() instead.
 **/
const char *
nm_device_vlan_get_hw_address (NMDeviceVlan *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_VLAN (device), NULL);

	return nm_device_get_hw_address (NM_DEVICE (device));
}

/**
 * nm_device_vlan_get_carrier:
 * @device: a #NMDeviceVlan
 *
 * Whether the device has carrier.
 *
 * Returns: %TRUE if the device has carrier
 **/
gboolean
nm_device_vlan_get_carrier (NMDeviceVlan *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_VLAN (device), FALSE);

	return NM_DEVICE_VLAN_GET_PRIVATE (device)->carrier;
}

/**
 * nm_device_vlan_get_parent:
 * @device: a #NMDeviceVlan
 *
 * Returns: (transfer none): the device's parent device
 **/
NMDevice *
nm_device_vlan_get_parent (NMDeviceVlan *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_VLAN (device), FALSE);

	return nml_dbus_property_o_get_obj (&NM_DEVICE_VLAN_GET_PRIVATE (device)->parent);
}

/**
 * nm_device_vlan_get_vlan_id:
 * @device: a #NMDeviceVlan
 *
 * Returns: the device's VLAN ID
 **/
guint
nm_device_vlan_get_vlan_id (NMDeviceVlan *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_VLAN (device), FALSE);

	return NM_DEVICE_VLAN_GET_PRIVATE (device)->vlan_id;
}

static gboolean
connection_compatible (NMDevice *device, NMConnection *connection, GError **error)
{
	NMSettingVlan *s_vlan;
	NMSettingWired *s_wired;
	const char *setting_hwaddr;
	const char *hw_address;

	if (!NM_DEVICE_CLASS (nm_device_vlan_parent_class)->connection_compatible (device, connection, error))
		return FALSE;

	if (!nm_connection_is_type (connection, NM_SETTING_VLAN_SETTING_NAME)) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
		                     _("The connection was not a VLAN connection."));
		return FALSE;
	}

	s_vlan = nm_connection_get_setting_vlan (connection);
	if (nm_setting_vlan_get_id (s_vlan) != nm_device_vlan_get_vlan_id (NM_DEVICE_VLAN (device))) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
		                     _("The VLAN identifiers of the device and the connection didn't match."));
		return FALSE;
	}

	s_wired = nm_connection_get_setting_wired (connection);
	if (s_wired)
		setting_hwaddr = nm_setting_wired_get_mac_address (s_wired);
	else
		setting_hwaddr = NULL;
	if (setting_hwaddr) {
		hw_address = nm_device_get_hw_address (NM_DEVICE (device));

		if (   !hw_address
		    || !nm_utils_hwaddr_matches (setting_hwaddr, -1,
		                                 hw_address, -1)) {
			g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
			                     _("The hardware address of the device and the connection didn't match."));
		}
	}

	return TRUE;
}

static GType
get_setting_type (NMDevice *device)
{
	return NM_TYPE_SETTING_VLAN;
}

/*****************************************************************************/

static void
nm_device_vlan_init (NMDeviceVlan *device)
{
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMDeviceVlan *device = NM_DEVICE_VLAN (object);

	switch (prop_id) {
	case PROP_CARRIER:
		g_value_set_boolean (value, nm_device_vlan_get_carrier (device));
		break;
	case PROP_PARENT:
		g_value_set_object (value, nm_device_vlan_get_parent (device));
		break;
	case PROP_VLAN_ID:
		g_value_set_uint (value, nm_device_vlan_get_vlan_id (device));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

const NMLDBusMetaIface _nml_dbus_meta_iface_nm_device_vlan = NML_DBUS_META_IFACE_INIT_PROP (
	NM_DBUS_INTERFACE_DEVICE_VLAN,
	nm_device_vlan_get_type,
	NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_HIGH,
	NML_DBUS_META_IFACE_DBUS_PROPERTIES (
		NML_DBUS_META_PROPERTY_INIT_B      ("Carrier",   PROP_CARRIER,    NMDeviceVlan, _priv.carrier                                               ),
		NML_DBUS_META_PROPERTY_INIT_FCN    ("HwAddress", 0,               "s",          _nm_device_notify_update_prop_hw_address                    ),
		NML_DBUS_META_PROPERTY_INIT_O_PROP ("Parent",    PROP_PARENT,     NMDeviceVlan, _priv.parent,                            nm_device_get_type ),
		NML_DBUS_META_PROPERTY_INIT_U      ("VlanId",    PROP_VLAN_ID,    NMDeviceVlan, _priv.vlan_id                                               ),
	),
);

static void
nm_device_vlan_class_init (NMDeviceVlanClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMObjectClass *nm_object_class = NM_OBJECT_CLASS (klass);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);

	object_class->get_property = get_property;

	_NM_OBJECT_CLASS_INIT_PRIV_PTR_DIRECT (nm_object_class, NMDeviceVlan);

	_NM_OBJECT_CLASS_INIT_PROPERTY_O_FIELDS_1 (nm_object_class, NMDeviceVlanPrivate, parent);

	device_class->connection_compatible = connection_compatible;
	device_class->get_setting_type      = get_setting_type;

	/**
	 * NMDeviceVlan:carrier:
	 *
	 * Whether the device has carrier.
	 **/
	obj_properties[PROP_CARRIER] =
	    g_param_spec_boolean (NM_DEVICE_VLAN_CARRIER, "", "",
	                          FALSE,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	/**
	 * NMDeviceVlan:parent:
	 *
	 * The devices's parent device.
	 **/
	obj_properties[PROP_PARENT] =
	    g_param_spec_object (NM_DEVICE_VLAN_PARENT, "", "",
	                         NM_TYPE_DEVICE,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMDeviceVlan:vlan-id:
	 *
	 * The device's VLAN ID.
	 **/
	obj_properties[PROP_VLAN_ID] =
	    g_param_spec_uint (NM_DEVICE_VLAN_VLAN_ID, "", "",
	                       0, 4095, 0,
	                       G_PARAM_READABLE |
	                       G_PARAM_STATIC_STRINGS);

	_nml_dbus_meta_class_init_with_properties (object_class, &_nml_dbus_meta_iface_nm_device_vlan);
}
