// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2015 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-setting-macvlan.h"

#include "nm-setting-connection.h"
#include "nm-setting-wired.h"
#include "nm-utils.h"
#include "nm-device-macvlan.h"
#include "nm-object-private.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE (
	PROP_PARENT,
	PROP_MODE,
	PROP_NO_PROMISC,
	PROP_TAP,
);

typedef struct {
	NMLDBusPropertyO parent;
	char *mode;
	bool no_promisc;
	bool tap;
} NMDeviceMacvlanPrivate;

struct _NMDeviceMacvlan {
	NMDevice parent;
	NMDeviceMacvlanPrivate _priv;
};

struct _NMDeviceMacvlanClass {
	NMDeviceClass parent;
};

G_DEFINE_TYPE (NMDeviceMacvlan, nm_device_macvlan, NM_TYPE_DEVICE)

#define NM_DEVICE_MACVLAN_GET_PRIVATE(self) _NM_GET_PRIVATE(self, NMDeviceMacvlan, NM_IS_DEVICE_MACVLAN, NMObject, NMDevice)

/*****************************************************************************/

/**
 * nm_device_macvlan_get_parent:
 * @device: a #NMDeviceMacvlan
 *
 * Returns: (transfer none): the device's parent device
 *
 * Since: 1.2
 **/
NMDevice *
nm_device_macvlan_get_parent (NMDeviceMacvlan *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_MACVLAN (device), FALSE);

	return nml_dbus_property_o_get_obj (&NM_DEVICE_MACVLAN_GET_PRIVATE (device)->parent);
}

/**
 * nm_device_macvlan_get_mode:
 * @device: a #NMDeviceMacvlan
 *
 * Gets the MACVLAN mode of the device.
 *
 * Returns: the MACVLAN mode. This is the internal string used by the
 * device, and must not be modified.
 *
 * Since: 1.2
 **/
const char *
nm_device_macvlan_get_mode (NMDeviceMacvlan *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_MACVLAN (device), NULL);

	return _nml_coerce_property_str_not_empty (NM_DEVICE_MACVLAN_GET_PRIVATE (device)->mode);
}

/**
 * nm_device_macvlan_get_no_promisc
 * @device: a #NMDeviceMacvlan
 *
 * Gets the no-promiscuous flag of the device.
 *
 * Returns: the no-promiscuous flag of the device.
 *
 * Since: 1.2
 **/
gboolean
nm_device_macvlan_get_no_promisc (NMDeviceMacvlan *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_MACVLAN (device), FALSE);

	return NM_DEVICE_MACVLAN_GET_PRIVATE (device)->no_promisc;
}

/**
 * nm_device_macvlan_get_tap:
 * @device: a #NMDeviceMacvlan
 *
 * Gets the device type (MACVLAN or MACVTAP).
 *
 * Returns: %TRUE if the device is a MACVTAP, %FALSE if it is a MACVLAN.
 *
 * Since: 1.2
 **/
gboolean
nm_device_macvlan_get_tap (NMDeviceMacvlan *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_MACVLAN (device), FALSE);

	return NM_DEVICE_MACVLAN_GET_PRIVATE (device)->tap;
}

/**
 * nm_device_macvlan_get_hw_address: (skip)
 * @device: a #NMDeviceMacvlan
 *
 * Gets the hardware (MAC) address of the #NMDeviceMacvlan
 *
 * Returns: the hardware address. This is the internal string used by the
 * device, and must not be modified.
 *
 * Since: 1.2
 *
 * This property is not implemented yet, and the function always return NULL.
 *
 * Deprecated: 1.24: Use nm_device_get_hw_address() instead.
 **/
const char *
nm_device_macvlan_get_hw_address (NMDeviceMacvlan *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_MACVLAN (device), NULL);

	return nm_device_get_hw_address (NM_DEVICE (device));
}

static gboolean
connection_compatible (NMDevice *device, NMConnection *connection, GError **error)
{
	NMDeviceMacvlanPrivate *priv = NM_DEVICE_MACVLAN_GET_PRIVATE (device);
	NMSettingMacvlan *s_macvlan;

	if (!NM_DEVICE_CLASS (nm_device_macvlan_parent_class)->connection_compatible (device, connection, error))
		return FALSE;

	if (!nm_connection_is_type (connection, NM_SETTING_MACVLAN_SETTING_NAME)) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
		                     _("The connection was not a MAC-VLAN connection."));
		return FALSE;
	}

	s_macvlan = nm_connection_get_setting_macvlan (connection);
	if (s_macvlan) {
		if (nm_setting_macvlan_get_tap (s_macvlan) != priv->tap)
			return FALSE;
	}

	return TRUE;
}

static GType
get_setting_type (NMDevice *device)
{
	return NM_TYPE_SETTING_MACVLAN;
}

/*****************************************************************************/

static void
nm_device_macvlan_init (NMDeviceMacvlan *device)
{
}

static void
finalize (GObject *object)
{
	NMDeviceMacvlanPrivate *priv = NM_DEVICE_MACVLAN_GET_PRIVATE (object);

	g_free (priv->mode);

	G_OBJECT_CLASS (nm_device_macvlan_parent_class)->finalize (object);
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMDeviceMacvlan *device = NM_DEVICE_MACVLAN (object);

	switch (prop_id) {
	case PROP_PARENT:
		g_value_set_object (value, nm_device_macvlan_get_parent (device));
		break;
	case PROP_MODE:
		g_value_set_string (value, nm_device_macvlan_get_mode (device));
		break;
	case PROP_NO_PROMISC:
		g_value_set_boolean (value, nm_device_macvlan_get_no_promisc (device));
		break;
	case PROP_TAP:
		g_value_set_boolean (value, nm_device_macvlan_get_tap (device));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

const NMLDBusMetaIface _nml_dbus_meta_iface_nm_device_macvlan = NML_DBUS_META_IFACE_INIT_PROP (
	NM_DBUS_INTERFACE_DEVICE_MACVLAN,
	nm_device_macvlan_get_type,
	NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_HIGH,
	NML_DBUS_META_IFACE_DBUS_PROPERTIES (
		NML_DBUS_META_PROPERTY_INIT_S      ("Mode",      PROP_MODE,       NMDeviceMacvlan, _priv.mode                          ),
		NML_DBUS_META_PROPERTY_INIT_B      ("NoPromisc", PROP_NO_PROMISC, NMDeviceMacvlan, _priv.no_promisc                    ),
		NML_DBUS_META_PROPERTY_INIT_O_PROP ("Parent",    PROP_PARENT,     NMDeviceMacvlan, _priv.parent,    nm_device_get_type ),
		NML_DBUS_META_PROPERTY_INIT_B      ("Tap",       PROP_TAP,        NMDeviceMacvlan, _priv.tap                           ),
	),
);

static void
nm_device_macvlan_class_init (NMDeviceMacvlanClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMObjectClass *nm_object_class = NM_OBJECT_CLASS (klass);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);

	object_class->get_property = get_property;
	object_class->finalize     = finalize;

	_NM_OBJECT_CLASS_INIT_PRIV_PTR_DIRECT (nm_object_class, NMDeviceMacvlan);

	_NM_OBJECT_CLASS_INIT_PROPERTY_O_FIELDS_1 (nm_object_class, NMDeviceMacvlanPrivate, parent);

	device_class->connection_compatible = connection_compatible;
	device_class->get_setting_type      = get_setting_type;

	/**
	 * NMDeviceMacvlan:parent:
	 *
	 * The devices's parent device.
	 *
	 * Since: 1.2
	 **/
	obj_properties[PROP_PARENT] =
	    g_param_spec_object (NM_DEVICE_MACVLAN_PARENT, "", "",
	                         NM_TYPE_DEVICE,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMDeviceMacvlan:mode:
	 *
	 * The MACVLAN mode.
	 *
	 * Since: 1.2
	 **/
	obj_properties[PROP_MODE] =
	    g_param_spec_string (NM_DEVICE_MACVLAN_MODE, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMDeviceMacvlan:no-promisc:
	 *
	 * Whether the device has the no-promiscuos flag.
	 *
	 * Since: 1.2
	 **/
	obj_properties[PROP_NO_PROMISC] =
	    g_param_spec_boolean (NM_DEVICE_MACVLAN_NO_PROMISC, "", "",
	                          FALSE,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	/**
	 * NMDeviceMacvlan:tap:
	 *
	 * Whether the device is a MACVTAP.
	 *
	 * Since: 1.2
	 **/
	obj_properties[PROP_TAP] =
	    g_param_spec_boolean (NM_DEVICE_MACVLAN_TAP, "", "",
	                          FALSE,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	_nml_dbus_meta_class_init_with_properties (object_class, &_nml_dbus_meta_iface_nm_device_macvlan);
}
