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
	PROP_HW_ADDRESS,
);

typedef struct {
	NMDevice *parent;
	char *mode;
	gboolean no_promisc;
	gboolean tap;
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

	return NM_DEVICE_MACVLAN_GET_PRIVATE (device)->parent;
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
 * nm_device_macvlan_get_hw_address:
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
 **/
const char *
nm_device_macvlan_get_hw_address (NMDeviceMacvlan *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_MACVLAN (device), NULL);

	return NULL;
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

static const char *
get_hw_address (NMDevice *device)
{
	return nm_device_macvlan_get_hw_address (NM_DEVICE_MACVLAN (device));
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
init_dbus (NMObject *object)
{
	NMDeviceMacvlanPrivate *priv = NM_DEVICE_MACVLAN_GET_PRIVATE (object);
	const NMPropertiesInfo property_info[] = {
		{ NM_DEVICE_MACVLAN_PARENT,      &priv->parent, NULL, NM_TYPE_DEVICE },
		{ NM_DEVICE_MACVLAN_MODE,        &priv->mode },
		{ NM_DEVICE_MACVLAN_NO_PROMISC,  &priv->no_promisc },
		{ NM_DEVICE_MACVLAN_TAP,         &priv->tap },
		{ NULL },
	};

	NM_OBJECT_CLASS (nm_device_macvlan_parent_class)->init_dbus (object);

	_nm_object_register_properties (object,
	                                NM_DBUS_INTERFACE_DEVICE_MACVLAN,
	                                property_info);
}

static void
finalize (GObject *object)
{
	NMDeviceMacvlanPrivate *priv = NM_DEVICE_MACVLAN_GET_PRIVATE (object);

	g_free (priv->mode);
	g_clear_object (&priv->parent);

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
	case PROP_HW_ADDRESS:
		g_value_set_string (value, nm_device_macvlan_get_hw_address (device));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_device_macvlan_class_init (NMDeviceMacvlanClass *gre_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (gre_class);
	NMObjectClass *nm_object_class = NM_OBJECT_CLASS (gre_class);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (gre_class);

	object_class->get_property = get_property;
	object_class->finalize     = finalize;

	nm_object_class->init_dbus = init_dbus;

	device_class->connection_compatible = connection_compatible;
	device_class->get_setting_type      = get_setting_type;
	device_class->get_hw_address        = get_hw_address;

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

	/**
	 * NMDeviceMacvlan:hw-address:
	 *
	 * The hardware (MAC) address of the device.
	 *
	 * Since: 1.2
	 *
	 * This property is not implemented yet, and the function always return NULL.
	 **/
	obj_properties[PROP_HW_ADDRESS] =
	    g_param_spec_string (NM_DEVICE_MACVLAN_HW_ADDRESS, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);
}
