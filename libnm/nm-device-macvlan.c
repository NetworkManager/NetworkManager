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
 * Copyright 2015 Red Hat, Inc.
 */

#include "nm-default.h"

#include <string.h>

#include "nm-setting-connection.h"
#include "nm-setting-macvlan.h"
#include "nm-setting-wired.h"
#include "nm-utils.h"

#include "nm-device-macvlan.h"
#include "nm-device-private.h"
#include "nm-object-private.h"

G_DEFINE_TYPE (NMDeviceMacvlan, nm_device_macvlan, NM_TYPE_DEVICE)

#define NM_DEVICE_MACVLAN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_MACVLAN, NMDeviceMacvlanPrivate))

typedef struct {
	NMDevice *parent;
	char *mode;
	gboolean no_promisc;
	gboolean tap;
	char *hw_address;
} NMDeviceMacvlanPrivate;

enum {
	PROP_0,
	PROP_PARENT,
	PROP_MODE,
	PROP_NO_PROMISC,
	PROP_TAP,
	PROP_HW_ADDRESS,

	LAST_PROP
};

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

	return NM_DEVICE_MACVLAN_GET_PRIVATE (device)->mode;
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
 **/
const char *
nm_device_macvlan_get_hw_address (NMDeviceMacvlan *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_MACVLAN (device), NULL);

	return NM_DEVICE_MACVLAN_GET_PRIVATE (device)->hw_address;
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

/***********************************************************/

static void
nm_device_macvlan_init (NMDeviceMacvlan *device)
{
	_nm_device_set_device_type (NM_DEVICE (device), NM_DEVICE_TYPE_MACVLAN);
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
		{ NM_DEVICE_MACVLAN_HW_ADDRESS,  &priv->hw_address },
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
	g_free (priv->hw_address);
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

	g_type_class_add_private (gre_class, sizeof (NMDeviceMacvlanPrivate));

	_nm_object_class_add_interface (nm_object_class, NM_DBUS_INTERFACE_DEVICE_MACVLAN);

	/* virtual methods */
	object_class->finalize = finalize;
	object_class->get_property = get_property;

	nm_object_class->init_dbus = init_dbus;

	device_class->connection_compatible = connection_compatible;
	device_class->get_setting_type = get_setting_type;
	device_class->get_hw_address = get_hw_address;

	/* properties */

	/**
	 * NMDeviceMacvlan:parent:
	 *
	 * The devices's parent device.
	 *
	 * Since: 1.2
	 **/
	g_object_class_install_property
	    (object_class, PROP_PARENT,
	     g_param_spec_object (NM_DEVICE_MACVLAN_PARENT, "", "",
	                          NM_TYPE_DEVICE,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceMacvlan:mode:
	 *
	 * The MACVLAN mode.
	 *
	 * Since: 1.2
	 **/
	g_object_class_install_property
		(object_class, PROP_MODE,
		 g_param_spec_string (NM_DEVICE_MACVLAN_MODE, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceMacvlan:no-promisc:
	 *
	 * Whether the device has the no-promiscuos flag.
	 *
	 * Since: 1.2
	 **/
	g_object_class_install_property
		(object_class, PROP_NO_PROMISC,
		 g_param_spec_boolean (NM_DEVICE_MACVLAN_NO_PROMISC, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceMacvlan:tap:
	 *
	 * Whether the device is a MACVTAP.
	 *
	 * Since: 1.2
	 **/
	g_object_class_install_property
		(object_class, PROP_TAP,
		 g_param_spec_boolean (NM_DEVICE_MACVLAN_TAP, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceMacvlan:hw-address:
	 *
	 * The hardware (MAC) address of the device.
	 *
	 * Since: 1.2
	 **/
	g_object_class_install_property
		(object_class, PROP_HW_ADDRESS,
		 g_param_spec_string (NM_DEVICE_MACVLAN_HW_ADDRESS, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));
}
