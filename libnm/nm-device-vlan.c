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

#include "config.h"

#include <string.h>
#include <glib/gi18n-lib.h>

#include <nm-setting-connection.h>
#include <nm-setting-vlan.h>
#include <nm-setting-wired.h>
#include <nm-utils.h>

#include "nm-glib.h"
#include "nm-device-vlan.h"
#include "nm-device-private.h"
#include "nm-object-private.h"

G_DEFINE_TYPE (NMDeviceVlan, nm_device_vlan, NM_TYPE_DEVICE)

#define NM_DEVICE_VLAN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_VLAN, NMDeviceVlanPrivate))

typedef struct {
	char *hw_address;
	gboolean carrier;
	NMDevice *parent;
	guint vlan_id;
} NMDeviceVlanPrivate;

enum {
	PROP_0,
	PROP_HW_ADDRESS,
	PROP_CARRIER,
	PROP_PARENT,
	PROP_VLAN_ID,

	LAST_PROP
};

/**
 * nm_device_vlan_get_hw_address:
 * @device: a #NMDeviceVlan
 *
 * Gets the hardware (MAC) address of the #NMDeviceVlan
 *
 * Returns: the hardware address. This is the internal string used by the
 * device, and must not be modified.
 **/
const char *
nm_device_vlan_get_hw_address (NMDeviceVlan *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_VLAN (device), NULL);

	return NM_DEVICE_VLAN_GET_PRIVATE (device)->hw_address;
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

	return NM_DEVICE_VLAN_GET_PRIVATE (device)->parent;
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
		if (!nm_utils_hwaddr_matches (setting_hwaddr, -1,
		                              NM_DEVICE_VLAN_GET_PRIVATE (device)->hw_address, -1)) {
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

static const char *
get_hw_address (NMDevice *device)
{
	return nm_device_vlan_get_hw_address (NM_DEVICE_VLAN (device));
}

/***********************************************************/

static void
nm_device_vlan_init (NMDeviceVlan *device)
{
	_nm_device_set_device_type (NM_DEVICE (device), NM_DEVICE_TYPE_VLAN);
}

static void
init_dbus (NMObject *object)
{
	NMDeviceVlanPrivate *priv = NM_DEVICE_VLAN_GET_PRIVATE (object);
	const NMPropertiesInfo property_info[] = {
		{ NM_DEVICE_VLAN_HW_ADDRESS, &priv->hw_address },
		{ NM_DEVICE_VLAN_CARRIER,    &priv->carrier },
		{ NM_DEVICE_VLAN_PARENT,     &priv->parent, NULL, NM_TYPE_DEVICE },
		{ NM_DEVICE_VLAN_VLAN_ID,    &priv->vlan_id },
		{ NULL },
	};

	NM_OBJECT_CLASS (nm_device_vlan_parent_class)->init_dbus (object);

	_nm_object_register_properties (object,
	                                NM_DBUS_INTERFACE_DEVICE_VLAN,
	                                property_info);
}

static void
finalize (GObject *object)
{
	NMDeviceVlanPrivate *priv = NM_DEVICE_VLAN_GET_PRIVATE (object);

	g_free (priv->hw_address);
	g_clear_object (&priv->parent);

	G_OBJECT_CLASS (nm_device_vlan_parent_class)->finalize (object);
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMDeviceVlan *device = NM_DEVICE_VLAN (object);

	switch (prop_id) {
	case PROP_HW_ADDRESS:
		g_value_set_string (value, nm_device_vlan_get_hw_address (device));
		break;
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

static void
nm_device_vlan_class_init (NMDeviceVlanClass *vlan_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (vlan_class);
	NMObjectClass *nm_object_class = NM_OBJECT_CLASS (vlan_class);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (vlan_class);

	g_type_class_add_private (vlan_class, sizeof (NMDeviceVlanPrivate));

	_nm_object_class_add_interface (nm_object_class, NM_DBUS_INTERFACE_DEVICE_VLAN);

	/* virtual methods */
	object_class->finalize = finalize;
	object_class->get_property = get_property;

	nm_object_class->init_dbus = init_dbus;

	device_class->connection_compatible = connection_compatible;
	device_class->get_setting_type = get_setting_type;
	device_class->get_hw_address = get_hw_address;

	/* properties */

	/**
	 * NMDeviceVlan:hw-address:
	 *
	 * The hardware (MAC) address of the device.
	 **/
	g_object_class_install_property
		(object_class, PROP_HW_ADDRESS,
		 g_param_spec_string (NM_DEVICE_VLAN_HW_ADDRESS, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceVlan:carrier:
	 *
	 * Whether the device has carrier.
	 **/
	g_object_class_install_property
		(object_class, PROP_CARRIER,
		 g_param_spec_boolean (NM_DEVICE_VLAN_CARRIER, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceVlan:parent:
	 *
	 * The devices's parent device.
	 **/
	g_object_class_install_property
	    (object_class, PROP_PARENT,
	     g_param_spec_object (NM_DEVICE_VLAN_PARENT, "", "",
	                          NM_TYPE_DEVICE,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceVlan:vlan-id:
	 *
	 * The device's VLAN ID.
	 **/
	g_object_class_install_property
		(object_class, PROP_VLAN_ID,
		 g_param_spec_uint (NM_DEVICE_VLAN_VLAN_ID, "", "",
		                    0, 4095, 0,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));
}
