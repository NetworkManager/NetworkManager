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

#include "config.h"

#include <string.h>
#include <glib/gi18n-lib.h>

#include <nm-setting-connection.h>
#include <nm-setting-wired.h>
#include <nm-setting-pppoe.h>
#include <nm-utils.h>

#include "nm-glib.h"
#include "nm-device-ethernet.h"
#include "nm-device-private.h"
#include "nm-object-private.h"

G_DEFINE_TYPE (NMDeviceEthernet, nm_device_ethernet, NM_TYPE_DEVICE)

#define NM_DEVICE_ETHERNET_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_ETHERNET, NMDeviceEthernetPrivate))

typedef struct {
	char *hw_address;
	char *perm_hw_address;
	guint32 speed;
	gboolean carrier;
} NMDeviceEthernetPrivate;

enum {
	PROP_0,
	PROP_HW_ADDRESS,
	PROP_PERM_HW_ADDRESS,
	PROP_SPEED,
	PROP_CARRIER,

	LAST_PROP
};

/**
 * nm_device_ethernet_get_hw_address:
 * @device: a #NMDeviceEthernet
 *
 * Gets the active hardware (MAC) address of the #NMDeviceEthernet
 *
 * Returns: the active hardware address. This is the internal string used by the
 * device, and must not be modified.
 **/
const char *
nm_device_ethernet_get_hw_address (NMDeviceEthernet *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_ETHERNET (device), NULL);

	return NM_DEVICE_ETHERNET_GET_PRIVATE (device)->hw_address;
}

/**
 * nm_device_ethernet_get_permanent_hw_address:
 * @device: a #NMDeviceEthernet
 *
 * Gets the permanent hardware (MAC) address of the #NMDeviceEthernet
 *
 * Returns: the permanent hardware address. This is the internal string used by the
 * device, and must not be modified.
 **/
const char *
nm_device_ethernet_get_permanent_hw_address (NMDeviceEthernet *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_ETHERNET (device), NULL);

	return NM_DEVICE_ETHERNET_GET_PRIVATE (device)->perm_hw_address;
}

/**
 * nm_device_ethernet_get_speed:
 * @device: a #NMDeviceEthernet
 *
 * Gets the speed of the #NMDeviceEthernet.
 *
 * Returns: the speed of the device
 **/
guint32
nm_device_ethernet_get_speed (NMDeviceEthernet *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_ETHERNET (device), 0);

	return NM_DEVICE_ETHERNET_GET_PRIVATE (device)->speed;
}

/**
 * nm_device_ethernet_get_carrier:
 * @device: a #NMDeviceEthernet
 *
 * Whether the device has carrier.
 *
 * Returns: %TRUE if the device has carrier
 **/
gboolean
nm_device_ethernet_get_carrier (NMDeviceEthernet *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_ETHERNET (device), FALSE);

	return NM_DEVICE_ETHERNET_GET_PRIVATE (device)->carrier;
}

static gboolean
connection_compatible (NMDevice *device, NMConnection *connection, GError **error)
{
	NMSettingWired *s_wired;
	gboolean is_pppoe = FALSE;

	if (!NM_DEVICE_CLASS (nm_device_ethernet_parent_class)->connection_compatible (device, connection, error))
		return FALSE;

	if (nm_connection_is_type (connection, NM_SETTING_PPPOE_SETTING_NAME))
		is_pppoe = TRUE;
	else if (!nm_connection_is_type (connection, NM_SETTING_WIRED_SETTING_NAME)) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
		                     _("The connection was not an Ethernet or PPPoE connection."));
		return FALSE;
	}

	s_wired = nm_connection_get_setting_wired (connection);
	/* Wired setting optional for PPPoE */
	if (s_wired) {
		const char *perm_addr, *setting_addr;

		/* FIXME: filter using s390 subchannels when they are exported over the bus */

		/* Check MAC address */
		perm_addr = nm_device_ethernet_get_permanent_hw_address (NM_DEVICE_ETHERNET (device));
		if (perm_addr) {
			if (!nm_utils_hwaddr_valid (perm_addr, ETH_ALEN)) {
				g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_FAILED,
				                     _("Invalid device MAC address."));
				return FALSE;
			}
			setting_addr = nm_setting_wired_get_mac_address (s_wired);
			if (setting_addr && !nm_utils_hwaddr_matches (setting_addr, -1, perm_addr, -1)) {
				g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
				                     _("The MACs of the device and the connection didn't match."));
				return FALSE;
			}
		}
	}

	return TRUE;
}

static GType
get_setting_type (NMDevice *device)
{
	return NM_TYPE_SETTING_WIRED;
}

static const char *
get_hw_address (NMDevice *device)
{
	return nm_device_ethernet_get_hw_address (NM_DEVICE_ETHERNET (device));
}

/***********************************************************/

static void
nm_device_ethernet_init (NMDeviceEthernet *device)
{
	_nm_device_set_device_type (NM_DEVICE (device), NM_DEVICE_TYPE_ETHERNET);
}

static void
init_dbus (NMObject *object)
{
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (object);
	const NMPropertiesInfo property_info[] = {
		{ NM_DEVICE_ETHERNET_HW_ADDRESS,           &priv->hw_address },
		{ NM_DEVICE_ETHERNET_PERMANENT_HW_ADDRESS, &priv->perm_hw_address },
		{ NM_DEVICE_ETHERNET_SPEED,                &priv->speed },
		{ NM_DEVICE_ETHERNET_CARRIER,              &priv->carrier },
		{ NULL },
	};

	NM_OBJECT_CLASS (nm_device_ethernet_parent_class)->init_dbus (object);

	_nm_object_register_properties (object,
	                                NM_DBUS_INTERFACE_DEVICE_WIRED,
	                                property_info);
}

static void
finalize (GObject *object)
{
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (object);

	g_free (priv->hw_address);
	g_free (priv->perm_hw_address);

	G_OBJECT_CLASS (nm_device_ethernet_parent_class)->finalize (object);
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMDeviceEthernet *device = NM_DEVICE_ETHERNET (object);

	switch (prop_id) {
	case PROP_HW_ADDRESS:
		g_value_set_string (value, nm_device_ethernet_get_hw_address (device));
		break;
	case PROP_PERM_HW_ADDRESS:
		g_value_set_string (value, nm_device_ethernet_get_permanent_hw_address (device));
		break;
	case PROP_SPEED:
		g_value_set_uint (value, nm_device_ethernet_get_speed (device));
		break;
	case PROP_CARRIER:
		g_value_set_boolean (value, nm_device_ethernet_get_carrier (device));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_device_ethernet_class_init (NMDeviceEthernetClass *eth_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (eth_class);
	NMObjectClass *nm_object_class = NM_OBJECT_CLASS (eth_class);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (eth_class);

	g_type_class_add_private (eth_class, sizeof (NMDeviceEthernetPrivate));

	_nm_object_class_add_interface (nm_object_class, NM_DBUS_INTERFACE_DEVICE_WIRED);

	/* virtual methods */
	object_class->finalize = finalize;
	object_class->get_property = get_property;

	nm_object_class->init_dbus = init_dbus;

	device_class->connection_compatible = connection_compatible;
	device_class->get_setting_type = get_setting_type;
	device_class->get_hw_address = get_hw_address;

	/* properties */

	/**
	 * NMDeviceEthernet:hw-address:
	 *
	 * The active hardware (MAC) address of the device.
	 **/
	g_object_class_install_property
		(object_class, PROP_HW_ADDRESS,
		 g_param_spec_string (NM_DEVICE_ETHERNET_HW_ADDRESS, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceEthernet:perm-hw-address:
	 *
	 * The permanent hardware (MAC) address of the device.
	 **/
	g_object_class_install_property
		(object_class, PROP_PERM_HW_ADDRESS,
		 g_param_spec_string (NM_DEVICE_ETHERNET_PERMANENT_HW_ADDRESS, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceEthernet:speed:
	 *
	 * The speed of the device.
	 **/
	g_object_class_install_property
		(object_class, PROP_SPEED,
		 g_param_spec_uint (NM_DEVICE_ETHERNET_SPEED, "", "",
		                    0, G_MAXUINT32, 0,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceEthernet:carrier:
	 *
	 * Whether the device has carrier.
	 **/
	g_object_class_install_property
		(object_class, PROP_CARRIER,
		 g_param_spec_boolean (NM_DEVICE_ETHERNET_CARRIER, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

}
