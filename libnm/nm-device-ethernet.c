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

#include "nm-device-ethernet.h"

#include "nm-setting-connection.h"
#include "nm-setting-wired.h"
#include "nm-setting-pppoe.h"
#include "nm-utils.h"
#include "nm-object-private.h"

G_DEFINE_TYPE (NMDeviceEthernet, nm_device_ethernet, NM_TYPE_DEVICE)

#define NM_DEVICE_ETHERNET_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_ETHERNET, NMDeviceEthernetPrivate))

typedef struct {
	char *hw_address;
	char *perm_hw_address;
	guint32 speed;
	gboolean carrier;
	char **s390_subchannels;
} NMDeviceEthernetPrivate;

enum {
	PROP_0,
	PROP_HW_ADDRESS,
	PROP_PERM_HW_ADDRESS,
	PROP_SPEED,
	PROP_CARRIER,
	PROP_S390_SUBCHANNELS,

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

	return nm_str_not_empty (NM_DEVICE_ETHERNET_GET_PRIVATE (device)->hw_address);
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

	return nm_str_not_empty (NM_DEVICE_ETHERNET_GET_PRIVATE (device)->perm_hw_address);
}

/**
 * nm_device_ethernet_get_speed:
 * @device: a #NMDeviceEthernet
 *
 * Gets the speed of the #NMDeviceEthernet in Mbit/s.
 *
 * Returns: the speed of the device in Mbit/s
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

/**
 * nm_device_ethernet_get_s390_subchannels:
 * @device: a #NMDeviceEthernet
 *
 * Return the list of s390 subchannels if the device supports them.
 *
 * Returns: (transfer none) (element-type utf8): array of strings, each specifying
 *   one subchannel the s390 device uses to communicate to the host.
 *
 * Since: 1.2
 **/
const char * const *
nm_device_ethernet_get_s390_subchannels (NMDeviceEthernet *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_ETHERNET (device), NULL);

	return (const char * const *) NM_DEVICE_ETHERNET_GET_PRIVATE (device)->s390_subchannels;
}

static guint32
_subchannels_count_num (const char * const *array)
{
	int i;

	if (!array)
		return 0;
	for (i = 0; array[i]; i++)
		/* NOP */;
	return i;
}

static gboolean
match_subchans (NMDeviceEthernet *self, NMSettingWired *s_wired, gboolean *try_mac)
{
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);
	const char * const *subchans;
	guint32 num1, num2;
	int i, j;

	*try_mac = TRUE;

	subchans = nm_setting_wired_get_s390_subchannels (s_wired);
	num1 = _subchannels_count_num (subchans);
	num2 = _subchannels_count_num ((const char * const *) priv->s390_subchannels);
	/* connection has no subchannels */
	if (num1 == 0)
		return TRUE;
	/* connection requires subchannels but the device has none */
	if (num2 == 0)
		return FALSE;
	/* number of subchannels differ */
	if (num1 != num2)
		return FALSE;

	/* Make sure each subchannel in the connection is a subchannel of this device */
	for (i = 0; subchans[i]; i++) {
		const char *candidate = subchans[i];
		gboolean found = FALSE;

		for (j = 0; priv->s390_subchannels[j]; j++) {
			if (!g_strcmp0 (priv->s390_subchannels[j], candidate))
				found = TRUE;
		}
		if (!found)
			return FALSE;  /* a subchannel was not found */
	}

	*try_mac = FALSE;
	return TRUE;
}

static gboolean
connection_compatible (NMDevice *device, NMConnection *connection, GError **error)
{
	NMSettingWired *s_wired;

	if (!NM_DEVICE_CLASS (nm_device_ethernet_parent_class)->connection_compatible (device, connection, error))
		return FALSE;

	if (nm_connection_is_type (connection, NM_SETTING_PPPOE_SETTING_NAME)) {
		/* NOP */
	} else if (!nm_connection_is_type (connection, NM_SETTING_WIRED_SETTING_NAME)) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
		                     _("The connection was not an Ethernet or PPPoE connection."));
		return FALSE;
	}

	s_wired = nm_connection_get_setting_wired (connection);
	/* Wired setting optional for PPPoE */
	if (s_wired) {
		const char *perm_addr, *s_mac;
		gboolean try_mac = TRUE;
		const char * const *mac_blacklist;
		int i;

		/* Check s390 subchannels */
		if (!match_subchans (NM_DEVICE_ETHERNET (device), s_wired, &try_mac)) {
			g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
			                     _("The connection and device differ in S390 subchannels."));
			return FALSE;
		}

		/* Check MAC address */
		perm_addr = nm_device_ethernet_get_permanent_hw_address (NM_DEVICE_ETHERNET (device));
		s_mac = nm_setting_wired_get_mac_address (s_wired);
		if (perm_addr) {
			/* Virtual devices will have empty permanent addr but they should not be excluded
			 * from the MAC address check specified in the connection */
			if (*perm_addr == 0)
				perm_addr = nm_device_ethernet_get_hw_address (NM_DEVICE_ETHERNET (device));

			if (!nm_utils_hwaddr_valid (perm_addr, ETH_ALEN)) {
				g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_FAILED,
				                     _("Invalid device MAC address %s."), perm_addr);
				return FALSE;
			}
			if (try_mac && s_mac && !nm_utils_hwaddr_matches (s_mac, -1, perm_addr, -1)) {
				g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
				                     _("The MACs of the device and the connection do not match."));
				return FALSE;
			}

			/* Check for MAC address blacklist */
			mac_blacklist = nm_setting_wired_get_mac_address_blacklist (s_wired);
			for (i = 0; mac_blacklist[i]; i++) {
				if (!nm_utils_hwaddr_valid (mac_blacklist[i], ETH_ALEN)) {
					g_warn_if_reached ();
					g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
				                     _("Invalid MAC in the blacklist: %s."), mac_blacklist[i]);
					return FALSE;
				}

				if (nm_utils_hwaddr_matches (mac_blacklist[i], -1, perm_addr, -1)) {
					g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
				                     _("Device MAC (%s) is blacklisted by the connection."), perm_addr);
					return FALSE;
				}
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

/*****************************************************************************/

static void
nm_device_ethernet_init (NMDeviceEthernet *device)
{
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
		{ NM_DEVICE_ETHERNET_S390_SUBCHANNELS,     &priv->s390_subchannels },
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
	g_strfreev (priv->s390_subchannels);

	G_OBJECT_CLASS (nm_device_ethernet_parent_class)->finalize (object);
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMDeviceEthernet *device = NM_DEVICE_ETHERNET (object);
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (device);

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
	case PROP_S390_SUBCHANNELS:
		g_value_set_boxed (value, priv->s390_subchannels);
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

	/**
	 * NMDeviceEthernet:s390-subchannels:
	 *
	 * Identifies subchannels of this network device used for
	 * communication with z/VM or s390 host.
	 *
	 * Since: 1.2
	 **/
	g_object_class_install_property
		(object_class, PROP_S390_SUBCHANNELS,
		 g_param_spec_boxed (NM_DEVICE_ETHERNET_S390_SUBCHANNELS, "", "",
		                     G_TYPE_STRV,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));
}
