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
#include <netinet/ether.h>

#include <nm-setting-connection.h>
#include <nm-setting-wired.h>
#include <nm-setting-pppoe.h>

#include "nm-default.h"
#include "nm-device-ethernet.h"
#include "nm-device-private.h"
#include "nm-object-private.h"

G_DEFINE_TYPE (NMDeviceEthernet, nm_device_ethernet, NM_TYPE_DEVICE)

#define NM_DEVICE_ETHERNET_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_ETHERNET, NMDeviceEthernetPrivate))

typedef struct {
	DBusGProxy *proxy;

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
 * nm_device_ethernet_error_quark:
 *
 * Registers an error quark for #NMDeviceEthernet if necessary.
 *
 * Returns: the error quark used for #NMDeviceEthernet errors.
 **/
GQuark
nm_device_ethernet_error_quark (void)
{
	static GQuark quark = 0;

	if (G_UNLIKELY (quark == 0))
		quark = g_quark_from_static_string ("nm-device-ethernet-error-quark");
	return quark;
}

/**
 * nm_device_ethernet_new:
 * @connection: the #DBusGConnection
 * @path: the DBus object path of the device
 *
 * Creates a new #NMDeviceEthernet.
 *
 * Returns: (transfer full): a new device
 **/
GObject *
nm_device_ethernet_new (DBusGConnection *connection, const char *path)
{
	GObject *device;

	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (path != NULL, NULL);

	device = g_object_new (NM_TYPE_DEVICE_ETHERNET,
	                       NM_OBJECT_DBUS_CONNECTION, connection,
	                       NM_OBJECT_DBUS_PATH, path,
	                       NULL);
	_nm_object_ensure_inited (NM_OBJECT (device));
	return device;
}

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

	_nm_object_ensure_inited (NM_OBJECT (device));
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

	_nm_object_ensure_inited (NM_OBJECT (device));
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

	_nm_object_ensure_inited (NM_OBJECT (device));
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

	_nm_object_ensure_inited (NM_OBJECT (device));
	return NM_DEVICE_ETHERNET_GET_PRIVATE (device)->carrier;
}

static gboolean
connection_compatible (NMDevice *device, NMConnection *connection, GError **error)
{
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	const char *ctype;
	gboolean is_pppoe = FALSE;

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);

	ctype = nm_setting_connection_get_connection_type (s_con);
	if (!strcmp (ctype, NM_SETTING_PPPOE_SETTING_NAME))
		is_pppoe = TRUE;
	else if (strcmp (ctype, NM_SETTING_WIRED_SETTING_NAME) != 0) {
		g_set_error (error, NM_DEVICE_ETHERNET_ERROR, NM_DEVICE_ETHERNET_ERROR_NOT_ETHERNET_CONNECTION,
		             "The connection was not a wired or PPPoE connection.");
		return FALSE;
	}

	s_wired = nm_connection_get_setting_wired (connection);
	/* Wired setting optional for PPPoE */
	if (!is_pppoe && !s_wired) {
		g_set_error (error, NM_DEVICE_ETHERNET_ERROR, NM_DEVICE_ETHERNET_ERROR_INVALID_ETHERNET_CONNECTION,
		             "The connection was not a valid Ethernet connection.");
		return FALSE;
	}

	if (s_wired) {
		const GByteArray *mac;
		const char *perm_str;
		struct ether_addr *perm_mac;

		/* FIXME: filter using s390 subchannels when they are exported over the bus */

		/* Check MAC address */
		perm_str = nm_device_ethernet_get_permanent_hw_address (NM_DEVICE_ETHERNET (device));
		if (perm_str) {
			perm_mac = ether_aton (perm_str);
			if (!perm_mac) {
				g_set_error (error, NM_DEVICE_ETHERNET_ERROR, NM_DEVICE_ETHERNET_ERROR_INVALID_DEVICE_MAC,
				             "Invalid device MAC address.");
				return FALSE;
			}
			mac = nm_setting_wired_get_mac_address (s_wired);
			if (mac && perm_mac && memcmp (mac->data, perm_mac->ether_addr_octet, ETH_ALEN)) {
				g_set_error (error, NM_DEVICE_ETHERNET_ERROR, NM_DEVICE_ETHERNET_ERROR_MAC_MISMATCH,
				             "The MACs of the device and the connection didn't match.");
				return FALSE;
			}
		}
	}

	return NM_DEVICE_CLASS (nm_device_ethernet_parent_class)->connection_compatible (device, connection, error);
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
register_properties (NMDeviceEthernet *device)
{
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (device);
	const NMPropertiesInfo property_info[] = {
		{ NM_DEVICE_ETHERNET_HW_ADDRESS,           &priv->hw_address },
		{ NM_DEVICE_ETHERNET_PERMANENT_HW_ADDRESS, &priv->perm_hw_address },
		{ NM_DEVICE_ETHERNET_SPEED,                &priv->speed },
		{ NM_DEVICE_ETHERNET_CARRIER,              &priv->carrier },
		{ NULL },
	};

	_nm_object_register_properties (NM_OBJECT (device),
	                                priv->proxy,
	                                property_info);
}

static void
constructed (GObject *object)
{
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (object);

	G_OBJECT_CLASS (nm_device_ethernet_parent_class)->constructed (object);

	priv->proxy = _nm_object_new_proxy (NM_OBJECT (object), NULL, NM_DBUS_INTERFACE_DEVICE_WIRED);
	register_properties (NM_DEVICE_ETHERNET (object));
}

static void
dispose (GObject *object)
{
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (object);

	g_clear_object (&priv->proxy);

	G_OBJECT_CLASS (nm_device_ethernet_parent_class)->dispose (object);
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

	_nm_object_ensure_inited (NM_OBJECT (object));

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
	NMDeviceClass *device_class = NM_DEVICE_CLASS (eth_class);

	g_type_class_add_private (eth_class, sizeof (NMDeviceEthernetPrivate));

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
