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
 * Copyright 2011 - 2012 Red Hat, Inc.
 */

#include "config.h"

#include <string.h>
#include <linux/if_infiniband.h>
#include <netinet/ether.h>

#include <nm-setting-connection.h>
#include <nm-setting-infiniband.h>
#include <nm-utils.h>

#include "nm-default.h"
#include "nm-device-infiniband.h"
#include "nm-device-private.h"
#include "nm-object-private.h"

G_DEFINE_TYPE (NMDeviceInfiniband, nm_device_infiniband, NM_TYPE_DEVICE)

#define NM_DEVICE_INFINIBAND_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_INFINIBAND, NMDeviceInfinibandPrivate))

typedef struct {
	DBusGProxy *proxy;

	char *hw_address;
	gboolean carrier;
} NMDeviceInfinibandPrivate;

enum {
	PROP_0,
	PROP_HW_ADDRESS,
	PROP_CARRIER,

	LAST_PROP
};

/**
 * nm_device_infiniband_error_quark:
 *
 * Registers an error quark for #NMDeviceInfiniband if necessary.
 *
 * Returns: the error quark used for #NMDeviceInfiniband errors.
 **/
GQuark
nm_device_infiniband_error_quark (void)
{
	static GQuark quark = 0;

	if (G_UNLIKELY (quark == 0))
		quark = g_quark_from_static_string ("nm-device-infiniband-error-quark");
	return quark;
}

/**
 * nm_device_infiniband_new:
 * @connection: the #DBusGConnection
 * @path: the DBus object path of the device
 *
 * Creates a new #NMDeviceInfiniband.
 *
 * Returns: (transfer full): a new device
 **/
GObject *
nm_device_infiniband_new (DBusGConnection *connection, const char *path)
{
	GObject *device;

	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (path != NULL, NULL);

	device = g_object_new (NM_TYPE_DEVICE_INFINIBAND,
	                       NM_OBJECT_DBUS_CONNECTION, connection,
	                       NM_OBJECT_DBUS_PATH, path,
	                       NULL);
	_nm_object_ensure_inited (NM_OBJECT (device));
	return device;
}

/**
 * nm_device_infiniband_get_hw_address:
 * @device: a #NMDeviceInfiniband
 *
 * Gets the hardware (MAC) address of the #NMDeviceInfiniband
 *
 * Returns: the hardware address. This is the internal string used by the
 * device, and must not be modified.
 **/
const char *
nm_device_infiniband_get_hw_address (NMDeviceInfiniband *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_INFINIBAND (device), NULL);

	_nm_object_ensure_inited (NM_OBJECT (device));
	return NM_DEVICE_INFINIBAND_GET_PRIVATE (device)->hw_address;
}

/**
 * nm_device_infiniband_get_carrier:
 * @device: a #NMDeviceInfiniband
 *
 * Whether the device has carrier.
 *
 * Returns: %TRUE if the device has carrier
 **/
gboolean
nm_device_infiniband_get_carrier (NMDeviceInfiniband *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_INFINIBAND (device), FALSE);

	_nm_object_ensure_inited (NM_OBJECT (device));
	return NM_DEVICE_INFINIBAND_GET_PRIVATE (device)->carrier;
}

static gboolean
connection_compatible (NMDevice *device, NMConnection *connection, GError **error)
{
	NMSettingConnection *s_con;
	NMSettingInfiniband *s_infiniband;
	const char *ctype, *hwaddr_str;
	const GByteArray *mac;
	guint8 *hwaddr, hwaddr_buf[INFINIBAND_ALEN];

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);

	ctype = nm_setting_connection_get_connection_type (s_con);
	if (strcmp (ctype, NM_SETTING_INFINIBAND_SETTING_NAME) != 0) {
		g_set_error (error, NM_DEVICE_INFINIBAND_ERROR, NM_DEVICE_INFINIBAND_ERROR_NOT_INFINIBAND_CONNECTION,
		             "The connection was not a InfiniBand connection.");
		return FALSE;
	}

	s_infiniband = nm_connection_get_setting_infiniband (connection);
	if (!s_infiniband) {
		g_set_error (error, NM_DEVICE_INFINIBAND_ERROR, NM_DEVICE_INFINIBAND_ERROR_INVALID_INFINIBAND_CONNECTION,
		             "The connection was not a valid InfiniBand connection.");
		return FALSE;
	}

	hwaddr_str = nm_device_infiniband_get_hw_address (NM_DEVICE_INFINIBAND (device));
	if (hwaddr_str) {
		hwaddr = nm_utils_hwaddr_aton (hwaddr_str, ARPHRD_INFINIBAND, hwaddr_buf);
		if (!hwaddr) {
			g_set_error (error, NM_DEVICE_INFINIBAND_ERROR, NM_DEVICE_INFINIBAND_ERROR_INVALID_DEVICE_MAC,
			             "Invalid device MAC address.");
			return FALSE;
		}
		mac = nm_setting_infiniband_get_mac_address (s_infiniband);

		/* We only match against the last 8 bytes */
		if (mac && hwaddr && memcmp (mac->data + INFINIBAND_ALEN - 8, hwaddr + INFINIBAND_ALEN - 8, 8)) {
			g_set_error (error, NM_DEVICE_INFINIBAND_ERROR, NM_DEVICE_INFINIBAND_ERROR_MAC_MISMATCH,
			             "The MACs of the device and the connection didn't match.");
			return FALSE;
		}
	}

	return NM_DEVICE_CLASS (nm_device_infiniband_parent_class)->connection_compatible (device, connection, error);
}

static GType
get_setting_type (NMDevice *device)
{
	return NM_TYPE_SETTING_INFINIBAND;
}

static const char *
get_hw_address (NMDevice *device)
{
	return nm_device_infiniband_get_hw_address (NM_DEVICE_INFINIBAND (device));
}

/***********************************************************/

static void
nm_device_infiniband_init (NMDeviceInfiniband *device)
{
	_nm_device_set_device_type (NM_DEVICE (device), NM_DEVICE_TYPE_INFINIBAND);
}

static void
register_properties (NMDeviceInfiniband *device)
{
	NMDeviceInfinibandPrivate *priv = NM_DEVICE_INFINIBAND_GET_PRIVATE (device);
	const NMPropertiesInfo property_info[] = {
		{ NM_DEVICE_INFINIBAND_HW_ADDRESS, &priv->hw_address },
		{ NM_DEVICE_INFINIBAND_CARRIER,    &priv->carrier },
		{ NULL },
	};

	_nm_object_register_properties (NM_OBJECT (device),
	                                priv->proxy,
	                                property_info);
}

static void
constructed (GObject *object)
{
	NMDeviceInfinibandPrivate *priv = NM_DEVICE_INFINIBAND_GET_PRIVATE (object);

	G_OBJECT_CLASS (nm_device_infiniband_parent_class)->constructed (object);

	priv->proxy = _nm_object_new_proxy (NM_OBJECT (object), NULL, NM_DBUS_INTERFACE_DEVICE_INFINIBAND);
	register_properties (NM_DEVICE_INFINIBAND (object));
}

static void
dispose (GObject *object)
{
	NMDeviceInfinibandPrivate *priv = NM_DEVICE_INFINIBAND_GET_PRIVATE (object);

	g_clear_object (&priv->proxy);

	G_OBJECT_CLASS (nm_device_infiniband_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMDeviceInfinibandPrivate *priv = NM_DEVICE_INFINIBAND_GET_PRIVATE (object);

	g_free (priv->hw_address);

	G_OBJECT_CLASS (nm_device_infiniband_parent_class)->finalize (object);
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMDeviceInfiniband *device = NM_DEVICE_INFINIBAND (object);

	_nm_object_ensure_inited (NM_OBJECT (object));

	switch (prop_id) {
	case PROP_HW_ADDRESS:
		g_value_set_string (value, nm_device_infiniband_get_hw_address (device));
		break;
	case PROP_CARRIER:
		g_value_set_boolean (value, nm_device_infiniband_get_carrier (device));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_device_infiniband_class_init (NMDeviceInfinibandClass *ib_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (ib_class);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (ib_class);

	g_type_class_add_private (ib_class, sizeof (NMDeviceInfinibandPrivate));

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
	 * NMDeviceInfiniband:hw-address:
	 *
	 * The hardware (MAC) address of the device.
	 **/
	g_object_class_install_property
		(object_class, PROP_HW_ADDRESS,
		 g_param_spec_string (NM_DEVICE_INFINIBAND_HW_ADDRESS, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceInfiniband:carrier:
	 *
	 * Whether the device has carrier.
	 **/
	g_object_class_install_property
		(object_class, PROP_CARRIER,
		 g_param_spec_boolean (NM_DEVICE_INFINIBAND_CARRIER, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

}
