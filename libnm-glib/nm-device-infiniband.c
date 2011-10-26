/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * libnm_glib -- Access network status & information from glib applications
 *
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
 * Copyright (C) 2007 - 2008 Novell, Inc.
 * Copyright (C) 2007 - 2011 Red Hat, Inc.
 */

#include <config.h>
#include <string.h>
#include <linux/if_infiniband.h>
#include <netinet/ether.h>

#include <nm-setting-connection.h>
#include <nm-setting-infiniband.h>
#include <nm-utils.h>

#include "nm-device-infiniband.h"
#include "nm-device-private.h"
#include "nm-object-private.h"

#include "nm-device-infiniband-bindings.h"

G_DEFINE_TYPE (NMDeviceInfiniband, nm_device_infiniband, NM_TYPE_DEVICE)

#define NM_DEVICE_INFINIBAND_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_INFINIBAND, NMDeviceInfinibandPrivate))

typedef struct {
	DBusGProxy *proxy;

	char *hw_address;
	gboolean carrier;
	gboolean carrier_valid;
} NMDeviceInfinibandPrivate;

enum {
	PROP_0,
	PROP_HW_ADDRESS,
	PROP_CARRIER,

	LAST_PROP
};

#define DBUS_PROP_HW_ADDRESS "HwAddress"
#define DBUS_PROP_CARRIER "Carrier"

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
	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (path != NULL, NULL);

	return g_object_new (NM_TYPE_DEVICE_INFINIBAND,
	                     NM_OBJECT_DBUS_CONNECTION, connection,
	                     NM_OBJECT_DBUS_PATH, path,
	                     NULL);
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
	NMDeviceInfinibandPrivate *priv;

	g_return_val_if_fail (NM_IS_DEVICE_INFINIBAND (device), NULL);

	priv = NM_DEVICE_INFINIBAND_GET_PRIVATE (device);
	if (!priv->hw_address) {
		priv->hw_address = _nm_object_get_string_property (NM_OBJECT (device),
								   NM_DBUS_INTERFACE_DEVICE_INFINIBAND,
								   DBUS_PROP_HW_ADDRESS,
								   NULL);
	}

	return priv->hw_address;
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
	NMDeviceInfinibandPrivate *priv;

	g_return_val_if_fail (NM_IS_DEVICE_INFINIBAND (device), FALSE);

	priv = NM_DEVICE_INFINIBAND_GET_PRIVATE (device);
	if (!priv->carrier_valid) {
		priv->carrier = _nm_object_get_boolean_property (NM_OBJECT (device),
								 NM_DBUS_INTERFACE_DEVICE_INFINIBAND,
								 DBUS_PROP_CARRIER,
								 NULL);
		priv->carrier_valid = TRUE;
	}

	return priv->carrier;
}

static gboolean
connection_valid (NMDevice *device, NMConnection *connection)
{
	NMSettingConnection *s_con;
	NMSettingInfiniband *s_infiniband;
	const char *ctype, *hwaddr_str;
	const GByteArray *mac;
	guint8 *hwaddr, hwaddr_buf[INFINIBAND_ALEN];

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);

	ctype = nm_setting_connection_get_connection_type (s_con);
	if (strcmp (ctype, NM_SETTING_INFINIBAND_SETTING_NAME) != 0)
		return FALSE;

	s_infiniband = nm_connection_get_setting_infiniband (connection);
	if (!s_infiniband)
		return FALSE;

	hwaddr_str = nm_device_infiniband_get_hw_address (NM_DEVICE_INFINIBAND (device));
	if (hwaddr_str) {
		hwaddr = nm_utils_hwaddr_aton (hwaddr_str, ARPHRD_INFINIBAND, hwaddr_buf);
		mac = nm_setting_infiniband_get_mac_address (s_infiniband);
		if (mac && hwaddr && memcmp (mac->data, hwaddr, INFINIBAND_ALEN))
			return FALSE;
	}

	return TRUE;
}

/***********************************************************/

static void
nm_device_infiniband_init (NMDeviceInfiniband *device)
{
	NMDeviceInfinibandPrivate *priv = NM_DEVICE_INFINIBAND_GET_PRIVATE (device);

	priv->carrier = FALSE;
	priv->carrier_valid = FALSE;
}

static void
register_for_property_changed (NMDeviceInfiniband *device)
{
	NMDeviceInfinibandPrivate *priv = NM_DEVICE_INFINIBAND_GET_PRIVATE (device);
	const NMPropertiesChangedInfo property_changed_info[] = {
		{ NM_DEVICE_INFINIBAND_HW_ADDRESS, _nm_object_demarshal_generic, &priv->hw_address },
		{ NM_DEVICE_INFINIBAND_CARRIER,    _nm_object_demarshal_generic, &priv->carrier },
		{ NULL },
	};

	_nm_object_handle_properties_changed (NM_OBJECT (device),
	                                      priv->proxy,
	                                      property_changed_info);
}

static GObject*
constructor (GType type,
             guint n_construct_params,
             GObjectConstructParam *construct_params)
{
	GObject *object;
	NMDeviceInfinibandPrivate *priv;

	object = G_OBJECT_CLASS (nm_device_infiniband_parent_class)->constructor (type,
																			  n_construct_params,
																			  construct_params);
	if (!object)
		return NULL;

	priv = NM_DEVICE_INFINIBAND_GET_PRIVATE (object);

	priv->proxy = dbus_g_proxy_new_for_name (nm_object_get_connection (NM_OBJECT (object)),
	                                         NM_DBUS_SERVICE,
	                                         nm_object_get_path (NM_OBJECT (object)),
	                                         NM_DBUS_INTERFACE_DEVICE_INFINIBAND);

	register_for_property_changed (NM_DEVICE_INFINIBAND (object));

	return object;
}

static void
dispose (GObject *object)
{
	NMDeviceInfinibandPrivate *priv = NM_DEVICE_INFINIBAND_GET_PRIVATE (object);

	if (priv->proxy) {
		g_object_unref (priv->proxy);
		priv->proxy = NULL;
	}

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
nm_device_infiniband_class_init (NMDeviceInfinibandClass *eth_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (eth_class);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (eth_class);

	g_type_class_add_private (eth_class, sizeof (NMDeviceInfinibandPrivate));

	/* virtual methods */
	object_class->constructor = constructor;
	object_class->dispose = dispose;
	object_class->finalize = finalize;
	object_class->get_property = get_property;
	device_class->connection_valid = connection_valid;

	/* properties */

	/**
	 * NMDeviceInfiniband:hw-address:
	 *
	 * The hardware (MAC) address of the device.
	 **/
	g_object_class_install_property
		(object_class, PROP_HW_ADDRESS,
		 g_param_spec_string (NM_DEVICE_INFINIBAND_HW_ADDRESS,
		                      "Active MAC Address",
		                      "Currently set hardware MAC address",
		                      NULL,
		                      G_PARAM_READABLE));

	/**
	 * NMDeviceInfiniband:carrier:
	 *
	 * Whether the device has carrier.
	 **/
	g_object_class_install_property
		(object_class, PROP_CARRIER,
		 g_param_spec_boolean (NM_DEVICE_INFINIBAND_CARRIER,
		                       "Carrier",
		                       "Carrier",
		                       FALSE,
		                       G_PARAM_READABLE));

}

