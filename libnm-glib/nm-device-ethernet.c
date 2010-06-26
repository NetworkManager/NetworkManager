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
 * Copyright (C) 2007 - 2010 Red Hat, Inc.
 */

#include "nm-device-ethernet.h"
#include "nm-device-private.h"
#include "nm-object-private.h"

#include "nm-device-ethernet-bindings.h"

G_DEFINE_TYPE (NMDeviceEthernet, nm_device_ethernet, NM_TYPE_DEVICE)

#define NM_DEVICE_ETHERNET_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_ETHERNET, NMDeviceEthernetPrivate))

typedef struct {
	DBusGProxy *proxy;

	char *hw_address;
	char *perm_hw_address;
	guint32 speed;
	gboolean carrier;
	gboolean carrier_valid;

	gboolean disposed;
} NMDeviceEthernetPrivate;

enum {
	PROP_0,
	PROP_HW_ADDRESS,
	PROP_PERM_HW_ADDRESS,
	PROP_SPEED,
	PROP_CARRIER,

	LAST_PROP
};

#define DBUS_PROP_HW_ADDRESS "HwAddress"
#define DBUS_PROP_PERM_HW_ADDRESS "PermHwAddress"
#define DBUS_PROP_SPEED "Speed"
#define DBUS_PROP_CARRIER "Carrier"

/**
 * nm_device_ethernet_new:
 * @connection: the #DBusGConnection
 * @path: the DBus object path of the device
 *
 * Creates a new #NMDeviceEthernet.
 *
 * Returns: a new device
 **/
GObject *
nm_device_ethernet_new (DBusGConnection *connection, const char *path)
{
	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (path != NULL, NULL);

	return g_object_new (NM_TYPE_DEVICE_ETHERNET,
	                     NM_OBJECT_DBUS_CONNECTION, connection,
	                     NM_OBJECT_DBUS_PATH, path,
	                     NULL);
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
	NMDeviceEthernetPrivate *priv;

	g_return_val_if_fail (NM_IS_DEVICE_ETHERNET (device), NULL);

	priv = NM_DEVICE_ETHERNET_GET_PRIVATE (device);
	if (!priv->hw_address) {
		priv->hw_address = _nm_object_get_string_property (NM_OBJECT (device),
		                                                  NM_DBUS_INTERFACE_DEVICE_WIRED,
		                                                  DBUS_PROP_HW_ADDRESS);
	}

	return priv->hw_address;
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
	NMDeviceEthernetPrivate *priv;

	g_return_val_if_fail (NM_IS_DEVICE_ETHERNET (device), NULL);

	priv = NM_DEVICE_ETHERNET_GET_PRIVATE (device);
	if (!priv->perm_hw_address) {
		priv->perm_hw_address = _nm_object_get_string_property (NM_OBJECT (device),
		                                                        NM_DBUS_INTERFACE_DEVICE_WIRED,
		                                                        DBUS_PROP_PERM_HW_ADDRESS);
	}

	return priv->perm_hw_address;
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
	NMDeviceEthernetPrivate *priv;

	g_return_val_if_fail (NM_IS_DEVICE_ETHERNET (device), 0);

	priv = NM_DEVICE_ETHERNET_GET_PRIVATE (device);
	if (!priv->speed) {
		priv->speed = _nm_object_get_uint_property (NM_OBJECT (device),
		                                           NM_DBUS_INTERFACE_DEVICE_WIRED,
		                                           DBUS_PROP_SPEED);
	}

	return priv->speed;
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
	NMDeviceEthernetPrivate *priv;

	g_return_val_if_fail (NM_IS_DEVICE_ETHERNET (device), FALSE);

	priv = NM_DEVICE_ETHERNET_GET_PRIVATE (device);
	if (!priv->carrier_valid) {
		priv->carrier = _nm_object_get_boolean_property (NM_OBJECT (device),
		                                                NM_DBUS_INTERFACE_DEVICE_WIRED,
		                                                DBUS_PROP_CARRIER);
		priv->carrier_valid = TRUE;
	}

	return priv->carrier;
}

static void
nm_device_ethernet_init (NMDeviceEthernet *device)
{
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (device);

	priv->disposed = FALSE;
	priv->carrier = FALSE;
	priv->carrier_valid = FALSE;
}

static void
register_for_property_changed (NMDeviceEthernet *device)
{
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (device);
	const NMPropertiesChangedInfo property_changed_info[] = {
		{ NM_DEVICE_ETHERNET_HW_ADDRESS,           _nm_object_demarshal_generic, &priv->hw_address },
		{ NM_DEVICE_ETHERNET_PERMANENT_HW_ADDRESS, _nm_object_demarshal_generic, &priv->perm_hw_address },
		{ NM_DEVICE_ETHERNET_SPEED,                _nm_object_demarshal_generic, &priv->speed },
		{ NM_DEVICE_ETHERNET_CARRIER,              _nm_object_demarshal_generic, &priv->carrier },
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
	NMDeviceEthernetPrivate *priv;

	object = G_OBJECT_CLASS (nm_device_ethernet_parent_class)->constructor (type,
																				  n_construct_params,
																				  construct_params);
	if (!object)
		return NULL;

	priv = NM_DEVICE_ETHERNET_GET_PRIVATE (object);

	priv->proxy = dbus_g_proxy_new_for_name (nm_object_get_connection (NM_OBJECT (object)),
	                                         NM_DBUS_SERVICE,
	                                         nm_object_get_path (NM_OBJECT (object)),
	                                         NM_DBUS_INTERFACE_DEVICE_WIRED);

	register_for_property_changed (NM_DEVICE_ETHERNET (object));

	return object;
}

static void
dispose (GObject *object)
{
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (object);

	if (priv->disposed) {
		G_OBJECT_CLASS (nm_device_ethernet_parent_class)->dispose (object);
		return;
	}

	priv->disposed = TRUE;

	g_object_unref (priv->proxy);

	G_OBJECT_CLASS (nm_device_ethernet_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (object);

	if (priv->hw_address)
		g_free (priv->hw_address);

	if (priv->perm_hw_address)
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
nm_device_ethernet_class_init (NMDeviceEthernetClass *device_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (device_class);

	g_type_class_add_private (device_class, sizeof (NMDeviceEthernetPrivate));

	/* virtual methods */
	object_class->constructor = constructor;
	object_class->dispose = dispose;
	object_class->finalize = finalize;
	object_class->get_property = get_property;

	/* properties */

	/**
	 * NMDeviceEthernet:hw-address:
	 *
	 * The active hardware (MAC) address of the device.
	 **/
	g_object_class_install_property
		(object_class, PROP_HW_ADDRESS,
		 g_param_spec_string (NM_DEVICE_ETHERNET_HW_ADDRESS,
						  "Active MAC Address",
						  "Currently set hardware MAC address",
						  NULL,
						  G_PARAM_READABLE));

	/**
	 * NMDeviceEthernet:perm-hw-address:
	 *
	 * The permanent hardware (MAC) address of the device.
	 **/
	g_object_class_install_property
		(object_class, PROP_PERM_HW_ADDRESS,
		 g_param_spec_string (NM_DEVICE_ETHERNET_PERMANENT_HW_ADDRESS,
						  "Permanent MAC Address",
						  "Permanent hardware MAC address",
						  NULL,
						  G_PARAM_READABLE));

	/**
	 * NMDeviceEthernet:speed:
	 *
	 * The speed of the device.
	 **/
	g_object_class_install_property
		(object_class, PROP_SPEED,
		 g_param_spec_uint (NM_DEVICE_ETHERNET_SPEED,
					    "Speed",
					    "Speed",
					    0, G_MAXUINT32, 0,
					    G_PARAM_READABLE));

	/**
	 * NMDeviceEthernet:carrier:
	 *
	 * Whether the device has carrier.
	 **/
	g_object_class_install_property
		(object_class, PROP_CARRIER,
		 g_param_spec_boolean (NM_DEVICE_ETHERNET_CARRIER,
					    "Carrier",
					    "Carrier",
					    FALSE,
					    G_PARAM_READABLE));

}

