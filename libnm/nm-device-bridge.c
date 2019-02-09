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

#include "nm-default.h"

#include "nm-setting-bridge.h"

#include "nm-setting-connection.h"
#include "nm-utils.h"
#include "nm-device-bridge.h"
#include "nm-object-private.h"
#include "nm-core-internal.h"

G_DEFINE_TYPE (NMDeviceBridge, nm_device_bridge, NM_TYPE_DEVICE)

#define NM_DEVICE_BRIDGE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_BRIDGE, NMDeviceBridgePrivate))

typedef struct {
	char *hw_address;
	gboolean carrier;
	GPtrArray *slaves;
} NMDeviceBridgePrivate;

enum {
	PROP_0,
	PROP_HW_ADDRESS,
	PROP_CARRIER,
	PROP_SLAVES,

	LAST_PROP
};

/**
 * nm_device_bridge_get_hw_address:
 * @device: a #NMDeviceBridge
 *
 * Gets the hardware (MAC) address of the #NMDeviceBridge
 *
 * Returns: the hardware address. This is the internal string used by the
 * device, and must not be modified.
 **/
const char *
nm_device_bridge_get_hw_address (NMDeviceBridge *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_BRIDGE (device), NULL);

	return nm_str_not_empty (NM_DEVICE_BRIDGE_GET_PRIVATE (device)->hw_address);
}

/**
 * nm_device_bridge_get_carrier:
 * @device: a #NMDeviceBridge
 *
 * Whether the device has carrier.
 *
 * Returns: %TRUE if the device has carrier
 **/
gboolean
nm_device_bridge_get_carrier (NMDeviceBridge *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_BRIDGE (device), FALSE);

	return NM_DEVICE_BRIDGE_GET_PRIVATE (device)->carrier;
}

/**
 * nm_device_bridge_get_slaves:
 * @device: a #NMDeviceBridge
 *
 * Gets the devices currently enslaved to @device.
 *
 * Returns: (element-type NMDevice): the #GPtrArray containing
 * #NMDevices that are slaves of @device. This is the internal
 * copy used by the device, and must not be modified.
 **/
const GPtrArray *
nm_device_bridge_get_slaves (NMDeviceBridge *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_BRIDGE (device), FALSE);

	return NM_DEVICE_BRIDGE_GET_PRIVATE (device)->slaves;
}

static gboolean
connection_compatible (NMDevice *device, NMConnection *connection, GError **error)
{
	if (!NM_DEVICE_CLASS (nm_device_bridge_parent_class)->connection_compatible (device, connection, error))
		return FALSE;

	if (!nm_connection_is_type (connection, NM_SETTING_BRIDGE_SETTING_NAME)) {
		if (   _nm_connection_get_setting_bluetooth_for_nap (connection)
		    && nm_connection_is_type (connection, NM_SETTING_BLUETOOTH_SETTING_NAME)) {
			/* a bluetooth NAP setting is a compatible connection for a bridge. */
		} else {
			g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
			                     _("The connection was not a bridge connection."));
			return FALSE;
		}
	}

	/* FIXME: check ports? */

	return TRUE;
}

static GType
get_setting_type (NMDevice *device)
{
	return NM_TYPE_SETTING_BRIDGE;
}

static const char *
get_hw_address (NMDevice *device)
{
	return nm_device_bridge_get_hw_address (NM_DEVICE_BRIDGE (device));
}

/*****************************************************************************/

static void
nm_device_bridge_init (NMDeviceBridge *device)
{
	NMDeviceBridgePrivate *priv = NM_DEVICE_BRIDGE_GET_PRIVATE (device);

	priv->slaves = g_ptr_array_new ();
}

static void
init_dbus (NMObject *object)
{
	NMDeviceBridgePrivate *priv = NM_DEVICE_BRIDGE_GET_PRIVATE (object);
	const NMPropertiesInfo property_info[] = {
		{ NM_DEVICE_BRIDGE_HW_ADDRESS, &priv->hw_address },
		{ NM_DEVICE_BRIDGE_CARRIER,    &priv->carrier },
		{ NM_DEVICE_BRIDGE_SLAVES,     &priv->slaves, NULL, NM_TYPE_DEVICE },
		{ NULL },
	};

	NM_OBJECT_CLASS (nm_device_bridge_parent_class)->init_dbus (object);

	_nm_object_register_properties (object,
	                                NM_DBUS_INTERFACE_DEVICE_BRIDGE,
	                                property_info);
}

static void
dispose (GObject *object)
{
	NMDeviceBridgePrivate *priv = NM_DEVICE_BRIDGE_GET_PRIVATE (object);

	g_clear_pointer (&priv->slaves, g_ptr_array_unref);

	G_OBJECT_CLASS (nm_device_bridge_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMDeviceBridgePrivate *priv = NM_DEVICE_BRIDGE_GET_PRIVATE (object);

	g_free (priv->hw_address);

	G_OBJECT_CLASS (nm_device_bridge_parent_class)->finalize (object);
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMDeviceBridge *device = NM_DEVICE_BRIDGE (object);

	switch (prop_id) {
	case PROP_HW_ADDRESS:
		g_value_set_string (value, nm_device_bridge_get_hw_address (device));
		break;
	case PROP_CARRIER:
		g_value_set_boolean (value, nm_device_bridge_get_carrier (device));
		break;
	case PROP_SLAVES:
		g_value_take_boxed (value, _nm_utils_copy_object_array (nm_device_bridge_get_slaves (device)));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_device_bridge_class_init (NMDeviceBridgeClass *bridge_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (bridge_class);
	NMObjectClass *nm_object_class = NM_OBJECT_CLASS (bridge_class);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (bridge_class);

	g_type_class_add_private (bridge_class, sizeof (NMDeviceBridgePrivate));

	/* virtual methods */
	object_class->dispose = dispose;
	object_class->finalize = finalize;
	object_class->get_property = get_property;

	nm_object_class->init_dbus = init_dbus;

	device_class->connection_compatible = connection_compatible;
	device_class->get_setting_type = get_setting_type;
	device_class->get_hw_address = get_hw_address;

	/* properties */

	/**
	 * NMDeviceBridge:hw-address:
	 *
	 * The hardware (MAC) address of the device.
	 **/
	g_object_class_install_property
		(object_class, PROP_HW_ADDRESS,
		 g_param_spec_string (NM_DEVICE_BRIDGE_HW_ADDRESS, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceBridge:carrier:
	 *
	 * Whether the device has carrier.
	 **/
	g_object_class_install_property
		(object_class, PROP_CARRIER,
		 g_param_spec_boolean (NM_DEVICE_BRIDGE_CARRIER, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceBridge:slaves: (type GPtrArray(NMDevice))
	 *
	 * The devices enslaved to the bridge device.
	 **/
	g_object_class_install_property
		(object_class, PROP_SLAVES,
		 g_param_spec_boxed (NM_DEVICE_BRIDGE_SLAVES, "", "",
		                     G_TYPE_PTR_ARRAY,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));
}
