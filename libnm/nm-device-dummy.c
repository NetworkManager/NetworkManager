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
 * Copyright 2017 Red Hat, Inc.
 */

#include "nm-default.h"

#include <string.h>

#include "nm-device-dummy.h"
#include "nm-object-private.h"
#include "nm-setting-dummy.h"
#include "nm-setting-connection.h"

G_DEFINE_TYPE (NMDeviceDummy, nm_device_dummy, NM_TYPE_DEVICE)

#define NM_DEVICE_DUMMY_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_DUMMY, NMDeviceDummyPrivate))

typedef struct {
	char *hw_address;
} NMDeviceDummyPrivate;

enum {
	PROP_0,
	PROP_HW_ADDRESS,

	LAST_PROP
};

/*****************************************************************************/

/**
 * nm_device_dummy_get_hw_address:
 * @device: a #NMDeviceDummy
 *
 * Gets the hardware (MAC) address of the #NMDeviceDummy
 *
 * Returns: the hardware address. This is the internal string used by the
 * device, and must not be modified.
 *
 * Since: 1.10
 **/
const char *
nm_device_dummy_get_hw_address (NMDeviceDummy *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_DUMMY (device), NULL);

	return nm_str_not_empty (NM_DEVICE_DUMMY_GET_PRIVATE (device)->hw_address);
}

static gboolean
connection_compatible (NMDevice *device, NMConnection *connection, GError **error)
{
	const char *iface_name;

	if (!NM_DEVICE_CLASS (nm_device_dummy_parent_class)->connection_compatible (device, connection, error))
		return FALSE;

	if (!nm_connection_is_type (connection, NM_SETTING_DUMMY_SETTING_NAME)) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
		                     _("The connection was not a dummy connection."));
		return FALSE;
	}

	iface_name = nm_connection_get_interface_name (connection);
	if (!iface_name) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INVALID_CONNECTION,
		                     _("The connection did not specify an interface name."));
		return FALSE;
	}

	return TRUE;
}

static GType
get_setting_type (NMDevice *device)
{
	return NM_TYPE_SETTING_DUMMY;
}

static const char *
get_hw_address (NMDevice *device)
{
	return nm_device_dummy_get_hw_address (NM_DEVICE_DUMMY (device));
}

/*****************************************************************************/

static void
nm_device_dummy_init (NMDeviceDummy *device)
{
}

static void
init_dbus (NMObject *object)
{
	NMDeviceDummyPrivate *priv = NM_DEVICE_DUMMY_GET_PRIVATE (object);
	const NMPropertiesInfo property_info[] = {
		{ NM_DEVICE_DUMMY_HW_ADDRESS, &priv->hw_address },
		{ NULL },
	};

	NM_OBJECT_CLASS (nm_device_dummy_parent_class)->init_dbus (object);

	_nm_object_register_properties (object,
	                                NM_DBUS_INTERFACE_DEVICE_DUMMY,
	                                property_info);
}

static void
dispose (GObject *object)
{
	NMDeviceDummyPrivate *priv = NM_DEVICE_DUMMY_GET_PRIVATE (object);

	g_clear_pointer (&priv->hw_address, g_free);

	G_OBJECT_CLASS (nm_device_dummy_parent_class)->dispose (object);
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMDeviceDummy *device = NM_DEVICE_DUMMY (object);

	switch (prop_id) {
	case PROP_HW_ADDRESS:
		g_value_set_string (value, nm_device_dummy_get_hw_address (device));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_device_dummy_class_init (NMDeviceDummyClass *dummy_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (dummy_class);
	NMObjectClass *nm_object_class = NM_OBJECT_CLASS (dummy_class);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (dummy_class);

	g_type_class_add_private (dummy_class, sizeof (NMDeviceDummyPrivate));

	object_class->dispose = dispose;
	object_class->get_property = get_property;

	nm_object_class->init_dbus = init_dbus;

	device_class->connection_compatible = connection_compatible;
	device_class->get_hw_address = get_hw_address;
	device_class->get_setting_type = get_setting_type;

	/**
	 * NMDeviceDummy:hw-address:
	 *
	 * The active hardware (MAC) address of the device.
	 *
	 * Since: 1.10
	 **/
	g_object_class_install_property
		(object_class, PROP_HW_ADDRESS,
		 g_param_spec_string (NM_DEVICE_DUMMY_HW_ADDRESS, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));
}
