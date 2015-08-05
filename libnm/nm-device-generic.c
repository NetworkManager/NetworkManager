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
 * Copyright 2013 Red Hat, Inc.
 */

#include "config.h"

#include <string.h>

#include "nm-device-generic.h"
#include "nm-device-private.h"
#include "nm-object-private.h"
#include "nm-setting-generic.h"
#include "nm-setting-connection.h"

G_DEFINE_TYPE (NMDeviceGeneric, nm_device_generic, NM_TYPE_DEVICE)

#define NM_DEVICE_GENERIC_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_GENERIC, NMDeviceGenericPrivate))

typedef struct {
	char *hw_address;
	char *type_description;
} NMDeviceGenericPrivate;

enum {
	PROP_0,
	PROP_HW_ADDRESS,
	PROP_TYPE_DESCRIPTION,

	LAST_PROP
};

/**
 * nm_device_generic_get_hw_address:
 * @device: a #NMDeviceGeneric
 *
 * Gets the hardware address of the #NMDeviceGeneric
 *
 * Returns: the hardware address. This is the internal string used by the
 * device, and must not be modified.
 **/
const char *
nm_device_generic_get_hw_address (NMDeviceGeneric *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_GENERIC (device), NULL);

	return NM_DEVICE_GENERIC_GET_PRIVATE (device)->hw_address;
}

/***********************************************************/

static const char *
get_type_description (NMDevice *device)
{
	NMDeviceGenericPrivate *priv = NM_DEVICE_GENERIC_GET_PRIVATE (device);

	return priv->type_description;
}

static const char *
get_hw_address (NMDevice *device)
{
	return nm_device_generic_get_hw_address (NM_DEVICE_GENERIC (device));
}

static gboolean
connection_compatible (NMDevice *device, NMConnection *connection, GError **error)
{
	const char *iface_name;

	if (!NM_DEVICE_CLASS (nm_device_generic_parent_class)->connection_compatible (device, connection, error))
		return FALSE;

	if (!nm_connection_is_type (connection, NM_SETTING_GENERIC_SETTING_NAME)) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
		                     _("The connection was not a generic connection."));
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
	return NM_TYPE_SETTING_GENERIC;
}

/***********************************************************/

static void
nm_device_generic_init (NMDeviceGeneric *device)
{
	_nm_device_set_device_type (NM_DEVICE (device), NM_DEVICE_TYPE_GENERIC);
}

static void
init_dbus (NMObject *object)
{
	NMDeviceGenericPrivate *priv = NM_DEVICE_GENERIC_GET_PRIVATE (object);
	const NMPropertiesInfo property_info[] = {
		{ NM_DEVICE_GENERIC_HW_ADDRESS, &priv->hw_address },
		{ NM_DEVICE_GENERIC_TYPE_DESCRIPTION, &priv->type_description },
		{ NULL },
	};

	NM_OBJECT_CLASS (nm_device_generic_parent_class)->init_dbus (object);

	_nm_object_register_properties (object,
	                                NM_DBUS_INTERFACE_DEVICE_GENERIC,
	                                property_info);
}

static void
finalize (GObject *object)
{
	NMDeviceGenericPrivate *priv = NM_DEVICE_GENERIC_GET_PRIVATE (object);

	g_free (priv->hw_address);
	g_free (priv->type_description);

	G_OBJECT_CLASS (nm_device_generic_parent_class)->finalize (object);
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMDeviceGenericPrivate *priv = NM_DEVICE_GENERIC_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_HW_ADDRESS:
		g_value_set_string (value, priv->hw_address);
		break;
	case PROP_TYPE_DESCRIPTION:
		g_value_set_string (value, priv->type_description);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_device_generic_class_init (NMDeviceGenericClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMObjectClass *nm_object_class = NM_OBJECT_CLASS (klass);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NMDeviceGenericPrivate));

	_nm_object_class_add_interface (nm_object_class, NM_DBUS_INTERFACE_DEVICE_GENERIC);

	object_class->finalize = finalize;
	object_class->get_property = get_property;

	nm_object_class->init_dbus = init_dbus;

	device_class->get_type_description = get_type_description;
	device_class->get_hw_address = get_hw_address;
	device_class->connection_compatible = connection_compatible;
	device_class->get_setting_type = get_setting_type;

	/**
	 * NMDeviceGeneric:hw-address:
	 *
	 * The hardware address of the device.
	 **/
	g_object_class_install_property
		(object_class, PROP_HW_ADDRESS,
		 g_param_spec_string (NM_DEVICE_GENERIC_HW_ADDRESS, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceGeneric:type-description:
	 *
	 * A description of the specific type of device this is, or %NULL
	 * if not known.
	 **/
	g_object_class_install_property
		(object_class, PROP_TYPE_DESCRIPTION,
		 g_param_spec_string (NM_DEVICE_GENERIC_TYPE_DESCRIPTION, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));
}
