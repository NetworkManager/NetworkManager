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
 * Copyright 2013 Red Hat, Inc.
 */

#include <config.h>

#include <string.h>

#include "nm-device-generic.h"
#include "nm-device-private.h"
#include "nm-object-private.h"
#include "nm-setting-generic.h"

G_DEFINE_TYPE (NMDeviceGeneric, nm_device_generic, NM_TYPE_DEVICE)

#define NM_DEVICE_GENERIC_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_GENERIC, NMDeviceGenericPrivate))

typedef struct {
	DBusGProxy *proxy;

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
 * nm_device_generic_error_quark:
 *
 * Registers an error quark for #NMDeviceGeneric if necessary.
 *
 * Returns: the error quark used for #NMDeviceGeneric errors.
 *
 * Since: 0.9.10
 **/
GQuark
nm_device_generic_error_quark (void)
{
	static GQuark quark = 0;

	if (G_UNLIKELY (quark == 0))
		quark = g_quark_from_static_string ("nm-device-generic-error-quark");
	return quark;
}

/**
 * nm_device_generic_new:
 * @connection: the #DBusGConnection
 * @path: the DBus object path of the device
 *
 * Creates a new #NMDeviceGeneric.
 *
 * Returns: (transfer full): a new device
 *
 * Since: 0.9.10
 **/
GObject *
nm_device_generic_new (DBusGConnection *connection, const char *path)
{
	GObject *device;

	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (path != NULL, NULL);

	device = g_object_new (NM_TYPE_DEVICE_GENERIC,
	                       NM_OBJECT_DBUS_CONNECTION, connection,
	                       NM_OBJECT_DBUS_PATH, path,
	                       NULL);
	_nm_object_ensure_inited (NM_OBJECT (device));
	return device;
}

/**
 * nm_device_generic_get_hw_address:
 * @device: a #NMDeviceGeneric
 *
 * Gets the hardware address of the #NMDeviceGeneric
 *
 * Returns: the hardware address. This is the internal string used by the
 * device, and must not be modified.
 *
 * Since: 0.9.10
 **/
const char *
nm_device_generic_get_hw_address (NMDeviceGeneric *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_GENERIC (device), NULL);

	_nm_object_ensure_inited (NM_OBJECT (device));
	return NM_DEVICE_GENERIC_GET_PRIVATE (device)->hw_address;
}

/***********************************************************/

static const char *
get_type_description (NMDevice *device)
{
	NMDeviceGenericPrivate *priv = NM_DEVICE_GENERIC_GET_PRIVATE (device);

	_nm_object_ensure_inited (NM_OBJECT (device));
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
	NMSettingConnection *s_con;
	const char *ctype, *iface_name;

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);

	ctype = nm_setting_connection_get_connection_type (s_con);
	if (strcmp (ctype, NM_SETTING_GENERIC_SETTING_NAME) != 0) {
		g_set_error (error, NM_DEVICE_GENERIC_ERROR, NM_DEVICE_GENERIC_ERROR_NOT_GENERIC_CONNECTION,
		             "The connection was not a generic connection.");
		return FALSE;
	}

	iface_name = nm_setting_connection_get_interface_name (s_con);
	if (!iface_name) {
		g_set_error (error, NM_DEVICE_GENERIC_ERROR, NM_DEVICE_GENERIC_ERROR_MISSING_INTERFACE_NAME,
		             "The connection did not specify an interface name.");
		return FALSE;
	}

	return NM_DEVICE_CLASS (nm_device_generic_parent_class)->connection_compatible (device, connection, error);
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
register_properties (NMDeviceGeneric *device)
{
	NMDeviceGenericPrivate *priv = NM_DEVICE_GENERIC_GET_PRIVATE (device);
	const NMPropertiesInfo property_info[] = {
		{ NM_DEVICE_GENERIC_HW_ADDRESS, &priv->hw_address },
		{ NM_DEVICE_GENERIC_TYPE_DESCRIPTION, &priv->type_description },
		{ NULL },
	};

	_nm_object_register_properties (NM_OBJECT (device),
	                                priv->proxy,
	                                property_info);
}

static void
constructed (GObject *object)
{
	NMDeviceGenericPrivate *priv = NM_DEVICE_GENERIC_GET_PRIVATE (object);

	G_OBJECT_CLASS (nm_device_generic_parent_class)->constructed (object);

	priv->proxy = _nm_object_new_proxy (NM_OBJECT (object), NULL, NM_DBUS_INTERFACE_DEVICE_GENERIC);
	register_properties (NM_DEVICE_GENERIC (object));
}

static void
dispose (GObject *object)
{
	NMDeviceGenericPrivate *priv = NM_DEVICE_GENERIC_GET_PRIVATE (object);

	g_clear_object (&priv->proxy);

	G_OBJECT_CLASS (nm_device_generic_parent_class)->dispose (object);
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

	_nm_object_ensure_inited (NM_OBJECT (object));

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
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NMDeviceGenericPrivate));

	object_class->constructed = constructed;
	object_class->dispose = dispose;
	object_class->finalize = finalize;
	object_class->get_property = get_property;

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
		 g_param_spec_string (NM_DEVICE_GENERIC_HW_ADDRESS,
		                      "Hardware Address",
		                      "Hardware address",
		                      NULL,
		                      G_PARAM_READABLE));

	/**
	 * NMDeviceGeneric:type-description:
	 *
	 * A description of the specific type of device this is, or %NULL
	 * if not known.
	 **/
	g_object_class_install_property
		(object_class, PROP_TYPE_DESCRIPTION,
		 g_param_spec_string (NM_DEVICE_GENERIC_TYPE_DESCRIPTION,
		                      "Type Description",
		                      "Type description",
		                      NULL,
		                      G_PARAM_READABLE));
}

