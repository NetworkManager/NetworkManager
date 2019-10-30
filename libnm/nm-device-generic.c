// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-device-generic.h"

#include "nm-object-private.h"
#include "nm-setting-generic.h"
#include "nm-setting-connection.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE (
	PROP_HW_ADDRESS,
	PROP_TYPE_DESCRIPTION,
);

typedef struct {
	char *hw_address;
	char *type_description;
} NMDeviceGenericPrivate;

struct _NMDeviceGeneric {
	NMDevice parent;
	NMDeviceGenericPrivate _priv;
};

struct _NMDeviceGenericClass {
	NMDeviceClass parent;
};

G_DEFINE_TYPE (NMDeviceGeneric, nm_device_generic, NM_TYPE_DEVICE)

#define NM_DEVICE_GENERIC_GET_PRIVATE(self) _NM_GET_PRIVATE(self, NMDeviceGeneric, NM_IS_DEVICE_GENERIC, NMObject, NMDevice)

/*****************************************************************************/

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

	return _nml_coerce_property_str_not_empty (NM_DEVICE_GENERIC_GET_PRIVATE (device)->hw_address);
}

/*****************************************************************************/

static const char *
get_type_description (NMDevice *device)
{
	NMDeviceGenericPrivate *priv = NM_DEVICE_GENERIC_GET_PRIVATE (device);

	return _nml_coerce_property_str_not_empty (priv->type_description);
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

/*****************************************************************************/

static void
nm_device_generic_init (NMDeviceGeneric *device)
{
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
	NMDeviceGeneric *self = NM_DEVICE_GENERIC (object);
	NMDeviceGenericPrivate *priv = NM_DEVICE_GENERIC_GET_PRIVATE (self);

	switch (prop_id) {
	case PROP_HW_ADDRESS:
		g_value_set_string (value, priv->hw_address);
		break;
	case PROP_TYPE_DESCRIPTION:
		g_value_set_string (value, get_type_description ((NMDevice *) self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

const NMLDBusMetaIface _nml_dbus_meta_iface_nm_device_generic = NML_DBUS_META_IFACE_INIT_PROP (
	NM_DBUS_INTERFACE_DEVICE_GENERIC,
	nm_device_generic_get_type,
	NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_HIGH,
	NML_DBUS_META_IFACE_DBUS_PROPERTIES (
		NML_DBUS_META_PROPERTY_INIT_S ("HwAddress",       PROP_HW_ADDRESS,       NMDeviceGeneric, _priv.hw_address       ),
		NML_DBUS_META_PROPERTY_INIT_S ("TypeDescription", PROP_TYPE_DESCRIPTION, NMDeviceGeneric, _priv.type_description ),
	),
);

static void
nm_device_generic_class_init (NMDeviceGenericClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);

	object_class->get_property = get_property;
	object_class->finalize     = finalize;

	device_class->get_type_description  = get_type_description;
	device_class->get_hw_address        = get_hw_address;
	device_class->connection_compatible = connection_compatible;
	device_class->get_setting_type      = get_setting_type;

	/**
	 * NMDeviceGeneric:hw-address:
	 *
	 * The hardware address of the device.
	 **/
	obj_properties[PROP_HW_ADDRESS] =
	    g_param_spec_string (NM_DEVICE_GENERIC_HW_ADDRESS, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMDeviceGeneric:type-description:
	 *
	 * A description of the specific type of device this is, or %NULL
	 * if not known.
	 **/
	obj_properties[PROP_TYPE_DESCRIPTION] =
	    g_param_spec_string (NM_DEVICE_GENERIC_TYPE_DESCRIPTION, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	_nml_dbus_meta_class_init_with_properties (object_class, &_nml_dbus_meta_iface_nm_device_generic);
}
