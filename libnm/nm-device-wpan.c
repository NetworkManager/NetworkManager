// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2018 Lubomir Rintel <lkundrak@v3.sk>
 */

#include "nm-default.h"

#include "nm-device-wpan.h"

#include "nm-object-private.h"
#include "nm-setting-wpan.h"
#include "nm-setting-connection.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE (
	PROP_HW_ADDRESS,
);

typedef struct {
	char *hw_address;
} NMDeviceWpanPrivate;

struct _NMDeviceWpan {
	NMDevice parent;
	NMDeviceWpanPrivate _priv;
};

struct _NMDeviceWpanClass {
	NMDeviceClass parent;
};

G_DEFINE_TYPE (NMDeviceWpan, nm_device_wpan, NM_TYPE_DEVICE)

#define NM_DEVICE_WPAN_GET_PRIVATE(self) _NM_GET_PRIVATE(self, NMDeviceWpan, NM_IS_DEVICE_WPAN, NMObject, NMDevice)

/*****************************************************************************/

/**
 * nm_device_wpan_get_hw_address:
 * @device: a #NMDeviceWpan
 *
 * Gets the active hardware (MAC) address of the #NMDeviceWpan
 *
 * Returns: the active hardware address. This is the internal string used by the
 * device, and must not be modified.
 **/
const char *
nm_device_wpan_get_hw_address (NMDeviceWpan *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_WPAN (device), NULL);

	return _nml_coerce_property_str_not_empty (NM_DEVICE_WPAN_GET_PRIVATE (device)->hw_address);
}

static gboolean
connection_compatible (NMDevice *device, NMConnection *connection, GError **error)
{
	if (!NM_DEVICE_CLASS (nm_device_wpan_parent_class)->connection_compatible (device, connection, error))
		return FALSE;

	if (!nm_connection_is_type (connection, NM_SETTING_WPAN_SETTING_NAME)) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
		                     _("The connection was not a wpan connection."));
		return FALSE;
	}

	return TRUE;
}

static GType
get_setting_type (NMDevice *device)
{
	return NM_TYPE_SETTING_WPAN;
}

static const char *
get_hw_address (NMDevice *device)
{
	return nm_device_wpan_get_hw_address (NM_DEVICE_WPAN (device));
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
	switch (prop_id) {
	case PROP_HW_ADDRESS:
		g_value_set_string (value, nm_device_wpan_get_hw_address (NM_DEVICE_WPAN (object)));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_device_wpan_init (NMDeviceWpan *device)
{
}

static void
finalize (GObject *object)
{
	NMDeviceWpanPrivate *priv = NM_DEVICE_WPAN_GET_PRIVATE (object);

	g_free (priv->hw_address);

	G_OBJECT_CLASS (nm_device_wpan_parent_class)->finalize (object);
}

const NMLDBusMetaIface _nml_dbus_meta_iface_nm_device_wpan = NML_DBUS_META_IFACE_INIT_PROP (
	NM_DBUS_INTERFACE_DEVICE_WPAN,
	nm_device_wpan_get_type,
	NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_HIGH,
	NML_DBUS_META_IFACE_DBUS_PROPERTIES (
		NML_DBUS_META_PROPERTY_INIT_S ("HwAddress", PROP_HW_ADDRESS, NMDeviceWpan, _priv.hw_address ),
	),
);

static void
nm_device_wpan_class_init (NMDeviceWpanClass *wpan_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (wpan_class);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (wpan_class);

	object_class->get_property = get_property;
	object_class->finalize     = finalize;

	device_class->connection_compatible = connection_compatible;
	device_class->get_setting_type      = get_setting_type;
	device_class->get_hw_address        = get_hw_address;

	/**
	 * NMDeviceWpan:hw-address:
	 *
	 * The active hardware (MAC) address of the device.
	 **/
	obj_properties[PROP_HW_ADDRESS] =
	    g_param_spec_string (NM_DEVICE_WPAN_HW_ADDRESS, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	_nml_dbus_meta_class_init_with_properties (object_class, &_nml_dbus_meta_iface_nm_device_wpan);
}
