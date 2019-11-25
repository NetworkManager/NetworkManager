// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2017 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-device-dummy.h"

#include "nm-object-private.h"
#include "nm-setting-dummy.h"
#include "nm-setting-connection.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE (
	PROP_HW_ADDRESS,
);

typedef struct {
	char *hw_address;
} NMDeviceDummyPrivate;

struct _NMDeviceDummy {
	NMDevice parent;
	NMDeviceDummyPrivate _priv;
};

struct _NMDeviceDummyClass {
	NMDeviceClass parent;
};

G_DEFINE_TYPE (NMDeviceDummy, nm_device_dummy, NM_TYPE_DEVICE)

#define NM_DEVICE_DUMMY_GET_PRIVATE(self) _NM_GET_PRIVATE(self, NMDeviceDummy, NM_IS_DEVICE_DUMMY, NMObject, NMDevice)

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

	return _nml_coerce_property_str_not_empty (NM_DEVICE_DUMMY_GET_PRIVATE (device)->hw_address);
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
finalize (GObject *object)
{
	NMDeviceDummyPrivate *priv = NM_DEVICE_DUMMY_GET_PRIVATE (object);

	g_free (priv->hw_address);

	G_OBJECT_CLASS (nm_device_dummy_parent_class)->finalize (object);
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

const NMLDBusMetaIface _nml_dbus_meta_iface_nm_device_dummy = NML_DBUS_META_IFACE_INIT_PROP (
	NM_DBUS_INTERFACE_DEVICE_DUMMY,
	nm_device_dummy_get_type,
	NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_HIGH,
	NML_DBUS_META_IFACE_DBUS_PROPERTIES (
		NML_DBUS_META_PROPERTY_INIT_S ("HwAddress", PROP_HW_ADDRESS, NMDeviceDummy, _priv.hw_address ),
	),
);

static void
nm_device_dummy_class_init (NMDeviceDummyClass *dummy_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (dummy_class);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (dummy_class);

	object_class->get_property = get_property;
	object_class->finalize      = finalize;

	device_class->connection_compatible = connection_compatible;
	device_class->get_hw_address        = get_hw_address;
	device_class->get_setting_type      = get_setting_type;

	/**
	 * NMDeviceDummy:hw-address:
	 *
	 * The active hardware (MAC) address of the device.
	 *
	 * Since: 1.10
	 **/
	obj_properties[PROP_HW_ADDRESS] =
	    g_param_spec_string (NM_DEVICE_DUMMY_HW_ADDRESS, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	_nml_dbus_meta_class_init_with_properties (object_class, &_nml_dbus_meta_iface_nm_device_dummy);
}
