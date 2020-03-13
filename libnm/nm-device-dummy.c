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

struct _NMDeviceDummy {
	NMDevice parent;
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
 *
 * Deprecated: 1.24 use nm_device_get_hw_address() instead.
 **/
const char *
nm_device_dummy_get_hw_address (NMDeviceDummy *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_DUMMY (device), NULL);

	return nm_device_get_hw_address (NM_DEVICE (device));
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

/*****************************************************************************/

static void
nm_device_dummy_init (NMDeviceDummy *device)
{
}

const NMLDBusMetaIface _nml_dbus_meta_iface_nm_device_dummy = NML_DBUS_META_IFACE_INIT (
	NM_DBUS_INTERFACE_DEVICE_DUMMY,
	nm_device_dummy_get_type,
	NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_HIGH,
	NML_DBUS_META_IFACE_DBUS_PROPERTIES (
		NML_DBUS_META_PROPERTY_INIT_FCN ("HwAddress", 0, "s", _nm_device_notify_update_prop_hw_address ),
	),
);

static void
nm_device_dummy_class_init (NMDeviceDummyClass *dummy_class)
{
	NMDeviceClass *device_class = NM_DEVICE_CLASS (dummy_class);

	device_class->connection_compatible = connection_compatible;
	device_class->get_setting_type      = get_setting_type;
}
