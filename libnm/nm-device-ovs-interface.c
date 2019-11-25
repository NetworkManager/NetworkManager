// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2017 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-device-ovs-interface.h"

#include "nm-object-private.h"
#include "nm-setting-ovs-interface.h"
#include "nm-setting-ovs-port.h"
#include "nm-setting-connection.h"

/*****************************************************************************/

struct _NMDeviceOvsInterface {
	NMDevice parent;
};

struct _NMDeviceOvsInterfaceClass {
	NMDeviceClass parent;
};

G_DEFINE_TYPE (NMDeviceOvsInterface, nm_device_ovs_interface, NM_TYPE_DEVICE)

/*****************************************************************************/

static const char *
get_type_description (NMDevice *device)
{
	return "ovs-interface";
}

static gboolean
connection_compatible (NMDevice *device, NMConnection *connection, GError **error)
{
	const char *iface_name;

	if (!NM_DEVICE_CLASS (nm_device_ovs_interface_parent_class)->connection_compatible (device, connection, error))
		return FALSE;

	if (!nm_connection_is_type (connection, NM_SETTING_OVS_INTERFACE_SETTING_NAME)) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
		                     _("The connection was not a ovs_interface connection."));
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
	return NM_TYPE_SETTING_OVS_INTERFACE;
}

/*****************************************************************************/

static void
nm_device_ovs_interface_init (NMDeviceOvsInterface *device)
{
}

const NMLDBusMetaIface _nml_dbus_meta_iface_nm_device_ovsinterface = NML_DBUS_META_IFACE_INIT (
	NM_DBUS_INTERFACE_DEVICE_OVS_INTERFACE,
	nm_device_ovs_interface_get_type,
	NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_HIGH,
);

static void
nm_device_ovs_interface_class_init (NMDeviceOvsInterfaceClass *ovs_interface_class)
{
	NMDeviceClass *device_class = NM_DEVICE_CLASS (ovs_interface_class);

	device_class->get_type_description = get_type_description;
	device_class->connection_compatible = connection_compatible;
	device_class->get_setting_type = get_setting_type;
}
