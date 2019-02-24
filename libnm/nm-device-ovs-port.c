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
 * Copyright 2017,2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-device-ovs-port.h"

#include "nm-object-private.h"
#include "nm-setting-ovs-port.h"
#include "nm-setting-ovs-port.h"
#include "nm-setting-connection.h"
#include "nm-core-internal.h"

enum {
	PROP_0,
	PROP_SLAVES,

	LAST_PROP
};

/**
 * NMDeviceOvsPort:
 */
struct _NMDeviceOvsPort {
	NMDevice parent;
	GPtrArray *slaves;
};

struct _NMDeviceOvsPortClass {
	NMDeviceClass parent;
};

G_DEFINE_TYPE (NMDeviceOvsPort, nm_device_ovs_port, NM_TYPE_DEVICE)

/*****************************************************************************/

/**
 * nm_device_ovs_port_get_slaves:
 * @device: a #NMDeviceOvsPort
 *
 * Gets the interfaces currently enslaved to @device.
 *
 * Returns: (element-type NMDevice): the #GPtrArray containing
 * #NMDevices that are slaves of @device. This is the internal
 * copy used by the device, and must not be modified.
 *
 * Since: 1.14
 **/
const GPtrArray *
nm_device_ovs_port_get_slaves (NMDeviceOvsPort *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_OVS_PORT (device), FALSE);

	return device->slaves;
}

static const char *
get_type_description (NMDevice *device)
{
	return "ovs-port";
}

static gboolean
connection_compatible (NMDevice *device, NMConnection *connection, GError **error)
{
	const char *iface_name;

	if (!NM_DEVICE_CLASS (nm_device_ovs_port_parent_class)->connection_compatible (device, connection, error))
		return FALSE;

	if (!nm_connection_is_type (connection, NM_SETTING_OVS_PORT_SETTING_NAME)) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
		                     _("The connection was not a ovs_port connection."));
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
	return NM_TYPE_SETTING_OVS_PORT;
}

/*****************************************************************************/

static void
init_dbus (NMObject *object)
{
	NMDeviceOvsPort *device = NM_DEVICE_OVS_PORT (object);
	const NMPropertiesInfo property_info[] = {
		{ NM_DEVICE_OVS_PORT_SLAVES, &device->slaves, NULL, NM_TYPE_DEVICE },
		{ NULL },
	};

	NM_OBJECT_CLASS (nm_device_ovs_port_parent_class)->init_dbus (object);

	_nm_object_register_properties (object,
	                                NM_DBUS_INTERFACE_DEVICE_OVS_PORT,
	                                property_info);
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMDeviceOvsPort *device = NM_DEVICE_OVS_PORT (object);

	switch (prop_id) {
	case PROP_SLAVES:
		g_value_take_boxed (value, _nm_utils_copy_object_array (nm_device_ovs_port_get_slaves (device)));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_device_ovs_port_init (NMDeviceOvsPort *device)
{
}

static void
dispose (GObject *object)
{
	NMDeviceOvsPort *device = NM_DEVICE_OVS_PORT (object);

	g_clear_pointer (&device->slaves, g_ptr_array_unref);

	G_OBJECT_CLASS (nm_device_ovs_port_parent_class)->dispose (object);
}

static void
nm_device_ovs_port_class_init (NMDeviceOvsPortClass *ovs_port_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (ovs_port_class);
	NMObjectClass *nm_object_class = NM_OBJECT_CLASS (ovs_port_class);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (ovs_port_class);

	object_class->get_property = get_property;
	object_class->dispose = dispose;

	nm_object_class->init_dbus = init_dbus;

	device_class->get_type_description = get_type_description;
	device_class->connection_compatible = connection_compatible;
	device_class->get_setting_type = get_setting_type;
}
