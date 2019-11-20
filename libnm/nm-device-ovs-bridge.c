// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2017, 2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-device-ovs-bridge.h"

#include "nm-object-private.h"
#include "nm-setting-ovs-bridge.h"
#include "nm-setting-ovs-port.h"
#include "nm-setting-connection.h"
#include "nm-core-internal.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE (
	PROP_SLAVES,
);

typedef struct {
	GPtrArray *slaves;
} NMDeviceOvsBridgePrivate;

struct _NMDeviceOvsBridge {
	NMDevice parent;
	NMDeviceOvsBridgePrivate _priv;
};

struct _NMDeviceOvsBridgeClass {
	NMDeviceClass parent;
};

G_DEFINE_TYPE (NMDeviceOvsBridge, nm_device_ovs_bridge, NM_TYPE_DEVICE)

#define NM_DEVICE_OVS_BRIDGE_GET_PRIVATE(self) _NM_GET_PRIVATE(self, NMDeviceOvsBridge, NM_IS_DEVICE_OVS_BRIDGE, NMObject, NMDevice)

/*****************************************************************************/

/**
 * nm_device_ovs_bridge_get_slaves:
 * @device: a #NMDeviceOvsBridge
 *
 * Gets the ports currently enslaved to @device.
 *
 * Returns: (element-type NMDevice): the #GPtrArray containing
 * #NMDevices that are slaves of @device. This is the internal
 * copy used by the device, and must not be modified.
 *
 * Since: 1.14
 **/
const GPtrArray *
nm_device_ovs_bridge_get_slaves (NMDeviceOvsBridge *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_OVS_BRIDGE (device), FALSE);

	return NM_DEVICE_OVS_BRIDGE_GET_PRIVATE (device)->slaves;
}

static const char *
get_type_description (NMDevice *device)
{
	return "ovs-bridge";
}

static gboolean
connection_compatible (NMDevice *device, NMConnection *connection, GError **error)
{
	const char *iface_name;

	if (!NM_DEVICE_CLASS (nm_device_ovs_bridge_parent_class)->connection_compatible (device, connection, error))
		return FALSE;

	if (!nm_connection_is_type (connection, NM_SETTING_OVS_BRIDGE_SETTING_NAME)) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
		                     _("The connection was not a ovs_bridge connection."));
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
	return NM_TYPE_SETTING_OVS_BRIDGE;
}

/*****************************************************************************/

static void
init_dbus (NMObject *object)
{
	NMDeviceOvsBridge *device = NM_DEVICE_OVS_BRIDGE (object);
	const NMPropertiesInfo property_info[] = {
		{ NM_DEVICE_OVS_BRIDGE_SLAVES, &device->_priv.slaves, NULL, NM_TYPE_DEVICE },
		{ NULL },
	};

	NM_OBJECT_CLASS (nm_device_ovs_bridge_parent_class)->init_dbus (object);

	_nm_object_register_properties (object,
	                                NM_DBUS_INTERFACE_DEVICE_OVS_BRIDGE,
	                                property_info);
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMDeviceOvsBridge *device = NM_DEVICE_OVS_BRIDGE (object);

	switch (prop_id) {
	case PROP_SLAVES:
		g_value_take_boxed (value, _nm_utils_copy_object_array (nm_device_ovs_bridge_get_slaves (device)));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_device_ovs_bridge_init (NMDeviceOvsBridge *device)
{
}

static void
dispose (GObject *object)
{
	NMDeviceOvsBridgePrivate *priv = NM_DEVICE_OVS_BRIDGE_GET_PRIVATE (object);

	g_clear_pointer (&priv->slaves, g_ptr_array_unref);

	G_OBJECT_CLASS (nm_device_ovs_bridge_parent_class)->dispose (object);
}

static void
nm_device_ovs_bridge_class_init (NMDeviceOvsBridgeClass *ovs_bridge_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (ovs_bridge_class);
	NMObjectClass *nm_object_class = NM_OBJECT_CLASS (ovs_bridge_class);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (ovs_bridge_class);

	object_class->get_property = get_property;
	object_class->dispose      = dispose;

	nm_object_class->init_dbus = init_dbus;

	device_class->get_type_description  = get_type_description;
	device_class->connection_compatible = connection_compatible;
	device_class->get_setting_type      = get_setting_type;

	/**
	 * NMDeviceOvsBridge:slaves: (type GPtrArray(NMDevice))
	 *
	 * Gets the ports currently enslaved to the device.
	 *
	 * Since: 1.22
	 */
	obj_properties[PROP_SLAVES] =
	    g_param_spec_boxed (NM_DEVICE_OVS_BRIDGE_SLAVES, "", "",
	                        G_TYPE_PTR_ARRAY,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);
}
