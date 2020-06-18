// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2012 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-setting-bridge.h"

#include "nm-setting-connection.h"
#include "nm-utils.h"
#include "nm-device-bridge.h"
#include "nm-object-private.h"
#include "nm-core-internal.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE (
	PROP_CARRIER,
	PROP_SLAVES,
);

typedef struct {
	NMLDBusPropertyAO slaves;
	bool carrier;
} NMDeviceBridgePrivate;

struct _NMDeviceBridge {
	NMDevice parent;
	NMDeviceBridgePrivate _priv;
};

struct _NMDeviceBridgeClass {
	NMDeviceClass parent;
};

G_DEFINE_TYPE (NMDeviceBridge, nm_device_bridge, NM_TYPE_DEVICE)

#define NM_DEVICE_BRIDGE_GET_PRIVATE(self) _NM_GET_PRIVATE(self, NMDeviceBridge, NM_IS_DEVICE_BRIDGE, NMObject, NMDevice)

/*****************************************************************************/

/**
 * nm_device_bridge_get_hw_address: (skip)
 * @device: a #NMDeviceBridge
 *
 * Gets the hardware (MAC) address of the #NMDeviceBridge
 *
 * Returns: the hardware address. This is the internal string used by the
 * device, and must not be modified.
 *
 * Deprecated: 1.24: Use nm_device_get_hw_address() instead.
 **/
const char *
nm_device_bridge_get_hw_address (NMDeviceBridge *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_BRIDGE (device), NULL);

	return nm_device_get_hw_address (NM_DEVICE (device));
}

/**
 * nm_device_bridge_get_carrier:
 * @device: a #NMDeviceBridge
 *
 * Whether the device has carrier.
 *
 * Returns: %TRUE if the device has carrier
 **/
gboolean
nm_device_bridge_get_carrier (NMDeviceBridge *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_BRIDGE (device), FALSE);

	return NM_DEVICE_BRIDGE_GET_PRIVATE (device)->carrier;
}

/**
 * nm_device_bridge_get_slaves:
 * @device: a #NMDeviceBridge
 *
 * Gets the devices currently enslaved to @device.
 *
 * Returns: (element-type NMDevice): the #GPtrArray containing
 * #NMDevices that are slaves of @device. This is the internal
 * copy used by the device, and must not be modified.
 **/
const GPtrArray *
nm_device_bridge_get_slaves (NMDeviceBridge *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_BRIDGE (device), FALSE);

	return nml_dbus_property_ao_get_objs_as_ptrarray (&NM_DEVICE_BRIDGE_GET_PRIVATE (device)->slaves);
}

static gboolean
connection_compatible (NMDevice *device, NMConnection *connection, GError **error)
{
	if (!NM_DEVICE_CLASS (nm_device_bridge_parent_class)->connection_compatible (device, connection, error))
		return FALSE;

	if (!nm_connection_is_type (connection, NM_SETTING_BRIDGE_SETTING_NAME)) {
		if (   _nm_connection_get_setting_bluetooth_for_nap (connection)
		    && nm_connection_is_type (connection, NM_SETTING_BLUETOOTH_SETTING_NAME)) {
			/* a bluetooth NAP setting is a compatible connection for a bridge. */
		} else {
			g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
			                     _("The connection was not a bridge connection."));
			return FALSE;
		}
	}

	/* FIXME: check ports? */

	return TRUE;
}

static GType
get_setting_type (NMDevice *device)
{
	return NM_TYPE_SETTING_BRIDGE;
}

/*****************************************************************************/

static void
nm_device_bridge_init (NMDeviceBridge *device)
{
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMDeviceBridge *device = NM_DEVICE_BRIDGE (object);

	switch (prop_id) {
	case PROP_CARRIER:
		g_value_set_boolean (value, nm_device_bridge_get_carrier (device));
		break;
	case PROP_SLAVES:
		g_value_take_boxed (value, _nm_utils_copy_object_array (nm_device_bridge_get_slaves (device)));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

const NMLDBusMetaIface _nml_dbus_meta_iface_nm_device_bridge = NML_DBUS_META_IFACE_INIT_PROP (
	NM_DBUS_INTERFACE_DEVICE_BRIDGE,
	nm_device_bridge_get_type,
	NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_HIGH,
	NML_DBUS_META_IFACE_DBUS_PROPERTIES (
		NML_DBUS_META_PROPERTY_INIT_B       ("Carrier",   PROP_CARRIER,    NMDeviceBridge, _priv.carrier                                               ),
		NML_DBUS_META_PROPERTY_INIT_FCN     ("HwAddress", 0,               "s",            _nm_device_notify_update_prop_hw_address                    ),
		NML_DBUS_META_PROPERTY_INIT_AO_PROP ("Slaves",    PROP_SLAVES,     NMDeviceBridge, _priv.slaves,                            nm_device_get_type ),
	),
);

static void
nm_device_bridge_class_init (NMDeviceBridgeClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMObjectClass *nm_object_class = NM_OBJECT_CLASS (klass);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);

	object_class->get_property = get_property;

	_NM_OBJECT_CLASS_INIT_PRIV_PTR_DIRECT (nm_object_class, NMDeviceBridge);

	_NM_OBJECT_CLASS_INIT_PROPERTY_AO_FIELDS_1 (nm_object_class, NMDeviceBridgePrivate, slaves);

	device_class->connection_compatible = connection_compatible;
	device_class->get_setting_type      = get_setting_type;

	/**
	 * NMDeviceBridge:carrier:
	 *
	 * Whether the device has carrier.
	 **/
	obj_properties[PROP_CARRIER] =
	    g_param_spec_boolean (NM_DEVICE_BRIDGE_CARRIER, "", "",
	                          FALSE,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	/**
	 * NMDeviceBridge:slaves: (type GPtrArray(NMDevice))
	 *
	 * The devices enslaved to the bridge device.
	 **/
	obj_properties[PROP_SLAVES] =
	    g_param_spec_boxed (NM_DEVICE_BRIDGE_SLAVES, "", "",
	                        G_TYPE_PTR_ARRAY,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);

	_nml_dbus_meta_class_init_with_properties (object_class, &_nml_dbus_meta_iface_nm_device_bridge);
}
