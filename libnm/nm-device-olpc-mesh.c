// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2012 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-device-olpc-mesh.h"

#include "nm-setting-connection.h"
#include "nm-setting-olpc-mesh.h"
#include "nm-object-private.h"
#include "nm-device-wifi.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE (
	PROP_COMPANION,
	PROP_ACTIVE_CHANNEL,
);

typedef struct {
	NMLDBusPropertyO companion;
	guint32 active_channel;
} NMDeviceOlpcMeshPrivate;

struct _NMDeviceOlpcMesh {
	NMDevice parent;
	NMDeviceOlpcMeshPrivate _priv;
};

struct _NMDeviceOlpcMeshClass {
	NMDeviceClass parent;
};

G_DEFINE_TYPE (NMDeviceOlpcMesh, nm_device_olpc_mesh, NM_TYPE_DEVICE)

#define NM_DEVICE_OLPC_MESH_GET_PRIVATE(self) _NM_GET_PRIVATE(self, NMDeviceOlpcMesh, NM_IS_DEVICE_OLPC_MESH, NMObject, NMDevice)

/*****************************************************************************/

/**
 * nm_device_olpc_mesh_get_hw_address:
 * @device: a #NMDeviceOlpcMesh
 *
 * Gets the hardware (MAC) address of the #NMDeviceOlpcMesh
 *
 * Returns: the hardware address. This is the internal string used by the
 * device, and must not be modified.
 *
 * Deprecated: 1.24: Use nm_device_get_hw_address() instead.
 **/
const char *
nm_device_olpc_mesh_get_hw_address (NMDeviceOlpcMesh *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_OLPC_MESH (device), NULL);

	return nm_device_get_hw_address (NM_DEVICE (device));
}

/**
 * nm_device_olpc_mesh_get_companion:
 * @device: a #NMDeviceOlpcMesh
 *
 * Gets the companion device of the #NMDeviceOlpcMesh.
 *
 * Returns: (transfer none): the companion of the device of %NULL
 **/
NMDeviceWifi *
nm_device_olpc_mesh_get_companion (NMDeviceOlpcMesh *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_OLPC_MESH (device), NULL);

	return nml_dbus_property_o_get_obj (&NM_DEVICE_OLPC_MESH_GET_PRIVATE (device)->companion);
}

/**
 * nm_device_olpc_mesh_get_active_channel:
 * @device: a #NMDeviceOlpcMesh
 *
 * Returns the active channel of the #NMDeviceOlpcMesh device.
 *
 * Returns: active channel of the device
 **/
guint32
nm_device_olpc_mesh_get_active_channel (NMDeviceOlpcMesh *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_OLPC_MESH (device), 0);

	return NM_DEVICE_OLPC_MESH_GET_PRIVATE (device)->active_channel;
}

static gboolean
connection_compatible (NMDevice *device, NMConnection *connection, GError **error)
{
	if (!NM_DEVICE_CLASS (nm_device_olpc_mesh_parent_class)->connection_compatible (device, connection, error))
		return FALSE;

	if (!nm_connection_is_type (connection, NM_SETTING_OLPC_MESH_SETTING_NAME)) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
		                     _("The connection was not an OLPC Mesh connection."));
		return FALSE;
	}

	return TRUE;
}

static GType
get_setting_type (NMDevice *device)
{
	return NM_TYPE_SETTING_OLPC_MESH;
}

/*****************************************************************************/

static void
nm_device_olpc_mesh_init (NMDeviceOlpcMesh *device)
{
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMDeviceOlpcMesh *device = NM_DEVICE_OLPC_MESH (object);

	switch (prop_id) {
	case PROP_COMPANION:
		g_value_set_object (value, nm_device_olpc_mesh_get_companion (device));
		break;
	case PROP_ACTIVE_CHANNEL:
		g_value_set_uint (value, nm_device_olpc_mesh_get_active_channel (device));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

const NMLDBusMetaIface _nml_dbus_meta_iface_nm_device_olpcmesh = NML_DBUS_META_IFACE_INIT_PROP (
	NM_DBUS_INTERFACE_DEVICE_OLPC_MESH,
	nm_device_olpc_mesh_get_type,
	NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_HIGH,
	NML_DBUS_META_IFACE_DBUS_PROPERTIES (
		NML_DBUS_META_PROPERTY_INIT_U      ("ActiveChannel", PROP_ACTIVE_CHANNEL, NMDeviceOlpcMesh, _priv.active_channel                                             ),
		NML_DBUS_META_PROPERTY_INIT_O_PROP ("Companion",     PROP_COMPANION,      NMDeviceOlpcMesh, _priv.companion,                         nm_device_wifi_get_type ),
		NML_DBUS_META_PROPERTY_INIT_FCN    ("HwAddress",     0,                   "s",              _nm_device_notify_update_prop_hw_address                         ),
	),
);

static void
nm_device_olpc_mesh_class_init (NMDeviceOlpcMeshClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMObjectClass *nm_object_class = NM_OBJECT_CLASS (klass);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);

	object_class->get_property = get_property;

	_NM_OBJECT_CLASS_INIT_PRIV_PTR_DIRECT (nm_object_class, NMDeviceOlpcMesh);

	_NM_OBJECT_CLASS_INIT_PROPERTY_O_FIELDS_1 (nm_object_class, NMDeviceOlpcMeshPrivate, companion);

	device_class->connection_compatible = connection_compatible;
	device_class->get_setting_type      = get_setting_type;

	/**
	 * NMDeviceOlpcMesh:companion:
	 *
	 * The companion device.
	 **/
	obj_properties[PROP_COMPANION] =
	    g_param_spec_object (NM_DEVICE_OLPC_MESH_COMPANION, "", "",
	                         NM_TYPE_DEVICE_WIFI,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMDeviceOlpcMesh:active-channel:
	 *
	 * The device's active channel.
	 **/
	obj_properties[PROP_ACTIVE_CHANNEL] =
	    g_param_spec_uint (NM_DEVICE_OLPC_MESH_ACTIVE_CHANNEL, "", "",
	                       0, G_MAXUINT32, 0,
	                       G_PARAM_READABLE |
	                       G_PARAM_STATIC_STRINGS);

	_nml_dbus_meta_class_init_with_properties (object_class, &_nml_dbus_meta_iface_nm_device_olpcmesh);
}
