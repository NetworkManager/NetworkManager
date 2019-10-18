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
	PROP_HW_ADDRESS,
	PROP_COMPANION,
	PROP_ACTIVE_CHANNEL,
);

typedef struct {
	char *hw_address;
	NMDeviceWifi *companion;
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
 **/
const char *
nm_device_olpc_mesh_get_hw_address (NMDeviceOlpcMesh *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_OLPC_MESH (device), NULL);

	return nm_str_not_empty (NM_DEVICE_OLPC_MESH_GET_PRIVATE (device)->hw_address);
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

	return NM_DEVICE_OLPC_MESH_GET_PRIVATE (device)->companion;
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

static const char *
get_hw_address (NMDevice *device)
{
	return nm_device_olpc_mesh_get_hw_address (NM_DEVICE_OLPC_MESH (device));
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
init_dbus (NMObject *object)
{
	NMDeviceOlpcMeshPrivate *priv = NM_DEVICE_OLPC_MESH_GET_PRIVATE (object);
	const NMPropertiesInfo property_info[] = {
		{ NM_DEVICE_OLPC_MESH_HW_ADDRESS,     &priv->hw_address },
		{ NM_DEVICE_OLPC_MESH_COMPANION,      &priv->companion, NULL, NM_TYPE_DEVICE_WIFI },
		{ NM_DEVICE_OLPC_MESH_ACTIVE_CHANNEL, &priv->active_channel },
		{ NULL },
	};

	NM_OBJECT_CLASS (nm_device_olpc_mesh_parent_class)->init_dbus (object);

	_nm_object_register_properties (object,
	                                NM_DBUS_INTERFACE_DEVICE_OLPC_MESH,
	                                property_info);
}

static void
dispose (GObject *object)
{
	NMDeviceOlpcMeshPrivate *priv = NM_DEVICE_OLPC_MESH_GET_PRIVATE (object);

	g_clear_object (&priv->companion);

	G_OBJECT_CLASS (nm_device_olpc_mesh_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMDeviceOlpcMeshPrivate *priv = NM_DEVICE_OLPC_MESH_GET_PRIVATE (object);

	g_free (priv->hw_address);

	G_OBJECT_CLASS (nm_device_olpc_mesh_parent_class)->finalize (object);
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMDeviceOlpcMesh *device = NM_DEVICE_OLPC_MESH (object);

	switch (prop_id) {
	case PROP_HW_ADDRESS:
		g_value_set_string (value, nm_device_olpc_mesh_get_hw_address (device));
		break;
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

static void
nm_device_olpc_mesh_class_init (NMDeviceOlpcMeshClass *olpc_mesh_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (olpc_mesh_class);
	NMObjectClass *nm_object_class = NM_OBJECT_CLASS (olpc_mesh_class);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (olpc_mesh_class);

	object_class->get_property = get_property;
	object_class->dispose      = dispose;
	object_class->finalize     = finalize;

	nm_object_class->init_dbus = init_dbus;

	device_class->connection_compatible = connection_compatible;
	device_class->get_setting_type      = get_setting_type;
	device_class->get_hw_address        = get_hw_address;

	/**
	 * NMDeviceOlpcMesh:hw-address:
	 *
	 * The hardware (MAC) address of the device.
	 **/
	obj_properties[PROP_HW_ADDRESS] =
	    g_param_spec_string (NM_DEVICE_OLPC_MESH_HW_ADDRESS, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

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

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);
}
