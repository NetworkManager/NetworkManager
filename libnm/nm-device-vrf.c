// SPDX-License-Identifier: LGPL-2.1+

#include "nm-default.h"

#include "nm-device-vrf.h"

#include "nm-setting-connection.h"
#include "nm-setting-vrf.h"
#include "nm-utils.h"
#include "nm-object-private.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE (
	PROP_TABLE,
);

typedef struct {
	guint32 table;
} NMDeviceVrfPrivate;

struct _NMDeviceVrf {
	NMDevice parent;
	NMDeviceVrfPrivate _priv;
};

struct _NMDeviceVrfClass {
	NMDeviceClass parent;
};

G_DEFINE_TYPE (NMDeviceVrf, nm_device_vrf, NM_TYPE_DEVICE)

#define NM_DEVICE_VRF_GET_PRIVATE(self) _NM_GET_PRIVATE(self, NMDeviceVrf, NM_IS_DEVICE_VRF, NMObject, NMDevice)

/*****************************************************************************/

/**
 * nm_device_vrf_get_table:
 * @device: a #NMDeviceVrf
 *
 * Returns: the device's VRF routing table.
 *
 * Since: 1.24
 **/
guint32
nm_device_vrf_get_table (NMDeviceVrf *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_VRF (device), 0);

	return NM_DEVICE_VRF_GET_PRIVATE (device)->table;
}

static gboolean
connection_compatible (NMDevice *device, NMConnection *connection, GError **error)
{
	NMSettingVrf *s_vrf;

	if (!NM_DEVICE_CLASS (nm_device_vrf_parent_class)->connection_compatible (device, connection, error))
		return FALSE;

	if (!nm_connection_is_type (connection, NM_SETTING_VRF_SETTING_NAME)) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
		                     _("The connection was not a VRF connection."));
		return FALSE;
	}

	s_vrf = (NMSettingVrf *) nm_connection_get_setting (connection, NM_TYPE_SETTING_VRF);
	if (nm_setting_vrf_get_table (s_vrf) != nm_device_vrf_get_table (NM_DEVICE_VRF (device))) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
		                     _("The VRF table of the device and the connection didn't match."));
		return FALSE;
	}

	return TRUE;
}

static GType
get_setting_type (NMDevice *device)
{
	return NM_TYPE_SETTING_VRF;
}

/*****************************************************************************/

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMDeviceVrf *device = NM_DEVICE_VRF (object);

	switch (prop_id) {
	case PROP_TABLE:
		g_value_set_uint (value, nm_device_vrf_get_table (device));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_device_vrf_init (NMDeviceVrf *device)
{
}

const NMLDBusMetaIface _nml_dbus_meta_iface_nm_device_vrf = NML_DBUS_META_IFACE_INIT_PROP (
	NM_DBUS_INTERFACE_DEVICE_VRF,
	nm_device_vrf_get_type,
	NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_HIGH,
	NML_DBUS_META_IFACE_DBUS_PROPERTIES (
		NML_DBUS_META_PROPERTY_INIT_U ("Table", PROP_TABLE, NMDeviceVrf, _priv.table),
	),
);

static void
nm_device_vrf_class_init (NMDeviceVrfClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMObjectClass *nm_object_class = NM_OBJECT_CLASS (klass);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);

	object_class->get_property = get_property;

	_NM_OBJECT_CLASS_INIT_PRIV_PTR_DIRECT (nm_object_class, NMDeviceVrf);

	device_class->connection_compatible = connection_compatible;
	device_class->get_setting_type      = get_setting_type;

	/**
	 * NMDeviceVrf:table:
	 *
	 * The device's VRF table.
	 *
	 * Since: 1.24
	 **/
	obj_properties[PROP_TABLE] =
	    g_param_spec_uint (NM_DEVICE_VRF_TABLE, "", "",
	                       0, G_MAXUINT32, 0,
	                       G_PARAM_READABLE |
	                       G_PARAM_STATIC_STRINGS);

	_nml_dbus_meta_class_init_with_properties (object_class, &_nml_dbus_meta_iface_nm_device_vrf);
}
