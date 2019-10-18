// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2011 - 2012 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-device-infiniband.h"

#include "nm-setting-connection.h"
#include "nm-setting-infiniband.h"
#include "nm-utils.h"
#include "nm-object-private.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE (
	PROP_HW_ADDRESS,
	PROP_CARRIER,
);

typedef struct {
	char *hw_address;
	gboolean carrier;
} NMDeviceInfinibandPrivate;

struct _NMDeviceInfiniband {
	NMDevice parent;
	NMDeviceInfinibandPrivate _priv;
};

struct _NMDeviceInfinibandClass {
	NMDeviceClass parent;
};

G_DEFINE_TYPE (NMDeviceInfiniband, nm_device_infiniband, NM_TYPE_DEVICE)

#define NM_DEVICE_INFINIBAND_GET_PRIVATE(self) _NM_GET_PRIVATE(self, NMDeviceInfiniband, NM_IS_DEVICE_INFINIBAND, NMObject, NMDevice)

/*****************************************************************************/

/**
 * nm_device_infiniband_get_hw_address:
 * @device: a #NMDeviceInfiniband
 *
 * Gets the hardware (MAC) address of the #NMDeviceInfiniband
 *
 * Returns: the hardware address. This is the internal string used by the
 * device, and must not be modified.
 **/
const char *
nm_device_infiniband_get_hw_address (NMDeviceInfiniband *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_INFINIBAND (device), NULL);

	return nm_str_not_empty (NM_DEVICE_INFINIBAND_GET_PRIVATE (device)->hw_address);
}

/**
 * nm_device_infiniband_get_carrier:
 * @device: a #NMDeviceInfiniband
 *
 * Whether the device has carrier.
 *
 * Returns: %TRUE if the device has carrier
 **/
gboolean
nm_device_infiniband_get_carrier (NMDeviceInfiniband *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_INFINIBAND (device), FALSE);

	return NM_DEVICE_INFINIBAND_GET_PRIVATE (device)->carrier;
}

static gboolean
connection_compatible (NMDevice *device, NMConnection *connection, GError **error)
{
	NMSettingInfiniband *s_infiniband;
	const char *hwaddr, *setting_hwaddr;

	if (!NM_DEVICE_CLASS (nm_device_infiniband_parent_class)->connection_compatible (device, connection, error))
		return FALSE;

	if (!nm_connection_is_type (connection, NM_SETTING_INFINIBAND_SETTING_NAME)) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
		                     _("The connection was not an InfiniBand connection."));
		return FALSE;
	}

	hwaddr = nm_device_infiniband_get_hw_address (NM_DEVICE_INFINIBAND (device));
	if (hwaddr) {
		if (!nm_utils_hwaddr_valid (hwaddr, INFINIBAND_ALEN)) {
			g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_FAILED,
			                     _("Invalid device MAC address."));
			return FALSE;
		}

		s_infiniband = nm_connection_get_setting_infiniband (connection);
		setting_hwaddr = nm_setting_infiniband_get_mac_address (s_infiniband);
		if (setting_hwaddr && !nm_utils_hwaddr_matches (setting_hwaddr, -1, hwaddr, -1)) {
			g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
			                     _("The MACs of the device and the connection didn't match."));
			return FALSE;
		}
	}

	return TRUE;
}

static GType
get_setting_type (NMDevice *device)
{
	return NM_TYPE_SETTING_INFINIBAND;
}

static const char *
get_hw_address (NMDevice *device)
{
	return nm_device_infiniband_get_hw_address (NM_DEVICE_INFINIBAND (device));
}

/*****************************************************************************/

static void
nm_device_infiniband_init (NMDeviceInfiniband *device)
{
}

static void
init_dbus (NMObject *object)
{
	NMDeviceInfinibandPrivate *priv = NM_DEVICE_INFINIBAND_GET_PRIVATE (object);
	const NMPropertiesInfo property_info[] = {
		{ NM_DEVICE_INFINIBAND_HW_ADDRESS, &priv->hw_address },
		{ NM_DEVICE_INFINIBAND_CARRIER,    &priv->carrier },
		{ NULL },
	};

	NM_OBJECT_CLASS (nm_device_infiniband_parent_class)->init_dbus (object);

	_nm_object_register_properties (object,
	                                NM_DBUS_INTERFACE_DEVICE_INFINIBAND,
	                                property_info);
}

static void
finalize (GObject *object)
{
	NMDeviceInfinibandPrivate *priv = NM_DEVICE_INFINIBAND_GET_PRIVATE (object);

	g_free (priv->hw_address);

	G_OBJECT_CLASS (nm_device_infiniband_parent_class)->finalize (object);
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMDeviceInfiniband *device = NM_DEVICE_INFINIBAND (object);

	switch (prop_id) {
	case PROP_HW_ADDRESS:
		g_value_set_string (value, nm_device_infiniband_get_hw_address (device));
		break;
	case PROP_CARRIER:
		g_value_set_boolean (value, nm_device_infiniband_get_carrier (device));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_device_infiniband_class_init (NMDeviceInfinibandClass *ib_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (ib_class);
	NMObjectClass *nm_object_class = NM_OBJECT_CLASS (ib_class);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (ib_class);

	object_class->get_property = get_property;
	object_class->finalize     = finalize;

	nm_object_class->init_dbus = init_dbus;

	device_class->connection_compatible = connection_compatible;
	device_class->get_setting_type      = get_setting_type;
	device_class->get_hw_address        = get_hw_address;

	/**
	 * NMDeviceInfiniband:hw-address:
	 *
	 * The hardware (MAC) address of the device.
	 **/
	obj_properties[PROP_HW_ADDRESS] =
	    g_param_spec_string (NM_DEVICE_INFINIBAND_HW_ADDRESS, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMDeviceInfiniband:carrier:
	 *
	 * Whether the device has carrier.
	 **/
	obj_properties[PROP_CARRIER] =
	    g_param_spec_boolean (NM_DEVICE_INFINIBAND_CARRIER, "", "",
	                          FALSE,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);
}
