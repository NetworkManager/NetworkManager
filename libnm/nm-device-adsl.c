// SPDX-License-Identifier: LGPL-2.1+
/*
 * Author: Pantelis Koukousoulas <pktoss@gmail.com>
 * Copyright (C) 2009 - 2011 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-device-adsl.h"

#include "nm-object-private.h"
#include "nm-setting-adsl.h"
#include "nm-setting-connection.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE (
	PROP_CARRIER,
);

typedef struct {
	bool carrier;
} NMDeviceAdslPrivate;

struct _NMDeviceAdsl {
	NMDevice parent;
	NMDeviceAdslPrivate _priv;
};

struct _NMDeviceAdslClass {
	NMDeviceClass parent;
};

G_DEFINE_TYPE (NMDeviceAdsl, nm_device_adsl, NM_TYPE_DEVICE)

#define NM_DEVICE_ADSL_GET_PRIVATE(self) _NM_GET_PRIVATE(self, NMDeviceAdsl, NM_IS_DEVICE_ADSL, NMObject, NMDevice)

/*****************************************************************************/

/**
 * nm_device_adsl_get_carrier:
 * @device: a #NMDeviceAdsl
 *
 * Whether the device has carrier.
 *
 * Returns: %TRUE if the device has carrier
 **/
gboolean
nm_device_adsl_get_carrier (NMDeviceAdsl *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_ADSL (device), FALSE);

	return NM_DEVICE_ADSL_GET_PRIVATE (device)->carrier;
}

static gboolean
connection_compatible (NMDevice *device, NMConnection *connection, GError **error)
{
	if (!NM_DEVICE_CLASS (nm_device_adsl_parent_class)->connection_compatible (device, connection, error))
		return FALSE;

	if (!nm_connection_is_type (connection, NM_SETTING_ADSL_SETTING_NAME)) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
		                     _("The connection was not an ADSL connection."));
		return FALSE;
	}

	return TRUE;
}

static GType
get_setting_type (NMDevice *device)
{
	return NM_TYPE_SETTING_ADSL;
}

/*****************************************************************************/

static void
nm_device_adsl_init (NMDeviceAdsl *device)
{
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMDeviceAdsl *device = NM_DEVICE_ADSL (object);

	switch (prop_id) {
	case PROP_CARRIER:
		g_value_set_boolean (value, nm_device_adsl_get_carrier (device));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

const NMLDBusMetaIface _nml_dbus_meta_iface_nm_device_adsl = NML_DBUS_META_IFACE_INIT_PROP (
	NM_DBUS_INTERFACE_DEVICE_ADSL,
	nm_device_adsl_get_type,
	NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_HIGH,
	NML_DBUS_META_IFACE_DBUS_PROPERTIES (
		NML_DBUS_META_PROPERTY_INIT_B ("Carrier", PROP_CARRIER, NMDeviceAdsl, _priv.carrier),
	),
);

static void
nm_device_adsl_class_init (NMDeviceAdslClass *adsl_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (adsl_class);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (adsl_class);

	object_class->get_property = get_property;

	device_class->connection_compatible = connection_compatible;
	device_class->get_setting_type      = get_setting_type;

	/**
	 * NMDeviceAdsl:carrier:
	 *
	 * Whether the device has carrier.
	 **/
	obj_properties[PROP_CARRIER] =
	    g_param_spec_boolean (NM_DEVICE_ADSL_CARRIER, "", "",
	                          FALSE,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	_nml_dbus_meta_class_init_with_properties (object_class, &_nml_dbus_meta_iface_nm_device_adsl);
}
