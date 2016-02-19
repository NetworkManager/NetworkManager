/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
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
 * author: Pantelis Koukousoulas <pktoss@gmail.com>
 * Copyright 2009 - 2011 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-device-adsl.h"

#include <string.h>

#include "nm-device-private.h"
#include "nm-object-private.h"

#include "nm-setting-adsl.h"
#include "nm-setting-connection.h"


G_DEFINE_TYPE (NMDeviceAdsl, nm_device_adsl, NM_TYPE_DEVICE)

#define NM_DEVICE_ADSL_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_ADSL, NMDeviceAdslPrivate))

typedef struct {
	gboolean carrier;

} NMDeviceAdslPrivate;

enum {
	PROP_0,
	PROP_CARRIER,
	LAST_PROP
};

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

/******************************************************************/

static void
nm_device_adsl_init (NMDeviceAdsl *device)
{
	_nm_device_set_device_type (NM_DEVICE (device), NM_DEVICE_TYPE_ADSL);
}

static void
init_dbus (NMObject *object)
{
	NMDeviceAdslPrivate *priv = NM_DEVICE_ADSL_GET_PRIVATE (object);
	const NMPropertiesInfo property_info[] = {
		{ NM_DEVICE_ADSL_CARRIER, &priv->carrier },
		{ NULL },
	};

	NM_OBJECT_CLASS (nm_device_adsl_parent_class)->init_dbus (object);

	_nm_object_register_properties (object,
	                                NM_DBUS_INTERFACE_DEVICE_ADSL,
	                                property_info);
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

static void
nm_device_adsl_class_init (NMDeviceAdslClass *adsl_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (adsl_class);
	NMObjectClass *nm_object_class = NM_OBJECT_CLASS (adsl_class);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (adsl_class);

	g_type_class_add_private (object_class, sizeof (NMDeviceAdslPrivate));

	_nm_object_class_add_interface (nm_object_class, NM_DBUS_INTERFACE_DEVICE_ADSL);

	/* virtual methods */
	object_class->get_property = get_property;

	nm_object_class->init_dbus = init_dbus;

	device_class->connection_compatible = connection_compatible;
	device_class->get_setting_type = get_setting_type;

	/* properties */
	/**
	 * NMDeviceAdsl:carrier:
	 *
	 * Whether the device has carrier.
	 **/
	g_object_class_install_property
		(object_class, PROP_CARRIER,
		 g_param_spec_boolean (NM_DEVICE_ADSL_CARRIER, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));
}
