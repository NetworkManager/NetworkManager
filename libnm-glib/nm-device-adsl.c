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

G_DEFINE_TYPE (NMDeviceAdsl, nm_device_adsl, NM_TYPE_DEVICE)

#define NM_DEVICE_ADSL_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_ADSL, NMDeviceAdslPrivate))

typedef struct {
	DBusGProxy *proxy;

	gboolean carrier;

	gboolean disposed;
} NMDeviceAdslPrivate;

enum {
	PROP_0,
	PROP_CARRIER,
	LAST_PROP
};

/**
 * nm_device_adsl_error_quark:
 *
 * Registers an error quark for #NMDeviceAdsl if necessary.
 *
 * Returns: the error quark used for #NMDeviceAdsl errors.
 **/
GQuark
nm_device_adsl_error_quark (void)
{
	static GQuark quark = 0;

	if (G_UNLIKELY (quark == 0))
		quark = g_quark_from_static_string ("nm-device-adsl-error-quark");
	return quark;
}

/**
 * nm_device_adsl_new:
 * @connection: the #DBusGConnection
 * @path: the DBus object path of the device
 *
 * Creates a new #NMDeviceAdsl.
 *
 * Returns: (transfer full): a new device
 **/
GObject *
nm_device_adsl_new (DBusGConnection *connection, const char *path)
{
	GObject *device;

	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (path != NULL, NULL);

	device = g_object_new (NM_TYPE_DEVICE_ADSL,
	                       NM_OBJECT_DBUS_CONNECTION, connection,
	                       NM_OBJECT_DBUS_PATH, path,
	                       NULL);
	_nm_object_ensure_inited (NM_OBJECT (device));
	return device;
}

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

	_nm_object_ensure_inited (NM_OBJECT (device));
	return NM_DEVICE_ADSL_GET_PRIVATE (device)->carrier;
}

static gboolean
connection_compatible (NMDevice *device, NMConnection *connection, GError **error)
{
	NMSettingConnection *s_con;
	NMSettingAdsl *s_adsl;
	const char *ctype;

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);

	ctype = nm_setting_connection_get_connection_type (s_con);
	if (strcmp (ctype, NM_SETTING_ADSL_SETTING_NAME) != 0) {
		g_set_error (error, NM_DEVICE_ADSL_ERROR, NM_DEVICE_ADSL_ERROR_NOT_ADSL_CONNECTION,
		             "The connection was not an ADSL connection.");
		return FALSE;
	}

	s_adsl = nm_connection_get_setting_adsl (connection);
	if (!s_adsl) {
		g_set_error (error, NM_DEVICE_ADSL_ERROR, NM_DEVICE_ADSL_ERROR_INVALID_ADSL_CONNECTION,
		             "The connection was not a valid ADSL connection.");
		return FALSE;
	}

	return NM_DEVICE_CLASS (nm_device_adsl_parent_class)->connection_compatible (device, connection, error);
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
register_properties (NMDeviceAdsl *device)
{
	NMDeviceAdslPrivate *priv = NM_DEVICE_ADSL_GET_PRIVATE (device);
	const NMPropertiesInfo property_info[] = {
		{ NM_DEVICE_ADSL_CARRIER,              &priv->carrier },
		{ NULL },
	};

	_nm_object_register_properties (NM_OBJECT (device),
	                                priv->proxy,
	                                property_info);
}

static void
constructed (GObject *object)
{
	NMDeviceAdslPrivate *priv = NM_DEVICE_ADSL_GET_PRIVATE (object);

	G_OBJECT_CLASS (nm_device_adsl_parent_class)->constructed (object);

	priv->proxy = _nm_object_new_proxy (NM_OBJECT (object), NULL, NM_DBUS_INTERFACE_DEVICE_ADSL);
	register_properties (NM_DEVICE_ADSL (object));
}

static void
dispose (GObject *object)
{
	NMDeviceAdslPrivate *priv = NM_DEVICE_ADSL_GET_PRIVATE (object);

	if (priv->disposed) {
		G_OBJECT_CLASS (nm_device_adsl_parent_class)->dispose (object);
		return;
	}

	priv->disposed = TRUE;

	g_object_unref (priv->proxy);

	G_OBJECT_CLASS (nm_device_adsl_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	G_OBJECT_CLASS (nm_device_adsl_parent_class)->finalize (object);
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
	NMDeviceClass *device_class = NM_DEVICE_CLASS (adsl_class);

	g_type_class_add_private (object_class, sizeof (NMDeviceAdslPrivate));

	/* virtual methods */
	object_class->constructed = constructed;
	object_class->dispose = dispose;
	object_class->finalize = finalize;
	object_class->get_property = get_property;
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
