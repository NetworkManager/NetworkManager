/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * libnm_glib -- Access network status & information from glib applications
 *
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
 * Copyright (C) 2007 - 2008 Novell, Inc.
 * Copyright (C) 2007 - 2008 Red Hat, Inc.
 */

#include "nm-gsm-device.h"
#include "nm-device-private.h"
#include "nm-object-private.h"

G_DEFINE_TYPE (NMGsmDevice, nm_gsm_device, NM_TYPE_SERIAL_DEVICE)

#define NM_GSM_DEVICE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_GSM_DEVICE, NMGsmDevicePrivate))

typedef struct {
	DBusGProxy *proxy;

	gboolean disposed;
} NMGsmDevicePrivate;

static void
nm_gsm_device_init (NMGsmDevice *device)
{
}

static void
register_for_property_changed (NMGsmDevice *device)
{
	NMGsmDevicePrivate *priv = NM_GSM_DEVICE_GET_PRIVATE (device);
	const NMPropertiesChangedInfo property_changed_info[] = {
		{ NULL },
	};

	_nm_object_handle_properties_changed (NM_OBJECT (device),
	                                     priv->proxy,
	                                     property_changed_info);
}

static GObject*
constructor (GType type,
             guint n_construct_params,
             GObjectConstructParam *construct_params)
{
	GObject *object;
	NMGsmDevicePrivate *priv;

	object = G_OBJECT_CLASS (nm_gsm_device_parent_class)->constructor (type,
														  n_construct_params,
														  construct_params);
	if (!object)
		return NULL;

	priv = NM_GSM_DEVICE_GET_PRIVATE (object);

	priv->proxy = dbus_g_proxy_new_for_name (nm_object_get_connection (NM_OBJECT (object)),
										NM_DBUS_SERVICE,
										nm_object_get_path (NM_OBJECT (object)),
										NM_DBUS_INTERFACE_GSM_DEVICE);

	register_for_property_changed (NM_GSM_DEVICE (object));

	return object;
}

static void
dispose (GObject *object)
{
	NMGsmDevicePrivate *priv = NM_GSM_DEVICE_GET_PRIVATE (object);

	if (priv->disposed) {
		G_OBJECT_CLASS (nm_gsm_device_parent_class)->dispose (object);
		return;
	}

	priv->disposed = TRUE;

	g_object_unref (priv->proxy);

	G_OBJECT_CLASS (nm_gsm_device_parent_class)->dispose (object);
}

static void
nm_gsm_device_class_init (NMGsmDeviceClass *device_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (device_class);

	g_type_class_add_private (device_class, sizeof (NMGsmDevicePrivate));

	/* virtual methods */
	object_class->constructor = constructor;
	object_class->dispose = dispose;
}

/**
 * nm_gsm_device_new:
 * @connection: the #DBusGConnection
 * @path: the DBus object path of the device
 *
 * Creates a new #NMGsmDevice.
 *
 * Returns: a new device
 **/
NMGsmDevice *
nm_gsm_device_new (DBusGConnection *connection, const char *path)
{
	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (path != NULL, NULL);

	return (NMGsmDevice *) g_object_new (NM_TYPE_GSM_DEVICE,
								  NM_OBJECT_DBUS_CONNECTION, connection,
								  NM_OBJECT_DBUS_PATH, path,
								  NULL);
}
