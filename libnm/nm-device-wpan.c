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
 * Copyright 2018 Lubomir Rintel <lkundrak@v3.sk>
 */

#include "nm-default.h"

#include "nm-device-wpan.h"

#include "nm-object-private.h"
#include "nm-setting-wpan.h"
#include "nm-setting-connection.h"

enum {
        PROP_0,
        PROP_HW_ADDRESS,

        LAST_PROP
};

typedef struct {
        char *hw_address;
} NMDeviceWpanPrivate;

/**
 * NMDeviceWpan:
 */
struct _NMDeviceWpan {
        NMDevice parent;
};

typedef struct {
        NMDeviceClass parent;
} NMDeviceWpanClass;

G_DEFINE_TYPE (NMDeviceWpan, nm_device_wpan, NM_TYPE_DEVICE)

#define NM_DEVICE_WPAN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_WPAN, NMDeviceWpanPrivate))

/*****************************************************************************/

/**
 * nm_device_wpan_get_hw_address:
 * @device: a #NMDeviceWpan
 *
 * Gets the active hardware (MAC) address of the #NMDeviceWpan
 *
 * Returns: the active hardware address. This is the internal string used by the
 * device, and must not be modified.
 **/
const char *
nm_device_wpan_get_hw_address (NMDeviceWpan *device)
{
        g_return_val_if_fail (NM_IS_DEVICE_WPAN (device), NULL);

        return nm_str_not_empty (NM_DEVICE_WPAN_GET_PRIVATE (device)->hw_address);
}

static gboolean
connection_compatible (NMDevice *device, NMConnection *connection, GError **error)
{
	if (!NM_DEVICE_CLASS (nm_device_wpan_parent_class)->connection_compatible (device, connection, error))
		return FALSE;

	if (!nm_connection_is_type (connection, NM_SETTING_WPAN_SETTING_NAME)) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
		                     _("The connection was not a wpan connection."));
		return FALSE;
	}

	return TRUE;
}

static GType
get_setting_type (NMDevice *device)
{
	return NM_TYPE_SETTING_WPAN;
}

static const char *
get_hw_address (NMDevice *device)
{
	return nm_device_wpan_get_hw_address (NM_DEVICE_WPAN (device));
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
	switch (prop_id) {
	case PROP_HW_ADDRESS:
		g_value_set_string (value, nm_device_wpan_get_hw_address (NM_DEVICE_WPAN (object)));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_device_wpan_init (NMDeviceWpan *device)
{
}

static void
init_dbus (NMObject *object)
{
        NMDeviceWpanPrivate *priv = NM_DEVICE_WPAN_GET_PRIVATE (object);
	const NMPropertiesInfo property_info[] = {
		{ NM_DEVICE_WPAN_HW_ADDRESS, &priv->hw_address },
		{ NULL },
	};

	NM_OBJECT_CLASS (nm_device_wpan_parent_class)->init_dbus (object);

	_nm_object_register_properties (object,
	                                NM_DBUS_INTERFACE_DEVICE_WPAN,
	                                property_info);
}

static void
finalize (GObject *object)
{
        NMDeviceWpanPrivate *priv = NM_DEVICE_WPAN_GET_PRIVATE (object);

        g_free (priv->hw_address);

        G_OBJECT_CLASS (nm_device_wpan_parent_class)->finalize (object);
}

static void
nm_device_wpan_class_init (NMDeviceWpanClass *wpan_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (wpan_class);
	NMObjectClass *nm_object_class = NM_OBJECT_CLASS (wpan_class);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (wpan_class);

	g_type_class_add_private (wpan_class, sizeof (NMDeviceWpanPrivate));

	/* virtual methods */
	object_class->finalize = finalize;
	object_class->get_property = get_property;

	nm_object_class->init_dbus = init_dbus;

	device_class->connection_compatible = connection_compatible;
	device_class->get_setting_type = get_setting_type;
	device_class->get_hw_address = get_hw_address;

	/* properties */

	/**
	 * NMDeviceWpan:hw-address:
	 *
	 * The active hardware (MAC) address of the device.
	 **/
	g_object_class_install_property
		(object_class, PROP_HW_ADDRESS,
		 g_param_spec_string (NM_DEVICE_WPAN_HW_ADDRESS, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));
}
