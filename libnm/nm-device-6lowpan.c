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
 * Copyright 2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-device-6lowpan.h"
#include "nm-object-private.h"

typedef struct {
	NMDevice *parent;
	char *hw_address;
} NMDevice6LowpanPrivate;

/**
 * NMDevice6Lowpan:
 */
struct _NMDevice6Lowpan {
        NMDevice parent;
};

typedef struct {
        NMDeviceClass parent;

        /*< private >*/
        gpointer padding[4];
} NMDevice6LowpanClass;

G_DEFINE_TYPE (NMDevice6Lowpan, nm_device_6lowpan, NM_TYPE_DEVICE)

#define NM_DEVICE_6LOWPAN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_6LOWPAN, NMDevice6LowpanPrivate))

NM_GOBJECT_PROPERTIES_DEFINE_BASE (
	PROP_PARENT,
	PROP_HW_ADDRESS,
);

/**
 * nm_device_6lowpan_get_parent:
 * @device: a #NMDevice6Lowpan
 *
 * Returns: (transfer none): the device's parent device
 *
 * Since: 1.14
 **/
NMDevice *
nm_device_6lowpan_get_parent (NMDevice6Lowpan *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_6LOWPAN (device), NULL);

	return NM_DEVICE_6LOWPAN_GET_PRIVATE (device)->parent;
}

/**
 * nm_device_6lowpan_get_hw_address:
 * @device: a #NMDevice6Lowpan
 *
 * Gets the hardware (MAC) address of the #NMDevice6Lowpan
 *
 * Returns: the hardware address. This is the internal string used by the
 * device, and must not be modified.
 *
 * Since: 1.14
 **/
const char *
nm_device_6lowpan_get_hw_address (NMDevice6Lowpan *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_6LOWPAN (device), NULL);

	return NM_DEVICE_6LOWPAN_GET_PRIVATE (device)->hw_address;
}

static const char *
get_hw_address (NMDevice *device)
{
	return nm_device_6lowpan_get_hw_address (NM_DEVICE_6LOWPAN (device));
}

/***********************************************************/

static void
nm_device_6lowpan_init (NMDevice6Lowpan *device)
{
}

static void
init_dbus (NMObject *object)
{
	NMDevice6LowpanPrivate *priv = NM_DEVICE_6LOWPAN_GET_PRIVATE (object);
	const NMPropertiesInfo property_info[] = {
		{ NM_DEVICE_6LOWPAN_PARENT,         &priv->parent, NULL, NM_TYPE_DEVICE },
		{ NM_DEVICE_6LOWPAN_HW_ADDRESS,     &priv->hw_address },
		{ NULL },
	};

	NM_OBJECT_CLASS (nm_device_6lowpan_parent_class)->init_dbus (object);

	_nm_object_register_properties (object,
	                                NM_DBUS_INTERFACE_DEVICE_6LOWPAN,
	                                property_info);
}

static void
finalize (GObject *object)
{
	NMDevice6LowpanPrivate *priv = NM_DEVICE_6LOWPAN_GET_PRIVATE (object);

	g_free (priv->hw_address);
	g_clear_object (&priv->parent);

	G_OBJECT_CLASS (nm_device_6lowpan_parent_class)->finalize (object);
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMDevice6Lowpan *device = NM_DEVICE_6LOWPAN (object);

	switch (prop_id) {
	case PROP_PARENT:
		g_value_set_object (value, nm_device_6lowpan_get_parent (device));
		break;
	case PROP_HW_ADDRESS:
		g_value_set_string (value, nm_device_6lowpan_get_hw_address (device));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_device_6lowpan_class_init (NMDevice6LowpanClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMObjectClass *nm_object_class = NM_OBJECT_CLASS (klass);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NMDevice6LowpanPrivate));

	object_class->finalize = finalize;
	object_class->get_property = get_property;

	nm_object_class->init_dbus = init_dbus;

	device_class->get_hw_address = get_hw_address;

	/**
	 * NMDevice6Lowpan:parent:
	 *
	 * The devices's parent device.
	 *
	 * Since: 1.14
	 **/
	obj_properties[PROP_PARENT] =
		g_param_spec_object (NM_DEVICE_6LOWPAN_PARENT, "", "",
		                     NM_TYPE_DEVICE,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS);

	/**
	 * NMDevice6Lowpan:hw-address:
	 *
	 * The hardware (MAC) address of the device.
	 *
	 * Since: 1.14
	 **/
	obj_properties[PROP_HW_ADDRESS] =
		g_param_spec_string (NM_DEVICE_6LOWPAN_HW_ADDRESS, "", "",
		                     NULL,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);
}
