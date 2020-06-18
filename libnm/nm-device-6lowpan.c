// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-device-6lowpan.h"

#include "nm-object-private.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE (
	PROP_PARENT,
);

typedef struct {
	NMLDBusPropertyO parent;
} NMDevice6LowpanPrivate;

struct _NMDevice6Lowpan {
	NMDevice parent;
	NMDevice6LowpanPrivate _priv;
};

struct _NMDevice6LowpanClass {
	NMDeviceClass parent;
};

G_DEFINE_TYPE (NMDevice6Lowpan, nm_device_6lowpan, NM_TYPE_DEVICE)

#define NM_DEVICE_6LOWPAN_GET_PRIVATE(self) _NM_GET_PRIVATE(self, NMDevice6Lowpan, NM_IS_DEVICE_6LOWPAN, NMObject, NMDevice)

/*****************************************************************************/

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

	return nml_dbus_property_o_get_obj (&NM_DEVICE_6LOWPAN_GET_PRIVATE (device)->parent);
}

/**
 * nm_device_6lowpan_get_hw_address: (skip)
 * @device: a #NMDevice6Lowpan
 *
 * Gets the hardware (MAC) address of the #NMDevice6Lowpan
 *
 * Returns: the hardware address. This is the internal string used by the
 * device, and must not be modified.
 *
 * Since: 1.14
 *
 * Deprecated: 1.24: Use nm_device_get_hw_address() instead.
 **/
const char *
nm_device_6lowpan_get_hw_address (NMDevice6Lowpan *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_6LOWPAN (device), NULL);

	return nm_device_get_hw_address (NM_DEVICE (device));
}

/*****************************************************************************/

static void
nm_device_6lowpan_init (NMDevice6Lowpan *device)
{
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
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

const NMLDBusMetaIface _nml_dbus_meta_iface_nm_device_lowpan = NML_DBUS_META_IFACE_INIT_PROP (
	NM_DBUS_INTERFACE_DEVICE_6LOWPAN,
	nm_device_6lowpan_get_type,
	NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_HIGH,
	NML_DBUS_META_IFACE_DBUS_PROPERTIES (
		NML_DBUS_META_PROPERTY_INIT_FCN    ("HwAddress", 0,               "s",             _nm_device_notify_update_prop_hw_address                    ),
		NML_DBUS_META_PROPERTY_INIT_O_PROP ("Parent",    PROP_PARENT,     NMDevice6Lowpan, _priv.parent,                            nm_device_get_type ),
	),
);

static void
nm_device_6lowpan_class_init (NMDevice6LowpanClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMObjectClass *nm_object_class = NM_OBJECT_CLASS (klass);

	object_class->get_property = get_property;

	_NM_OBJECT_CLASS_INIT_PRIV_PTR_DIRECT (nm_object_class, NMDevice6Lowpan);

	_NM_OBJECT_CLASS_INIT_PROPERTY_O_FIELDS_1 (nm_object_class, NMDevice6LowpanPrivate, parent);

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

	_nml_dbus_meta_class_init_with_properties (object_class, &_nml_dbus_meta_iface_nm_device_lowpan);
}
