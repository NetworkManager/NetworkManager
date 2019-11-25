// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2017 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-checkpoint.h"

#include "nm-core-internal.h"
#include "nm-dbus-interface.h"
#include "nm-device.h"
#include "nm-object-private.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE (
	PROP_DEVICES,
	PROP_CREATED,
	PROP_ROLLBACK_TIMEOUT,
);

typedef struct {
	NMLDBusPropertyAO devices;
	gint64 created;
	guint32 rollback_timeout;
} NMCheckpointPrivate;

struct _NMCheckpoint {
	NMObject parent;
	NMCheckpointPrivate _priv;
};

struct _NMCheckpointClass {
	NMObjectClass parent;
};

G_DEFINE_TYPE (NMCheckpoint, nm_checkpoint, NM_TYPE_OBJECT)

#define NM_CHECKPOINT_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMCheckpoint, NM_IS_CHECKPOINT, NMObject)

/*****************************************************************************/

/**
 * nm_checkpoint_get_devices:
 * @checkpoint: a #NMCheckpoint
 *
 * The devices that are part of this checkpoint.
 *
 * Returns: (element-type NMDevice): the devices list.
 *
 * Since: 1.12
 **/
const GPtrArray *
nm_checkpoint_get_devices (NMCheckpoint *checkpoint)
{
	g_return_val_if_fail (NM_IS_CHECKPOINT (checkpoint), NULL);

	return nml_dbus_property_ao_get_objs_as_ptrarray (&NM_CHECKPOINT_GET_PRIVATE (checkpoint)->devices);
}

/**
 * nm_checkpoint_get_created:
 * @checkpoint: a #NMCheckpoint
 *
 * Gets the timestamp (in CLOCK_BOOTTIME milliseconds) of checkpoint creation.
 *
 * Use nm_utils_get_timestamp_msec() to obtain current time value suitable for
 * comparing to this value.
 *
 * Returns: the timestamp of checkpoint creation.
 *
 * Since: 1.12
 **/
gint64
nm_checkpoint_get_created (NMCheckpoint *checkpoint)
{
	g_return_val_if_fail (NM_IS_CHECKPOINT (checkpoint), 0);

	return NM_CHECKPOINT_GET_PRIVATE (checkpoint)->created;
}

/**
 * nm_checkpoint_get_rollback_timeout:
 * @checkpoint: a #NMCheckpoint
 *
 * Gets the timeout in seconds for automatic rollback.
 *
 * Returns: the rollback timeout.
 *
 * Since: 1.12
 **/
guint32
nm_checkpoint_get_rollback_timeout (NMCheckpoint *checkpoint)
{
	g_return_val_if_fail (NM_IS_CHECKPOINT (checkpoint), 0);

	return NM_CHECKPOINT_GET_PRIVATE (checkpoint)->rollback_timeout;
}

/*****************************************************************************/

static void
nm_checkpoint_init (NMCheckpoint *checkpoint)
{
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMCheckpoint *checkpoint = NM_CHECKPOINT (object);
	NMCheckpointPrivate *priv = NM_CHECKPOINT_GET_PRIVATE (checkpoint);

	switch (prop_id) {
	case PROP_DEVICES:
		g_value_take_boxed (value, _nm_utils_copy_object_array (nm_checkpoint_get_devices (checkpoint)));
		break;
	case PROP_CREATED:
		g_value_set_int64 (value, priv->created);
		break;
	case PROP_ROLLBACK_TIMEOUT:
		g_value_set_uint (value, priv->rollback_timeout);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

const NMLDBusMetaIface _nml_dbus_meta_iface_nm_checkpoint = NML_DBUS_META_IFACE_INIT_PROP (
	NM_DBUS_INTERFACE_CHECKPOINT,
	nm_checkpoint_get_type,
	NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_HIGH,
	NML_DBUS_META_IFACE_DBUS_PROPERTIES (
		NML_DBUS_META_PROPERTY_INIT_X       ("Created",         PROP_CREATED,          NMCheckpoint, _priv.created                                                      ),
		NML_DBUS_META_PROPERTY_INIT_AO_PROP ("Devices",         PROP_DEVICES,          NMCheckpoint, _priv.devices,         nm_device_get_type, .is_always_ready = TRUE ),
		NML_DBUS_META_PROPERTY_INIT_U       ("RollbackTimeout", PROP_ROLLBACK_TIMEOUT, NMCheckpoint, _priv.rollback_timeout                                             ),
	),
);

static void
nm_checkpoint_class_init (NMCheckpointClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMObjectClass *nm_object_class = NM_OBJECT_CLASS (klass);

	object_class->get_property = get_property;

	_NM_OBJECT_CLASS_INIT_PRIV_PTR_DIRECT (nm_object_class, NMCheckpoint);

	_NM_OBJECT_CLASS_INIT_PROPERTY_AO_FIELDS_1 (nm_object_class, NMCheckpointPrivate, devices);

	/**
	 * NMCheckpoint:devices: (type GPtrArray(NMDevice))
	 *
	 * The devices that are part of this checkpoint.
	 *
	 * Since: 1.12
	 **/
	obj_properties[PROP_DEVICES] =
	    g_param_spec_boxed (NM_CHECKPOINT_DEVICES, "", "",
	                        G_TYPE_PTR_ARRAY,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMCheckpoint:created:
	 *
	 * The timestamp (in CLOCK_BOOTTIME milliseconds) of checkpoint creation.
	 *
	 * Since: 1.12
	 **/
	obj_properties[PROP_CREATED] =
	    g_param_spec_int64 (NM_CHECKPOINT_CREATED, "", "",
	                        G_MININT64, G_MAXINT64, 0,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMCheckpoint:rollback-timeout:
	 *
	 * Timeout in seconds for automatic rollback, or zero.
	 *
	 * Since: 1.12
	 **/
	obj_properties[PROP_ROLLBACK_TIMEOUT] =
	    g_param_spec_uint (NM_CHECKPOINT_ROLLBACK_TIMEOUT, "", "",
	                       0, G_MAXUINT32, 0,
	                       G_PARAM_READABLE |
	                       G_PARAM_STATIC_STRINGS);

	_nml_dbus_meta_class_init_with_properties (object_class, &_nml_dbus_meta_iface_nm_checkpoint);
}
