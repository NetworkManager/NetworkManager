/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program. If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Copyright 2017 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-checkpoint.h"
#include "nm-core-internal.h"
#include "nm-dbus-interface.h"
#include "nm-device.h"
#include "nm-object-private.h"

typedef struct {
	GPtrArray *devices;
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

#define NM_CHECKPOINT_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMCheckpoint, NM_IS_CHECKPOINT)

enum {
	PROP_0,
	PROP_DEVICES,
	PROP_CREATED,
	PROP_ROLLBACK_TIMEOUT,

	LAST_PROP
};

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

	return NM_CHECKPOINT_GET_PRIVATE (checkpoint)->devices;
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
finalize (GObject *object)
{
	NMCheckpointPrivate *priv = NM_CHECKPOINT_GET_PRIVATE (NM_CHECKPOINT (object));

	g_ptr_array_unref (priv->devices);

	G_OBJECT_CLASS (nm_checkpoint_parent_class)->finalize (object);
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
		g_value_take_boxed (value, _nm_utils_copy_object_array (priv->devices));
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

static void
init_dbus (NMObject *object)
{
	NMCheckpointPrivate *priv = NM_CHECKPOINT_GET_PRIVATE (NM_CHECKPOINT (object));
	const NMPropertiesInfo property_info[] = {
		{ NM_CHECKPOINT_DEVICES,            &priv->devices, NULL, NM_TYPE_DEVICE },
		{ NM_CHECKPOINT_CREATED,            &priv->created },
		{ NM_CHECKPOINT_ROLLBACK_TIMEOUT,   &priv->rollback_timeout },
		{ NULL },
	};

	NM_OBJECT_CLASS (nm_checkpoint_parent_class)->init_dbus (object);

	_nm_object_register_properties (object,
	                                NM_DBUS_INTERFACE_CHECKPOINT,
	                                property_info);
}

static void
nm_checkpoint_class_init (NMCheckpointClass *checkpoint_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (checkpoint_class);
	NMObjectClass *nm_object_class = NM_OBJECT_CLASS (checkpoint_class);

	object_class->get_property = get_property;
	object_class->finalize = finalize;

	nm_object_class->init_dbus = init_dbus;

	/**
	 * NMCheckpoint:devices: (type GPtrArray(NMDevice))
	 *
	 * The devices that are part of this checkpoint.
	 *
	 * Since: 1.12
	 **/
	g_object_class_install_property
		(object_class, PROP_DEVICES,
		 g_param_spec_boxed (NM_CHECKPOINT_DEVICES, "", "",
		                     G_TYPE_PTR_ARRAY,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));

	/**
	 * NMCheckpoint:created:
	 *
	 * The timestamp (in CLOCK_BOOTTIME milliseconds) of checkpoint creation.
	 *
	 * Since: 1.12
	 **/
	g_object_class_install_property
		(object_class, PROP_CREATED,
		 g_param_spec_int64 (NM_CHECKPOINT_CREATED, "", "",
		                     G_MININT64, G_MAXINT64, 0,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));

	/**
	 * NMCheckpoint:rollback-timeout:
	 *
	 * Timeout in seconds for automatic rollback, or zero.
	 *
	 * Since: 1.12
	 **/
	g_object_class_install_property
		(object_class, PROP_ROLLBACK_TIMEOUT,
		 g_param_spec_uint (NM_CHECKPOINT_ROLLBACK_TIMEOUT, "", "",
		                    0, G_MAXUINT32, 0,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));
}
