/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2016 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-checkpoint.h"

#include <string.h>

#include "nm-active-connection.h"
#include "nm-auth-subject.h"
#include "nm-core-utils.h"
#include "nm-dbus-interface.h"
#include "devices/nm-device.h"
#include "nm-manager.h"
#include "settings/nm-settings.h"
#include "settings/nm-settings-connection.h"
#include "nm-simple-connection.h"
#include "nm-utils.h"
#include "introspection/org.freedesktop.NetworkManager.Checkpoint.h"

/*****************************************************************************/

typedef struct {
	char *original_dev_path;
	NMDevice *device;
	NMConnection *applied_connection;
	NMConnection *settings_connection;
	guint64 ac_version_id;
	NMDeviceState state;
	bool realized:1;
	NMUnmanFlagOp unmanaged_explicit;
} DeviceCheckpoint;

NM_GOBJECT_PROPERTIES_DEFINE_BASE (
	PROP_DEVICES,
	PROP_CREATED,
	PROP_ROLLBACK_TIMEOUT,
);

typedef struct {
	/* properties */
	GHashTable *devices;
	gint64 created;
	guint32 rollback_timeout;
	/* private members */
	NMManager *manager;
	gint64 rollback_ts;
	NMCheckpointCreateFlags flags;
	GHashTable *connection_uuids;
} NMCheckpointPrivate;

struct _NMCheckpoint {
	NMExportedObject parent;
	NMCheckpointPrivate _priv;
};

struct _NMCheckpointClass {
	NMExportedObjectClass parent;
};

G_DEFINE_TYPE (NMCheckpoint, nm_checkpoint, NM_TYPE_EXPORTED_OBJECT)

#define NM_CHECKPOINT_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMCheckpoint, NM_IS_CHECKPOINT)

/*****************************************************************************/

#define _NMLOG_PREFIX_NAME                "checkpoint"
#define _NMLOG_DOMAIN                     LOGD_CORE

#define _NMLOG(level, ...) \
	G_STMT_START { \
		if (nm_logging_enabled (level, _NMLOG_DOMAIN)) { \
			char __prefix[32]; \
			\
			if (self) \
				g_snprintf (__prefix, sizeof (__prefix), "%s[%p]", ""_NMLOG_PREFIX_NAME"", (self)); \
			else \
				g_strlcpy (__prefix, _NMLOG_PREFIX_NAME, sizeof (__prefix)); \
			_nm_log ((level), (_NMLOG_DOMAIN), 0, NULL, NULL, \
			          "%s: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__), \
			          __prefix _NM_UTILS_MACRO_REST(__VA_ARGS__)); \
		} \
	} G_STMT_END

/*****************************************************************************/

guint64
nm_checkpoint_get_rollback_ts (NMCheckpoint *self)
{
	g_return_val_if_fail (NM_IS_CHECKPOINT (self), 0);

	return NM_CHECKPOINT_GET_PRIVATE (self)->rollback_ts;
}

gboolean
nm_checkpoint_includes_device (NMCheckpoint *self, NMDevice *device)
{
	NMCheckpointPrivate *priv = NM_CHECKPOINT_GET_PRIVATE (self);

	return g_hash_table_contains (priv->devices, device);
}

static NMSettingsConnection *
find_settings_connection (NMCheckpoint *self,
                          DeviceCheckpoint *dev_checkpoint,
                          gboolean *need_update,
                          gboolean *need_activation)
{
	NMCheckpointPrivate *priv = NM_CHECKPOINT_GET_PRIVATE (self);
	NMActiveConnection *active;
	NMSettingsConnection *connection;
	const char *uuid, *ac_uuid;
	const CList *tmp_clist;

	*need_activation = FALSE;
	*need_update = FALSE;

	uuid = nm_connection_get_uuid (dev_checkpoint->settings_connection);
	connection = nm_settings_get_connection_by_uuid (nm_settings_get (), uuid);

	if (!connection)
		return NULL;

	/* Now check if the connection changed, ... */
	if (!nm_connection_compare (dev_checkpoint->settings_connection,
	                            NM_CONNECTION (connection),
	                            NM_SETTING_COMPARE_FLAG_EXACT)) {
		_LOGT ("rollback: settings connection %s changed", uuid);
		*need_update = TRUE;
		*need_activation = TRUE;
	}

	/* ... is active, ... */
	nm_manager_for_each_active_connection (priv->manager, active, tmp_clist) {
		ac_uuid = nm_settings_connection_get_uuid (nm_active_connection_get_settings_connection (active));
		if (nm_streq (uuid, ac_uuid)) {
			_LOGT ("rollback: connection %s is active", uuid);
			break;
		}
	}

	if (!active) {
		_LOGT ("rollback: connection %s is not active", uuid);
		*need_activation = TRUE;
		return connection;
	}

	/* ... or if the connection was reactivated/reapplied */
	if (nm_active_connection_version_id_get (active) != dev_checkpoint->ac_version_id) {
		_LOGT ("rollback: active connection version id of %s changed", uuid);
		*need_activation = TRUE;
	}

	return connection;
}

GVariant *
nm_checkpoint_rollback (NMCheckpoint *self)
{
	NMCheckpointPrivate *priv = NM_CHECKPOINT_GET_PRIVATE (self);
	DeviceCheckpoint *dev_checkpoint;
	GHashTableIter iter;
	NMSettingsConnection *connection;
	NMDevice *device;
	GError *local_error = NULL;
	GVariantBuilder builder;

	_LOGI ("rollback of %s", nm_exported_object_get_path ((NMExportedObject *) self));
	 g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{su}"));

	/* Start rolling-back each device */
	g_hash_table_iter_init (&iter, priv->devices);
	while (g_hash_table_iter_next (&iter, (gpointer *) &device, (gpointer *) &dev_checkpoint)) {
		gs_unref_object NMAuthSubject *subject = NULL;
		guint32 result = NM_ROLLBACK_RESULT_OK;

		_LOGD ("rollback: restoring device %s (state %d, realized %d, explicitly unmanaged %d)",
		       nm_device_get_iface (device),
		       (int) dev_checkpoint->state,
		       dev_checkpoint->realized,
		       dev_checkpoint->unmanaged_explicit);

		if (nm_device_is_real (device)) {
			if (!dev_checkpoint->realized) {
				_LOGD ("rollback: device was not realized, unmanage it");
				nm_device_set_unmanaged_by_flags_queue (device,
				                                        NM_UNMANAGED_USER_EXPLICIT,
				                                        TRUE,
				                                        NM_DEVICE_STATE_REASON_NOW_UNMANAGED);
				goto next_dev;
			}
		} else {
			if (dev_checkpoint->realized) {
				if (nm_device_is_software (device)) {
					/* try to recreate software device */
					_LOGD ("rollback: software device not realized, will re-activate");
					goto activate;
				} else {
					_LOGD ("rollback: device is not realized");
					result = NM_ROLLBACK_RESULT_ERR_FAILED;
				}
			}
			goto next_dev;
		}

activate:
		/* Manage the device again if needed */
		if (   nm_device_get_unmanaged_flags (device, NM_UNMANAGED_USER_EXPLICIT)
		    && dev_checkpoint->unmanaged_explicit != NM_UNMAN_FLAG_OP_SET_UNMANAGED) {
			_LOGD ("rollback: restore unmanaged user-explicit");
			nm_device_set_unmanaged_by_flags_queue (device,
			                                        NM_UNMANAGED_USER_EXPLICIT,
			                                        dev_checkpoint->unmanaged_explicit,
			                                        NM_DEVICE_STATE_REASON_NOW_MANAGED);
		}

		if (dev_checkpoint->state == NM_DEVICE_STATE_UNMANAGED) {
			if (   nm_device_get_state (device) != NM_DEVICE_STATE_UNMANAGED
			    || dev_checkpoint->unmanaged_explicit == NM_UNMAN_FLAG_OP_SET_UNMANAGED) {
				_LOGD ("rollback: explicitly unmanage device");
				nm_device_set_unmanaged_by_flags_queue (device,
				                                        NM_UNMANAGED_USER_EXPLICIT,
				                                        TRUE,
				                                        NM_DEVICE_STATE_REASON_NOW_UNMANAGED);
			}
			goto next_dev;
		}

		if (dev_checkpoint->applied_connection) {
			gboolean need_update, need_activation;

			/* The device had an active connection: check if the
			 * connection still exists, is active and was changed */
			connection = find_settings_connection (self, dev_checkpoint, &need_update, &need_activation);
			if (connection) {
				if (need_update) {
					_LOGD ("rollback: updating connection %s",
					        nm_settings_connection_get_uuid (connection));
					nm_settings_connection_update (connection,
					                               dev_checkpoint->settings_connection,
					                               NM_SETTINGS_CONNECTION_PERSIST_MODE_DISK,
					                               NM_SETTINGS_CONNECTION_COMMIT_REASON_NONE,
					                               "checkpoint-rollback",
					                               NULL);
				}
			} else {
				/* The connection was deleted, recreate it */
				_LOGD ("rollback: adding connection %s again",
				       nm_connection_get_uuid (dev_checkpoint->settings_connection));

				connection = nm_settings_add_connection (nm_settings_get (),
				                                         dev_checkpoint->settings_connection,
				                                         TRUE,
				                                         &local_error);
				if (!connection) {
					_LOGD ("rollback: connection add failure: %s", local_error->message);
					g_clear_error (&local_error);
					result = NM_ROLLBACK_RESULT_ERR_FAILED;
					goto next_dev;
				}
				need_activation = TRUE;
			}

			if (need_activation) {
				_LOGD ("rollback: reactivating connection %s",
				       nm_settings_connection_get_uuid (connection));
				subject = nm_auth_subject_new_internal ();

				/* Disconnect the device if needed. This necessary because now
				 * the manager prevents the reactivation of the same connection by
				 * an internal subject. */
				if (   nm_device_get_state (device) > NM_DEVICE_STATE_DISCONNECTED
				    && nm_device_get_state (device) < NM_DEVICE_STATE_DEACTIVATING) {
					nm_device_state_changed (device,
					                         NM_DEVICE_STATE_DEACTIVATING,
					                         NM_DEVICE_STATE_REASON_NEW_ACTIVATION);
				}

				if (!nm_manager_activate_connection (priv->manager,
				                                     connection,
				                                     dev_checkpoint->applied_connection,
				                                     NULL,
				                                     device,
				                                     subject,
				                                     NM_ACTIVATION_TYPE_MANAGED,
				                                     &local_error)) {
					_LOGW ("rollback: reactivation of connection %s/%s failed: %s",
					       nm_connection_get_id ((NMConnection *) connection),
					       nm_connection_get_uuid ((NMConnection *	) connection),
					       local_error->message);
					g_clear_error (&local_error);
					result = NM_ROLLBACK_RESULT_ERR_FAILED;
					goto next_dev;
				}
			}
		} else {
			/* The device was initially disconnected, deactivate any existing connection */
			_LOGD ("rollback: disconnecting device");

			if (   nm_device_get_state (device) > NM_DEVICE_STATE_DISCONNECTED
			    && nm_device_get_state (device) < NM_DEVICE_STATE_DEACTIVATING) {
				nm_device_state_changed (device,
				                         NM_DEVICE_STATE_DEACTIVATING,
				                         NM_DEVICE_STATE_REASON_USER_REQUESTED);
			}
		}

next_dev:
		g_variant_builder_add (&builder, "{su}", dev_checkpoint->original_dev_path, result);
	}

	if (NM_FLAGS_HAS (priv->flags, NM_CHECKPOINT_CREATE_FLAG_DELETE_NEW_CONNECTIONS)) {
		NMSettingsConnection *con;
		gs_free NMSettingsConnection **list = NULL;
		guint i;

		g_return_val_if_fail (priv->connection_uuids, NULL);
		list = nm_settings_get_connections_clone (nm_settings_get (), NULL,
		                                          NULL, NULL,
		                                          nm_settings_connection_cmp_autoconnect_priority_p_with_data, NULL);

		for (i = 0; list[i]; i++) {
			con = list[i];
			if (!g_hash_table_contains (priv->connection_uuids,
			                            nm_settings_connection_get_uuid (con))) {
				_LOGD ("rollback: deleting new connection %s",
				       nm_settings_connection_get_uuid (con));
				nm_settings_connection_delete (con, NULL);
			}
		}
	}

	if (NM_FLAGS_HAS (priv->flags, NM_CHECKPOINT_CREATE_FLAG_DISCONNECT_NEW_DEVICES)) {
		const GSList *list;
		NMDeviceState state;
		NMDevice *dev;

		for (list = nm_manager_get_devices (priv->manager); list ; list = g_slist_next (list)) {
			dev = list->data;
			if (!g_hash_table_contains (priv->devices, dev)) {
				state = nm_device_get_state (dev);
				if (   state > NM_DEVICE_STATE_DISCONNECTED
				    && state < NM_DEVICE_STATE_DEACTIVATING) {
					_LOGD ("rollback: disconnecting new device %s", nm_device_get_iface (dev));
					nm_device_state_changed (dev,
					                         NM_DEVICE_STATE_DEACTIVATING,
					                         NM_DEVICE_STATE_REASON_USER_REQUESTED);
				}
			}
		}

	}

	return g_variant_new ("(a{su})", &builder);
}

static DeviceCheckpoint *
device_checkpoint_create (NMDevice *device,
                          GError **error)
{
	DeviceCheckpoint *dev_checkpoint;
	NMConnection *applied_connection;
	NMSettingsConnection *settings_connection;
	const char *path;
	NMActRequest *act_request;

	path = nm_exported_object_get_path (NM_EXPORTED_OBJECT (device));

	dev_checkpoint = g_slice_new0 (DeviceCheckpoint);
	dev_checkpoint->device = g_object_ref (device);
	dev_checkpoint->original_dev_path = g_strdup (path);
	dev_checkpoint->state = nm_device_get_state (device);
	dev_checkpoint->realized = nm_device_is_real (device);

	if (nm_device_get_unmanaged_mask (device, NM_UNMANAGED_USER_EXPLICIT)) {
		dev_checkpoint->unmanaged_explicit =
			!!nm_device_get_unmanaged_flags (device, NM_UNMANAGED_USER_EXPLICIT);
	} else
		dev_checkpoint->unmanaged_explicit = NM_UNMAN_FLAG_OP_FORGET;

	applied_connection = nm_device_get_applied_connection (device);
	if (applied_connection) {
		dev_checkpoint->applied_connection =
			nm_simple_connection_new_clone (applied_connection);

		settings_connection = nm_device_get_settings_connection (device);
		g_return_val_if_fail (settings_connection, NULL);
		dev_checkpoint->settings_connection =
			nm_simple_connection_new_clone (NM_CONNECTION (settings_connection));

		act_request = nm_device_get_act_request (device);
		g_return_val_if_fail (act_request, NULL);
		dev_checkpoint->ac_version_id =
			nm_active_connection_version_id_get (NM_ACTIVE_CONNECTION (act_request));
	}

	return dev_checkpoint;
}

static void
device_checkpoint_destroy (gpointer data)
{
	DeviceCheckpoint *dev_checkpoint = data;

	g_clear_object (&dev_checkpoint->applied_connection);
	g_clear_object (&dev_checkpoint->settings_connection);
	g_clear_object (&dev_checkpoint->device);
	g_free (dev_checkpoint->original_dev_path);

	g_slice_free (DeviceCheckpoint, dev_checkpoint);
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMCheckpoint *self = NM_CHECKPOINT (object);
	NMCheckpointPrivate *priv = NM_CHECKPOINT_GET_PRIVATE (self);
	gs_free_slist GSList *devices = NULL;
	GHashTableIter iter;
	NMDevice *device;

	switch (prop_id) {
	case PROP_DEVICES:
		g_hash_table_iter_init (&iter, priv->devices);
		while (g_hash_table_iter_next (&iter, (gpointer *) &device, NULL))
			devices = g_slist_append (devices, device);
		nm_utils_g_value_set_object_path_array (value, devices, NULL, NULL);
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

/*****************************************************************************/

static void
nm_checkpoint_init (NMCheckpoint *self)
{
	NMCheckpointPrivate *priv = NM_CHECKPOINT_GET_PRIVATE (self);

	priv->devices = g_hash_table_new_full (g_direct_hash, g_direct_equal,
	                                       NULL, device_checkpoint_destroy);
}

NMCheckpoint *
nm_checkpoint_new (NMManager *manager, GPtrArray *devices, guint32 rollback_timeout,
                   NMCheckpointCreateFlags flags, GError **error)
{
	NMCheckpoint *self;
	NMCheckpointPrivate *priv;
	NMSettingsConnection *const *con;
	DeviceCheckpoint *dev_checkpoint;
	NMDevice *device;
	guint i;

	g_return_val_if_fail (manager, NULL);
	g_return_val_if_fail (devices, NULL);
	g_return_val_if_fail (!error || !*error, NULL);

	if (!devices->len) {
		g_set_error_literal (error,
		                     NM_MANAGER_ERROR,
		                     NM_MANAGER_ERROR_INVALID_ARGUMENTS,
		                     "no device available");
		return NULL;
	}

	self = g_object_new (NM_TYPE_CHECKPOINT, NULL);

	priv = NM_CHECKPOINT_GET_PRIVATE (self);
	priv->manager = manager;
	priv->created = nm_utils_monotonic_timestamp_as_boottime (nm_utils_get_monotonic_timestamp_ms (),
	                                                          NM_UTILS_NS_PER_MSEC);
	priv->rollback_timeout = rollback_timeout;
	priv->rollback_ts = rollback_timeout ?
	    (nm_utils_get_monotonic_timestamp_ms () + ((gint64) rollback_timeout * 1000)) :
	    0;
	priv->flags = flags;

	if (NM_FLAGS_HAS (flags, NM_CHECKPOINT_CREATE_FLAG_DELETE_NEW_CONNECTIONS)) {
		priv->connection_uuids = g_hash_table_new_full (nm_str_hash, g_str_equal, g_free, NULL);
		for (con = nm_settings_get_connections (nm_settings_get (), NULL); *con; con++) {
			g_hash_table_add (priv->connection_uuids,
			                  g_strdup (nm_settings_connection_get_uuid (*con)));
		}
	}

	for (i = 0; i < devices->len; i++) {
		device = (NMDevice *) devices->pdata[i];
		dev_checkpoint = device_checkpoint_create (device, error);
		if (!dev_checkpoint) {
			g_object_unref (self);
			return NULL;
		}
		g_hash_table_insert (priv->devices, device, dev_checkpoint);
	}

	return self;
}

static void
dispose (GObject *object)
{
	NMCheckpoint *self = NM_CHECKPOINT (object);
	NMCheckpointPrivate *priv = NM_CHECKPOINT_GET_PRIVATE (self);

	g_clear_pointer (&priv->devices, g_hash_table_unref);
	g_clear_pointer (&priv->connection_uuids, g_hash_table_unref);

	G_OBJECT_CLASS (nm_checkpoint_parent_class)->dispose (object);
}

static void
nm_checkpoint_class_init (NMCheckpointClass *checkpoint_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (checkpoint_class);
	NMExportedObjectClass *exported_object_class = NM_EXPORTED_OBJECT_CLASS (checkpoint_class);

	exported_object_class->export_path = NM_EXPORT_PATH_NUMBERED (NM_DBUS_PATH"/Checkpoint");
	exported_object_class->export_on_construction = FALSE;

	object_class->dispose = dispose;
	object_class->get_property = get_property;

	obj_properties[PROP_DEVICES] =
	     g_param_spec_boxed (NM_CHECKPOINT_DEVICES, "", "",
	                         G_TYPE_STRV,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_CREATED] =
	    g_param_spec_int64 (NM_CHECKPOINT_CREATED, "", "",
	                        G_MININT64, G_MAXINT64, 0,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_ROLLBACK_TIMEOUT] =
	    g_param_spec_uint (NM_CHECKPOINT_ROLLBACK_TIMEOUT, "", "",
	                       0, G_MAXUINT32, 0,
	                       G_PARAM_READABLE |
	                       G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);

	nm_exported_object_class_add_interface (NM_EXPORTED_OBJECT_CLASS (checkpoint_class),
	                                        NMDBUS_TYPE_CHECKPOINT_SKELETON,
	                                        NULL);
}
