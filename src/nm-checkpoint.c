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

#include "nm-active-connection.h"
#include "nm-act-request.h"
#include "nm-auth-subject.h"
#include "nm-core-utils.h"
#include "nm-dbus-interface.h"
#include "devices/nm-device.h"
#include "nm-manager.h"
#include "settings/nm-settings.h"
#include "settings/nm-settings-connection.h"
#include "nm-simple-connection.h"
#include "nm-utils.h"

/*****************************************************************************/

typedef struct {
	char *original_dev_path;
	char *original_dev_name;
	NMDeviceType dev_type;
	NMDevice *device;
	NMConnection *applied_connection;
	NMConnection *settings_connection;
	guint64 ac_version_id;
	NMDeviceState state;
	bool is_software:1;
	bool realized:1;
	bool activation_lifetime_bound_to_profile_visiblity:1;
	NMUnmanFlagOp unmanaged_explicit;
	NMActivationReason activation_reason;
	gulong dev_exported_change_id;
} DeviceCheckpoint;

NM_GOBJECT_PROPERTIES_DEFINE (NMCheckpoint,
	PROP_DEVICES,
	PROP_CREATED,
	PROP_ROLLBACK_TIMEOUT,
);

struct _NMCheckpointPrivate {
	/* properties */
	GHashTable *devices;
	GPtrArray *removed_devices;
	gint64 created_at_ms;
	guint32 rollback_timeout_s;
	guint timeout_id;
	/* private members */
	NMManager *manager;
	NMCheckpointCreateFlags flags;
	GHashTable *connection_uuids;
	gulong dev_removed_id;

	NMCheckpointTimeoutCallback timeout_cb;
	gpointer timeout_data;
};

struct _NMCheckpointClass {
	NMDBusObjectClass parent;
};

G_DEFINE_TYPE (NMCheckpoint, nm_checkpoint, NM_TYPE_DBUS_OBJECT)

#define NM_CHECKPOINT_GET_PRIVATE(self) _NM_GET_PRIVATE_PTR (self, NMCheckpoint, NM_IS_CHECKPOINT)

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

void
nm_checkpoint_log_destroy (NMCheckpoint *self)
{
	_LOGI ("destroy %s", nm_dbus_object_get_path (NM_DBUS_OBJECT (self)));
}

void
nm_checkpoint_set_timeout_callback (NMCheckpoint *self,
                                    NMCheckpointTimeoutCallback callback,
                                    gpointer user_data)
{
	NMCheckpointPrivate *priv = NM_CHECKPOINT_GET_PRIVATE (self);

	/* in glib world, we would have a GSignal for this. But as there
	 * is only one subscriber, it's simpler to just set and unset(!)
	 * the callback this way. */
	priv->timeout_cb = callback;
	priv->timeout_data = user_data;
}

NMDevice *
nm_checkpoint_includes_devices (NMCheckpoint *self, NMDevice *const*devices, guint n_devices)
{
	NMCheckpointPrivate *priv = NM_CHECKPOINT_GET_PRIVATE (self);
	guint i;

	for (i = 0; i < n_devices; i++) {
		if (g_hash_table_contains (priv->devices, devices[i]))
			return devices[i];
	}
	return NULL;
}

NMDevice *
nm_checkpoint_includes_devices_of (NMCheckpoint *self, NMCheckpoint *cp_for_devices)
{
	NMCheckpointPrivate *priv = NM_CHECKPOINT_GET_PRIVATE (self);
	NMCheckpointPrivate *priv2 = NM_CHECKPOINT_GET_PRIVATE (cp_for_devices);
	GHashTableIter iter;
	NMDevice *device;

	g_hash_table_iter_init (&iter, priv2->devices);
	while (g_hash_table_iter_next (&iter, (gpointer *) &device, NULL)) {
		if (g_hash_table_contains (priv->devices, device))
			return device;
	}
	return NULL;
}

static NMSettingsConnection *
find_settings_connection (NMCheckpoint *self,
                          DeviceCheckpoint *dev_checkpoint,
                          gboolean *need_update,
                          gboolean *need_activation)
{
	NMCheckpointPrivate *priv = NM_CHECKPOINT_GET_PRIVATE (self);
	NMActiveConnection *active;
	NMSettingsConnection *sett_conn;
	const char *uuid, *ac_uuid;
	const CList *tmp_clist;

	*need_activation = FALSE;
	*need_update = FALSE;

	uuid = nm_connection_get_uuid (dev_checkpoint->settings_connection);
	sett_conn = nm_settings_get_connection_by_uuid (nm_settings_get (), uuid);

	if (!sett_conn)
		return NULL;

	/* Now check if the connection changed, ... */
	if (!nm_connection_compare (dev_checkpoint->settings_connection,
	                            nm_settings_connection_get_connection (sett_conn),
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
		return sett_conn;
	}

	/* ... or if the connection was reactivated/reapplied */
	if (nm_active_connection_version_id_get (active) != dev_checkpoint->ac_version_id) {
		_LOGT ("rollback: active connection version id of %s changed", uuid);
		*need_activation = TRUE;
	}

	return sett_conn;
}

static gboolean
restore_and_activate_connection (NMCheckpoint *self,
                                 DeviceCheckpoint *dev_checkpoint)
{
	NMCheckpointPrivate *priv = NM_CHECKPOINT_GET_PRIVATE (self);
	NMSettingsConnection *connection;
	gs_unref_object NMAuthSubject *subject = NULL;
	GError *local_error = NULL;
	gboolean need_update, need_activation;

	connection = find_settings_connection (self,
	                                       dev_checkpoint,
	                                       &need_update,
	                                       &need_activation);
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
			return FALSE;
		}

		/* If the device is software, a brand new NMDevice may have been created */
		if (   dev_checkpoint->is_software
		    && !dev_checkpoint->device) {
			dev_checkpoint->device = nm_manager_get_device (priv->manager,
			                                                dev_checkpoint->original_dev_name,
			                                                dev_checkpoint->dev_type);
			nm_g_object_ref (dev_checkpoint->device);
		}
		need_activation = TRUE;
	}

	if (!dev_checkpoint->device) {
		_LOGD ("rollback: device cannot be restored");
		return FALSE;
	}

	if (need_activation) {
		_LOGD ("rollback: reactivating connection %s",
		       nm_settings_connection_get_uuid (connection));
		subject = nm_auth_subject_new_internal ();

		/* Disconnect the device if needed. This necessary because now
		 * the manager prevents the reactivation of the same connection by
		 * an internal subject. */
		if (   nm_device_get_state (dev_checkpoint->device) > NM_DEVICE_STATE_DISCONNECTED
		    && nm_device_get_state (dev_checkpoint->device) < NM_DEVICE_STATE_DEACTIVATING) {
			nm_device_state_changed (dev_checkpoint->device,
			                         NM_DEVICE_STATE_DEACTIVATING,
			                         NM_DEVICE_STATE_REASON_NEW_ACTIVATION);
		}

		if (!nm_manager_activate_connection (priv->manager,
		                                     connection,
		                                     dev_checkpoint->applied_connection,
		                                     NULL,
		                                     dev_checkpoint->device,
		                                     subject,
		                                     NM_ACTIVATION_TYPE_MANAGED,
		                                     dev_checkpoint->activation_reason,
		                                       dev_checkpoint->activation_lifetime_bound_to_profile_visiblity
		                                     ? NM_ACTIVATION_STATE_FLAG_LIFETIME_BOUND_TO_PROFILE_VISIBILITY
		                                     : NM_ACTIVATION_STATE_FLAG_NONE,
		                                     &local_error)) {
			_LOGW ("rollback: reactivation of connection %s/%s failed: %s",
			       nm_settings_connection_get_id (connection),
			       nm_settings_connection_get_uuid (connection),
			       local_error->message);
			g_clear_error (&local_error);
			return FALSE;
		}
	}
	return TRUE;
}

GVariant *
nm_checkpoint_rollback (NMCheckpoint *self)
{
	NMCheckpointPrivate *priv = NM_CHECKPOINT_GET_PRIVATE (self);
	DeviceCheckpoint *dev_checkpoint;
	GHashTableIter iter;
	NMDevice *device;
	GVariantBuilder builder;
	uint i;

	_LOGI ("rollback of %s", nm_dbus_object_get_path (NM_DBUS_OBJECT (self)));
	 g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{su}"));

	/* Start creating removed devices (if any and if possible) */
	if (priv->removed_devices) {
		for (i = 0; i < priv->removed_devices->len; i++) {
			guint32 result = NM_ROLLBACK_RESULT_OK;

			dev_checkpoint = priv->removed_devices->pdata[i];
			_LOGD ("rollback: restoring removed device %s (state %d, realized %d, explicitly unmanaged %d)",
			       dev_checkpoint->original_dev_name,
			       (int) dev_checkpoint->state,
			       dev_checkpoint->realized,
			       dev_checkpoint->unmanaged_explicit);

			if (dev_checkpoint->applied_connection) {
				if (!restore_and_activate_connection (self, dev_checkpoint))
					result = NM_ROLLBACK_RESULT_ERR_FAILED;
			}
			g_variant_builder_add (&builder, "{su}", dev_checkpoint->original_dev_path, result);
		}
	}

	/* Start rolling-back each device */
	g_hash_table_iter_init (&iter, priv->devices);
	while (g_hash_table_iter_next (&iter, (gpointer *) &device, (gpointer *) &dev_checkpoint)) {
		guint32 result = NM_ROLLBACK_RESULT_OK;

		_LOGD ("rollback: restoring device %s (state %d, realized %d, explicitly unmanaged %d)",
		       dev_checkpoint->original_dev_name,
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
				if (dev_checkpoint->is_software) {
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

activate:
		if (dev_checkpoint->applied_connection) {
			if (!restore_and_activate_connection (self, dev_checkpoint)) {
				result = NM_ROLLBACK_RESULT_ERR_FAILED;
				goto next_dev;
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
		const CList *tmp_lst;
		NMDeviceState state;

		nm_manager_for_each_device (priv->manager, device, tmp_lst) {
			if (g_hash_table_contains (priv->devices, device))
				continue;
			state = nm_device_get_state (device);
			if (   state > NM_DEVICE_STATE_DISCONNECTED
			    && state < NM_DEVICE_STATE_DEACTIVATING) {
				_LOGD ("rollback: disconnecting new device %s", nm_device_get_iface (device));
				nm_device_state_changed (device,
				                         NM_DEVICE_STATE_DEACTIVATING,
				                         NM_DEVICE_STATE_REASON_USER_REQUESTED);
			}
		}

	}

	return g_variant_new ("(a{su})", &builder);
}

static void
device_checkpoint_destroy (gpointer data)
{
	DeviceCheckpoint *dev_checkpoint = data;

	nm_clear_g_signal_handler (dev_checkpoint->device, &dev_checkpoint->dev_exported_change_id);
	g_clear_object (&dev_checkpoint->applied_connection);
	g_clear_object (&dev_checkpoint->settings_connection);
	g_clear_object (&dev_checkpoint->device);
	g_free (dev_checkpoint->original_dev_path);
	g_free (dev_checkpoint->original_dev_name);

	g_slice_free (DeviceCheckpoint, dev_checkpoint);
}

static void
_move_dev_to_removed_devices (NMDevice *device,
                              NMCheckpoint *checkpoint)
{
	NMCheckpointPrivate *priv = NM_CHECKPOINT_GET_PRIVATE (checkpoint);
	DeviceCheckpoint *dev_checkpoint;

	g_return_if_fail (device);

	dev_checkpoint = g_hash_table_lookup (priv->devices, device);
	if (!dev_checkpoint)
		return;

	g_hash_table_steal (priv->devices, dev_checkpoint->device);
	nm_clear_g_signal_handler (dev_checkpoint->device,
	                           &dev_checkpoint->dev_exported_change_id);
	g_clear_object (&dev_checkpoint->device);

	if (!priv->removed_devices)
		priv->removed_devices = g_ptr_array_new_with_free_func ((GDestroyNotify) device_checkpoint_destroy);
	g_ptr_array_add (priv->removed_devices, dev_checkpoint);

	_notify (checkpoint, PROP_DEVICES);
}

static void
_dev_exported_changed (NMDBusObject *obj,
                       NMCheckpoint *checkpoint)
{

	_move_dev_to_removed_devices (NM_DEVICE (obj), checkpoint);
}

static DeviceCheckpoint *
device_checkpoint_create (NMCheckpoint *checkpoint, NMDevice *device)
{
	DeviceCheckpoint *dev_checkpoint;
	NMConnection *applied_connection;
	NMSettingsConnection *settings_connection;
	const char *path;
	NMActRequest *act_request;

	nm_assert (NM_IS_DEVICE (device));
	nm_assert (nm_device_is_real (device));

	path = nm_dbus_object_get_path (NM_DBUS_OBJECT (device));

	dev_checkpoint = g_slice_new0 (DeviceCheckpoint);
	dev_checkpoint->device = g_object_ref (device);
	dev_checkpoint->original_dev_path = g_strdup (path);
	dev_checkpoint->original_dev_name = g_strdup (nm_device_get_iface (device));
	dev_checkpoint->dev_type = nm_device_get_device_type (device);
	dev_checkpoint->state = nm_device_get_state (device);
	dev_checkpoint->is_software = nm_device_is_software (device);
	dev_checkpoint->realized = nm_device_is_real (device);
	dev_checkpoint->dev_exported_change_id = g_signal_connect (device,
	                                                           NM_DBUS_OBJECT_EXPORTED_CHANGED,
	                                                           G_CALLBACK (_dev_exported_changed),
	                                                           checkpoint);

	if (nm_device_get_unmanaged_mask (device, NM_UNMANAGED_USER_EXPLICIT)) {
		dev_checkpoint->unmanaged_explicit = !!nm_device_get_unmanaged_flags (device,
		                                                                      NM_UNMANAGED_USER_EXPLICIT);
	} else
		dev_checkpoint->unmanaged_explicit = NM_UNMAN_FLAG_OP_FORGET;

	act_request = nm_device_get_act_request (device);
	if (act_request) {
		settings_connection = nm_act_request_get_settings_connection (act_request);
		applied_connection = nm_act_request_get_applied_connection (act_request);

		dev_checkpoint->applied_connection = nm_simple_connection_new_clone (applied_connection);
		dev_checkpoint->settings_connection = nm_simple_connection_new_clone (nm_settings_connection_get_connection (settings_connection));
		dev_checkpoint->ac_version_id = nm_active_connection_version_id_get (NM_ACTIVE_CONNECTION (act_request));
		dev_checkpoint->activation_reason = nm_active_connection_get_activation_reason (NM_ACTIVE_CONNECTION (act_request));
		dev_checkpoint->activation_lifetime_bound_to_profile_visiblity = NM_FLAGS_HAS (nm_active_connection_get_state_flags (NM_ACTIVE_CONNECTION (act_request)),
		                                                                               NM_ACTIVATION_STATE_FLAG_LIFETIME_BOUND_TO_PROFILE_VISIBILITY);
	}

	return dev_checkpoint;
}

static gboolean
_timeout_cb (gpointer user_data)
{
	NMCheckpoint *self = user_data;
	NMCheckpointPrivate *priv = NM_CHECKPOINT_GET_PRIVATE (self);

	priv->timeout_id = 0;

	if (priv->timeout_cb)
		priv->timeout_cb (self, priv->timeout_data);

	/* beware, @self likely got destroyed! */
	return G_SOURCE_REMOVE;
}

void
nm_checkpoint_adjust_rollback_timeout (NMCheckpoint *self, guint32 add_timeout)
{
	guint32 rollback_timeout_s;
	gint64 now_ms, add_timeout_ms, rollback_timeout_ms;

	NMCheckpointPrivate *priv = NM_CHECKPOINT_GET_PRIVATE (self);

	nm_clear_g_source (&priv->timeout_id);

	if (add_timeout == 0)
		rollback_timeout_s = 0;
	else {
		now_ms = nm_utils_get_monotonic_timestamp_ms ();
		add_timeout_ms = ((gint64) add_timeout) * 1000;
		rollback_timeout_ms = (now_ms - priv->created_at_ms) + add_timeout_ms;

		/* round to nearest integer second. Since NM_CHECKPOINT_ROLLBACK_TIMEOUT is
		 * in units seconds, it will be able to exactly express the timeout. */
		rollback_timeout_s = NM_MIN ((rollback_timeout_ms + 500) / 1000, (gint64) G_MAXUINT32);

		/* we expect the timeout to be positive, because add_timeout_ms is positive.
		 * We cannot accept a zero, because it means "infinity". */
		nm_assert (rollback_timeout_s > 0);

		priv->timeout_id = g_timeout_add (NM_MIN (add_timeout_ms, (gint64) G_MAXUINT32),
		                                  _timeout_cb,
		                                  self);
	}

	if (rollback_timeout_s != priv->rollback_timeout_s) {
		priv->rollback_timeout_s = rollback_timeout_s;
		_notify (self, PROP_ROLLBACK_TIMEOUT);
	}
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMCheckpoint *self = NM_CHECKPOINT (object);
	NMCheckpointPrivate *priv = NM_CHECKPOINT_GET_PRIVATE (self);

	switch (prop_id) {
	case PROP_DEVICES:
		nm_dbus_utils_g_value_set_object_path_from_hash (value,
		                                                 priv->devices,
		                                                 FALSE);
		break;
	case PROP_CREATED:
		g_value_set_int64 (value,
		                   nm_utils_monotonic_timestamp_as_boottime (priv->created_at_ms,
		                                                             NM_UTILS_NS_PER_MSEC));
		break;
	case PROP_ROLLBACK_TIMEOUT:
		g_value_set_uint (value, priv->rollback_timeout_s);
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
	NMCheckpointPrivate *priv;

	priv = G_TYPE_INSTANCE_GET_PRIVATE (self, NM_TYPE_CHECKPOINT, NMCheckpointPrivate);

	self->_priv = priv;

	c_list_init (&self->checkpoints_lst);

	priv->devices = g_hash_table_new_full (nm_direct_hash, NULL,
	                                       NULL, device_checkpoint_destroy);
}

static void
_device_removed (NMManager *manager, NMDevice *device, gpointer user_data)
{
	_move_dev_to_removed_devices (device, NM_CHECKPOINT (user_data));
}

NMCheckpoint *
nm_checkpoint_new (NMManager *manager, GPtrArray *devices, guint32 rollback_timeout_s,
                   NMCheckpointCreateFlags flags)
{
	NMCheckpoint *self;
	NMCheckpointPrivate *priv;
	NMSettingsConnection *const *con;
	gint64 rollback_timeout_ms;
	guint i;

	g_return_val_if_fail (manager, NULL);
	g_return_val_if_fail (devices, NULL);
	g_return_val_if_fail (devices->len > 0, NULL);

	self = g_object_new (NM_TYPE_CHECKPOINT, NULL);

	priv = NM_CHECKPOINT_GET_PRIVATE (self);
	priv->manager = g_object_ref (manager);
	priv->rollback_timeout_s = rollback_timeout_s;
	priv->created_at_ms = nm_utils_get_monotonic_timestamp_ms ();
	priv->flags = flags;

	if (rollback_timeout_s != 0) {
		rollback_timeout_ms = ((gint64) rollback_timeout_s) * 1000;
		priv->timeout_id = g_timeout_add (NM_MIN (rollback_timeout_ms, (gint64) G_MAXUINT32),
		                                  _timeout_cb,
		                                  self);
	}

	if (NM_FLAGS_HAS (flags, NM_CHECKPOINT_CREATE_FLAG_DELETE_NEW_CONNECTIONS)) {
		priv->connection_uuids = g_hash_table_new_full (nm_str_hash, g_str_equal, g_free, NULL);
		for (con = nm_settings_get_connections (nm_settings_get (), NULL); *con; con++) {
			g_hash_table_add (priv->connection_uuids,
			                  g_strdup (nm_settings_connection_get_uuid (*con)));
		}
	}

	for (i = 0; i < devices->len; i++) {
		NMDevice *device = devices->pdata[i];

		/* As long as the check point instance exists, it will keep a reference
		 * to the device also if the device gets removed (by rmmod or by deleting
		 * a connection profile for a software device). */
		g_hash_table_insert (priv->devices,
		                     device,
		                     device_checkpoint_create (self, device));
	}

	priv->dev_removed_id = g_signal_connect (priv->manager,
	                                         NM_MANAGER_DEVICE_REMOVED,
	                                         G_CALLBACK (_device_removed),
	                                         self);
	return self;
}

static void
dispose (GObject *object)
{
	NMCheckpoint *self = NM_CHECKPOINT (object);
	NMCheckpointPrivate *priv = NM_CHECKPOINT_GET_PRIVATE (self);

	nm_assert (c_list_is_empty (&self->checkpoints_lst));

	g_clear_pointer (&priv->devices, g_hash_table_unref);
	g_clear_pointer (&priv->connection_uuids, g_hash_table_unref);
	nm_clear_pointer (&priv->removed_devices, g_ptr_array_unref);

	nm_clear_g_signal_handler (priv->manager, &priv->dev_removed_id);
	g_clear_object (&priv->manager);

	nm_clear_g_source (&priv->timeout_id);

	G_OBJECT_CLASS (nm_checkpoint_parent_class)->dispose (object);
}

static const NMDBusInterfaceInfoExtended interface_info_checkpoint = {
	.parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT (
		NM_DBUS_INTERFACE_CHECKPOINT,
		.signals = NM_DEFINE_GDBUS_SIGNAL_INFOS (
			&nm_signal_info_property_changed_legacy,
		),
		.properties = NM_DEFINE_GDBUS_PROPERTY_INFOS (
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("Devices",         "ao", NM_CHECKPOINT_DEVICES),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("Created",         "x",  NM_CHECKPOINT_CREATED),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("RollbackTimeout", "u",  NM_CHECKPOINT_ROLLBACK_TIMEOUT),
		),
	),
	.legacy_property_changed = TRUE,
};

static void
nm_checkpoint_class_init (NMCheckpointClass *checkpoint_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (checkpoint_class);
	NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS (checkpoint_class);

	g_type_class_add_private (object_class, sizeof (NMCheckpointPrivate));

	dbus_object_class->export_path = NM_DBUS_EXPORT_PATH_NUMBERED (NM_DBUS_PATH"/Checkpoint");
	dbus_object_class->interface_infos = NM_DBUS_INTERFACE_INFOS (&interface_info_checkpoint);

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
}
