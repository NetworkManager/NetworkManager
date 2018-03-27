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

#include "nm-checkpoint-manager.h"

#include "nm-checkpoint.h"
#include "nm-connection.h"
#include "nm-core-utils.h"
#include "devices/nm-device.h"
#include "nm-manager.h"
#include "nm-utils.h"
#include "nm-utils/c-list.h"

/*****************************************************************************/

struct _NMCheckpointManager {
	NMManager *_manager;
	GParamSpec *property_spec;
	GHashTable *checkpoints;
	CList checkpoints_lst_head;
	guint rollback_timeout_id;
};

#define GET_MANAGER(self) \
	({ \
		typeof (self) _self = (self); \
		\
		_nm_unused NMCheckpointManager *_self2 = _self; \
		\
		nm_assert (_self); \
		nm_assert (NM_IS_MANAGER (_self->_manager)); \
		_self->_manager; \
	})

/*****************************************************************************/

#define _NMLOG_DOMAIN      LOGD_CORE
#define _NMLOG(level, ...) __NMLOG_DEFAULT (level, _NMLOG_DOMAIN, "checkpoint", __VA_ARGS__)

/*****************************************************************************/

static void update_rollback_timeout (NMCheckpointManager *self);

static void
notify_checkpoints (NMCheckpointManager *self) {
	g_object_notify_by_pspec ((GObject *) GET_MANAGER (self),
	                          self->property_spec);
}

static void
item_destroy (gpointer data)
{
	NMCheckpoint *checkpoint = data;

	c_list_unlink (&checkpoint->checkpoints_lst);
	nm_dbus_object_unexport (NM_DBUS_OBJECT (checkpoint));
	g_object_unref (checkpoint);
}

static gboolean
rollback_timeout_cb (NMCheckpointManager *self)
{
	NMCheckpoint *checkpoint, *checkpoint_safe;
	GVariant *result;
	gint64 ts, now;
	const char *path;
	gboolean removed = FALSE;

	now = nm_utils_get_monotonic_timestamp_ms ();

	c_list_for_each_entry_safe (checkpoint, checkpoint_safe, &self->checkpoints_lst_head, checkpoints_lst) {
		ts = nm_checkpoint_get_rollback_ts (checkpoint);
		if (ts && ts <= now) {
			result = nm_checkpoint_rollback (checkpoint);
			if (result)
				g_variant_unref (result);
			path = nm_dbus_object_get_path (NM_DBUS_OBJECT (checkpoint));
			if (!g_hash_table_remove (self->checkpoints, path))
				nm_assert_not_reached();
			removed = TRUE;
		}
	}

	self->rollback_timeout_id = 0;
	update_rollback_timeout (self);

	if (removed)
		notify_checkpoints (self);

	return G_SOURCE_REMOVE;
}

static void
update_rollback_timeout (NMCheckpointManager *self)
{
	NMCheckpoint *checkpoint;
	gint64 ts, delta, next = G_MAXINT64;

	c_list_for_each_entry (checkpoint, &self->checkpoints_lst_head, checkpoints_lst) {
		ts = nm_checkpoint_get_rollback_ts (checkpoint);
		if (ts && ts < next)
			next = ts;
	}

	nm_clear_g_source (&self->rollback_timeout_id);

	if (next != G_MAXINT64) {
		delta = MAX (next - nm_utils_get_monotonic_timestamp_ms (), 0);
		self->rollback_timeout_id = g_timeout_add (delta,
		                                           (GSourceFunc) rollback_timeout_cb,
		                                           self);
		_LOGT ("update timeout: next check in %" G_GINT64_FORMAT " ms", delta);
	}
}

static NMCheckpoint *
find_checkpoint_for_device (NMCheckpointManager *self, NMDevice *device)
{
	NMCheckpoint *checkpoint;

	c_list_for_each_entry (checkpoint, &self->checkpoints_lst_head, checkpoints_lst) {
		if (nm_checkpoint_includes_device (checkpoint, device))
			return checkpoint;
	}

	return NULL;
}

NMCheckpoint *
nm_checkpoint_manager_create (NMCheckpointManager *self,
                              const char *const *device_paths,
                              guint32 rollback_timeout,
                              NMCheckpointCreateFlags flags,
                              GError **error)
{
	NMManager *manager;
	NMCheckpoint *checkpoint;
	const char *const *dev_paths;
	gs_unref_ptrarray GPtrArray *devices = NULL;
	NMDevice *device;
	const char *path;
	gs_free const char **device_paths_free = NULL;
	guint i;

	g_return_val_if_fail (self, FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);
	manager = GET_MANAGER (self);

	if (!device_paths || !device_paths[0]) {
		const char *device_path;
		const CList *tmp_lst;
		GPtrArray *paths;

		paths = g_ptr_array_new ();
		nm_manager_for_each_device (manager, device, tmp_lst) {
			if (!nm_device_is_real (device))
				continue;
			device_path = nm_dbus_object_get_path (NM_DBUS_OBJECT (device));
			if (device_path)
				g_ptr_array_add (paths, (gpointer) device_path);
		}
		g_ptr_array_add (paths, NULL);
		device_paths_free = (const char **) g_ptr_array_free (paths, FALSE);
		device_paths = (const char *const *) device_paths_free;
	} else if (NM_FLAGS_HAS (flags, NM_CHECKPOINT_CREATE_FLAG_DISCONNECT_NEW_DEVICES)) {
		g_set_error_literal (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_INVALID_ARGUMENTS,
		                     "the DISCONNECT_NEW_DEVICES flag can only be used with an empty device list");
		return NULL;
	}

	devices = g_ptr_array_new ();
	for (dev_paths = device_paths; *dev_paths; dev_paths++) {
		device = nm_manager_get_device_by_path (manager, *dev_paths);
		if (!device) {
			g_set_error (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_UNKNOWN_DEVICE,
			             "device %s does not exist", *dev_paths);
			return NULL;
		}
		g_ptr_array_add (devices, device);
	}

	if (!NM_FLAGS_HAS (flags, NM_CHECKPOINT_CREATE_FLAG_DESTROY_ALL)) {
		for (i = 0; i < devices->len; i++) {
			device = devices->pdata[i];
			checkpoint = find_checkpoint_for_device (self, device);
			if (checkpoint) {
				g_set_error (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_INVALID_ARGUMENTS,
				             "device '%s' is already included in checkpoint %s",
				             nm_device_get_iface (device),
				             nm_dbus_object_get_path (NM_DBUS_OBJECT (checkpoint)));
				return NULL;
			}
		}
	}

	checkpoint = nm_checkpoint_new (manager, devices, rollback_timeout, flags, error);
	if (!checkpoint)
		return NULL;

	if (NM_FLAGS_HAS (flags, NM_CHECKPOINT_CREATE_FLAG_DESTROY_ALL))
		g_hash_table_remove_all (self->checkpoints);

	path = nm_dbus_object_export (NM_DBUS_OBJECT (checkpoint));

	c_list_link_tail (&self->checkpoints_lst_head, &checkpoint->checkpoints_lst);

	if (!g_hash_table_insert (self->checkpoints, (gpointer) path, checkpoint))
		g_return_val_if_reached (NULL);

	notify_checkpoints (self);
	update_rollback_timeout (self);

	return checkpoint;
}

gboolean
nm_checkpoint_manager_destroy_all (NMCheckpointManager *self,
                                   GError **error)
{
	g_return_val_if_fail (self, FALSE);

	g_hash_table_remove_all (self->checkpoints);
	notify_checkpoints (self);

	return TRUE;
}

gboolean
nm_checkpoint_manager_destroy (NMCheckpointManager *self,
                               const char *path,
                               GError **error)
{
	gboolean ret;

	g_return_val_if_fail (self, FALSE);
	g_return_val_if_fail (path && path[0] == '/', FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);

	if (!nm_streq (path, "/")) {
		ret = g_hash_table_remove (self->checkpoints, path);
		if (ret) {
			notify_checkpoints (self);
		} else {
			g_set_error (error,
			             NM_MANAGER_ERROR,
			             NM_MANAGER_ERROR_INVALID_ARGUMENTS,
			             "checkpoint %s does not exist", path);
		}
		return ret;
	} else
		return nm_checkpoint_manager_destroy_all (self, error);
}

gboolean
nm_checkpoint_manager_rollback (NMCheckpointManager *self,
                                const char *path,
                                GVariant **results,
                                GError **error)
{
	NMCheckpoint *checkpoint;

	g_return_val_if_fail (self, FALSE);
	g_return_val_if_fail (path && path[0] == '/', FALSE);
	g_return_val_if_fail (results, FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);

	checkpoint = g_hash_table_lookup (self->checkpoints, path);
	if (!checkpoint) {
		g_set_error (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_FAILED,
		             "checkpoint %s does not exist", path);
		return FALSE;
	}

	*results = nm_checkpoint_rollback (checkpoint);
	g_hash_table_remove (self->checkpoints, path);
	notify_checkpoints (self);

	return TRUE;
}

char **
nm_checkpoint_manager_get_checkpoint_paths (NMCheckpointManager *self)
{
	NMCheckpoint *checkpoint;
	char **strv;
	guint num, i = 0;

	num = g_hash_table_size (self->checkpoints);
	if (!num) {
		nm_assert (c_list_is_empty (&self->checkpoints_lst_head));
		return NULL;
	}

	strv = g_new (char *, num + 1);
	c_list_for_each_entry (checkpoint, &self->checkpoints_lst_head, checkpoints_lst)
		strv[i++] = g_strdup (nm_dbus_object_get_path (NM_DBUS_OBJECT (checkpoint)));
	nm_assert (i == num);
	strv[i] = NULL;

	return strv;
}

/*****************************************************************************/

NMCheckpointManager *
nm_checkpoint_manager_new (NMManager *manager, GParamSpec *spec)
{
	NMCheckpointManager *self;

	g_return_val_if_fail (NM_IS_MANAGER (manager), FALSE);

	self = g_slice_new0 (NMCheckpointManager);

	/* the NMCheckpointManager instance is actually owned by NMManager.
	 * Thus, we cannot take a reference to it, and we also don't bother
	 * taking a weak-reference. Instead let GET_MANAGER() assert that
	 * self->_manager is alive -- which we always expect as the lifetime
	 * of NMManager shall surpass the lifetime of the NMCheckpointManager
	 * instance. */
	self->_manager = manager;
	self->checkpoints = g_hash_table_new_full (nm_str_hash, g_str_equal,
	                                           NULL, item_destroy);
	self->property_spec = spec;
	c_list_init (&self->checkpoints_lst_head);

	return self;
}

void
nm_checkpoint_manager_free (NMCheckpointManager *self)
{
	if (!self)
		return;

	nm_clear_g_source (&self->rollback_timeout_id);
	g_hash_table_destroy (self->checkpoints);

	g_slice_free (NMCheckpointManager, self);
}
