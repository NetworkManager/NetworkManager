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

/*****************************************************************************/

static void
notify_checkpoints (NMCheckpointManager *self) {
	g_object_notify_by_pspec ((GObject *) GET_MANAGER (self),
	                          self->property_spec);
}

static void
destroy_checkpoint (NMCheckpointManager *self, NMCheckpoint *checkpoint)
{
	nm_assert (NM_IS_CHECKPOINT (checkpoint));
	nm_assert (nm_dbus_object_is_exported (NM_DBUS_OBJECT (checkpoint)));
	nm_assert (c_list_contains (&self->checkpoints_lst_head, &checkpoint->checkpoints_lst));

	c_list_unlink (&checkpoint->checkpoints_lst);

	notify_checkpoints (self);

	nm_dbus_object_unexport (NM_DBUS_OBJECT (checkpoint));
	g_object_unref (checkpoint);
}

static GVariant *
rollback_checkpoint (NMCheckpointManager *self, NMCheckpoint *checkpoint)
{
	GVariant *result;

	result = nm_checkpoint_rollback (checkpoint);
	destroy_checkpoint (self, checkpoint);
	return result;
}

static gboolean
rollback_timeout_cb (NMCheckpointManager *self)
{
	NMCheckpoint *checkpoint, *checkpoint_safe;
	gint64 ts, now;

	self->rollback_timeout_id = 0;

	now = nm_utils_get_monotonic_timestamp_ms ();

	c_list_for_each_entry_safe (checkpoint, checkpoint_safe, &self->checkpoints_lst_head, checkpoints_lst) {
		ts = nm_checkpoint_get_rollback_ts (checkpoint);
		if (ts && ts <= now) {
			gs_unref_variant GVariant *result = NULL;

			result = rollback_checkpoint (self, checkpoint);
		}
	}

	update_rollback_timeout (self);

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
	gs_unref_ptrarray GPtrArray *devices = NULL;
	NMDevice *device;
	guint i;

	g_return_val_if_fail (self, FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);
	manager = GET_MANAGER (self);

	devices = g_ptr_array_new ();

	if (!device_paths || !device_paths[0]) {
		const CList *tmp_lst;

		nm_manager_for_each_device (manager, device, tmp_lst) {
			if (!nm_device_is_real (device))
				continue;
			nm_assert (nm_dbus_object_get_path (NM_DBUS_OBJECT (device)));
			g_ptr_array_add (devices, device);
		}
	} else if (NM_FLAGS_HAS (flags, NM_CHECKPOINT_CREATE_FLAG_DISCONNECT_NEW_DEVICES)) {
		g_set_error_literal (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_INVALID_ARGUMENTS,
		                     "the DISCONNECT_NEW_DEVICES flag can only be used with an empty device list");
		return NULL;
	} else {
		for (; *device_paths; device_paths++) {
			device = nm_manager_get_device_by_path (manager, *device_paths);
			if (!device) {
				g_set_error (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_UNKNOWN_DEVICE,
				             "device %s does not exist", *device_paths);
				return NULL;
			}
			if (!nm_device_is_real (device)) {
				g_set_error (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_UNKNOWN_DEVICE,
				             "device %s is not realized", *device_paths);
				return NULL;
			}
			g_ptr_array_add (devices, device);
		}
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
		nm_checkpoint_manager_destroy_all (self);

	nm_dbus_object_export (NM_DBUS_OBJECT (checkpoint));

	c_list_link_tail (&self->checkpoints_lst_head, &checkpoint->checkpoints_lst);
	notify_checkpoints (self);
	update_rollback_timeout (self);
	return checkpoint;
}

void
nm_checkpoint_manager_destroy_all (NMCheckpointManager *self)
{
	NMCheckpoint *checkpoint;

	g_return_if_fail (self);

	while ((checkpoint = c_list_first_entry (&self->checkpoints_lst_head, NMCheckpoint, checkpoints_lst)))
		destroy_checkpoint (self, checkpoint);
}

gboolean
nm_checkpoint_manager_destroy (NMCheckpointManager *self,
                               const char *path,
                               GError **error)
{
	NMCheckpoint *checkpoint;

	g_return_val_if_fail (self, FALSE);
	g_return_val_if_fail (path && path[0] == '/', FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);

	if (!nm_streq (path, "/")) {
		nm_checkpoint_manager_destroy_all (self);
		return TRUE;
	}

	checkpoint = nm_checkpoint_manager_lookup_by_path (self, path);
	if (!checkpoint) {
		g_set_error (error,
		             NM_MANAGER_ERROR,
		             NM_MANAGER_ERROR_INVALID_ARGUMENTS,
		             "checkpoint %s does not exist", path);
		return FALSE;
	}

	destroy_checkpoint (self, checkpoint);
	return TRUE;
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

	checkpoint = nm_checkpoint_manager_lookup_by_path (self, path);
	if (!checkpoint) {
		g_set_error (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_FAILED,
		             "checkpoint %s does not exist", path);
		return FALSE;
	}

	*results = rollback_checkpoint (self, checkpoint);
	return TRUE;
}

NMCheckpoint *
nm_checkpoint_manager_lookup_by_path (NMCheckpointManager *self, const char *path)
{
	NMCheckpoint *checkpoint;

	g_return_val_if_fail (self, NULL);

	checkpoint = (NMCheckpoint *) nm_dbus_manager_lookup_object (nm_dbus_object_get_manager (NM_DBUS_OBJECT (GET_MANAGER (self))),
	                                                             path);
	if (   !checkpoint
	    || !NM_IS_CHECKPOINT (checkpoint))
		return NULL;

	nm_assert (c_list_contains (&self->checkpoints_lst_head, &checkpoint->checkpoints_lst));
	return checkpoint;
}

const char **
nm_checkpoint_manager_get_checkpoint_paths (NMCheckpointManager *self, guint *out_length)
{
	NMCheckpoint *checkpoint;
	const char **strv;
	guint num, i = 0;

	num = c_list_length (&self->checkpoints_lst_head);
	NM_SET_OUT (out_length, num);
	if (!num)
		return NULL;

	strv = g_new (const char *, num + 1);
	c_list_for_each_entry (checkpoint, &self->checkpoints_lst_head, checkpoints_lst)
		strv[i++] = nm_dbus_object_get_path (NM_DBUS_OBJECT (checkpoint));
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
	self->property_spec = spec;
	c_list_init (&self->checkpoints_lst_head);
	return self;
}

void
nm_checkpoint_manager_free (NMCheckpointManager *self)
{
	if (!self)
		return;

	nm_checkpoint_manager_destroy_all (self);
	nm_clear_g_source (&self->rollback_timeout_id);
	g_slice_free (NMCheckpointManager, self);
}
