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
#include "c-list/src/c-list.h"

/*****************************************************************************/

struct _NMCheckpointManager {
	NMManager *_manager;
	GParamSpec *property_spec;
	CList checkpoints_lst_head;
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

static void
notify_checkpoints (NMCheckpointManager *self) {
	g_object_notify_by_pspec ((GObject *) GET_MANAGER (self),
	                          self->property_spec);
}

static void
destroy_checkpoint (NMCheckpointManager *self, NMCheckpoint *checkpoint, gboolean log_destroy)
{
	nm_assert (NM_IS_CHECKPOINT (checkpoint));
	nm_assert (nm_dbus_object_is_exported (NM_DBUS_OBJECT (checkpoint)));
	nm_assert (c_list_contains (&self->checkpoints_lst_head, &checkpoint->checkpoints_lst));

	nm_checkpoint_set_timeout_callback (checkpoint, NULL, NULL);

	c_list_unlink (&checkpoint->checkpoints_lst);

	if (log_destroy)
		nm_checkpoint_log_destroy (checkpoint);

	notify_checkpoints (self);

	nm_dbus_object_unexport (NM_DBUS_OBJECT (checkpoint));
	g_object_unref (checkpoint);
}

static GVariant *
rollback_checkpoint (NMCheckpointManager *self, NMCheckpoint *checkpoint)
{
	GVariant *result;
	const CList *iter;

	nm_assert (c_list_contains (&self->checkpoints_lst_head, &checkpoint->checkpoints_lst));

	/* we destroy first all overlapping checkpoints that are younger/newer. */
	for (iter = checkpoint->checkpoints_lst.next;
	     iter != &self->checkpoints_lst_head;
	     ) {
		NMCheckpoint *cp = c_list_entry (iter, NMCheckpoint, checkpoints_lst);

		iter = iter->next;
		if (nm_checkpoint_includes_devices_of (cp, checkpoint)) {
			/* the younger checkpoint has overlapping devices and gets obsoleted.
			 * Destroy it. */
			destroy_checkpoint (self, cp, TRUE);
		}
	}

	result = nm_checkpoint_rollback (checkpoint);
	destroy_checkpoint (self, checkpoint, FALSE);
	return result;
}

static void
rollback_timeout_cb (NMCheckpoint *checkpoint,
                     gpointer user_data)
{
	NMCheckpointManager *self = user_data;
	gs_unref_variant GVariant *result = NULL;

	result = rollback_checkpoint (self, checkpoint);
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

	g_return_val_if_fail (self, FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);
	manager = GET_MANAGER (self);

	devices = g_ptr_array_new ();

	if (!device_paths || !device_paths[0]) {
		const CList *tmp_lst;

		nm_manager_for_each_device (manager, device, tmp_lst) {
			/* FIXME: there is no strong reason to skip over unrealized devices.
			 *        Also, NMCheckpoint anticipates to handle them (in parts). */
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

	if (!devices->len) {
		g_set_error_literal (error,
		                     NM_MANAGER_ERROR,
		                     NM_MANAGER_ERROR_INVALID_ARGUMENTS,
		                     "no device available");
		return NULL;
	}

	if (NM_FLAGS_HAS (flags, NM_CHECKPOINT_CREATE_FLAG_DESTROY_ALL))
		nm_checkpoint_manager_destroy_all (self);
	else if (!NM_FLAGS_HAS (flags, NM_CHECKPOINT_CREATE_FLAG_ALLOW_OVERLAPPING)) {
		c_list_for_each_entry (checkpoint, &self->checkpoints_lst_head, checkpoints_lst) {
			device = nm_checkpoint_includes_devices (checkpoint, (NMDevice *const*) devices->pdata, devices->len);
			if (device) {
				g_set_error (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_INVALID_ARGUMENTS,
				             "device '%s' is already included in checkpoint %s",
				             nm_device_get_iface (device),
				             nm_dbus_object_get_path (NM_DBUS_OBJECT (checkpoint)));
				return NULL;
			}
		}
	}

	checkpoint = nm_checkpoint_new (manager, devices, rollback_timeout, flags);

	nm_dbus_object_export (NM_DBUS_OBJECT (checkpoint));

	nm_checkpoint_set_timeout_callback (checkpoint, rollback_timeout_cb, self);
	c_list_link_tail (&self->checkpoints_lst_head, &checkpoint->checkpoints_lst);
	notify_checkpoints (self);
	return checkpoint;
}

void
nm_checkpoint_manager_destroy_all (NMCheckpointManager *self)
{
	NMCheckpoint *checkpoint;

	g_return_if_fail (self);

	while ((checkpoint = c_list_first_entry (&self->checkpoints_lst_head, NMCheckpoint, checkpoints_lst)))
		destroy_checkpoint (self, checkpoint, TRUE);
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

	if (nm_streq (path, "/")) {
		nm_checkpoint_manager_destroy_all (self);
		return TRUE;
	}

	checkpoint = nm_checkpoint_manager_lookup_by_path (self, path, error);
	if (!checkpoint)
		return FALSE;

	destroy_checkpoint (self, checkpoint, TRUE);
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

	checkpoint = nm_checkpoint_manager_lookup_by_path (self, path, error);
	if (!checkpoint)
		return FALSE;

	*results = rollback_checkpoint (self, checkpoint);
	return TRUE;
}

NMCheckpoint *
nm_checkpoint_manager_lookup_by_path (NMCheckpointManager *self, const char *path, GError **error)
{
	NMCheckpoint *checkpoint;

	g_return_val_if_fail (self, NULL);

	checkpoint = nm_dbus_manager_lookup_object (nm_dbus_object_get_manager (NM_DBUS_OBJECT (GET_MANAGER (self))),
	                                            path);
	if (   !checkpoint
	    || !NM_IS_CHECKPOINT (checkpoint)) {
		g_set_error (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_INVALID_ARGUMENTS,
		             "checkpoint %s does not exist", path);
		return NULL;
	}

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

gboolean
nm_checkpoint_manager_adjust_rollback_timeout (NMCheckpointManager *self,
                                               const char *path,
                                               guint32 add_timeout,
                                               GError **error)
{
	NMCheckpoint *checkpoint;

	g_return_val_if_fail (self, FALSE);
	g_return_val_if_fail (path && path[0] == '/', FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);

	checkpoint = nm_checkpoint_manager_lookup_by_path (self, path, error);
	if (!checkpoint)
		return FALSE;

	nm_checkpoint_adjust_rollback_timeout (checkpoint, add_timeout);
	return TRUE;
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
	g_slice_free (NMCheckpointManager, self);
}
