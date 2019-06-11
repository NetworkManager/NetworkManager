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

#ifndef __NETWORKMANAGER_CHECKPOINT_H__
#define __NETWORKMANAGER_CHECKPOINT_H__

#include "nm-dbus-object.h"
#include "nm-dbus-interface.h"

#define NM_TYPE_CHECKPOINT            (nm_checkpoint_get_type ())
#define NM_CHECKPOINT(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_CHECKPOINT, NMCheckpoint))
#define NM_CHECKPOINT_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_CHECKPOINT, NMCheckpointClass))
#define NM_IS_CHECKPOINT(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_CHECKPOINT))
#define NM_IS_CHECKPOINT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_CHECKPOINT))
#define NM_CHECKPOINT_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_CHECKPOINT, NMCheckpointClass))

#define NM_CHECKPOINT_DEVICES "devices"
#define NM_CHECKPOINT_CREATED "created"
#define NM_CHECKPOINT_ROLLBACK_TIMEOUT "rollback-timeout"

typedef struct _NMCheckpointPrivate NMCheckpointPrivate;

typedef struct {
	NMDBusObject parent;
	NMCheckpointPrivate *_priv;
	CList checkpoints_lst;
} NMCheckpoint;

typedef struct _NMCheckpointClass NMCheckpointClass;

GType nm_checkpoint_get_type (void);

NMCheckpoint *nm_checkpoint_new (NMManager *manager, GPtrArray *devices, guint32 rollback_timeout,
                                 NMCheckpointCreateFlags flags);

typedef void (*NMCheckpointTimeoutCallback) (NMCheckpoint *self,
                                             gpointer user_data);

void nm_checkpoint_log_destroy (NMCheckpoint *self);

void nm_checkpoint_set_timeout_callback (NMCheckpoint *self,
                                         NMCheckpointTimeoutCallback callback,
                                         gpointer user_data);

GVariant *nm_checkpoint_rollback (NMCheckpoint *self);

void nm_checkpoint_adjust_rollback_timeout (NMCheckpoint *self, guint32 add_timeout);

NMDevice *nm_checkpoint_includes_devices (NMCheckpoint *self, NMDevice *const*devices, guint n_devices);
NMDevice *nm_checkpoint_includes_devices_of (NMCheckpoint *self, NMCheckpoint *cp_for_devices);

#endif /* __NETWORKMANAGER_CHECKPOINT_H__ */
