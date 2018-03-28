/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager
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

#ifndef __NM_CHECKPOINT_MANAGER_H__
#define __NM_CHECKPOINT_MANAGER_H__

#include "nm-dbus-interface.h"

#include "nm-checkpoint.h"

typedef struct _NMCheckpointManager NMCheckpointManager;

NMCheckpointManager *nm_checkpoint_manager_new (NMManager *manager, GParamSpec *spec);

void nm_checkpoint_manager_free (NMCheckpointManager *self);

NMCheckpoint *nm_checkpoint_manager_lookup_by_path (NMCheckpointManager *self,
                                                    const char *path,
                                                    GError **error);

NMCheckpoint *nm_checkpoint_manager_create (NMCheckpointManager *self,
                                            const char *const*device_names,
                                            guint32 rollback_timeout,
                                            NMCheckpointCreateFlags flags,
                                            GError **error);

void nm_checkpoint_manager_destroy_all (NMCheckpointManager *self);

gboolean nm_checkpoint_manager_destroy (NMCheckpointManager *self,
                                        const char *path,
                                        GError **error);
gboolean nm_checkpoint_manager_rollback (NMCheckpointManager *self,
                                         const char *path,
                                         GVariant **results,
                                         GError **error);

gboolean nm_checkpoint_manager_adjust_rollback_timeout (NMCheckpointManager *self,
                                                        const char *path,
                                                        guint32 add_timeout,
                                                        GError **error);

const char **nm_checkpoint_manager_get_checkpoint_paths (NMCheckpointManager *self,
                                                         guint *out_length);

#endif /* __NM_CHECKPOINT_MANAGER_H__ */
