// SPDX-License-Identifier: GPL-2.0+
/*
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
