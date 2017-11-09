/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
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

#ifndef __NM_CHECKPOINT_H__
#define __NM_CHECKPOINT_H__

#if !defined (__NETWORKMANAGER_H_INSIDE__) && !defined (NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-object.h"

G_BEGIN_DECLS

#define NM_TYPE_CHECKPOINT            (nm_checkpoint_get_type ())
#define NM_CHECKPOINT(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_CHECKPOINT, NMCheckpoint))
#define NM_CHECKPOINT_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_CHECKPOINT, NMCheckpointClass))
#define NM_IS_CHECKPOINT(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_CHECKPOINT))
#define NM_IS_CHECKPOINT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_CHECKPOINT))
#define NM_CHECKPOINT_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_CHECKPOINT, NMCheckpointClass))

#define NM_CHECKPOINT_DEVICES          "devices"
#define NM_CHECKPOINT_CREATED          "created"
#define NM_CHECKPOINT_ROLLBACK_TIMEOUT "rollback-timeout"

/**
 * NMCheckpoint:
 */
typedef struct _NMCheckpointClass NMCheckpointClass;

GType nm_checkpoint_get_type (void);

NM_AVAILABLE_IN_1_12
const GPtrArray *nm_checkpoint_get_devices (NMCheckpoint *checkpoint);
NM_AVAILABLE_IN_1_12
gint64 nm_checkpoint_get_created (NMCheckpoint *checkpoint);
NM_AVAILABLE_IN_1_12
guint32 nm_checkpoint_get_rollback_timeout (NMCheckpoint *checkpoint);

G_END_DECLS

#endif /* __NM_CHECKPOINT_H__ */
