// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

#ifndef NMT_UTILS_H
#define NMT_UTILS_H

typedef struct {
	gpointer private[3];
} NmtSyncOp;

void      nmt_sync_op_init             (NmtSyncOp  *op);

gboolean  nmt_sync_op_wait_boolean     (NmtSyncOp  *op,
                                        GError    **error);
void      nmt_sync_op_complete_boolean (NmtSyncOp  *op,
                                        gboolean    result,
                                        GError     *error);

gpointer  nmt_sync_op_wait_pointer     (NmtSyncOp  *op,
                                        GError    **error);
void      nmt_sync_op_complete_pointer (NmtSyncOp  *op,
                                        gpointer    result,
                                        GError     *error);

#endif /* NMT_UTILS_H */
