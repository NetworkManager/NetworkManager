/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright 2013 Red Hat, Inc.
 */

#ifndef NMT_UTILS_H
#define NMT_UTILS_H

#include "nm-glib.h"

G_BEGIN_DECLS

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

G_END_DECLS

#endif /* NMT_UTILS_H */
