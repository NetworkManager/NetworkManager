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

/**
 * SECTION:nmt-utils
 * @short_description: Miscellaneous nmtui-specific utilities
 */

#include "config.h"

#include <string.h>

#include "nmt-utils.h"

/**
 * NmtSyncOp:
 *
 * A helper object used when synchronously waiting for an asynchronous
 * operation to complete.
 *
 * The caller first does:
 *
 * |[
 *     NmtSyncOp op;
 *
 *     nmt_sync_op_init (&op);
 * ]|
 *
 * It then passes the op as the user_data to the async operation's
 * callback function, and then calls nmt_sync_op_wait_boolean() or
 * nmt_sync_op_wait_pointer() to wait for the result.
 *
 * When the async callback is invoked, it should call
 * nmt_sync_op_complete_boolean() or nmt_sync_op_complete_pointer() to
 * return a result or an error to the caller. 
 *
 * There is no free/clear function; any memory that needs to be freed
 * will have been returned to the caller from
 * nmt_sync_op_wait_boolean() or nmt_sync_op_wait_pointer(), so there
 * is nothing left that needs to be freed.
 */

typedef struct {
	gpointer result;
	GError *error;
	gpointer complete;
} NmtSyncOpReal;

/**
 * nmt_sync_op_init:
 * @op: pointer to a stack-allocated #NmtSyncOp
 *
 * Initializes @op before use.
 */
void
nmt_sync_op_init (NmtSyncOp *op)
{
	memset (op, 0, sizeof (*op));
}

/**
 * nmt_sync_op_wait_boolean:
 * @op: the #NmtSyncOp
 * @error: return location for a #GError
 *
 * This runs the main loop until @op's operation returns, and then
 * returns the result or error.
 *
 * Returns: the result of the operation.
 */
gboolean
nmt_sync_op_wait_boolean (NmtSyncOp  *op,
                          GError    **error)
{
	return GPOINTER_TO_UINT (nmt_sync_op_wait_pointer (op, error));
}

/**
 * nmt_sync_op_complete_boolean:
 * @op: the #NmtSyncOp
 * @result: the result of the operation
 * @error: (allow-none): the error, or %NULL
 *
 * Completes @op and returns @result and/or @error to the caller.
 */
void
nmt_sync_op_complete_boolean (NmtSyncOp  *op,
                              gboolean    result,
                              GError     *error)
{
	nmt_sync_op_complete_pointer (op, GUINT_TO_POINTER (result), error);
}

/**
 * nmt_sync_op_wait_pointer:
 * @op: the #NmtSyncOp
 * @error: return location for a #GError
 *
 * This runs the main loop until @op's operation returns, and then
 * returns the result or error.
 *
 * Returns: the result of the operation.
 */
gpointer
nmt_sync_op_wait_pointer (NmtSyncOp  *op,
                          GError    **error)
{
	NmtSyncOpReal *real = (NmtSyncOpReal *)op;

	while (!real->complete)
		g_main_context_iteration (NULL, TRUE);

	if (real->error)
		g_propagate_error (error, real->error);
	return real->result;
}

/**
 * nmt_sync_op_complete_pointer:
 * @op: the #NmtSyncOp
 * @result: the result of the operation
 * @error: (allow-none): the error, or %NULL
 *
 * Completes @op and returns @result and/or @error to the caller.
 */
void
nmt_sync_op_complete_pointer (NmtSyncOp  *op,
                              gpointer    result,
                              GError     *error)
{
	NmtSyncOpReal *real = (NmtSyncOpReal *)op;

	real->result = result;
	real->error = error ? g_error_copy (error) : NULL;
	real->complete = GUINT_TO_POINTER (TRUE);
}
