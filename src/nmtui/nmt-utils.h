/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

#ifndef NMT_UTILS_H
#define NMT_UTILS_H

#include "libnmt-newt/nmt-newt-types.h"

typedef struct {
    gpointer private[3];
} NmtSyncOp;

void nmt_sync_op_init(NmtSyncOp *op);

gboolean nmt_sync_op_wait_boolean(NmtSyncOp *op, GError **error);
void     nmt_sync_op_complete_boolean(NmtSyncOp *op, gboolean result, GError *error);

gpointer nmt_sync_op_wait_pointer(NmtSyncOp *op, GError **error);
void     nmt_sync_op_complete_pointer(NmtSyncOp *op, gpointer result, GError *error);

gboolean nmt_utils_filter_match(const char *haystack, const char *needle);

#define NMT_SEARCH_ENTRY_WIDTH 34

/**
 * NmtSearch:
 *
 * Vim-style '/' search glue shared by the connection lists. The caller builds
 * the @label and @entry into its own layout and hands them over; NmtSearch
 * wires '/' to reveal the entry, Enter to confirm, Esc to clear, keeps the
 * status label in sync, and pins the form width so the list does not jump.
 *
 * @apply is invoked with the current text whenever the filter changes; @count
 * returns the live match count for the label.
 */
typedef struct _NmtSearch NmtSearch;

typedef void (*NmtSearchApplyFunc)(gpointer user_data, const char *text);
typedef int (*NmtSearchCountFunc)(gpointer user_data);

NmtSearch *nmt_search_new(NmtNewtEntry      *entry,
                          NmtNewtLabel      *label,
                          NmtNewtWidget     *focus,
                          NmtSearchApplyFunc apply,
                          NmtSearchCountFunc count,
                          gpointer           user_data);

void nmt_search_bind_form(NmtSearch *search, NmtNewtForm *form);
void nmt_search_update_label(NmtSearch *search);

GVariant *
nmt_sync_get_secrets(NMRemoteConnection *connection, const char *setting_name, GError **error);

#endif /* NMT_UTILS_H */
