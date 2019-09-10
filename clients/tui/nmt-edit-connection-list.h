// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2013 Red Hat, Inc.
 */

#ifndef NMT_EDIT_CONNECTION_LIST_H
#define NMT_EDIT_CONNECTION_LIST_H

#include "nmt-newt.h"

#define NMT_TYPE_EDIT_CONNECTION_LIST            (nmt_edit_connection_list_get_type ())
#define NMT_EDIT_CONNECTION_LIST(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMT_TYPE_EDIT_CONNECTION_LIST, NmtEditConnectionList))
#define NMT_EDIT_CONNECTION_LIST_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMT_TYPE_EDIT_CONNECTION_LIST, NmtEditConnectionListClass))
#define NMT_IS_EDIT_CONNECTION_LIST(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMT_TYPE_EDIT_CONNECTION_LIST))
#define NMT_IS_EDIT_CONNECTION_LIST_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMT_TYPE_EDIT_CONNECTION_LIST))
#define NMT_EDIT_CONNECTION_LIST_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMT_TYPE_EDIT_CONNECTION_LIST, NmtEditConnectionListClass))

typedef struct {
	NmtNewtGrid parent;

} NmtEditConnectionList;

typedef struct {
	NmtNewtGridClass parent;

	/* signals */
	void (*add_connection)    (NmtEditConnectionList *list);
	void (*edit_connection)   (NmtEditConnectionList *list,
	                           NMConnection          *connection);
	void (*remove_connection) (NmtEditConnectionList *list,
	                           NMRemoteConnection    *connection);
} NmtEditConnectionListClass;

GType nmt_edit_connection_list_get_type (void);

typedef gboolean (*NmtEditConnectionListFilter) (NmtEditConnectionList *list,
                                                 NMConnection          *connection,
                                                 gpointer               user_data);

void nmt_edit_connection_list_recommit (NmtEditConnectionList *list);

#endif /* NMT_EDIT_CONNECTION_LIST_H */
