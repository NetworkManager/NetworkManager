// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

#ifndef NMT_SLAVE_LIST_H
#define NMT_SLAVE_LIST_H

#include "nmt-edit-connection-list.h"
#include "nmtui-edit.h"

#define NMT_TYPE_SLAVE_LIST            (nmt_slave_list_get_type ())
#define NMT_SLAVE_LIST(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMT_TYPE_SLAVE_LIST, NmtSlaveList))
#define NMT_SLAVE_LIST_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMT_TYPE_SLAVE_LIST, NmtSlaveListClass))
#define NMT_IS_SLAVE_LIST(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMT_TYPE_SLAVE_LIST))
#define NMT_IS_SLAVE_LIST_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMT_TYPE_SLAVE_LIST))
#define NMT_SLAVE_LIST_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMT_TYPE_SLAVE_LIST, NmtSlaveListClass))

typedef struct {
	NmtEditConnectionList parent;

} NmtSlaveList;

typedef struct {
	NmtEditConnectionListClass parent;

} NmtSlaveListClass;

GType nmt_slave_list_get_type (void);

NmtNewtWidget *nmt_slave_list_new (NMConnection               *master,
                                   NmtAddConnectionTypeFilter  type_filter,
                                   gpointer                    type_filter_data);

#endif /* NMT_SLAVE_LIST_H */
