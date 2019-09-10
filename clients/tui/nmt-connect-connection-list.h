// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2013 Red Hat, Inc.
 */

#ifndef NMT_CONNECT_CONNECTION_LIST_H
#define NMT_CONNECT_CONNECTION_LIST_H

#include "nmt-newt.h"

#define NMT_TYPE_CONNECT_CONNECTION_LIST            (nmt_connect_connection_list_get_type ())
#define NMT_CONNECT_CONNECTION_LIST(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMT_TYPE_CONNECT_CONNECTION_LIST, NmtConnectConnectionList))
#define NMT_CONNECT_CONNECTION_LIST_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMT_TYPE_CONNECT_CONNECTION_LIST, NmtConnectConnectionListClass))
#define NMT_IS_CONNECT_CONNECTION_LIST(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMT_TYPE_CONNECT_CONNECTION_LIST))
#define NMT_IS_CONNECT_CONNECTION_LIST_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMT_TYPE_CONNECT_CONNECTION_LIST))
#define NMT_CONNECT_CONNECTION_LIST_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMT_TYPE_CONNECT_CONNECTION_LIST, NmtConnectConnectionListClass))

typedef struct {
	NmtNewtListbox parent;

} NmtConnectConnectionList;

typedef struct {
	NmtNewtListboxClass parent;

} NmtConnectConnectionListClass;

GType nmt_connect_connection_list_get_type (void);

NmtNewtWidget *nmt_connect_connection_list_new (void);

gboolean nmt_connect_connection_list_get_connection (NmtConnectConnectionList  *list,
                                                     const char                *identifier,
                                                     NMConnection             **connection,
                                                     NMDevice                 **device,
                                                     NMObject                 **specific_object,
                                                     NMActiveConnection       **active);
gboolean nmt_connect_connection_list_get_selection  (NmtConnectConnectionList  *list,
                                                     NMConnection             **connection,
                                                     NMDevice                 **device,
                                                     NMObject                 **specific_object,
                                                     NMActiveConnection       **active);

#endif /* NMT_CONNECT_CONNECTION_LIST_H */
