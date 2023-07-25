/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

#ifndef NMT_PORT_LIST_H
#define NMT_PORT_LIST_H

#include "nmt-edit-connection-list.h"
#include "nmtui-edit.h"

#define NMT_TYPE_PORT_LIST (nmt_port_list_get_type())
#define NMT_PORT_LIST(obj) (_NM_G_TYPE_CHECK_INSTANCE_CAST((obj), NMT_TYPE_PORT_LIST, NmtPortList))
#define NMT_PORT_LIST_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NMT_TYPE_PORT_LIST, NmtPortListClass))
#define NMT_IS_PORT_LIST(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NMT_TYPE_PORT_LIST))
#define NMT_IS_PORT_LIST_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NMT_TYPE_PORT_LIST))
#define NMT_PORT_LIST_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NMT_TYPE_PORT_LIST, NmtPortListClass))

typedef struct {
    NmtEditConnectionList parent;

} NmtPortList;

typedef struct {
    NmtEditConnectionListClass parent;

} NmtPortListClass;

GType nmt_port_list_get_type(void);

NmtNewtWidget *nmt_port_list_new(NMConnection              *controller,
                                 NmtAddConnectionTypeFilter type_filter,
                                 gpointer                   type_filter_data);

#endif /* NMT_PORT_LIST_H */
