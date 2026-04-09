/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

#ifndef NMT_LIST_H
#define NMT_LIST_H

#include "nmt-widget-list.h"

#define NMT_TYPE_LIST            (nmt_list_get_type())
#define NMT_LIST(obj)            (_NM_G_TYPE_CHECK_INSTANCE_CAST((obj), NMT_TYPE_LIST, NmtList))
#define NMT_LIST_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST((klass), NMT_TYPE_LIST, NmtListClass))
#define NMT_IS_LIST(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NMT_TYPE_LIST))
#define NMT_IS_LIST_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NMT_TYPE_LIST))
#define NMT_LIST_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS((obj), NMT_TYPE_LIST, NmtListClass))

typedef struct {
    NmtWidgetList parent;

} NmtList;

typedef struct {
    NmtWidgetListClass parent;

} NmtListClass;

GType nmt_list_get_type(void);

typedef enum {
    NMT_LIST_IP4_WITH_PREFIX,
    NMT_LIST_IP4,
    NMT_LIST_IP6_WITH_PREFIX,
    NMT_LIST_IP6,
    NMT_LIST_HOSTNAME,
    NMT_LIST_KEY_VALUE
} NmtListType;

NmtNewtWidget *nmt_list_new(NmtListType list_type);

#endif /* NMT_LIST_H */
