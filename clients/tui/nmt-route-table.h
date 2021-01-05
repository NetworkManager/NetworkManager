/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

#ifndef NMT_ROUTE_TABLE_H
#define NMT_ROUTE_TABLE_H

#include "nmt-newt.h"

#define NMT_TYPE_ROUTE_TABLE (nmt_route_table_get_type())
#define NMT_ROUTE_TABLE(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NMT_TYPE_ROUTE_TABLE, NmtRouteTable))
#define NMT_ROUTE_TABLE_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NMT_TYPE_ROUTE_TABLE, NmtRouteTableClass))
#define NMT_IS_ROUTE_TABLE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NMT_TYPE_ROUTE_TABLE))
#define NMT_IS_ROUTE_TABLE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NMT_TYPE_ROUTE_TABLE))
#define NMT_ROUTE_TABLE_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NMT_TYPE_ROUTE_TABLE, NmtRouteTableClass))

typedef struct {
    NmtNewtGrid parent;

} NmtRouteTable;

typedef struct {
    NmtNewtGridClass parent;

} NmtRouteTableClass;

GType nmt_route_table_get_type(void);

NmtNewtWidget *nmt_route_table_new(int family);

#endif /* NMT_ROUTE_TABLE_H */
