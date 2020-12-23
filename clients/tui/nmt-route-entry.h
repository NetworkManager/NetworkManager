/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

#ifndef NMT_ROUTE_ENTRY_H
#define NMT_ROUTE_ENTRY_H

#include "nmt-newt.h"

#define NMT_TYPE_ROUTE_ENTRY (nmt_route_entry_get_type())
#define NMT_ROUTE_ENTRY(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NMT_TYPE_ROUTE_ENTRY, NmtRouteEntry))
#define NMT_ROUTE_ENTRY_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NMT_TYPE_ROUTE_ENTRY, NmtRouteEntryClass))
#define NMT_IS_ROUTE_ENTRY(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NMT_TYPE_ROUTE_ENTRY))
#define NMT_IS_ROUTE_ENTRY_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NMT_TYPE_ROUTE_ENTRY))
#define NMT_ROUTE_ENTRY_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NMT_TYPE_ROUTE_ENTRY, NmtRouteEntryClass))

typedef struct {
    NmtNewtGrid parent;

} NmtRouteEntry;

typedef struct {
    NmtNewtGridClass parent;

} NmtRouteEntryClass;

GType nmt_route_entry_get_type(void);

NmtNewtWidget *nmt_route_entry_new(int family, int ip_entry_width, int metric_entry_width);

#endif /* NMT_ROUTE_ENTRY_H */
