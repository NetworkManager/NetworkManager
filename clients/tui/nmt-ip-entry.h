// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2013 Red Hat, Inc.
 */

#ifndef NMT_IP_ENTRY_H
#define NMT_IP_ENTRY_H

#include "nmt-newt.h"

#define NMT_TYPE_IP_ENTRY            (nmt_ip_entry_get_type ())
#define NMT_IP_ENTRY(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMT_TYPE_IP_ENTRY, NmtIPEntry))
#define NMT_IP_ENTRY_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMT_TYPE_IP_ENTRY, NmtIPEntryClass))
#define NMT_IS_IP_ENTRY(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMT_TYPE_IP_ENTRY))
#define NMT_IS_IP_ENTRY_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMT_TYPE_IP_ENTRY))
#define NMT_IP_ENTRY_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMT_TYPE_IP_ENTRY, NmtIPEntryClass))

typedef struct {
	NmtNewtEntry parent;

} NmtIPEntry;

typedef struct {
	NmtNewtEntryClass parent;

} NmtIPEntryClass;

GType nmt_ip_entry_get_type (void);

NmtNewtWidget *nmt_ip_entry_new (int      width,
                                 int      family,
                                 gboolean prefix,
                                 gboolean optional);

#endif /* NMT_IP_ENTRY_H */
