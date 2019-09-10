// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2013 Red Hat, Inc.
 */

#ifndef NMT_MTU_ENTRY_H
#define NMT_MTU_ENTRY_H

#include "nmt-newt.h"

#define NMT_TYPE_MTU_ENTRY            (nmt_mtu_entry_get_type ())
#define NMT_MTU_ENTRY(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMT_TYPE_MTU_ENTRY, NmtMtuEntry))
#define NMT_MTU_ENTRY_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMT_TYPE_MTU_ENTRY, NmtMtuEntryClass))
#define NMT_IS_MTU_ENTRY(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMT_TYPE_MTU_ENTRY))
#define NMT_IS_MTU_ENTRY_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMT_TYPE_MTU_ENTRY))
#define NMT_MTU_ENTRY_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMT_TYPE_MTU_ENTRY, NmtMtuEntryClass))

typedef struct {
	NmtNewtGrid parent;

} NmtMtuEntry;

typedef struct {
	NmtNewtGridClass parent;

} NmtMtuEntryClass;

GType nmt_mtu_entry_get_type (void);

NmtNewtWidget *nmt_mtu_entry_new (void);

#endif /* NMT_MTU_ENTRY_H */
