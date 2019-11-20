// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

#ifndef NMT_MAC_ENTRY_H
#define NMT_MAC_ENTRY_H

#include "nm-utils.h"
#include "nmt-newt.h"

typedef enum { /*< skip >*/
	NMT_MAC_ENTRY_TYPE_MAC,
	NMT_MAC_ENTRY_TYPE_CLONED,
} NmtMacEntryType;

#define NMT_TYPE_MAC_ENTRY            (nmt_mac_entry_get_type ())
#define NMT_MAC_ENTRY(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMT_TYPE_MAC_ENTRY, NmtMacEntry))
#define NMT_MAC_ENTRY_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMT_TYPE_MAC_ENTRY, NmtMacEntryClass))
#define NMT_IS_MAC_ENTRY(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMT_TYPE_MAC_ENTRY))
#define NMT_IS_MAC_ENTRY_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMT_TYPE_MAC_ENTRY))
#define NMT_MAC_ENTRY_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMT_TYPE_MAC_ENTRY, NmtMacEntryClass))

typedef struct {
	NmtNewtEntry parent;

} NmtMacEntry;

typedef struct {
	NmtNewtEntryClass parent;

} NmtMacEntryClass;

GType nmt_mac_entry_get_type (void);

NmtNewtWidget *nmt_mac_entry_new (int width,
                                  int mac_length,
                                  NmtMacEntryType type);

#endif /* NMT_MAC_ENTRY_H */
