// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2013 Red Hat, Inc.
 */

#ifndef NMT_NEWT_ENTRY_NUMERIC_H
#define NMT_NEWT_ENTRY_NUMERIC_H

#include "nmt-newt-entry.h"

#define NMT_TYPE_NEWT_ENTRY_NUMERIC            (nmt_newt_entry_numeric_get_type ())
#define NMT_NEWT_ENTRY_NUMERIC(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMT_TYPE_NEWT_ENTRY_NUMERIC, NmtNewtEntryNumeric))
#define NMT_NEWT_ENTRY_NUMERIC_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMT_TYPE_NEWT_ENTRY_NUMERIC, NmtNewtEntryNumericClass))
#define NMT_IS_NEWT_ENTRY_NUMERIC(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMT_TYPE_NEWT_ENTRY_NUMERIC))
#define NMT_IS_NEWT_ENTRY_NUMERIC_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMT_TYPE_NEWT_ENTRY_NUMERIC))
#define NMT_NEWT_ENTRY_NUMERIC_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMT_TYPE_NEWT_ENTRY_NUMERIC, NmtNewtEntryNumericClass))

struct _NmtNewtEntryNumeric {
	NmtNewtEntry parent;

};

typedef struct {
	NmtNewtEntryClass parent;

} NmtNewtEntryNumericClass;

GType nmt_newt_entry_numeric_get_type (void);

NmtNewtWidget *nmt_newt_entry_numeric_new (int width,
                                           gint64 min,
                                           gint64 max);

NmtNewtWidget *nmt_newt_entry_numeric_new_full (int width,
                                                gint64 min,
                                                gint64 max,
                                                gboolean optional);

#endif /* NMT_NEWT_ENTRY_NUMERIC_H */
