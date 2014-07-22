/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright 2013 Red Hat, Inc.
 */

#ifndef NMT_NEWT_ENTRY_NUMERIC_H
#define NMT_NEWT_ENTRY_NUMERIC_H

#include "nmt-newt-entry.h"

G_BEGIN_DECLS

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
                                           int min,
                                           int max);

G_END_DECLS

#endif /* NMT_NEWT_ENTRY_NUMERIC_H */
