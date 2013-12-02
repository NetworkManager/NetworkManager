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

#ifndef NMT_NEWT_ENTRY_H
#define NMT_NEWT_ENTRY_H

#include "nmt-newt-component.h"

G_BEGIN_DECLS

#define NMT_TYPE_NEWT_ENTRY            (nmt_newt_entry_get_type ())
#define NMT_NEWT_ENTRY(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMT_TYPE_NEWT_ENTRY, NmtNewtEntry))
#define NMT_NEWT_ENTRY_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMT_TYPE_NEWT_ENTRY, NmtNewtEntryClass))
#define NMT_IS_NEWT_ENTRY(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMT_TYPE_NEWT_ENTRY))
#define NMT_IS_NEWT_ENTRY_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMT_TYPE_NEWT_ENTRY))
#define NMT_NEWT_ENTRY_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMT_TYPE_NEWT_ENTRY, NmtNewtEntryClass))

struct _NmtNewtEntry {
  NmtNewtComponent parent;

};

typedef struct {
  NmtNewtComponentClass parent;

} NmtNewtEntryClass;

GType nmt_newt_entry_get_type (void);

typedef gboolean (*NmtNewtEntryFilter) (NmtNewtEntry *, const char *text, int ch, int position, gpointer);
typedef gboolean (*NmtNewtEntryValidator) (NmtNewtEntry *, const char *text, gpointer);

typedef enum {
	NMT_NEWT_ENTRY_NOSCROLL = (1 << 0),
	NMT_NEWT_ENTRY_PASSWORD = (1 << 1),
	NMT_NEWT_ENTRY_NONEMPTY = (1 << 2)
} NmtNewtEntryFlags;

NmtNewtWidget *nmt_newt_entry_new           (int                    width,
                                             NmtNewtEntryFlags      flags);

void           nmt_newt_entry_set_filter    (NmtNewtEntry          *entry,
                                             NmtNewtEntryFilter     filter,
                                             gpointer               user_data);
void           nmt_newt_entry_set_validator (NmtNewtEntry          *entry,
                                             NmtNewtEntryValidator  validator,
                                             gpointer               user_data);

void           nmt_newt_entry_set_text      (NmtNewtEntry          *entry,
                                             const char            *text);
const char    *nmt_newt_entry_get_text      (NmtNewtEntry          *entry);

void           nmt_newt_entry_set_width     (NmtNewtEntry          *entry,
                                             int                    width);
int            nmt_newt_entry_get_width     (NmtNewtEntry          *entry);

G_END_DECLS

#endif /* NMT_NEWT_ENTRY_H */
