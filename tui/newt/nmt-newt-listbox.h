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

#ifndef NMT_NEWT_LISTBOX_H
#define NMT_NEWT_LISTBOX_H

#include "nmt-newt-component.h"

G_BEGIN_DECLS

#define NMT_TYPE_NEWT_LISTBOX            (nmt_newt_listbox_get_type ())
#define NMT_NEWT_LISTBOX(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMT_TYPE_NEWT_LISTBOX, NmtNewtListbox))
#define NMT_NEWT_LISTBOX_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMT_TYPE_NEWT_LISTBOX, NmtNewtListboxClass))
#define NMT_IS_NEWT_LISTBOX(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMT_TYPE_NEWT_LISTBOX))
#define NMT_IS_NEWT_LISTBOX_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMT_TYPE_NEWT_LISTBOX))
#define NMT_NEWT_LISTBOX_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMT_TYPE_NEWT_LISTBOX, NmtNewtListboxClass))

struct _NmtNewtListbox {
	NmtNewtComponent parent;

};

typedef struct {
	NmtNewtComponentClass parent;

} NmtNewtListboxClass;

GType nmt_newt_listbox_get_type (void);

typedef enum {
	NMT_NEWT_LISTBOX_SCROLL = (1 << 0),
	NMT_NEWT_LISTBOX_BORDER = (1 << 1)
} NmtNewtListboxFlags;

NmtNewtWidget *nmt_newt_listbox_new            (int                  height,
                                                NmtNewtListboxFlags  flags);

void           nmt_newt_listbox_set_height     (NmtNewtListbox      *listbox,
                                                int                  height);

void           nmt_newt_listbox_append         (NmtNewtListbox      *listbox,
                                                const char          *entry,
                                                gpointer             key);
void           nmt_newt_listbox_clear          (NmtNewtListbox      *listbox);

void           nmt_newt_listbox_set_active     (NmtNewtListbox      *listbox,
                                                int                  active);
void           nmt_newt_listbox_set_active_key (NmtNewtListbox      *listbox,
                                                gpointer             active_key);

int            nmt_newt_listbox_get_active     (NmtNewtListbox      *listbox);
gpointer       nmt_newt_listbox_get_active_key (NmtNewtListbox      *listbox);

G_END_DECLS

#endif /* NMT_NEWT_LISTBOX_H */
