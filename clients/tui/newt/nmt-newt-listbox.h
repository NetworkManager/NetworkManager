// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2013 Red Hat, Inc.
 */

#ifndef NMT_NEWT_LISTBOX_H
#define NMT_NEWT_LISTBOX_H

#include "nmt-newt-component.h"

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

#endif /* NMT_NEWT_LISTBOX_H */
