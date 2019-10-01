// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

#ifndef NMT_NEWT_TEXTBOX_H
#define NMT_NEWT_TEXTBOX_H

#include "nmt-newt-component.h"

#define NMT_TYPE_NEWT_TEXTBOX            (nmt_newt_textbox_get_type ())
#define NMT_NEWT_TEXTBOX(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMT_TYPE_NEWT_TEXTBOX, NmtNewtTextbox))
#define NMT_NEWT_TEXTBOX_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMT_TYPE_NEWT_TEXTBOX, NmtNewtTextboxClass))
#define NMT_IS_NEWT_TEXTBOX(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMT_TYPE_NEWT_TEXTBOX))
#define NMT_IS_NEWT_TEXTBOX_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMT_TYPE_NEWT_TEXTBOX))
#define NMT_NEWT_TEXTBOX_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMT_TYPE_NEWT_TEXTBOX, NmtNewtTextboxClass))

struct _NmtNewtTextbox {
	NmtNewtComponent parent;

};

typedef struct {
	NmtNewtComponentClass parent;

} NmtNewtTextboxClass;

GType nmt_newt_textbox_get_type (void);

typedef enum {
	NMT_NEWT_TEXTBOX_SCROLLABLE     = (1 << 0),
	NMT_NEWT_TEXTBOX_SET_BACKGROUND = (1 << 1)
} NmtNewtTextboxFlags;

NmtNewtWidget *nmt_newt_textbox_new      (NmtNewtTextboxFlags  flags,
                                          int                  wrap_width);

void           nmt_newt_textbox_set_text (NmtNewtTextbox      *textbox,
                                          const char          *text);
const char    *nmt_newt_textbox_get_text (NmtNewtTextbox      *textbox);

#endif /* NMT_NEWT_TEXTBOX_H */
