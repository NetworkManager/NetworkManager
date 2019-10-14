// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

#ifndef NMT_NEWT_FORM_H
#define NMT_NEWT_FORM_H

#include "nmt-newt-container.h"

#define NMT_TYPE_NEWT_FORM            (nmt_newt_form_get_type ())
#define NMT_NEWT_FORM(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMT_TYPE_NEWT_FORM, NmtNewtForm))
#define NMT_NEWT_FORM_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMT_TYPE_NEWT_FORM, NmtNewtFormClass))
#define NMT_IS_NEWT_FORM(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMT_TYPE_NEWT_FORM))
#define NMT_IS_NEWT_FORM_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMT_TYPE_NEWT_FORM))
#define NMT_NEWT_FORM_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMT_TYPE_NEWT_FORM, NmtNewtFormClass))

struct _NmtNewtForm {
	NmtNewtContainer parent;

};

typedef struct {
	NmtNewtContainerClass parent;

	/* signals */
	void (*quit) (NmtNewtForm *form);

	/* methods */
	void (*show) (NmtNewtForm *form);

} NmtNewtFormClass;

GType nmt_newt_form_get_type (void);

NmtNewtForm   *nmt_newt_form_new              (const char          *title);
NmtNewtForm   *nmt_newt_form_new_fullscreen   (const char          *title);

void           nmt_newt_form_set_content      (NmtNewtForm         *form,
                                               NmtNewtWidget       *content);

void           nmt_newt_form_show             (NmtNewtForm         *form);
NmtNewtWidget *nmt_newt_form_run_sync         (NmtNewtForm         *form);
void           nmt_newt_form_quit             (NmtNewtForm         *form);

void           nmt_newt_form_set_focus        (NmtNewtForm         *form,
                                               NmtNewtWidget       *widget);

#endif /* NMT_NEWT_FORM_H */
