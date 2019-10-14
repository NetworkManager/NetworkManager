// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

#ifndef NMT_NEWT_CHECKBOX_H
#define NMT_NEWT_CHECKBOX_H

#include "nmt-newt-component.h"

#define NMT_TYPE_NEWT_CHECKBOX            (nmt_newt_checkbox_get_type ())
#define NMT_NEWT_CHECKBOX(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMT_TYPE_NEWT_CHECKBOX, NmtNewtCheckbox))
#define NMT_NEWT_CHECKBOX_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMT_TYPE_NEWT_CHECKBOX, NmtNewtCheckboxClass))
#define NMT_IS_NEWT_CHECKBOX(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMT_TYPE_NEWT_CHECKBOX))
#define NMT_IS_NEWT_CHECKBOX_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMT_TYPE_NEWT_CHECKBOX))
#define NMT_NEWT_CHECKBOX_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMT_TYPE_NEWT_CHECKBOX, NmtNewtCheckboxClass))

struct _NmtNewtCheckbox {
	NmtNewtComponent parent;

};

typedef struct {
	NmtNewtComponentClass parent;

} NmtNewtCheckboxClass;

GType nmt_newt_checkbox_get_type (void);

NmtNewtWidget *nmt_newt_checkbox_new (const char *label);

void     nmt_newt_checkbox_set_active (NmtNewtCheckbox *checkbox,
                                       gboolean         active);
gboolean nmt_newt_checkbox_get_active (NmtNewtCheckbox *checkbox);

#endif /* NMT_NEWT_CHECKBOX_H */
