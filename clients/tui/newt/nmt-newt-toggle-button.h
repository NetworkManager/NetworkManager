// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2013 Red Hat, Inc.
 */

#ifndef NMT_NEWT_TOGGLE_BUTTON_H
#define NMT_NEWT_TOGGLE_BUTTON_H

#include "nmt-newt-button.h"

#define NMT_TYPE_NEWT_TOGGLE_BUTTON            (nmt_newt_toggle_button_get_type ())
#define NMT_NEWT_TOGGLE_BUTTON(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMT_TYPE_NEWT_TOGGLE_BUTTON, NmtNewtToggleButton))
#define NMT_NEWT_TOGGLE_BUTTON_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMT_TYPE_NEWT_TOGGLE_BUTTON, NmtNewtToggleButtonClass))
#define NMT_IS_NEWT_TOGGLE_BUTTON(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMT_TYPE_NEWT_TOGGLE_BUTTON))
#define NMT_IS_NEWT_TOGGLE_BUTTON_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMT_TYPE_NEWT_TOGGLE_BUTTON))
#define NMT_NEWT_TOGGLE_BUTTON_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMT_TYPE_NEWT_TOGGLE_BUTTON, NmtNewtToggleButtonClass))

struct _NmtNewtToggleButton {
	NmtNewtButton parent;

};

typedef struct {
	NmtNewtButtonClass parent;

} NmtNewtToggleButtonClass;

GType nmt_newt_toggle_button_get_type (void);

NmtNewtWidget *nmt_newt_toggle_button_new        (const char          *on_label,
                                                  const char          *off_label);

gboolean       nmt_newt_toggle_button_get_active (NmtNewtToggleButton *button);
void           nmt_newt_toggle_button_set_active (NmtNewtToggleButton *button,
                                                  gboolean             active);

#endif /* NMT_NEWT_TOGGLE_BUTTON_H */
