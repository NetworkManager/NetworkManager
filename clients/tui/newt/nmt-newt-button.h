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

#ifndef NMT_NEWT_BUTTON_H
#define NMT_NEWT_BUTTON_H

#include "nmt-newt-component.h"

#define NMT_TYPE_NEWT_BUTTON            (nmt_newt_button_get_type ())
#define NMT_NEWT_BUTTON(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMT_TYPE_NEWT_BUTTON, NmtNewtButton))
#define NMT_NEWT_BUTTON_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMT_TYPE_NEWT_BUTTON, NmtNewtButtonClass))
#define NMT_IS_NEWT_BUTTON(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMT_TYPE_NEWT_BUTTON))
#define NMT_IS_NEWT_BUTTON_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMT_TYPE_NEWT_BUTTON))
#define NMT_NEWT_BUTTON_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMT_TYPE_NEWT_BUTTON, NmtNewtButtonClass))

struct _NmtNewtButton {
	NmtNewtComponent parent;

};

typedef struct {
	NmtNewtComponentClass parent;

} NmtNewtButtonClass;

GType nmt_newt_button_get_type (void);

NmtNewtWidget *nmt_newt_button_new       (const char    *label);

void           nmt_newt_button_set_label (NmtNewtButton *button,
                                          const char    *label);
const char    *nmt_newt_button_get_label (NmtNewtButton *button);

#endif /* NMT_NEWT_BUTTON_H */
