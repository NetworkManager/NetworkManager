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

#ifndef NMT_NEWT_BUTTON_BOX_H
#define NMT_NEWT_BUTTON_BOX_H

#include "nmt-newt-grid.h"

#define NMT_TYPE_NEWT_BUTTON_BOX            (nmt_newt_button_box_get_type ())
#define NMT_NEWT_BUTTON_BOX(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMT_TYPE_NEWT_BUTTON_BOX, NmtNewtButtonBox))
#define NMT_NEWT_BUTTON_BOX_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMT_TYPE_NEWT_BUTTON_BOX, NmtNewtButtonBoxClass))
#define NMT_IS_NEWT_BUTTON_BOX(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMT_TYPE_NEWT_BUTTON_BOX))
#define NMT_IS_NEWT_BUTTON_BOX_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMT_TYPE_NEWT_BUTTON_BOX))
#define NMT_NEWT_BUTTON_BOX_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMT_TYPE_NEWT_BUTTON_BOX, NmtNewtButtonBoxClass))

struct _NmtNewtButtonBox {
	NmtNewtContainer parent;

};

typedef struct {
	NmtNewtContainerClass parent;

} NmtNewtButtonBoxClass;

GType nmt_newt_button_box_get_type (void);

typedef enum {
	NMT_NEWT_BUTTON_BOX_HORIZONTAL,
	NMT_NEWT_BUTTON_BOX_VERTICAL
} NmtNewtButtonBoxOrientation;

NmtNewtWidget *nmt_newt_button_box_new       (NmtNewtButtonBoxOrientation orientation);

NmtNewtWidget *nmt_newt_button_box_add_start (NmtNewtButtonBox *bbox,
                                              const char       *label);
NmtNewtWidget *nmt_newt_button_box_add_end   (NmtNewtButtonBox *bbox,
                                              const char       *label);

void           nmt_newt_button_box_add_widget_start (NmtNewtButtonBox *bbox,
                                                     NmtNewtWidget    *widget);
void           nmt_newt_button_box_add_widget_end   (NmtNewtButtonBox *bbox,
                                                     NmtNewtWidget    *widget);

#endif /* NMT_NEWT_BUTTON_BOX_H */
