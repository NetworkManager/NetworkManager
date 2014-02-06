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

#ifndef NMT_NEWT_FORM_H
#define NMT_NEWT_FORM_H

#include "nmt-newt-container.h"

G_BEGIN_DECLS

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

G_END_DECLS

#endif /* NMT_NEWT_FORM_H */
