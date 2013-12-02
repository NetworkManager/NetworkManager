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

#ifndef NMT_NEWT_LABEL_H
#define NMT_NEWT_LABEL_H

#include "nmt-newt-component.h"

G_BEGIN_DECLS

#define NMT_TYPE_NEWT_LABEL            (nmt_newt_label_get_type ())
#define NMT_NEWT_LABEL(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMT_TYPE_NEWT_LABEL, NmtNewtLabel))
#define NMT_NEWT_LABEL_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMT_TYPE_NEWT_LABEL, NmtNewtLabelClass))
#define NMT_IS_NEWT_LABEL(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMT_TYPE_NEWT_LABEL))
#define NMT_IS_NEWT_LABEL_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMT_TYPE_NEWT_LABEL))
#define NMT_NEWT_LABEL_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMT_TYPE_NEWT_LABEL, NmtNewtLabelClass))

struct _NmtNewtLabel {
	NmtNewtComponent parent;

};

typedef struct {
	NmtNewtComponentClass parent;

} NmtNewtLabelClass;

GType nmt_newt_label_get_type (void);

typedef enum {
	NMT_NEWT_LABEL_NORMAL,
	NMT_NEWT_LABEL_PLAIN
} NmtNewtLabelStyle;

NmtNewtWidget     *nmt_newt_label_new           (const char        *text);

void               nmt_newt_label_set_text      (NmtNewtLabel      *label,
                                                 const char        *text);
const char        *nmt_newt_label_get_text      (NmtNewtLabel      *label);

void               nmt_newt_label_set_style     (NmtNewtLabel      *label,
                                                 NmtNewtLabelStyle  style);
NmtNewtLabelStyle  nmt_newt_label_get_style     (NmtNewtLabel      *label);

void               nmt_newt_label_set_highlight (NmtNewtLabel      *label,
                                                 gboolean           highlight);
gboolean           nmt_newt_label_get_highlight (NmtNewtLabel      *label);

G_END_DECLS

#endif /* NMT_NEWT_LABEL_H */
