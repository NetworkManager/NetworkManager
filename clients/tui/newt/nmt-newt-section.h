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

#ifndef NMT_NEWT_SECTION_H
#define NMT_NEWT_SECTION_H

#include "nmt-newt-container.h"

G_BEGIN_DECLS

#define NMT_TYPE_NEWT_SECTION            (nmt_newt_section_get_type ())
#define NMT_NEWT_SECTION(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMT_TYPE_NEWT_SECTION, NmtNewtSection))
#define NMT_NEWT_SECTION_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMT_TYPE_NEWT_SECTION, NmtNewtSectionClass))
#define NMT_IS_NEWT_SECTION(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMT_TYPE_NEWT_SECTION))
#define NMT_IS_NEWT_SECTION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMT_TYPE_NEWT_SECTION))
#define NMT_NEWT_SECTION_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMT_TYPE_NEWT_SECTION, NmtNewtSectionClass))

struct _NmtNewtSection {
	NmtNewtContainer parent;

};

typedef struct {
	NmtNewtContainerClass parent;

} NmtNewtSectionClass;

GType nmt_newt_section_get_type (void);

NmtNewtWidget *nmt_newt_section_new (void);

void           nmt_newt_section_set_header (NmtNewtSection *section,
                                            NmtNewtWidget  *header);
NmtNewtWidget *nmt_newt_section_get_header (NmtNewtSection *section);

void           nmt_newt_section_set_body   (NmtNewtSection *section,
                                            NmtNewtWidget  *body);
NmtNewtWidget *nmt_newt_section_get_body   (NmtNewtSection *section);

G_END_DECLS

#endif /* NMT_NEWT_SECTION_H */
