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

#ifndef NMT_EDITOR_SECTION_H
#define NMT_EDITOR_SECTION_H

#include "nmt-newt-section.h"
#include "nmt-editor-grid.h"

G_BEGIN_DECLS

#define NMT_TYPE_EDITOR_SECTION            (nmt_editor_section_get_type ())
#define NMT_EDITOR_SECTION(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMT_TYPE_EDITOR_SECTION, NmtEditorSection))
#define NMT_EDITOR_SECTION_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMT_TYPE_EDITOR_SECTION, NmtEditorSectionClass))
#define NMT_IS_EDITOR_SECTION(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMT_TYPE_EDITOR_SECTION))
#define NMT_IS_EDITOR_SECTION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMT_TYPE_EDITOR_SECTION))
#define NMT_EDITOR_SECTION_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMT_TYPE_EDITOR_SECTION, NmtEditorSectionClass))

typedef struct {
	NmtNewtSection parent;

} NmtEditorSection;

typedef struct {
	NmtNewtSectionClass parent;

} NmtEditorSectionClass;

GType nmt_editor_section_get_type (void);

NmtEditorSection *nmt_editor_section_new               (const char *title,
                                                        NmtNewtWidget *header_widget,
                                                        gboolean show_by_default);

const char       *nmt_editor_section_get_title         (NmtEditorSection *section);
NmtNewtWidget    *nmt_editor_section_get_header_widget (NmtEditorSection *section);
NmtEditorGrid    *nmt_editor_section_get_body          (NmtEditorSection *section);

G_END_DECLS

#endif /* NMT_EDITOR_SECTION_H */
