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
 * Copyright 2013-2014 Red Hat, Inc.
 */

#ifndef NMT_EDITOR_PAGE_H
#define NMT_EDITOR_PAGE_H

#include <NetworkManager.h>

#include "nmt-editor-grid.h"
#include "nmt-editor-section.h"

G_BEGIN_DECLS

#define NMT_TYPE_EDITOR_PAGE            (nmt_editor_page_get_type ())
#define NMT_EDITOR_PAGE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMT_TYPE_EDITOR_PAGE, NmtEditorPage))
#define NMT_EDITOR_PAGE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMT_TYPE_EDITOR_PAGE, NmtEditorPageClass))
#define NMT_IS_EDITOR_PAGE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMT_TYPE_EDITOR_PAGE))
#define NMT_IS_EDITOR_PAGE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMT_TYPE_EDITOR_PAGE))
#define NMT_EDITOR_PAGE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMT_TYPE_EDITOR_PAGE, NmtEditorPageClass))

typedef struct {
	GObject parent;

} NmtEditorPage;

typedef struct {
	GObjectClass parent;

} NmtEditorPageClass;

GType nmt_editor_page_get_type (void);

NMConnection  *nmt_editor_page_get_connection    (NmtEditorPage *page);

GSList        *nmt_editor_page_get_sections      (NmtEditorPage *page);

/*< protected >*/
void           nmt_editor_page_add_section       (NmtEditorPage *page,
                                                  NmtEditorSection *section);

G_END_DECLS

#endif /* NMT_EDITOR_PAGE_H */
