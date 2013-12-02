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

#ifndef NMT_EDITOR_PAGE_H
#define NMT_EDITOR_PAGE_H

#include <nm-connection.h>

#include "nmt-page-grid.h"

G_BEGIN_DECLS

#define NMT_TYPE_EDITOR_PAGE            (nmt_editor_page_get_type ())
#define NMT_EDITOR_PAGE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMT_TYPE_EDITOR_PAGE, NmtEditorPage))
#define NMT_EDITOR_PAGE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMT_TYPE_EDITOR_PAGE, NmtEditorPageClass))
#define NMT_IS_EDITOR_PAGE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMT_TYPE_EDITOR_PAGE))
#define NMT_IS_EDITOR_PAGE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMT_TYPE_EDITOR_PAGE))
#define NMT_EDITOR_PAGE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMT_TYPE_EDITOR_PAGE, NmtEditorPageClass))

typedef struct {
	NmtPageGrid parent;

} NmtEditorPage;

typedef struct {
	NmtPageGridClass parent;

} NmtEditorPageClass;

GType nmt_editor_page_get_type (void);

NMConnection  *nmt_editor_page_get_connection    (NmtEditorPage *page);

void           nmt_editor_page_set_header_widget (NmtEditorPage *page,
                                                  NmtNewtWidget *widget);
NmtNewtWidget *nmt_editor_page_get_header_widget (NmtEditorPage *page);

const char    *nmt_editor_page_get_title         (NmtEditorPage *page);

G_END_DECLS

#endif /* NMT_EDITOR_PAGE_H */
