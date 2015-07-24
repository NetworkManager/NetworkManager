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

#ifndef NMT_PAGE_DSL_H
#define NMT_PAGE_DSL_H

#include "nm-glib.h"
#include "nmt-editor-page-device.h"

G_BEGIN_DECLS

#define NMT_TYPE_PAGE_DSL            (nmt_page_dsl_get_type ())
#define NMT_PAGE_DSL(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMT_TYPE_PAGE_DSL, NmtPageDsl))
#define NMT_PAGE_DSL_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMT_TYPE_PAGE_DSL, NmtPageDslClass))
#define NMT_IS_PAGE_DSL(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMT_TYPE_PAGE_DSL))
#define NMT_IS_PAGE_DSL_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMT_TYPE_PAGE_DSL))
#define NMT_PAGE_DSL_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMT_TYPE_PAGE_DSL, NmtPageDslClass))

typedef struct {
	NmtEditorPageDevice parent;

} NmtPageDsl;

typedef struct {
	NmtEditorPageDeviceClass parent;

} NmtPageDslClass;

GType nmt_page_dsl_get_type (void);

NmtEditorPage *nmt_page_dsl_new (NMConnection *conn,
                                 NmtDeviceEntry *deventry);

G_END_DECLS

#endif /* NMT_PAGE_DSL_H */
