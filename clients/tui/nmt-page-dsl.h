// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2013 Red Hat, Inc.
 */

#ifndef NMT_PAGE_DSL_H
#define NMT_PAGE_DSL_H

#include "nmt-editor-page-device.h"

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

#endif /* NMT_PAGE_DSL_H */
