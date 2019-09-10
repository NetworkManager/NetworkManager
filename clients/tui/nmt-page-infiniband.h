// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2013 Red Hat, Inc.
 */

#ifndef NMT_PAGE_INFINIBAND_H
#define NMT_PAGE_INFINIBAND_H

#include "nmt-editor-page-device.h"

#define NMT_TYPE_PAGE_INFINIBAND            (nmt_page_infiniband_get_type ())
#define NMT_PAGE_INFINIBAND(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMT_TYPE_PAGE_INFINIBAND, NmtPageInfiniband))
#define NMT_PAGE_INFINIBAND_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMT_TYPE_PAGE_INFINIBAND, NmtPageInfinibandClass))
#define NMT_IS_PAGE_INFINIBAND(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMT_TYPE_PAGE_INFINIBAND))
#define NMT_IS_PAGE_INFINIBAND_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMT_TYPE_PAGE_INFINIBAND))
#define NMT_PAGE_INFINIBAND_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMT_TYPE_PAGE_INFINIBAND, NmtPageInfinibandClass))

typedef struct {
	NmtEditorPageDevice parent;

} NmtPageInfiniband;

typedef struct {
	NmtEditorPageDeviceClass parent;

} NmtPageInfinibandClass;

GType nmt_page_infiniband_get_type (void);

NmtEditorPage *nmt_page_infiniband_new (NMConnection   *conn,
                                        NmtDeviceEntry *deventry);

#endif /* NMT_PAGE_INFINIBAND_H */
