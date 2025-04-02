/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2025 Red Hat, Inc.
 */

#ifndef NMT_PAGE_LOOPBACK_H
#define NMT_PAGE_LOOPBACK_H

#include "nmt-editor-page-device.h"

#define NMT_TYPE_PAGE_LOOPBACK (nmt_page_loopback_get_type())
#define NMT_PAGE_LOOPBACK(obj) \
    (_NM_G_TYPE_CHECK_INSTANCE_CAST((obj), NMT_TYPE_PAGE_LOOPBACK, NmtPageLoopback))
#define NMT_PAGE_LOOPBACK_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NMT_TYPE_PAGE_LOOPBACK, NmtPageLoopbackClass))
#define NMT_IS_PAGE_LOOPBACK(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NMT_TYPE_PAGE_LOOPBACK))
#define NMT_IS_PAGE_LOOPBACK_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NMT_TYPE_PAGE_LOOPBACK))
#define NMT_PAGE_LOOPBACK_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NMT_TYPE_PAGE_LOOPBACK, NmtPageLoopbackClass))

typedef struct {
    NmtEditorPageDevice parent;
} NmtPageLoopback;

typedef struct {
    NmtEditorPageDeviceClass parent;
} NmtPageLoopbackClass;

GType nmt_page_loopback_get_type(void);

NmtEditorPage *nmt_page_loopback_new(NMConnection *conn, NmtDeviceEntry *deventry);

#endif /* NMT_PAGE_LOOPBACK_H */
