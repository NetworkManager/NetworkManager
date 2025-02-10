/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2024 Red Hat, Inc.
 */

#ifndef NMT_PAGE_VETH_H
#define NMT_PAGE_VETH_H

#include "nmt-editor-page-device.h"

#define NMT_TYPE_PAGE_VETH (nmt_page_veth_get_type())
#define NMT_PAGE_VETH(obj) (_NM_G_TYPE_CHECK_INSTANCE_CAST((obj), NMT_TYPE_PAGE_VETH, NmtPageVeth))
#define NMT_PAGE_VETH_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NMT_TYPE_PAGE_VETH, NmtPageVethClass))
#define NMT_IS_PAGE_VETH(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NMT_TYPE_PAGE_VETH))
#define NMT_IS_PAGE_VETH_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NMT_TYPE_PAGE_VETH))
#define NMT_PAGE_VETH_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NMT_TYPE_PAGE_VETH, NmtPageVethClass))

typedef struct {
    NmtEditorPageDevice parent;
} NmtPageVeth;

typedef struct {
    NmtEditorPageDeviceClass parent;
} NmtPageVethClass;

GType nmt_page_veth_get_type(void);

NmtEditorPage *nmt_page_veth_new(NMConnection *conn, NmtDeviceEntry *deventry);

#endif /* NMT_PAGE_VETH_H */
