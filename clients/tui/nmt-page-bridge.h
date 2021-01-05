/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

#ifndef NMT_PAGE_BRIDGE_H
#define NMT_PAGE_BRIDGE_H

#include "nmt-editor-page-device.h"

#define NMT_TYPE_PAGE_BRIDGE (nmt_page_bridge_get_type())
#define NMT_PAGE_BRIDGE(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NMT_TYPE_PAGE_BRIDGE, NmtPageBridge))
#define NMT_PAGE_BRIDGE_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NMT_TYPE_PAGE_BRIDGE, NmtPageBridgeClass))
#define NMT_IS_PAGE_BRIDGE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NMT_TYPE_PAGE_BRIDGE))
#define NMT_IS_PAGE_BRIDGE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NMT_TYPE_PAGE_BRIDGE))
#define NMT_PAGE_BRIDGE_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NMT_TYPE_PAGE_BRIDGE, NmtPageBridgeClass))

typedef struct {
    NmtEditorPageDevice parent;

} NmtPageBridge;

typedef struct {
    NmtEditorPageDeviceClass parent;

} NmtPageBridgeClass;

GType nmt_page_bridge_get_type(void);

NmtEditorPage *nmt_page_bridge_new(NMConnection *conn, NmtDeviceEntry *deventry);

#endif /* NMT_PAGE_BRIDGE_H */
