/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

#ifndef NMT_PAGE_BRIDGE_PORT_H
#define NMT_PAGE_BRIDGE_PORT_H

#include "nmt-editor-page.h"

#define NMT_TYPE_PAGE_BRIDGE_PORT (nmt_page_bridge_port_get_type())
#define NMT_PAGE_BRIDGE_PORT(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NMT_TYPE_PAGE_BRIDGE_PORT, NmtPageBridgePort))
#define NMT_PAGE_BRIDGE_PORT_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NMT_TYPE_PAGE_BRIDGE_PORT, NmtPageBridgePortClass))
#define NMT_IS_PAGE_BRIDGE_PORT(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), NMT_TYPE_PAGE_BRIDGE_PORT))
#define NMT_IS_PAGE_BRIDGE_PORT_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_TYPE((klass), NMT_TYPE_PAGE_BRIDGE_PORT))
#define NMT_PAGE_BRIDGE_PORT_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NMT_TYPE_PAGE_BRIDGE_PORT, NmtPageBridgePortClass))

typedef struct {
    NmtEditorPage parent;

} NmtPageBridgePort;

typedef struct {
    NmtEditorPageClass parent;

} NmtPageBridgePortClass;

GType nmt_page_bridge_port_get_type(void);

NmtEditorPage *nmt_page_bridge_port_new(NMConnection *conn);

#endif /* NMT_PAGE_BRIDGE_PORT_H */
