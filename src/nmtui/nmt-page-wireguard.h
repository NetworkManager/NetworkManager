/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2021 Red Hat, Inc.
 */

#ifndef NMT_PAGE_WIREGUARD_H
#define NMT_PAGE_WIREGUARD_H

#include "nmt-editor-page-device.h"

#define NMT_TYPE_PAGE_WIREGUARD (nmt_page_wireguard_get_type())
#define NMT_PAGE_WIREGUARD(obj) \
    (_NM_G_TYPE_CHECK_INSTANCE_CAST((obj), NMT_TYPE_PAGE_WIREGUARD, NmtPageWireGuard))
#define NMT_PAGE_WIREGUARD_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NMT_TYPE_PAGE_WIREGUARD, NmtPageWireGuardClass))
#define NMT_IS_PAGE_WIREGUARD(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), NMT_TYPE_PAGE_WIREGUARD))
#define NMT_IS_PAGE_WIREGUARD_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_TYPE((klass), NMT_TYPE_PAGE_WIREGUARD))
#define NMT_PAGE_WIREGUARD_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NMT_TYPE_PAGE_WIREGUARD, NmtPageWireGuardClass))

typedef struct {
    NmtEditorPageDevice parent;
} NmtPageWireGuard;

typedef struct {
    NmtEditorPageDeviceClass parent;
} NmtPageWireGuardClass;

GType nmt_page_wireguard_get_type(void);

NmtEditorPage *nmt_page_wireguard_new(NMConnection *conn, NmtDeviceEntry *deventry);

#endif /* NMT_PAGE_WIREGUARD_H */
