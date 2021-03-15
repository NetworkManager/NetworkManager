/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2016 Red Hat, Inc.
 */

#ifndef NMT_PAGE_IP_TUNNEL_H
#define NMT_PAGE_IP_TUNNEL_H

#include "nmt-editor-page-device.h"

#define NMT_TYPE_PAGE_IP_TUNNEL (nmt_page_ip_tunnel_get_type())
#define NMT_PAGE_IP_TUNNEL(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NMT_TYPE_PAGE_IP_TUNNEL, NmtPageIPTunnel))
#define NMT_PAGE_IP_TUNNEL_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NMT_TYPE_PAGE_IP_TUNNEL, NmtPageIPTunnelClass))
#define NMT_IS_PAGE_IP_TUNNEL(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), NMT_TYPE_PAGE_IP_TUNNEL))
#define NMT_IS_PAGE_IP_TUNNEL_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_TYPE((klass), NMT_TYPE_PAGE_IP_TUNNEL))
#define NMT_PAGE_IP_TUNNEL_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NMT_TYPE_PAGE_IP_TUNNEL, NmtPageIPTunnelClass))

typedef struct {
    NmtEditorPageDevice parent;
} NmtPageIPTunnel;

typedef struct {
    NmtEditorPageDeviceClass parent;
} NmtPageIPTunnelClass;

GType nmt_page_ip_tunnel_get_type(void);

NmtEditorPage *nmt_page_ip_tunnel_new(NMConnection *conn, NmtDeviceEntry *deventry);

#endif /* NMT_PAGE_IP_TUNNEL_H */
