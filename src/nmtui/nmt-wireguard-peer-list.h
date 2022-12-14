/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2021 Red Hat, Inc.
 */

#ifndef NMT_WIREGUARD_PEER_LIST_H
#define NMT_WIREGUARD_PEER_LIST_H

#include "libnmt-newt/nmt-newt.h"
#include "nmtui-edit.h"

#define NMT_TYPE_WIREGUARD_PEER_LIST (nmt_wireguard_peer_list_get_type())
#define NMT_WIREGUARD_PEER_LIST(obj) \
    (_NM_G_TYPE_CHECK_INSTANCE_CAST((obj), NMT_TYPE_WIREGUARD_PEER_LIST, NmtWireguardPeerList))
#define NMT_WIREGUARD_PEER_LIST_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NMT_TYPE_WIREGUARD_PEER_LIST, NmtWireguardPeerListClass))
#define NMT_IS_WIREGUARD_PEER_LIST(obj) \
    (G_TYPE_CHECK_INSTANCE_TYPE((obj), NMT_TYPE_WIREGUARD_PEER_LIST))
#define NMT_IS_WIREGUARD_PEER_LIST_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_TYPE((klass), NMT_TYPE_WIREGUARD_PEER_LIST))
#define NMT_WIREGUARD_PEER_LIST_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NMT_TYPE_WIREGUARD_PEER_LIST, NmtWireguardPeerListClass))

typedef struct {
    NmtNewtGrid parent;

} NmtWireguardPeerList;

typedef struct {
    NmtNewtGridClass parent;

    /* signals */
    void (*add_peer)(NmtWireguardPeerList *list);
    void (*edit_peer)(NmtWireguardPeerList *list);
    void (*remove_peer)(NmtWireguardPeerList *list);
} NmtWireguardPeerListClass;

GType nmt_wireguard_peer_list_get_type(void);

NmtNewtWidget *nmt_wireguard_peer_list_new(NMSettingWireGuard *setting);

#endif /* NMT_WIREGUARD_PEER_LIST_H */
