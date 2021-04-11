/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2021 Red Hat, Inc.
 */

#ifndef NMT_PEER_LIST_H
#define NMT_PEER_LIST_H

#include "nmt-newt.h"
#include "nmtui-edit.h"

#define NMT_TYPE_PEER_LIST (nmt_peer_list_get_type())
#define NMT_PEER_LIST(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), NMT_TYPE_PEER_LIST, NmtPeerList))
#define NMT_PEER_LIST_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NMT_TYPE_PEER_LIST, NmtPeerListClass))
#define NMT_IS_PEER_LIST(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NMT_TYPE_PEER_LIST))
#define NMT_IS_PEER_LIST_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NMT_TYPE_PEER_LIST))
#define NMT_PEER_LIST_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NMT_TYPE_PEER_LIST, NmtPeerListClass))

typedef struct {
    NmtNewtGrid parent;

} NmtPeerList;

typedef struct {
    NmtNewtGridClass parent;

    /* signals */
    void (*add_peer)(NmtPeerList *list);
    void (*edit_peer)(NmtPeerList *list, NMConnection *connection);
    void (*remove_peer)(NmtPeerList *list, NMConnection *connection);
} NmtPeerListClass;

GType nmt_peer_list_get_type(void);

NmtNewtWidget *nmt_peer_list_new(NMSettingWireGuard *setting);

#endif /* NMT_PEER_LIST_H */
