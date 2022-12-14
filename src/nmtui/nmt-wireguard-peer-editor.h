/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2021 Red Hat, Inc.
 */

#ifndef NMT_WIREGUARD_PEER_EDITOR_H
#define NMT_WIREGUARD_PEER_EDITOR_H

#include "libnmt-newt/nmt-newt.h"

#define NMT_TYPE_WIREGUARD_PEER_EDITOR (nmt_wireguard_peer_editor_get_type())
#define NMT_WIREGUARD_PEER_EDITOR(obj) \
    (_NM_G_TYPE_CHECK_INSTANCE_CAST((obj), NMT_TYPE_WIREGUARD_PEER_EDITOR, NmtWireguardPeerEditor))
#define NMT_WIREGUARD_PEER_EDITOR_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NMT_TYPE_WIREGUARD_PEER_EDITOR, NmtWireguardPeerEditorClass))
#define NMT_IS_WIREGUARD_PEER_EDITOR(obj) \
    (G_TYPE_CHECK_INSTANCE_TYPE((obj), NMT_TYPE_WIREGUARD_PEER_EDITOR))
#define NMT_IS_WIREGUARD_PEER_EDITOR_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_TYPE((klass), NMT_TYPE_WIREGUARD_PEER_EDITOR))
#define NMT_WIREGUARD_PEER_EDITOR_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NMT_TYPE_WIREGUARD_PEER_EDITOR, NmtWireguardPeerEditorClass))

typedef struct {
    NmtNewtForm parent;
} NmtWireguardPeerEditor;

typedef struct {
    NmtNewtFormClass parent;
} NmtWireguardPeerEditorClass;

GType nmt_wireguard_peer_editor_get_type(void);

NmtNewtForm *nmt_wireguard_peer_editor_new(NMSettingWireGuard *setting, NMWireGuardPeer *peer);

#endif /* NMT_WIREGUARD_PEER_EDITOR_H */
