/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright 2007 - 2008 Novell, Inc.
 * Copyright 2007 - 2011 Red Hat, Inc.
 */

#ifndef __NM_P2P_PEER_H__
#define __NM_P2P_PEER_H__

#if !defined (__NETWORKMANAGER_H_INSIDE__) && !defined (NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-object.h"

G_BEGIN_DECLS

#define NM_TYPE_P2P_PEER            (nm_p2p_peer_get_type ())
#define NM_P2P_PEER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_P2P_PEER, NMP2PPeer))
#define NM_P2P_PEER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_P2P_PEER, NMP2PPeerClass))
#define NM_IS_P2P_PEER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_P2P_PEER))
#define NM_IS_P2P_PEER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_P2P_PEER))
#define NM_P2P_PEER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_P2P_PEER, NMP2PPeerClass))

#define NM_P2P_PEER_FLAGS                "flags"
#define NM_P2P_PEER_NAME                 "name"
#define NM_P2P_PEER_MANUFACTURER         "manufacturer"
#define NM_P2P_PEER_MODEL                "model"
#define NM_P2P_PEER_MODEL_NUMBER         "model-number"
#define NM_P2P_PEER_SERIAL               "serial"
#define NM_P2P_PEER_WFD_IES              "wfd-ies"
#define NM_P2P_PEER_HW_ADDRESS           "hw-address"
#define NM_P2P_PEER_STRENGTH             "strength"
#define NM_P2P_PEER_LAST_SEEN            "last-seen"

/**
 * NMP2PPeer:
 */
NM_AVAILABLE_IN_1_16
struct _NMP2PPeer {
	NMObject parent;
};

NM_AVAILABLE_IN_1_16
typedef struct {
	NMObjectClass parent;

	/*< private >*/
	gpointer padding[4];
} NMP2PPeerClass;

NM_AVAILABLE_IN_1_16
GType nm_p2p_peer_get_type (void);

NM_AVAILABLE_IN_1_16
NM80211ApFlags         nm_p2p_peer_get_flags        (NMP2PPeer *peer);

NM_AVAILABLE_IN_1_16
const char *           nm_p2p_peer_get_name         (NMP2PPeer *peer);
NM_AVAILABLE_IN_1_16
const char *           nm_p2p_peer_get_manufacturer (NMP2PPeer *peer);
NM_AVAILABLE_IN_1_16
const char *           nm_p2p_peer_get_model        (NMP2PPeer *peer);
NM_AVAILABLE_IN_1_16
const char *           nm_p2p_peer_get_model_number (NMP2PPeer *peer);
NM_AVAILABLE_IN_1_16
const char *           nm_p2p_peer_get_serial       (NMP2PPeer *peer);

NM_AVAILABLE_IN_1_16
GBytes *               nm_p2p_peer_get_wfd_ies      (NMP2PPeer *peer);

NM_AVAILABLE_IN_1_16
const char *           nm_p2p_peer_get_hw_address   (NMP2PPeer *peer);

NM_AVAILABLE_IN_1_16
guint8                 nm_p2p_peer_get_strength     (NMP2PPeer *peer);
NM_AVAILABLE_IN_1_16
int                    nm_p2p_peer_get_last_seen    (NMP2PPeer *peer);

NM_AVAILABLE_IN_1_16
GPtrArray *            nm_p2p_peer_filter_connections (NMP2PPeer *peer,
                                                       const GPtrArray *connections);

NM_AVAILABLE_IN_1_16
gboolean               nm_p2p_peer_connection_valid   (NMP2PPeer *peer,
                                                       NMConnection *connection);

G_END_DECLS

#endif /* __NM_P2P_PEER_H__ */
