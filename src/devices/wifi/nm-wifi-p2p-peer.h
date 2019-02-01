/* NetworkManager -- Wi-Fi P2P Peer
 *
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
 * Copyright (C) 2018 Red Hat, Inc.
 */

#ifndef __NM_WIFI_P2P_PEER_H__
#define __NM_WIFI_P2P_PEER_H__

#include "nm-dbus-object.h"
#include "nm-dbus-interface.h"
#include "nm-connection.h"

#define NM_TYPE_WIFI_P2P_PEER            (nm_wifi_p2p_peer_get_type ())
#define NM_WIFI_P2P_PEER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_WIFI_P2P_PEER, NMWifiP2PPeer))
#define NM_WIFI_P2P_PEER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_WIFI_P2P_PEER, NMWifiP2PPeerClass))
#define NM_IS_WIFI_P2P_PEER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_WIFI_P2P_PEER))
#define NM_IS_WIFI_P2P_PEER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_WIFI_P2P_PEER))
#define NM_WIFI_P2P_PEER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_WIFI_P2P_PEER, NMWifiP2PPeerClass))

#define NM_WIFI_P2P_PEER_FLAGS                "flags"
#define NM_WIFI_P2P_PEER_NAME                 "name"
#define NM_WIFI_P2P_PEER_MANUFACTURER         "manufacturer"
#define NM_WIFI_P2P_PEER_MODEL                "model"
#define NM_WIFI_P2P_PEER_MODEL_NUMBER         "model-number"
#define NM_WIFI_P2P_PEER_SERIAL               "serial"
#define NM_WIFI_P2P_PEER_WFD_IES              "wfd-ies"
#define NM_WIFI_P2P_PEER_GROUPS               "groups"
#define NM_WIFI_P2P_PEER_HW_ADDRESS           "hw-address"
#define NM_WIFI_P2P_PEER_STRENGTH             "strength"
#define NM_WIFI_P2P_PEER_LAST_SEEN            "last-seen"

typedef struct {
	NMDBusObject parent;
	NMDevice *wifi_device;
	CList peers_lst;
	struct _NMWifiP2PPeerPrivate *_priv;
} NMWifiP2PPeer;

typedef struct _NMWifiP2PPeerClass NMWifiP2PPeerClass;

GType nm_wifi_p2p_peer_get_type (void);

NMWifiP2PPeer *   nm_wifi_p2p_peer_new_from_properties      (const char *supplicant_path,
                                                             GVariant *properties);

gboolean          nm_wifi_p2p_peer_update_from_properties   (NMWifiP2PPeer *peer,
                                                             const char *supplicant_path,
                                                             GVariant *properties);

gboolean          nm_wifi_p2p_peer_check_compatible         (NMWifiP2PPeer *self,
                                                             NMConnection *connection);

const char *      nm_wifi_p2p_peer_get_supplicant_path      (NMWifiP2PPeer *peer);

const char *      nm_wifi_p2p_peer_get_name                 (const NMWifiP2PPeer *peer);
gboolean          nm_wifi_p2p_peer_set_name                 (NMWifiP2PPeer *peer,
                                                             const char *name);
const char *      nm_wifi_p2p_peer_get_manufacturer         (const NMWifiP2PPeer *peer);
gboolean          nm_wifi_p2p_peer_set_manufacturer         (NMWifiP2PPeer *peer,
                                                             const char *manufacturer);
const char *      nm_wifi_p2p_peer_get_model                (const NMWifiP2PPeer *peer);
gboolean          nm_wifi_p2p_peer_set_model                (NMWifiP2PPeer *peer,
                                                             const char *model);
const char *      nm_wifi_p2p_peer_get_model_number         (const NMWifiP2PPeer *peer);
gboolean          nm_wifi_p2p_peer_set_model_number         (NMWifiP2PPeer *peer,
                                                             const char *number);
const char *      nm_wifi_p2p_peer_get_serial               (const NMWifiP2PPeer *peer);
gboolean          nm_wifi_p2p_peer_set_serial               (NMWifiP2PPeer *peer,
                                                             const char *serial);

GBytes *          nm_wifi_p2p_peer_get_wfd_ies             (const NMWifiP2PPeer *peer);
gboolean          nm_wifi_p2p_peer_set_wfd_ies             (NMWifiP2PPeer *peer,
                                                            GBytes *bytes);

const char *const*nm_wifi_p2p_peer_get_groups              (const NMWifiP2PPeer *peer);

const char *      nm_wifi_p2p_peer_get_address              (const NMWifiP2PPeer *peer);
gboolean          nm_wifi_p2p_peer_set_address              (NMWifiP2PPeer *peer,
                                                             const char *addr);
gint8             nm_wifi_p2p_peer_get_strength             (NMWifiP2PPeer *peer);
gboolean          nm_wifi_p2p_peer_set_strength             (NMWifiP2PPeer *peer,
                                                             gint8 strength);
NM80211ApFlags    nm_wifi_p2p_peer_get_flags                (const NMWifiP2PPeer *self);

const char       *nm_wifi_p2p_peer_to_string                (const NMWifiP2PPeer *self,
                                                             char *str_buf,
                                                             gsize buf_len,
                                                             gint32 now_s);

const char      **nm_wifi_p2p_peers_get_paths               (const CList *peers_lst_head);

NMWifiP2PPeer    *nm_wifi_p2p_peers_find_first_compatible (const CList *peers_lst_head,
                                                           NMConnection *connection);

NMWifiP2PPeer    *nm_wifi_p2p_peers_find_by_supplicant_path (const CList *peers_lst_head, const char *path);

NMWifiP2PPeer    *nm_wifi_p2p_peer_lookup_for_device (NMDevice *device, const char *exported_path);

#endif /* __NM_WIFI_P2P_PEER_H__ */
