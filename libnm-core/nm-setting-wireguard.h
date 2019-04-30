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
 * Copyright 2018 - 2019 Red Hat, Inc.
 */

#ifndef __NM_SETTING_WIREGUARD_H__
#define __NM_SETTING_WIREGUARD_H__

#if !defined (__NETWORKMANAGER_H_INSIDE__) && !defined (NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-setting.h"
#include "nm-utils.h"

G_BEGIN_DECLS

/*****************************************************************************/

#define NM_WIREGUARD_PUBLIC_KEY_LEN     32
#define NM_WIREGUARD_SYMMETRIC_KEY_LEN  32

/*****************************************************************************/

typedef struct _NMWireGuardPeer NMWireGuardPeer;

NM_AVAILABLE_IN_1_16
GType nm_wireguard_peer_get_type (void);

NM_AVAILABLE_IN_1_16
NMWireGuardPeer *nm_wireguard_peer_new (void);

NM_AVAILABLE_IN_1_16
NMWireGuardPeer *nm_wireguard_peer_new_clone (const NMWireGuardPeer *self,
                                              gboolean with_secrets);

NM_AVAILABLE_IN_1_16
NMWireGuardPeer *nm_wireguard_peer_ref (NMWireGuardPeer *self);
NM_AVAILABLE_IN_1_16
void nm_wireguard_peer_unref (NMWireGuardPeer *self);

NM_AVAILABLE_IN_1_16
void nm_wireguard_peer_seal (NMWireGuardPeer *self);
NM_AVAILABLE_IN_1_16
gboolean nm_wireguard_peer_is_sealed (const NMWireGuardPeer *self);

NM_AVAILABLE_IN_1_16
const char *nm_wireguard_peer_get_public_key (const NMWireGuardPeer *self);
NM_AVAILABLE_IN_1_16
gboolean nm_wireguard_peer_set_public_key (NMWireGuardPeer *self,
                                           const char *public_key,
                                           gboolean accept_invalid);

NM_AVAILABLE_IN_1_16
const char *nm_wireguard_peer_get_preshared_key (const NMWireGuardPeer *self);
NM_AVAILABLE_IN_1_16
gboolean nm_wireguard_peer_set_preshared_key (NMWireGuardPeer *self,
                                              const char *preshared_key,
                                              gboolean accept_invalid);

NM_AVAILABLE_IN_1_16
NMSettingSecretFlags nm_wireguard_peer_get_preshared_key_flags (const NMWireGuardPeer *self);
NM_AVAILABLE_IN_1_16
void nm_wireguard_peer_set_preshared_key_flags (NMWireGuardPeer *self,
                                                NMSettingSecretFlags preshared_key_flags);

NM_AVAILABLE_IN_1_16
guint16 nm_wireguard_peer_get_persistent_keepalive (const NMWireGuardPeer *self);
NM_AVAILABLE_IN_1_16
void nm_wireguard_peer_set_persistent_keepalive (NMWireGuardPeer *self,
                                                 guint16 persistent_keepalive);

NM_AVAILABLE_IN_1_16
const char *nm_wireguard_peer_get_endpoint (const NMWireGuardPeer *self);
NM_AVAILABLE_IN_1_16
gboolean nm_wireguard_peer_set_endpoint (NMWireGuardPeer *self,
                                         const char *endpoint,
                                         gboolean allow_invalid);

NM_AVAILABLE_IN_1_16
guint nm_wireguard_peer_get_allowed_ips_len (const NMWireGuardPeer *self);
NM_AVAILABLE_IN_1_16
const char *nm_wireguard_peer_get_allowed_ip (const NMWireGuardPeer *self,
                                              guint idx,
                                              gboolean *out_is_valid);
NM_AVAILABLE_IN_1_16
void nm_wireguard_peer_clear_allowed_ips (NMWireGuardPeer *self);
NM_AVAILABLE_IN_1_16
gboolean nm_wireguard_peer_append_allowed_ip (NMWireGuardPeer *self,
                                              const char *allowed_ip,
                                              gboolean accept_invalid);
NM_AVAILABLE_IN_1_16
gboolean nm_wireguard_peer_remove_allowed_ip (NMWireGuardPeer *self,
                                              guint idx);

NM_AVAILABLE_IN_1_16
gboolean nm_wireguard_peer_is_valid (const NMWireGuardPeer *self,
                                     gboolean check_non_secrets,
                                     gboolean check_secrets,
                                     GError **error);

NM_AVAILABLE_IN_1_16
int nm_wireguard_peer_cmp (const NMWireGuardPeer *a,
                           const NMWireGuardPeer *b,
                           NMSettingCompareFlags compare_flags);

/*****************************************************************************/

#define NM_TYPE_SETTING_WIREGUARD            (nm_setting_wireguard_get_type ())
#define NM_SETTING_WIREGUARD(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_WIREGUARD, NMSettingWireGuard))
#define NM_SETTING_WIREGUARD_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_WIREGUARD, NMSettingWireGuardClass))
#define NM_IS_SETTING_WIREGUARD(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_WIREGUARD))
#define NM_IS_SETTING_WIREGUARD_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SETTING_WIREGUARD))
#define NM_SETTING_WIREGUARD_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_WIREGUARD, NMSettingWireGuardClass))

#define NM_SETTING_WIREGUARD_SETTING_NAME "wireguard"

#define NM_SETTING_WIREGUARD_FWMARK            "fwmark"
#define NM_SETTING_WIREGUARD_LISTEN_PORT       "listen-port"
#define NM_SETTING_WIREGUARD_PRIVATE_KEY       "private-key"
#define NM_SETTING_WIREGUARD_PRIVATE_KEY_FLAGS "private-key-flags"

#define NM_SETTING_WIREGUARD_PEERS             "peers"

#define NM_SETTING_WIREGUARD_MTU               "mtu"
#define NM_SETTING_WIREGUARD_PEER_ROUTES       "peer-routes"
#define NM_SETTING_WIREGUARD_IP4_AUTO_DEFAULT_ROUTE "ip4-auto-default-route"
#define NM_SETTING_WIREGUARD_IP6_AUTO_DEFAULT_ROUTE "ip6-auto-default-route"

#define NM_WIREGUARD_PEER_ATTR_ALLOWED_IPS          "allowed-ips"
#define NM_WIREGUARD_PEER_ATTR_ENDPOINT             "endpoint"
#define NM_WIREGUARD_PEER_ATTR_PERSISTENT_KEEPALIVE "persistent-keepalive"
#define NM_WIREGUARD_PEER_ATTR_PRESHARED_KEY        "preshared-key"
#define NM_WIREGUARD_PEER_ATTR_PRESHARED_KEY_FLAGS  "preshared-key-flags"
#define NM_WIREGUARD_PEER_ATTR_PUBLIC_KEY           "public-key"

/*****************************************************************************/

typedef struct _NMSettingWireGuardClass NMSettingWireGuardClass;

NM_AVAILABLE_IN_1_16
GType nm_setting_wireguard_get_type (void);

NM_AVAILABLE_IN_1_16
NMSetting *nm_setting_wireguard_new (void);

/*****************************************************************************/

NM_AVAILABLE_IN_1_16
const char *nm_setting_wireguard_get_private_key (NMSettingWireGuard *self);

NM_AVAILABLE_IN_1_16
NMSettingSecretFlags nm_setting_wireguard_get_private_key_flags (NMSettingWireGuard *self);

NM_AVAILABLE_IN_1_16
guint16 nm_setting_wireguard_get_listen_port (NMSettingWireGuard *self);

NM_AVAILABLE_IN_1_16
guint32 nm_setting_wireguard_get_fwmark (NMSettingWireGuard *self);

/*****************************************************************************/

NM_AVAILABLE_IN_1_16
guint nm_setting_wireguard_get_peers_len (NMSettingWireGuard *self);

NM_AVAILABLE_IN_1_16
NMWireGuardPeer *nm_setting_wireguard_get_peer (NMSettingWireGuard *self,
                                                guint idx);

NM_AVAILABLE_IN_1_16
NMWireGuardPeer *nm_setting_wireguard_get_peer_by_public_key (NMSettingWireGuard *self,
                                                              const char *public_key,
                                                              guint *out_idx);

NM_AVAILABLE_IN_1_16
void nm_setting_wireguard_set_peer (NMSettingWireGuard *self,
                                    NMWireGuardPeer *peer,
                                    guint idx);

NM_AVAILABLE_IN_1_16
void nm_setting_wireguard_append_peer (NMSettingWireGuard *self,
                                       NMWireGuardPeer *peer);

NM_AVAILABLE_IN_1_16
gboolean nm_setting_wireguard_remove_peer (NMSettingWireGuard *self,
                                           guint idx);

NM_AVAILABLE_IN_1_16
guint nm_setting_wireguard_clear_peers (NMSettingWireGuard *self);

NM_AVAILABLE_IN_1_16
gboolean nm_setting_wireguard_get_peer_routes (NMSettingWireGuard *self);

NM_AVAILABLE_IN_1_16
guint32 nm_setting_wireguard_get_mtu (NMSettingWireGuard *self);

NM_AVAILABLE_IN_1_20
NMTernary nm_setting_wireguard_get_ip4_auto_default_route (NMSettingWireGuard *self);

NM_AVAILABLE_IN_1_20
NMTernary nm_setting_wireguard_get_ip6_auto_default_route (NMSettingWireGuard *self);

/*****************************************************************************/

G_END_DECLS

#endif /* __NM_SETTING_WIREGUARD_H__ */
