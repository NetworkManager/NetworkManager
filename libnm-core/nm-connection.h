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
 * Copyright 2007 - 2018 Red Hat, Inc.
 * Copyright 2007 - 2008 Novell, Inc.
 */

#ifndef __NM_CONNECTION_H__
#define __NM_CONNECTION_H__

#if !defined (__NETWORKMANAGER_H_INSIDE__) && !defined (NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-core-types.h"
#include "nm-setting.h"
#include "nm-errors.h"

G_BEGIN_DECLS

#define NM_TYPE_CONNECTION                (nm_connection_get_type ())
#define NM_CONNECTION(obj)                (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_CONNECTION, NMConnection))
#define NM_IS_CONNECTION(obj)             (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_CONNECTION))
#define NM_CONNECTION_GET_INTERFACE(obj)  (G_TYPE_INSTANCE_GET_INTERFACE ((obj), NM_TYPE_CONNECTION, NMConnectionClass))

/* Signals */
#define NM_CONNECTION_SECRETS_UPDATED "secrets-updated"
#define NM_CONNECTION_SECRETS_CLEARED "secrets-cleared"
#define NM_CONNECTION_CHANGED         "changed"

/*
 * NM_CONNECTION_NORMALIZE_PARAM_IP6_CONFIG_METHOD: overwrite the ip6 method
 * when normalizing ip6 configuration. If omitted, this defaults to
 * @NM_SETTING_IP6_CONFIG_METHOD_AUTO.
 */
#define NM_CONNECTION_NORMALIZE_PARAM_IP6_CONFIG_METHOD "ip6-config-method"

/**
 * NMConnection:
 *
 * NMConnection is the interface implemented by #NMRemoteConnection on the
 * client side, and #NMSettingsConnection on the daemon side.
 */

/**
 * NMConnectionInterface:
 * @parent: the parent interface struct
 * @secrets_updated: emitted when the connection's secrets are updated
 * @secrets_cleared: emitted when the connection's secrets are cleared
 * @changed: emitted when any change to the connection's settings occurs
 */
typedef struct {
	GTypeInterface parent;

	/* Signals */
	void (*secrets_updated) (NMConnection *connection,
	                         const char   *setting);
	void (*secrets_cleared) (NMConnection *connection);
	void (*changed)         (NMConnection *connection);

} NMConnectionInterface;

GType nm_connection_get_type (void);

void          nm_connection_add_setting   (NMConnection *connection,
                                           NMSetting    *setting);

void          nm_connection_remove_setting (NMConnection *connection,
                                            GType         setting_type);

NMSetting    *nm_connection_get_setting   (NMConnection *connection,
                                           GType         setting_type);

NMSetting    *nm_connection_get_setting_by_name (NMConnection *connection,
                                                 const char   *name);

/**
 * NM_VARIANT_TYPE_CONNECTION:
 *
 * #GVariantType for a dictionary mapping from setting names to
 * %NM_VARIANT_TYPE_SETTING variants. This is used to represent an
 * #NMConnection, and is the type taken by nm_simple_connection_new_from_dbus()
 * and returned from nm_connection_to_dbus().
 */
#define NM_VARIANT_TYPE_CONNECTION (G_VARIANT_TYPE ("a{sa{sv}}"))

/**
 * NM_VARIANT_TYPE_SETTING:
 *
 * #GVariantType for a dictionary mapping from property names to values. This is
 * an alias for %G_VARIANT_TYPE_VARDICT, and is the type of each element of
 * an %NM_VARIANT_TYPE_CONNECTION dictionary.
 */
#define NM_VARIANT_TYPE_SETTING G_VARIANT_TYPE_VARDICT

/**
 * NMConnectionSerializationFlags:
 * @NM_CONNECTION_SERIALIZE_ALL: serialize all properties (including secrets)
 * @NM_CONNECTION_SERIALIZE_NO_SECRETS: do not include secrets
 * @NM_CONNECTION_SERIALIZE_ONLY_SECRETS: only serialize secrets
 * @NM_CONNECTION_SERIALIZE_WITH_SECRETS_AGENT_OWNED: if set, only secrets that
 *   are agent owned will be serialized. Since: 1.20
 *
 * These flags determine which properties are serialized when calling when
 * calling nm_connection_to_dbus().
 **/
typedef enum { /*< flags >*/
	NM_CONNECTION_SERIALIZE_ALL                      = 0x00000000,
	NM_CONNECTION_SERIALIZE_NO_SECRETS               = 0x00000001,
	NM_CONNECTION_SERIALIZE_ONLY_SECRETS             = 0x00000002,
	NM_CONNECTION_SERIALIZE_WITH_SECRETS_AGENT_OWNED = 0x00000004,
} NMConnectionSerializationFlags;

GVariant     *nm_connection_to_dbus       (NMConnection *connection,
                                           NMConnectionSerializationFlags flags);

gboolean      nm_connection_replace_settings (NMConnection *connection,
                                              GVariant *new_settings,
                                              GError **error);

void          nm_connection_replace_settings_from_connection (NMConnection *connection,
                                                              NMConnection *new_connection);

void          nm_connection_clear_settings (NMConnection *connection);

gboolean      nm_connection_compare       (NMConnection *a,
                                           NMConnection *b,
                                           NMSettingCompareFlags flags);

gboolean      nm_connection_diff          (NMConnection *a,
                                           NMConnection *b,
                                           NMSettingCompareFlags flags,
                                           GHashTable **out_settings);

gboolean      nm_connection_verify        (NMConnection *connection, GError **error);
NM_AVAILABLE_IN_1_2
gboolean      nm_connection_verify_secrets (NMConnection *connection, GError **error);
gboolean      nm_connection_normalize     (NMConnection *connection,
                                           GHashTable *parameters,
                                           gboolean *modified,
                                           GError **error);

const char *  nm_connection_need_secrets  (NMConnection *connection,
                                           GPtrArray **hints);

void          nm_connection_clear_secrets (NMConnection *connection);

void          nm_connection_clear_secrets_with_flags (NMConnection *connection,
                                                      NMSettingClearSecretsWithFlagsFn func,
                                                      gpointer user_data);

gboolean      nm_connection_update_secrets (NMConnection *connection,
                                            const char *setting_name,
                                            GVariant *secrets,
                                            GError **error);

void          nm_connection_set_path      (NMConnection *connection,
                                           const char *path);

const char *  nm_connection_get_path      (NMConnection *connection);

const char *  nm_connection_get_interface_name (NMConnection *connection);

gboolean      nm_connection_is_type (NMConnection *connection, const char *type);

void          nm_connection_for_each_setting_value (NMConnection *connection,
                                                    NMSettingValueIterFn func,
                                                    gpointer user_data);

NM_AVAILABLE_IN_1_10
NMSetting **  nm_connection_get_settings (NMConnection *connection,
                                          guint *out_length);

void          nm_connection_dump          (NMConnection *connection);

/* Helpers */
const char *  nm_connection_get_uuid            (NMConnection *connection);
const char *  nm_connection_get_id              (NMConnection *connection);
const char *  nm_connection_get_connection_type (NMConnection *connection);

gboolean      nm_connection_is_virtual          (NMConnection *connection);
char *        nm_connection_get_virtual_device_description (NMConnection *connection);

NMSetting8021x *           nm_connection_get_setting_802_1x            (NMConnection *connection);
NMSettingBluetooth *       nm_connection_get_setting_bluetooth         (NMConnection *connection);
NMSettingBond *            nm_connection_get_setting_bond              (NMConnection *connection);
NMSettingTeam *            nm_connection_get_setting_team              (NMConnection *connection);
NMSettingTeamPort *        nm_connection_get_setting_team_port         (NMConnection *connection);
NMSettingBridge *          nm_connection_get_setting_bridge            (NMConnection *connection);
NMSettingBridgePort *      nm_connection_get_setting_bridge_port       (NMConnection *connection);
NMSettingCdma *            nm_connection_get_setting_cdma              (NMConnection *connection);
NMSettingConnection *      nm_connection_get_setting_connection        (NMConnection *connection);
NMSettingDcb *             nm_connection_get_setting_dcb               (NMConnection *connection);
NM_AVAILABLE_IN_1_8
NMSettingDummy *           nm_connection_get_setting_dummy             (NMConnection *connection);
NMSettingGeneric *         nm_connection_get_setting_generic           (NMConnection *connection);
NMSettingGsm *             nm_connection_get_setting_gsm               (NMConnection *connection);
NMSettingInfiniband *      nm_connection_get_setting_infiniband        (NMConnection *connection);
NM_AVAILABLE_IN_1_2
NMSettingIPTunnel *        nm_connection_get_setting_ip_tunnel         (NMConnection *connection);
NMSettingIPConfig *        nm_connection_get_setting_ip4_config        (NMConnection *connection);
NMSettingIPConfig *        nm_connection_get_setting_ip6_config        (NMConnection *connection);
NM_AVAILABLE_IN_1_6
NMSettingMacsec *          nm_connection_get_setting_macsec            (NMConnection *connection);
NM_AVAILABLE_IN_1_2
NMSettingMacvlan *         nm_connection_get_setting_macvlan           (NMConnection *connection);
NMSettingOlpcMesh *        nm_connection_get_setting_olpc_mesh         (NMConnection *connection);
NM_AVAILABLE_IN_1_10
NMSettingOvsBridge *       nm_connection_get_setting_ovs_bridge        (NMConnection *connection);
NM_AVAILABLE_IN_1_10
NMSettingOvsInterface *    nm_connection_get_setting_ovs_interface     (NMConnection *connection);
NMSettingOvsPatch *        nm_connection_get_setting_ovs_patch         (NMConnection *connection);
NM_AVAILABLE_IN_1_10
NMSettingOvsPort *         nm_connection_get_setting_ovs_port          (NMConnection *connection);
NMSettingPpp *             nm_connection_get_setting_ppp               (NMConnection *connection);
NMSettingPppoe *           nm_connection_get_setting_pppoe             (NMConnection *connection);
NM_AVAILABLE_IN_1_6
NMSettingProxy *           nm_connection_get_setting_proxy             (NMConnection *connection);
NMSettingSerial *          nm_connection_get_setting_serial            (NMConnection *connection);
NM_AVAILABLE_IN_1_12
NMSettingTCConfig *        nm_connection_get_setting_tc_config         (NMConnection *connection);
NM_AVAILABLE_IN_1_2
NMSettingTun *             nm_connection_get_setting_tun               (NMConnection *connection);
NMSettingVpn *             nm_connection_get_setting_vpn               (NMConnection *connection);
NMSettingWimax *           nm_connection_get_setting_wimax             (NMConnection *connection);
NMSettingAdsl *            nm_connection_get_setting_adsl              (NMConnection *connection);
NMSettingWired *           nm_connection_get_setting_wired             (NMConnection *connection);
NMSettingWireless *        nm_connection_get_setting_wireless          (NMConnection *connection);
NMSettingWirelessSecurity *nm_connection_get_setting_wireless_security (NMConnection *connection);
NMSettingVlan *            nm_connection_get_setting_vlan              (NMConnection *connection);
NM_AVAILABLE_IN_1_2
NMSettingVxlan *           nm_connection_get_setting_vxlan             (NMConnection *connection);

G_END_DECLS

#endif /* __NM_CONNECTION_H__ */
