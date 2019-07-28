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
 * (C) Copyright 2014 - 2018 Red Hat, Inc.
 */

#ifndef NM_CORE_NM_INTERNAL_H
#define NM_CORE_NM_INTERNAL_H

/* This header file contain functions that are provided as private API
 * by libnm-core. It will contain functions to give privileged access to
 * libnm-core. This can be useful for NetworkManager and libnm.so
 * which both are special users of libnm-core.
 * It also exposes some utility functions for reuse.
 *
 * These functions are not exported and are only available to components that link
 * statically against libnm-core. This basically means libnm-core, libnm, NetworkManager
 * and some test programs.
 **/
#if !((NETWORKMANAGER_COMPILATION) & NM_NETWORKMANAGER_COMPILATION_WITH_LIBNM_CORE_INTERNAL)
#error Cannot use this header.
#endif

#include "nm-connection.h"
#include "nm-core-enum-types.h"
#include "nm-core-types-internal.h"
#include "nm-meta-setting.h"
#include "nm-setting-6lowpan.h"
#include "nm-setting-8021x.h"
#include "nm-setting-adsl.h"
#include "nm-setting-bluetooth.h"
#include "nm-setting-bond.h"
#include "nm-setting-bridge-port.h"
#include "nm-setting-bridge.h"
#include "nm-setting-cdma.h"
#include "nm-setting-connection.h"
#include "nm-setting-dcb.h"
#include "nm-setting-dummy.h"
#include "nm-setting-generic.h"
#include "nm-setting-gsm.h"
#include "nm-setting-infiniband.h"
#include "nm-setting-ip-tunnel.h"
#include "nm-setting-ip4-config.h"
#include "nm-setting-ip6-config.h"
#include "nm-setting-macsec.h"
#include "nm-setting-macvlan.h"
#include "nm-setting-match.h"
#include "nm-setting-olpc-mesh.h"
#include "nm-setting-ovs-bridge.h"
#include "nm-setting-ovs-interface.h"
#include "nm-setting-ovs-dpdk.h"
#include "nm-setting-ovs-patch.h"
#include "nm-setting-ovs-port.h"
#include "nm-setting-ppp.h"
#include "nm-setting-pppoe.h"
#include "nm-setting-proxy.h"
#include "nm-setting-serial.h"
#include "nm-setting-sriov.h"
#include "nm-setting-tc-config.h"
#include "nm-setting-team-port.h"
#include "nm-setting-team.h"
#include "nm-setting-tun.h"
#include "nm-setting-vlan.h"
#include "nm-setting-vpn.h"
#include "nm-setting-vxlan.h"
#include "nm-setting-wifi-p2p.h"
#include "nm-setting-wimax.h"
#include "nm-setting-wired.h"
#include "nm-setting-wireguard.h"
#include "nm-setting-wireless-security.h"
#include "nm-setting-wireless.h"
#include "nm-setting-wpan.h"
#include "nm-setting.h"
#include "nm-simple-connection.h"
#include "nm-utils.h"
#include "nm-vpn-dbus-interface.h"
#include "nm-vpn-editor-plugin.h"
#include "nm-libnm-core-intern/nm-libnm-core-utils.h"

/* IEEE 802.1D-1998 timer values */
#define NM_BR_MIN_HELLO_TIME    1
#define NM_BR_MAX_HELLO_TIME    10

#define NM_BR_MIN_FORWARD_DELAY 2
#define NM_BR_MAX_FORWARD_DELAY 30

#define NM_BR_MIN_MAX_AGE       6
#define NM_BR_MAX_MAX_AGE       40

/* IEEE 802.1D-1998 Table 7.4 */
#define NM_BR_MIN_AGEING_TIME   0
#define NM_BR_MAX_AGEING_TIME   1000000

#define NM_BR_PORT_MAX_PRIORITY 63
#define NM_BR_PORT_DEF_PRIORITY 32

#define NM_BR_PORT_MAX_PATH_COST 65535

/* NM_SETTING_COMPARE_FLAG_INFERRABLE: check whether a device-generated
 * connection can be replaced by a already-defined connection. This flag only
 * takes into account properties marked with the %NM_SETTING_PARAM_INFERRABLE
 * flag.
 */
#define NM_SETTING_COMPARE_FLAG_INFERRABLE ((NMSettingCompareFlags) 0x80000000)

/* NM_SETTING_COMPARE_FLAG_IGNORE_REAPPLY_IMMEDIATELY: this flag is used for properties
 * that automatically get re-applied on an active connection when the settings
 * connection is modified. For most properties, the applied-connection is distinct
 * from the setting-connection and changes don't propagate. Exceptions are the
 * firewall-zone and the metered property.
 */
#define NM_SETTING_COMPARE_FLAG_IGNORE_REAPPLY_IMMEDIATELY ((NMSettingCompareFlags) 0x40000000)

/* NM_SETTING_COMPARE_FLAG_NONE: for convenience, define a special flag NONE -- which
 * equals to numeric zero (NM_SETTING_COMPARE_FLAG_EXACT).
 */
#define NM_SETTING_COMPARE_FLAG_NONE ((NMSettingCompareFlags) 0)

/*****************************************************************************/

#define NM_SETTING_SECRET_FLAG_ALL \
	((NMSettingSecretFlags) (  NM_SETTING_SECRET_FLAG_NONE \
	                         | NM_SETTING_SECRET_FLAG_AGENT_OWNED \
	                         | NM_SETTING_SECRET_FLAG_NOT_SAVED \
	                         | NM_SETTING_SECRET_FLAG_NOT_REQUIRED))

static inline gboolean
_nm_setting_secret_flags_valid (NMSettingSecretFlags flags)
{
	return !NM_FLAGS_ANY (flags, ~NM_SETTING_SECRET_FLAG_ALL);
}

/*****************************************************************************/

typedef enum { /*< skip >*/
	NM_SETTING_PARSE_FLAGS_NONE                     = 0,
	NM_SETTING_PARSE_FLAGS_STRICT                   = 1LL << 0,
	NM_SETTING_PARSE_FLAGS_BEST_EFFORT              = 1LL << 1,
	NM_SETTING_PARSE_FLAGS_NORMALIZE                = 1LL << 2,

	_NM_SETTING_PARSE_FLAGS_LAST,
	NM_SETTING_PARSE_FLAGS_ALL                      = ((_NM_SETTING_PARSE_FLAGS_LAST - 1) << 1) - 1,
} NMSettingParseFlags;

gboolean _nm_connection_replace_settings (NMConnection *connection,
                                          GVariant *new_settings,
                                          NMSettingParseFlags parse_flags,
                                          GError **error);

gpointer _nm_connection_check_main_setting (NMConnection *connection,
                                            const char *setting_name,
                                            GError **error);

typedef struct {
	struct {
		guint64 val;
		bool has;
	} timestamp;

	const char **seen_bssids;

} NMConnectionSerializationOptions;

GVariant *nm_connection_to_dbus_full (NMConnection *connection,
                                      NMConnectionSerializationFlags flags,
                                      const NMConnectionSerializationOptions *options);

typedef enum {
	/* whether the connection has any secrets.
	 *
	 * @arg may be %NULL or a pointer to a gboolean for the result. The return
	 *   value of _nm_connection_aggregate() is likewise the boolean result. */
	NM_CONNECTION_AGGREGATE_ANY_SECRETS,

	/* whether the connection has any secret with flags NM_SETTING_SECRET_FLAG_NONE.
	 * Note that this only cares about the flags, not whether the secret is actually
	 * present.
	 *
	 * @arg may be %NULL or a pointer to a gboolean for the result. The return
	 *   value of _nm_connection_aggregate() is likewise the boolean result. */
	NM_CONNECTION_AGGREGATE_ANY_SYSTEM_SECRET_FLAGS,
} NMConnectionAggregateType;

gboolean _nm_connection_aggregate (NMConnection *connection,
                                   NMConnectionAggregateType type,
                                   gpointer arg);

/**
 * NMSettingVerifyResult:
 * @NM_SETTING_VERIFY_SUCCESS: the setting verifies successfully
 * @NM_SETTING_VERIFY_ERROR: the setting has a serious misconfiguration
 * @NM_SETTING_VERIFY_NORMALIZABLE: the setting is valid but has properties
 * that should be normalized
 * @NM_SETTING_VERIFY_NORMALIZABLE_ERROR: the setting is invalid but the
 * errors can be fixed by nm_connection_normalize().
 */
typedef enum {
	NM_SETTING_VERIFY_SUCCESS       = TRUE,
	NM_SETTING_VERIFY_ERROR         = FALSE,
	NM_SETTING_VERIFY_NORMALIZABLE  = 2,
	NM_SETTING_VERIFY_NORMALIZABLE_ERROR = 3,
} NMSettingVerifyResult;

NMSettingVerifyResult _nm_connection_verify (NMConnection *connection, GError **error);

gboolean _nm_connection_ensure_normalized (NMConnection *connection,
                                           gboolean allow_modify,
                                           const char *expected_uuid,
                                           gboolean coerce_uuid,
                                           NMConnection **out_connection_clone,
                                           GError **error);

gboolean _nm_connection_remove_setting (NMConnection *connection, GType setting_type);

#if NM_MORE_ASSERTS
extern const char _nmtst_connection_unchanging_user_data;
void nmtst_connection_assert_unchanging (NMConnection *connection);
#else
static inline void
nmtst_connection_assert_unchanging (NMConnection *connection)
{
}
#endif

NMConnection *_nm_simple_connection_new_from_dbus (GVariant      *dict,
                                                   NMSettingParseFlags parse_flags,
                                                   GError       **error);

NMSettingPriority _nm_setting_get_setting_priority (NMSetting *setting);

gboolean _nm_setting_get_property (NMSetting *setting, const char *name, GValue *value);

/*****************************************************************************/

GHashTable *_nm_setting_gendata_hash (NMSetting *setting,
                                      gboolean create_if_necessary);

void _nm_setting_gendata_notify (NMSetting *setting,
                                 gboolean keys_changed);

guint _nm_setting_gendata_get_all (NMSetting *setting,
                                   const char *const**out_names,
                                   GVariant *const**out_values);

gboolean _nm_setting_gendata_reset_from_hash (NMSetting *setting,
                                              GHashTable *new);

void _nm_setting_gendata_to_gvalue (NMSetting *setting,
                                    GValue *value);

GVariant *nm_setting_gendata_get (NMSetting *setting,
                                  const char *name);

const char *const*nm_setting_gendata_get_all_names (NMSetting *setting,
                                                    guint *out_len);

GVariant *const*nm_setting_gendata_get_all_values (NMSetting *setting);

/*****************************************************************************/

guint nm_setting_ethtool_init_features (NMSettingEthtool *setting,
                                        NMTernary *requested /* indexed by NMEthtoolID - _NM_ETHTOOL_ID_FEATURE_FIRST */);

/*****************************************************************************/

#define NM_UTILS_HWADDR_LEN_MAX_STR (NM_UTILS_HWADDR_LEN_MAX * 3)

guint8 *_nm_utils_hwaddr_aton (const char *asc, gpointer buffer, gsize buffer_length, gsize *out_length);
const char *nm_utils_hwaddr_ntoa_buf (gconstpointer addr, gsize addr_len, gboolean upper_case, char *buf, gsize buf_len);

gboolean nm_utils_is_valid_iface_name_utf8safe (const char *utf8safe_name);

GSList *    _nm_utils_hash_values_to_slist (GHashTable *hash);

GHashTable *_nm_utils_copy_strdict (GHashTable *strdict);

typedef gpointer (*NMUtilsCopyFunc) (gpointer);

const char **_nm_ip_address_get_attribute_names (const NMIPAddress *addr, gboolean sorted, guint *out_length);

void _nm_setting_wired_clear_s390_options (NMSettingWired *setting);

gboolean _nm_ip_route_attribute_validate_all (const NMIPRoute *route);
const char **_nm_ip_route_get_attribute_names (const NMIPRoute *route, gboolean sorted, guint *out_length);
GHashTable *_nm_ip_route_get_attributes (NMIPRoute *route);

NMSriovVF *_nm_utils_sriov_vf_from_strparts (const char *index, const char *detail, gboolean ignore_unknown, GError **error);
gboolean _nm_sriov_vf_attribute_validate_all (const NMSriovVF *vf, GError **error);

GPtrArray *_nm_utils_copy_array (const GPtrArray *array,
                                 NMUtilsCopyFunc copy_func,
                                 GDestroyNotify free_func);
GPtrArray *_nm_utils_copy_object_array (const GPtrArray *array);

gssize _nm_utils_ptrarray_find_first (gconstpointer *list, gssize len, gconstpointer needle);

GSList *    _nm_utils_strv_to_slist (char **strv, gboolean deep_copy);
char **     _nm_utils_slist_to_strv (const GSList *slist, gboolean deep_copy);

GPtrArray * _nm_utils_strv_to_ptrarray (char **strv);
char **     _nm_utils_ptrarray_to_strv (const GPtrArray *ptrarray);

gboolean _nm_utils_check_file (const char *filename,
                               gint64 check_owner,
                               NMUtilsCheckFilePredicate check_file,
                               gpointer user_data,
                               struct stat *out_st,
                               GError **error);

gboolean _nm_utils_check_module_file (const char *name,
                                      int check_owner,
                                      NMUtilsCheckFilePredicate check_file,
                                      gpointer user_data,
                                      GError **error);

/*****************************************************************************/

typedef struct _NMUuid {
	guchar uuid[16];
} NMUuid;

NMUuid *_nm_utils_uuid_parse (const char *str,
                              NMUuid *uuid);
char *_nm_utils_uuid_unparse (const NMUuid *uuid,
                              char *out_str /*[37]*/);
NMUuid *_nm_utils_uuid_generate_random (NMUuid *out_uuid);

gboolean nm_utils_uuid_is_null (const NMUuid *uuid);

#define NM_UTILS_UUID_TYPE_LEGACY            0
#define NM_UTILS_UUID_TYPE_VERSION3          3
#define NM_UTILS_UUID_TYPE_VERSION5          5

NMUuid *nm_utils_uuid_generate_from_string_bin (NMUuid *uuid, const char *s, gssize slen, int uuid_type, gpointer type_args);

char *nm_utils_uuid_generate_from_string (const char *s, gssize slen, int uuid_type, gpointer type_args);

/* arbitrarily chosen namespace UUID for _nm_utils_uuid_generate_from_strings() */
#define NM_UTILS_UUID_NS "b425e9fb-7598-44b4-9e3b-5a2e3aaa4905"

char *_nm_utils_uuid_generate_from_strings (const char *string1, ...) G_GNUC_NULL_TERMINATED;

char *nm_utils_uuid_generate_buf_ (char *buf);
#define nm_utils_uuid_generate_buf(buf) \
	({ \
		G_STATIC_ASSERT (sizeof (buf) == G_N_ELEMENTS (buf) && sizeof (buf) >= 37); \
		nm_utils_uuid_generate_buf_ (buf); \
	})
#define nm_utils_uuid_generate_a() (nm_utils_uuid_generate_buf_ (g_alloca (37)))

void _nm_dbus_errors_init (void);

extern gboolean _nm_utils_is_manager_process;

gboolean _nm_dbus_typecheck_response (GVariant *response,
                                      const GVariantType *reply_type,
                                      GError **error);

gulong _nm_dbus_signal_connect_data (GDBusProxy *proxy,
                                     const char *signal_name,
                                     const GVariantType *signature,
                                     GCallback c_handler,
                                     gpointer data,
                                     GClosureNotify destroy_data,
                                     GConnectFlags connect_flags);
#define _nm_dbus_signal_connect(proxy, name, signature, handler, data) \
	_nm_dbus_signal_connect_data (proxy, name, signature, handler, data, NULL, (GConnectFlags) 0)

GVariant *_nm_dbus_proxy_call_finish (GDBusProxy           *proxy,
                                      GAsyncResult         *res,
                                      const GVariantType   *reply_type,
                                      GError              **error);

GVariant *_nm_dbus_proxy_call_sync   (GDBusProxy           *proxy,
                                      const char           *method_name,
                                      GVariant             *parameters,
                                      const GVariantType   *reply_type,
                                      GDBusCallFlags        flags,
                                      int                   timeout_msec,
                                      GCancellable         *cancellable,
                                      GError              **error);

GVariant * _nm_dbus_connection_call_finish (GDBusConnection *dbus_connection,
                                            GAsyncResult *result,
                                            const GVariantType *reply_type,
                                            GError **error);

gboolean _nm_dbus_error_has_name (GError     *error,
                                  const char *dbus_error_name);

/*****************************************************************************/

char *_nm_utils_ssid_to_string_arr (const guint8 *ssid, gsize len);
char *_nm_utils_ssid_to_string (GBytes *ssid);
char *_nm_utils_ssid_to_utf8 (GBytes *ssid);
gboolean _nm_utils_is_empty_ssid (GBytes *ssid);

/*****************************************************************************/

gboolean _nm_vpn_plugin_info_check_file (const char *filename,
                                         gboolean check_absolute,
                                         gboolean do_validate_filename,
                                         gint64 check_owner,
                                         NMUtilsCheckFilePredicate check_file,
                                         gpointer user_data,
                                         GError **error);

const char *_nm_vpn_plugin_info_get_default_dir_etc (void);
const char *_nm_vpn_plugin_info_get_default_dir_lib (void);
const char *_nm_vpn_plugin_info_get_default_dir_user (void);

GSList *_nm_vpn_plugin_info_list_load_dir (const char *dirname,
                                           gboolean do_validate_filename,
                                           gint64 check_owner,
                                           NMUtilsCheckFilePredicate check_file,
                                           gpointer user_data);

/*****************************************************************************/

typedef struct {
	const char *name;
	gboolean numeric;
	gboolean ipv6_only;
} NMUtilsDNSOptionDesc;

extern const NMUtilsDNSOptionDesc _nm_utils_dns_option_descs[];

gboolean    _nm_utils_dns_option_validate (const char *option, char **out_name,
                                           long *out_value, gboolean ipv6,
                                           const NMUtilsDNSOptionDesc *option_descs);
gssize      _nm_utils_dns_option_find_idx (GPtrArray *array, const char *option);

/*****************************************************************************/

typedef struct _NMUtilsStrStrDictKey NMUtilsStrStrDictKey;
guint                 _nm_utils_strstrdictkey_hash   (gconstpointer a);
gboolean              _nm_utils_strstrdictkey_equal  (gconstpointer a, gconstpointer b);
NMUtilsStrStrDictKey *_nm_utils_strstrdictkey_create (const char *v1, const char *v2);

#define _nm_utils_strstrdictkey_static(v1, v2) \
    ( (NMUtilsStrStrDictKey *) ("\03" v1 "\0" v2 "") )

/*****************************************************************************/

gboolean _nm_setting_vlan_set_priorities (NMSettingVlan *setting,
                                          NMVlanPriorityMap map,
                                          const NMVlanQosMapping *qos_map,
                                          guint n_qos_map);
void     _nm_setting_vlan_get_priorities (NMSettingVlan *setting,
                                          NMVlanPriorityMap map,
                                          NMVlanQosMapping **out_qos_map,
                                          guint *out_n_qos_map);

/*****************************************************************************/

struct ether_addr;

gboolean _nm_utils_generate_mac_address_mask_parse (const char *value,
                                                    struct ether_addr *out_mask,
                                                    struct ether_addr **out_ouis,
                                                    gsize *out_ouis_len,
                                                    GError **error);

/*****************************************************************************/

static inline gpointer
_nm_connection_get_setting (NMConnection *connection,
                            GType type)
{
	return (gpointer) nm_connection_get_setting (connection, type);
}

NMSettingIPConfig *nm_connection_get_setting_ip_config (NMConnection *connection,
                                                        int addr_family);

/*****************************************************************************/

typedef enum {
	NM_BOND_OPTION_TYPE_INT,
	NM_BOND_OPTION_TYPE_STRING,
	NM_BOND_OPTION_TYPE_BOTH,
	NM_BOND_OPTION_TYPE_IP,
	NM_BOND_OPTION_TYPE_MAC,
	NM_BOND_OPTION_TYPE_IFNAME,
} NMBondOptionType;

NMBondOptionType
_nm_setting_bond_get_option_type (NMSettingBond *setting, const char *name);

/*****************************************************************************/

/* nm_connection_get_uuid() asserts against NULL, which is the right thing to
 * do in order to catch bugs. However, sometimes that behavior is inconvenient.
 * Just try or return NULL. */

static inline const char *
_nm_connection_get_id (NMConnection *connection)
{
	return connection ? nm_connection_get_id (connection) : NULL;
}

static inline const char *
_nm_connection_get_uuid (NMConnection *connection)
{
	return connection ? nm_connection_get_uuid (connection) : NULL;
}

NMConnectionMultiConnect _nm_connection_get_multi_connect (NMConnection *connection);

/*****************************************************************************/

typedef enum {
	NM_BOND_MODE_UNKNOWN = 0,
	NM_BOND_MODE_ROUNDROBIN,
	NM_BOND_MODE_ACTIVEBACKUP,
	NM_BOND_MODE_XOR,
	NM_BOND_MODE_BROADCAST,
	NM_BOND_MODE_8023AD,
	NM_BOND_MODE_TLB,
	NM_BOND_MODE_ALB,
} NMBondMode;

NMBondMode _nm_setting_bond_mode_from_string (const char *str);
gboolean _nm_setting_bond_option_supported (const char *option, NMBondMode mode);

/*****************************************************************************/

NMSettingBluetooth *_nm_connection_get_setting_bluetooth_for_nap (NMConnection *connection);

/*****************************************************************************/

const char *nm_utils_inet_ntop (int addr_family, gconstpointer addr, char *dst);

static inline char *
nm_utils_inet4_ntop_dup (in_addr_t addr)
{
	char buf[NM_UTILS_INET_ADDRSTRLEN];

	return g_strdup (nm_utils_inet4_ntop (addr, buf));
}

static inline char *
nm_utils_inet6_ntop_dup (const struct in6_addr *addr)
{
	char buf[NM_UTILS_INET_ADDRSTRLEN];

	return g_strdup (nm_utils_inet6_ntop (addr, buf));
}

static inline char *
nm_utils_inet_ntop_dup (int addr_family, gconstpointer addr)
{
	char buf[NM_UTILS_INET_ADDRSTRLEN];

	return g_strdup (nm_utils_inet_ntop (addr_family, addr, buf));
}

gboolean _nm_utils_inet6_is_token (const struct in6_addr *in6addr);

/*****************************************************************************/

NMTeamLinkWatcher *_nm_team_link_watcher_ref (NMTeamLinkWatcher *watcher);

int nm_team_link_watcher_cmp (const NMTeamLinkWatcher *watcher, const NMTeamLinkWatcher *other);

int nm_team_link_watchers_cmp (const NMTeamLinkWatcher *const*a,
                               const NMTeamLinkWatcher *const*b,
                               gsize len,
                               gboolean ignore_order);

gboolean nm_team_link_watchers_equal (const GPtrArray *a,
                                      const GPtrArray *b,
                                      gboolean ignore_order);

/*****************************************************************************/

guint32 _nm_utils_parse_tc_handle                (const char *str,
                                                  GError **error);
void _nm_utils_string_append_tc_parent           (GString *string,
                                                  const char *prefix,
                                                  guint32 parent);
void _nm_utils_string_append_tc_qdisc_rest       (GString *string,
                                                  NMTCQdisc *qdisc);
gboolean _nm_utils_string_append_tc_tfilter_rest (GString *string,
                                                  NMTCTfilter *tfilter,
                                                  GError **error);

GHashTable *_nm_tc_qdisc_get_attributes (NMTCQdisc *qdisc);
GHashTable *_nm_tc_action_get_attributes (NMTCAction *action);

/*****************************************************************************/

static inline gboolean
_nm_connection_type_is_master (const char *type)
{
	return (NM_IN_STRSET (type,
	                      NM_SETTING_BOND_SETTING_NAME,
	                      NM_SETTING_BRIDGE_SETTING_NAME,
	                      NM_SETTING_TEAM_SETTING_NAME,
	                      NM_SETTING_OVS_BRIDGE_SETTING_NAME,
	                      NM_SETTING_OVS_PORT_SETTING_NAME));
}

/*****************************************************************************/

gboolean _nm_utils_dhcp_duid_valid (const char *duid, GBytes **out_duid_bin);

/*****************************************************************************/

gboolean _nm_setting_sriov_sort_vfs (NMSettingSriov *setting);
gboolean _nm_setting_bridge_port_sort_vlans (NMSettingBridgePort *setting);
gboolean _nm_setting_bridge_sort_vlans (NMSettingBridge *setting);

/*****************************************************************************/

typedef struct _NMSockAddrEndpoint NMSockAddrEndpoint;

NMSockAddrEndpoint *nm_sock_addr_endpoint_new (const char *endpoint);

NMSockAddrEndpoint *nm_sock_addr_endpoint_ref (NMSockAddrEndpoint *self);
void nm_sock_addr_endpoint_unref (NMSockAddrEndpoint *self);

const char *nm_sock_addr_endpoint_get_endpoint (NMSockAddrEndpoint *self);
const char *nm_sock_addr_endpoint_get_host (NMSockAddrEndpoint *self);
gint32 nm_sock_addr_endpoint_get_port (NMSockAddrEndpoint *self);

gboolean nm_sock_addr_endpoint_get_fixed_sockaddr (NMSockAddrEndpoint *self,
                                                   gpointer sockaddr);

#define nm_auto_unref_sockaddrendpoint nm_auto(_nm_auto_unref_sockaddrendpoint)
NM_AUTO_DEFINE_FCN0 (NMSockAddrEndpoint *, _nm_auto_unref_sockaddrendpoint, nm_sock_addr_endpoint_unref)

/*****************************************************************************/

NMSockAddrEndpoint *_nm_wireguard_peer_get_endpoint (const NMWireGuardPeer *self);
void _nm_wireguard_peer_set_endpoint (NMWireGuardPeer *self,
                                      NMSockAddrEndpoint *endpoint);

void _nm_wireguard_peer_set_public_key_bin (NMWireGuardPeer *self,
                                            const guint8 public_key[static NM_WIREGUARD_PUBLIC_KEY_LEN]);

/*****************************************************************************/

const NMIPAddr *nm_ip_routing_rule_get_from_bin (const NMIPRoutingRule *self);
void nm_ip_routing_rule_set_from_bin (NMIPRoutingRule *self,
                                      gconstpointer from,
                                      guint8 len);

const NMIPAddr *nm_ip_routing_rule_get_to_bin (const NMIPRoutingRule *self);
void nm_ip_routing_rule_set_to_bin (NMIPRoutingRule *self,
                                    gconstpointer to,
                                    guint8 len);

gboolean nm_ip_routing_rule_get_xifname_bin (const NMIPRoutingRule *self,
                                             gboolean iif /* or else oif */,
                                             char out_xifname[static 16]);

#define NM_IP_ROUTING_RULE_ATTR_ACTION                "action"
#define NM_IP_ROUTING_RULE_ATTR_DPORT_END             "dport-end"
#define NM_IP_ROUTING_RULE_ATTR_DPORT_START           "dport-start"
#define NM_IP_ROUTING_RULE_ATTR_FAMILY                "family"
#define NM_IP_ROUTING_RULE_ATTR_FROM                  "from"
#define NM_IP_ROUTING_RULE_ATTR_FROM_LEN              "from-len"
#define NM_IP_ROUTING_RULE_ATTR_FWMARK                "fwmark"
#define NM_IP_ROUTING_RULE_ATTR_FWMASK                "fwmask"
#define NM_IP_ROUTING_RULE_ATTR_IIFNAME               "iifname"
#define NM_IP_ROUTING_RULE_ATTR_INVERT                "invert"
#define NM_IP_ROUTING_RULE_ATTR_IPPROTO               "ipproto"
#define NM_IP_ROUTING_RULE_ATTR_OIFNAME               "oifname"
#define NM_IP_ROUTING_RULE_ATTR_PRIORITY              "priority"
#define NM_IP_ROUTING_RULE_ATTR_SPORT_END             "sport-end"
#define NM_IP_ROUTING_RULE_ATTR_SPORT_START           "sport-start"
#define NM_IP_ROUTING_RULE_ATTR_SUPPRESS_PREFIXLENGTH "suppress-prefixlength"
#define NM_IP_ROUTING_RULE_ATTR_TABLE                 "table"
#define NM_IP_ROUTING_RULE_ATTR_TO                    "to"
#define NM_IP_ROUTING_RULE_ATTR_TOS                   "tos"
#define NM_IP_ROUTING_RULE_ATTR_TO_LEN                "to-len"

NMIPRoutingRule *nm_ip_routing_rule_from_dbus (GVariant *variant,
                                               gboolean strict,
                                               GError **error);
GVariant *nm_ip_routing_rule_to_dbus (const NMIPRoutingRule *self);

/*****************************************************************************/

typedef struct _NMSettInfoSetting  NMSettInfoSetting;
typedef struct _NMSettInfoProperty NMSettInfoProperty;

typedef GVariant *(*NMSettInfoPropToDBusFcn)            (const NMSettInfoSetting *sett_info,
                                                         guint property_idx,
                                                         NMConnection  *connection,
                                                         NMSetting     *setting,
                                                         NMConnectionSerializationFlags flags,
                                                         const NMConnectionSerializationOptions *options);
typedef gboolean  (*NMSettInfoPropFromDBusFcn)          (NMSetting     *setting,
                                                         GVariant      *connection_dict,
                                                         const char    *property,
                                                         GVariant      *value,
                                                         NMSettingParseFlags parse_flags,
                                                         GError       **error);
typedef gboolean  (*NMSettInfoPropMissingFromDBusFcn)   (NMSetting     *setting,
                                                         GVariant      *connection_dict,
                                                         const char    *property,
                                                         NMSettingParseFlags parse_flags,
                                                         GError       **error);
typedef GVariant *(*NMSettInfoPropGPropToDBusFcn)       (const GValue *from);
typedef void      (*NMSettInfoPropGPropFromDBusFcn)     (GVariant *from,
                                                         GValue *to);

struct _NMSettInfoProperty {
	const char *name;
	GParamSpec *param_spec;

	const GVariantType *dbus_type;

	NMSettInfoPropToDBusFcn            to_dbus_fcn;
	NMSettInfoPropFromDBusFcn          from_dbus_fcn;
	NMSettInfoPropMissingFromDBusFcn   missing_from_dbus_fcn;

	/* Simpler variants of @to_dbus_fcn/@from_dbus_fcn that operate solely
	 * on the GValue value of the GObject property. */
	NMSettInfoPropGPropToDBusFcn       gprop_to_dbus_fcn;
	NMSettInfoPropGPropFromDBusFcn     gprop_from_dbus_fcn;
};

typedef struct {
	const GVariantType *(*get_variant_type) (const struct _NMSettInfoSetting *sett_info,
	                                         const char *name,
	                                         GError **error);
} NMSettInfoSettGendata;

typedef struct {
	/* if set, then this setting class has no own fields. Instead, its
	 * data is entirely based on gendata. Meaning: it tracks all data
	 * as native GVariants.
	 * It might have some GObject properties, but these are merely accessors
	 * to the underlying gendata.
	 *
	 * Note, that at the moment there are few hooks, to customize the behavior
	 * of the setting further. They are currently unneeded. This is desired,
	 * but could be added when there is a good reason.
	 *
	 * However, a few hooks there are... see NMSettInfoSettGendata. */
	const NMSettInfoSettGendata *gendata_info;
} NMSettInfoSettDetail;

struct _NMSettInfoSetting {
	NMSettingClass *setting_class;

	/* the properties, sorted by property name. */
	const NMSettInfoProperty *property_infos;

	/* the @property_infos list is sorted by property name. For some uses we need
	 * a different sort order. If @property_infos_sorted is set, this is the order
	 * instead. It is used for:
	 *
	 *   - nm_setting_enumerate_values()
	 *   - keyfile writer adding keys to the group.
	 *
	 * Note that currently only NMSettingConnection implements here a sort order
	 * that differs from alphabetical sort of the property names.
	 */
	const NMSettInfoProperty *const*property_infos_sorted;

	guint property_infos_len;
	NMSettInfoSettDetail detail;
};

static inline const NMSettInfoProperty *
_nm_sett_info_property_info_get_sorted (const NMSettInfoSetting *sett_info,
                                        guint idx)
{
	nm_assert (sett_info);
	nm_assert (idx < sett_info->property_infos_len);
	nm_assert (!sett_info->property_infos_sorted || sett_info->property_infos_sorted[idx]);

	return   sett_info->property_infos_sorted
	       ? sett_info->property_infos_sorted[idx]
	       : &sett_info->property_infos[idx];
}

const NMSettInfoProperty *_nm_sett_info_setting_get_property_info (const NMSettInfoSetting *sett_info,
                                                                   const char *property_name);

const NMSettInfoSetting *_nm_setting_class_get_sett_info (NMSettingClass *setting_class);

static inline const NMSettInfoProperty *
_nm_setting_class_get_property_info (NMSettingClass *setting_class,
                                     const char *property_name)
{
	return _nm_sett_info_setting_get_property_info (_nm_setting_class_get_sett_info (setting_class),
	                                                property_name);
}

/*****************************************************************************/

gboolean _nm_setting_compare (NMConnection *con_a,
                              NMSetting *set_a,
                              NMConnection *con_b,
                              NMSetting *set_b,
                              NMSettingCompareFlags flags);

gboolean _nm_setting_diff (NMConnection *con_a,
                           NMSetting *set_a,
                           NMConnection *con_b,
                           NMSetting *set_b,
                           NMSettingCompareFlags flags,
                           gboolean invert_results,
                           GHashTable **results);

NMSetting8021xCKScheme _nm_setting_802_1x_cert_get_scheme (GBytes *bytes, GError **error);

GBytes *_nm_setting_802_1x_cert_value_to_bytes (NMSetting8021xCKScheme scheme,
                                                const guint8 *val_bin,
                                                gssize val_len,
                                                GError **error);

/*****************************************************************************/

static inline gboolean
_nm_connection_serialize_secrets (NMConnectionSerializationFlags flags,
                                  NMSettingSecretFlags secret_flags)
{
	if (NM_FLAGS_HAS (flags, NM_CONNECTION_SERIALIZE_NO_SECRETS))
		return FALSE;
	if (   NM_FLAGS_HAS (flags, NM_CONNECTION_SERIALIZE_WITH_SECRETS_AGENT_OWNED)
	    && !NM_FLAGS_HAS (secret_flags, NM_SETTING_SECRET_FLAG_AGENT_OWNED))
		return FALSE;
	return TRUE;
}

void _nm_connection_clear_secrets_by_secret_flags (NMConnection *self,
                                                   NMSettingSecretFlags filter_flags);

GVariant *_nm_connection_for_each_secret (NMConnection *self,
                                          GVariant *secrets,
                                          gboolean remove_non_secrets,
                                          _NMConnectionForEachSecretFunc callback,
                                          gpointer callback_data);

typedef gboolean (*NMConnectionFindSecretFunc) (NMSettingSecretFlags flags,
                                                gpointer user_data);

gboolean _nm_connection_find_secret (NMConnection *self,
                                     GVariant *secrets,
                                     NMConnectionFindSecretFunc callback,
                                     gpointer callback_data);

/*****************************************************************************/

gboolean nm_utils_base64secret_normalize (const char *base64_key,
                                          gsize required_key_len,
                                          char **out_base64_key_norm);

/*****************************************************************************/

void _nm_bridge_vlan_str_append_rest (const NMBridgeVlan *vlan,
                                      GString *string,
                                      gboolean leading_space);

gboolean nm_utils_connection_is_adhoc_wpa (NMConnection *connection);

const char *nm_utils_wifi_freq_to_band (guint32 freq);

#endif
