/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2014 - 2018 Red Hat, Inc.
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
#if !((NETWORKMANAGER_COMPILATION) &NM_NETWORKMANAGER_COMPILATION_WITH_LIBNM_CORE_INTERNAL)
#error Cannot use this header.
#endif

#include "libnm-base/nm-base.h"
#include "nm-connection.h"
#include "nm-core-enum-types.h"
#include "nm-meta-setting-base.h"
#include "nm-setting-6lowpan.h"
#include "nm-setting-8021x.h"
#include "nm-setting-adsl.h"
#include "nm-setting-bluetooth.h"
#include "nm-setting-bond.h"
#include "nm-setting-bond-port.h"
#include "nm-setting-bridge-port.h"
#include "nm-setting-bridge.h"
#include "nm-setting-cdma.h"
#include "nm-setting-connection.h"
#include "nm-setting-dcb.h"
#include "nm-setting-dummy.h"
#include "nm-setting-generic.h"
#include "nm-setting-gsm.h"
#include "nm-setting-hostname.h"
#include "nm-setting-infiniband.h"
#include "nm-setting-ip-tunnel.h"
#include "nm-setting-ip4-config.h"
#include "nm-setting-ip6-config.h"
#include "nm-setting-loopback.h"
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
#include "nm-setting-user.h"
#include "nm-setting-veth.h"
#include "nm-setting-vlan.h"
#include "nm-setting-vpn.h"
#include "nm-setting-vrf.h"
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
#include "libnm-core-aux-intern/nm-libnm-core-utils.h"
#include "libnm-glib-aux/nm-value-type.h"

#define NM_USER_TAG_ORIGIN "org.freedesktop.NetworkManager.origin"

/*****************************************************************************/

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

#define NM_SETTING_SECRET_FLAG_ALL                                                            \
    ((NMSettingSecretFlags) (NM_SETTING_SECRET_FLAG_NONE | NM_SETTING_SECRET_FLAG_AGENT_OWNED \
                             | NM_SETTING_SECRET_FLAG_NOT_SAVED                               \
                             | NM_SETTING_SECRET_FLAG_NOT_REQUIRED))

static inline gboolean
_nm_setting_secret_flags_valid(NMSettingSecretFlags flags)
{
    return !NM_FLAGS_ANY(flags, ~NM_SETTING_SECRET_FLAG_ALL);
}

/*****************************************************************************/

const char *
nm_bluetooth_capability_to_string(NMBluetoothCapabilities capabilities, char *buf, gsize len);

/*****************************************************************************/

#define NM_DHCP_HOSTNAME_FLAGS_FQDN_MASK                                         \
    (NM_DHCP_HOSTNAME_FLAG_FQDN_ENCODED | NM_DHCP_HOSTNAME_FLAG_FQDN_SERV_UPDATE \
     | NM_DHCP_HOSTNAME_FLAG_FQDN_NO_UPDATE | NM_DHCP_HOSTNAME_FLAG_FQDN_CLEAR_FLAGS)

#define NM_DHCP_HOSTNAME_FLAGS_FQDN_DEFAULT_IP4 \
    (NM_DHCP_HOSTNAME_FLAG_FQDN_ENCODED | NM_DHCP_HOSTNAME_FLAG_FQDN_SERV_UPDATE)

#define NM_DHCP_HOSTNAME_FLAGS_FQDN_DEFAULT_IP6 NM_DHCP_HOSTNAME_FLAG_FQDN_SERV_UPDATE

/*****************************************************************************/

static inline _NMSettingWiredWakeOnLan
_NM_SETTING_WIRED_WAKE_ON_LAN_CAST(NMSettingWiredWakeOnLan v)
{
    /* _NMSettingWiredWakeOnLan and NMSettingWiredWakeOnLan enums are really
     * the same.
     *
     * The former is used by libnm-platform (which should have no libnm-core* dependency),
     * the latter is public API in libnm-core-public. A unit test ensures they are exactly the same,
     * so we can just cast them. */
    return (_NMSettingWiredWakeOnLan) v;
}

static inline _NMSettingWirelessWakeOnWLan
_NM_SETTING_WIRELESS_WAKE_ON_WLAN_CAST(NMSettingWirelessWakeOnWLan v)
{
    return (_NMSettingWirelessWakeOnWLan) v;
}

static inline NM80211Mode
NM_802_11_MODE_CAST(_NM80211Mode v)
{
    return (NM80211Mode) v;
}

static inline NMVlanFlags
NM_VLAN_FLAGS_CAST(_NMVlanFlags v)
{
    return (NMVlanFlags) v;
}

/*****************************************************************************/

static inline NMTernary
NM_TERNARY_FROM_OPTION_BOOL(NMOptionBool v)
{
    nm_assert_is_ternary(v);

    return (int) v;
}

static inline NMOptionBool
NM_TERNARY_TO_OPTION_BOOL(NMTernary v)
{
    nm_assert_is_ternary(v);

    return (int) v;
}

/*****************************************************************************/

NMSetting **_nm_connection_get_settings_arr(NMConnection *connection);

typedef enum /*< skip >*/ {
    NM_SETTING_PARSE_FLAGS_NONE        = 0,
    NM_SETTING_PARSE_FLAGS_STRICT      = 1LL << 0,
    NM_SETTING_PARSE_FLAGS_BEST_EFFORT = 1LL << 1,
    NM_SETTING_PARSE_FLAGS_NORMALIZE   = 1LL << 2,

    _NM_SETTING_PARSE_FLAGS_LAST,
    NM_SETTING_PARSE_FLAGS_ALL = ((_NM_SETTING_PARSE_FLAGS_LAST - 1) << 1) - 1,
} NMSettingParseFlags;

gboolean _nm_connection_replace_settings(NMConnection       *connection,
                                         GVariant           *new_settings,
                                         NMSettingParseFlags parse_flags,
                                         GError            **error);

gpointer _nm_connection_check_main_setting(NMConnection *connection,
                                           const char   *setting_name,
                                           GError      **error);

typedef struct {
    struct {
        guint64 val;
        bool    has;
    } timestamp;

    const char *const *seen_bssids;

} NMConnectionSerializationOptions;

gboolean nm_connection_serialization_options_equal(const NMConnectionSerializationOptions *a,
                                                   const NMConnectionSerializationOptions *b);

GVariant *nm_connection_to_dbus_full(NMConnection                           *connection,
                                     NMConnectionSerializationFlags          flags,
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

gboolean
_nm_connection_aggregate(NMConnection *connection, NMConnectionAggregateType type, gpointer arg);

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
    NM_SETTING_VERIFY_SUCCESS            = TRUE,
    NM_SETTING_VERIFY_ERROR              = FALSE,
    NM_SETTING_VERIFY_NORMALIZABLE       = 2,
    NM_SETTING_VERIFY_NORMALIZABLE_ERROR = 3,
} NMSettingVerifyResult;

NMSettingVerifyResult _nm_connection_verify(NMConnection *connection, GError **error);

gboolean _nm_connection_ensure_normalized(NMConnection  *connection,
                                          gboolean       allow_modify,
                                          const char    *expected_uuid,
                                          gboolean       coerce_uuid,
                                          NMConnection **out_connection_clone,
                                          GError       **error);

gboolean _nm_connection_remove_setting(NMConnection *connection, GType setting_type);

#if NM_MORE_ASSERTS
extern const char _nm_assert_connection_unchanging_user_data;
void              nm_assert_connection_unchanging(NMConnection *connection);
#else
static inline void
nm_assert_connection_unchanging(NMConnection *connection)
{}
#endif

NMConnection *_nm_simple_connection_new_from_dbus(GVariant           *dict,
                                                  NMSettingParseFlags parse_flags,
                                                  GError            **error);

NMSettingPriority _nm_setting_get_setting_priority(NMSetting *setting);

gboolean _nm_setting_get_property(NMSetting *setting, const char *name, GValue *value);

/*****************************************************************************/

GHashTable *_nm_setting_option_hash(NMSetting *setting, gboolean create_if_necessary);

void _nm_setting_option_notify(NMSetting *setting, gboolean keys_changed);

guint _nm_setting_option_get_all(NMSetting          *setting,
                                 const char *const **out_names,
                                 GVariant *const   **out_values);

gboolean _nm_setting_option_clear(NMSetting *setting, const char *optname);

/*****************************************************************************/

guint nm_setting_ethtool_init_features(
    NMSettingEthtool *setting,
    NMOptionBool     *requested /* indexed by NMEthtoolID - _NM_ETHTOOL_ID_FEATURE_FIRST */);

/*****************************************************************************/

#define NM_UTILS_HWADDR_LEN_MAX_STR (NM_UTILS_HWADDR_LEN_MAX * 3)

gboolean nm_utils_is_valid_iface_name_utf8safe(const char *utf8safe_name);

GSList *_nm_utils_hash_values_to_slist(GHashTable *hash);

GHashTable *_nm_utils_copy_strdict(GHashTable *strdict);

typedef gpointer (*NMUtilsCopyFunc)(gpointer);

const char **
_nm_ip_address_get_attribute_names(const NMIPAddress *addr, gboolean sorted, guint *out_length);

#define NM_SETTING_WIRED_S390_OPTION_MAX_LEN 200u

void     _nm_setting_wired_clear_s390_options(NMSettingWired *setting);
gboolean _nm_setting_wired_is_valid_s390_option(const char *option);
gboolean _nm_setting_wired_is_valid_s390_option_value(const char *name, const char *option);

gboolean _nm_ip_route_attribute_validate_all(const NMIPRoute *route, GError **error);
const char **
_nm_ip_route_get_attribute_names(const NMIPRoute *route, gboolean sorted, guint *out_length);
GHashTable *_nm_ip_route_get_attributes(NMIPRoute *route);

NMSriovVF *_nm_utils_sriov_vf_from_strparts(const char *index,
                                            const char *detail,
                                            gboolean    ignore_unknown,
                                            GError    **error);
gboolean   _nm_sriov_vf_attribute_validate_all(const NMSriovVF *vf, GError **error);

GPtrArray *
_nm_utils_copy_array(const GPtrArray *array, NMUtilsCopyFunc copy_func, GDestroyNotify free_func);
GPtrArray *_nm_utils_copy_object_array(const GPtrArray *array);

GSList *nm_strv_to_gslist(char **strv, gboolean deep_copy);
char  **_nm_utils_slist_to_strv(const GSList *slist, gboolean deep_copy);

GPtrArray *nm_strv_to_ptrarray(char **strv);
char     **_nm_utils_ptrarray_to_strv(const GPtrArray *ptrarray);

gboolean _nm_utils_check_file(const char               *filename,
                              gint64                    check_owner,
                              NMUtilsCheckFilePredicate check_file,
                              gpointer                  user_data,
                              struct stat              *out_st,
                              GError                  **error);

gboolean _nm_utils_check_module_file(const char               *name,
                                     int                       check_owner,
                                     NMUtilsCheckFilePredicate check_file,
                                     gpointer                  user_data,
                                     GError                  **error);

/*****************************************************************************/

void _nm_dbus_errors_init(void);

extern gboolean _nm_utils_is_manager_process;

/*****************************************************************************/

char *_nm_utils_ssid_to_utf8(GBytes *ssid);

/*****************************************************************************/

gboolean _nm_vpn_plugin_info_check_file(const char               *filename,
                                        gboolean                  check_absolute,
                                        gboolean                  do_validate_filename,
                                        gint64                    check_owner,
                                        NMUtilsCheckFilePredicate check_file,
                                        gpointer                  user_data,
                                        GError                  **error);

const char *_nm_vpn_plugin_info_get_default_dir_etc(void);
const char *_nm_vpn_plugin_info_get_default_dir_lib(void);
const char *_nm_vpn_plugin_info_get_default_dir_user(void);

GSList *_nm_vpn_plugin_info_list_load_dir(const char               *dirname,
                                          gboolean                  do_validate_filename,
                                          gint64                    check_owner,
                                          NMUtilsCheckFilePredicate check_file,
                                          gpointer                  user_data);

/*****************************************************************************/

GHashTable *_nm_setting_ovs_external_ids_get_data(NMSettingOvsExternalIDs *self);
GHashTable *_nm_setting_ovs_other_config_get_data(NMSettingOvsOtherConfig *self);

/*****************************************************************************/

typedef struct {
    const char *name;
    gboolean    numeric;
    gboolean    ipv6_only;
} NMUtilsDNSOptionDesc;

extern const NMUtilsDNSOptionDesc _nm_utils_dns_option_descs[];

gboolean _nm_utils_dns_option_validate(const char                 *option,
                                       char                      **out_name,
                                       long                       *out_value,
                                       gboolean                    ipv6,
                                       const NMUtilsDNSOptionDesc *option_descs);
gssize   _nm_utils_dns_option_find_idx(GPtrArray *array, const char *option);

int nm_setting_ip_config_next_valid_dns_option(NMSettingIPConfig *setting, guint idx);

/*****************************************************************************/

typedef struct _NMUtilsStrStrDictKey NMUtilsStrStrDictKey;
guint                                _nm_utils_strstrdictkey_hash(gconstpointer a);
gboolean              _nm_utils_strstrdictkey_equal(gconstpointer a, gconstpointer b);
NMUtilsStrStrDictKey *_nm_utils_strstrdictkey_create(const char *v1, const char *v2);

#define _nm_utils_strstrdictkey_static(v1, v2) ((NMUtilsStrStrDictKey *) ("\03" v1 "\0" v2 ""))

/*****************************************************************************/

gboolean _nm_setting_vlan_set_priorities(NMSettingVlan          *setting,
                                         NMVlanPriorityMap       map,
                                         const NMVlanQosMapping *qos_map,
                                         guint                   n_qos_map);
void     _nm_setting_vlan_get_priorities(NMSettingVlan     *setting,
                                         NMVlanPriorityMap  map,
                                         NMVlanQosMapping **out_qos_map,
                                         guint             *out_n_qos_map);

/*****************************************************************************/

struct ether_addr;

gboolean _nm_utils_generate_mac_address_mask_parse(const char         *value,
                                                   struct ether_addr  *out_mask,
                                                   struct ether_addr **out_ouis,
                                                   gsize              *out_ouis_len,
                                                   GError            **error);

/*****************************************************************************/

static inline gpointer
_nm_connection_get_setting(NMConnection *connection, GType type)
{
    return (gpointer) nm_connection_get_setting(connection, type);
}

NMSettingIPConfig *nm_connection_get_setting_ip_config(NMConnection *connection, int addr_family);

/*****************************************************************************/

struct _NMRefString;

void _nm_connection_set_path_rstr(NMConnection *connection, struct _NMRefString *path);

struct _NMRefString *_nm_connection_get_path_rstr(NMConnection *connection);

/*****************************************************************************/

typedef enum {
    NM_BOND_OPTION_TYPE_INT,
    NM_BOND_OPTION_TYPE_BOTH,
    NM_BOND_OPTION_TYPE_IP,
    NM_BOND_OPTION_TYPE_MAC,
    NM_BOND_OPTION_TYPE_IFNAME,
} NMBondOptionType;

NMBondOptionType _nm_setting_bond_get_option_type(NMSettingBond *setting, const char *name);

#define NM_BOND_AD_ACTOR_SYSTEM_DEFAULT "00:00:00:00:00:00"

/*****************************************************************************/

/* nm_connection_get_uuid() asserts against NULL, which is the right thing to
 * do in order to catch bugs. However, sometimes that behavior is inconvenient.
 * Just try or return NULL. */

static inline const char *
_nm_connection_get_id(NMConnection *connection)
{
    return connection ? nm_connection_get_id(connection) : NULL;
}

static inline const char *
_nm_connection_get_uuid(NMConnection *connection)
{
    return connection ? nm_connection_get_uuid(connection) : NULL;
}

NMConnectionMultiConnect _nm_connection_get_multi_connect(NMConnection *connection);

/*****************************************************************************/

gboolean _nm_setting_bond_option_supported(const char *option, NMBondMode mode);

guint8  _nm_setting_bond_opt_value_as_u8(NMSettingBond *s_bond, const char *opt);
guint16 _nm_setting_bond_opt_value_as_u16(NMSettingBond *s_bond, const char *opt);
guint32 _nm_setting_bond_opt_value_as_u32(NMSettingBond *s_bond, const char *opt);
bool    _nm_setting_bond_opt_value_as_intbool(NMSettingBond *s_bond, const char *opt);

/*****************************************************************************/

GPtrArray *_nm_setting_bridge_get_vlans(NMSettingBridge *setting);

GPtrArray *_nm_setting_bridge_port_get_vlans(NMSettingBridgePort *setting);

/*****************************************************************************/

GArray *_nm_setting_connection_get_secondaries(NMSettingConnection *setting);

/*****************************************************************************/

NMSettingBluetooth *_nm_connection_get_setting_bluetooth_for_nap(NMConnection *connection);

/*****************************************************************************/

NMTeamLinkWatcher *_nm_team_link_watcher_ref(NMTeamLinkWatcher *watcher);

int nm_team_link_watcher_cmp(const NMTeamLinkWatcher *watcher, const NMTeamLinkWatcher *other);

int nm_team_link_watchers_cmp(const NMTeamLinkWatcher *const *a,
                              const NMTeamLinkWatcher *const *b,
                              gsize                           len,
                              gboolean                        ignore_order);

gboolean nm_team_link_watchers_equal(const GPtrArray *a, const GPtrArray *b, gboolean ignore_order);

/*****************************************************************************/

guint32 _nm_utils_parse_tc_handle(const char *str, GError **error);
void    _nm_utils_string_append_tc_parent(GString *string, const char *prefix, guint32 parent);
void    _nm_utils_string_append_tc_qdisc_rest(GString *string, NMTCQdisc *qdisc);
gboolean
_nm_utils_string_append_tc_tfilter_rest(GString *string, NMTCTfilter *tfilter, GError **error);

GHashTable *_nm_tc_qdisc_get_attributes(NMTCQdisc *qdisc);
GHashTable *_nm_tc_action_get_attributes(NMTCAction *action);

/*****************************************************************************/

static inline gboolean
_nm_connection_type_is_master(const char *type)
{
    return (NM_IN_STRSET(type,
                         NM_SETTING_BOND_SETTING_NAME,
                         NM_SETTING_BRIDGE_SETTING_NAME,
                         NM_SETTING_TEAM_SETTING_NAME,
                         NM_SETTING_OVS_BRIDGE_SETTING_NAME,
                         NM_SETTING_OVS_PORT_SETTING_NAME));
}

/*****************************************************************************/

gboolean _nm_utils_dhcp_duid_valid(const char *duid, GBytes **out_duid_bin);

/*****************************************************************************/

gboolean _nm_setting_sriov_sort_vfs(NMSettingSriov *setting);
gboolean _nm_setting_bridge_port_sort_vlans(NMSettingBridgePort *setting);
gboolean _nm_setting_bridge_sort_vlans(NMSettingBridge *setting);
gboolean _nm_setting_ovs_port_sort_trunks(NMSettingOvsPort *self);

/*****************************************************************************/

typedef struct _NMSockAddrEndpoint NMSockAddrEndpoint;

NMSockAddrEndpoint *nm_sock_addr_endpoint_new(const char *endpoint);

NMSockAddrEndpoint *nm_sock_addr_endpoint_ref(NMSockAddrEndpoint *self);
void                nm_sock_addr_endpoint_unref(NMSockAddrEndpoint *self);

const char *nm_sock_addr_endpoint_get_endpoint(NMSockAddrEndpoint *self);
const char *nm_sock_addr_endpoint_get_host(NMSockAddrEndpoint *self);
gint32      nm_sock_addr_endpoint_get_port(NMSockAddrEndpoint *self);

gboolean nm_sock_addr_endpoint_get_fixed_sockaddr(NMSockAddrEndpoint *self, gpointer sockaddr);

#define nm_auto_unref_sockaddrendpoint nm_auto(_nm_auto_unref_sockaddrendpoint)
NM_AUTO_DEFINE_FCN0(NMSockAddrEndpoint *,
                    _nm_auto_unref_sockaddrendpoint,
                    nm_sock_addr_endpoint_unref);

/*****************************************************************************/

NMSockAddrEndpoint *_nm_wireguard_peer_get_endpoint(const NMWireGuardPeer *self);
void _nm_wireguard_peer_set_endpoint(NMWireGuardPeer *self, NMSockAddrEndpoint *endpoint);

void
_nm_wireguard_peer_set_public_key_bin(NMWireGuardPeer *self,
                                      const guint8 public_key[static NM_WIREGUARD_PUBLIC_KEY_LEN]);

/*****************************************************************************/

const NMIPAddr *nm_ip_routing_rule_get_from_bin(const NMIPRoutingRule *self);
void nm_ip_routing_rule_set_from_bin(NMIPRoutingRule *self, gconstpointer from, guint8 len);

const NMIPAddr *nm_ip_routing_rule_get_to_bin(const NMIPRoutingRule *self);
void            nm_ip_routing_rule_set_to_bin(NMIPRoutingRule *self, gconstpointer to, guint8 len);

gboolean nm_ip_routing_rule_get_xifname_bin(const NMIPRoutingRule *self,
                                            gboolean               iif /* or else oif */,
                                            char                   out_xifname[static 16]);

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
#define NM_IP_ROUTING_RULE_ATTR_UID_RANGE_START       "uid-range-start"
#define NM_IP_ROUTING_RULE_ATTR_UID_RANGE_END         "uid-range-end"

NMIPRoutingRule *nm_ip_routing_rule_from_dbus(GVariant *variant, gboolean strict, GError **error);
GVariant        *nm_ip_routing_rule_to_dbus(const NMIPRoutingRule *self);

/*****************************************************************************/

GVariant *nm_utils_hwaddr_to_dbus(const char *str);

/*****************************************************************************/

typedef struct _NMSettInfoSetting  NMSettInfoSetting;
typedef struct _NMSettInfoProperty NMSettInfoProperty;

const NMSettInfoSetting *nmtst_sett_info_settings(void);

typedef enum _nm_packed {
    NM_SETTING_PROPERTY_TO_DBUS_FCN_GPROP_TYPE_DEFAULT = 0,
    NM_SETTING_PROPERTY_TO_DBUS_FCN_GPROP_TYPE_GARRAY_UINT,
    NM_SETTING_PROPERTY_TO_DBUS_FCN_GPROP_TYPE_STRDICT,
} NMSettingPropertyToDBusFcnGPropType;

typedef struct {
    const GVariantType *dbus_type;

    /* If this is not NM_VALUE_TYPE_UNSPEC, then this is a "direct" property,
     * meaning that _nm_setting_get_private() at NMSettInfoProperty.direct_offset
     * gives direct access to the field.
     *
     * Direct properties can use this information to generically implement access
     * to the property value. */
    NMValueType direct_type;

    /* Whether from_dbus_fcn() has special capabilities
     *
     * - whether the from_dbus_fcn expects to handle differences between
     *   the D-Bus types and can convert between them. Otherwise, the caller
     *   will already pre-validate that the D-Bus types match.
     * - by default, with NM_SETTING_PARSE_FLAGS_BEST_EFFORT all errors from
     *   from_dbus_fcn() are ignored. If true, then error are propagated. */
    bool from_dbus_is_full : 1;

    /* Only if from_dbus_fcn is set to _nm_setting_property_from_dbus_fcn_direct.
     * Historically, libnm used g_dbus_gvariant_to_gvalue() and g_value_transform() to
     * convert from D-Bus to the GObject property. Thereby, various transformations are
     * allowed and supported. If this is TRUE, then such transformations are still
     * allowed for backward compatibility. */
    bool from_dbus_direct_allow_transform : 1;

#define _NM_SETT_INFO_PROP_COMPARE_FCN_ARGS                                           \
    const NMSettInfoSetting *sett_info, const NMSettInfoProperty *property_info,      \
        NMConnection *con_a, NMSetting *set_a, NMConnection *con_b, NMSetting *set_b, \
        NMSettingCompareFlags flags

    /* compare_fcn() returns a ternary, where DEFAULT means that the property should not
     * be compared due to the compare @flags. A TRUE/FALSE result means that the property is
     * equal/not-equal.
     *
     * The "b" setting may be %NULL, in which case the function only determines whether
     * the setting should be compared (TRUE) or not (DEFAULT). */
    NMTernary (*compare_fcn)(_NM_SETT_INFO_PROP_COMPARE_FCN_ARGS _nm_nil);

#define _NM_SETT_INFO_PROP_TO_DBUS_FCN_ARGS                                                 \
    const NMSettInfoSetting *sett_info, const NMSettInfoProperty *property_info,            \
        NMConnection *connection, NMSetting *setting, NMConnectionSerializationFlags flags, \
        const NMConnectionSerializationOptions *options

    GVariant *(*to_dbus_fcn)(_NM_SETT_INFO_PROP_TO_DBUS_FCN_ARGS _nm_nil);

#define _NM_SETT_INFO_PROP_FROM_DBUS_FCN_ARGS                                    \
    const NMSettInfoSetting *sett_info, const NMSettInfoProperty *property_info, \
        NMSetting *setting, GVariant *connection_dict, GVariant *value,          \
        NMSettingParseFlags parse_flags, NMTernary *out_is_modified, GError **error

    gboolean (*from_dbus_fcn)(_NM_SETT_INFO_PROP_FROM_DBUS_FCN_ARGS _nm_nil);

#define _NM_SETT_INFO_PROP_MISSING_FROM_DBUS_FCN_ARGS                    \
    NMSetting *setting, GVariant *connection_dict, const char *property, \
        NMSettingParseFlags parse_flags, GError **error

    gboolean (*missing_from_dbus_fcn)(_NM_SETT_INFO_PROP_MISSING_FROM_DBUS_FCN_ARGS _nm_nil);

    struct {
#define _NM_SETT_INFO_PROP_FROM_DBUS_GPROP_FCN_ARGS GVariant *from, GValue *to

        /* Only if from_dbus_fcn is set to _nm_setting_property_from_dbus_fcn_gprop.
         * This is an optional handler for converting between GVariant and
         * GValue. */
        void (*gprop_fcn)(_NM_SETT_INFO_PROP_FROM_DBUS_GPROP_FCN_ARGS _nm_nil);
    } typdata_from_dbus;

    struct {
        union {
            NMSettingPropertyToDBusFcnGPropType gprop_type;
        };
    } typdata_to_dbus;

} NMSettInfoPropertType;

struct _NMSettInfoProperty {
    const char *name;

    GParamSpec *param_spec;

    /* We want that our properties follow a small number of "default" types
     * and behaviors. For example, we have int32 and string properties, but
     * most properties of a certain type should behave in a similar way.
     *
     * That common behavior is realized via the property_type, which defines
     * general behaviors for the property.
     *
     * Note that we still will need some property-specific additional tweaks.
     * Of course, the name and param_spec are per-property. But below there are
     * also flags and hooks, that can augment the behavior in the property_type.
     * For example, the property_type in general might be of type string, but
     * then we might want for some properties that the setter will strip
     * whitespace. That is for example express with the flag direct_set_string_strip,
     * which now is per-property-info, and no longer per-property-type.
     *
     * The distinction between those two is fixed. At the most extreme, we could
     * move all fields from property_type to NMSettInfoProperty or we could move
     * behavioral tweaks into the classes themselves. It's chosen this way so
     * that we still have sensible common behaviors (string type), but minor
     * tweaks are per property-info (and don't require a separate property-type). */
    const NMSettInfoPropertType *property_type;

    union {
        /* Optional hook for direct string properties, this gets called when setting the string.
         * Return whether the value changed. */
        gboolean (*set_string_fcn)(const NMSettInfoSetting  *sett_info,
                                   const NMSettInfoProperty *property_info,
                                   NMSetting                *setting,
                                   const char               *src);
    } direct_hook;

    /* This only has meaning for direct properties (property_type->direct_type != NM_VALUE_TYPE_UNSPEC).
     * In that case, this is the offset where _nm_setting_get_private() can find
     * the direct location. */
    guint16 direct_offset;

    /* If TRUE, this is a NM_VALUE_TYPE_STRING direct property, and the setter will
     * normalize the string via g_ascii_strdown(). */
    bool direct_set_string_ascii_strdown : 1;

    /* If TRUE, this is a NM_VALUE_TYPE_STRING direct property, and the setter will
     * normalize the string via g_strstrip(). */
    bool direct_set_string_strip : 1;

    /* If non-zero, this is a NM_VALUE_TYPE_STRING direct property. Actually, it is
     * a _nm_setting_property_define_direct_mac_address(), and the setter will
     * call _nm_utils_hwaddr_canonical_or_invalid() on the string, with the specified
     * MAC address length. */
    guint8 direct_set_string_mac_address_len : 5;

    /* If non-zero, this is the addr-family (AF_UNSPEC/AF_INET/AF_INET6) for normalizing an IP
     * address with _nm_utils_ipaddr_canonical_or_invalid().
     * Note that AF_UNSPEC is zero, so to differentiate between zero and AF_UNSPEC
     * this value is actually the address family + 1. So either zero or AF_UNSPEC+1, AF_INET+1,
     * or AF_INET6+1. */
    guint8 direct_set_string_ip_address_addr_family : 5;

    /* Only makes sense together with direct_set_string_ip_address_addr_family. This flag
     * is passed to _nm_utils_ipaddr_canonical_or_invalid(). */
    bool direct_set_string_ip_address_addr_family_map_zero_to_null : 1;

    /* Whether the string property is implemented as a (downcast) NMRefString. */
    bool direct_string_is_refstr : 1;

    /* Usually, properties that are set to the default value for the GParamSpec
     * are not serialized to GVariant (and NULL is returned by to_dbus_data().
     * Set this flag to force always converting the property even if the value
     * is the default. */
    bool to_dbus_including_default : 1;

    /* This indicates, that the property is deprecated (on D-Bus) for another property.
     * See also _nm_setting_use_legacy_property() how that works.
     *
     * The to_dbus_fcn() will be skipped for such properties, if _nm_utils_is_manager_process
     * is FALSE. */
    bool to_dbus_only_in_manager_process : 1;

    /* Whether the property is deprecated.
     *
     * Note that we have various representations of profiles, e.g. on D-Bus, keyfile,
     * nmcli, libnm/NMSetting. Usually a property (in the general sense) is named and
     * applies similarly to all those. But not always, for example, on D-Bus we
     * have the field "ethernet.assigned-mac-address", but that exists nowhere
     * as a property in the other parts (the real property is called
     * "ethernet.cloned-mac-address").
     *
     * This flag indicates whether a property is deprecated. Here "property" means
     * no specific representation. When a property is deprecated this way, it will
     * also indirectly apply to setting the property on D-Bus, keyfile, nmcli, etc.
     * It means the general concept of this thing is no longer useful/recommended.
     */
    bool is_deprecated : 1;

    /* Whether the property is deprecated in the D-Bus API.
     *
     * This has no real effect (for now). It is only self-documenting code that
     * this property is discouraged on D-Bus. We might honor this when generating
     * documentation, or we might use it to find properties that are deprecated.
     *
     * Note what this means. For example, "802-1x.phase2-subject-match" is deprecated
     * as a property altogether, but that does not mean it's deprecated specifically on
     * D-Bus.
     * "ethernet.cloned-mac-address" is deprecated on D-Bus in favor of
     * "ethernet.assigned-mac-address", but the property clone-mac-address itself
     * is not deprecated. This flag is about the deprecation of the D-Bus representation
     * of a property. */
    bool dbus_deprecated : 1;
};

typedef struct {
    /* we want to do binary search by "GParamSpec *", but unrelated pointers
     * are not directly comparable in C. No problem, we convert them to
     * uintptr_t for the search, that is guaranteed to work. */
    uintptr_t param_spec_as_uint;

    const NMSettInfoProperty *property_info;
} NMSettInfoPropertLookupByParamSpec;

typedef struct {
    const GVariantType *(*get_variant_type)(const struct _NMSettInfoSetting *sett_info,
                                            const char                      *name,
                                            GError                         **error);
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
    const NMSettInfoProperty *const *property_infos_sorted;

    const NMSettInfoPropertLookupByParamSpec *property_lookup_by_param_spec;

    guint16 property_infos_len;

    guint16 property_lookup_by_param_spec_len;

    /* the offset in bytes to get the private data from the @self pointer. */
    gint16 private_offset;

    NMSettInfoSettDetail detail;
};

#define NM_SETT_INFO_PRIVATE_OFFSET_FROM_CLASS ((gint16) G_MININT16)

static inline gpointer
_nm_setting_get_private(NMSetting *self, const NMSettInfoSetting *sett_info, guint16 offset)
{
    nm_assert(NM_IS_SETTING(self));
    nm_assert(sett_info);
    nm_assert(NM_SETTING_GET_CLASS(self) == sett_info->setting_class);

    return ((((char *) ((gpointer) self)) + sett_info->private_offset) + offset);
}

static inline gpointer
_nm_setting_get_private_field(NMSetting                *self,
                              const NMSettInfoSetting  *sett_info,
                              const NMSettInfoProperty *prop_info)
{
    nm_assert(sett_info);
    nm_assert(prop_info);
    nm_assert(prop_info->property_type);
    nm_assert(prop_info->property_type->direct_type > NM_VALUE_TYPE_UNSPEC);
    nm_assert(sett_info->private_offset != 0 || prop_info->direct_offset != 0);

    return _nm_setting_get_private(self, sett_info, prop_info->direct_offset);
}

static inline const NMSettInfoProperty *
_nm_sett_info_property_info_get_sorted(const NMSettInfoSetting *sett_info, guint16 idx)
{
    nm_assert(sett_info);
    nm_assert(idx < sett_info->property_infos_len);
    nm_assert(!sett_info->property_infos_sorted || sett_info->property_infos_sorted[idx]);

    return sett_info->property_infos_sorted ? sett_info->property_infos_sorted[idx]
                                            : &sett_info->property_infos[idx];
}

const NMSettInfoProperty *
_nm_sett_info_setting_get_property_info(const NMSettInfoSetting *sett_info,
                                        const char              *property_name);

const NMSettInfoSetting *_nm_setting_class_get_sett_info(NMSettingClass *setting_class);

static inline const NMSettInfoProperty *
_nm_setting_class_get_property_info(NMSettingClass *setting_class, const char *property_name)
{
    return _nm_sett_info_setting_get_property_info(_nm_setting_class_get_sett_info(setting_class),
                                                   property_name);
}

/*****************************************************************************/

gboolean _nm_setting_compare(NMConnection         *con_a,
                             NMSetting            *set_a,
                             NMConnection         *con_b,
                             NMSetting            *set_b,
                             NMSettingCompareFlags flags);

gboolean _nm_setting_diff(NMConnection         *con_a,
                          NMSetting            *set_a,
                          NMConnection         *con_b,
                          NMSetting            *set_b,
                          NMSettingCompareFlags flags,
                          gboolean              invert_results,
                          GHashTable          **results);

NMSetting8021xCKScheme _nm_setting_802_1x_cert_get_scheme(GBytes *bytes, GError **error);

GBytes *_nm_setting_802_1x_cert_value_to_bytes(NMSetting8021xCKScheme scheme,
                                               const guint8          *val_bin,
                                               gssize                 val_len,
                                               GError               **error);

/*****************************************************************************/

static inline gboolean
_nm_connection_serialize_non_secret(NMConnectionSerializationFlags flags)
{
    if (flags == NM_CONNECTION_SERIALIZE_ALL)
        return TRUE;

    return NM_FLAGS_HAS(flags, NM_CONNECTION_SERIALIZE_WITH_NON_SECRET);
}

static inline gboolean
_nm_connection_serialize_secrets(NMConnectionSerializationFlags flags,
                                 NMSettingSecretFlags           secret_flags)
{
    if (flags == NM_CONNECTION_SERIALIZE_ALL)
        return TRUE;

    if (NM_FLAGS_HAS(flags, NM_CONNECTION_SERIALIZE_WITH_SECRETS)
        && !NM_FLAGS_ANY(flags,
                         NM_CONNECTION_SERIALIZE_WITH_SECRETS_AGENT_OWNED
                             | NM_CONNECTION_SERIALIZE_WITH_SECRETS_SYSTEM_OWNED
                             | NM_CONNECTION_SERIALIZE_WITH_SECRETS_NOT_SAVED))
        return TRUE;

    if (NM_FLAGS_HAS(flags, NM_CONNECTION_SERIALIZE_WITH_SECRETS_AGENT_OWNED)
        && NM_FLAGS_HAS(secret_flags, NM_SETTING_SECRET_FLAG_AGENT_OWNED))
        return TRUE;

    if (NM_FLAGS_HAS(flags, NM_CONNECTION_SERIALIZE_WITH_SECRETS_SYSTEM_OWNED)
        && !NM_FLAGS_ANY(secret_flags,
                         NM_SETTING_SECRET_FLAG_AGENT_OWNED | NM_SETTING_SECRET_FLAG_NOT_SAVED))
        return TRUE;

    if (NM_FLAGS_HAS(flags, NM_CONNECTION_SERIALIZE_WITH_SECRETS_NOT_SAVED)
        && NM_FLAGS_HAS(secret_flags, NM_SETTING_SECRET_FLAG_NOT_SAVED))
        return TRUE;

    return FALSE;
}

void _nm_connection_clear_secrets_by_secret_flags(NMConnection        *self,
                                                  NMSettingSecretFlags filter_flags);

GVariant *_nm_connection_for_each_secret(NMConnection                  *self,
                                         GVariant                      *secrets,
                                         gboolean                       remove_non_secrets,
                                         _NMConnectionForEachSecretFunc callback,
                                         gpointer                       callback_data);

typedef gboolean (*NMConnectionFindSecretFunc)(NMSettingSecretFlags flags, gpointer user_data);

gboolean _nm_connection_find_secret(NMConnection              *self,
                                    GVariant                  *secrets,
                                    NMConnectionFindSecretFunc callback,
                                    gpointer                   callback_data);

/*****************************************************************************/

gboolean nm_utils_base64secret_normalize(const char *base64_key,
                                         gsize       required_key_len,
                                         char      **out_base64_key_norm);

/*****************************************************************************/

gboolean nm_utils_connection_is_adhoc_wpa(NMConnection *connection);

const char *nm_utils_wifi_freq_to_band(guint32 freq);

gboolean _nm_utils_iaid_verify(const char *str, gint64 *out_value);

gboolean
_nm_utils_validate_dhcp_hostname_flags(NMDhcpHostnameFlags flags, int addr_family, GError **error);

/*****************************************************************************/

gboolean _nmtst_variant_attribute_spec_assert_sorted(const NMVariantAttributeSpec *const *array,
                                                     gsize                                len);

const NMVariantAttributeSpec *
_nm_variant_attribute_spec_find_binary_search(const NMVariantAttributeSpec *const *array,
                                              gsize                                len,
                                              const char                          *name);

/*****************************************************************************/

gboolean _nm_ip_tunnel_mode_is_layer2(NMIPTunnelMode mode);

GPtrArray *_nm_setting_ip_config_get_dns_array(NMSettingIPConfig *setting);

gboolean nm_connection_need_secrets_for_rerequest(NMConnection *connection);

const GPtrArray *_nm_setting_ovs_port_get_trunks_arr(NMSettingOvsPort *self);

#endif
