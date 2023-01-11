/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef __NM_LIBNM_SHARED_UTILS_H__
#define __NM_LIBNM_SHARED_UTILS_H__

/****************************************************************************/

#include "nm-setting-bond.h"
#include "nm-setting-bridge.h"
#include "nm-setting-connection.h"
#include "nm-setting-ip-config.h"
#include "nm-setting-ip4-config.h"
#include "nm-setting-ip6-config.h"
#include "nm-setting-sriov.h"
#include "nm-setting-team.h"
#include "nm-setting-vlan.h"
#include "nm-setting-wireguard.h"

/****************************************************************************/

#define nm_auto_unref_ip_address nm_auto(_nm_ip_address_unref)
NM_AUTO_DEFINE_FCN0(NMIPAddress *, _nm_ip_address_unref, nm_ip_address_unref);

#define nm_auto_unref_ip_route nm_auto(_nm_auto_unref_ip_route)
NM_AUTO_DEFINE_FCN0(NMIPRoute *, _nm_auto_unref_ip_route, nm_ip_route_unref);

#define nm_auto_unref_ip_routing_rule nm_auto(_nm_auto_unref_ip_routing_rule)
NM_AUTO_DEFINE_FCN0(NMIPRoutingRule *, _nm_auto_unref_ip_routing_rule, nm_ip_routing_rule_unref);

#define nm_auto_unref_sriov_vf nm_auto(_nm_auto_unref_sriov_vf)
NM_AUTO_DEFINE_FCN0(NMSriovVF *, _nm_auto_unref_sriov_vf, nm_sriov_vf_unref);

#define nm_auto_unref_tc_qdisc nm_auto(_nm_auto_unref_tc_qdisc)
NM_AUTO_DEFINE_FCN0(NMTCQdisc *, _nm_auto_unref_tc_qdisc, nm_tc_qdisc_unref);

#define nm_auto_unref_tc_tfilter nm_auto(_nm_auto_unref_tc_tfilter)
NM_AUTO_DEFINE_FCN0(NMTCTfilter *, _nm_auto_unref_tc_tfilter, nm_tc_tfilter_unref);

#define nm_auto_unref_tc_action nm_auto(_nm_auto_unref_tc_action)
NM_AUTO_DEFINE_FCN0(NMTCAction *, _nm_auto_unref_tc_action, nm_tc_action_unref);

#define nm_auto_unref_bridge_vlan nm_auto(_nm_auto_unref_bridge_vlan)
NM_AUTO_DEFINE_FCN0(NMBridgeVlan *, _nm_auto_unref_bridge_vlan, nm_bridge_vlan_unref);

#define nm_auto_unref_team_link_watcher nm_auto(_nm_auto_unref_team_link_watcher)
NM_AUTO_DEFINE_FCN0(NMTeamLinkWatcher *,
                    _nm_auto_unref_team_link_watcher,
                    nm_team_link_watcher_unref);

#define nm_auto_unref_wgpeer nm_auto(_nm_auto_unref_wgpeer)
NM_AUTO_DEFINE_FCN0(NMWireGuardPeer *, _nm_auto_unref_wgpeer, nm_wireguard_peer_unref);

/****************************************************************************/

const char **nm_utils_bond_option_arp_ip_targets_split(const char *arp_ip_target);

void _nm_setting_bond_remove_options_miimon(NMSettingBond *s_bond);
void _nm_setting_bond_remove_options_arp_interval(NMSettingBond *s_bond);

typedef enum {
    NM_BOND_AD_SELECT_UNKNOWN = -1,

    /* The numeric values correspond to kernel's numbering. */
    NM_BOND_AD_SELECT_STABLE    = 0,
    NM_BOND_AD_SELECT_BANDWIDTH = 1,
    NM_BOND_AD_SELECT_COUNT     = 2,

    _NM_BOND_AD_SELECT_NUM,
} NMBondAdSelect;

NMBondAdSelect _nm_setting_bond_ad_select_from_string(const char *str);

typedef enum {
    NM_BOND_ARP_ALL_TARGETS_UNKNOWN = -1,

    /* The numeric values correspond to kernel's numbering. */
    NM_BOND_ARP_ALL_TARGETS_ANY = 0,
    NM_BOND_ARP_ALL_TARGETS_ALL = 1,

    _NM_BOND_ARP_ALL_TARGETS_NUM,
} NMBondArpAllTargets;

NMBondArpAllTargets _nm_setting_bond_arp_all_targets_from_string(const char *str);

typedef enum {
    NM_BOND_FAIL_OVER_MAC_UNKNOWN = -1,

    /* The numeric values correspond to kernel's numbering. */
    NM_BOND_FAIL_OVER_MAC_NONE   = 0,
    NM_BOND_FAIL_OVER_MAC_ACTIVE = 1,
    NM_BOND_FAIL_OVER_MAC_FOLLOW = 2,

    _NM_BOND_FAIL_OVER_MAC_NUM,
} NMBondFailOverMac;

NMBondFailOverMac _nm_setting_bond_fail_over_mac_from_string(const char *str);

typedef enum {
    NM_BOND_LACP_RATE_UNKNOWN = -1,

    /* The numeric values correspond to kernel's numbering. */
    NM_BOND_LACP_RATE_SLOW = 0,
    NM_BOND_LACP_RATE_FAST = 1,

    _NM_BOND_LACP_RATE_NUM,
} NMBondLacpRate;

NMBondLacpRate _nm_setting_bond_lacp_rate_from_string(const char *str);

typedef enum {
    NM_BOND_ARP_VALIDATE_UNKNOWN = -1,

    /* The numeric values correspond to kernel's numbering. */
    NM_BOND_ARP_VALIDATE_NONE          = 0,
    NM_BOND_ARP_VALIDATE_ACTIVE        = 1,
    NM_BOND_ARP_VALIDATE_BACKUP        = 2,
    NM_BOND_ARP_VALIDATE_ALL           = 3,
    NM_BOND_ARP_VALIDATE_FILTER        = 4,
    NM_BOND_ARP_VALIDATE_FILTER_ACTIVE = 5,
    NM_BOND_ARP_VALIDATE_FILTER_BACKUP = 6,

    _NM_BOND_ARP_VALIDATE_NUM,
} NMBondArpValidate;

NMBondArpValidate _nm_setting_bond_arp_validate_from_string(const char *str);

typedef enum {
    NM_BOND_PRIMARY_RESELECT_UNKNOWN = -1,

    /* The numeric values correspond to kernel's numbering. */
    NM_BOND_PRIMARY_RESELECT_ALWAYS  = 0,
    NM_BOND_PRIMARY_RESELECT_BETTER  = 1,
    NM_BOND_PRIMARY_RESELECT_FAILURE = 2,

    _NM_BOND_PRIMARY_RESELECT_NUM,
} NMBondPrimaryReselect;

NMBondPrimaryReselect _nm_setting_bond_primary_reselect_from_string(const char *str);

typedef enum {
    NM_BOND_XMIT_HASH_POLICY_UNKNOWN = -1,

    /* The numeric values correspond to kernel's numbering. */
    NM_BOND_XMIT_HASH_POLICY_LAYER2      = 0,
    NM_BOND_XMIT_HASH_POLICY_LAYER3_4    = 1,
    NM_BOND_XMIT_HASH_POLICY_LAYER2_3    = 2,
    NM_BOND_XMIT_HASH_POLICY_ENCAP2_3    = 3,
    NM_BOND_XMIT_HASH_POLICY_ENCAP3_4    = 4,
    NM_BOND_XMIT_HASH_POLICY_VLAN_SRCMAC = 5,

    _NM_BOND_XMIT_HASH_POLICY_NUM,
} NMBondXmitHashPolicy;

NMBondXmitHashPolicy _nm_setting_bond_xmit_hash_policy_from_string(const char *str);

typedef enum {
    NM_BOND_MODE_UNKNOWN = -1,

    /* The numeric values correspond to kernel's numbering of the modes. */
    NM_BOND_MODE_ROUNDROBIN   = 0,
    NM_BOND_MODE_ACTIVEBACKUP = 1,
    NM_BOND_MODE_XOR          = 2,
    NM_BOND_MODE_BROADCAST    = 3,
    NM_BOND_MODE_8023AD       = 4,
    NM_BOND_MODE_TLB          = 5,
    NM_BOND_MODE_ALB          = 6,

    _NM_BOND_MODE_NUM,
} NMBondMode;

NMBondMode _nm_setting_bond_mode_from_string(const char *str);

const char *_nm_setting_bond_mode_to_string(int mode);

gboolean _nm_setting_bond_validate_option(const char *name, const char *value, GError **error);

/*****************************************************************************/

static inline guint32
nm_utils_vlan_priority_map_get_max_prio(NMVlanPriorityMap map, gboolean from)
{
    if (map == NM_VLAN_INGRESS_MAP) {
        return from ? 7u /* MAX_8021P_PRIO */
                    : (guint32) G_MAXUINT32 /* MAX_SKB_PRIO */;
    }
    nm_assert(map == NM_VLAN_EGRESS_MAP);
    return from ? (guint32) G_MAXUINT32 /* MAX_SKB_PRIO */
                : 7u /* MAX_8021P_PRIO */;
}

gboolean nm_utils_vlan_priority_map_parse_str(NMVlanPriorityMap map_type,
                                              const char       *str,
                                              gboolean          allow_wildcard_to,
                                              guint32          *out_from,
                                              guint32          *out_to,
                                              gboolean         *out_has_wildcard_to);

/*****************************************************************************/

#define _NM_DEVICE_INTERFACE_FLAG_ALL                                                          \
    ((NMDeviceInterfaceFlags) (NM_DEVICE_INTERFACE_FLAG_UP | NM_DEVICE_INTERFACE_FLAG_LOWER_UP \
                               | NM_DEVICE_INTERFACE_FLAG_CARRIER                              \
                               | NM_DEVICE_INTERFACE_FLAG_PROMISC                              \
                               | NM_DEVICE_INTERFACE_FLAG_LLDP_CLIENT_ENABLED))

/*****************************************************************************/

#define NM_OVS_EXTERNAL_ID_NM_PREFIX          "NM."
#define NM_OVS_EXTERNAL_ID_NM_CONNECTION_UUID "NM.connection.uuid"

/*****************************************************************************/

static inline int
nm_setting_ip_config_get_addr_family(NMSettingIPConfig *s_ip)
{
    if (NM_IS_SETTING_IP4_CONFIG(s_ip))
        return AF_INET;
    if (NM_IS_SETTING_IP6_CONFIG(s_ip))
        return AF_INET6;
    g_return_val_if_reached(AF_UNSPEC);
}

/*****************************************************************************/

/* The maximum MTU for infiniband.
 *
 * This is both in transport-mode "datagram" and "connected"
 * and they both have the same maximum define.
 *
 * Note that in the past, MTU in "datagram" mode was restricted
 * to 2044 bytes. That is no longer the case and we accept large
 * MTUs.
 *
 * This define is the maxiumum for the MTU in a connection profile (the
 * setting). Whether large MTUs can be configured later (at activation time)
 * depends on other factors. */
#define NM_INFINIBAND_MAX_MTU ((guint) 65520)

/*****************************************************************************/

#define _NM_CAPABILITY_MAX NM_CAPABILITY_OVS

/*****************************************************************************/

extern const char *const        nm_auth_permission_names_by_idx[NM_CLIENT_PERMISSION_LAST];
extern const NMClientPermission nm_auth_permission_sorted[NM_CLIENT_PERMISSION_LAST];

const char        *nm_auth_permission_to_string(NMClientPermission permission);
NMClientPermission nm_auth_permission_from_string(const char *str);

/*****************************************************************************/

NMClientPermissionResult nm_client_permission_result_from_string(const char *nm);
const char              *nm_client_permission_result_to_string(NMClientPermissionResult permission);

gboolean nm_utils_validate_dhcp4_vendor_class_id(const char *vci, GError **error);

/*****************************************************************************/

#define NM_SETTINGS_CONNECTION_PERMISSION_USER        "user"
#define NM_SETTINGS_CONNECTION_PERMISSION_USER_PREFIX "user:"

gboolean nm_settings_connection_validate_permission_user(const char *item, gssize len);

/*****************************************************************************/

gpointer _nm_connection_ensure_setting(NMConnection *connection, GType gtype);
gpointer _nm_connection_new_setting(NMConnection *connection, GType gtype);

/*****************************************************************************/

#define _NM_MPTCP_FLAGS_ALL                                                              \
    ((NMMptcpFlags) (NM_MPTCP_FLAGS_DISABLED | NM_MPTCP_FLAGS_ENABLED                    \
                     | NM_MPTCP_FLAGS_ALSO_WITHOUT_SYSCTL                                \
                     | NM_MPTCP_FLAGS_ALSO_WITHOUT_DEFAULT_ROUTE | NM_MPTCP_FLAGS_SIGNAL \
                     | NM_MPTCP_FLAGS_SUBFLOW | NM_MPTCP_FLAGS_BACKUP | NM_MPTCP_FLAGS_FULLMESH))

#define _NM_MPTCP_FLAGS_DEFAULT ((NMMptcpFlags) (NM_MPTCP_FLAGS_ENABLED | NM_MPTCP_FLAGS_SUBFLOW))

NMMptcpFlags nm_mptcp_flags_normalize(NMMptcpFlags flags);

/*****************************************************************************/

gboolean nm_utils_dnsname_parse(int                          addr_family,
                                const char                  *dns,
                                int                         *out_addr_family,
                                gpointer /* (NMIPAddr **) */ out_addr,
                                const char                 **out_servername);

#define nm_utils_dnsname_parse_assert(addr_family, dns, out_addr_family, out_addr, out_servername) \
    ({                                                                                             \
        gboolean _good;                                                                            \
                                                                                                   \
        _good = nm_utils_dnsname_parse((addr_family),                                              \
                                       (dns),                                                      \
                                       (out_addr_family),                                          \
                                       (out_addr),                                                 \
                                       (out_servername));                                          \
        nm_assert(_good);                                                                          \
        _good;                                                                                     \
    })

const char *nm_utils_dnsname_construct(int                                    addr_family,
                                       gconstpointer /* (const NMIPAddr *) */ addr,
                                       const char                            *server_name,
                                       char                                  *result,
                                       gsize                                  result_len);

const char *nm_utils_dnsname_normalize(int addr_family, const char *dns, char **out_free);

/*****************************************************************************/

gboolean nm_setting_ovs_other_config_check_key(const char *key, GError **error);
gboolean nm_setting_ovs_other_config_check_val(const char *val, GError **error);

#endif /* __NM_LIBNM_SHARED_UTILS_H__ */
