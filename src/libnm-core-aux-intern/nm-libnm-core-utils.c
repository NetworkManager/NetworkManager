/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "libnm-glib-aux/nm-default-glib-i18n-lib.h"

#include "nm-libnm-core-utils.h"

#include <linux/rtnetlink.h>

#include "nm-common-macros.h"
#include "nm-errors.h"
#include "libnm-core-public/nm-connection.h"

/*****************************************************************************/

const char **
nm_utils_bond_option_ip_split(const char *arp_ip_target)
{
    return nm_strsplit_set_full(arp_ip_target, ",", NM_STRSPLIT_SET_FLAGS_STRSTRIP);
}

void
_nm_setting_bond_remove_options_miimon(NMSettingBond *s_bond)
{
    g_return_if_fail(NM_IS_SETTING_BOND(s_bond));

    nm_setting_bond_remove_option(s_bond, NM_SETTING_BOND_OPTION_MIIMON);
    nm_setting_bond_remove_option(s_bond, NM_SETTING_BOND_OPTION_UPDELAY);
    nm_setting_bond_remove_option(s_bond, NM_SETTING_BOND_OPTION_DOWNDELAY);
    nm_setting_bond_remove_option(s_bond, NM_SETTING_BOND_OPTION_PEER_NOTIF_DELAY);
}

void
_nm_setting_bond_remove_options_arp_interval(NMSettingBond *s_bond)
{
    g_return_if_fail(NM_IS_SETTING_BOND(s_bond));

    nm_setting_bond_remove_option(s_bond, NM_SETTING_BOND_OPTION_ARP_INTERVAL);
    nm_setting_bond_remove_option(s_bond, NM_SETTING_BOND_OPTION_ARP_IP_TARGET);
    nm_setting_bond_remove_option(s_bond, NM_SETTING_BOND_OPTION_NS_IP6_TARGET);
}

/*****************************************************************************/

NM_UTILS_STRING_TABLE_LOOKUP_DEFINE(
    _nm_setting_bond_ad_select_from_string,
    NMBondAdSelect,
    {
        G_STATIC_ASSERT_EXPR(_NM_BOND_AD_SELECT_NUM <= 3);

        if (name && name[0] < '0' + _NM_BOND_AD_SELECT_NUM && name[0] >= '0' && name[1] == '\0') {
            return name[0] - '0';
        }
    },
    { return NM_BOND_AD_SELECT_STABLE; },
    {"bandwidth", NM_BOND_AD_SELECT_BANDWIDTH},
    {"count", NM_BOND_AD_SELECT_COUNT},
    {"stable", NM_BOND_AD_SELECT_STABLE}, );

NM_UTILS_STRING_TABLE_LOOKUP_DEFINE(
    _nm_setting_bond_arp_all_targets_from_string,
    NMBondArpAllTargets,
    {
        G_STATIC_ASSERT_EXPR(_NM_BOND_ARP_ALL_TARGETS_NUM <= 2);

        if (name && name[0] < '0' + _NM_BOND_ARP_ALL_TARGETS_NUM && name[0] >= '0'
            && name[1] == '\0') {
            return name[0] - '0';
        }
    },
    { return NM_BOND_ARP_ALL_TARGETS_ANY; },
    {"all", NM_BOND_ARP_ALL_TARGETS_ALL},
    {"any", NM_BOND_ARP_ALL_TARGETS_ANY}, );

NM_UTILS_STRING_TABLE_LOOKUP_DEFINE(
    _nm_setting_bond_fail_over_mac_from_string,
    NMBondFailOverMac,
    {
        G_STATIC_ASSERT_EXPR(_NM_BOND_FAIL_OVER_MAC_NUM <= 3);

        if (name && name[0] < '0' + _NM_BOND_FAIL_OVER_MAC_NUM && name[0] >= '0'
            && name[1] == '\0') {
            return name[0] - '0';
        }
    },
    { return NM_BOND_FAIL_OVER_MAC_NONE; },
    {"active", NM_BOND_FAIL_OVER_MAC_ACTIVE},
    {"follow", NM_BOND_FAIL_OVER_MAC_FOLLOW},
    {"none", NM_BOND_FAIL_OVER_MAC_NONE}, );

NM_UTILS_STRING_TABLE_LOOKUP_DEFINE(
    _nm_setting_bond_lacp_active_from_string,
    NMBondLacpActive,
    {
        G_STATIC_ASSERT_EXPR(_NM_BOND_LACP_ACTIVE_NUM <= 2);

        if (name && name[0] < '0' + _NM_BOND_LACP_ACTIVE_NUM && name[0] >= '0' && name[1] == '\0') {
            return name[0] - '0';
        }
    },
    { return NM_BOND_LACP_ACTIVE_ON; },
    {"off", NM_BOND_LACP_ACTIVE_OFF},
    {"on", NM_BOND_LACP_ACTIVE_ON}, );

NM_UTILS_STRING_TABLE_LOOKUP_DEFINE(
    _nm_setting_bond_lacp_rate_from_string,
    NMBondLacpRate,
    {
        G_STATIC_ASSERT_EXPR(_NM_BOND_LACP_RATE_NUM <= 2);

        if (name && name[0] < '0' + _NM_BOND_LACP_RATE_NUM && name[0] >= '0' && name[1] == '\0') {
            return name[0] - '0';
        }
    },
    { return NM_BOND_LACP_RATE_SLOW; },
    {"fast", NM_BOND_LACP_RATE_FAST},
    {"slow", NM_BOND_LACP_RATE_SLOW}, );

NM_UTILS_STRING_TABLE_LOOKUP_DEFINE(
    _nm_setting_bond_arp_validate_from_string,
    NMBondArpValidate,
    {
        G_STATIC_ASSERT_EXPR(_NM_BOND_ARP_VALIDATE_NUM <= 7);

        if (name && name[0] < '0' + _NM_BOND_ARP_VALIDATE_NUM && name[0] >= '0'
            && name[1] == '\0') {
            return name[0] - '0';
        }
    },
    { return NM_BOND_ARP_VALIDATE_NONE; },
    {"active", NM_BOND_ARP_VALIDATE_ACTIVE},
    {"all", NM_BOND_ARP_VALIDATE_ALL},
    {"backup", NM_BOND_ARP_VALIDATE_BACKUP},
    {"filter", NM_BOND_ARP_VALIDATE_FILTER},
    {"filter_active", NM_BOND_ARP_VALIDATE_FILTER_ACTIVE},
    {"filter_backup", NM_BOND_ARP_VALIDATE_FILTER_BACKUP},
    {"none", NM_BOND_ARP_VALIDATE_NONE}, );

NM_UTILS_STRING_TABLE_LOOKUP_DEFINE(
    _nm_setting_bond_primary_reselect_from_string,
    NMBondPrimaryReselect,
    {
        G_STATIC_ASSERT_EXPR(_NM_BOND_PRIMARY_RESELECT_NUM <= 3);

        if (name && name[0] < '0' + _NM_BOND_PRIMARY_RESELECT_NUM && name[0] >= '0'
            && name[1] == '\0') {
            return name[0] - '0';
        }
    },
    { return NM_BOND_PRIMARY_RESELECT_ALWAYS; },
    {"always", NM_BOND_PRIMARY_RESELECT_ALWAYS},
    {"better", NM_BOND_PRIMARY_RESELECT_BETTER},
    {"failure", NM_BOND_PRIMARY_RESELECT_FAILURE}, );

NM_UTILS_STRING_TABLE_LOOKUP_DEFINE(
    _nm_setting_bond_xmit_hash_policy_from_string,
    NMBondXmitHashPolicy,
    {
        G_STATIC_ASSERT_EXPR(_NM_BOND_XMIT_HASH_POLICY_NUM <= 6);

        if (name && name[0] < '0' + _NM_BOND_XMIT_HASH_POLICY_NUM && name[0] >= '0'
            && name[1] == '\0') {
            return name[0] - '0';
        }
    },
    { return NM_BOND_XMIT_HASH_POLICY_LAYER2; },
    {"encap2+3", NM_BOND_XMIT_HASH_POLICY_ENCAP2_3},
    {"encap3+4", NM_BOND_XMIT_HASH_POLICY_ENCAP3_4},
    {"layer2", NM_BOND_XMIT_HASH_POLICY_LAYER2},
    {"layer2+3", NM_BOND_XMIT_HASH_POLICY_LAYER2_3},
    {"layer3+4", NM_BOND_XMIT_HASH_POLICY_LAYER3_4},
    {"vlan+srcmac", NM_BOND_XMIT_HASH_POLICY_VLAN_SRCMAC}, );

NM_UTILS_STRING_TABLE_LOOKUP_DEFINE(
    _nm_setting_bond_mode_from_string,
    NMBondMode,
    {
        G_STATIC_ASSERT_EXPR(_NM_BOND_MODE_NUM <= 9);

        if (name && name[0] < '0' + _NM_BOND_MODE_NUM && name[0] >= '0' && name[1] == '\0') {
            return name[0] - '0';
        }
    },
    { return NM_BOND_MODE_UNKNOWN; },
    {"802.3ad", NM_BOND_MODE_8023AD},
    {"active-backup", NM_BOND_MODE_ACTIVEBACKUP},
    {"balance-alb", NM_BOND_MODE_ALB},
    {"balance-rr", NM_BOND_MODE_ROUNDROBIN},
    {"balance-tlb", NM_BOND_MODE_TLB},
    {"balance-xor", NM_BOND_MODE_XOR},
    {"broadcast", NM_BOND_MODE_BROADCAST}, );

const char *
_nm_setting_bond_mode_to_string(int mode)
{
    static const char *const modes[] = {
        [NM_BOND_MODE_8023AD]       = "802.3ad",
        [NM_BOND_MODE_ACTIVEBACKUP] = "active-backup",
        [NM_BOND_MODE_ALB]          = "balance-alb",
        [NM_BOND_MODE_BROADCAST]    = "broadcast",
        [NM_BOND_MODE_ROUNDROBIN]   = "balance-rr",
        [NM_BOND_MODE_TLB]          = "balance-tlb",
        [NM_BOND_MODE_XOR]          = "balance-xor",
    };

    G_STATIC_ASSERT(G_N_ELEMENTS(modes) == _NM_BOND_MODE_NUM);

    if (NM_MORE_ASSERT_ONCE(5)) {
        char       sbuf[100];
        int        i;
        NMBondMode m;

        for (i = 0; i < (int) G_N_ELEMENTS(modes); i++) {
            nm_assert(modes[i]);
            nm_assert(i == _nm_setting_bond_mode_from_string(modes[i]));
            nm_assert(i == _nm_setting_bond_mode_from_string(nm_sprintf_buf(sbuf, "%d", i)));
        }
        nm_assert(NM_BOND_MODE_UNKNOWN == _nm_setting_bond_mode_from_string(NULL));
        nm_assert(NM_BOND_MODE_UNKNOWN == _nm_setting_bond_mode_from_string(""));
        for (i = -2; i < ((int) G_N_ELEMENTS(modes)) + 20; i++) {
            if (i < 0 || i >= G_N_ELEMENTS(modes))
                m = NM_BOND_MODE_UNKNOWN;
            else
                m = i;
            nm_assert(m == _nm_setting_bond_mode_from_string(nm_sprintf_buf(sbuf, "%d", i)));
        }
    }

    if (mode >= 0 && mode < (int) G_N_ELEMENTS(modes))
        return modes[mode];
    return NULL;
}

/*****************************************************************************/

gboolean
nm_utils_vlan_priority_map_parse_str(NMVlanPriorityMap map_type,
                                     const char       *str,
                                     gboolean          allow_wildcard_to,
                                     guint32          *out_from,
                                     guint32          *out_to,
                                     gboolean         *out_has_wildcard_to)
{
    const char *s2;
    gint64      v1, v2;

    nm_assert(str);

    s2 = strchr(str, ':');

    if (!s2) {
        if (!allow_wildcard_to)
            return FALSE;
        v1 = _nm_utils_ascii_str_to_int64(str, 10, 0, G_MAXUINT32, -1);
        v2 = -1;
    } else {
        gs_free char *s1_free = NULL;
        gsize         s1_len  = (s2 - str);

        s2 = nm_str_skip_leading_spaces(&s2[1]);
        if (s2[0] == '\0' || (s2[0] == '*' && NM_STRCHAR_ALL(&s2[1], ch, g_ascii_isspace(ch)))) {
            if (!allow_wildcard_to)
                return FALSE;
            v2 = -1;
        } else {
            v2 = _nm_utils_ascii_str_to_int64(s2, 10, 0, G_MAXUINT32, -1);
            if (v2 < 0 || (guint32) v2 > nm_utils_vlan_priority_map_get_max_prio(map_type, FALSE))
                return FALSE;
        }

        v1 = _nm_utils_ascii_str_to_int64(nm_strndup_a(100, str, s1_len, &s1_free),
                                          10,
                                          0,
                                          G_MAXUINT32,
                                          -1);
    }

    if (v1 < 0 || (guint32) v1 > nm_utils_vlan_priority_map_get_max_prio(map_type, TRUE))
        return FALSE;

    NM_SET_OUT(out_from, v1);
    NM_SET_OUT(out_to, v2 < 0 ? 0u : (guint) v2);
    NM_SET_OUT(out_has_wildcard_to, v2 < 0);
    return TRUE;
}

/*****************************************************************************/

const char *const nm_auth_permission_names_by_idx[NM_CLIENT_PERMISSION_LAST] = {
    [NM_CLIENT_PERMISSION_CHECKPOINT_ROLLBACK - 1] = NM_AUTH_PERMISSION_CHECKPOINT_ROLLBACK,
    [NM_CLIENT_PERMISSION_ENABLE_DISABLE_CONNECTIVITY_CHECK - 1] =
        NM_AUTH_PERMISSION_ENABLE_DISABLE_CONNECTIVITY_CHECK,
    [NM_CLIENT_PERMISSION_ENABLE_DISABLE_NETWORK - 1] = NM_AUTH_PERMISSION_ENABLE_DISABLE_NETWORK,
    [NM_CLIENT_PERMISSION_ENABLE_DISABLE_STATISTICS - 1] =
        NM_AUTH_PERMISSION_ENABLE_DISABLE_STATISTICS,
    [NM_CLIENT_PERMISSION_ENABLE_DISABLE_WIFI - 1]  = NM_AUTH_PERMISSION_ENABLE_DISABLE_WIFI,
    [NM_CLIENT_PERMISSION_ENABLE_DISABLE_WIMAX - 1] = NM_AUTH_PERMISSION_ENABLE_DISABLE_WIMAX,
    [NM_CLIENT_PERMISSION_ENABLE_DISABLE_WWAN - 1]  = NM_AUTH_PERMISSION_ENABLE_DISABLE_WWAN,
    [NM_CLIENT_PERMISSION_NETWORK_CONTROL - 1]      = NM_AUTH_PERMISSION_NETWORK_CONTROL,
    [NM_CLIENT_PERMISSION_RELOAD - 1]               = NM_AUTH_PERMISSION_RELOAD,
    [NM_CLIENT_PERMISSION_SETTINGS_MODIFY_GLOBAL_DNS - 1] =
        NM_AUTH_PERMISSION_SETTINGS_MODIFY_GLOBAL_DNS,
    [NM_CLIENT_PERMISSION_SETTINGS_MODIFY_HOSTNAME - 1] =
        NM_AUTH_PERMISSION_SETTINGS_MODIFY_HOSTNAME,
    [NM_CLIENT_PERMISSION_SETTINGS_MODIFY_OWN - 1]    = NM_AUTH_PERMISSION_SETTINGS_MODIFY_OWN,
    [NM_CLIENT_PERMISSION_SETTINGS_MODIFY_SYSTEM - 1] = NM_AUTH_PERMISSION_SETTINGS_MODIFY_SYSTEM,
    [NM_CLIENT_PERMISSION_SLEEP_WAKE - 1]             = NM_AUTH_PERMISSION_SLEEP_WAKE,
    [NM_CLIENT_PERMISSION_WIFI_SCAN - 1]              = NM_AUTH_PERMISSION_WIFI_SCAN,
    [NM_CLIENT_PERMISSION_WIFI_SHARE_OPEN - 1]        = NM_AUTH_PERMISSION_WIFI_SHARE_OPEN,
    [NM_CLIENT_PERMISSION_WIFI_SHARE_PROTECTED - 1]   = NM_AUTH_PERMISSION_WIFI_SHARE_PROTECTED,
};

const NMClientPermission nm_auth_permission_sorted[NM_CLIENT_PERMISSION_LAST] = {
    NM_CLIENT_PERMISSION_CHECKPOINT_ROLLBACK,
    NM_CLIENT_PERMISSION_ENABLE_DISABLE_CONNECTIVITY_CHECK,
    NM_CLIENT_PERMISSION_ENABLE_DISABLE_NETWORK,
    NM_CLIENT_PERMISSION_ENABLE_DISABLE_STATISTICS,
    NM_CLIENT_PERMISSION_ENABLE_DISABLE_WIFI,
    NM_CLIENT_PERMISSION_ENABLE_DISABLE_WIMAX,
    NM_CLIENT_PERMISSION_ENABLE_DISABLE_WWAN,
    NM_CLIENT_PERMISSION_NETWORK_CONTROL,
    NM_CLIENT_PERMISSION_RELOAD,
    NM_CLIENT_PERMISSION_SETTINGS_MODIFY_GLOBAL_DNS,
    NM_CLIENT_PERMISSION_SETTINGS_MODIFY_HOSTNAME,
    NM_CLIENT_PERMISSION_SETTINGS_MODIFY_OWN,
    NM_CLIENT_PERMISSION_SETTINGS_MODIFY_SYSTEM,
    NM_CLIENT_PERMISSION_SLEEP_WAKE,
    NM_CLIENT_PERMISSION_WIFI_SCAN,
    NM_CLIENT_PERMISSION_WIFI_SHARE_OPEN,
    NM_CLIENT_PERMISSION_WIFI_SHARE_PROTECTED,
};

const char *
nm_auth_permission_to_string(NMClientPermission permission)
{
    if (permission < 1)
        return NULL;
    if (permission > NM_CLIENT_PERMISSION_LAST)
        return NULL;
    return nm_auth_permission_names_by_idx[permission - 1];
}

#define AUTH_PERMISSION_PREFIX "org.freedesktop.NetworkManager."

static int
_nm_auth_permission_from_string_cmp(gconstpointer a, gconstpointer b, gpointer user_data)
{
    const NMClientPermission *const p      = a;
    const char *const               needle = b;
    const char                     *ss     = nm_auth_permission_names_by_idx[*p - 1];

    nm_assert(NM_STR_HAS_PREFIX(ss, AUTH_PERMISSION_PREFIX));
    nm_assert(ss[NM_STRLEN(AUTH_PERMISSION_PREFIX)] != '\0');

    return strcmp(&ss[NM_STRLEN(AUTH_PERMISSION_PREFIX)], needle);
}

NMClientPermission
nm_auth_permission_from_string(const char *str)
{
    gssize idx;

    if (!str)
        return NM_CLIENT_PERMISSION_NONE;

    if (!NM_STR_HAS_PREFIX(str, AUTH_PERMISSION_PREFIX))
        return NM_CLIENT_PERMISSION_NONE;
    idx = nm_array_find_bsearch(nm_auth_permission_sorted,
                                G_N_ELEMENTS(nm_auth_permission_sorted),
                                sizeof(nm_auth_permission_sorted[0]),
                                &str[NM_STRLEN(AUTH_PERMISSION_PREFIX)],
                                _nm_auth_permission_from_string_cmp,
                                NULL);
    if (idx < 0)
        return NM_CLIENT_PERMISSION_NONE;
    return nm_auth_permission_sorted[idx];
}

/*****************************************************************************/

NMClientPermissionResult
nm_client_permission_result_from_string(const char *nm)
{
    if (!nm)
        return NM_CLIENT_PERMISSION_RESULT_UNKNOWN;
    if (nm_streq(nm, "yes"))
        return NM_CLIENT_PERMISSION_RESULT_YES;
    if (nm_streq(nm, "no"))
        return NM_CLIENT_PERMISSION_RESULT_NO;
    if (nm_streq(nm, "auth"))
        return NM_CLIENT_PERMISSION_RESULT_AUTH;
    return NM_CLIENT_PERMISSION_RESULT_UNKNOWN;
}

const char *
nm_client_permission_result_to_string(NMClientPermissionResult permission)
{
    switch (permission) {
    case NM_CLIENT_PERMISSION_RESULT_YES:
        return "yes";
    case NM_CLIENT_PERMISSION_RESULT_NO:
        return "no";
    case NM_CLIENT_PERMISSION_RESULT_AUTH:
        return "auth";
    case NM_CLIENT_PERMISSION_RESULT_UNKNOWN:
        return "unknown";
    }
    nm_assert_not_reached();
    return NULL;
}

gboolean
nm_utils_validate_dhcp4_vendor_class_id(const char *vci, GError **error)
{
    const char   *bin;
    gsize         unescaped_len;
    gs_free char *to_free = NULL;

    g_return_val_if_fail(!error || !(*error), FALSE);
    g_return_val_if_fail(vci, FALSE);

    if (vci[0] == '\0') {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("property cannot be an empty string"));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_IP4_CONFIG_SETTING_NAME,
                       NM_SETTING_IP4_CONFIG_DHCP_VENDOR_CLASS_IDENTIFIER);
        return FALSE;
    }

    bin = nm_utils_buf_utf8safe_unescape(vci,
                                         NM_UTILS_STR_UTF8_SAFE_FLAG_NONE,
                                         &unescaped_len,
                                         (gpointer *) &to_free);
    /* a DHCP option cannot be longer than 255 bytes */
    if (unescaped_len > 255) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("property cannot be longer than 255 bytes"));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_IP4_CONFIG_SETTING_NAME,
                       NM_SETTING_IP4_CONFIG_DHCP_VENDOR_CLASS_IDENTIFIER);
        return FALSE;
    }
    if (strlen(bin) != unescaped_len) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("property cannot contain any nul bytes"));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_IP4_CONFIG_SETTING_NAME,
                       NM_SETTING_IP4_CONFIG_DHCP_VENDOR_CLASS_IDENTIFIER);
        return FALSE;
    }

    return TRUE;
}

gboolean
nm_utils_validate_dhcp_dscp(const char *dscp, GError **error)
{
    g_return_val_if_fail(!error || !(*error), FALSE);
    g_return_val_if_fail(dscp, FALSE);

    if (!NM_IN_STRSET(dscp, "CS0", "CS4", "CS6")) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("invalid DSCP value; allowed values are: 'CS0', 'CS4', 'CS6'"));
        return FALSE;
    }

    return TRUE;
}

gboolean
nm_utils_validate_shared_dhcp_range(const char *shared_dhcp_range,
                                    GPtrArray  *addresses,
                                    GError    **error)
{
    const char   *start_address_str;
    const char   *end_address_str;
    NMIPAddress  *interface_address_with_prefix;
    NMIPAddr      interface_address;
    NMIPAddr      start_address;
    NMIPAddr      end_address;
    guint32       i;
    guint32       mask;
    guint32       prefix_length;
    guint32       start_network;
    guint32       end_network;
    guint32       interface_network;
    guint32       start_ip_length;
    bool          range_is_in_interface_network;
    gs_free char *to_free = NULL;

    g_return_val_if_fail(!error || !(*error), FALSE);

    if (!shared_dhcp_range) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("NULL DHCP range; it should be provided as <START_IP>,<END_IP>."));
        return FALSE;
    }

    if (!*shared_dhcp_range) {
        return TRUE;
    }

    if (!addresses) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("Non-NULL range and NULL addresses detected."));
        return FALSE;
    }

    end_address_str = strchr(shared_dhcp_range, ',');
    if (!end_address_str) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("Invalid DHCP range; it should be provided as <START_IP>,<END_IP>."));
        return FALSE;
    }

    start_ip_length = end_address_str - shared_dhcp_range;
    if (start_ip_length > 15) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("Start IP has invalid length."));
        return FALSE;
    }

    start_address_str = nm_strndup_a(200, shared_dhcp_range, start_ip_length, &to_free);
    ++end_address_str; /* end address is pointing to ',', shift it to the actual address */

    if (!nm_inet_parse_bin(AF_INET, start_address_str, NULL, &start_address)) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("Start IP is invalid."));
        return FALSE;
    }

    if (!nm_inet_parse_bin(AF_INET, end_address_str, NULL, &end_address)) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("End IP is invalid."));
        return FALSE;
    }

    if (ntohl(start_address.addr4) > ntohl(end_address.addr4)) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("Start IP should be lower than the end IP."));
        return FALSE;
    }

    range_is_in_interface_network = FALSE;
    for (i = 0; i < (*addresses).len; ++i) {
        interface_address_with_prefix = (NMIPAddress *) addresses->pdata[i];
        nm_inet_parse_bin(AF_INET,
                          nm_ip_address_get_address(interface_address_with_prefix),
                          NULL,
                          &interface_address);
        prefix_length = nm_ip_address_get_prefix(interface_address_with_prefix);
        mask          = nm_utils_ip4_prefix_to_netmask(prefix_length);

        interface_network = interface_address.addr4 & mask;
        start_network     = start_address.addr4 & mask;
        end_network       = end_address.addr4 & mask;

        if (start_network == interface_network && end_network == interface_network) {
            range_is_in_interface_network = TRUE;
            break;
        }
    }

    if (!range_is_in_interface_network) {
        g_set_error_literal(
            error,
            NM_CONNECTION_ERROR,
            NM_CONNECTION_ERROR_INVALID_PROPERTY,
            _("Requested range is not in any network configured on the interface."));
        return FALSE;
    }

    return TRUE;
}

gboolean
nm_utils_validate_shared_dhcp_lease_time(int shared_dhcp_lease_time, GError **error)
{
    g_return_val_if_fail(!error || !(*error), FALSE);

    if (shared_dhcp_lease_time == 0 || shared_dhcp_lease_time == G_MAXINT32) {
        return TRUE;
    }

    if (shared_dhcp_lease_time < NM_MIN_FINITE_LEASE_TIME
        || NM_MAX_FINITE_LEASE_TIME < shared_dhcp_lease_time) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("Invalid DHCP lease time value; it should be either default or a positive "
                      "number between %u and %u or %s."),
                    NM_MIN_FINITE_LEASE_TIME,
                    NM_MAX_FINITE_LEASE_TIME,
                    NM_INFINITE_LEASE_TIME);
        return FALSE;
    }

    return TRUE;
}

gboolean
nm_settings_connection_validate_permission_user(const char *item, gssize len)
{
    gsize l;

    if (!item)
        return FALSE;

    if (len < 0) {
        nm_assert(len == -1);
        l = strlen(item);
    } else
        l = (gsize) len;

    if (l == 0)
        return FALSE;

    if (!g_utf8_validate(item, l, NULL))
        return FALSE;

    if (l >= 100)
        return FALSE;

    if (memchr(item, ':', l))
        return FALSE;

    return TRUE;
}

gpointer
_nm_connection_ensure_setting(NMConnection *connection, GType gtype)
{
    return nm_connection_get_setting(connection, gtype)
               ?: _nm_connection_new_setting(connection, gtype);
}

gpointer
_nm_connection_new_setting(NMConnection *connection, GType gtype)
{
    NMSetting *setting;

    nm_assert(g_type_is_a(gtype, NM_TYPE_SETTING));

    setting = g_object_new(gtype, NULL);
    nm_connection_add_setting(connection, setting);
    return setting;
}

/*****************************************************************************/

NMMptcpFlags
nm_mptcp_flags_normalize(NMMptcpFlags flags)
{
    /* Certain combinations of flags are incompatible. Normalize them.
     *
     * This function never returns 0x0 (NONE). If the flags are neither
     * disabled,enabled-on-global-iface,enabled, then we default to "enabled". */

    if (NM_FLAGS_HAS(flags, NM_MPTCP_FLAGS_DISABLED)) {
        /* If the disabled flag is set, then that's the end of it. */
        return NM_MPTCP_FLAGS_DISABLED;
    }

    /* Clear all unknown flags. */
    flags &= _NM_MPTCP_FLAGS_ALL;

    /* Not disabled means enabled. */
    flags |= NM_MPTCP_FLAGS_ENABLED;

    if (NM_FLAGS_ALL(flags, NM_MPTCP_FLAGS_SIGNAL | NM_MPTCP_FLAGS_FULLMESH))
        flags = NM_FLAGS_UNSET(flags, NM_MPTCP_FLAGS_FULLMESH);

    return flags;
}

/*****************************************************************************/

/*
 * nm_dns_uri_parse:
 * @addr_family: the address family, or AF_UNSPEC to autodetect it
 * @str: the name server URI string to parse
 * @dns: the name server descriptor to fill, or %NULL
 * @error: the error to set if the string cannot be parsed
 *
 * Parses the given name server URI string. Each name server is represented
 * by the following grammar:
 *
 *   NAMESERVER   := { PLAIN | TLS_URI | UDP_URI }
 *   PLAIN        := { ipv4address | ipv6address } [ '#' SERVERNAME ]
 *   TLS_URI      := 'dns+tls://' URI_ADDRESS [ ':' PORT ] [ '#' SERVERNAME ]
 *   UDP_URI      := 'dns+udp://' URI_ADDRESS [ ':' PORT ]
 *   URI_ADDRESS  := { ipv4address | '[' ipv6address [ '%' ifname ] ']' }
 *
 * Examples:
 *
 *   192.0.2.0
 *   192.0.2.0#example.com
 *   2001:db8::1
 *   dns+tls://192.0.2.0
 *   dns+tls://[2001:db8::1]
 *   dns+tls://192.0.2.0:53#example.com
 *   dns+udp://[fe80::1%enp1s0]
 *
 * Note that on return, the lifetime of the members in the @dns struct is
 * the same as the input string @str.
 *
 * Returns: %TRUE on success, %FALSE on failure
 */
gboolean
nm_dns_uri_parse(int addr_family, const char *str, NMDnsServer *dns, GError **error)
{
    NMDnsServer   dns_stack;
    gs_free char *addr_port_heap = NULL;
    gs_free char *addr_heap      = NULL;
    const char   *addr_port;
    const char   *addr;
    const char   *name;
    const char   *port;

    nm_assert_addr_family_or_unspec(addr_family);

    if (!dns)
        dns = &dns_stack;

    if (!str) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("the string is empty"));
        return FALSE;
    }

    *dns = (NMDnsServer) {0};

    if (NM_STR_HAS_PREFIX(str, "dns+tls://")) {
        dns->scheme = NM_DNS_URI_SCHEME_TLS;
        str += NM_STRLEN("dns+tls://");
    } else if (NM_STR_HAS_PREFIX(str, "dns+udp://")) {
        dns->scheme = NM_DNS_URI_SCHEME_UDP;
        str += NM_STRLEN("dns+udp://");
    } else {
        name = strchr(str, '#');
        if (name) {
            str = nm_strndup_a(200, str, name - str, &addr_heap);
            name++;
        }

        if (name && name[0] == '\0') {
            g_set_error_literal(error,
                                NM_CONNECTION_ERROR,
                                NM_CONNECTION_ERROR_INVALID_PROPERTY,
                                _("the DNS-over-TLS server name is empty"));
            return FALSE;
        }

        if (!nm_inet_parse_bin(addr_family, str, &dns->addr_family, &dns->addr)) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_INVALID_PROPERTY,
                        _("\"%s\" is not a valid IP address or a supported URI"),
                        str);
            return FALSE;
        }

        dns->servername = name;
        dns->scheme     = NM_DNS_URI_SCHEME_NONE;

        return TRUE;
    }

    addr_port = str;
    name      = strrchr(addr_port, '#');
    if (name) {
        addr_port = nm_strndup_a(100, addr_port, name - addr_port, &addr_port_heap);
        name++;
        if (*name == '\0') {
            g_set_error_literal(error,
                                NM_CONNECTION_ERROR,
                                NM_CONNECTION_ERROR_INVALID_PROPERTY,
                                _("the DNS-over-TLS server name is empty"));
            return FALSE;
        }
        dns->servername = name;
    }

    if (addr_family != AF_INET && *addr_port == '[') {
        const char *end;
        char       *perc;

        addr_family = AF_INET6;
        addr_port++;
        end = strchr(addr_port, ']');
        if (!end) {
            g_set_error_literal(error,
                                NM_CONNECTION_ERROR,
                                NM_CONNECTION_ERROR_INVALID_PROPERTY,
                                _("unterminated square bracket"));
            return FALSE;
        }
        addr = nm_strndup_a(100, addr_port, end - addr_port, &addr_heap);

        /* IPv6 link-local scope-id */
        perc = (char *) strchr(addr, '%');
        if (perc) {
            *perc = '\0';
            if (g_strlcpy(dns->interface, perc + 1, sizeof(dns->interface))
                >= sizeof(dns->interface)) {
                g_set_error_literal(error,
                                    NM_CONNECTION_ERROR,
                                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                                    _("the interface name is too long"));
                return FALSE;
            }
        }

        /* port */
        end++;
        if (*end == ':') {
            end++;
            dns->port = _nm_utils_ascii_str_to_int64(end, 10, 1, 65535, 0);
            if (dns->port == 0) {
                g_set_error(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("\"%s\" is not a valid port number"),
                            end);
                return FALSE;
            }
        }
    } else if (addr_family != AF_INET6) {
        /* square brackets are mandatory for IPv6, so it must be IPv4 */

        addr_family = AF_INET;
        addr        = addr_port;

        /* port */
        port = strchr(addr_port, ':');
        if (port) {
            addr = nm_strndup_a(100, addr_port, port - addr_port, &addr_heap);
            port++;
            dns->port = _nm_utils_ascii_str_to_int64(port, 10, 1, 65535, 0);
            if (dns->port == 0) {
                g_set_error(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("\"%s\" is not a valid port number"),
                            port);
                return FALSE;
            }
        }
    } else {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("IPv6 addresses must be enclosed in square brackets"));
        return FALSE;
    }

    if (!nm_inet_parse_bin(addr_family, addr, &dns->addr_family, &dns->addr)) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("\"%s\" is not a valid IP address"),
                    addr);
        return FALSE;
    }

    if (dns->scheme != NM_DNS_URI_SCHEME_TLS && dns->servername) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("the server name is only supported for DNS-over-TLS"));
        return FALSE;
    }

    /* For now, allow the interface only for IPv6 link-local addresses */
    if (dns->interface[0]
        && (dns->addr_family != AF_INET6 || !IN6_IS_ADDR_LINKLOCAL(&dns->addr.addr6))) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("the scope-id is only supported for IPv6 link-local addresses"));
        return FALSE;
    }

    return TRUE;
}

/* @nm_dns_uri_parse_plain:
 * @addr_family: the address family, or AF_UNSPEC to autodetect it
 * @str: the name server URI string
 * @out_addrstr: the buffer to fill with the address string on return,
 *   or %NULL. Must be of size at least NM_INET_ADDRSTRLEN.
 * @out_addr: the %NMIPAddr struct to fill on return, or %NULL
 *
 * Returns whether the string contains a "plain" (DNS over UDP on port 53)
 * name server. In such case, it fills the arguments with the address
 * of the name server.
 *
 * Returns: %TRUE on success, %FALSE if the string can't be parsed or
 *   if it's not a plain name server.
 */
gboolean
nm_dns_uri_parse_plain(int addr_family, const char *str, char *out_addrstr, NMIPAddr *out_addr)
{
    NMDnsServer dns;

    if (!nm_dns_uri_parse(addr_family, str, &dns, NULL))
        return FALSE;

    switch (dns.scheme) {
    case NM_DNS_URI_SCHEME_TLS:
        return FALSE;
    case NM_DNS_URI_SCHEME_NONE:
        NM_SET_OUT(out_addr, dns.addr);
        if (out_addrstr) {
            nm_inet_ntop(dns.addr_family, &dns.addr, out_addrstr);
        }
        return TRUE;
    case NM_DNS_URI_SCHEME_UDP:
        if (dns.port != NM_DNS_PORT_UNDEFINED && dns.port != 53)
            return FALSE;
        if (dns.interface[0])
            return FALSE;
        NM_SET_OUT(out_addr, dns.addr);
        if (out_addrstr) {
            nm_inet_ntop(dns.addr_family, &dns.addr, out_addrstr);
        }
        return TRUE;
    case NM_DNS_URI_SCHEME_UNKNOWN:
    default:
        return FALSE;
    }
}

/* @nm_dns_uri_normalize:
 * @addr_family: the address family, or AF_UNSPEC to autodetect it
 * @str: the name server URI string
 * @out_free: the newly-allocated string to set on return, or %NULL
 *
 * Returns the "normal" representation for the given name server URI.
 * Note that a plain name server (DNS over UDP on port 53) is always
 * represented in the "legacy" (non-URI) form.
 *
 * Returns: the normalized DNS URI
 */
const char *
nm_dns_uri_normalize(int addr_family, const char *str, char **out_free)
{
    NMDnsServer dns;
    char        addrstr[NM_INET_ADDRSTRLEN];
    char        portstr[32];
    char       *ret;
    gsize       len;

    nm_assert_addr_family_or_unspec(addr_family);
    nm_assert(str);
    nm_assert(out_free && !*out_free);

    if (!nm_dns_uri_parse(addr_family, str, &dns, NULL))
        return NULL;

    nm_inet_ntop(dns.addr_family, &dns.addr, addrstr);

    if (dns.port != NM_DNS_PORT_UNDEFINED) {
        nm_assert(dns.port >= 1 && dns.port <= 65535);
        g_snprintf(portstr, sizeof(portstr), "%" G_GUINT16_FORMAT, dns.port);
    }

    switch (dns.scheme) {
    case NM_DNS_URI_SCHEME_NONE:
        len = strlen(addrstr);
        /* In the vast majority of cases, the name is in fact normalized. Check
         * whether it is, and don't duplicate the string. */
        if (strncmp(str, addrstr, len) == 0) {
            if (dns.servername) {
                if (str[len] == '#' && nm_streq(&str[len + 1], dns.servername))
                    return str;
            } else {
                if (str[len] == '\0')
                    return str;
            }
        }

        if (!dns.servername)
            ret = g_strdup(addrstr);
        else
            ret = g_strconcat(addrstr, "#", dns.servername, NULL);
        break;
    case NM_DNS_URI_SCHEME_UDP:
        if (dns.interface[0] || dns.port != NM_DNS_PORT_UNDEFINED) {
            ret = g_strdup_printf("dns+udp://%s%s%s%s%s%s%s",
                                  dns.addr_family == AF_INET6 ? "[" : "",
                                  addrstr,
                                  dns.interface[0] ? "%" : "",
                                  dns.interface[0] ? dns.interface : "",
                                  dns.addr_family == AF_INET6 ? "]" : "",
                                  dns.port != NM_DNS_PORT_UNDEFINED ? ":" : "",
                                  dns.port != NM_DNS_PORT_UNDEFINED ? portstr : "");
            break;
        }
        ret = g_strdup_printf("%s%s%s", addrstr, dns.servername ? "#" : "", dns.servername ?: "");
        break;
    case NM_DNS_URI_SCHEME_TLS:
        ret = g_strdup_printf("dns+tls://%s%s%s%s%s%s%s%s%s",
                              dns.addr_family == AF_INET6 ? "[" : "",
                              addrstr,
                              dns.interface[0] ? "%%" : "",
                              dns.interface[0] ? dns.interface : "",
                              dns.addr_family == AF_INET6 ? "]" : "",
                              dns.port != NM_DNS_PORT_UNDEFINED ? ":" : "",
                              dns.port != NM_DNS_PORT_UNDEFINED ? portstr : "",
                              dns.servername ? "#" : "",
                              dns.servername ?: "");
        break;
    case NM_DNS_URI_SCHEME_UNKNOWN:
    default:
        nm_assert_not_reached();
        ret = NULL;
    }

    *out_free = ret;

    return ret;
}

/*****************************************************************************/

/**
 * nm_setting_ovs_other_config_check_key:
 * @key: (nullable): the key to check
 * @error: a #GError, %NULL to ignore.
 *
 * Checks whether @key is a valid key for OVS' other-config.
 * This means, the key cannot be %NULL, not too large and valid ASCII.
 * Also, only digits and numbers are allowed with a few special
 * characters.
 *
 * Returns: %TRUE if @key is a valid user data key.
 */
gboolean
nm_setting_ovs_other_config_check_key(const char *key, GError **error)
{
    gsize len;

    g_return_val_if_fail(!error || !*error, FALSE);

    if (!key || !key[0]) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("missing key"));
        return FALSE;
    }
    len = strlen(key);
    if (len > 255u) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("key is too long"));
        return FALSE;
    }
    if (!g_utf8_validate(key, len, NULL)) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("key must be UTF8"));
        return FALSE;
    }
    if (!NM_STRCHAR_ALL(key, ch, nm_ascii_is_regular_char(ch))) {
        /* Probably OVS is more forgiving about what makes a valid key for
         * an other-key. However, we are strict (at least, for now). */
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("key contains invalid characters"));
        return FALSE;
    }

    return TRUE;
}

/**
 * nm_setting_ovs_other_config_check_val:
 * @val: (nullable): the value to check
 * @error: a #GError, %NULL to ignore.
 *
 * Checks whether @val is a valid user data value. This means,
 * value is not %NULL, not too large and valid UTF-8.
 *
 * Returns: %TRUE if @val is a valid user data value.
 */
gboolean
nm_setting_ovs_other_config_check_val(const char *val, GError **error)
{
    gsize len;

    g_return_val_if_fail(!error || !*error, FALSE);

    if (!val) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("value is missing"));
        return FALSE;
    }

    len = strlen(val);
    if (len > (2u * 1024u)) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("value is too large"));
        return FALSE;
    }

    if (!g_utf8_validate(val, len, NULL)) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("value is not valid UTF8"));
        return FALSE;
    }

    return TRUE;
}

/*****************************************************************************/

typedef struct {
    NMIPAddr dest;
    guint    prefix;
} DirectRoute;

static void
_setting_ip_config_collect_unreachable_gateways(NMSettingIPConfig *s_ip, GHashTable **result)
{
    const int            addr_family = nm_setting_ip_config_get_addr_family(s_ip);
    guint                num_routes;
    guint                num_addrs;
    guint                n_direct_routes = 0;
    NMIPAddr             gw_bin          = NM_IP_ADDR_INIT;
    guint                i;
    guint                j;
    const char          *gateway;
    gs_free DirectRoute *direct_routes = NULL;

    num_routes = nm_setting_ip_config_get_num_routes(s_ip);
    num_addrs  = nm_setting_ip_config_get_num_addresses(s_ip);

    direct_routes = g_new0(DirectRoute, num_routes + num_addrs);

    /* Collect direct routes (routes without a gateway) from the setting. */
    for (i = 0; i < num_routes; i++) {
        NMIPRoute *route = nm_setting_ip_config_get_route(s_ip, i);

        if (nm_ip_route_get_next_hop(route))
            continue;

        nm_ip_route_get_dest_binary(route, &direct_routes[n_direct_routes].dest);
        direct_routes[n_direct_routes].prefix = nm_ip_route_get_prefix(route);
        n_direct_routes++;
    }

    /* Add prefix routes (device routes) for each static address. */
    for (i = 0; i < num_addrs; i++) {
        NMIPAddress *addr = nm_setting_ip_config_get_address(s_ip, i);

        nm_ip_address_get_address_binary(addr, &direct_routes[n_direct_routes].dest);
        direct_routes[n_direct_routes].prefix = nm_ip_address_get_prefix(addr);
        n_direct_routes++;
    }

    /* Check the setting's default gateway. */
    gateway = nm_setting_ip_config_get_gateway(s_ip);
    if (gateway && nm_inet_parse_bin(addr_family, gateway, NULL, &gw_bin)) {
        gboolean reachable = FALSE;

        if (addr_family == AF_INET6 && IN6_IS_ADDR_LINKLOCAL(&gw_bin.addr6))
            reachable = TRUE;

        if (!reachable) {
            for (j = 0; j < n_direct_routes; j++) {
                if (nm_ip_addr_same_prefix(addr_family,
                                           &gw_bin,
                                           &direct_routes[j].dest,
                                           direct_routes[j].prefix)) {
                    reachable = TRUE;
                    break;
                }
            }
        }

        if (!reachable) {
            if (!*result)
                *result = g_hash_table_new(nm_str_hash, g_str_equal);
            g_hash_table_add(*result, (gpointer) gateway);
        }
    }

    /* Check gateways of each route in the setting. */
    for (i = 0; i < num_routes; i++) {
        NMIPRoute *route     = nm_setting_ip_config_get_route(s_ip, i);
        NMIPAddr   next_hop  = NM_IP_ADDR_INIT;
        gboolean   reachable = FALSE;
        GVariant  *attribute;

        if (!nm_ip_route_get_next_hop_binary(route, &next_hop))
            continue;

        if (addr_family == AF_INET6 && IN6_IS_ADDR_LINKLOCAL(&next_hop.addr6))
            continue;

        attribute = nm_ip_route_get_attribute(route, NM_IP_ROUTE_ATTRIBUTE_ONLINK);
        if (attribute && g_variant_is_of_type(attribute, G_VARIANT_TYPE("b"))
            && g_variant_get_boolean(attribute)) {
            /* the gateway of a onlink route is reachable */
            continue;
        }

        for (j = 0; j < n_direct_routes; j++) {
            if (nm_ip_addr_same_prefix(addr_family,
                                       &next_hop,
                                       &direct_routes[j].dest,
                                       direct_routes[j].prefix)) {
                reachable = TRUE;
                break;
            }
        }

        if (!reachable) {
            if (!*result)
                *result = g_hash_table_new(nm_str_hash, g_str_equal);
            g_hash_table_add(*result, (gpointer) nm_ip_route_get_next_hop(route));
        }
    }
}

/**
 * nm_connection_get_unreachable_gateways:
 * @connection: the #NMConnection
 *
 * Checks whether there are gateways (either the default gateway or gateways
 * of routes) that are not directly reachable in the IPv4 and IPv6 settings
 * of the connection. A gateway is considered directly reachable if it falls
 * within the subnet of a direct route (a route without a next hop) or of a
 * prefix route from a static address.
 *
 * Returns: a %NULL-terminated array of gateway strings not directly reachable,
 *   or %NULL if all gateways are reachable. The individual strings are owned
 *   by the setting. Free the returned array with g_free().
 */
const char **
nm_connection_get_unreachable_gateways(NMConnection *connection)
{
    gs_unref_hashtable GHashTable *result = NULL;
    NMSettingIPConfig             *s_ip;
    guint                          len;
    const char                   **strv;

    if (!connection)
        return NULL;

    s_ip = nm_connection_get_setting_ip4_config(connection);
    if (s_ip
        && nm_streq0(nm_setting_ip_config_get_method(s_ip), NM_SETTING_IP4_CONFIG_METHOD_MANUAL)) {
        _setting_ip_config_collect_unreachable_gateways(s_ip, &result);
    }

    s_ip = nm_connection_get_setting_ip6_config(connection);
    if (s_ip
        && nm_streq0(nm_setting_ip_config_get_method(s_ip), NM_SETTING_IP6_CONFIG_METHOD_MANUAL)) {
        _setting_ip_config_collect_unreachable_gateways(s_ip, &result);
    }

    if (result) {
        strv = (const char **) g_hash_table_get_keys_as_array(result, &len);
        nm_strv_sort(strv, len);
        return strv;
    }

    return NULL;
}
