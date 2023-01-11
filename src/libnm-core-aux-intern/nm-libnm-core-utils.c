/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "libnm-glib-aux/nm-default-glib-i18n-lib.h"

#include "nm-libnm-core-utils.h"

#include <linux/rtnetlink.h>

#include "nm-common-macros.h"
#include "nm-errors.h"
#include "libnm-core-public/nm-connection.h"

/*****************************************************************************/

const char **
nm_utils_bond_option_arp_ip_targets_split(const char *arp_ip_target)
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

gboolean
nm_utils_dnsname_parse(int                          addr_family,
                       const char                  *dns,
                       int                         *out_addr_family,
                       gpointer /* (NMIPAddr **) */ out_addr,
                       const char                 **out_servername)
{
    gs_free char *dns_heap = NULL;
    const char   *s;
    NMIPAddr      addr;

    nm_assert_addr_family_or_unspec(addr_family);
    nm_assert(!out_addr || out_addr_family || NM_IN_SET(addr_family, AF_INET, AF_INET6));

    if (!dns)
        return FALSE;

    s = strchr(dns, '#');

    if (s) {
        dns = nm_strndup_a(200, dns, s - dns, &dns_heap);
        s++;
    }

    if (s && s[0] == '\0') {
        /* "ADDR#" empty DoT SNI name is not allowed. */
        return FALSE;
    }

    if (!nm_inet_parse_bin(addr_family, dns, &addr_family, out_addr ? &addr : NULL))
        return FALSE;

    NM_SET_OUT(out_addr_family, addr_family);
    if (out_addr)
        nm_ip_addr_set(addr_family, out_addr, &addr);
    NM_SET_OUT(out_servername, s);
    return TRUE;
}

const char *
nm_utils_dnsname_construct(int                                    addr_family,
                           gconstpointer /* (const NMIPAddr *) */ addr,
                           const char                            *server_name,
                           char                                  *result,
                           gsize                                  result_len)
{
    char  sbuf[NM_INET_ADDRSTRLEN];
    gsize l;
    int   d;

    nm_assert_addr_family(addr_family);
    nm_assert(addr);
    nm_assert(!server_name || !nm_str_is_empty(server_name));

    nm_inet_ntop(addr_family, addr, sbuf);

    if (!server_name) {
        l = g_strlcpy(result, sbuf, result_len);
    } else {
        d = g_snprintf(result, result_len, "%s#%s", sbuf, server_name);
        nm_assert(d >= 0);
        l = (gsize) d;
    }

    return l < result_len ? result : NULL;
}

const char *
nm_utils_dnsname_normalize(int addr_family, const char *dns, char **out_free)
{
    char        sbuf[NM_INET_ADDRSTRLEN];
    const char *server_name;
    char       *s;
    NMIPAddr    a;
    gsize       l;

    nm_assert_addr_family_or_unspec(addr_family);
    nm_assert(dns);
    nm_assert(out_free && !*out_free);

    if (!nm_utils_dnsname_parse(addr_family, dns, &addr_family, &a, &server_name))
        return NULL;

    nm_inet_ntop(addr_family, &a, sbuf);

    l = strlen(sbuf);

    /* In the vast majority of cases, the name is in fact normalized. Check
     * whether it is, and don't duplicate the string. */
    if (strncmp(dns, sbuf, l) == 0) {
        if (server_name) {
            if (dns[l] == '#' && nm_streq(&dns[l + 1], server_name))
                return dns;
        } else {
            if (dns[l] == '\0')
                return dns;
        }
    }

    if (!server_name)
        s = g_strdup(sbuf);
    else
        s = g_strconcat(sbuf, "#", server_name, NULL);

    *out_free = s;
    return s;
}

/*****************************************************************************/

/**
 * nm_setting_ovs_other_config_check_key:
 * @key: (allow-none): the key to check
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
 * @val: (allow-none): the value to check
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
