/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "libnm-core/nm-default-libnm-core.h"

#include "nm-libnm-core-utils.h"

#include <linux/rtnetlink.h>

#include "nm-common-macros.h"
#include "nm-errors.h"

/*****************************************************************************/

const char **
nm_utils_bond_option_arp_ip_targets_split(const char *arp_ip_target)
{
    return nm_utils_strsplit_set_full(arp_ip_target, ",", NM_UTILS_STRSPLIT_SET_FLAGS_STRSTRIP);
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
                                     const char *      str,
                                     gboolean          allow_wildcard_to,
                                     guint32 *         out_from,
                                     guint32 *         out_to,
                                     gboolean *        out_has_wildcard_to)
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
    const char *                    ss     = nm_auth_permission_names_by_idx[*p - 1];

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
    idx = nm_utils_array_find_binary_search(nm_auth_permission_sorted,
                                            sizeof(nm_auth_permission_sorted[0]),
                                            G_N_ELEMENTS(nm_auth_permission_sorted),
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

NM_UTILS_STRING_TABLE_LOOKUP_DEFINE(
    nm_utils_route_type_by_name,
    guint8,
    { nm_assert(name); },
    { return RTN_UNSPEC; },
    {"blackhole", RTN_BLACKHOLE},
    {"broadcast", RTN_BROADCAST},
    {"local", RTN_LOCAL},
    {"multicast", RTN_MULTICAST},
    {"nat", RTN_NAT},
    {"prohibit", RTN_PROHIBIT},
    {"throw", RTN_THROW},
    {"unicast", RTN_UNICAST},
    {"unreachable", RTN_UNREACHABLE}, );

NM_UTILS_ENUM2STR_DEFINE(nm_utils_route_type2str,
                         guint8,
                         NM_UTILS_ENUM2STR(RTN_BLACKHOLE, "blackhole"),
                         NM_UTILS_ENUM2STR(RTN_BROADCAST, "broadcast"),
                         NM_UTILS_ENUM2STR(RTN_LOCAL, "local"),
                         NM_UTILS_ENUM2STR(RTN_MULTICAST, "multicast"),
                         NM_UTILS_ENUM2STR(RTN_NAT, "nat"),
                         NM_UTILS_ENUM2STR(RTN_PROHIBIT, "prohibit"),
                         NM_UTILS_ENUM2STR(RTN_THROW, "throw"),
                         NM_UTILS_ENUM2STR(RTN_UNICAST, "unicast"),
                         NM_UTILS_ENUM2STR(RTN_UNREACHABLE, "unreachable"),
                         NM_UTILS_ENUM2STR(RTN_UNSPEC, "unspecified"), );

gboolean
nm_utils_validate_dhcp4_vendor_class_id(const char *vci, GError **error)
{
    const char *  bin;
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
