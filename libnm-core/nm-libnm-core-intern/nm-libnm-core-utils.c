// SPDX-License-Identifier: LGPL-2.1+

#include "nm-default.h"

#include "nm-libnm-core-utils.h"

#include "nm-common-macros.h"

#include <linux/rtnetlink.h>

/*****************************************************************************/

gboolean
nm_utils_vlan_priority_map_parse_str (NMVlanPriorityMap map_type,
                                      const char *str,
                                      gboolean allow_wildcard_to,
                                      guint32 *out_from,
                                      guint32 *out_to,
                                      gboolean *out_has_wildcard_to)
{
	const char *s2;
	gint64 v1, v2;

	nm_assert (str);

	s2 = strchr (str, ':');

	if (!s2) {
		if (!allow_wildcard_to)
			return FALSE;
		v1 = _nm_utils_ascii_str_to_int64 (str, 10, 0, G_MAXUINT32, -1);
		v2 = -1;
	} else {
		gs_free char *s1_free = NULL;
		gsize s1_len = (s2 - str);

		s2 = nm_str_skip_leading_spaces (&s2[1]);
		if (   s2[0] == '\0'
		    || (   s2[0] == '*'
		        && NM_STRCHAR_ALL (&s2[1], ch, g_ascii_isspace (ch)))) {
			if (!allow_wildcard_to)
				return FALSE;
			v2 = -1;
		} else {
			v2 = _nm_utils_ascii_str_to_int64 (s2, 10, 0, G_MAXUINT32, -1);
			if (   v2 < 0
			    || (guint32) v2 > nm_utils_vlan_priority_map_get_max_prio (map_type, FALSE))
				return FALSE;
		}

		v1 = _nm_utils_ascii_str_to_int64 (nm_strndup_a (100, str, s1_len, &s1_free),
		                                   10, 0, G_MAXUINT32, -1);
	}

	if (   v1 < 0
	    || (guint32) v1 > nm_utils_vlan_priority_map_get_max_prio (map_type, TRUE))
		return FALSE;

	NM_SET_OUT (out_from, v1);
	NM_SET_OUT (out_to,   v2 < 0
	                    ? 0u
	                    : (guint) v2);
	NM_SET_OUT (out_has_wildcard_to, v2 < 0);
	return TRUE;
}

/*****************************************************************************/

const char *const nm_auth_permission_names_by_idx[NM_CLIENT_PERMISSION_LAST] = {
	[NM_CLIENT_PERMISSION_CHECKPOINT_ROLLBACK - 1]               = NM_AUTH_PERMISSION_CHECKPOINT_ROLLBACK,
	[NM_CLIENT_PERMISSION_ENABLE_DISABLE_CONNECTIVITY_CHECK - 1] = NM_AUTH_PERMISSION_ENABLE_DISABLE_CONNECTIVITY_CHECK,
	[NM_CLIENT_PERMISSION_ENABLE_DISABLE_NETWORK - 1]            = NM_AUTH_PERMISSION_ENABLE_DISABLE_NETWORK,
	[NM_CLIENT_PERMISSION_ENABLE_DISABLE_STATISTICS - 1]         = NM_AUTH_PERMISSION_ENABLE_DISABLE_STATISTICS,
	[NM_CLIENT_PERMISSION_ENABLE_DISABLE_WIFI - 1]               = NM_AUTH_PERMISSION_ENABLE_DISABLE_WIFI,
	[NM_CLIENT_PERMISSION_ENABLE_DISABLE_WIMAX - 1]              = NM_AUTH_PERMISSION_ENABLE_DISABLE_WIMAX,
	[NM_CLIENT_PERMISSION_ENABLE_DISABLE_WWAN - 1]               = NM_AUTH_PERMISSION_ENABLE_DISABLE_WWAN,
	[NM_CLIENT_PERMISSION_NETWORK_CONTROL - 1]                   = NM_AUTH_PERMISSION_NETWORK_CONTROL,
	[NM_CLIENT_PERMISSION_RELOAD - 1]                            = NM_AUTH_PERMISSION_RELOAD,
	[NM_CLIENT_PERMISSION_SETTINGS_MODIFY_GLOBAL_DNS - 1]        = NM_AUTH_PERMISSION_SETTINGS_MODIFY_GLOBAL_DNS,
	[NM_CLIENT_PERMISSION_SETTINGS_MODIFY_HOSTNAME - 1]          = NM_AUTH_PERMISSION_SETTINGS_MODIFY_HOSTNAME,
	[NM_CLIENT_PERMISSION_SETTINGS_MODIFY_OWN - 1]               = NM_AUTH_PERMISSION_SETTINGS_MODIFY_OWN,
	[NM_CLIENT_PERMISSION_SETTINGS_MODIFY_SYSTEM - 1]            = NM_AUTH_PERMISSION_SETTINGS_MODIFY_SYSTEM,
	[NM_CLIENT_PERMISSION_SLEEP_WAKE - 1]                        = NM_AUTH_PERMISSION_SLEEP_WAKE,
	[NM_CLIENT_PERMISSION_WIFI_SCAN - 1]                         = NM_AUTH_PERMISSION_WIFI_SCAN,
	[NM_CLIENT_PERMISSION_WIFI_SHARE_OPEN - 1]                   = NM_AUTH_PERMISSION_WIFI_SHARE_OPEN,
	[NM_CLIENT_PERMISSION_WIFI_SHARE_PROTECTED - 1]              = NM_AUTH_PERMISSION_WIFI_SHARE_PROTECTED,
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
nm_auth_permission_to_string (NMClientPermission permission)
{
	if (permission < 1)
		return NULL;
	if (permission > NM_CLIENT_PERMISSION_LAST)
		return NULL;
	return nm_auth_permission_names_by_idx[permission - 1];
}

#define AUTH_PERMISSION_PREFIX "org.freedesktop.NetworkManager."

static int
_nm_auth_permission_from_string_cmp (gconstpointer a, gconstpointer b, gpointer user_data)
{
	const NMClientPermission *const p = a;
	const char *const needle = b;
	const char *ss = nm_auth_permission_names_by_idx[*p - 1];

	nm_assert (NM_STR_HAS_PREFIX (ss, AUTH_PERMISSION_PREFIX));
	nm_assert (ss[NM_STRLEN (AUTH_PERMISSION_PREFIX)] != '\0');

	return strcmp (&ss[NM_STRLEN (AUTH_PERMISSION_PREFIX)], needle);
}

NMClientPermission
nm_auth_permission_from_string (const char *str)
{
	gssize idx;

	if (!str)
		return NM_CLIENT_PERMISSION_NONE;

	if (!NM_STR_HAS_PREFIX (str, AUTH_PERMISSION_PREFIX))
		return NM_CLIENT_PERMISSION_NONE;
	idx = nm_utils_array_find_binary_search (nm_auth_permission_sorted,
	                                         sizeof (nm_auth_permission_sorted[0]),
	                                         G_N_ELEMENTS (nm_auth_permission_sorted),
	                                         &str[NM_STRLEN (AUTH_PERMISSION_PREFIX)],
	                                         _nm_auth_permission_from_string_cmp,
	                                         NULL);
	if (idx < 0)
		return NM_CLIENT_PERMISSION_NONE;
	return nm_auth_permission_sorted[idx];
}

/*****************************************************************************/

NMClientPermissionResult
nm_client_permission_result_from_string (const char *nm)
{
	if (!nm)
		return NM_CLIENT_PERMISSION_RESULT_UNKNOWN;
	if (nm_streq (nm, "yes"))
		return NM_CLIENT_PERMISSION_RESULT_YES;
	if (nm_streq (nm, "no"))
		return NM_CLIENT_PERMISSION_RESULT_NO;
	if (nm_streq (nm, "auth"))
		return NM_CLIENT_PERMISSION_RESULT_AUTH;
	return NM_CLIENT_PERMISSION_RESULT_UNKNOWN;
}

const char *
nm_client_permission_result_to_string (NMClientPermissionResult permission)
{
	switch (permission) {
	case NM_CLIENT_PERMISSION_RESULT_YES:     return "yes";
	case NM_CLIENT_PERMISSION_RESULT_NO:      return "no";
	case NM_CLIENT_PERMISSION_RESULT_AUTH:    return "auth";
	case NM_CLIENT_PERMISSION_RESULT_UNKNOWN: return "unknown";
	}
	nm_assert_not_reached ();
	return NULL;
}

NM_UTILS_STRING_TABLE_LOOKUP_DEFINE (
	nm_utils_route_type_by_name,
	guint8,
	{ nm_assert (name); },
	{ return RTN_UNSPEC; },
	{ "blackhole",   RTN_BLACKHOLE   },
	{ "broadcast",   RTN_BROADCAST   },
	{ "local",       RTN_LOCAL       },
	{ "multicast",   RTN_MULTICAST   },
	{ "nat",         RTN_NAT         },
	{ "prohibit",    RTN_PROHIBIT    },
	{ "throw",       RTN_THROW       },
	{ "unicast",     RTN_UNICAST     },
	{ "unreachable", RTN_UNREACHABLE },
);

NM_UTILS_ENUM2STR_DEFINE (nm_utils_route_type2str, guint8,
	NM_UTILS_ENUM2STR (RTN_BLACKHOLE, "blackhole"),
	NM_UTILS_ENUM2STR (RTN_BROADCAST, "broadcast"),
	NM_UTILS_ENUM2STR (RTN_LOCAL, "local"),
	NM_UTILS_ENUM2STR (RTN_MULTICAST, "multicast"),
	NM_UTILS_ENUM2STR (RTN_NAT, "nat"),
	NM_UTILS_ENUM2STR (RTN_PROHIBIT, "prohibit"),
	NM_UTILS_ENUM2STR (RTN_THROW, "throw"),
	NM_UTILS_ENUM2STR (RTN_UNICAST, "unicast"),
	NM_UTILS_ENUM2STR (RTN_UNREACHABLE, "unreachable"),
);
