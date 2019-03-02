/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager system settings service - keyfile plugin
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2008 - 2009 Novell, Inc.
 * Copyright (C) 2008 - 2017 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-keyfile-internal.h"

#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <linux/pkt_sched.h>

#include "nm-utils/nm-secret-utils.h"
#include "systemd/nm-sd-utils-shared.h"
#include "nm-common-macros.h"
#include "nm-core-internal.h"
#include "nm-keyfile-utils.h"

#include "nm-setting-user.h"

/*****************************************************************************/

typedef struct {
	NMConnection *connection;
	GKeyFile *keyfile;
	const char *base_dir;
	NMKeyfileReadHandler handler;
	void *user_data;
	GError *error;
	const char *group;
	NMSetting *setting;
} KeyfileReaderInfo;

typedef struct {
	NMConnection *connection;
	GKeyFile *keyfile;
	GError *error;
	NMKeyfileWriteHandler handler;
	void *user_data;
} KeyfileWriterInfo;

/*****************************************************************************/

static void
_handle_warn (KeyfileReaderInfo *info,
              const char *property_name,
              NMKeyfileWarnSeverity severity,
              char *message)
{
	NMKeyfileReadTypeDataWarn type_data = {
		.group = info->group,
		.setting = info->setting,
		.property_name = property_name,
		.severity = severity,
		.message = message,
	};

	info->handler (info->keyfile,
	               info->connection,
	               NM_KEYFILE_READ_TYPE_WARN,
	               &type_data,
	               info->user_data,
	               &info->error);
	g_free (message);
}
#define handle_warn(arg_info, arg_property_name, arg_severity, ...) \
	({ \
		KeyfileReaderInfo *_info = (arg_info); \
		\
		if (_info->handler) { \
			_handle_warn (_info, (arg_property_name), (arg_severity), \
			              g_strdup_printf (__VA_ARGS__)); \
		} \
		_info->error == NULL; \
	})

/*****************************************************************************/

static gboolean
_secret_flags_persist_secret (NMSettingSecretFlags flags)
{
	return flags == NM_SETTING_SECRET_FLAG_NONE;
}

/*****************************************************************************/
/* Some setting properties also contain setting names, such as
 * NMSettingConnection's 'type' property (which specifies the base type of the
 * connection, e.g. ethernet or wifi) or 'slave-type' (specifies type of slave
 * connection, e.g. bond or bridge). This function handles translating those
 * properties' values to the real setting name if they are an alias.
 */
static void
setting_alias_parser (KeyfileReaderInfo *info, NMSetting *setting, const char *key)
{
	const char *setting_name = nm_setting_get_name (setting);
	const char *key_setting_name;
	gs_free char *s = NULL;

	s = nm_keyfile_plugin_kf_get_string (info->keyfile, setting_name, key, NULL);
	if (!s)
		return;

	key_setting_name = nm_keyfile_plugin_get_setting_name_for_alias (s);
	g_object_set (G_OBJECT (setting),
	              key,
	              key_setting_name ?: s,
	              NULL);
}

static void
sriov_vfs_parser (KeyfileReaderInfo *info, NMSetting *setting, const char *key)
{
	const char *setting_name = nm_setting_get_name (setting);
	gs_unref_ptrarray GPtrArray *vfs = NULL;
	gs_strfreev char **keys = NULL;
	gsize n_keys = 0;
	int i;

	keys = nm_keyfile_plugin_kf_get_keys (info->keyfile, setting_name, &n_keys, NULL);
	if (n_keys == 0)
		return;

	vfs = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_sriov_vf_unref);

	for (i = 0; i < n_keys; i++) {
		gs_free char *value = NULL;
		NMSriovVF *vf;
		const char *rest;

		if (!g_str_has_prefix (keys[i], "vf."))
			continue;

		rest = &keys[i][3];

		if (!NM_STRCHAR_ALL (rest, ch, g_ascii_isdigit (ch)))
			continue;

		value = nm_keyfile_plugin_kf_get_string (info->keyfile,
		                                         setting_name,
		                                         keys[i],
		                                         NULL);

		vf = _nm_utils_sriov_vf_from_strparts (rest, value, TRUE, NULL);
		if (vf)
			g_ptr_array_add (vfs, vf);
	}

	g_object_set (G_OBJECT (setting),
	              key, vfs,
	              NULL);
}

static void
read_array_of_uint (GKeyFile *file,
                    NMSetting *setting,
                    const char *key)
{
	gs_unref_array GArray *array = NULL;
	gsize length;
	gsize i;
	gs_free int *tmp = NULL;

	tmp = nm_keyfile_plugin_kf_get_integer_list (file, nm_setting_get_name (setting), key, &length, NULL);
	if (length > G_MAXUINT)
		return;

	array = g_array_sized_new (FALSE, FALSE, sizeof (guint), length);

	for (i = 0; i < length; i++) {
		if (tmp[i] < 0)
			return;
		g_array_append_val (array, tmp[i]);
	}

	g_object_set (setting, key, array, NULL);
}

static gboolean
get_one_int (KeyfileReaderInfo *info, const char *property_name, const char *str, guint32 max_val, guint32 *out)
{
	gint64 tmp;

	g_return_val_if_fail (!info == !property_name, FALSE);

	if (!str || !str[0]) {
		if (property_name)
			handle_warn (info, property_name, NM_KEYFILE_WARN_SEVERITY_WARN,
			             _("ignoring missing number"));
		return FALSE;
	}

	tmp = _nm_utils_ascii_str_to_int64 (str, 10, 0, max_val, -1);
	if (tmp == -1) {
		if (property_name) {
			handle_warn (info, property_name, NM_KEYFILE_WARN_SEVERITY_WARN,
			             _("ignoring invalid number '%s'"),
			            str);
		}
		return FALSE;
	}

	*out = (guint32) tmp;
	return TRUE;
}

static gpointer
build_address (KeyfileReaderInfo *info, int family, const char *address_str, guint32 plen, const char *property_name)
{
	NMIPAddress *addr;
	GError *error = NULL;

	g_return_val_if_fail (address_str, NULL);

	addr = nm_ip_address_new (family, address_str, plen, &error);
	if (!addr) {
		handle_warn (info, property_name, NM_KEYFILE_WARN_SEVERITY_WARN,
		             _("ignoring invalid %s address: %s"),
		            family == AF_INET ? "IPv4" : "IPv6", error->message);
		g_error_free (error);
	}

	return addr;
}

static gpointer
build_route (KeyfileReaderInfo *info,
             const char *property_name,
             int family,
             const char *dest_str, guint32 plen,
             const char *gateway_str, const char *metric_str)
{
	NMIPRoute *route;
	guint32 u32;
	gint64 metric = -1;
	GError *error = NULL;

	g_return_val_if_fail (plen, NULL);
	g_return_val_if_fail (dest_str, NULL);

	/* Next hop */
	if (gateway_str && gateway_str[0]) {
		if (!nm_utils_ipaddr_valid (family, gateway_str)) {
			/* Try workaround for routes written by broken keyfile writer.
			 * Due to bug bgo#719851, an older version of writer would have
			 * written "a:b:c:d::/plen,metric" if the gateway was ::, instead
			 * of "a:b:c:d::/plen,,metric" or "a:b:c:d::/plen,::,metric"
			 * Try workaround by interpreting gateway_str as metric to accept such
			 * invalid routes. This broken syntax should not be not officially
			 * supported.
			 **/
			if (   family == AF_INET6
			    && !metric_str
			    && get_one_int (NULL, NULL, gateway_str, G_MAXUINT32, &u32)) {
				metric = u32;
				gateway_str = NULL;
			} else {
				if (!info->error) {
					handle_warn (info, property_name, NM_KEYFILE_WARN_SEVERITY_WARN,
					             _("ignoring invalid gateway '%s' for %s route"),
					             gateway_str, family == AF_INET ? "IPv4" : "IPv6");
				}
				return NULL;
			}
		}
	} else
		gateway_str = NULL;

	/* parse metric, default to -1 */
	if (metric_str) {
		if (!get_one_int (info, property_name, metric_str, G_MAXUINT32, &u32))
			return NULL;
		metric = u32;
	}

	route = nm_ip_route_new (family, dest_str, plen, gateway_str,
	                         metric,
	                         &error);
	if (!route) {
		handle_warn (info, property_name, NM_KEYFILE_WARN_SEVERITY_WARN,
		             _("ignoring invalid %s route: %s"),
		             family == AF_INET ? "IPv4" : "IPv6",
		             error->message);
		g_error_free (error);
	}

	return route;
}

/* On success, returns pointer to the zero-terminated field (original @current).
 * The @current * pointer target is set to point to the rest of the input
 * or %NULL if there is no more input. Sets error to %NULL for convenience.
 *
 * On failure, returns %NULL (unspecified). The @current pointer target is
 * resets to its original value to allow skipping fields. The @error target
 * is set to the character that breaks the parsing or %NULL if @current was %NULL.
 *
 * When @current target is %NULL, gracefully fail returning %NULL while
 * leaving the @current target %NULL end setting @error to %NULL;
 */
static const char *
read_field (char **current, const char **out_err_str, const char *characters, const char *delimiters)
{
	const char *start;

	nm_assert (current);
	nm_assert (out_err_str);
	nm_assert (characters);
	nm_assert (delimiters);

	*out_err_str = NULL;

	if (!*current) {
		/* graceful failure, leave '*current' NULL */
		return NULL;
	}

	/* fail on empty input */
	if (!**current)
		return NULL;

	/* remember beginning of input */
	start = *current;

	while (**current && strchr (characters, **current))
		(*current)++;
	if (**current)
		if (strchr (delimiters, **current)) {
			/* success, more data available */
			*(*current)++ = '\0';
			return start;
		} else {
			/* error, bad character */
			*out_err_str = *current;
			*current = (char *) start;
			return NULL;
		}
	else {
		/* success, end of input */
		*current = NULL;
		return start;
	}
}

#define IP_ADDRESS_CHARS "0123456789abcdefABCDEF:.%"
#define DIGITS "0123456789"
#define DELIMITERS "/;,"

/* The following IPv4 and IPv6 address formats are supported:
 *
 * address (DEPRECATED)
 * address/plen
 * address/gateway (DEPRECATED)
 * address/plen,gateway
 *
 * The following IPv4 and IPv6 route formats are supported:
 *
 * address/plen (NETWORK dev DEVICE)
 * address/plen,gateway (NETWORK via GATEWAY dev DEVICE)
 * address/plen,,metric (NETWORK dev DEVICE metric METRIC)
 * address/plen,gateway,metric (NETWORK via GATEWAY dev DEVICE metric METRIC)
 *
 * For backward, forward and sideward compatibility, slash (/),
 * semicolon (;) and comma (,) are interchangeable. The choice of
 * separator in the above examples is therefore not significant.
 *
 * Leaving out the prefix length is discouraged and DEPRECATED. The
 * default value of IPv6 prefix length was 64 and has not been
 * changed. The default for IPv4 is now 24, which is the closest
 * IPv4 equivalent. These defaults may just as well be changed to
 * match the iproute2 defaults (32 for IPv4 and 128 for IPv6).
 */
static gpointer
read_one_ip_address_or_route (KeyfileReaderInfo *info,
                              const char *property_name,
                              const char *setting_name,
                              const char *key_name,
                              gboolean ipv6,
                              gboolean route,
                              char **out_gateway,
                              NMSetting *setting)
{
	guint plen;
	gpointer result;
	const char *address_str;
	const char *plen_str;
	const char *gateway_str;
	const char *metric_str;
	const char *err_str = NULL;
	char *current;
	gs_free char *value = NULL;
	gs_free char *value_orig = NULL;

#define VALUE_ORIG()   (value_orig ?: (value_orig = nm_keyfile_plugin_kf_get_string (info->keyfile, setting_name, key_name, NULL)))

	value = nm_keyfile_plugin_kf_get_string (info->keyfile, setting_name, key_name, NULL);
	if (!value)
		return NULL;

	current = value;

	/* get address field */
	address_str = read_field (&current, &err_str, IP_ADDRESS_CHARS, DELIMITERS);
	if (err_str) {
		handle_warn (info, property_name, NM_KEYFILE_WARN_SEVERITY_WARN,
		             _("unexpected character '%c' for address %s: '%s' (position %td)"),
		             *err_str, key_name, VALUE_ORIG (), err_str - current);
		return NULL;
	}
	/* get prefix length field (skippable) */
	plen_str = read_field (&current, &err_str, DIGITS, DELIMITERS);
	/* get gateway field */
	gateway_str = read_field (&current, &err_str, IP_ADDRESS_CHARS, DELIMITERS);
	if (err_str) {
		handle_warn (info, property_name, NM_KEYFILE_WARN_SEVERITY_WARN,
		             _("unexpected character '%c' for %s: '%s' (position %td)"),
		             *err_str, key_name, VALUE_ORIG (), err_str - current);
		return NULL;
	}
	/* for routes, get metric */
	if (route) {
		metric_str = read_field (&current, &err_str, DIGITS, DELIMITERS);
		if (err_str) {
			handle_warn (info, property_name, NM_KEYFILE_WARN_SEVERITY_WARN,
			             _("unexpected character '%c' in prefix length for %s: '%s' (position %td)"),
			             *err_str, key_name, VALUE_ORIG (), err_str - current);
			return NULL;
		}
	} else
		metric_str = NULL;
	if (current) {
		/* there is still some data */
		if (*current) {
			/* another field follows */
			handle_warn (info, property_name, NM_KEYFILE_WARN_SEVERITY_WARN,
			             _("garbage at the end of value %s: '%s'"),
			             key_name, VALUE_ORIG ());
			return NULL;
		} else {
			/* semicolon at the end of input */
			if (!handle_warn (info, property_name, NM_KEYFILE_WARN_SEVERITY_INFO,
			                  _("deprecated semicolon at the end of value %s: '%s'"),
			                  key_name, VALUE_ORIG ()))
				return NULL;
		}
	}

#define DEFAULT_PREFIX(for_route, for_ipv6) ( (for_route) ? ( (for_ipv6) ? 128 : 24 ) : ( (for_ipv6) ? 64 : 24 ) )

	/* parse plen, fallback to defaults */
	if (plen_str) {
		if (   !get_one_int (info, property_name, plen_str, ipv6 ? 128 : 32, &plen)
		    || (route && plen == 0)) {
			plen = DEFAULT_PREFIX (route, ipv6);
			if (   info->error
			    || !handle_warn (info, property_name, NM_KEYFILE_WARN_SEVERITY_WARN,
			                     _("invalid prefix length for %s '%s', defaulting to %d"),
			                     key_name, VALUE_ORIG (), plen))
				return NULL;
		}
	} else {
		plen = DEFAULT_PREFIX (route, ipv6);
		if (!handle_warn (info, property_name, NM_KEYFILE_WARN_SEVERITY_WARN,
		                  _("missing prefix length for %s '%s', defaulting to %d"),
		                  key_name, VALUE_ORIG (), plen))
			return NULL;
	}

	/* build the appropriate data structure for NetworkManager settings */
	if (route) {
		result = build_route (info, property_name,
		                      ipv6 ? AF_INET6 : AF_INET,
		                      address_str, plen, gateway_str, metric_str);
	} else {
		result = build_address (info, ipv6 ? AF_INET6 : AF_INET,
		                        address_str, plen, property_name);
		if (!result)
			return NULL;
		if (gateway_str)
			NM_SET_OUT (out_gateway, g_strdup (gateway_str));
	}

#undef VALUE_ORIG

	return result;
}

static void
fill_route_attributes (GKeyFile *kf, NMIPRoute *route, const char *setting, const char *key, int family)
{
	gs_free char *value = NULL;
	gs_unref_hashtable GHashTable *hash = NULL;
	GHashTableIter iter;
	char *name;
	GVariant *variant;

	value = nm_keyfile_plugin_kf_get_string (kf, setting, key, NULL);
	if (!value || !value[0])
		return;

	hash = nm_utils_parse_variant_attributes (value, ',', '=', TRUE,
	                                          nm_ip_route_get_variant_attribute_spec (),
	                                          NULL);
	if (hash) {
		g_hash_table_iter_init (&iter, hash);
		while (g_hash_table_iter_next (&iter, (gpointer *) &name, (gpointer *) &variant)) {
			if (nm_ip_route_attribute_validate (name, variant, family, NULL, NULL))
				nm_ip_route_set_attribute (route, name, g_variant_ref (variant));
		}
	}
}

typedef struct {
	const char *s_key;
	gint32 key_idx;
	gint8 key_type;
} IPAddrRouteBuildListData;

static int
_ip_addrroute_build_lst_data_cmp (gconstpointer p_a, gconstpointer p_b, gpointer user_data)
{
	const IPAddrRouteBuildListData *a = p_a;
	const IPAddrRouteBuildListData *b = p_b;

	NM_CMP_FIELD (a, b, key_idx);
	NM_CMP_FIELD (a, b, key_type);
	NM_CMP_FIELD_STR (a, b, s_key);
	return 0;
}

static gboolean
ip_addrroute_match_key_w_name_ (const char *key,
                                const char *base_name,
                                gsize base_name_l,
                                gint32 *out_key_idx)
{
	gint64 v;

	/* some very strict parsing. */

	/* the key must start with base_name. */
	if (strncmp (key, base_name, base_name_l) != 0)
		return FALSE;

	key += base_name_l;
	if (key[0] == '\0') {
		/* if key is identical to base_name, that's good. */
		NM_SET_OUT (out_key_idx, -1);
		return TRUE;
	}

	/* if base_name is followed by a zero, then it must be
	 * only a zero, nothing else. */
	if (key[0] == '0') {
		if (key[1] != '\0')
			return FALSE;
		NM_SET_OUT (out_key_idx, 0);
		return TRUE;
	}

	/* otherwise, it can only be followed by a non-zero decimal. */
	if (!(key[0] >= '1' && key[0] <= '9'))
		return FALSE;
	/* and all remaining chars must be decimals too. */
	if (!NM_STRCHAR_ALL (&key[1], ch, g_ascii_isdigit (ch)))
		return FALSE;

	/* and it must be convertible to a (positive) int. */
	v = _nm_utils_ascii_str_to_int64 (key, 10, 0, G_MAXINT32, -1);
	if (v < 0)
		return FALSE;

	/* good */
	NM_SET_OUT (out_key_idx, v);
	return TRUE;
}

static gboolean
ip_addrroute_match_key (const char *key,
                        gboolean is_routes,
                        gint32 *out_key_idx,
                        gint8 *out_key_type)
{
#define ip_addrroute_match_key_w_name(key, base_name, out_key_idx) \
	ip_addrroute_match_key_w_name_ (key, base_name, NM_STRLEN (base_name), out_key_idx)

	if (is_routes) {
		if (ip_addrroute_match_key_w_name (key, "route", out_key_idx))
			NM_SET_OUT (out_key_type, 0);
		else if (ip_addrroute_match_key_w_name (key, "routes", out_key_idx))
			NM_SET_OUT (out_key_type, 1);
		else
			return FALSE;
	} else {
		if (ip_addrroute_match_key_w_name (key, "address", out_key_idx))
			NM_SET_OUT (out_key_type, 0);
		else if (ip_addrroute_match_key_w_name (key, "addresses", out_key_idx))
			NM_SET_OUT (out_key_type, 1);
		else
			return FALSE;
	}
	return TRUE;
}

static void
ip_address_or_route_parser (KeyfileReaderInfo *info, NMSetting *setting, const char *setting_key)
{
	const char *setting_name = nm_setting_get_name (setting);
	gboolean is_ipv6 = nm_streq (setting_name, "ipv6");
	gboolean is_routes = nm_streq (setting_key, "routes");
	gs_free char *gateway = NULL;
	gs_unref_ptrarray GPtrArray *list = NULL;
	gs_strfreev char **keys = NULL;
	gsize i_keys, n_keys;
	gs_free IPAddrRouteBuildListData *build_list = NULL;
	gsize i_build_list, build_list_len = 0;

	keys = nm_keyfile_plugin_kf_get_keys (info->keyfile, setting_name, &n_keys, NULL);
	if (n_keys == 0)
		return;

	/* first create a list of all relevant keys, and sort them. */
	for (i_keys = 0; i_keys < n_keys; i_keys++) {
		const char *s_key = keys[i_keys];
		gint32 key_idx;
		gint8 key_type;

		if (!ip_addrroute_match_key (s_key, is_routes, &key_idx, &key_type))
			continue;

		if (G_UNLIKELY (!build_list))
			build_list = g_new (IPAddrRouteBuildListData, n_keys - i_keys);

		build_list[build_list_len].s_key = s_key;
		build_list[build_list_len].key_idx = key_idx;
		build_list[build_list_len].key_type = key_type;
		build_list_len++;
	}

	if (build_list_len == 0)
		return;

	g_qsort_with_data (build_list,
	                   build_list_len,
	                   sizeof (IPAddrRouteBuildListData),
	                   _ip_addrroute_build_lst_data_cmp,
	                   NULL);

	list = g_ptr_array_new_with_free_func (is_routes
	                                       ? (GDestroyNotify) nm_ip_route_unref
	                                       : (GDestroyNotify) nm_ip_address_unref);

	for (i_build_list = 0; i_build_list < build_list_len; i_build_list++) {
		const IPAddrRouteBuildListData *build_data = &build_list[i_build_list];
		gpointer item;

		if (   i_build_list + 1 < build_list_len
		    && build_data->key_idx == build_data[1].key_idx
		    && build_data->key_type == build_data[1].key_type
		    && nm_streq (build_data->s_key, build_data[1].s_key)) {
			/* the keyfile contains duplicate keys, which are both returned
			 * by g_key_file_get_keys() (WHY??).
			 *
			 * Skip the earlier one. */
			continue;
		}

		item = read_one_ip_address_or_route (info,
		                                     setting_key,
		                                     setting_name,
		                                     build_data->s_key,
		                                     is_ipv6,
		                                     is_routes,
		                                     gateway ? NULL : &gateway,
		                                     setting);
		if (item && is_routes) {
			char options_key[128];

			nm_sprintf_buf (options_key, "%s_options", build_data->s_key);
			fill_route_attributes (info->keyfile,
			                       item,
			                       setting_name,
			                       options_key,
			                       is_ipv6 ? AF_INET6 : AF_INET);
		}

		if (info->error)
			return;

		if (item)
			g_ptr_array_add (list, item);
	}

	if (list->len >= 1)
		g_object_set (setting, setting_key, list, NULL);

	if (gateway)
		g_object_set (setting, "gateway", gateway, NULL);
}

static void
ip_dns_parser (KeyfileReaderInfo *info, NMSetting *setting, const char *key)
{
	int addr_family;
	gs_strfreev char **list = NULL;
	gsize i, n, length;

	nm_assert (NM_IS_SETTING_IP4_CONFIG (setting) || NM_IS_SETTING_IP6_CONFIG (setting));

	list = nm_keyfile_plugin_kf_get_string_list (info->keyfile,
	                                             nm_setting_get_name (setting),
	                                             key,
	                                             &length,
	                                             NULL);
	nm_assert (length == NM_PTRARRAY_LEN (list));
	if (length == 0)
		return;

	addr_family = NM_IS_SETTING_IP4_CONFIG (setting) ? AF_INET : AF_INET6;

	n = 0;
	for (i = 0; i < length; i++) {
		NMIPAddr addr;

		if (inet_pton (addr_family, list[i], &addr) <= 0) {
			if (!handle_warn (info, key, NM_KEYFILE_WARN_SEVERITY_WARN,
			                  _("ignoring invalid DNS server IPv%c address '%s'"),
			                  nm_utils_addr_family_to_char (addr_family),
			                  list[i])) {
				do {
					nm_clear_g_free (&list[i]);
				} while (++i < length);
				return;
			}
			nm_clear_g_free (&list[i]);
			continue;
		}

		if (n != i)
			list[n] = g_steal_pointer (&list[i]);
		n++;
	}

	g_object_set (setting, key, list, NULL);
}

static void
ip6_addr_gen_mode_parser (KeyfileReaderInfo *info, NMSetting *setting, const char *key)
{
	NMSettingIP6ConfigAddrGenMode addr_gen_mode;
	const char *setting_name = nm_setting_get_name (setting);
	gs_free char *s = NULL;

	s = nm_keyfile_plugin_kf_get_string (info->keyfile, setting_name, key, NULL);
	if (s) {
		if (!nm_utils_enum_from_str (nm_setting_ip6_config_addr_gen_mode_get_type (), s,
		                             (int *) &addr_gen_mode, NULL)) {
			handle_warn (info, key, NM_KEYFILE_WARN_SEVERITY_WARN,
			             _("invalid option '%s', use one of [%s]"),
			             s, "eui64,stable-privacy");
			return;
		}
	} else
		addr_gen_mode = NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_EUI64;

	g_object_set (G_OBJECT (setting), key, (int) addr_gen_mode, NULL);
}

static void
mac_address_parser (KeyfileReaderInfo *info, NMSetting *setting, const char *key, gsize enforce_length, gboolean cloned_mac_addr)
{
	const char *setting_name = nm_setting_get_name (setting);
	gs_free char *tmp_string = NULL;
	const char *p, *mac_str;
	gs_free guint8 *buf_arr = NULL;
	guint buf_len = 0;

	tmp_string = nm_keyfile_plugin_kf_get_string (info->keyfile, setting_name, key, NULL);

	if (   cloned_mac_addr
	    && NM_CLONED_MAC_IS_SPECIAL (tmp_string)) {
		mac_str = tmp_string;
		goto out;
	}

	if (tmp_string && tmp_string[0]) {
		/* Look for enough ':' characters to signify a MAC address */
		guint i = 0;

		p = tmp_string;
		while (*p) {
			if (*p == ':')
				i++;
			p++;
		}

		if (enforce_length == 0 || enforce_length == i+1) {
			/* If we found enough it's probably a string-format MAC address */
			buf_len = i + 1;
			buf_arr = g_new (guint8, buf_len);
			if (!nm_utils_hwaddr_aton (tmp_string, buf_arr, buf_len))
				g_clear_pointer (&buf_arr, g_free);
		}
	}
	g_clear_pointer (&tmp_string, g_free);

	if (!buf_arr) {
		gs_free int *tmp_list = NULL;
		gsize length;

		/* Old format; list of ints */
		tmp_list = nm_keyfile_plugin_kf_get_integer_list (info->keyfile, setting_name, key, &length, NULL);
		if (length > 0 && (enforce_length == 0 || enforce_length == length)) {
			gsize i;

			buf_len = length;
			buf_arr = g_new (guint8, buf_len);
			for (i = 0; i < length; i++) {
				int val = tmp_list[i];

				if (val < 0 || val > 255) {
					handle_warn (info, key, NM_KEYFILE_WARN_SEVERITY_WARN,
					             _("ignoring invalid byte element '%d' (not between 0 and 255 inclusive)"),
					             val);
					return;
				}
				buf_arr[i] = (guint8) val;
			}
		}
	}

	if (!buf_arr) {
		handle_warn (info, key, NM_KEYFILE_WARN_SEVERITY_WARN,
		             _("ignoring invalid MAC address"));
		return;
	}

	tmp_string = nm_utils_hwaddr_ntoa (buf_arr, buf_len);
	mac_str = tmp_string;

out:
	g_object_set (setting, key, mac_str, NULL);
}

static void
mac_address_parser_ETHER (KeyfileReaderInfo *info, NMSetting *setting, const char *key)
{
	mac_address_parser (info, setting, key, ETH_ALEN, FALSE);
}

static void
mac_address_parser_ETHER_cloned (KeyfileReaderInfo *info, NMSetting *setting, const char *key)
{
	mac_address_parser (info, setting, key, ETH_ALEN, TRUE);
}

static void
mac_address_parser_INFINIBAND (KeyfileReaderInfo *info, NMSetting *setting, const char *key)
{
	mac_address_parser (info, setting, key, INFINIBAND_ALEN, FALSE);
}

static void
read_hash_of_string (GKeyFile *file, NMSetting *setting, const char *key)
{
	gs_strfreev char **keys = NULL;
	const char *const*iter;
	const char *setting_name = nm_setting_get_name (setting);
	gboolean is_vpn;
	gsize n_keys;

	keys = nm_keyfile_plugin_kf_get_keys (file, setting_name, &n_keys, NULL);
	if (n_keys == 0)
		return;

	if (   (is_vpn = NM_IS_SETTING_VPN (setting))
	    || NM_IS_SETTING_BOND (setting)) {
		for (iter = (const char *const*) keys; *iter; iter++) {
			gs_free char *to_free = NULL;
			gs_free char *value = NULL;
			const char *name;

			value = nm_keyfile_plugin_kf_get_string (file, setting_name, *iter, NULL);
			if (!value)
				continue;

			name = nm_keyfile_key_decode (*iter, &to_free);

			if (is_vpn) {
				/* Add any item that's not a class property to the data hash */
				if (!g_object_class_find_property (G_OBJECT_GET_CLASS (setting), name))
					nm_setting_vpn_add_data_item (NM_SETTING_VPN (setting), name, value);
			} else {
				if (!nm_streq (name, "interface-name"))
					nm_setting_bond_add_option (NM_SETTING_BOND (setting), name, value);
			}
		}
		return;
	}

	if (NM_IS_SETTING_USER (setting)) {
		gs_unref_hashtable GHashTable *data = NULL;

		data = g_hash_table_new_full (nm_str_hash, g_str_equal, g_free, g_free);
		for (iter = (const char *const*) keys; *iter; iter++) {
			gs_free char *to_free = NULL;
			char *value = NULL;
			const char *name;

			value = nm_keyfile_plugin_kf_get_string (file, setting_name, *iter, NULL);
			if (!value)
				continue;
			name = nm_keyfile_key_decode (*iter, &to_free);
			g_hash_table_insert (data,
			                     g_steal_pointer (&to_free) ?: g_strdup (name),
			                     value);
		}
		g_object_set (setting, NM_SETTING_USER_DATA, data, NULL);
	}
}

static gsize
unescape_semicolons (char *str)
{
	gsize i, j;

	for (i = 0, j = 0; str[i]; ) {
		if (str[i] == '\\' && str[i+1] == ';')
			i++;
		str[j++] = str[i++];;
	}
	nm_explicit_bzero (&str[j], i - j);
	return j;
}

static GBytes *
get_bytes (KeyfileReaderInfo *info,
           const char *setting_name,
           const char *key,
           gboolean zero_terminate,
           gboolean unescape_semicolon)
{
	nm_auto_free_secret char *tmp_string = NULL;
	gboolean may_be_int_list = TRUE;
	gsize length;
	GBytes *result;

	/* New format: just a string
	 * Old format: integer list; e.g. 11;25;38;
	 */
	tmp_string = nm_keyfile_plugin_kf_get_string (info->keyfile, setting_name, key, NULL);
	if (!tmp_string)
		return NULL;

	/* if the string is empty, we return an empty GBytes array.
	 * Note that for NM_SETTING_802_1X_PASSWORD_RAW both %NULL and
	 * an empty GBytes are valid, and shall be destinguished. */
	if (!tmp_string[0]) {
		/* note that even if @zero_terminate is TRUE, we return an empty
		 * byte-array. The reason is that zero_terminate is there to terminate
		 * *valid* strings. It's not there to terminated invalid (empty) strings.
		 */
		return g_bytes_new_static ("", 0);
	}

	for (length = 0; tmp_string[length]; length++) {
		const char ch = tmp_string[length];

		if (   !g_ascii_isspace (ch)
		    && !g_ascii_isdigit (ch)
		    && ch != ';') {
			may_be_int_list = FALSE;
			length += strlen (&tmp_string[length]);
			break;
		}
	}

	/* Try to parse the string as a integer list. */
	if (may_be_int_list && length > 0) {
		nm_auto_free_secret_buf NMSecretBuf *bin = NULL;
		const char *const s = tmp_string;
		gsize i, d;

		bin = nm_secret_buf_new (length / 2 + 3);

#define DIGIT(c) ((c) - '0')
		i = 0;
		d = 0;
		while (TRUE) {
			int n;

			/* leading whitespace */
			while (g_ascii_isspace (s[i]))
				i++;
			if (s[i] == '\0')
				break;
			/* then expect 1 to 3 digits */
			if (!g_ascii_isdigit (s[i])) {
				d = 0;
				break;
			}
			n = DIGIT (s[i]);
			i++;
			if (g_ascii_isdigit (s[i])) {
				n = 10 * n + DIGIT (s[i]);
				i++;
				if (g_ascii_isdigit (s[i])) {
					n = 10 * n + DIGIT (s[i]);
					i++;
				}
			}
			if (n > 255) {
				d = 0;
				break;
			}

			nm_assert (d < bin->len);
			bin->bin[d++] = n;

			/* allow whitespace after the digit. */
			while (g_ascii_isspace (s[i]))
				i++;
			/* need a semicolon as separator. */
			if (s[i] != ';') {
				d = 0;
				break;
			}
			i++;
		}
#undef DIGIT

		/* Old format; list of ints. We already did a strict validation of the
		 * string format before. We expect that this conversion cannot fail. */
		if (d > 0) {
			/* note that @zero_terminate does not add a terminating '\0' to
			 * binary data as an integer list. If the bytes are expressed as
			 * an integer list, all potential NUL characters are supposed to
			 * be included there explicitly.
			 *
			 * However, in the spirit of defensive programming, we do append a
			 * NUL character to the buffer, although this character is hidden
			 * and only a mitigation for bugs. */

			if (d + 10 < bin->len) {
				/* hm, too much unused memory. Copy the memory to a suitable
				 * sized buffer. */
				return nm_secret_copy_to_gbytes (bin->bin, d);
			}

			nm_assert (d < bin->len);
			bin->bin[d] = '\0';
			return nm_secret_buf_to_gbytes_take (g_steal_pointer (&bin), d);
		}
	}

	/* Handle as a simple string (ie, new format) */
	if (unescape_semicolon)
		length = unescape_semicolons (tmp_string);
	if (zero_terminate)
		length++;
	if (length == 0)
		return NULL;

	result = g_bytes_new_with_free_func (tmp_string,
	                                     length,
	                                     (GDestroyNotify) nm_free_secret,
	                                     tmp_string);
	tmp_string = NULL;
	return result;
}

static void
ssid_parser (KeyfileReaderInfo *info, NMSetting *setting, const char *key)
{
	const char *setting_name = nm_setting_get_name (setting);
	GBytes *bytes;

	bytes = get_bytes (info, setting_name, key, FALSE, TRUE);
	if (bytes) {
		g_object_set (setting, key, bytes, NULL);
		g_bytes_unref (bytes);
	} else if (!info->error) {
		handle_warn (info, key, NM_KEYFILE_WARN_SEVERITY_WARN,
		             _("ignoring invalid SSID"));
	}
}

static void
password_raw_parser (KeyfileReaderInfo *info, NMSetting *setting, const char *key)
{
	const char *setting_name = nm_setting_get_name (setting);
	GBytes *bytes;

	bytes = get_bytes (info, setting_name, key, FALSE, TRUE);
	if (bytes) {
		g_object_set (setting, key, bytes, NULL);
		g_bytes_unref (bytes);
	} else if (!info->error) {
		handle_warn (info, key, NM_KEYFILE_WARN_SEVERITY_WARN,
		             _("ignoring invalid raw password"));
	}
}

static char *
get_cert_path (const char *base_dir, const guint8 *cert_path, gsize cert_path_len)
{
	const char *base;
	char *p = NULL, *path, *tmp;

	g_return_val_if_fail (base_dir != NULL, NULL);
	g_return_val_if_fail (cert_path != NULL, NULL);

	path = g_strndup ((char *) cert_path, cert_path_len);

	if (path[0] == '/')
		return path;

	base = path;
	p = strrchr (path, '/');
	if (p)
		base = p + 1;

	tmp = g_build_path ("/", base_dir, base, NULL);
	g_free (path);
	return tmp;
}

static const char *certext[] = { ".pem", ".cert", ".crt", ".cer", ".p12", ".der", ".key" };

static gboolean
has_cert_ext (const char *path)
{
	int i;

	for (i = 0; i < G_N_ELEMENTS (certext); i++) {
		if (g_str_has_suffix (path, certext[i]))
			return TRUE;
	}
	return FALSE;
}

char *
nm_keyfile_detect_unqualified_path_scheme (const char *base_dir,
                                           gconstpointer pdata,
                                           gsize data_len,
                                           gboolean consider_exists,
                                           gboolean *out_exists)
{
	const char *data = pdata;
	gboolean exists = FALSE;
	gsize validate_len;
	gsize path_len, pathuri_len;
	gs_free char *path = NULL;
	gs_free char *pathuri = NULL;

	g_return_val_if_fail (base_dir && base_dir[0] == '/', NULL);

	if (!pdata)
		return NULL;
	if (data_len == -1)
		data_len = strlen (data);
	if (data_len > 500 || data_len < 1)
		return NULL;

	/* If there's a trailing zero tell g_utf8_validate() to validate until the zero */
	if (data[data_len - 1] == '\0') {
		/* setting it to -1, would mean we accept data to contain NUL characters before the
		 * end. Don't accept any NUL in [0 .. data_len-1[ . */
		validate_len = data_len - 1;
	} else
		validate_len = data_len;
	if (   validate_len == 0
	    || g_utf8_validate ((const char *) data, validate_len, NULL) == FALSE)
		 return NULL;

	/* Might be a bare path without the file:// prefix; in that case
	 * if it's an absolute path, use that, otherwise treat it as a
	 * relative path to the current directory.
	 */

	path = get_cert_path (base_dir, (const guint8 *) data, data_len);
	if (   !memchr (data, '/', data_len)
	    && !has_cert_ext (path)) {
		if (!consider_exists)
			return NULL;
		exists = g_file_test (path, G_FILE_TEST_EXISTS);
		if (!exists)
			return NULL;
	} else if (out_exists)
		exists = g_file_test (path, G_FILE_TEST_EXISTS);

	/* Construct the proper value as required for the PATH scheme.
	 *
	 * When returning TRUE, we must also be sure that @data_len does not look like
	 * the deprecated format of list of integers. With this implementation that is the
	 * case, as long as @consider_exists is FALSE. */
	path_len = strlen (path);
	pathuri_len = (NM_STRLEN (NM_KEYFILE_CERT_SCHEME_PREFIX_PATH) + 1) + path_len;
	pathuri = g_new (char, pathuri_len);
	memcpy (pathuri, NM_KEYFILE_CERT_SCHEME_PREFIX_PATH, NM_STRLEN (NM_KEYFILE_CERT_SCHEME_PREFIX_PATH));
	memcpy (&pathuri[NM_STRLEN (NM_KEYFILE_CERT_SCHEME_PREFIX_PATH)], path, path_len + 1);
	if (nm_setting_802_1x_check_cert_scheme (pathuri, pathuri_len, NULL) != NM_SETTING_802_1X_CK_SCHEME_PATH)
		return NULL;

	NM_SET_OUT (out_exists, exists);
	return g_steal_pointer (&pathuri);
}

#define HAS_SCHEME_PREFIX(bin, bin_len, scheme) \
	({ \
		const char *const _bin = (bin); \
		const gsize _bin_len = (bin_len); \
		\
		nm_assert (_bin && _bin_len > 0); \
		\
		(   _bin_len > NM_STRLEN (scheme) + 1 \
		 && _bin[_bin_len - 1] == '\0' \
		 && memcmp (_bin, scheme, NM_STRLEN (scheme)) == 0); \
	})

static void
cert_parser (KeyfileReaderInfo *info, NMSetting *setting, const char *key)
{
	const char *setting_name = nm_setting_get_name (setting);
	gs_unref_bytes GBytes *bytes = NULL;
	const char *bin = NULL;
	gsize bin_len = 0;
	char *path;
	gboolean path_exists;

	bytes = get_bytes (info, setting_name, key, TRUE, FALSE);
	if (bytes)
		bin = g_bytes_get_data (bytes, &bin_len);
	if (bin_len == 0) {
		if (!info->error) {
			handle_warn (info, key, NM_KEYFILE_WARN_SEVERITY_WARN,
			             _("invalid key/cert value"));
		}
		return;
	}

	if (HAS_SCHEME_PREFIX (bin, bin_len, NM_KEYFILE_CERT_SCHEME_PREFIX_PATH)) {
		const char *path2 = &bin[NM_STRLEN (NM_KEYFILE_CERT_SCHEME_PREFIX_PATH)];
		gs_free char *path2_free = NULL;

		if (nm_setting_802_1x_check_cert_scheme (bin, bin_len, NULL) != NM_SETTING_802_1X_CK_SCHEME_PATH) {
			handle_warn (info, key, NM_KEYFILE_WARN_SEVERITY_WARN,
			             _("invalid key/cert value path \"%s\""), bin);
			return;
		}

		g_object_set (setting, key, bytes, NULL);

		if (path2[0] != '/') {
			/* we want to read absolute paths because we use keyfile as exchange
			 * between different processes which might not have the same cwd. */
			path2_free = get_cert_path (info->base_dir, (const guint8 *) path2,
			                            bin_len - NM_STRLEN (NM_KEYFILE_CERT_SCHEME_PREFIX_PATH) - 1);
			path2 = path2_free;
		}

		if (!g_file_test (path2, G_FILE_TEST_EXISTS)) {
			handle_warn (info, key, NM_KEYFILE_WARN_SEVERITY_INFO_MISSING_FILE,
			             _("certificate or key file '%s' does not exist"),
			             path2);
		}
		return;
	}

	if (HAS_SCHEME_PREFIX (bin, bin_len, NM_KEYFILE_CERT_SCHEME_PREFIX_PKCS11)) {
		if (nm_setting_802_1x_check_cert_scheme (bin, bin_len, NULL) != NM_SETTING_802_1X_CK_SCHEME_PKCS11) {
			handle_warn (info, key, NM_KEYFILE_WARN_SEVERITY_WARN,
			             _("invalid PKCS#11 URI \"%s\""), bin);
			return;
		}

		g_object_set (setting, key, bytes, NULL);
		return;
	}

	if (HAS_SCHEME_PREFIX (bin, bin_len, NM_KEYFILE_CERT_SCHEME_PREFIX_BLOB)) {
		const char *cdata = bin + NM_STRLEN (NM_KEYFILE_CERT_SCHEME_PREFIX_BLOB);
		gsize cdata_len = bin_len - NM_STRLEN (NM_KEYFILE_CERT_SCHEME_PREFIX_BLOB) - 1;
		gs_free guchar *bin_decoded = NULL;
		gsize bin_decoded_len = 0;
		gsize i;
		gboolean valid_base64;
		gs_unref_bytes GBytes *val = NULL;

		/* Let's be strict here. We expect valid base64, no funny stuff!!
		 * We didn't write such invalid data ourselfes and refuse to read it as blob. */
		if ((valid_base64 = (cdata_len % 4 == 0))) {
			for (i = 0; i < cdata_len; i++) {
				char c = cdata[i];

				if (!(   (c >= 'a' && c <= 'z')
				      || (c >= 'A' && c <= 'Z')
				      || (c >= '0' && c <= '9')
				      || (c == '+' || c == '/'))) {
					if (c != '=' || i < cdata_len - 2)
						valid_base64 = FALSE;
					else {
						for (; i < cdata_len; i++) {
							if (cdata[i] != '=')
								valid_base64 = FALSE;
						}
					}
					break;
				}
			}
		}
		if (valid_base64)
			bin_decoded = g_base64_decode (cdata, &bin_decoded_len);

		if (bin_decoded_len == 0) {
			handle_warn (info, key, NM_KEYFILE_WARN_SEVERITY_WARN,
			             _("invalid key/cert value data:;base64, is not base64"));
			return;
		}

		if (nm_setting_802_1x_check_cert_scheme (bin_decoded, bin_decoded_len, NULL) != NM_SETTING_802_1X_CK_SCHEME_BLOB) {
			/* The blob probably starts with "file://". Setting the cert data will confuse NMSetting8021x.
			 * In fact this is a limitation of NMSetting8021x which does not support setting blobs that start
			 * with file://. Just warn and return TRUE to signal that we ~handled~ the setting. */
			handle_warn (info, key, NM_KEYFILE_WARN_SEVERITY_WARN,
			             _("invalid key/cert value data:;base64,file://"));
			return;
		}

		val = g_bytes_new_take (g_steal_pointer (&bin_decoded), bin_decoded_len);
		g_object_set (setting, key, val, NULL);
		return;
	}

	/* If not, it might be a plain path */
	path = nm_keyfile_detect_unqualified_path_scheme (info->base_dir, bin, bin_len, TRUE, &path_exists);
	if (path) {
		gs_unref_bytes GBytes *val = NULL;

		/* Construct the proper value as required for the PATH scheme */
		val = g_bytes_new_take (path, strlen (path) + 1);
		g_object_set (setting, key, val, NULL);

		/* Warn if the certificate didn't exist */
		if (!path_exists) {
			handle_warn (info, key, NM_KEYFILE_WARN_SEVERITY_INFO_MISSING_FILE,
			             _("certificate or key file '%s' does not exist"),
			             path);
		}
		return;
	}

	if (nm_setting_802_1x_check_cert_scheme (bin, bin_len, NULL) != NM_SETTING_802_1X_CK_SCHEME_BLOB) {
		/* The blob probably starts with "file://" but contains invalid characters for a path.
		 * Setting the cert data will confuse NMSetting8021x.
		 * In fact, NMSetting8021x does not support setting such binary data, so just warn and
		 * continue. */
		handle_warn (info, key, NM_KEYFILE_WARN_SEVERITY_WARN,
		             _("invalid key/cert value is not a valid blob"));
		return;
	}

	g_object_set (setting, key, bytes, NULL);
}

static int
_parity_from_char (int ch)
{
#if NM_MORE_ASSERTS > 5
	{
		static char check = 0;

		if (check == 0) {
			nm_auto_unref_gtypeclass GEnumClass *klass = g_type_class_ref (NM_TYPE_SETTING_SERIAL_PARITY);
			guint i;

			check = 1;

			/* In older versions, parity was G_TYPE_CHAR/gint8, and the character
			 * value was stored as integer.
			 * For example parity=69 equals parity=E, meaning NM_SETTING_SERIAL_PARITY_EVEN.
			 *
			 * That means, certain values are reserved. Assert that these numbers
			 * are not reused when we extend NMSettingSerialParity enum.
			 * Actually, since NM_SETTING_SERIAL_PARITY is g_param_spec_enum(),
			 * we anyway cannot extend the enum without breaking API...
			 *
			 * [1] commit "a91e60902e libnm-core: make NMSettingSerial:parity an enum"
			 * [2] https://cgit.freedesktop.org/NetworkManager/NetworkManager/commit/?id=a91e60902eabae1de93d61323dae6ac894b5d40f
			 */
			g_assert (G_IS_ENUM_CLASS (klass));
			for (i = 0; i < klass->n_values; i++) {
				const GEnumValue *v = &klass->values[i];
				int num = v->value;

				g_assert (_parity_from_char (num) == -1);
				g_assert (!NM_IN_SET (num, 'e', 'E', 'o', 'O', 'n', 'N'));
			}
		}
	}
#endif

	switch (ch) {
	case 'E':
	case 'e':
		return NM_SETTING_SERIAL_PARITY_EVEN;
	case 'O':
	case 'o':
		return NM_SETTING_SERIAL_PARITY_ODD;
	case 'N':
	case 'n':
		return NM_SETTING_SERIAL_PARITY_NONE;
	}

	return -1;
}

static void
parity_parser (KeyfileReaderInfo *info, NMSetting *setting, const char *key)
{
	const char *setting_name = nm_setting_get_name (setting);
	gs_free_error GError *err = NULL;
	int parity;
	gs_free char *tmp_str = NULL;
	gint64 i64;

	/* Keyfile traditionally stored this as the ASCII value for 'E', 'o', or 'n'.
	 * We now accept either that or the (case-insensitive) character itself (but
	 * still always write it the old way, for backward compatibility).
	 */
	tmp_str = nm_keyfile_plugin_kf_get_value (info->keyfile, setting_name, key, &err);
	if (err)
		goto out_err;

	if (   tmp_str
	    && tmp_str[0] != '\0'
	    && tmp_str[1] == '\0') {
		/* the ASCII characters like 'E' are taken directly... */
		parity = _parity_from_char (tmp_str[0]);
		if (parity >= 0)
			goto parity_good;
	}

	i64 = _nm_utils_ascii_str_to_int64 (tmp_str, 0, G_MININT, G_MAXINT, G_MININT64);
	if (   i64 != G_MININT64
	    && errno == 0) {

		if ((parity = _parity_from_char (i64)) >= 0) {
			/* another oddity: the string is a valid number. However, if the numeric values
			 * is one of the supported ASCII codes, accept it (like 69 for 'E').
			 */
			goto parity_good;
		}

		/* Finally, take the numeric value as is. */
		parity = i64;
		goto parity_good;
	}

	handle_warn (info, key, NM_KEYFILE_WARN_SEVERITY_WARN,
	             _("invalid parity value '%s'"),
	             tmp_str ?: "");
	return;

parity_good:
	nm_g_object_set_property_enum (G_OBJECT (setting), key, NM_TYPE_SETTING_SERIAL_PARITY, parity, &err);

out_err:
	if (!err)
		return;
	if (   err->domain == G_KEY_FILE_ERROR
	    && NM_IN_SET (err->code, G_KEY_FILE_ERROR_GROUP_NOT_FOUND,
	                             G_KEY_FILE_ERROR_KEY_NOT_FOUND)) {
		/* ignore such errors. The key is not present. */
		return;
	}
	handle_warn (info, key, NM_KEYFILE_WARN_SEVERITY_WARN,
	             _("invalid setting: %s"), err->message);
}

static void
team_config_parser (KeyfileReaderInfo *info, NMSetting *setting, const char *key)
{
	const char *setting_name = nm_setting_get_name (setting);
	gs_free char *conf = NULL;
	gs_free_error GError *error = NULL;

	conf = nm_keyfile_plugin_kf_get_string (info->keyfile, setting_name, key, NULL);
	if (   conf
	    && conf[0]
	    && !nm_utils_is_json_object (conf, &error)) {
		handle_warn (info, key, NM_KEYFILE_WARN_SEVERITY_WARN,
		             _("ignoring invalid team configuration: %s"),
		             error->message);
		g_clear_pointer (&conf, g_free);
	}

	g_object_set (G_OBJECT (setting), key, conf, NULL);
}

static void
qdisc_parser (KeyfileReaderInfo *info, NMSetting *setting, const char *key)
{
	const char *setting_name = nm_setting_get_name (setting);
	GPtrArray *qdiscs;
	gs_strfreev char **keys = NULL;
	gsize n_keys = 0;
	int i;

	qdiscs = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_tc_qdisc_unref);

	keys = nm_keyfile_plugin_kf_get_keys (info->keyfile, setting_name, &n_keys, NULL);
	if (n_keys == 0)
		return;

	for (i = 0; i < n_keys; i++) {
		NMTCQdisc *qdisc;
		const char *qdisc_parent;
		gs_free char *qdisc_rest = NULL;
		gs_free char *qdisc_str = NULL;
		gs_free_error GError *err = NULL;

		if (!g_str_has_prefix (keys[i], "qdisc."))
			continue;

		qdisc_parent = keys[i] + sizeof ("qdisc.") - 1;
		qdisc_rest = nm_keyfile_plugin_kf_get_string (info->keyfile, setting_name, keys[i], NULL);
		qdisc_str = g_strdup_printf ("%s%s %s",
		                             _nm_utils_parse_tc_handle (qdisc_parent, NULL) != TC_H_UNSPEC ? "parent " : "",
		                             qdisc_parent,
		                             qdisc_rest);

		qdisc = nm_utils_tc_qdisc_from_str (qdisc_str, &err);
		if (!qdisc) {
			handle_warn (info, keys[i], NM_KEYFILE_WARN_SEVERITY_WARN,
			             _("invalid qdisc: %s"),
			             err->message);
		} else {
			g_ptr_array_add (qdiscs, qdisc);
		}
	}

	if (qdiscs->len >= 1)
		g_object_set (setting, key, qdiscs, NULL);

	g_ptr_array_unref (qdiscs);
}

static void
tfilter_parser (KeyfileReaderInfo *info, NMSetting *setting, const char *key)
{
	const char *setting_name = nm_setting_get_name (setting);
	GPtrArray *tfilters;
	gs_strfreev char **keys = NULL;
	gsize n_keys = 0;
	int i;

	tfilters = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_tc_tfilter_unref);

	keys = nm_keyfile_plugin_kf_get_keys (info->keyfile, setting_name, &n_keys, NULL);
	if (n_keys == 0)
		return;

	for (i = 0; i < n_keys; i++) {
		NMTCTfilter *tfilter;
		const char *tfilter_parent;
		gs_free char *tfilter_rest = NULL;
		gs_free char *tfilter_str = NULL;
		gs_free_error GError *err = NULL;

		if (!g_str_has_prefix (keys[i], "tfilter."))
			continue;

		tfilter_parent = keys[i] + sizeof ("tfilter.") - 1;
		tfilter_rest = nm_keyfile_plugin_kf_get_string (info->keyfile, setting_name, keys[i], NULL);
		tfilter_str = g_strdup_printf ("%s%s %s",
		                             _nm_utils_parse_tc_handle (tfilter_parent, NULL) != TC_H_UNSPEC ? "parent " : "",
		                             tfilter_parent,
		                             tfilter_rest);

		tfilter = nm_utils_tc_tfilter_from_str (tfilter_str, &err);
		if (!tfilter) {
			handle_warn (info, keys[i], NM_KEYFILE_WARN_SEVERITY_WARN,
			             _("invalid tfilter: %s"),
			             err->message);
		} else {
			g_ptr_array_add (tfilters, tfilter);
		}
	}

	if (tfilters->len >= 1)
		g_object_set (setting, key, tfilters, NULL);

	g_ptr_array_unref (tfilters);
}

/*****************************************************************************/

/* Some setting properties also contain setting names, such as
 * NMSettingConnection's 'type' property (which specifies the base type of the
 * connection, eg ethernet or wifi) or the 802-11-wireless setting's
 * 'security' property which specifies whether or not the AP requires
 * encryption.  This function handles translating those properties' values
 * from the real setting name to the more-readable alias.
 */
static void
setting_alias_writer (KeyfileWriterInfo *info,
                      NMSetting *setting,
                      const char *key,
                      const GValue *value)
{
	const char *str, *alias;

	str = g_value_get_string (value);
	alias = nm_keyfile_plugin_get_alias_for_setting_name (str);
	nm_keyfile_plugin_kf_set_string (info->keyfile,
	                                 nm_setting_get_name (setting),
	                                 key,
	                                 alias ?: str);
}

static void
sriov_vfs_writer (KeyfileWriterInfo *info,
                  NMSetting *setting,
                  const char *key,
                  const GValue *value)
{
	GPtrArray *vfs;
	guint i;

	vfs = g_value_get_boxed (value);
	if (!vfs)
		return;

	for (i = 0; i < vfs->len; i++) {
		const NMSriovVF *vf = vfs->pdata[i];
		gs_free char *kf_value = NULL;
		char kf_key[32];

		kf_value = nm_utils_sriov_vf_to_str (vf, TRUE, NULL);
		if (!kf_value)
			continue;

		nm_sprintf_buf (kf_key, "vf.%u", nm_sriov_vf_get_index (vf));

		nm_keyfile_plugin_kf_set_string (info->keyfile,
		                                 nm_setting_get_name (setting),
		                                 kf_key,
		                                 kf_value);
	}
}

static void
write_array_of_uint (GKeyFile *file,
                     NMSetting *setting,
                     const char *key,
                     const GValue *value)
{
	GArray *array;
	guint i;
	gs_free int *tmp_array = NULL;

	array = (GArray *) g_value_get_boxed (value);
	if (!array || !array->len)
		return;

	g_return_if_fail (g_array_get_element_size (array) == sizeof (guint));

	tmp_array = g_new (int, array->len);
	for (i = 0; i < array->len; i++) {
		guint v = g_array_index (array, guint, i);

		if (v > G_MAXINT)
			g_return_if_reached ();
		tmp_array[i] = (int) v;
	}

	nm_keyfile_plugin_kf_set_integer_list (file, nm_setting_get_name (setting), key, tmp_array, array->len);
}

static void
dns_writer (KeyfileWriterInfo *info,
            NMSetting *setting,
            const char *key,
            const GValue *value)
{
	char **list;

	list = g_value_get_boxed (value);
	if (list && list[0]) {
		nm_keyfile_plugin_kf_set_string_list (info->keyfile, nm_setting_get_name (setting), key,
		                                      (const char **) list, g_strv_length (list));
	}
}

static void
ip6_addr_gen_mode_writer (KeyfileWriterInfo *info,
                          NMSetting *setting,
                          const char *key,
                          const GValue *value)
{
	NMSettingIP6ConfigAddrGenMode addr_gen_mode;
	gs_free char *str = NULL;

	addr_gen_mode = (NMSettingIP6ConfigAddrGenMode) g_value_get_int (value);
	str = nm_utils_enum_to_str (nm_setting_ip6_config_addr_gen_mode_get_type (),
	                            addr_gen_mode);
	nm_keyfile_plugin_kf_set_string (info->keyfile,
	                                 nm_setting_get_name (setting),
	                                 key,
	                                 str);
}

static void
write_ip_values (GKeyFile *file,
                 const char *setting_name,
                 GPtrArray *array,
                 const char *gateway,
                 gboolean is_route)
{
	nm_auto_free_gstring GString *output = NULL;
	int addr_family;
	guint i;
	const char *addr;
	const char *gw;
	guint32 plen;
	char key_name[64];
	char *key_name_idx;

	if (!array->len)
		return;

	addr_family =   nm_streq (setting_name, NM_SETTING_IP4_CONFIG_SETTING_NAME)
	              ? AF_INET
	              : AF_INET6;

	strcpy (key_name, is_route ? "route" : "address");
	key_name_idx = key_name + strlen (key_name);

	output = g_string_sized_new (2*INET_ADDRSTRLEN + 10);
	for (i = 0; i < array->len; i++) {
		gint64 metric = -1;

		if (is_route) {
			NMIPRoute *route = array->pdata[i];

			addr = nm_ip_route_get_dest (route);
			plen = nm_ip_route_get_prefix (route);
			gw = nm_ip_route_get_next_hop (route);
			metric = nm_ip_route_get_metric (route);
		} else {
			NMIPAddress *address = array->pdata[i];

			addr = nm_ip_address_get_address (address);
			plen = nm_ip_address_get_prefix (address);
			gw =   (i == 0)
			     ? gateway
			     : NULL;
		}

		g_string_set_size (output, 0);
		g_string_append_printf (output, "%s/%u", addr, plen);
		if (   metric != -1
		    || gw) {
			/* Older versions of the plugin do not support the form
			 * "a.b.c.d/plen,,metric", so, we always have to write the
			 * gateway, even if there isn't one.
			 * The current version supports reading of the above form.
			 */
			if (!gw) {
				if (addr_family == AF_INET)
					gw = "0.0.0.0";
				else
					gw = "::";
			}

			g_string_append_printf (output, ",%s", gw);
			if (   is_route
			    && metric != -1)
				g_string_append_printf (output, ",%lu", (unsigned long) metric);
		}

		sprintf (key_name_idx, "%u", i + 1);
		nm_keyfile_plugin_kf_set_string (file, setting_name, key_name, output->str);

		if (is_route) {
			gs_free char *attributes = NULL;
			GHashTable *hash;

			hash = _nm_ip_route_get_attributes_direct (array->pdata[i]);
			attributes = nm_utils_format_variant_attributes (hash, ',', '=');
			if (attributes) {
				g_strlcat (key_name, "_options", sizeof (key_name));
				nm_keyfile_plugin_kf_set_string (file, setting_name, key_name, attributes);
			}
		}
	}
}

static void
addr_writer (KeyfileWriterInfo *info,
             NMSetting *setting,
             const char *key,
             const GValue *value)
{
	GPtrArray *array;
	const char *setting_name = nm_setting_get_name (setting);
	const char *gateway = nm_setting_ip_config_get_gateway (NM_SETTING_IP_CONFIG (setting));

	array = (GPtrArray *) g_value_get_boxed (value);
	if (array && array->len)
		write_ip_values (info->keyfile, setting_name, array, gateway, FALSE);
}

static void
route_writer (KeyfileWriterInfo *info,
              NMSetting *setting,
              const char *key,
              const GValue *value)
{
	GPtrArray *array;
	const char *setting_name = nm_setting_get_name (setting);

	array = (GPtrArray *) g_value_get_boxed (value);
	if (array && array->len)
		write_ip_values (info->keyfile, setting_name, array, NULL, TRUE);
}

static void
qdisc_writer (KeyfileWriterInfo *info,
              NMSetting *setting,
              const char *key,
              const GValue *value)
{
	gsize i;
	GPtrArray *array;

	array = (GPtrArray *) g_value_get_boxed (value);
	if (!array || !array->len)
		return;

	for (i = 0; i < array->len; i++) {
		NMTCQdisc *qdisc = array->pdata[i];
		GString *key_name = g_string_sized_new (16);
		GString *value_str = g_string_sized_new (60);

		g_string_append (key_name, "qdisc.");
		_nm_utils_string_append_tc_parent (key_name, NULL,
		                                   nm_tc_qdisc_get_parent (qdisc));
		_nm_utils_string_append_tc_qdisc_rest (value_str, qdisc);

		nm_keyfile_plugin_kf_set_string (info->keyfile,
		                                 NM_SETTING_TC_CONFIG_SETTING_NAME,
		                                 key_name->str,
		                                 value_str->str);

		g_string_free (key_name, TRUE);
		g_string_free (value_str, TRUE);
	}
}

static void
tfilter_writer (KeyfileWriterInfo *info,
              NMSetting *setting,
              const char *key,
              const GValue *value)
{
	gsize i;
	GPtrArray *array;

	array = (GPtrArray *) g_value_get_boxed (value);
	if (!array || !array->len)
		return;

	for (i = 0; i < array->len; i++) {
		NMTCTfilter *tfilter = array->pdata[i];
		GString *key_name = g_string_sized_new (16);
		GString *value_str = g_string_sized_new (60);

		g_string_append (key_name, "tfilter.");
		_nm_utils_string_append_tc_parent (key_name, NULL,
		                                   nm_tc_tfilter_get_parent (tfilter));
		_nm_utils_string_append_tc_tfilter_rest (value_str, tfilter, NULL);

		nm_keyfile_plugin_kf_set_string (info->keyfile,
		                                 NM_SETTING_TC_CONFIG_SETTING_NAME,
		                                 key_name->str,
		                                 value_str->str);

		g_string_free (key_name, TRUE);
		g_string_free (value_str, TRUE);
	}
}

static void
write_hash_of_string (GKeyFile *file,
                      NMSetting *setting,
                      const char *key,
                      const GValue *value)
{
	GHashTable *hash;
	const char *group_name = nm_setting_get_name (setting);
	gboolean vpn_secrets = FALSE;
	gs_free const char **keys = NULL;
	guint i, l;

	/* Write VPN secrets out to a different group to keep them separate */
	if (   NM_IS_SETTING_VPN (setting)
	    && nm_streq (key, NM_SETTING_VPN_SECRETS)) {
		group_name = NM_KEYFILE_GROUP_VPN_SECRETS;
		vpn_secrets = TRUE;
	}

	hash = g_value_get_boxed (value);

	keys = nm_utils_strdict_get_keys (hash, TRUE, &l);
	for (i = 0; i < l; i++) {
		gs_free char *to_free = NULL;
		const char *property, *data;

		property = keys[i];

		/* Handle VPN secrets specially; they are nested in the property's hash;
		 * we don't want to write them if the secret is not saved, not required,
		 * or owned by a user's secret agent.
		 */
		if (vpn_secrets) {
			NMSettingSecretFlags secret_flags = NM_SETTING_SECRET_FLAG_NONE;

			if (!nm_setting_get_secret_flags (setting, property, &secret_flags, NULL))
				nm_assert_not_reached ();
			if (!_secret_flags_persist_secret (secret_flags))
				continue;
		}

		data = g_hash_table_lookup (hash, property);
		nm_keyfile_plugin_kf_set_string (file, group_name,
		                                 nm_keyfile_key_encode (property, &to_free),
		                                 data);
	}
}

static void
ssid_writer (KeyfileWriterInfo *info,
             NMSetting *setting,
             const char *key,
             const GValue *value)
{
	GBytes *bytes;
	const guint8 *ssid_data;
	gsize ssid_len;
	const char *setting_name = nm_setting_get_name (setting);
	gboolean new_format = TRUE;
	gsize semicolons = 0;
	gsize i;

	g_return_if_fail (G_VALUE_HOLDS (value, G_TYPE_BYTES));

	bytes = g_value_get_boxed (value);
	if (!bytes)
		return;
	ssid_data = g_bytes_get_data (bytes, &ssid_len);
	if (!ssid_data || !ssid_len) {
		nm_keyfile_plugin_kf_set_string (info->keyfile, setting_name, key, "");
		return;
	}

	/* Check whether each byte is printable.  If not, we have to use an
	 * integer list, otherwise we can just use a string.
	 */
	for (i = 0; i < ssid_len; i++) {
		const char c = ssid_data[i];

		if (!g_ascii_isprint (c)) {
			new_format = FALSE;
			break;
		}
		if (c == ';')
			semicolons++;
	}

	if (new_format) {
		gs_free char *ssid = NULL;

		if (semicolons == 0)
			ssid = g_strndup ((char *) ssid_data, ssid_len);
		else {
			/* Escape semicolons with backslashes to make strings
			 * containing ';', such as '16;17;' unambiguous */
			gsize j = 0;

			ssid = g_malloc (ssid_len + semicolons + 1);
			for (i = 0; i < ssid_len; i++) {
				if (ssid_data[i] == ';')
					ssid[j++] = '\\';
				ssid[j++] = ssid_data[i];
			}
			ssid[j] = '\0';
		}
		nm_keyfile_plugin_kf_set_string (info->keyfile, setting_name, key, ssid);
	} else
		nm_keyfile_plugin_kf_set_integer_list_uint8 (info->keyfile, setting_name, key, ssid_data, ssid_len);
}

static void
password_raw_writer (KeyfileWriterInfo *info,
                     NMSetting *setting,
                     const char *key,
                     const GValue *value)
{
	const char *setting_name = nm_setting_get_name (setting);
	GBytes *array;
	gsize len;
	const guint8 *data;

	g_return_if_fail (G_VALUE_HOLDS (value, G_TYPE_BYTES));

	array = (GBytes *) g_value_get_boxed (value);
	if (!array)
		return;
	data = g_bytes_get_data (array, &len);
	if (!data)
		len = 0;
	nm_keyfile_plugin_kf_set_integer_list_uint8 (info->keyfile, setting_name, key, data, len);
}

/*****************************************************************************/

static void
cert_writer_default (NMConnection *connection,
                     GKeyFile *file,
                     NMKeyfileWriteTypeDataCert *cert_data)
{
	const char *setting_name = nm_setting_get_name (NM_SETTING (cert_data->setting));
	NMSetting8021xCKScheme scheme;

	scheme = cert_data->vtable->scheme_func (cert_data->setting);
	if (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH) {
		gs_free char *path_free = NULL;
		gs_free char *base_dir = NULL;
		gs_free char *tmp = NULL;
		const char *path;

		path = cert_data->vtable->path_func (cert_data->setting);
		g_assert (path);

		/* If the path is relative, make it an absolute path.
		 * Relative paths make a keyfile not easily usable in another
		 * context. */
		if (path[0] && path[0] != '/') {
			base_dir = g_get_current_dir ();
			path_free = g_strconcat (base_dir, "/", path, NULL);
			path = path_free;
		} else
			base_dir = g_path_get_dirname (path);

		/* path cannot start with "file://" or "data:;base64,", because it is an absolute path.
		 * Still, make sure that a prefix-less path will be recognized. This can happen
		 * for example if the path is longer then 500 chars. */
		tmp = nm_keyfile_detect_unqualified_path_scheme (base_dir, path, -1, FALSE, NULL);
		if (tmp)
			g_clear_pointer (&tmp, g_free);
		else {
			tmp = g_strconcat (NM_KEYFILE_CERT_SCHEME_PREFIX_PATH, path, NULL);
			path = tmp;
		}

		/* Path contains at least a '/', hence it cannot be recognized as the old
		 * binary format consisting of a list of integers. */

		nm_keyfile_plugin_kf_set_string (file, setting_name, cert_data->vtable->setting_key, path);
	} else if (scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB) {
		GBytes *blob;
		const guint8 *blob_data;
		gsize blob_len;
		gs_free char *blob_base64 = NULL;
		gs_free char *val = NULL;

		blob = cert_data->vtable->blob_func (cert_data->setting);
		g_assert (blob);
		blob_data = g_bytes_get_data (blob, &blob_len);

		blob_base64 = g_base64_encode (blob_data, blob_len);
		val = g_strconcat (NM_KEYFILE_CERT_SCHEME_PREFIX_BLOB, blob_base64, NULL);

		nm_keyfile_plugin_kf_set_string (file, setting_name, cert_data->vtable->setting_key, val);
	} else if (scheme == NM_SETTING_802_1X_CK_SCHEME_PKCS11) {
		nm_keyfile_plugin_kf_set_string (file, setting_name, cert_data->vtable->setting_key,
		                                 cert_data->vtable->uri_func (cert_data->setting));
	} else {
		/* scheme_func() returns UNKNOWN in all other cases. The only valid case
		 * where a scheme is allowed to be UNKNOWN, is unsetting the value. In this
		 * case, we don't expect the writer to be called, because the default value
		 * will not be serialized.
		 * The only other reason for the scheme to be UNKNOWN is an invalid cert.
		 * But our connection verifies, so that cannot happen either. */
		g_return_if_reached ();
	}
}

static void
cert_writer (KeyfileWriterInfo *info,
             NMSetting *setting,
             const char *key,
             const GValue *value)
{
	const NMSetting8021xSchemeVtable *objtype = NULL;
	guint i;
	NMKeyfileWriteTypeDataCert type_data = { 0 };

	for (i = 0; nm_setting_8021x_scheme_vtable[i].setting_key; i++) {
		if (nm_streq0 (nm_setting_8021x_scheme_vtable[i].setting_key, key)) {
			objtype = &nm_setting_8021x_scheme_vtable[i];
			break;
		}
	}
	if (!objtype)
		g_return_if_reached ();

	type_data.setting = NM_SETTING_802_1X (setting);
	type_data.vtable = objtype;

	if (info->handler) {
		if (info->handler (info->connection,
		                   info->keyfile,
		                   NM_KEYFILE_WRITE_TYPE_CERT,
		                   &type_data,
		                   info->user_data,
		                   &info->error))
			return;
		if (info->error)
			return;
	}

	cert_writer_default (info->connection, info->keyfile, &type_data);
}

/*****************************************************************************/

typedef struct {
	const char *property_name;
	void (*parser) (KeyfileReaderInfo *info,
	                NMSetting *setting,
	                const char *key);
	void (*writer) (KeyfileWriterInfo *info,
	                NMSetting *setting,
	                const char *key,
	                const GValue *value);
	bool parser_skip;
	bool parser_no_check_key:1;
	bool writer_skip:1;

	/* usually, we skip to write values that have their
	 * default value. By setting this flag to TRUE, also
	 * default values are written. */
	bool writer_persist_default:1;
} ParseInfoProperty;

#define PARSE_INFO_PROPERTY(_property_name, ...) \
	(&((const ParseInfoProperty) { \
		.property_name = _property_name, \
		__VA_ARGS__ \
	}))

#define PARSE_INFO_PROPERTIES(...) \
	.properties = ((const ParseInfoProperty*const[]) { \
		__VA_ARGS__ \
		NULL, \
	})

typedef struct {
	const ParseInfoProperty*const*properties;
} ParseInfoSetting;

#define PARSE_INFO_SETTING(setting_type, ...) \
	[setting_type] = (&((const ParseInfoSetting) { \
		__VA_ARGS__ \
	}))

static const ParseInfoSetting *const parse_infos[_NM_META_SETTING_TYPE_NUM] = {
	PARSE_INFO_SETTING (NM_META_SETTING_TYPE_WIRELESS,
		PARSE_INFO_PROPERTIES (
			PARSE_INFO_PROPERTY (NM_SETTING_WIRELESS_BSSID,
				.parser        = mac_address_parser_ETHER,
			),
			PARSE_INFO_PROPERTY (NM_SETTING_WIRELESS_CLONED_MAC_ADDRESS,
				.parser        = mac_address_parser_ETHER_cloned,
			),
			PARSE_INFO_PROPERTY (NM_SETTING_WIRELESS_MAC_ADDRESS,
				.parser        = mac_address_parser_ETHER,
			),
			PARSE_INFO_PROPERTY (NM_SETTING_WIRELESS_SSID,
				.parser        = ssid_parser,
				.writer        = ssid_writer,
			),
		),
	),
	PARSE_INFO_SETTING (NM_META_SETTING_TYPE_802_1X,
		PARSE_INFO_PROPERTIES (
			PARSE_INFO_PROPERTY (NM_SETTING_802_1X_CA_CERT,
				.parser        = cert_parser,
				.writer        = cert_writer,
			),
			PARSE_INFO_PROPERTY (NM_SETTING_802_1X_CLIENT_CERT,
				.parser        = cert_parser,
				.writer        = cert_writer,
			),
			PARSE_INFO_PROPERTY (NM_SETTING_802_1X_PASSWORD_RAW,
				.parser        = password_raw_parser,
				.writer        = password_raw_writer,
			),
			PARSE_INFO_PROPERTY (NM_SETTING_802_1X_PHASE2_CA_CERT,
				.parser        = cert_parser,
				.writer        = cert_writer,
			),
			PARSE_INFO_PROPERTY (NM_SETTING_802_1X_PHASE2_CLIENT_CERT,
				.parser        = cert_parser,
				.writer        = cert_writer,
			),
			PARSE_INFO_PROPERTY (NM_SETTING_802_1X_PHASE2_PRIVATE_KEY,
				.parser        = cert_parser,
				.writer        = cert_writer,
			),
			PARSE_INFO_PROPERTY (NM_SETTING_802_1X_PRIVATE_KEY,
				.parser        = cert_parser,
				.writer        = cert_writer,
			),
		),
	),
	PARSE_INFO_SETTING (NM_META_SETTING_TYPE_WIRED,
		PARSE_INFO_PROPERTIES (
			PARSE_INFO_PROPERTY (NM_SETTING_WIRED_CLONED_MAC_ADDRESS,
				.parser        = mac_address_parser_ETHER_cloned,
			),
			PARSE_INFO_PROPERTY (NM_SETTING_WIRED_MAC_ADDRESS,
				.parser        = mac_address_parser_ETHER,
			),
		),
	),
	PARSE_INFO_SETTING (NM_META_SETTING_TYPE_BLUETOOTH,
		PARSE_INFO_PROPERTIES (
			PARSE_INFO_PROPERTY (NM_SETTING_BLUETOOTH_BDADDR,
				.parser        = mac_address_parser_ETHER,
			),
		),
	),
	PARSE_INFO_SETTING (NM_META_SETTING_TYPE_BOND,
		PARSE_INFO_PROPERTIES (
			PARSE_INFO_PROPERTY (NM_SETTING_BOND_OPTIONS,
				.parser_no_check_key = TRUE,
			),
		),
	),
	PARSE_INFO_SETTING (NM_META_SETTING_TYPE_BRIDGE,
		PARSE_INFO_PROPERTIES (
			PARSE_INFO_PROPERTY (NM_SETTING_BRIDGE_MAC_ADDRESS,
				.parser        = mac_address_parser_ETHER,
			),
		),
	),
	PARSE_INFO_SETTING (NM_META_SETTING_TYPE_CONNECTION,
		PARSE_INFO_PROPERTIES (
			PARSE_INFO_PROPERTY (NM_SETTING_CONNECTION_READ_ONLY,
				.parser_skip   = TRUE,
				.writer_skip   = TRUE,
			),
			PARSE_INFO_PROPERTY (NM_SETTING_CONNECTION_TYPE,
				.parser        = setting_alias_parser,
				.writer        = setting_alias_writer,
			),
		),
	),
	PARSE_INFO_SETTING (NM_META_SETTING_TYPE_INFINIBAND,
		PARSE_INFO_PROPERTIES (
			PARSE_INFO_PROPERTY (NM_SETTING_INFINIBAND_MAC_ADDRESS,
				.parser        = mac_address_parser_INFINIBAND,
			),
		),
	),
	PARSE_INFO_SETTING (NM_META_SETTING_TYPE_IP4_CONFIG,
		PARSE_INFO_PROPERTIES (
			PARSE_INFO_PROPERTY (NM_SETTING_IP_CONFIG_ADDRESSES,
				.parser_no_check_key = TRUE,
				.parser        = ip_address_or_route_parser,
				.writer        = addr_writer,
			),
			PARSE_INFO_PROPERTY (NM_SETTING_IP_CONFIG_DNS,
				.parser_no_check_key = TRUE,
				.parser        = ip_dns_parser,
				.writer        = dns_writer,
			),
			PARSE_INFO_PROPERTY (NM_SETTING_IP_CONFIG_GATEWAY,
				.writer_skip   = TRUE,
			),
			PARSE_INFO_PROPERTY (NM_SETTING_IP_CONFIG_ROUTES,
				.parser_no_check_key = TRUE,
				.parser        = ip_address_or_route_parser,
				.writer        = route_writer,
			),
		),
	),
	PARSE_INFO_SETTING (NM_META_SETTING_TYPE_IP6_CONFIG,
		PARSE_INFO_PROPERTIES (
			PARSE_INFO_PROPERTY (NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE,
				.parser_no_check_key = TRUE,
				.parser        = ip6_addr_gen_mode_parser,
				.writer        = ip6_addr_gen_mode_writer,
				.writer_persist_default = TRUE,
			),
			PARSE_INFO_PROPERTY (NM_SETTING_IP_CONFIG_ADDRESSES,
				.parser_no_check_key = TRUE,
				.parser        = ip_address_or_route_parser,
				.writer        = addr_writer,
			),
			PARSE_INFO_PROPERTY (NM_SETTING_IP_CONFIG_DNS,
				.parser_no_check_key = TRUE,
				.parser        = ip_dns_parser,
				.writer        = dns_writer,
			),
			PARSE_INFO_PROPERTY (NM_SETTING_IP_CONFIG_GATEWAY,
				.writer_skip   = TRUE,
			),
			PARSE_INFO_PROPERTY (NM_SETTING_IP_CONFIG_ROUTES,
				.parser_no_check_key = TRUE,
				.parser        = ip_address_or_route_parser,
				.writer        = route_writer,
			),
		),
	),
	PARSE_INFO_SETTING (NM_META_SETTING_TYPE_SERIAL,
		PARSE_INFO_PROPERTIES (
			PARSE_INFO_PROPERTY (NM_SETTING_SERIAL_PARITY,
				.parser        = parity_parser,
			),
		),
	),
	PARSE_INFO_SETTING (NM_META_SETTING_TYPE_SRIOV,
		PARSE_INFO_PROPERTIES (
			PARSE_INFO_PROPERTY (NM_SETTING_SRIOV_VFS,
				.parser_no_check_key = TRUE,
				.parser        = sriov_vfs_parser,
				.writer        = sriov_vfs_writer,
			),
		),
	),
	PARSE_INFO_SETTING (NM_META_SETTING_TYPE_TC_CONFIG,
		PARSE_INFO_PROPERTIES (
			PARSE_INFO_PROPERTY (NM_SETTING_TC_CONFIG_QDISCS,
				.parser_no_check_key = TRUE,
				.parser        = qdisc_parser,
				.writer        = qdisc_writer,
			),
			PARSE_INFO_PROPERTY (NM_SETTING_TC_CONFIG_TFILTERS,
				.parser_no_check_key = TRUE,
				.parser        = tfilter_parser,
				.writer        = tfilter_writer,
			),
		),
	),
	PARSE_INFO_SETTING (NM_META_SETTING_TYPE_TEAM,
		PARSE_INFO_PROPERTIES (
			PARSE_INFO_PROPERTY (NM_SETTING_TEAM_CONFIG,
				.parser        = team_config_parser,
			),
			PARSE_INFO_PROPERTY (NM_SETTING_TEAM_LINK_WATCHERS,
				.parser_skip   = TRUE,
				.writer_skip   = TRUE,
			),
			PARSE_INFO_PROPERTY (NM_SETTING_TEAM_MCAST_REJOIN_COUNT,
				.parser_skip   = TRUE,
				.writer_skip   = TRUE,
			),
			PARSE_INFO_PROPERTY (NM_SETTING_TEAM_MCAST_REJOIN_INTERVAL,
				.parser_skip   = TRUE,
				.writer_skip   = TRUE,
			),
			PARSE_INFO_PROPERTY (NM_SETTING_TEAM_NOTIFY_PEERS_COUNT,
				.parser_skip   = TRUE,
				.writer_skip   = TRUE,
			),
			PARSE_INFO_PROPERTY (NM_SETTING_TEAM_NOTIFY_PEERS_INTERVAL,
				.parser_skip   = TRUE,
				.writer_skip   = TRUE,
			),
			PARSE_INFO_PROPERTY (NM_SETTING_TEAM_RUNNER,
				.parser_skip   = TRUE,
				.writer_skip   = TRUE,
			),
			PARSE_INFO_PROPERTY (NM_SETTING_TEAM_RUNNER_ACTIVE,
				.parser_skip   = TRUE,
				.writer_skip   = TRUE,
			),
			PARSE_INFO_PROPERTY (NM_SETTING_TEAM_RUNNER_AGG_SELECT_POLICY,
				.parser_skip   = TRUE,
				.writer_skip   = TRUE,
			),
			PARSE_INFO_PROPERTY (NM_SETTING_TEAM_RUNNER_FAST_RATE,
				.parser_skip   = TRUE,
				.writer_skip   = TRUE,
			),
			PARSE_INFO_PROPERTY (NM_SETTING_TEAM_RUNNER_HWADDR_POLICY,
				.parser_skip   = TRUE,
				.writer_skip   = TRUE,
			),
			PARSE_INFO_PROPERTY (NM_SETTING_TEAM_RUNNER_MIN_PORTS,
				.parser_skip   = TRUE,
				.writer_skip   = TRUE,
			),
			PARSE_INFO_PROPERTY (NM_SETTING_TEAM_RUNNER_SYS_PRIO,
				.parser_skip   = TRUE,
				.writer_skip   = TRUE,
			),
			PARSE_INFO_PROPERTY (NM_SETTING_TEAM_RUNNER_TX_BALANCER,
				.parser_skip   = TRUE,
				.writer_skip   = TRUE,
			),
			PARSE_INFO_PROPERTY (NM_SETTING_TEAM_RUNNER_TX_BALANCER_INTERVAL,
				.parser_skip   = TRUE,
				.writer_skip   = TRUE,
			),
			PARSE_INFO_PROPERTY (NM_SETTING_TEAM_RUNNER_TX_HASH,
				.parser_skip   = TRUE,
				.writer_skip   = TRUE,
			),
		),
	),
	PARSE_INFO_SETTING (NM_META_SETTING_TYPE_TEAM_PORT,
		PARSE_INFO_PROPERTIES (
			PARSE_INFO_PROPERTY (NM_SETTING_TEAM_CONFIG,
				.parser        = team_config_parser,
			),
			PARSE_INFO_PROPERTY (NM_SETTING_TEAM_PORT_LACP_KEY,
				.parser_skip   = TRUE,
				.writer_skip   = TRUE,
			),
			PARSE_INFO_PROPERTY (NM_SETTING_TEAM_PORT_LACP_PRIO,
				.parser_skip   = TRUE,
				.writer_skip   = TRUE,
			),
			PARSE_INFO_PROPERTY (NM_SETTING_TEAM_PORT_LINK_WATCHERS,
				.parser_skip   = TRUE,
				.writer_skip   = TRUE,
			),
			PARSE_INFO_PROPERTY (NM_SETTING_TEAM_PORT_PRIO,
				.parser_skip   = TRUE,
				.writer_skip   = TRUE,
			),
			PARSE_INFO_PROPERTY (NM_SETTING_TEAM_PORT_QUEUE_ID,
				.parser_skip   = TRUE,
				.writer_skip   = TRUE,
			),
			PARSE_INFO_PROPERTY (NM_SETTING_TEAM_PORT_STICKY,
				.parser_skip   = TRUE,
				.writer_skip   = TRUE,
			),
		),
	),
	PARSE_INFO_SETTING (NM_META_SETTING_TYPE_USER,
		PARSE_INFO_PROPERTIES (
			PARSE_INFO_PROPERTY (NM_SETTING_USER_DATA,
				.parser_no_check_key = TRUE,
			),
		),
	),
	PARSE_INFO_SETTING (NM_META_SETTING_TYPE_VLAN,
		PARSE_INFO_PROPERTIES (
			PARSE_INFO_PROPERTY (NM_SETTING_VLAN_FLAGS,
				.writer_persist_default = TRUE,
			),
		),
	),
	PARSE_INFO_SETTING (NM_META_SETTING_TYPE_VPN,
		PARSE_INFO_PROPERTIES (
			PARSE_INFO_PROPERTY (NM_SETTING_VPN_DATA,
				.parser_no_check_key = TRUE,
			),
			PARSE_INFO_PROPERTY (NM_SETTING_VPN_PERSISTENT,
				.parser_no_check_key = TRUE,
			),
			PARSE_INFO_PROPERTY (NM_SETTING_VPN_SECRETS,
				.parser_no_check_key = TRUE,
			),
			PARSE_INFO_PROPERTY (NM_SETTING_VPN_SERVICE_TYPE,
				.parser_no_check_key = TRUE,
			),
			PARSE_INFO_PROPERTY (NM_SETTING_VPN_TIMEOUT,
				.parser_no_check_key = TRUE,
			),
			PARSE_INFO_PROPERTY (NM_SETTING_VPN_USER_NAME,
				.parser_no_check_key = TRUE,
			),
		),
	),
	PARSE_INFO_SETTING (NM_META_SETTING_TYPE_WIMAX,
		PARSE_INFO_PROPERTIES (
			PARSE_INFO_PROPERTY (NM_SETTING_WIMAX_MAC_ADDRESS,
				.parser        = mac_address_parser_ETHER,
			),
		),
	),
};

static const ParseInfoProperty *
_parse_info_find (NMSetting *setting,
                  const char *property_name,
                  const char **out_setting_name)
{
	const NMMetaSettingInfo *setting_info;
	const ParseInfoSetting *pis;
	gssize idx;

#if NM_MORE_ASSERTS > 10
	{
		guint i, j;

		for (i = 0; i < G_N_ELEMENTS (parse_infos); i++) {
			pis = parse_infos[i];

			if (!pis)
				continue;

			g_assert (pis->properties);
			g_assert (pis->properties[0]);
			for (j = 0; pis->properties[j]; j++) {
				const ParseInfoProperty *pip0;
				const ParseInfoProperty *pip = pis->properties[j];

				g_assert (pip->property_name);
				if (   j > 0
				    && (pip0 = pis->properties[j - 1])
				    && strcmp (pip0->property_name, pip->property_name) >= 0) {
					g_error ("Wrong order at index #%d.%d: \"%s.%s\" before \"%s.%s\"",
					         i, j - 1,
					         nm_meta_setting_infos[i].setting_name, pip0->property_name,
					         nm_meta_setting_infos[i].setting_name, pip->property_name);
				}
			}
		}
	}
#endif

	if (   !NM_IS_SETTING (setting)
	    || !(setting_info = NM_SETTING_GET_CLASS (setting)->setting_info)) {
		/* handle invalid setting objects gracefully. */
		*out_setting_name = NULL;
		return NULL;
	}

	*out_setting_name = setting_info->setting_name;

	if ((pis = parse_infos[setting_info->meta_type])) {
		G_STATIC_ASSERT_EXPR (G_STRUCT_OFFSET (ParseInfoProperty, property_name) == 0);
		idx = nm_utils_ptrarray_find_binary_search ((gconstpointer *) pis->properties,
		                                            NM_PTRARRAY_LEN (pis->properties),
		                                            &property_name,
		                                            nm_strcmp_p_with_data,
		                                            NULL,
		                                            NULL,
		                                            NULL);
		if (idx >= 0)
			return pis->properties[idx];
	}

	return NULL;
}

/*****************************************************************************/

static void
read_one_setting_value (KeyfileReaderInfo *info,
                        NMSetting *setting,
                        const NMSettInfoProperty *property_info)
{
	GKeyFile *keyfile = info->keyfile;
	gs_free_error GError *err = NULL;
	const ParseInfoProperty *pip;
	gs_free char *tmp_str = NULL;
	const char *setting_name;
	const char *key;
	GType type;
	guint64 u64;
	gint64 i64;

	nm_assert (!info->error);
	nm_assert (property_info->param_spec);

	if ((property_info->param_spec->flags & (G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY)) != G_PARAM_WRITABLE)
		return;

	key = property_info->param_spec->name;

	pip = _parse_info_find (setting, key, &setting_name);

	nm_assert (setting_name);

	if (   !pip
	    && nm_streq (key, NM_SETTING_NAME))
		return;

	if (pip && pip->parser_skip)
		return;

	/* Check for the exact key in the GKeyFile if required.  Most setting
	 * properties map 1:1 to a key in the GKeyFile, but for those properties
	 * like IP addresses and routes where more than one value is actually
	 * encoded by the setting property, this won't be true.
	 */
	if (   (!pip || !pip->parser_no_check_key)
	    && !nm_keyfile_plugin_kf_has_key (keyfile, setting_name, key, &err)) {
		/* Key doesn't exist or an error occurred, thus nothing to do. */
		if (err) {
			if (!handle_warn (info, key, NM_KEYFILE_WARN_SEVERITY_WARN,
			                  _("error loading setting value: %s"),
			                  err->message))
				return;
		}
		return;
	}

	if (pip && pip->parser) {
		pip->parser (info, setting, key);
		return;
	}

	type = G_PARAM_SPEC_VALUE_TYPE (property_info->param_spec);

	if (type == G_TYPE_STRING) {
		gs_free char *str_val = NULL;

		str_val = nm_keyfile_plugin_kf_get_string (keyfile, setting_name, key, &err);
		if (!err)
			nm_g_object_set_property_string_take (G_OBJECT (setting), key, g_steal_pointer (&str_val), &err);
	} else if (type == G_TYPE_UINT) {
		tmp_str = nm_keyfile_plugin_kf_get_value (keyfile, setting_name, key, &err);
		if (!err) {
			u64 = _nm_utils_ascii_str_to_uint64 (tmp_str, 0, 0, G_MAXUINT, G_MAXUINT64);
			if (   u64 == G_MAXUINT64
			    && errno != 0) {
				g_set_error_literal (&err, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_INVALID_VALUE,
				                     _("value cannot be interpreted as integer"));
			} else
				nm_g_object_set_property_uint (G_OBJECT (setting), key, u64, &err);
		}
	} else if (type == G_TYPE_INT) {
		tmp_str = nm_keyfile_plugin_kf_get_value (keyfile, setting_name, key, &err);
		if (!err) {
			i64 = _nm_utils_ascii_str_to_int64 (tmp_str, 0, G_MININT, G_MAXINT, G_MININT64);
			if (   i64 == G_MININT64
			    && errno != 0) {
				g_set_error_literal (&err, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_INVALID_VALUE,
				                     _("value cannot be interpreted as integer"));
			} else
				nm_g_object_set_property_int (G_OBJECT (setting), key, i64, &err);
		}
	} else if (type == G_TYPE_BOOLEAN) {
		gboolean bool_val;

		bool_val = nm_keyfile_plugin_kf_get_boolean (keyfile, setting_name, key, &err);
		if (!err)
			nm_g_object_set_property_boolean (G_OBJECT (setting), key, bool_val, &err);
	} else if (type == G_TYPE_CHAR) {
		tmp_str = nm_keyfile_plugin_kf_get_value (keyfile, setting_name, key, &err);
		if (!err) {
			/* As documented by glib, G_TYPE_CHAR is really a (signed!) gint8. */
			i64 = _nm_utils_ascii_str_to_int64 (tmp_str, 0, G_MININT8, G_MAXINT8, G_MININT64);
			if (   i64 == G_MININT64
			    && errno != 0) {
				g_set_error_literal (&err, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_INVALID_VALUE,
				                     _("value cannot be interpreted as integer"));
			} else
				nm_g_object_set_property_char (G_OBJECT (setting), key, i64, &err);
		}
	} else if (type == G_TYPE_UINT64) {
		tmp_str = nm_keyfile_plugin_kf_get_value (keyfile, setting_name, key, &err);
		if (!err) {
			u64 = _nm_utils_ascii_str_to_uint64 (tmp_str, 0, 0, G_MAXUINT64, G_MAXUINT64);
			if (   u64 == G_MAXUINT64
			    && errno != 0) {
				g_set_error_literal (&err, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_INVALID_VALUE,
				                     _("value cannot be interpreted as integer"));
			} else
				nm_g_object_set_property_uint64 (G_OBJECT (setting), key, u64, &err);
		}
	} else if (type == G_TYPE_INT64) {
		tmp_str = nm_keyfile_plugin_kf_get_value (keyfile, setting_name, key, &err);
		if (!err) {
			i64 = _nm_utils_ascii_str_to_int64 (tmp_str, 0, G_MININT64, G_MAXINT64, G_MAXINT64);
			if (   i64 == G_MAXINT64
			    && errno != 0) {
				g_set_error_literal (&err, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_INVALID_VALUE,
				                     _("value cannot be interpreted as integer"));
			} else
				nm_g_object_set_property_int64 (G_OBJECT (setting), key, i64, &err);
		}
	} else if (type == G_TYPE_BYTES) {
		gs_free int *tmp = NULL;
		GByteArray *array;
		GBytes *bytes;
		gsize length;
		int i;
		gboolean already_warned = FALSE;

		tmp = nm_keyfile_plugin_kf_get_integer_list (keyfile, setting_name, key, &length, NULL);

		array = g_byte_array_sized_new (length);
		for (i = 0; i < length; i++) {
			const int val = tmp[i];
			unsigned char v = (unsigned char) (val & 0xFF);

			if (val < 0 || val > 255) {
				if (   !already_warned
				    && !handle_warn (info, key, NM_KEYFILE_WARN_SEVERITY_WARN,
				                     _("ignoring invalid byte element '%d' (not between 0 and 255 inclusive)"),
				                     val)) {
					g_byte_array_unref (array);
					return;
				}
				already_warned = TRUE;
			} else
				g_byte_array_append (array, (const unsigned char *) &v, sizeof (v));
		}

		bytes = g_byte_array_free_to_bytes (array);
		g_object_set (setting, key, bytes, NULL);
		g_bytes_unref (bytes);
	} else if (type == G_TYPE_STRV) {
		gs_strfreev char **sa = NULL;
		gsize length;

		sa = nm_keyfile_plugin_kf_get_string_list (keyfile, setting_name, key, &length, NULL);
		g_object_set (setting, key, sa, NULL);
	} else if (type == G_TYPE_HASH_TABLE) {
		read_hash_of_string (keyfile, setting, key);
	} else if (type == G_TYPE_ARRAY) {
		read_array_of_uint (keyfile, setting, key);
	} else if (G_TYPE_IS_FLAGS (type)) {
		tmp_str = nm_keyfile_plugin_kf_get_value (keyfile, setting_name, key, &err);
		if (!err) {
			u64 = _nm_utils_ascii_str_to_uint64 (tmp_str, 0, 0, G_MAXUINT, G_MAXUINT64);
			if (   u64 == G_MAXUINT64
			    && errno != 0) {
				g_set_error_literal (&err, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_INVALID_VALUE,
				                     _("value cannot be interpreted as integer"));
			} else
				nm_g_object_set_property_flags (G_OBJECT (setting), key, type, u64, &err);
		}
	} else if (G_TYPE_IS_ENUM (type)) {
		tmp_str = nm_keyfile_plugin_kf_get_value (keyfile, setting_name, key, &err);
		if (!err) {
			i64 = _nm_utils_ascii_str_to_int64 (tmp_str, 0, G_MININT, G_MAXINT, G_MAXINT64);
			if (   i64 == G_MAXINT64
			    && errno != 0) {
				g_set_error_literal (&err, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_INVALID_VALUE,
				                     _("value cannot be interpreted as integer"));
			} else
				nm_g_object_set_property_enum (G_OBJECT (setting), key, type, i64, &err);
		}
	} else
		g_return_if_reached ();

	if (err) {
		if (   err->domain == G_KEY_FILE_ERROR
		    && NM_IN_SET (err->code, G_KEY_FILE_ERROR_GROUP_NOT_FOUND,
		                             G_KEY_FILE_ERROR_KEY_NOT_FOUND)) {
			/* ignore such errors. The key is not present. */
		} else {
			handle_warn (info, key, NM_KEYFILE_WARN_SEVERITY_WARN,
			             _("invalid setting: %s"), err->message);
		}
	}
}

static void
_read_setting (KeyfileReaderInfo *info)
{
	const NMSettInfoSetting *sett_info;
	gs_unref_object NMSetting *setting = NULL;
	const char *alias;
	GType type;
	guint i;

	alias = nm_keyfile_plugin_get_setting_name_for_alias (info->group);
	if (!alias)
		alias = info->group;

	type = nm_setting_lookup_type (alias);
	if (!type) {
		handle_warn (info, NULL, NM_KEYFILE_WARN_SEVERITY_WARN,
		             _("invalid setting name '%s'"), info->group);
		return;
	}

	setting = g_object_new (type, NULL);

	info->setting = setting;

	sett_info = _nm_setting_class_get_sett_info (NM_SETTING_GET_CLASS (setting));

	if (sett_info->detail.gendata_info) {
		gs_free char **keys = NULL;
		gsize k, n_keys;

		keys = g_key_file_get_keys (info->keyfile, info->group, &n_keys, NULL);
		if (!keys)
			n_keys = 0;
		if (n_keys > 0) {
			GHashTable *h = _nm_setting_gendata_hash (setting, TRUE);

			nm_utils_strv_sort (keys, n_keys);
			for (k = 0; k < n_keys; k++) {
				gs_free char *key = keys[k];
				gs_free_error GError *local = NULL;
				const GVariantType *variant_type;
				GVariant *variant;

				/* a GKeyFile can return duplicate keys, there is just no API to make sense
				 * of them. Skip them. */
				if (   k + 1 < n_keys
				    && nm_streq (key, keys[k + 1]))
					continue;

				/* currently, the API is very simple. The setting class just returns
				 * the desired variant type, and keyfile reader will try to parse
				 * it accordingly. Note, that this does currently not allow, that
				 * a particular key can contain different variant types, nor is it
				 * very flexible in general.
				 *
				 * We add flexibility when we need it. Keep it simple for now. */
				variant_type = sett_info->detail.gendata_info->get_variant_type (sett_info,
				                                                                 key,
				                                                                 &local);
				if (!variant_type) {
					if (!handle_warn (info, key, NM_KEYFILE_WARN_SEVERITY_WARN,
					                  _("invalid key '%s.%s'"),
					                  info->group, key))
						break;
					continue;
				}

				if (g_variant_type_equal (variant_type, G_VARIANT_TYPE_BOOLEAN)) {
					gboolean v;

					v = g_key_file_get_boolean (info->keyfile,
					                            info->group,
					                            key,
					                            &local);
					if (local) {
						if (!handle_warn (info, key, NM_KEYFILE_WARN_SEVERITY_WARN,
						                  _("key '%s.%s' is not boolean"),
						                  info->group, key))
							break;
						continue;
					}
					variant = g_variant_new_boolean (v);
				} else {
					nm_assert_not_reached ();
					continue;
				}

				g_hash_table_insert (h,
				                     g_steal_pointer (&key),
				                     g_variant_take_ref (variant));
			}
			for (; k < n_keys; k++)
				g_free (keys[k]);
		}
	}

	for (i = 0; i < sett_info->property_infos_len; i++) {
		const NMSettInfoProperty *property_info = &sett_info->property_infos[i];

		if (property_info->param_spec) {
			read_one_setting_value (info, setting, property_info);
			if (info->error)
				goto out;
		}
	}

out:
	info->setting = NULL;
	if (!info->error)
		nm_connection_add_setting (info->connection, g_steal_pointer (&setting));
}

static void
_read_setting_wireguard_peer (KeyfileReaderInfo *info)
{
	gs_unref_object NMSettingWireGuard *s_wg_new = NULL;
	nm_auto_unref_wgpeer NMWireGuardPeer *peer = NULL;
	gs_free_error GError *error = NULL;
	NMSettingWireGuard *s_wg;
	gs_free char *str = NULL;
	const char *cstr = NULL;
	const char *key;
	gint64 i64;
	gs_strfreev char **sa = NULL;
	gsize n_sa;

	peer = nm_wireguard_peer_new ();

	nm_assert (g_str_has_prefix (info->group, NM_KEYFILE_GROUPPREFIX_WIREGUARD_PEER));
	cstr = &info->group[NM_STRLEN (NM_KEYFILE_GROUPPREFIX_WIREGUARD_PEER)];
	if (   !nm_utils_base64secret_normalize (cstr, NM_WIREGUARD_PUBLIC_KEY_LEN, &str)
	    || !nm_streq0 (str, cstr)) {
		/* the group name must be identical to the normalized(!) key, so that it
		 * is uniquely identified. */
		handle_warn (info, NULL, NM_KEYFILE_WARN_SEVERITY_WARN,
		             _("invalid peer public key in section '%s'"),
		             info->group);
		return;
	}
	nm_wireguard_peer_set_public_key (peer, cstr, TRUE);
	nm_clear_g_free (&str);

	key = NM_WIREGUARD_PEER_ATTR_PRESHARED_KEY;
	str = nm_keyfile_plugin_kf_get_string (info->keyfile, info->group, key, NULL);
	if (str) {
		if (!nm_wireguard_peer_set_preshared_key (peer, str, FALSE)) {
			if (!handle_warn (info, key, NM_KEYFILE_WARN_SEVERITY_WARN,
			                  _("key '%s.%s' is not not a valid 256 bit key in base64 encoding"),
			                  info->group, key))
				return;
		}
		nm_clear_g_free (&str);
	}

	key = NM_WIREGUARD_PEER_ATTR_PRESHARED_KEY_FLAGS;
	i64 = nm_keyfile_plugin_kf_get_int64 (info->keyfile, info->group, key, 0, 0, NM_SETTING_SECRET_FLAG_ALL, -1, NULL);
	if (errno != ENODATA) {
		if (   i64 == -1
		    || !_nm_setting_secret_flags_valid (i64)) {
			if (!handle_warn (info, key, NM_KEYFILE_WARN_SEVERITY_WARN,
			                  _("key '%s.%s' is not not a valid secret flag"),
			                  info->group, key))
				return;
		} else
			nm_wireguard_peer_set_preshared_key_flags (peer, i64);
	}

	key = NM_WIREGUARD_PEER_ATTR_PERSISTENT_KEEPALIVE;
	i64 = nm_keyfile_plugin_kf_get_int64 (info->keyfile, info->group, key, 0, 0, G_MAXUINT32, -1, NULL);
	if (errno != ENODATA) {
		if (i64 == -1) {
			if (!handle_warn (info, key, NM_KEYFILE_WARN_SEVERITY_WARN,
			                  _("key '%s.%s' is not not a integer in range 0 to 2^32"),
			                  info->group, key))
				return;
		} else
			nm_wireguard_peer_set_persistent_keepalive (peer, i64);
	}

	key = NM_WIREGUARD_PEER_ATTR_ENDPOINT;
	str = nm_keyfile_plugin_kf_get_string (info->keyfile, info->group, key, NULL);
	if (str && str[0]) {
		if (!nm_wireguard_peer_set_endpoint (peer, str, FALSE)) {
			if (!handle_warn (info, key, NM_KEYFILE_WARN_SEVERITY_WARN,
			                  _("key '%s.%s' is not not a valid endpoint"),
			                  info->group, key))
				return;
		}
	}
	nm_clear_g_free (&str);

	key = NM_WIREGUARD_PEER_ATTR_ALLOWED_IPS;
	sa = nm_keyfile_plugin_kf_get_string_list (info->keyfile, info->group, key, &n_sa, NULL);
	if (n_sa > 0) {
		gboolean has_error = FALSE;
		gsize i;

		for (i = 0; i < n_sa; i++) {
			if (!nm_utils_parse_inaddr_prefix_bin (AF_UNSPEC, sa[i], NULL, NULL, NULL)) {
				has_error = TRUE;
				continue;
			}
			nm_wireguard_peer_append_allowed_ip (peer, sa[i], TRUE);
		}
		if (has_error) {
			if (!handle_warn (info, key, NM_KEYFILE_WARN_SEVERITY_WARN,
			                  _("key '%s.%s' has invalid allowed-ips"),
			                  info->group, key))
				return;
		}
	}
	nm_clear_pointer (&sa, g_strfreev);

	if (info->error)
		return;

	if (!nm_wireguard_peer_is_valid (peer, TRUE, TRUE, &error)) {
		if (!handle_warn (info, key, NM_KEYFILE_WARN_SEVERITY_WARN,
		                  _("peer '%s' is invalid: %s"),
		                  info->group, error->message))
			return;
		return;
	}

	s_wg = NM_SETTING_WIREGUARD (nm_connection_get_setting (info->connection, NM_TYPE_SETTING_WIREGUARD));
	if (!s_wg) {
		s_wg_new = NM_SETTING_WIREGUARD (nm_setting_wireguard_new ());
		s_wg = s_wg_new;
	}

	nm_setting_wireguard_append_peer (s_wg, peer);

	if (s_wg_new) {
		nm_connection_add_setting (info->connection,
		                           NM_SETTING (g_steal_pointer (&s_wg_new)));
	}
}

static void
_read_setting_vpn_secrets (KeyfileReaderInfo *info)
{
	gs_strfreev char **keys = NULL;
	gsize i, n_keys;
	NMSettingVpn *s_vpn;

	s_vpn = nm_connection_get_setting_vpn (info->connection);
	if (!s_vpn) {
		/* if we don't also have a [vpn] section (which must be parsed earlier),
		 * we don't do anything. */
		nm_assert (!g_key_file_has_group (info->keyfile, "vpn"));
		return;
	}

	keys = nm_keyfile_plugin_kf_get_keys (info->keyfile, NM_KEYFILE_GROUP_VPN_SECRETS, &n_keys, NULL);
	for (i = 0; i < n_keys; i++) {
		gs_free char *secret = NULL;

		secret = nm_keyfile_plugin_kf_get_string (info->keyfile, NM_KEYFILE_GROUP_VPN_SECRETS, keys[i], NULL);
		if (secret)
			nm_setting_vpn_add_secret (s_vpn, keys[i], secret);
	}
}

gboolean
nm_keyfile_read_ensure_id (NMConnection *connection,
                           const char *fallback_id)
{
	NMSettingConnection *s_con;

	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);
	g_return_val_if_fail (fallback_id, FALSE);

	s_con = nm_connection_get_setting_connection (connection);
	g_return_val_if_fail (NM_IS_SETTING_CONNECTION (s_con), FALSE);

	if (nm_setting_connection_get_id (s_con))
		return FALSE;

	g_object_set (s_con, NM_SETTING_CONNECTION_ID, fallback_id, NULL);
	return TRUE;
}

gboolean
nm_keyfile_read_ensure_uuid (NMConnection *connection,
                             const char *fallback_uuid_seed)
{
	NMSettingConnection *s_con;
	gs_free char *hashed_uuid = NULL;

	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);
	g_return_val_if_fail (fallback_uuid_seed, FALSE);

	s_con = nm_connection_get_setting_connection (connection);
	g_return_val_if_fail (NM_IS_SETTING_CONNECTION (s_con), FALSE);

	if (nm_setting_connection_get_uuid (s_con))
		return FALSE;

	hashed_uuid = _nm_utils_uuid_generate_from_strings ("keyfile", fallback_uuid_seed, NULL);
	g_object_set (s_con, NM_SETTING_CONNECTION_UUID, hashed_uuid, NULL);
	return TRUE;
}

/**
 * nm_keyfile_read:
 * @keyfile: the keyfile from which to create the connection
 * @base_dir: when reading certificates from files with relative name,
 *   the relative path is made absolute using @base_dir. This must
 *   be an absolute path.
 * @handler: read handler
 * @user_data: user data for read handler
 * @error: error
 *
 * Tries to create a NMConnection from a keyfile. The resulting keyfile is
 * not normalized and might not even verify.
 *
 * Returns: (transfer full): on success, returns the created connection.
 */
NMConnection *
nm_keyfile_read (GKeyFile *keyfile,
                 const char *base_dir,
                 NMKeyfileReadHandler handler,
                 void *user_data,
                 GError **error)
{
	gs_unref_object NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	gs_strfreev char **groups = NULL;
	gsize n_groups;
	gsize i;
	gboolean vpn_secrets = FALSE;
	KeyfileReaderInfo info;

	g_return_val_if_fail (keyfile, NULL);
	g_return_val_if_fail (!error || !*error, NULL);
	g_return_val_if_fail (base_dir && base_dir[0] == '/', NULL);

	connection = nm_simple_connection_new ();

	info = (KeyfileReaderInfo) {
		.connection = connection,
		.keyfile    = keyfile,
		.base_dir   = base_dir,
		.handler    = handler,
		.user_data  = user_data,
	};

	groups = g_key_file_get_groups (keyfile, &n_groups);
	if (!groups)
		n_groups = 0;

	for (i = 0; i < n_groups; i++) {

		info.group = groups[i];

		if (nm_streq (groups[i], NM_KEYFILE_GROUP_VPN_SECRETS)) {
			/* Only read out secrets when needed */
			vpn_secrets = TRUE;
		} else if (NM_STR_HAS_PREFIX (groups[i], NM_KEYFILE_GROUPPREFIX_WIREGUARD_PEER))
			_read_setting_wireguard_peer (&info);
		else
			_read_setting (&info);

		info.group = NULL;

		if (info.error)
			goto out_with_info_error;
	}

	s_con = nm_connection_get_setting_connection (connection);
	if (!s_con) {
		s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());
		nm_connection_add_setting (connection, NM_SETTING (s_con));
	}

	/* Make sure that we have 'interface-name' even if it was specified in the
	 * "wrong" (ie, deprecated) group.
	 */
	if (   !nm_setting_connection_get_interface_name (s_con)
	    && nm_setting_connection_get_connection_type (s_con)) {
		gs_free char *interface_name = NULL;

		interface_name = g_key_file_get_string (keyfile,
		                                        nm_setting_connection_get_connection_type (s_con),
		                                        "interface-name",
		                                        NULL);
		if (interface_name)
			g_object_set (s_con, NM_SETTING_CONNECTION_INTERFACE_NAME, interface_name, NULL);
	}

	if (vpn_secrets) {
		info.group = NM_KEYFILE_GROUP_VPN_SECRETS;
		_read_setting_vpn_secrets (&info);
		info.group = NULL;;
		if (info.error)
			goto out_with_info_error;
	}

	return g_steal_pointer (&connection);

out_with_info_error:
	g_propagate_error (error, info.error);
	return NULL;
}

/*****************************************************************************/

static void
write_setting_value (KeyfileWriterInfo *info,
                     NMSetting *setting,
                     const NMSettInfoProperty *property_info)
{
	const ParseInfoProperty *pip;
	const char *setting_name;
	const char *key;
	char numstr[64];
	GValue value;
	GType type;

	nm_assert (!info->error);

	if (!property_info->param_spec)
		return;

	key = property_info->param_spec->name;

	pip = _parse_info_find (setting, key, &setting_name);

	if (!setting_name) {
		/* the setting type is unknown. That is highly unexpected
		 * (and as this is currently only called from NetworkManager
		 * daemon, not possible).
		 *
		 * Still, handle it gracefully, because later keyfile writer will become
		 * public API of libnm, where @setting is (untrusted) user input.
		 *
		 * Gracefully here just means: ignore the setting. */
		return;
	}

	if (   !pip
	    && nm_streq (key, NM_SETTING_NAME))
		return;

	if (pip && pip->writer_skip)
		return;

	/* Don't write secrets that are owned by user secret agents or aren't
	 * supposed to be saved.  VPN secrets are handled specially though since
	 * the secret flags there are in a third-level hash in the 'secrets'
	 * property.
	 */
	if (   (property_info->param_spec->flags & NM_SETTING_PARAM_SECRET)
	    && !NM_IS_SETTING_VPN (setting)) {
		NMSettingSecretFlags secret_flags = NM_SETTING_SECRET_FLAG_NONE;

		if (!nm_setting_get_secret_flags (setting, key, &secret_flags, NULL))
			g_return_if_reached ();
		if (!_secret_flags_persist_secret (secret_flags))
			return;
	}

	value = (GValue) { 0 };

	g_value_init (&value, G_PARAM_SPEC_VALUE_TYPE (property_info->param_spec));
	g_object_get_property (G_OBJECT (setting), property_info->param_spec->name, &value);

	if (   (!pip || !pip->writer_persist_default)
	    && g_param_value_defaults (property_info->param_spec, &value)) {
		nm_assert (!g_key_file_has_key (info->keyfile, setting_name, key, NULL));
		goto out_unset_value;
	}

	if (pip && pip->writer) {
		pip->writer (info, setting, key, &value);
		goto out_unset_value;
	}

	type = G_VALUE_TYPE (&value);
	if (type == G_TYPE_STRING) {
		const char *str;

		str = g_value_get_string (&value);
		if (str)
			nm_keyfile_plugin_kf_set_string (info->keyfile, setting_name, key, str);
	} else if (type == G_TYPE_UINT) {
		nm_sprintf_buf (numstr, "%u", g_value_get_uint (&value));
		nm_keyfile_plugin_kf_set_value (info->keyfile, setting_name, key, numstr);
	} else if (type == G_TYPE_INT) {
		nm_sprintf_buf (numstr, "%d", g_value_get_int (&value));
		nm_keyfile_plugin_kf_set_value (info->keyfile, setting_name, key, numstr);
	} else if (type == G_TYPE_UINT64) {
		nm_sprintf_buf (numstr, "%" G_GUINT64_FORMAT, g_value_get_uint64 (&value));
		nm_keyfile_plugin_kf_set_value (info->keyfile, setting_name, key, numstr);
	} else if (type == G_TYPE_INT64) {
		nm_sprintf_buf (numstr, "%" G_GINT64_FORMAT, g_value_get_int64 (&value));
		nm_keyfile_plugin_kf_set_value (info->keyfile, setting_name, key, numstr);
	} else if (type == G_TYPE_BOOLEAN) {
		nm_keyfile_plugin_kf_set_value (info->keyfile, setting_name, key,
		                                  g_value_get_boolean (&value)
		                                ? "true"
		                                : "false");
	} else if (type == G_TYPE_CHAR) {
		nm_sprintf_buf (numstr, "%d", (int) g_value_get_schar (&value));
		nm_keyfile_plugin_kf_set_value (info->keyfile, setting_name, key, numstr);
	} else if (type == G_TYPE_BYTES) {
		GBytes *bytes;
		const guint8 *data;
		gsize len = 0;

		bytes = g_value_get_boxed (&value);
		data = bytes ? g_bytes_get_data (bytes, &len) : NULL;

		if (data != NULL && len > 0)
			nm_keyfile_plugin_kf_set_integer_list_uint8 (info->keyfile, setting_name, key, data, len);
	} else if (type == G_TYPE_STRV) {
		char **array;

		array = (char **) g_value_get_boxed (&value);
		nm_keyfile_plugin_kf_set_string_list (info->keyfile, setting_name, key, (const char **const) array, g_strv_length (array));
	} else if (type == G_TYPE_HASH_TABLE) {
		write_hash_of_string (info->keyfile, setting, key, &value);
	} else if (type == G_TYPE_ARRAY) {
		write_array_of_uint (info->keyfile, setting, key, &value);
	} else if (G_VALUE_HOLDS_FLAGS (&value)) {
		nm_sprintf_buf (numstr, "%u", g_value_get_flags (&value));
		nm_keyfile_plugin_kf_set_value (info->keyfile, setting_name, key, numstr);
	} else if (G_VALUE_HOLDS_ENUM (&value)) {
		nm_sprintf_buf (numstr, "%d", g_value_get_enum (&value));
		nm_keyfile_plugin_kf_set_value (info->keyfile, setting_name, key, numstr);
	} else
		g_return_if_reached ();

out_unset_value:
	g_value_unset (&value);
}

static void
_write_setting_wireguard (NMSetting *setting, KeyfileWriterInfo *info)
{
	NMSettingWireGuard *s_wg;
	guint i_peer, n_peers;

	s_wg = NM_SETTING_WIREGUARD (setting);

	n_peers = nm_setting_wireguard_get_peers_len (s_wg);
	for (i_peer = 0; i_peer < n_peers; i_peer++) {
		NMWireGuardPeer *peer = nm_setting_wireguard_get_peer (s_wg, i_peer);
		const char *public_key;
		char group[NM_STRLEN (NM_KEYFILE_GROUPPREFIX_WIREGUARD_PEER) + 200];
		NMSettingSecretFlags secret_flags;
		gboolean any_key = FALSE;
		guint i_aip, n_aip;
		const char *cstr;
		guint32 u32;

		public_key = nm_wireguard_peer_get_public_key (peer);
		if (   !public_key
		    || !public_key[0]
		    || !NM_STRCHAR_ALL (public_key, ch, nm_sd_utils_unbase64char (ch, TRUE) >= 0)) {
			/* invalid peer. Skip it */
			continue;
		}

		if (g_snprintf (group,
		                sizeof (group),
		                "%s%s",
		                NM_KEYFILE_GROUPPREFIX_WIREGUARD_PEER,
		                nm_wireguard_peer_get_public_key (peer)) >= sizeof (group)) {
			/* Too long. Not a valid public key. Skip the peer. */
			continue;
		}

		cstr = nm_wireguard_peer_get_endpoint (peer);
		if (cstr) {
			g_key_file_set_string (info->keyfile, group, NM_WIREGUARD_PEER_ATTR_ENDPOINT, cstr);
			any_key = TRUE;
		}

		secret_flags = nm_wireguard_peer_get_preshared_key_flags (peer);
		if (_secret_flags_persist_secret (secret_flags)) {
			cstr = nm_wireguard_peer_get_preshared_key (peer);
			if (cstr) {
				g_key_file_set_string (info->keyfile, group, NM_WIREGUARD_PEER_ATTR_PRESHARED_KEY, cstr);
				any_key = TRUE;
			}
		}

		/* usually, we don't persist the secret-flags 0 (because they are the default).
		 * For WireGuard peers, the default secret-flags for preshared-key are 4 (not-required).
		 * So, in this case behave differently: a missing preshared-key-flag setting means
		 * "not-required". */
		if (secret_flags != NM_SETTING_SECRET_FLAG_NOT_REQUIRED) {
			g_key_file_set_int64 (info->keyfile, group, NM_WIREGUARD_PEER_ATTR_PRESHARED_KEY_FLAGS, secret_flags);
			any_key = TRUE;
		}

		u32 = nm_wireguard_peer_get_persistent_keepalive (peer);
		if (u32) {
			g_key_file_set_uint64 (info->keyfile, group, NM_WIREGUARD_PEER_ATTR_PERSISTENT_KEEPALIVE, u32);
			any_key = TRUE;
		}

		n_aip = nm_wireguard_peer_get_allowed_ips_len (peer);
		if (n_aip > 0) {
			gs_free const char **strv = NULL;

			strv = g_new (const char *, ((gsize) n_aip) + 1);
			for (i_aip = 0; i_aip < n_aip; i_aip++)
				strv[i_aip] = nm_wireguard_peer_get_allowed_ip (peer, i_aip, NULL);
			strv[n_aip] = NULL;
			g_key_file_set_string_list (info->keyfile, group, NM_WIREGUARD_PEER_ATTR_ALLOWED_IPS,
			                            strv, n_aip);
			any_key = TRUE;
		}

		if (!any_key) {
			/* we cannot omit all keys. At an empty endpoint. */
			g_key_file_set_string (info->keyfile, group, NM_WIREGUARD_PEER_ATTR_ENDPOINT, "");
		}
	}
}

GKeyFile *
nm_keyfile_write (NMConnection *connection,
                  NMKeyfileWriteHandler handler,
                  void *user_data,
                  GError **error)
{
	gs_unref_keyfile GKeyFile *keyfile = NULL;
	KeyfileWriterInfo info;
	gs_free NMSetting **settings = NULL;
	guint i, j, n_settings = 0;

	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);
	g_return_val_if_fail (!error || !*error, NULL);

	if (!nm_connection_verify (connection, error))
		return NULL;

	keyfile = g_key_file_new ();

	info = (KeyfileWriterInfo) {
		.connection = connection,
		.keyfile    = keyfile,
		.error      = NULL,
		.handler    = handler,
		.user_data  = user_data,
	};

	settings = nm_connection_get_settings (connection, &n_settings);
	for (i = 0; i < n_settings; i++) {
		const NMSettInfoSetting *sett_info;
		NMSetting *setting = settings[i];

		sett_info = _nm_setting_class_get_sett_info (NM_SETTING_GET_CLASS (setting));

		if (sett_info->detail.gendata_info) {
			guint k, n_keys;
			const char *const*keys;

			nm_assert (!nm_keyfile_plugin_get_alias_for_setting_name (sett_info->setting_class->setting_info->setting_name));

			n_keys = _nm_setting_gendata_get_all (setting, &keys, NULL);

			if (n_keys > 0) {
				const char *setting_name = sett_info->setting_class->setting_info->setting_name;
				GHashTable *h = _nm_setting_gendata_hash (setting, FALSE);

				for (k = 0; k < n_keys; k++) {
					const char *key = keys[k];
					GVariant *v;

					v = g_hash_table_lookup (h, key);

					if (g_variant_is_of_type (v, G_VARIANT_TYPE_BOOLEAN)) {
						g_key_file_set_boolean (info.keyfile,
						                        setting_name,
						                        key,
						                        g_variant_get_boolean (v));
					} else {
						/* BUG: The variant type is not implemented. Since the connection
						 * verifies, this can only mean we either wrongly didn't reject
						 * the connection as invalid, or we didn't properly implement the
						 * variant type. */
						nm_assert_not_reached ();
						continue;
					}
				}
			}
		}

		for (j = 0; j < sett_info->property_infos_len; j++) {
			const NMSettInfoProperty *property_info = _nm_sett_info_property_info_get_sorted (sett_info, j);

			write_setting_value (&info, setting, property_info);
			if (info.error)
				goto out_with_info_error;
		}

		if (NM_IS_SETTING_WIREGUARD (setting)) {
			_write_setting_wireguard (setting, &info);
			if (info.error)
				goto out_with_info_error;
		}

		nm_assert (!info.error);
	}

	nm_assert (!info.error);

	return g_steal_pointer (&keyfile);

out_with_info_error:
	g_propagate_error (error, info.error);
	return NULL;
}

/*****************************************************************************/

static const char temp_letters[] =
"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/*
 * Check '.[a-zA-Z0-9]{6}' file suffix used for temporary files by g_file_set_contents() (mkstemp()).
 */
static gboolean
check_mkstemp_suffix (const char *path)
{
	const char *ptr;

	nm_assert (path);

	/* Matches *.[a-zA-Z0-9]{6} suffix of mkstemp()'s temporary files */
	ptr = strrchr (path, '.');
	if (   ptr
	    && strspn (&ptr[1], temp_letters) == 6
	    && ptr[7] == '\0')
		return TRUE;
	return FALSE;
}

static gboolean
_check_suffix_impl (const char *base, const char *tag, gsize tag_len)
{
	gsize len;

	nm_assert (base);
	nm_assert (tag);
	nm_assert (strlen (tag) == tag_len);

	len = strlen (base);
	if (   len > tag_len
	    && !g_ascii_strcasecmp (base + len - tag_len, tag))
		return TRUE;
	return FALSE;
}
#define check_suffix(base, tag) _check_suffix_impl ((base), ""tag"", NM_STRLEN (tag))

#define SWP_TAG ".swp"
#define SWPX_TAG ".swpx"
#define PEM_TAG ".pem"
#define DER_TAG ".der"

gboolean
nm_keyfile_utils_ignore_filename (const char *filename, gboolean require_extension)
{
	const char *base;
	gsize l;

	/* ignore_filename() must mirror nm_keyfile_utils_create_filename() */

	g_return_val_if_fail (filename, TRUE);

	base = strrchr (filename, '/');
	if (base)
		base++;
	else
		base = filename;

	if (!base[0]) {
		/* this check above with strrchr() also rejects "/some/path/with/trailing/slash/",
		 * but that is fine, because such a path would name a directory, and we are not
		 * interested in directories. */
		return TRUE;
	}

	if (base[0] == '.') {
		/* don't allow hidden files */
		return TRUE;
	}

	l = strlen (base);

	if (require_extension) {
		if (   l <= NM_STRLEN (NM_KEYFILE_PATH_SUFFIX_NMCONNECTION)
		    || !g_str_has_suffix (base, NM_KEYFILE_PATH_SUFFIX_NMCONNECTION))
			return TRUE;
		return FALSE;
	}

	/* Ignore backup files */
	if (base[l - 1] == '~')
		return TRUE;

	/* Ignore temporary files */
	if (check_mkstemp_suffix (base))
		return TRUE;

	/* Ignore 802.1x certificates and keys */
	if (   check_suffix (base, PEM_TAG)
	    || check_suffix (base, DER_TAG))
		return TRUE;

	return FALSE;
}

char *
nm_keyfile_utils_create_filename (const char *name,
                                  gboolean with_extension)
{
	GString *str;
	const char *f = name;
	/* keyfile used to escape with '*', do not change that behavior.
	 *
	 * But for newly added escapings, use '_' instead.
	 * Also, @with_extension is new-style. */
	const char ESCAPE_CHAR = with_extension ? '_' : '*';
	const char ESCAPE_CHAR2 = '_';

	g_return_val_if_fail (name && name[0], NULL);

	str = g_string_sized_new (60);

	/* Convert '/' to ESCAPE_CHAR */
	for (f = name; f[0]; f++) {
		if (f[0] == '/')
			g_string_append_c (str, ESCAPE_CHAR);
		else
			g_string_append_c (str, f[0]);
	}

	/* nm_keyfile_utils_create_filename() must avoid anything that ignore_filename() would reject.
	 * We can escape here more aggressivly then what we would read back. */
	if (str->str[0] == '.')
		str->str[0] = ESCAPE_CHAR2;
	if (str->str[str->len - 1] == '~')
		str->str[str->len - 1] = ESCAPE_CHAR2;
	if (   check_mkstemp_suffix (str->str)
	    || check_suffix (str->str, PEM_TAG)
	    || check_suffix (str->str, DER_TAG))
		g_string_append_c (str, ESCAPE_CHAR2);

	if (with_extension)
		g_string_append (str, NM_KEYFILE_PATH_SUFFIX_NMCONNECTION);

	/* nm_keyfile_utils_create_filename() must mirror ignore_filename() */
	nm_assert (!strchr (str->str, '/'));
	nm_assert (!nm_keyfile_utils_ignore_filename (str->str, with_extension));

	return g_string_free (str, FALSE);;
}
