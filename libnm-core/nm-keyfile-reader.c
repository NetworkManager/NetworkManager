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

#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <string.h>
#include <linux/pkt_sched.h>

#include "nm-common-macros.h"
#include "nm-core-internal.h"
#include "nm-keyfile-utils.h"

#include "nm-setting-user.h"

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
	char *s;
	const char *key_setting_name;

	s = nm_keyfile_plugin_kf_get_string (info->keyfile, setting_name, key, NULL);
	if (s) {
		key_setting_name = nm_keyfile_plugin_get_setting_name_for_alias (s);
		g_object_set (G_OBJECT (setting),
		              key, key_setting_name ? key_setting_name : s,
		              NULL);
		g_free (s);
	}
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
 * semicolon (;) and comma (,) are interchangable. The choice of
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

#define VALUE_ORIG()   (value_orig ? value_orig : (value_orig = nm_keyfile_plugin_kf_get_string (info->keyfile, setting_name, key_name, NULL)))

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
		if (out_gateway && gateway_str)
			*out_gateway = g_strdup (gateway_str);
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

static void
ip_address_or_route_parser (KeyfileReaderInfo *info, NMSetting *setting, const char *key)
{
	const char *setting_name = nm_setting_get_name (setting);
	gboolean ipv6 = !strcmp (setting_name, "ipv6");
	gboolean routes = !strcmp (key, "routes");
	static const char *key_names_routes[] = { "route", "routes", NULL };
	static const char *key_names_addresses[] = { "address", "addresses", NULL };
	const char **key_names = routes ? key_names_routes : key_names_addresses;
	char *gateway = NULL;
	GPtrArray *list;
	GDestroyNotify free_func;
	int i;

	if (routes)
		free_func = (GDestroyNotify) nm_ip_route_unref;
	else
		free_func = (GDestroyNotify) nm_ip_address_unref;
	list = g_ptr_array_new_with_free_func (free_func);

	for (i = -1; i < 1000; i++) {
		const char **key_basename;

		for (key_basename = key_names; *key_basename; key_basename++) {
			char *key_name;
			gpointer item;
			char options_key[128];

			/* -1 means no suffix */
			if (i >= 0)
				key_name = g_strdup_printf ("%s%d", *key_basename, i);
			else
				key_name = g_strdup (*key_basename);

			item = read_one_ip_address_or_route (info, key, setting_name, key_name, ipv6, routes,
			                                     gateway ? NULL : &gateway, setting);
			if (item && routes) {
				nm_sprintf_buf (options_key, "%s_options", key_name);
				fill_route_attributes (info->keyfile, item, setting_name, options_key, ipv6 ? AF_INET6 : AF_INET);
			}

			g_free (key_name);

			if (info->error) {
				g_ptr_array_unref (list);
				g_free (gateway);
				return;
			}
			if (item)
				g_ptr_array_add (list, item);

		}
	}

	if (list->len >= 1)
		g_object_set (setting, key, list, NULL);

	if (gateway) {
		g_object_set (setting, "gateway", gateway, NULL);
		g_free (gateway);
	}

	g_ptr_array_unref (list);
}

static void
ip4_dns_parser (KeyfileReaderInfo *info, NMSetting *setting, const char *key)
{
	const char *setting_name = nm_setting_get_name (setting);
	GPtrArray *array;
	gsize length;
	char **list, **iter;
	int ret;

	list = nm_keyfile_plugin_kf_get_string_list (info->keyfile, setting_name, key, &length, NULL);
	if (!list || !g_strv_length (list))
		return;

	array = g_ptr_array_sized_new (length + 1);
	for (iter = list; *iter; iter++) {
		guint32 addr;

		ret = inet_pton (AF_INET, *iter, &addr);
		if (ret <= 0) {
			if (!handle_warn (info, key, NM_KEYFILE_WARN_SEVERITY_WARN,
			                  _("ignoring invalid DNS server IPv4 address '%s'"),
			                  *iter)) {
				g_ptr_array_unref (array);
				g_strfreev (list);
				return;
			}
			continue;
		}

		g_ptr_array_add (array, *iter);
	}
	g_ptr_array_add (array, NULL);

	g_object_set (setting, key, array->pdata, NULL);
	g_ptr_array_unref (array);
	g_strfreev (list);
}

static void
ip6_dns_parser (KeyfileReaderInfo *info, NMSetting *setting, const char *key)
{
	const char *setting_name = nm_setting_get_name (setting);
	GPtrArray *array = NULL;
	gsize length;
	char **list, **iter;
	int ret;

	list = nm_keyfile_plugin_kf_get_string_list (info->keyfile, setting_name, key, &length, NULL);
	if (!list || !g_strv_length (list))
		return;

	array = g_ptr_array_sized_new (length + 1);

	for (iter = list; *iter; iter++) {
		struct in6_addr addr;

		ret = inet_pton (AF_INET6, *iter, &addr);
		if (ret <= 0) {
			if (!handle_warn (info, key, NM_KEYFILE_WARN_SEVERITY_WARN,
			                  _("ignoring invalid DNS server IPv6 address '%s'"),
			                  *iter)) {
				g_ptr_array_unref (array);
				g_strfreev (list);
				return;
			}
			continue;
		}

		g_ptr_array_add (array, *iter);
	}
	g_ptr_array_add (array, NULL);

	g_object_set (setting, key, array->pdata, NULL);
	g_ptr_array_unref (array);
	g_strfreev (list);
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

	g_object_set (G_OBJECT (setting), key, (gint) addr_gen_mode, NULL);
}

static void
mac_address_parser (KeyfileReaderInfo *info, NMSetting *setting, const char *key, gsize enforce_length, gboolean cloned_mac_addr)
{
	const char *setting_name = nm_setting_get_name (setting);
	gs_free char *tmp_string = NULL;
	const char *p, *mac_str;
	gs_free guint8 *buf_arr = NULL;
	guint buf_len = 0;
	gsize length;

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

	keys = nm_keyfile_plugin_kf_get_keys (file, setting_name, NULL, NULL);
	if (!keys || !*keys)
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
				if (strcmp (name, "interface-name"))
					nm_setting_bond_add_option (NM_SETTING_BOND (setting), name, value);
			}
		}
		return;
	}

	if (NM_IS_SETTING_USER (setting)) {
		gs_unref_hashtable GHashTable *data = NULL;

		data = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
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
	str[j] = '\0';
	return j;
}

static GBytes *
get_bytes (KeyfileReaderInfo *info,
           const char *setting_name,
           const char *key,
           gboolean zero_terminate,
           gboolean unescape_semicolon)
{
	gs_free char *tmp_string = NULL;
	gboolean may_be_int_list = TRUE;
	gsize length;

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
		return g_bytes_new_take (tmp_string, 0);
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
		gs_free guint8 *bin_data = NULL;
		const char *const s = tmp_string;
		gsize i, d;
		const gsize BIN_DATA_LEN = (length / 2 + 3);

		bin_data = g_malloc (BIN_DATA_LEN);

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

			bin_data[d++] = n;
			nm_assert (d < BIN_DATA_LEN);

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
			 * binary data as an integer list.
			 *
			 * But we add a '\0' to the bin_data pointer, just to avoid somebody
			 * (erronously!) reading the binary data as C-string.
			 *
			 * @d itself does not entail the '\0'. */
			nm_assert (d + 1 <= BIN_DATA_LEN);
			bin_data = g_realloc (bin_data, d + 1);
			bin_data[d] = '\0';
			return g_bytes_new_take (g_steal_pointer (&bin_data), d);
		}
	}

	/* Handle as a simple string (ie, new format) */
	if (unescape_semicolon)
		length = unescape_semicolons (tmp_string);
	if (zero_terminate)
		length++;
	if (length == 0)
		return NULL;
	tmp_string = g_realloc (tmp_string, length + (zero_terminate ? 0 : 1));
	return g_bytes_new_take (g_steal_pointer (&tmp_string), length);
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

	base = path = g_malloc0 (cert_path_len + 1);
	memcpy (path, cert_path, cert_path_len);

	if (path[0] == '/')
		return path;

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

static gboolean
handle_as_scheme (KeyfileReaderInfo *info, GBytes *bytes, NMSetting *setting, const char *key)
{
	const char *data;
	gsize data_len, bin_len;

	data = g_bytes_get_data (bytes, &data_len);

	g_return_val_if_fail (data && data_len > 0, FALSE);

	/* to be a scheme, @data must be a zero terminated string, which is counted by @data_len */
	if (data[data_len - 1] != '\0')
		return FALSE;
	data_len--;

	/* It's the PATH scheme, can just set plain data.
	 * In this case, @data_len includes */
	if (   data_len >= NM_STRLEN (NM_KEYFILE_CERT_SCHEME_PREFIX_PATH)
	    && g_str_has_prefix (data, NM_KEYFILE_CERT_SCHEME_PREFIX_PATH)) {
		if (nm_setting_802_1x_check_cert_scheme (data, data_len + 1, NULL) == NM_SETTING_802_1X_CK_SCHEME_PATH) {
			const char *path = &data[NM_STRLEN (NM_KEYFILE_CERT_SCHEME_PREFIX_PATH)];
			gs_free char *path_free = NULL;

			if (path[0] != '/') {
				/* we want to read absolute paths because we use keyfile as exchange
				 * between different processes which might not have the same cwd. */
				path = path_free = get_cert_path (info->base_dir, (const guint8 *) path,
				                                  data_len - NM_STRLEN (NM_KEYFILE_CERT_SCHEME_PREFIX_PATH));
			}

			g_object_set (setting, key, bytes, NULL);
			if (!g_file_test (path, G_FILE_TEST_EXISTS)) {
				handle_warn (info, key, NM_KEYFILE_WARN_SEVERITY_INFO_MISSING_FILE,
				             _("certificate or key file '%s' does not exist"),
				             path);
			}
		} else {
			handle_warn (info, key, NM_KEYFILE_WARN_SEVERITY_WARN,
			             _("invalid key/cert value path \"%s\""), data);
		}
		return TRUE;
	}
	if (   data_len >= NM_STRLEN (NM_KEYFILE_CERT_SCHEME_PREFIX_PKCS11)
	    && g_str_has_prefix (data, NM_KEYFILE_CERT_SCHEME_PREFIX_PKCS11)) {
		if (nm_setting_802_1x_check_cert_scheme (data, data_len + 1, NULL) == NM_SETTING_802_1X_CK_SCHEME_PKCS11) {
			g_object_set (setting, key, bytes, NULL);
		} else {
			handle_warn (info, key, NM_KEYFILE_WARN_SEVERITY_WARN,
			             _("invalid PKCS#11 URI \"%s\""), data);
		}
		return TRUE;
	}
	if (   data_len > NM_STRLEN (NM_KEYFILE_CERT_SCHEME_PREFIX_BLOB)
	    && g_str_has_prefix (data, NM_KEYFILE_CERT_SCHEME_PREFIX_BLOB)) {
		const char *cdata = data + NM_STRLEN (NM_KEYFILE_CERT_SCHEME_PREFIX_BLOB);
		guchar *bin;
		GBytes *bytes2;
		gsize i;
		gboolean valid_base64;

		data_len -= NM_STRLEN (NM_KEYFILE_CERT_SCHEME_PREFIX_BLOB);

		/* Let's be strict here. We expect valid base64, no funny stuff!!
		 * We didn't write such invalid data ourselfes and refuse to read it as blob. */
		if ((valid_base64 = (data_len % 4 == 0))) {
			for (i = 0; i < data_len; i++) {
				char c = cdata[i];

				if (!(   (c >= 'a' && c <= 'z')
				      || (c >= 'A' && c <= 'Z')
				      || (c >= '0' && c <= '9')
				      || (c == '+' || c == '/'))) {
					if (c != '=' || i < data_len - 2)
						valid_base64 = FALSE;
					else {
						for (; i < data_len; i++) {
							if (cdata[i] != '=')
								valid_base64 = FALSE;
						}
					}
					break;
				}
			}
		}
		if (!valid_base64) {
			handle_warn (info, key, NM_KEYFILE_WARN_SEVERITY_WARN,
			             _("invalid key/cert value data:;base64, is not base64"));
			return TRUE;
		}

		bin = g_base64_decode (cdata, &bin_len);

		g_return_val_if_fail (bin_len > 0, FALSE);
		if (nm_setting_802_1x_check_cert_scheme (bin, bin_len, NULL) != NM_SETTING_802_1X_CK_SCHEME_BLOB) {
			/* The blob probably starts with "file://". Setting the cert data will confuse NMSetting8021x.
			 * In fact this is a limitation of NMSetting8021x which does not support setting blobs that start
			 * with file://. Just warn and return TRUE to signal that we ~handled~ the setting. */
			g_free (bin);
			handle_warn (info, key, NM_KEYFILE_WARN_SEVERITY_WARN,
			             _("invalid key/cert value data:;base64,file://"));
		} else {
			bytes2 = g_bytes_new_take (bin, bin_len);
			g_object_set (setting, key, bytes2, NULL);
			g_bytes_unref (bytes2);
		}
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
	gboolean success = FALSE;
	gsize validate_len;
	char *path;
	GByteArray *tmp;

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
			goto out;
		exists = g_file_test (path, G_FILE_TEST_EXISTS);
		if (!exists)
			goto out;
	} else if (out_exists)
		exists = g_file_test (path, G_FILE_TEST_EXISTS);

	/* Construct the proper value as required for the PATH scheme */
	tmp = g_byte_array_sized_new (strlen (NM_KEYFILE_CERT_SCHEME_PREFIX_PATH) + strlen (path) + 1);
	g_byte_array_append (tmp, (const guint8 *) NM_KEYFILE_CERT_SCHEME_PREFIX_PATH, strlen (NM_KEYFILE_CERT_SCHEME_PREFIX_PATH));
	g_byte_array_append (tmp, (const guint8 *) path, strlen (path) + 1);
	if (nm_setting_802_1x_check_cert_scheme (tmp->data, tmp->len, NULL) == NM_SETTING_802_1X_CK_SCHEME_PATH) {
		g_free (path);
		path = (char *) g_byte_array_free (tmp, FALSE);
		/* when returning TRUE, we must also be sure that @data_len does not look like
		 * the deprecated format of list of integers. With this implementation that is the
		 * case, as long as @consider_exists is FALSE. */
		success = TRUE;
	} else
		g_byte_array_unref (tmp);

out:
	if (!success) {
		g_free (path);
		return NULL;
	}
	if (out_exists)
		*out_exists = exists;
	return path;
}

static gboolean
handle_as_path (KeyfileReaderInfo *info,
                GBytes *bytes,
                NMSetting *setting,
                const char *key)
{
	const guint8 *data;
	gsize data_len;
	char *path;
	gboolean exists = FALSE;
	GBytes *val;

	data = g_bytes_get_data (bytes, &data_len);

	path = nm_keyfile_detect_unqualified_path_scheme (info->base_dir, data, data_len, TRUE, &exists);
	if (!path)
		return FALSE;

	/* Construct the proper value as required for the PATH scheme */
	val = g_bytes_new_take (path, strlen (path) + 1);
	g_object_set (setting, key, val, NULL);

	/* Warn if the certificate didn't exist */
	if (!exists) {
		handle_warn (info, key, NM_KEYFILE_WARN_SEVERITY_INFO_MISSING_FILE,
		             _("certificate or key file '%s' does not exist"),
		             path);
	}
	g_bytes_unref (val);

	return TRUE;
}

static void
cert_parser (KeyfileReaderInfo *info, NMSetting *setting, const char *key)
{
	const char *setting_name = nm_setting_get_name (setting);
	gs_unref_bytes GBytes *bytes = NULL;
	gsize bin_len;
	const char *bin;

	bytes = get_bytes (info, setting_name, key, TRUE, FALSE);
	if (bytes) {
		/* Try as a path + scheme (ie, starts with "file://") */
		if (handle_as_scheme (info, bytes, setting, key))
			return;
		if (info->error)
			return;

		/* If not, it might be a plain path */
		if (handle_as_path (info, bytes, setting, key))
			return;
		if (info->error)
			return;

		bin = g_bytes_get_data (bytes, &bin_len);
		if (nm_setting_802_1x_check_cert_scheme (bin, bin_len, NULL) != NM_SETTING_802_1X_CK_SCHEME_BLOB) {
			/* The blob probably starts with "file://" but contains invalid characters for a path.
			 * Setting the cert data will confuse NMSetting8021x.
			 * In fact, NMSetting8021x does not support setting such binary data, so just warn and
			 * continue. */
			handle_warn (info, key, NM_KEYFILE_WARN_SEVERITY_WARN,
			             _("invalid key/cert value is not a valid blob"));
		} else
			g_object_set (setting, key, bytes, NULL);
	} else if (!info->error) {
		handle_warn (info, key, NM_KEYFILE_WARN_SEVERITY_WARN,
		             _("invalid key/cert value"));
	}
}

static void
parity_parser (KeyfileReaderInfo *info, NMSetting *setting, const char *key)
{
	const char *setting_name = nm_setting_get_name (setting);
	NMSettingSerialParity parity;
	int int_val;
	gs_free char *str_val = NULL;

	/* Keyfile traditionally stored this as the ASCII value for 'E', 'o', or 'n'.
	 * We now accept either that or the (case-insensitive) character itself (but
	 * still always write it the old way, for backward compatibility).
	 */
	int_val = nm_keyfile_plugin_kf_get_integer (info->keyfile, setting_name, key, NULL);
	if (!int_val) {
		str_val = nm_keyfile_plugin_kf_get_string (info->keyfile, setting_name, key, NULL);
		if (str_val) {
			if (str_val[0] && !str_val[1])
				int_val = str_val[0];
			else {
				/* This will hit the warning below */
				int_val = 'X';
			}
		}
	}

	if (!int_val)
		return;

	switch (int_val) {
	case 'E':
	case 'e':
		parity = NM_SETTING_SERIAL_PARITY_EVEN;
		break;
	case 'O':
	case 'o':
		parity = NM_SETTING_SERIAL_PARITY_ODD;
		break;
	case 'N':
	case 'n':
		parity = NM_SETTING_SERIAL_PARITY_NONE;
		break;
	default:
		handle_warn (info, key, NM_KEYFILE_WARN_SEVERITY_WARN,
		             _("invalid parity value '%s'"),
		             str_val ? str_val : "");
		return;
	}

	g_object_set (setting, key, parity, NULL);
}

static void
team_config_parser (KeyfileReaderInfo *info, NMSetting *setting, const char *key)
{
	const char *setting_name = nm_setting_get_name (setting);
	gs_free char *conf = NULL;
	gs_free_error GError *error = NULL;

	conf = nm_keyfile_plugin_kf_get_string (info->keyfile, setting_name, key, NULL);
	if (conf && conf[0] && !nm_utils_is_json_object (conf, &error)) {
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
	gs_strfreev gchar **keys = NULL;
	gsize n_keys = 0;
	int i;

	qdiscs = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_tc_qdisc_unref);

	keys = nm_keyfile_plugin_kf_get_keys (info->keyfile, setting_name, &n_keys, NULL);
	if (!keys || n_keys == 0)
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
	gs_strfreev gchar **keys = NULL;
	gsize n_keys = 0;
	int i;

	tfilters = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_tc_tfilter_unref);

	keys = nm_keyfile_plugin_kf_get_keys (info->keyfile, setting_name, &n_keys, NULL);
	if (!keys || n_keys == 0)
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

typedef struct {
	const char *setting_name;
	const char *key;
	gboolean check_for_key;
	void (*parser) (KeyfileReaderInfo *info, NMSetting *setting, const char *key);
} KeyParser;

/* A table of keys that require further parsing/conversion because they are
 * stored in a format that can't be automatically read using the key's type.
 * i.e. IPv4 addresses, which are stored in NetworkManager as guint32, but are
 * stored in keyfiles as strings, eg "10.1.1.2" or IPv6 addresses stored
 * in struct in6_addr internally, but as string in keyfiles.
 */
static KeyParser key_parsers[] = {
	{ NM_SETTING_CONNECTION_SETTING_NAME,
	  NM_SETTING_CONNECTION_TYPE,
	  TRUE,
	  setting_alias_parser },
	{ NM_SETTING_BRIDGE_SETTING_NAME,
	  NM_SETTING_BRIDGE_MAC_ADDRESS,
	  TRUE,
	  mac_address_parser_ETHER },
	{ NM_SETTING_IP4_CONFIG_SETTING_NAME,
	  NM_SETTING_IP_CONFIG_ADDRESSES,
	  FALSE,
	  ip_address_or_route_parser },
	{ NM_SETTING_IP6_CONFIG_SETTING_NAME,
	  NM_SETTING_IP_CONFIG_ADDRESSES,
	  FALSE,
	  ip_address_or_route_parser },
	{ NM_SETTING_IP4_CONFIG_SETTING_NAME,
	  NM_SETTING_IP_CONFIG_ROUTES,
	  FALSE,
	  ip_address_or_route_parser },
	{ NM_SETTING_IP6_CONFIG_SETTING_NAME,
	  NM_SETTING_IP_CONFIG_ROUTES,
	  FALSE,
	  ip_address_or_route_parser },
	{ NM_SETTING_IP4_CONFIG_SETTING_NAME,
	  NM_SETTING_IP_CONFIG_DNS,
	  FALSE,
	  ip4_dns_parser },
	{ NM_SETTING_IP6_CONFIG_SETTING_NAME,
	  NM_SETTING_IP_CONFIG_DNS,
	  FALSE,
	  ip6_dns_parser },
	{ NM_SETTING_IP6_CONFIG_SETTING_NAME,
	  NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE,
	  FALSE,
	  ip6_addr_gen_mode_parser },
	{ NM_SETTING_WIRED_SETTING_NAME,
	  NM_SETTING_WIRED_MAC_ADDRESS,
	  TRUE,
	  mac_address_parser_ETHER },
	{ NM_SETTING_WIRED_SETTING_NAME,
	  NM_SETTING_WIRED_CLONED_MAC_ADDRESS,
	  TRUE,
	  mac_address_parser_ETHER_cloned },
	{ NM_SETTING_WIRELESS_SETTING_NAME,
	  NM_SETTING_WIRELESS_MAC_ADDRESS,
	  TRUE,
	  mac_address_parser_ETHER },
	{ NM_SETTING_WIRELESS_SETTING_NAME,
	  NM_SETTING_WIRELESS_CLONED_MAC_ADDRESS,
	  TRUE,
	  mac_address_parser_ETHER_cloned },
	{ NM_SETTING_WIRELESS_SETTING_NAME,
	  NM_SETTING_WIRELESS_BSSID,
	  TRUE,
	  mac_address_parser_ETHER },
	{ NM_SETTING_BLUETOOTH_SETTING_NAME,
	  NM_SETTING_BLUETOOTH_BDADDR,
	  TRUE,
	  mac_address_parser_ETHER },
	{ NM_SETTING_INFINIBAND_SETTING_NAME,
	  NM_SETTING_INFINIBAND_MAC_ADDRESS,
	  TRUE,
	  mac_address_parser_INFINIBAND },
	{ NM_SETTING_WIMAX_SETTING_NAME,
	  NM_SETTING_WIMAX_MAC_ADDRESS,
	  TRUE,
	  mac_address_parser_ETHER },
	{ NM_SETTING_WIRELESS_SETTING_NAME,
	  NM_SETTING_WIRELESS_SSID,
	  TRUE,
	  ssid_parser },
	{ NM_SETTING_802_1X_SETTING_NAME,
	  NM_SETTING_802_1X_PASSWORD_RAW,
	  TRUE,
	  password_raw_parser },
	{ NM_SETTING_802_1X_SETTING_NAME,
	  NM_SETTING_802_1X_CA_CERT,
	  TRUE,
	  cert_parser },
	{ NM_SETTING_802_1X_SETTING_NAME,
	  NM_SETTING_802_1X_CLIENT_CERT,
	  TRUE,
	  cert_parser },
	{ NM_SETTING_802_1X_SETTING_NAME,
	  NM_SETTING_802_1X_PRIVATE_KEY,
	  TRUE,
	  cert_parser },
	{ NM_SETTING_802_1X_SETTING_NAME,
	  NM_SETTING_802_1X_PHASE2_CA_CERT,
	  TRUE,
	  cert_parser },
	{ NM_SETTING_802_1X_SETTING_NAME,
	  NM_SETTING_802_1X_PHASE2_CLIENT_CERT,
	  TRUE,
	  cert_parser },
	{ NM_SETTING_802_1X_SETTING_NAME,
	  NM_SETTING_802_1X_PHASE2_PRIVATE_KEY,
	  TRUE,
	  cert_parser },
	{ NM_SETTING_SERIAL_SETTING_NAME,
	  NM_SETTING_SERIAL_PARITY,
	  TRUE,
	  parity_parser },
	{ NM_SETTING_TEAM_SETTING_NAME,
	  NM_SETTING_TEAM_CONFIG,
	  TRUE,
	  team_config_parser },
	{ NM_SETTING_TEAM_PORT_SETTING_NAME,
	  NM_SETTING_TEAM_CONFIG,
	  TRUE,
	  team_config_parser },
        { NM_SETTING_TC_CONFIG_SETTING_NAME,
          NM_SETTING_TC_CONFIG_QDISCS,
	  FALSE,
          qdisc_parser },
        { NM_SETTING_TC_CONFIG_SETTING_NAME,
          NM_SETTING_TC_CONFIG_TFILTERS,
	  FALSE,
          tfilter_parser },
	{ NULL, NULL, FALSE }
};

static void
set_default_for_missing_key (NMSetting *setting, const char *property)
{
	/* Set a value different from the default value of the property's spec */
}

static void
read_one_setting_value (NMSetting *setting,
                        const char *key,
                        const GValue *value,
                        GParamFlags flags,
                        gpointer user_data)
{
	KeyfileReaderInfo *info = user_data;
	GKeyFile *keyfile = info->keyfile;
	const char *setting_name;
	int errsv;
	GType type;
	gs_free_error GError *err = NULL;
	gboolean check_for_key = TRUE;
	KeyParser *parser = &key_parsers[0];

	if (info->error)
		return;

	/* Property is not writable */
	if (!(flags & G_PARAM_WRITABLE))
		return;

	/* Setting name gets picked up from the keyfile's section name instead */
	if (!strcmp (key, NM_SETTING_NAME))
		return;

	/* Don't read the NMSettingConnection object's 'read-only' property */
	if (   NM_IS_SETTING_CONNECTION (setting)
	    && !strcmp (key, NM_SETTING_CONNECTION_READ_ONLY))
		return;

	if (   (   NM_IS_SETTING_TEAM (setting)
	        || NM_IS_SETTING_TEAM_PORT (setting))
	    && !NM_IN_STRSET (key, NM_SETTING_TEAM_CONFIG)) {
		/* silently ignore all team properties (except "config"). */
		return;
	}

	setting_name = nm_setting_get_name (setting);

	/* Look through the list of handlers for non-standard format key values */
	while (parser->setting_name) {
		if (!strcmp (parser->setting_name, setting_name) && !strcmp (parser->key, key)) {
			check_for_key = parser->check_for_key;
			break;
		}
		parser++;
	}

	if (NM_IS_SETTING_VPN (setting))
		check_for_key = FALSE;
	else if (NM_IS_SETTING_USER (setting))
		check_for_key = FALSE;
	else if (NM_IS_SETTING_BOND (setting))
		check_for_key = FALSE;

	/* Check for the exact key in the GKeyFile if required.  Most setting
	 * properties map 1:1 to a key in the GKeyFile, but for those properties
	 * like IP addresses and routes where more than one value is actually
	 * encoded by the setting property, this won't be true.
	 */
	if (check_for_key && !nm_keyfile_plugin_kf_has_key (keyfile, setting_name, key, &err)) {
		/* Key doesn't exist or an error ocurred, thus nothing to do. */
		if (err) {
			if (!handle_warn (info, key, NM_KEYFILE_WARN_SEVERITY_WARN,
			                  _("error loading setting value: %s"),
			                  err->message))
				goto out_error;
		}

		/* Allow default values different than in property spec */
		set_default_for_missing_key (setting, key);
		return;
	}

	/* If there's a custom parser for this key, handle that before the generic
	 * parsers below.
	 */
	if (parser->setting_name) {
		(*parser->parser) (info, setting, key);
		return;
	}

	type = G_VALUE_TYPE (value);

	if (type == G_TYPE_STRING) {
		char *str_val;

		str_val = nm_keyfile_plugin_kf_get_string (keyfile, setting_name, key, NULL);
		g_object_set (setting, key, str_val, NULL);
		g_free (str_val);
	} else if (type == G_TYPE_UINT) {
		int int_val;

		int_val = nm_keyfile_plugin_kf_get_integer (keyfile, setting_name, key, NULL);
		if (int_val < 0) {
			if (!handle_warn (info, key, NM_KEYFILE_WARN_SEVERITY_WARN,
			                  _("invalid negative value (%i)"),
			                  int_val))
				goto out_error;
		}
		g_object_set (setting, key, int_val, NULL);
	} else if (type == G_TYPE_INT) {
		int int_val;

		int_val = nm_keyfile_plugin_kf_get_integer (keyfile, setting_name, key, NULL);
		g_object_set (setting, key, int_val, NULL);
	} else if (type == G_TYPE_BOOLEAN) {
		gboolean bool_val;

		bool_val = nm_keyfile_plugin_kf_get_boolean (keyfile, setting_name, key, NULL);
		g_object_set (setting, key, bool_val, NULL);
	} else if (type == G_TYPE_CHAR) {
		int int_val;

		int_val = nm_keyfile_plugin_kf_get_integer (keyfile, setting_name, key, NULL);
		if (int_val < G_MININT8 || int_val > G_MAXINT8) {
			if (!handle_warn (info, key, NM_KEYFILE_WARN_SEVERITY_WARN,
			                  _("invalid char value (%i)"),
			                  int_val))
				goto out_error;
		}

		g_object_set (setting, key, int_val, NULL);
	} else if (type == G_TYPE_UINT64) {
		char *tmp_str;
		guint64 uint_val;

		tmp_str = nm_keyfile_plugin_kf_get_value (keyfile, setting_name, key, NULL);
		uint_val = g_ascii_strtoull (tmp_str, NULL, 10);
		g_free (tmp_str);
		g_object_set (setting, key, uint_val, NULL);
	} else if (type == G_TYPE_INT64) {
		gs_free char *tmp_str = NULL;
		gint64 int_val;

		tmp_str = nm_keyfile_plugin_kf_get_value (keyfile, setting_name, key, NULL);
		int_val = _nm_utils_ascii_str_to_int64 (tmp_str, 10, G_MININT64, G_MAXINT64, 0);
		errsv = errno;
		if (errsv) {
			if (!handle_warn (info, key, NM_KEYFILE_WARN_SEVERITY_WARN,
			                  _("invalid int64 value (%s)"),
			                  tmp_str))
				goto out_error;
		} else
			g_object_set (setting, key, int_val, NULL);
	} else if (type == G_TYPE_BYTES) {
		gint *tmp;
		GByteArray *array;
		GBytes *bytes;
		gsize length;
		int i;
		gboolean already_warned = FALSE;

		tmp = nm_keyfile_plugin_kf_get_integer_list (keyfile, setting_name, key, &length, NULL);

		array = g_byte_array_sized_new (length);
		for (i = 0; i < length; i++) {
			int val = tmp[i];
			unsigned char v = (unsigned char) (val & 0xFF);

			if (val < 0 || val > 255) {
				if (   !already_warned
				    && !handle_warn (info, key, NM_KEYFILE_WARN_SEVERITY_WARN,
				                     _("ignoring invalid byte element '%d' (not between 0 and 255 inclusive)"),
				                     val)) {
					g_byte_array_unref (array);
					g_free (tmp);
					goto out_error;
				}
				already_warned = TRUE;
			} else
				g_byte_array_append (array, (const unsigned char *) &v, sizeof (v));
		}

		bytes = g_byte_array_free_to_bytes (array);
		g_object_set (setting, key, bytes, NULL);
		g_bytes_unref (bytes);
		g_free (tmp);
	} else if (type == G_TYPE_STRV) {
		gchar **sa;
		gsize length;

		sa = nm_keyfile_plugin_kf_get_string_list (keyfile, setting_name, key, &length, NULL);
		g_object_set (setting, key, sa, NULL);
		g_strfreev (sa);
	} else if (type == G_TYPE_HASH_TABLE) {
		read_hash_of_string (keyfile, setting, key);
	} else if (type == G_TYPE_ARRAY) {
		read_array_of_uint (keyfile, setting, key);
	} else if (G_VALUE_HOLDS_FLAGS (value)) {
		guint64 uint_val;

		/* Flags are guint but GKeyFile has no uint reader, just uint64 */
		uint_val = nm_keyfile_plugin_kf_get_uint64 (keyfile, setting_name, key, &err);
		if (!err) {
			if (uint_val <= G_MAXUINT)
				g_object_set (setting, key, (guint) uint_val, NULL);
			else {
				if (!handle_warn (info, key, NM_KEYFILE_WARN_SEVERITY_WARN,
				                  _("too large FLAGS property '%s' (%llu)"),
				                  G_VALUE_TYPE_NAME (value), (unsigned long long) uint_val))
					goto out_error;
			}
		}
	} else if (G_VALUE_HOLDS_ENUM (value)) {
		gint int_val;

		int_val = nm_keyfile_plugin_kf_get_integer (keyfile, setting_name, key, &err);
		if (!err)
			g_object_set (setting, key, (gint) int_val, NULL);
	} else {
		if (!handle_warn (info, key, NM_KEYFILE_WARN_SEVERITY_WARN,
		                 _("unhandled setting property type '%s'"),
		                 G_VALUE_TYPE_NAME (value)))
			goto out_error;
	}
out_error:
	return;
}

static NMSetting *
read_setting (KeyfileReaderInfo *info)
{
	const char *alias;
	GType type;

	alias = nm_keyfile_plugin_get_setting_name_for_alias (info->group);
	if (!alias)
		alias = info->group;

	type = nm_setting_lookup_type (alias);
	if (type) {
		NMSetting *setting = g_object_new (type, NULL);

		info->setting = setting;
		nm_setting_enumerate_values (setting, read_one_setting_value, info);
		info->setting = NULL;
		if (!info->error)
			return setting;

		g_object_unref (setting);
	} else {
		handle_warn (info, NULL, NM_KEYFILE_WARN_SEVERITY_WARN,
		             _("invalid setting name '%s'"), info->group);
	}

	return NULL;
}

static void
read_vpn_secrets (KeyfileReaderInfo *info, NMSettingVpn *s_vpn)
{
	char **keys, **iter;

	keys = nm_keyfile_plugin_kf_get_keys (info->keyfile, NM_KEYFILE_GROUP_VPN_SECRETS, NULL, NULL);
	for (iter = keys; *iter; iter++) {
		char *secret;

		secret = nm_keyfile_plugin_kf_get_string (info->keyfile, NM_KEYFILE_GROUP_VPN_SECRETS, *iter, NULL);
		if (secret) {
			nm_setting_vpn_add_secret (s_vpn, *iter, secret);
			g_free (secret);
		}
	}
	g_strfreev (keys);
}

/**
 * nm_keyfile_read:
 * @keyfile: the keyfile from which to create the connection
 * @keyfile_name: keyfile allows missing connection id and uuid
 *   and NetworkManager will create those when reading a connection
 *   from file. By providing a filename you can reproduce that behavior,
 *   but of course, it can only recreate the same UUID if you provide the
 *   same filename as NetworkManager core daemon would.
 *   @keyfile_name has only a relevance for setting the id or uuid if it
 *   is missing and as fallback for @base_dir.
 * @base_dir: when reading certificates from files with relative name,
 *   the relative path is made absolute using @base_dir.
 *   If @base_dir is missing, first try to get the pathname from @keyfile_name
 *   (if it is given as absolute path). As last, fallback to the current path.
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
                 const char *keyfile_name,
                 const char *base_dir,
                 NMKeyfileReadHandler handler,
                 void *user_data,
                 GError **error)
{
	NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	NMSetting *setting;
	gchar **groups;
	gsize length;
	int i;
	gboolean vpn_secrets = FALSE;
	KeyfileReaderInfo info = { 0 };
	gs_free char *base_dir_free = NULL;

	g_return_val_if_fail (keyfile, NULL);
	g_return_val_if_fail (!error || !*error, NULL);

	if (!base_dir) {
		/* basedir is not given. Prefer it from the keyfile_name */
		if (keyfile_name && keyfile_name[0] == '/') {
			base_dir = base_dir_free = g_path_get_dirname (keyfile_name);
		} else {
			/* if keyfile is not given or not an absolute path, fallback
			 * to current working directory. */
			base_dir = base_dir_free = g_get_current_dir ();
		}
	} else
		g_return_val_if_fail ("/", NULL);

	connection = nm_simple_connection_new ();

	info.connection = connection;
	info.keyfile = (GKeyFile *) keyfile;
	info.base_dir = base_dir;
	info.handler = handler;
	info.user_data = user_data;

	groups = g_key_file_get_groups (keyfile, &length);
	if (!groups)
		length = 0;
	for (i = 0; i < length; i++) {
		/* Only read out secrets when needed */
		if (!strcmp (groups[i], NM_KEYFILE_GROUP_VPN_SECRETS)) {
			vpn_secrets = TRUE;
			continue;
		}

		info.group = groups[i];
		setting = read_setting (&info);
		info.group = NULL;
		if (info.error)
			goto out_error;
		if (setting)
			nm_connection_add_setting (connection, setting);
	}
	g_strfreev (groups);

	s_con = nm_connection_get_setting_connection (connection);
	if (!s_con) {
		s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());
		nm_connection_add_setting (connection, NM_SETTING (s_con));
	}

	/* Make sure that we have 'id' even if not explictly specified in the keyfile */
	if (   keyfile_name
	    && !nm_setting_connection_get_id (s_con)) {
		char *base_name;

		base_name = g_path_get_basename (keyfile_name);
		g_object_set (s_con, NM_SETTING_CONNECTION_ID, base_name, NULL);
		g_free (base_name);
	}

	/* Make sure that we have 'uuid' even if not explictly specified in the keyfile */
	if (   keyfile_name
	    && !nm_setting_connection_get_uuid (s_con)) {
		char *hashed_uuid;

		hashed_uuid = _nm_utils_uuid_generate_from_strings ("keyfile", keyfile_name, NULL);
		g_object_set (s_con, NM_SETTING_CONNECTION_UUID, hashed_uuid, NULL);
		g_free (hashed_uuid);
	}

	/* Make sure that we have 'interface-name' even if it was specified in the
	 * "wrong" (ie, deprecated) group.
	 */
	if (   !nm_setting_connection_get_interface_name (s_con)
	    && nm_setting_connection_get_connection_type (s_con)) {
		char *interface_name;

		interface_name = g_key_file_get_string (keyfile,
		                                        nm_setting_connection_get_connection_type (s_con),
		                                        "interface-name",
		                                        NULL);
		if (interface_name) {
			g_object_set (s_con, NM_SETTING_CONNECTION_INTERFACE_NAME, interface_name, NULL);
			g_free (interface_name);
		}
	}

	/* Handle vpn secrets after the 'vpn' setting was read */
	if (vpn_secrets) {
		NMSettingVpn *s_vpn;

		s_vpn = nm_connection_get_setting_vpn (connection);
		if (s_vpn) {
			read_vpn_secrets (&info, s_vpn);
			if (info.error)
				goto out_error;
		}
	}

	return connection;
out_error:
	g_propagate_error (error, info.error);
	g_free (connection);
	return NULL;
}
