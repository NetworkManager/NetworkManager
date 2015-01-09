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
 * Copyright (C) 2008 - 2011 Red Hat, Inc.
 */

#include "config.h"

#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <string.h>

#include "nm-core-internal.h"
#include "nm-dbus-glib-types.h"
#include "nm-glib-compat.h"
#include "nm-system-config-interface.h"
#include "nm-logging.h"
#include "reader.h"
#include "common.h"
#include "utils.h"
#include "nm-core-internal.h"
#include "NetworkManagerUtils.h"

/* Some setting properties also contain setting names, such as
 * NMSettingConnection's 'type' property (which specifies the base type of the
 * connection, e.g. ethernet or wifi) or 'slave-type' (specifies type of slave
 * connection, e.g. bond or bridge). This function handles translating those
 * properties' values to the real setting name if they are an alias.
 */
static void
setting_alias_parser (NMSetting *setting, const char *key, GKeyFile *keyfile, const char *keyfile_path)
{
	const char *setting_name = nm_setting_get_name (setting);
	char *s;
	const char *key_setting_name;

	s = nm_keyfile_plugin_kf_get_string (keyfile, setting_name, key, NULL);
	if (s) {
		key_setting_name = nm_keyfile_plugin_get_setting_name_for_alias (s);
		g_object_set (G_OBJECT (setting),
		              key, key_setting_name ? key_setting_name : s,
		              NULL);
		g_free (s);
	}
}

static gboolean
read_array_of_uint (GKeyFile *file,
                    NMSetting *setting,
                    const char *key)
{
	GArray *array = NULL;
	gsize length;
	int i;
	gint *tmp;

	tmp = nm_keyfile_plugin_kf_get_integer_list (file, nm_setting_get_name (setting), key, &length, NULL);
	array = g_array_sized_new (FALSE, FALSE, sizeof (guint32), length);
	g_return_val_if_fail (array != NULL, FALSE);

	for (i = 0; i < length; i++)
		g_array_append_val (array, tmp[i]);

	g_object_set (setting, key, array, NULL);
	g_array_unref (array);

	return TRUE;
}

static gboolean
get_one_int (const char *str, guint32 max_val, const char *key_name, guint32 *out)
{
	long tmp;
	char *endptr;

	if (!str || !str[0]) {
		if (key_name)
			nm_log_warn (LOGD_SETTINGS, "%s: ignoring missing number %s", __func__, key_name);
		return FALSE;
	}

	errno = 0;
	tmp = strtol (str, &endptr, 10);
	if (errno || (tmp < 0) || (tmp > max_val) || *endptr != 0) {
		if (key_name)
			nm_log_warn (LOGD_SETTINGS, "%s: ignoring invalid number %s '%s'", __func__, key_name, str);
		return FALSE;
	}

	*out = (guint32) tmp;
	return TRUE;
}

static gpointer
build_address (int family, const char *address_str, guint32 plen)
{
	NMIPAddress *addr;
	GError *error = NULL;

	g_return_val_if_fail (address_str, NULL);

	addr = nm_ip_address_new (family, address_str, plen, &error);
	if (!addr) {
		nm_log_warn (LOGD_SETTINGS, "%s: ignoring invalid %s address: %s", __func__,
		             family == AF_INET ? "IPv4" : "IPv6",
		             error->message);
		g_error_free (error);
	}

	return addr;
}

static gpointer
build_route (int family,
             const char *dest_str, guint32 plen,
             const char *gateway_str, const char *metric_str,
             const char *key_name)
{
	NMIPRoute *route;
	guint32 metric = 0;
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
			    && get_one_int (gateway_str, G_MAXUINT32, NULL, &metric))
				gateway_str = NULL;
			else {
				nm_log_warn (LOGD_SETTINGS, "%s: ignoring invalid gateway '%s'", __func__, gateway_str);
				return NULL;
			}
		}
	} else
		gateway_str = NULL;

	/* parse metric, default to 0 */
	if (metric_str) {
		if (!get_one_int (metric_str, G_MAXUINT32, key_name, &metric))
			return NULL;
	}

	route = nm_ip_route_new (family, dest_str, plen, gateway_str,
	                         metric ? (gint64) metric : -1,
	                         &error);
	if (!route) {
		nm_log_warn (LOGD_SETTINGS, "%s: ignoring invalid %s route: %s", __func__,
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
static char *
read_field (char **current, char **error, const char *characters, const char *delimiters)
{
	char *start;

	g_return_val_if_fail (current, NULL);
	g_return_val_if_fail (error, NULL);
	g_return_val_if_fail (characters, NULL);
	g_return_val_if_fail (delimiters, NULL);

	*error = NULL;

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
			*error = *current;
			*current = start;
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
read_one_ip_address_or_route (GKeyFile *file,
                              const char *setting_name,
                              const char *key_name,
                              gboolean ipv6,
                              gboolean route,
                              char **out_gateway)
{
	guint32 plen = G_MAXUINT32;
	gpointer result;
	char *address_str, *plen_str, *gateway_str, *metric_str, *value, *current, *error;

	current = value = nm_keyfile_plugin_kf_get_string (file, setting_name, key_name, NULL);
	if (!value)
		return NULL;

	/* get address field */
	address_str = read_field (&current, &error, IP_ADDRESS_CHARS, DELIMITERS);
	if (error) {
		nm_log_warn (LOGD_SETTINGS, "keyfile: Unexpected character '%c' in '%s.%s' address (position %td of '%s').",
		             *error, setting_name, key_name, error - current, current);
		goto error;
	}
	/* get prefix length field (skippable) */
	plen_str = read_field (&current, &error, DIGITS, DELIMITERS);
	/* get gateway field */
	gateway_str = read_field (&current, &error, IP_ADDRESS_CHARS, DELIMITERS);
	if (error) {
		nm_log_warn (LOGD_SETTINGS, "keyfile: Unexpected character '%c' in '%s.%s' %s (position %td of '%s').",
		             *error, setting_name, key_name,
		             plen_str ? "gateway" : "gateway or prefix length",
		             error - current, current);
		goto error;
	}
	/* for routes, get metric */
	if (route) {
		metric_str = read_field (&current, &error, DIGITS, DELIMITERS);
		if (error) {
			nm_log_warn (LOGD_SETTINGS, "keyfile: Unexpected character '%c' in '%s.%s' prefix length (position %td of '%s').",
			             *error, setting_name, key_name, error - current, current);
			goto error;
		}
	} else
		metric_str = NULL;
	if (current) {
		/* there is still some data */
		if (*current) {
			/* another field follows */
			nm_log_warn (LOGD_SETTINGS, "keyfile: %s.%s: Garbage at the and of the line: %s",
			             setting_name, key_name, current);
			goto error;
		} else {
			/* semicolon at the end of input */
			nm_log_info (LOGD_SETTINGS, "keyfile: %s.%s: Deprecated semicolon at the end of value.",
			             setting_name, key_name);
		}
	}

#define DEFAULT_PREFIX(for_route, for_ipv6) ( (for_route) ? ( (for_ipv6) ? 128 : 24 ) : ( (for_ipv6) ? 64 : 24 ) )

	/* parse plen, fallback to defaults */
	if (plen_str) {
		if (!get_one_int (plen_str, ipv6 ? 128 : 32, key_name, &plen)
		    || (route && plen == 0)) {
			plen = DEFAULT_PREFIX (route, ipv6);
			nm_log_warn (LOGD_SETTINGS, "keyfile: invalid prefix length '%s' in '%s.%s', defaulting to %d",
			             plen_str, setting_name, key_name, plen);
		}
	} else {
		plen = DEFAULT_PREFIX (route, ipv6);
		nm_log_warn (LOGD_SETTINGS, "keyfile: Missing prefix length in '%s.%s', defaulting to %d",
		             setting_name, key_name, plen);
	}

	/* build the appropriate data structure for NetworkManager settings */
	if (route) {
		result = build_route (ipv6 ? AF_INET6 : AF_INET,
		                      address_str, plen, gateway_str, metric_str,
		                      key_name);
	} else {
		result = build_address (ipv6 ? AF_INET6 : AF_INET,
		                        address_str, plen);
		if (out_gateway && gateway_str)
			*out_gateway = g_strdup (gateway_str);
	}

	g_free (value);
	return result;
error:
	g_free (value);
	return NULL;
}

static void
ip_address_or_route_parser (NMSetting *setting, const char *key, GKeyFile *keyfile, const char *keyfile_path)
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

			/* -1 means no suffix */
			if (i >= 0)
				key_name = g_strdup_printf ("%s%d", *key_basename, i);
			else
				key_name = g_strdup (*key_basename);

			item = read_one_ip_address_or_route (keyfile, setting_name, key_name, ipv6, routes,
			                                     gateway ? NULL : &gateway);
			if (item)
				g_ptr_array_add (list, item);

			g_free (key_name);
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
ip4_dns_parser (NMSetting *setting, const char *key, GKeyFile *keyfile, const char *keyfile_path)
{
	const char *setting_name = nm_setting_get_name (setting);
	GPtrArray *array;
	gsize length;
	char **list, **iter;
	int ret;

	list = nm_keyfile_plugin_kf_get_string_list (keyfile, setting_name, key, &length, NULL);
	if (!list || !g_strv_length (list))
		return;

	array = g_ptr_array_sized_new (length + 1);
	for (iter = list; *iter; iter++) {
		guint32 addr;

		ret = inet_pton (AF_INET, *iter, &addr);
		if (ret <= 0) {
			nm_log_warn (LOGD_SETTINGS, "%s: ignoring invalid DNS server address '%s'", __func__, *iter);
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
ip6_dns_parser (NMSetting *setting, const char *key, GKeyFile *keyfile, const char *keyfile_path)
{
	const char *setting_name = nm_setting_get_name (setting);
	GPtrArray *array = NULL;
	gsize length;
	char **list, **iter;
	int ret;

	list = nm_keyfile_plugin_kf_get_string_list (keyfile, setting_name, key, &length, NULL);
	if (!list || !g_strv_length (list))
		return;

	array = g_ptr_array_sized_new (length + 1);

	for (iter = list; *iter; iter++) {
		struct in6_addr addr;

		ret = inet_pton (AF_INET6, *iter, &addr);
		if (ret <= 0) {
			nm_log_warn (LOGD_SETTINGS, "%s: ignoring invalid DNS server IPv6 address '%s'", __func__, *iter);
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
mac_address_parser (NMSetting *setting, const char *key, GKeyFile *keyfile, const char *keyfile_path, gsize enforce_length)
{
	const char *setting_name = nm_setting_get_name (setting);
	char *tmp_string = NULL, *p, *mac_str;
	gint *tmp_list;
	GByteArray *array = NULL;
	gsize length;

	p = tmp_string = nm_keyfile_plugin_kf_get_string (keyfile, setting_name, key, NULL);
	if (tmp_string && tmp_string[0]) {
		/* Look for enough ':' characters to signify a MAC address */
		guint i = 0;

		while (*p) {
			if (*p == ':')
				i++;
			p++;
		}

		if (enforce_length == 0 || enforce_length == i+1) {
			/* If we found enough it's probably a string-format MAC address */
			array = g_byte_array_sized_new (i+1);
			g_byte_array_set_size (array, i+1);
			if (!nm_utils_hwaddr_aton (tmp_string, array->data, array->len)) {
				g_byte_array_unref (array);
				array = NULL;
			}
		}
	}
	g_free (tmp_string);

	if (array == NULL) {
		/* Old format; list of ints */
		tmp_list = nm_keyfile_plugin_kf_get_integer_list (keyfile, setting_name, key, &length, NULL);
		if (length > 0 && (enforce_length == 0 || enforce_length == length)) {
			gsize i;

			array = g_byte_array_sized_new (length);
			for (i = 0; i < length; i++) {
				int val = tmp_list[i];
				const guint8 v = (guint8) (val & 0xFF);

				if (val < 0 || val > 255) {
					nm_log_warn (LOGD_SETTINGS, "%s: %s / %s ignoring invalid byte element '%d' (not "
					             " between 0 and 255 inclusive)", __func__, setting_name,
					             key, val);
					g_byte_array_free (array, TRUE);
					array = NULL;
					break;
				}
				g_byte_array_append (array, &v, 1);
			}
		}
		g_free (tmp_list);
	}

	if (!array) {
		nm_log_warn (LOGD_SETTINGS, "%s: ignoring invalid MAC address for %s / %s",
		             __func__, setting_name, key);
		return;
	}

	mac_str = nm_utils_hwaddr_ntoa (array->data, array->len);
	g_object_set (setting, key, mac_str, NULL);
	g_free (mac_str);
	g_byte_array_free (array, TRUE);
}

static void
mac_address_parser_ETHER (NMSetting *setting, const char *key, GKeyFile *keyfile, const char *keyfile_path)
{
	mac_address_parser (setting, key, keyfile, keyfile_path, ETH_ALEN);
}

static void
mac_address_parser_INFINIBAND (NMSetting *setting, const char *key, GKeyFile *keyfile, const char *keyfile_path)
{
	mac_address_parser (setting, key, keyfile, keyfile_path, INFINIBAND_ALEN);
}

static void
read_hash_of_string (GKeyFile *file, NMSetting *setting, const char *key)
{
	char **keys, **iter;
	char *value;
	const char *setting_name = nm_setting_get_name (setting);

	keys = nm_keyfile_plugin_kf_get_keys (file, setting_name, NULL, NULL);
	if (!keys || !*keys)
		return;

	for (iter = keys; *iter; iter++) {
		value = nm_keyfile_plugin_kf_get_string (file, setting_name, *iter, NULL);
		if (!value)
			continue;

		if (NM_IS_SETTING_VPN (setting)) {
			/* Add any item that's not a class property to the data hash */
			if (!g_object_class_find_property (G_OBJECT_GET_CLASS (setting), *iter))
				nm_setting_vpn_add_data_item (NM_SETTING_VPN (setting), *iter, value);
		}
		if (NM_IS_SETTING_BOND (setting)) {
			if (strcmp (*iter, "interface-name"))
				nm_setting_bond_add_option (NM_SETTING_BOND (setting), *iter, value);
		}
		g_free (value);
	}
	g_strfreev (keys);
}

static void
unescape_semicolons (char *str)
{
	int i;
	gsize len = strlen (str);

	for (i = 0; i < len; i++) {
		if (str[i] == '\\' && str[i+1] == ';') {
			memmove(str + i, str + i + 1, len - (i + 1));
			len--;
		}
		str[len] = '\0';
	}
}

static GBytes *
get_bytes (GKeyFile *keyfile,
           const char *setting_name,
           const char *key,
           gboolean zero_terminate,
           gboolean unescape_semicolon)
{
	GByteArray *array = NULL;
	char *tmp_string;
	gint *tmp_list;
	gsize length;
	int i;

	/* New format: just a string
	 * Old format: integer list; e.g. 11;25;38;
	 */
	tmp_string = nm_keyfile_plugin_kf_get_string (keyfile, setting_name, key, NULL);
	if (tmp_string) {
		GRegex *regex;
		GMatchInfo *match_info;
		const char *pattern = "^[[:space:]]*[[:digit:]]{1,3}[[:space:]]*;([[:space:]]*[[:digit:]]{1,3}[[:space:]]*;)*([[:space:]]*)?$";

		regex = g_regex_new (pattern, 0, 0, NULL);
		g_regex_match (regex, tmp_string, 0, &match_info);
		if (!g_match_info_matches (match_info)) {
			/* Handle as a simple string (ie, new format) */
			if (unescape_semicolon)
				unescape_semicolons (tmp_string);
			length = strlen (tmp_string);
			if (zero_terminate)
				length++;
			array = g_byte_array_sized_new (length);
			g_byte_array_append (array, (guint8 *) tmp_string, length);
		}
		g_match_info_free (match_info);
		g_regex_unref (regex);
		g_free (tmp_string);
	}

	if (!array) {
		/* Old format; list of ints */
		tmp_list = nm_keyfile_plugin_kf_get_integer_list (keyfile, setting_name, key, &length, NULL);
		array = g_byte_array_sized_new (length);
		for (i = 0; i < length; i++) {
			int val = tmp_list[i];
			unsigned char v = (unsigned char) (val & 0xFF);

			if (val < 0 || val > 255) {
				nm_log_warn (LOGD_SETTINGS, "%s: %s / %s ignoring invalid byte element '%d' (not "
				             " between 0 and 255 inclusive)", __func__, setting_name,
				             key, val);
			} else
				g_byte_array_append (array, (const unsigned char *) &v, sizeof (v));
		}
		g_free (tmp_list);
	}

	if (array->len == 0) {
		g_byte_array_free (array, TRUE);
		return NULL;
	} else
		return g_byte_array_free_to_bytes (array);
}

static void
ssid_parser (NMSetting *setting, const char *key, GKeyFile *keyfile, const char *keyfile_path)
{
	const char *setting_name = nm_setting_get_name (setting);
	GBytes *bytes;

	bytes = get_bytes (keyfile, setting_name, key, FALSE, TRUE);
	if (bytes) {
		g_object_set (setting, key, bytes, NULL);
		g_bytes_unref (bytes);
	} else {
		nm_log_warn (LOGD_SETTINGS, "%s: ignoring invalid SSID for %s / %s",
		             __func__, setting_name, key);
	}
}

static void
password_raw_parser (NMSetting *setting, const char *key, GKeyFile *keyfile, const char *keyfile_path)
{
	const char *setting_name = nm_setting_get_name (setting);
	GBytes *bytes;

	bytes = get_bytes (keyfile, setting_name, key, FALSE, TRUE);
	if (bytes) {
		g_object_set (setting, key, bytes, NULL);
		g_bytes_unref (bytes);
	} else {
		nm_log_warn (LOGD_SETTINGS, "%s: ignoring invalid raw password for %s / %s",
		             __func__, setting_name, key);
	}
}

static char *
get_cert_path (const char *keyfile_path, const guint8 *cert_path, gsize cert_path_len)
{
	const char *base;
	char *p = NULL, *path, *dirname, *tmp;

	g_return_val_if_fail (keyfile_path != NULL, NULL);
	g_return_val_if_fail (cert_path != NULL, NULL);

	base = path = g_malloc0 (cert_path_len + 1);
	memcpy (path, cert_path, cert_path_len);

	if (path[0] == '/')
		return path;

	p = strrchr (path, '/');
	if (p)
		base = p + 1;

	dirname = g_path_get_dirname (keyfile_path);
	tmp = g_build_path ("/", dirname, base, NULL);
	g_free (dirname);
	g_free (path);
	return tmp;
}

#define SCHEME_PATH "file://"

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
handle_as_scheme (GBytes *bytes, NMSetting *setting, const char *key)
{
	const guint8 *data;
	gsize data_len;

	data = g_bytes_get_data (bytes, &data_len);

	/* It's the PATH scheme, can just set plain data */
	if (   (data_len > strlen (SCHEME_PATH))
	    && g_str_has_prefix ((const char *) data, SCHEME_PATH)
	    && (data[data_len - 1] == '\0')) {
		g_object_set (setting, key, bytes, NULL);
		return TRUE;
	}
	return FALSE;
}

static gboolean
handle_as_path (GBytes *bytes,
                NMSetting *setting,
                const char *key,
                const char *keyfile_path)
{
	const guint8 *data;
	gsize data_len;
	gsize validate_len;
	char *path;
	gboolean exists, success = FALSE;

	data = g_bytes_get_data (bytes, &data_len);
	if (data_len > 500 || data_len < 1)
		return FALSE;

	/* If there's a trailing NULL tell g_utf8_validate() to to until the NULL */
	if (data[data_len - 1] == '\0')
		validate_len = -1;
	else
		validate_len = data_len;

	if (g_utf8_validate ((const char *) data, validate_len, NULL) == FALSE)
		return FALSE;

	/* Might be a bare path without the file:// prefix; in that case
	 * if it's an absolute path, use that, otherwise treat it as a
	 * relative path to the current directory.
	 */

	path = get_cert_path (keyfile_path, data, data_len);
	exists = g_file_test (path, G_FILE_TEST_EXISTS);
	if (   exists
	    || memchr (data, '/', data_len)
	    || has_cert_ext (path)) {
		GByteArray *tmp;
		GBytes *val;

		/* Construct the proper value as required for the PATH scheme */
		tmp = g_byte_array_sized_new (strlen (SCHEME_PATH) + strlen (path) + 1);
		g_byte_array_append (tmp, (const guint8 *) SCHEME_PATH, strlen (SCHEME_PATH));
		g_byte_array_append (tmp, (const guint8 *) path, strlen (path));
		g_byte_array_append (tmp, (const guint8 *) "\0", 1);
		val = g_byte_array_free_to_bytes (tmp);
		g_object_set (setting, key, val, NULL);
		g_bytes_unref (val);
		success = TRUE;

		/* Warn if the certificate didn't exist */
		if (exists == FALSE)
			nm_log_warn (LOGD_SETTINGS, "certificate or key %s does not exist", path);
	}
	g_free (path);

	return success;
}

static void
cert_parser (NMSetting *setting, const char *key, GKeyFile *keyfile, const char *keyfile_path)
{
	const char *setting_name = nm_setting_get_name (setting);
	GBytes *bytes;
	gboolean success = FALSE;

	bytes = get_bytes (keyfile, setting_name, key, TRUE, FALSE);
	if (bytes) {
		/* Try as a path + scheme (ie, starts with "file://") */
		success = handle_as_scheme (bytes, setting, key);

		/* If not, it might be a plain path */
		if (success == FALSE)
			success = handle_as_path (bytes, setting, key, keyfile_path);

		/* If neither of those two, assume blob with certificate data */
		if (success == FALSE)
			g_object_set (setting, key, bytes, NULL);
	} else {
		nm_log_warn (LOGD_SETTINGS, "%s: ignoring invalid key/cert value for %s / %s",
		             __func__, setting_name, key);
	}

	if (bytes)
		g_bytes_unref (bytes);
}

static void
parity_parser (NMSetting *setting, const char *key, GKeyFile *keyfile, const char *keyfile_path)
{
	const char *setting_name = nm_setting_get_name (setting);
	NMSettingSerialParity parity;
	int int_val;
	char *str_val;

	/* Keyfile traditionally stored this as the ASCII value for 'E', 'o', or 'n'.
	 * We now accept either that or the (case-insensitive) character itself (but
	 * still always write it the old way, for backward compatibility).
	 */
	int_val = nm_keyfile_plugin_kf_get_integer (keyfile, setting_name, key, NULL);
	if (!int_val) {
		str_val = nm_keyfile_plugin_kf_get_string (keyfile, setting_name, key, NULL);
		if (str_val) {
			if (str_val[0] && !str_val[1])
				int_val = str_val[0];
			else {
				/* This will hit the warning below */
				int_val = 'X';
			}
		}
		g_free (str_val);
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
		nm_log_warn (LOGD_SETTINGS, "%s: ignoring invalid value for %s / %s",
		             __func__, setting_name, key);
		return;
	}

	g_object_set (setting, key, parity, NULL);
}

typedef struct {
	const char *setting_name;
	const char *key;
	gboolean check_for_key;
	void (*parser) (NMSetting *setting, const char *key, GKeyFile *keyfile, const char *keyfile_path);
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
	{ NM_SETTING_WIRED_SETTING_NAME,
	  NM_SETTING_WIRED_MAC_ADDRESS,
	  TRUE,
	  mac_address_parser_ETHER },
	{ NM_SETTING_WIRED_SETTING_NAME,
	  NM_SETTING_WIRED_CLONED_MAC_ADDRESS,
	  TRUE,
	  mac_address_parser_ETHER },
	{ NM_SETTING_WIRELESS_SETTING_NAME,
	  NM_SETTING_WIRELESS_MAC_ADDRESS,
	  TRUE,
	  mac_address_parser_ETHER },
	{ NM_SETTING_WIRELESS_SETTING_NAME,
	  NM_SETTING_WIRELESS_CLONED_MAC_ADDRESS,
	  TRUE,
	  mac_address_parser_ETHER },
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
	{ NULL, NULL, FALSE }
};

typedef struct {
	GKeyFile *keyfile;
	const char *keyfile_path;
} ReadInfo;

static void
read_one_setting_value (NMSetting *setting,
                        const char *key,
                        const GValue *value,
                        GParamFlags flags,
                        gpointer user_data)
{
	ReadInfo *info = user_data;
	const char *setting_name;
	int errsv;
	GType type;
	GError *err = NULL;
	gboolean check_for_key = TRUE;
	KeyParser *parser = &key_parsers[0];

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

	setting_name = nm_setting_get_name (setting);

	/* Look through the list of handlers for non-standard format key values */
	while (parser->setting_name) {
		if (!strcmp (parser->setting_name, setting_name) && !strcmp (parser->key, key)) {
			check_for_key = parser->check_for_key;
			break;
		}
		parser++;
	}

	/* VPN properties don't have the exact key name */
	if (NM_IS_SETTING_VPN (setting))
		check_for_key = FALSE;

	/* Bonding 'options' don't have the exact key name. The options are right under [bond] group. */
	if (NM_IS_SETTING_BOND (setting))
		check_for_key = FALSE;

	/* Check for the exact key in the GKeyFile if required.  Most setting
	 * properties map 1:1 to a key in the GKeyFile, but for those properties
	 * like IP addresses and routes where more than one value is actually
	 * encoded by the setting property, this won't be true.
	 */
	if (check_for_key && !nm_keyfile_plugin_kf_has_key (info->keyfile, setting_name, key, &err)) {
		/* Key doesn't exist or an error ocurred, thus nothing to do. */
		if (err) {
			nm_log_warn (LOGD_SETTINGS, "Error loading setting '%s' value: %s", setting_name, err->message);
			g_error_free (err);
		}
		return;
	}

	/* If there's a custom parser for this key, handle that before the generic
	 * parsers below.
	 */
	if (parser->setting_name) {
		(*parser->parser) (setting, key, info->keyfile, info->keyfile_path);
		return;
	}

	type = G_VALUE_TYPE (value);

	if (type == G_TYPE_STRING) {
		char *str_val;

		str_val = nm_keyfile_plugin_kf_get_string (info->keyfile, setting_name, key, NULL);
		g_object_set (setting, key, str_val, NULL);
		g_free (str_val);
	} else if (type == G_TYPE_UINT) {
		int int_val;

		int_val = nm_keyfile_plugin_kf_get_integer (info->keyfile, setting_name, key, NULL);
		if (int_val < 0)
			nm_log_warn (LOGD_SETTINGS, "Casting negative value (%i) to uint", int_val);
		g_object_set (setting, key, int_val, NULL);
	} else if (type == G_TYPE_INT) {
		int int_val;

		int_val = nm_keyfile_plugin_kf_get_integer (info->keyfile, setting_name, key, NULL);
		g_object_set (setting, key, int_val, NULL);
	} else if (type == G_TYPE_BOOLEAN) {
		gboolean bool_val;

		bool_val = nm_keyfile_plugin_kf_get_boolean (info->keyfile, setting_name, key, NULL);
		g_object_set (setting, key, bool_val, NULL);
	} else if (type == G_TYPE_CHAR) {
		int int_val;

		int_val = nm_keyfile_plugin_kf_get_integer (info->keyfile, setting_name, key, NULL);
		if (int_val < G_MININT8 || int_val > G_MAXINT8)
			nm_log_warn (LOGD_SETTINGS, "Casting value (%i) to char", int_val);

		g_object_set (setting, key, int_val, NULL);
	} else if (type == G_TYPE_UINT64) {
		char *tmp_str;
		guint64 uint_val;

		tmp_str = nm_keyfile_plugin_kf_get_value (info->keyfile, setting_name, key, NULL);
		uint_val = g_ascii_strtoull (tmp_str, NULL, 10);
		g_free (tmp_str);
		g_object_set (setting, key, uint_val, NULL);
	} else if (type == G_TYPE_INT64) {
		char *tmp_str;
		gint64 int_val;

		tmp_str = nm_keyfile_plugin_kf_get_value (info->keyfile, setting_name, key, NULL);
		int_val = _nm_utils_ascii_str_to_int64 (tmp_str, 10, G_MININT64, G_MAXINT64, 0);
		errsv = errno;
		if (errsv)
			nm_log_warn (LOGD_SETTINGS, "Invalid int64 value (%s)", tmp_str);
		else
			g_object_set (setting, key, int_val, NULL);
		g_free (tmp_str);
 	} else if (type == G_TYPE_BYTES) {
		gint *tmp;
		GByteArray *array;
		GBytes *bytes;
		gsize length;
		int i;

		tmp = nm_keyfile_plugin_kf_get_integer_list (info->keyfile, setting_name, key, &length, NULL);

		array = g_byte_array_sized_new (length);
		for (i = 0; i < length; i++) {
			int val = tmp[i];
			unsigned char v = (unsigned char) (val & 0xFF);

			if (val < 0 || val > 255) {
				nm_log_warn (LOGD_SETTINGS, "%s: %s / %s ignoring invalid byte element '%d' (not "
				             " between 0 and 255 inclusive)", __func__, setting_name,
				             key, val);
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

		sa = nm_keyfile_plugin_kf_get_string_list (info->keyfile, setting_name, key, &length, NULL);
		g_object_set (setting, key, sa, NULL);
		g_strfreev (sa);
	} else if (type == G_TYPE_HASH_TABLE) {
		read_hash_of_string (info->keyfile, setting, key);
	} else if (type == G_TYPE_ARRAY) {
		if (!read_array_of_uint (info->keyfile, setting, key)) {
			nm_log_warn (LOGD_SETTINGS, "Unhandled setting property type (read): '%s/%s' : '%s'",
			             setting_name, key, G_VALUE_TYPE_NAME (value));
		}
	} else if (G_VALUE_HOLDS_FLAGS (value)) {
		guint64 uint_val;

		/* Flags are guint but GKeyFile has no uint reader, just uint64 */
		uint_val = nm_keyfile_plugin_kf_get_uint64 (info->keyfile, setting_name, key, &err);
		if (!err) {
			if (uint_val <= G_MAXUINT)
				g_object_set (setting, key, (guint) uint_val, NULL);
			else {
				nm_log_warn (LOGD_SETTINGS, "Too large FLAGS property (read): '%s/%s' : '%s'",
				             setting_name, key, G_VALUE_TYPE_NAME (value));
			}
		}
		g_clear_error (&err);
	} else if (G_VALUE_HOLDS_ENUM (value)) {
		gint int_val;

		int_val = nm_keyfile_plugin_kf_get_integer (info->keyfile, setting_name, key, &err);
		if (!err)
			g_object_set (setting, key, (gint) int_val, NULL);
		g_clear_error (&err);
	} else {
		nm_log_warn (LOGD_SETTINGS, "Unhandled setting property type (read): '%s/%s' : '%s'",
		             setting_name, key, G_VALUE_TYPE_NAME (value));
	}
}

static NMSetting *
read_setting (GKeyFile *file, const char *keyfile_path, const char *group)
{
	NMSetting *setting = NULL;
	ReadInfo info = { file, keyfile_path };
	const char *alias;
	GType type;

	alias = nm_keyfile_plugin_get_setting_name_for_alias (group);
	if (alias)
		group = alias;

	type = nm_setting_lookup_type (group);
	if (type) {
		setting = g_object_new (type, NULL);
		nm_setting_enumerate_values (setting, read_one_setting_value, &info);
	} else
		nm_log_warn (LOGD_SETTINGS, "Invalid setting name '%s'", group);

	return setting;
}

static void
read_vpn_secrets (GKeyFile *file, NMSettingVpn *s_vpn)
{
	char **keys, **iter;

	keys = nm_keyfile_plugin_kf_get_keys (file, VPN_SECRETS_GROUP, NULL, NULL);
	for (iter = keys; *iter; iter++) {
		char *secret;

		secret = nm_keyfile_plugin_kf_get_string (file, VPN_SECRETS_GROUP, *iter, NULL);
		if (secret) {
			nm_setting_vpn_add_secret (s_vpn, *iter, secret);
			g_free (secret);
		}
	}
	g_strfreev (keys);
}

NMConnection *
nm_keyfile_plugin_connection_from_file (const char *filename, GError **error)
{
	GKeyFile *key_file;
	struct stat statbuf;
	gboolean bad_permissions;
	NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	NMSetting *setting;
	gchar **groups;
	gsize length;
	int i;
	gboolean vpn_secrets = FALSE;
	GError *verify_error = NULL;

	if (stat (filename, &statbuf) != 0 || !S_ISREG (statbuf.st_mode)) {
		g_set_error_literal (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		                     "File did not exist or was not a regular file");
		return NULL;
	}

	bad_permissions = statbuf.st_mode & 0077;

	if (bad_permissions) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "File permissions (%o) were insecure",
		             statbuf.st_mode);
		return NULL;
	}

	key_file = g_key_file_new ();
	if (!g_key_file_load_from_file (key_file, filename, G_KEY_FILE_NONE, error))
		goto out;

	connection = nm_simple_connection_new ();

	groups = g_key_file_get_groups (key_file, &length);
	for (i = 0; i < length; i++) {
		/* Only read out secrets when needed */
		if (!strcmp (groups[i], VPN_SECRETS_GROUP)) {
			vpn_secrets = TRUE;
			continue;
		}

		setting = read_setting (key_file, filename, groups[i]);
		if (setting)
			nm_connection_add_setting (connection, setting);
	}

	s_con = nm_connection_get_setting_connection (connection);
	if (!s_con) {
		s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());
		nm_connection_add_setting (connection, NM_SETTING (s_con));
	}

	/* Make sure that we have 'id' even if not explictly specified in the keyfile */
	if (!nm_setting_connection_get_id (s_con)) {
		char *base_name;

		base_name = g_path_get_basename (filename);
		g_object_set (s_con, NM_SETTING_CONNECTION_ID, base_name, NULL);
		g_free (base_name);
	}

	/* Make sure that we have 'uuid' even if not explictly specified in the keyfile */
	if (!nm_setting_connection_get_uuid (s_con)) {
		char *hashed_uuid;

		hashed_uuid = nm_utils_uuid_generate_from_strings ("keyfile", filename, NULL);
		g_object_set (s_con, NM_SETTING_CONNECTION_UUID, hashed_uuid, NULL);
		g_free (hashed_uuid);
	}

	/* Make sure that we have 'interface-name' even if it was specified in the
	 * "wrong" (ie, deprecated) group.
	 */
	if (   !nm_setting_connection_get_interface_name (s_con)
	    && nm_setting_connection_get_connection_type (s_con)) {
		char *interface_name;

		interface_name = g_key_file_get_string (key_file,
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
		if (s_vpn)
			read_vpn_secrets (key_file, s_vpn);
	}

	g_strfreev (groups);

	/* Normalize and verify the connection */
	if (!nm_connection_normalize (connection, NULL, NULL, &verify_error)) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			         "invalid connection: %s",
		             verify_error->message);
		g_clear_error (&verify_error);
		g_object_unref (connection);
		connection = NULL;
	}

out:
	g_key_file_free (key_file);
	return connection;
}
