/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
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
 * Copyright (C) 2008 - 2011 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-dispatcher-utils.h"

#include "nm-dbus-interface.h"
#include "nm-connection.h"
#include "nm-setting-ip4-config.h"
#include "nm-setting-ip6-config.h"
#include "nm-setting-connection.h"

#include "nm-libnm-core-aux/nm-dispatcher-api.h"
#include "nm-utils.h"

/*****************************************************************************/

static gboolean
_is_valid_key (const char *line, gssize len)
{
	gsize i, l;
	char ch;

	if (!line)
		return FALSE;

	if (len < 0)
		len = strlen (line);

	if (len == 0)
		return FALSE;

	ch = line[0];
	if (   !(ch >= 'A' && ch <= 'Z')
	    && !NM_IN_SET (ch, '_'))
		return FALSE;

	l = (gsize) len;

	for (i = 1; i < l; i++) {
		ch = line[i];

		if (   !(ch >= 'A' && ch <= 'Z')
		    && !(ch >= '0' && ch <= '9')
		    && !NM_IN_SET (ch, '_'))
			return FALSE;
	}

	return TRUE;
}

static gboolean
_is_valid_line (const char *line)
{
	const char *d;

	if (!line)
		return FALSE;

	d = strchr (line, '=');
	if (!d || d == line)
		return FALSE;

	return _is_valid_key (line, d - line);
}

static char *
_sanitize_var_name (const char *key)
{
	char *sanitized;

	nm_assert (key);

	if (!key[0])
		return NULL;

	sanitized = g_ascii_strup (key, -1);
	if (!NM_STRCHAR_ALL (sanitized, ch,    (ch >= 'A' && ch <= 'Z')
	                                    || (ch >= '0' && ch <= '9')
	                                    || NM_IN_SET (ch, '_'))) {
		g_free (sanitized);
		return NULL;
	}

	nm_assert (_is_valid_key (sanitized, -1));
	return sanitized;
}

static void
_items_add_str_take (GPtrArray *items, char *line)
{
	nm_assert (items);
	nm_assert (_is_valid_line (line));

	g_ptr_array_add (items, line);
}

static void
_items_add_str (GPtrArray *items, const char *line)
{
	_items_add_str_take (items, g_strdup (line));
}

static void
_items_add_key (GPtrArray *items, const char *prefix, const char *key, const char *value)
{
	nm_assert (items);
	nm_assert (_is_valid_key (key, -1));
	nm_assert (value);

	_items_add_str_take (items, g_strconcat (prefix ?: "", key, "=", value, NULL));
}

static void
_items_add_key0 (GPtrArray *items, const char *prefix, const char *key, const char *value)
{
	nm_assert (items);
	nm_assert (_is_valid_key (key, -1));

	if (!value) {
		/* for convenience, allow NULL values to indicate to skip the line. */
		return;
	}

	_items_add_str_take (items, g_strconcat (prefix ?: "", key, "=", value, NULL));
}

G_GNUC_PRINTF (2, 3)
static void
_items_add_printf (GPtrArray *items, const char *fmt, ...)
{
	va_list ap;
	char *line;

	nm_assert (items);
	nm_assert (fmt);

	va_start (ap, fmt);
	line = g_strdup_vprintf (fmt, ap);
	va_end (ap);
	_items_add_str_take (items, line);
}

static void
_items_add_strv (GPtrArray *items, const char *prefix, const char *key, const char *const*values)
{
	gboolean has;
	guint i;
	GString *str;

	nm_assert (items);
	nm_assert (_is_valid_key (key, -1));

	if (!values || !values[0]) {
		/* Only add an item if the list of @values is not empty */
		return;
	}

	str = g_string_new (NULL);

	if (prefix)
		g_string_append (str, prefix);
	g_string_append (str, key);
	g_string_append_c (str, '=');

	has = FALSE;
	for (i = 0; values[i]; i++) {
		if (!values[i][0])
			continue;
		if (has)
			g_string_append_c (str, ' ');
		else
			has = TRUE;
		g_string_append (str, values[i]);
	}

	_items_add_str_take (items, g_string_free (str, FALSE));
}

/*****************************************************************************/

static void
construct_proxy_items (GPtrArray *items, GVariant *proxy_config, const char *prefix)
{
	GVariant *variant;

	nm_assert (items);

	if (!proxy_config)
		return;

	variant = g_variant_lookup_value (proxy_config, "pac-url", G_VARIANT_TYPE_STRING);
	if (variant) {
		_items_add_key (items, prefix, "PROXY_PAC_URL",
		                g_variant_get_string (variant, NULL));
		g_variant_unref (variant);
	}

	variant = g_variant_lookup_value (proxy_config, "pac-script", G_VARIANT_TYPE_STRING);
	if (variant) {
		_items_add_key (items, prefix, "PROXY_PAC_SCRIPT",
		                g_variant_get_string (variant, NULL));
		g_variant_unref (variant);
	}
}

static void
construct_ip_items (GPtrArray *items, int addr_family, GVariant *ip_config, const char *prefix)
{
	GVariant *val;
	guint i;
	guint nroutes = 0;
	char four_or_six;

	if (!ip_config)
		return;

	if (!prefix)
		prefix = "";

	four_or_six = nm_utils_addr_family_to_char (addr_family);

	val = g_variant_lookup_value (ip_config,
	                              "addresses",
	                                addr_family == AF_INET
	                              ? G_VARIANT_TYPE ("aau")
	                              : G_VARIANT_TYPE ("a(ayuay)"));
	if (val) {
		gs_unref_ptrarray GPtrArray *addresses = NULL;
		gs_free char *gateway_free = NULL;
		const char *gateway;

		if (addr_family == AF_INET)
			addresses = nm_utils_ip4_addresses_from_variant (val, &gateway_free);
		else
			addresses = nm_utils_ip6_addresses_from_variant (val, &gateway_free);

		gateway = gateway_free ?: "0.0.0.0";

		if (addresses && addresses->len) {
			for (i = 0; i < addresses->len; i++) {
				NMIPAddress *addr = addresses->pdata[i];

				_items_add_printf (items,
				                   "%sIP%c_ADDRESS_%d=%s/%d %s",
				                   prefix,
				                   four_or_six,
				                   i,
				                   nm_ip_address_get_address (addr),
				                   nm_ip_address_get_prefix (addr),
				                   gateway);
			}

			_items_add_printf (items,
			                   "%sIP%c_NUM_ADDRESSES=%u",
			                   prefix,
			                   four_or_six,
			                   addresses->len);
		}

		_items_add_key (items,
		                prefix,
		                  addr_family == AF_INET
		                ? "IP4_GATEWAY"
		                : "IP6_GATEWAY",
		                gateway);

		g_variant_unref (val);
	}

	val = g_variant_lookup_value (ip_config,
	                              "nameservers",
	                                addr_family == AF_INET
	                              ? G_VARIANT_TYPE ("au")
	                              : G_VARIANT_TYPE ("aay"));
	if (val) {
		gs_strfreev char **v = NULL;

		if (addr_family == AF_INET)
			v = nm_utils_ip4_dns_from_variant (val);
		else
			v = nm_utils_ip6_dns_from_variant (val);
		_items_add_strv (items,
		                 prefix,
		                   addr_family == AF_INET
		                 ? "IP4_NAMESERVERS"
		                 : "IP6_NAMESERVERS",
		                 NM_CAST_STRV_CC (v));
		g_variant_unref (val);
	}

	val = g_variant_lookup_value (ip_config, "domains", G_VARIANT_TYPE_STRING_ARRAY);
	if (val) {
		gs_free const char **v = NULL;

		v = g_variant_get_strv (val, NULL);
		_items_add_strv (items, prefix,
		                   addr_family == AF_INET
		                 ? "IP4_DOMAINS"
		                 : "IP6_DOMAINS",
		                 v);
		g_variant_unref (val);
	}


	if (addr_family == AF_INET) {
		val = g_variant_lookup_value (ip_config, "wins-servers", G_VARIANT_TYPE ("au"));
		if (val) {
			gs_strfreev char **v = NULL;

			v = nm_utils_ip4_dns_from_variant (val);
			_items_add_strv (items, prefix, "IP4_WINS_SERVERS", NM_CAST_STRV_CC (v));
			g_variant_unref (val);
		}
	}

	val = g_variant_lookup_value (ip_config,
	                              "routes",
	                                addr_family == AF_INET
	                              ? G_VARIANT_TYPE ("aau")
	                              : G_VARIANT_TYPE ("a(ayuayu)"));
	if (val) {
		gs_unref_ptrarray GPtrArray *routes = NULL;

		if (addr_family == AF_INET)
			routes = nm_utils_ip4_routes_from_variant (val);
		else
			routes = nm_utils_ip6_routes_from_variant (val);

		if (   routes
		    && routes->len > 0) {
			const char *const DEFAULT_GW = addr_family == AF_INET ? "0.0.0.0" : "::";

			nroutes = routes->len;

			for (i = 0; i < routes->len; i++) {
				NMIPRoute *route = routes->pdata[i];

				_items_add_printf (items,
				                   "%sIP%c_ROUTE_%u=%s/%d %s %u",
				                   prefix,
				                   four_or_six,
				                   i,
				                   nm_ip_route_get_dest (route),
				                   nm_ip_route_get_prefix (route),
				                   nm_ip_route_get_next_hop (route) ?: DEFAULT_GW,
				                   (guint) NM_MAX ((gint64) 0, nm_ip_route_get_metric (route)));
			}
		}

		g_variant_unref (val);
	}
	if (nroutes > 0 || addr_family == AF_INET) {
		/* we also set IP4_NUM_ROUTES=0, but don't do so for addresses and IPv6 routes.
		 * Historic reasons. */
		_items_add_printf (items, "%sIP%c_NUM_ROUTES=%u", prefix, four_or_six, nroutes);
	}
}

static void
construct_device_dhcp_items (GPtrArray *items, int addr_family, GVariant *dhcp_config)
{
	GVariantIter iter;
	const char *key;
	GVariant *val;
	char four_or_six;

	if (!dhcp_config)
		return;

	if (!g_variant_is_of_type (dhcp_config, G_VARIANT_TYPE_VARDICT))
		return;

	four_or_six = nm_utils_addr_family_to_char (addr_family);

	g_variant_iter_init (&iter, dhcp_config);
	while (g_variant_iter_next (&iter, "{&sv}", &key, &val)) {
		if (g_variant_is_of_type (val, G_VARIANT_TYPE_STRING)) {
			gs_free char *ucased = NULL;

			ucased = _sanitize_var_name (key);
			if (ucased) {
				_items_add_printf (items,
				                   "DHCP%c_%s=%s",
				                   four_or_six,
				                   ucased,
				                   g_variant_get_string (val, NULL));
			}
		}
		g_variant_unref (val);
	}
}

/*****************************************************************************/

char **
nm_dispatcher_utils_construct_envp (const char *action,
                                    GVariant *connection_dict,
                                    GVariant *connection_props,
                                    GVariant *device_props,
                                    GVariant *device_proxy_props,
                                    GVariant *device_ip4_props,
                                    GVariant *device_ip6_props,
                                    GVariant *device_dhcp4_props,
                                    GVariant *device_dhcp6_props,
                                    const char *connectivity_state,
                                    const char *vpn_ip_iface,
                                    GVariant *vpn_proxy_props,
                                    GVariant *vpn_ip4_props,
                                    GVariant *vpn_ip6_props,
                                    char **out_iface,
                                    const char **out_error_message)
{
	const char *iface = NULL;
	const char *ip_iface = NULL;
	const char *uuid = NULL;
	const char *id = NULL;
	const char *path = NULL;
	const char *filename = NULL;
	gboolean external;
	NMDeviceState dev_state = NM_DEVICE_STATE_UNKNOWN;
	GVariant *variant;
	gs_unref_ptrarray GPtrArray *items = NULL;
	const char *error_message_backup;

	if (!out_error_message)
		out_error_message = &error_message_backup;

	g_return_val_if_fail (action != NULL, NULL);
	g_return_val_if_fail (out_iface != NULL, NULL);
	g_return_val_if_fail (*out_iface == NULL, NULL);

	items = g_ptr_array_new_with_free_func (g_free);

	/* Hostname and connectivity changes don't require a device nor contain a connection */
	if (NM_IN_STRSET (action, NMD_ACTION_HOSTNAME,
	                          NMD_ACTION_CONNECTIVITY_CHANGE))
		goto done;

	/* Connection properties */
	if (!g_variant_lookup (connection_props, NMD_CONNECTION_PROPS_PATH, "&o", &path)) {
		*out_error_message = "Missing or invalid required value " NMD_CONNECTION_PROPS_PATH "!";
		return NULL;
	}

	_items_add_key (items, NULL, "CONNECTION_DBUS_PATH", path);

	if (g_variant_lookup (connection_props, NMD_CONNECTION_PROPS_EXTERNAL, "b", &external) && external)
		_items_add_str (items, "CONNECTION_EXTERNAL=1");

	if (g_variant_lookup (connection_props, NMD_CONNECTION_PROPS_FILENAME, "&s", &filename))
		_items_add_key (items, NULL, "CONNECTION_FILENAME", filename);

	/* Canonicalize the VPN interface name; "" is used when passing it through
	 * D-Bus so make sure that's fixed up here.
	 */
	if (vpn_ip_iface && !vpn_ip_iface[0])
		vpn_ip_iface = NULL;

	if (!g_variant_lookup (device_props, NMD_DEVICE_PROPS_INTERFACE, "&s", &iface)) {
		*out_error_message = "Missing or invalid required value " NMD_DEVICE_PROPS_INTERFACE "!";
		return NULL;
	}
	if (!*iface)
		iface = NULL;

	variant = g_variant_lookup_value (device_props, NMD_DEVICE_PROPS_IP_INTERFACE, NULL);
	if (variant) {
		if (!g_variant_is_of_type (variant, G_VARIANT_TYPE_STRING)) {
			*out_error_message = "Invalid value " NMD_DEVICE_PROPS_IP_INTERFACE "!";
			return NULL;
		}
		g_variant_unref (variant);
		(void) g_variant_lookup (device_props, NMD_DEVICE_PROPS_IP_INTERFACE, "&s", &ip_iface);
	}

	if (!g_variant_lookup (device_props, NMD_DEVICE_PROPS_TYPE, "u", NULL)) {
		*out_error_message = "Missing or invalid required value " NMD_DEVICE_PROPS_TYPE "!";
		return NULL;
	}

	variant = g_variant_lookup_value (device_props, NMD_DEVICE_PROPS_STATE, G_VARIANT_TYPE_UINT32);
	if (!variant) {
		*out_error_message = "Missing or invalid required value " NMD_DEVICE_PROPS_STATE "!";
		return NULL;
	}
	dev_state = g_variant_get_uint32 (variant);
	g_variant_unref (variant);

	if (!g_variant_lookup (device_props, NMD_DEVICE_PROPS_PATH, "o", NULL)) {
		*out_error_message = "Missing or invalid required value " NMD_DEVICE_PROPS_PATH "!";
		return NULL;
	}

	{
		gs_unref_variant GVariant *con_setting = NULL;

		con_setting = g_variant_lookup_value (connection_dict, NM_SETTING_CONNECTION_SETTING_NAME, NM_VARIANT_TYPE_SETTING);
		if (!con_setting) {
			*out_error_message = "Failed to read connection setting";
			return NULL;
		}

		if (!g_variant_lookup (con_setting, NM_SETTING_CONNECTION_UUID, "&s", &uuid)) {
			*out_error_message = "Connection hash did not contain the UUID";
			return NULL;
		}

		if (!g_variant_lookup (con_setting, NM_SETTING_CONNECTION_ID, "&s", &id)) {
			*out_error_message = "Connection hash did not contain the ID";
			return NULL;
		}

		_items_add_key0 (items, NULL, "CONNECTION_UUID", uuid);
		_items_add_key0 (items, NULL, "CONNECTION_ID", id);
		_items_add_key0 (items, NULL, "DEVICE_IFACE", iface);
		_items_add_key0 (items, NULL, "DEVICE_IP_IFACE", ip_iface);
	}

	/* Device it's aren't valid if the device isn't activated */
	if (   iface
	    && dev_state == NM_DEVICE_STATE_ACTIVATED) {
		construct_proxy_items (items, device_proxy_props, NULL);
		construct_ip_items (items, AF_INET, device_ip4_props, NULL);
		construct_ip_items (items, AF_INET6, device_ip6_props, NULL);
		construct_device_dhcp_items (items, AF_INET, device_dhcp4_props);
		construct_device_dhcp_items (items, AF_INET6, device_dhcp6_props);
	}

	if (vpn_ip_iface) {
		_items_add_key (items, NULL, "VPN_IP_IFACE", vpn_ip_iface);
		construct_proxy_items (items, vpn_proxy_props, "VPN_");
		construct_ip_items (items, AF_INET, vpn_ip4_props, "VPN_");
		construct_ip_items (items, AF_INET6, vpn_ip6_props, "VPN_");
	}

	/* Backwards compat: 'iface' is set in this order:
	 * 1) VPN interface name
	 * 2) Device IP interface name
	 * 3) Device interface anme
	 */
	if (vpn_ip_iface)
		*out_iface = g_strdup (vpn_ip_iface);
	else if (ip_iface)
		*out_iface = g_strdup (ip_iface);
	else
		*out_iface = g_strdup (iface);

done:
	/* The connectivity_state value will only be meaningful for 'connectivity-change' events
	 * (otherwise it will be "UNKNOWN"), so we only set the environment variable in those cases.
	 */
	if (!NM_IN_STRSET (connectivity_state, NULL, "UNKNOWN"))
		_items_add_key (items, NULL, "CONNECTIVITY_STATE", connectivity_state);

	_items_add_key0 (items, NULL, "PATH", g_getenv ("PATH"));

	_items_add_key (items, NULL, "NM_DISPATCHER_ACTION", action);

	*out_error_message = NULL;
	g_ptr_array_add (items, NULL);
	return (char **) g_ptr_array_free (g_steal_pointer (&items), FALSE);
}
