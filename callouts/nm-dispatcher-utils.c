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

#include <config.h>
#include <string.h>

#include <glib-object.h>

#include <NetworkManager.h>
#include <nm-dbus-glib-types.h>
#include <nm-connection.h>
#include <nm-setting-ip4-config.h>
#include <nm-setting-ip6-config.h>
#include <nm-setting-connection.h>

#include "nm-dispatcher-api.h"
#include "nm-utils.h"

#include "nm-dispatcher-utils.h"

static GSList *
construct_basic_items (GSList *list,
                       const char *uuid,
                       const char *id,
                       const char *iface,
                       const char *ip_iface)
{
	if (uuid)
		list = g_slist_prepend (list, g_strdup_printf ("CONNECTION_UUID=%s", uuid));
	if (id)
		list = g_slist_prepend (list, g_strdup_printf ("CONNECTION_ID=%s", id));
	if (iface)
		list = g_slist_prepend (list, g_strdup_printf ("DEVICE_IFACE=%s", iface));
	if (ip_iface)
		list = g_slist_prepend (list, g_strdup_printf ("DEVICE_IP_IFACE=%s", ip_iface));
	return list;
}

static GSList *
add_domains (GSList *items,
             GHashTable *hash,
             const char *prefix,
             const char four_or_six)
{
	GValue *val;
	char **domains = NULL;
	GString *tmp;
	guint i;

	/* Search domains */
	val = g_hash_table_lookup (hash, "domains");
	if (!val)
		return items;

	g_return_val_if_fail (G_VALUE_HOLDS (val, G_TYPE_STRV), items);

	domains = (char **) g_value_get_boxed (val);
	if (!domains || !domains[0])
		return items;

	tmp = g_string_new (NULL);
	g_string_append_printf (tmp, "%sIP%c_DOMAINS=", prefix, four_or_six);
	for (i = 0; domains[i]; i++) {
		if (i > 0)
			g_string_append_c (tmp, ' ');
		g_string_append (tmp, domains[i]);
	}
	items = g_slist_prepend (items, tmp->str);
	g_string_free (tmp, FALSE);

	return items;
}

static GSList *
construct_ip4_items (GSList *items, GHashTable *ip4_config, const char *prefix)
{
	GSList *addresses = NULL, *routes = NULL, *iter;
	GArray *dns = NULL, *wins = NULL;
	guint32 num, i;
	GString *tmp;
	GValue *val;
	char str_addr[INET_ADDRSTRLEN];
	char str_gw[INET_ADDRSTRLEN];

	if (ip4_config == NULL)
		return items;

	if (prefix == NULL)
		prefix = "";

	/* IP addresses */
	val = g_hash_table_lookup (ip4_config, "addresses");
	if (val)
		addresses = nm_utils_ip4_addresses_from_gvalue (val);

	for (iter = addresses, num = 0; iter; iter = g_slist_next (iter)) {
		NMIP4Address *addr = (NMIP4Address *) iter->data;
		guint32 ip_prefix = nm_ip4_address_get_prefix (addr);
		char *addrtmp;

		nm_utils_inet4_ntop (nm_ip4_address_get_address (addr), str_addr);
		nm_utils_inet4_ntop (nm_ip4_address_get_gateway (addr), str_gw);

		addrtmp = g_strdup_printf ("%sIP4_ADDRESS_%d=%s/%d %s", prefix, num++, str_addr, ip_prefix, str_gw);
		items = g_slist_prepend (items, addrtmp);
	}
	if (num)
		items = g_slist_prepend (items, g_strdup_printf ("%sIP4_NUM_ADDRESSES=%d", prefix, num));
	if (addresses)
		g_slist_free_full (addresses, (GDestroyNotify) nm_ip4_address_unref);

	/* DNS servers */
	val = g_hash_table_lookup (ip4_config, "nameservers");
	if (val && G_VALUE_HOLDS (val, DBUS_TYPE_G_UINT_ARRAY))
		dns = (GArray *) g_value_get_boxed (val);

	if (dns && (dns->len > 0)) {
		gboolean first = TRUE;

		tmp = g_string_new (NULL);
		g_string_append_printf (tmp, "%sIP4_NAMESERVERS=", prefix);
		for (i = 0; i < dns->len; i++) {
			guint32 addr;

			addr = g_array_index (dns, guint32, i);
			if (!first)
				g_string_append_c (tmp, ' ');
			g_string_append (tmp, nm_utils_inet4_ntop (addr, NULL));
			first = FALSE;
		}
		items = g_slist_prepend (items, tmp->str);
		g_string_free (tmp, FALSE);
	}

	/* Search domains */
	items = add_domains (items, ip4_config, prefix, '4');

	/* WINS servers */
	val = g_hash_table_lookup (ip4_config, "wins-servers");
	if (val && G_VALUE_HOLDS (val, DBUS_TYPE_G_UINT_ARRAY))
		wins = (GArray *) g_value_get_boxed (val);

	if (wins && wins->len) {
		gboolean first = TRUE;

		tmp = g_string_new (NULL);
		g_string_append_printf (tmp, "%sIP4_WINS_SERVERS=", prefix);
		for (i = 0; i < wins->len; i++) {
			guint32 addr;

			addr = g_array_index (wins, guint32, i);
			if (!first)
				g_string_append_c (tmp, ' ');
			g_string_append (tmp, nm_utils_inet4_ntop (addr, NULL));
			first = FALSE;
		}
		items = g_slist_prepend (items, tmp->str);
		g_string_free (tmp, FALSE);
	}

	/* Static routes */
	val = g_hash_table_lookup (ip4_config, "routes");
	if (val)
		routes = nm_utils_ip4_routes_from_gvalue (val);

	for (iter = routes, num = 0; iter; iter = g_slist_next (iter)) {
		NMIP4Route *route = (NMIP4Route *) iter->data;
		guint32 ip_prefix = nm_ip4_route_get_prefix (route);
		guint32 metric = nm_ip4_route_get_metric (route);
		char *routetmp;

		nm_utils_inet4_ntop (nm_ip4_route_get_dest (route), str_addr);
		nm_utils_inet4_ntop (nm_ip4_route_get_next_hop (route), str_gw);

		routetmp = g_strdup_printf ("%sIP4_ROUTE_%d=%s/%d %s %d", prefix, num++, str_addr, ip_prefix, str_gw, metric);
		items = g_slist_prepend (items, routetmp);
	}
	items = g_slist_prepend (items, g_strdup_printf ("%sIP4_NUM_ROUTES=%d", prefix, num));
	if (routes)
		g_slist_free_full (routes, (GDestroyNotify) nm_ip4_route_unref);

	return items;
}

static GSList *
construct_device_dhcp4_items (GSList *items, GHashTable *dhcp4_config)
{
	GHashTableIter iter;
	const char *key, *tmp;
	GValue *val;
	char *ucased;

	if (dhcp4_config == NULL)
		return items;

	g_hash_table_iter_init (&iter, dhcp4_config);
	while (g_hash_table_iter_next (&iter, (gpointer) &key, (gpointer) &val)) {
		ucased = g_ascii_strup (key, -1);
		tmp = g_value_get_string (val);
		items = g_slist_prepend (items, g_strdup_printf ("DHCP4_%s=%s", ucased, tmp));
		g_free (ucased);
	}
	return items;
}

static GSList *
construct_ip6_items (GSList *items, GHashTable *ip6_config, const char *prefix)
{
	GSList *addresses = NULL, *routes = NULL, *dns = NULL, *iter;
	guint32 num;
	GString *tmp;
	GValue *val;
	char str_addr[INET6_ADDRSTRLEN];
	char str_gw[INET6_ADDRSTRLEN];

	if (ip6_config == NULL)
		return items;

	if (prefix == NULL)
		prefix = "";

	/* IP addresses */
	val = g_hash_table_lookup (ip6_config, "addresses");
	if (val)
		addresses = nm_utils_ip6_addresses_from_gvalue (val);

	for (iter = addresses, num = 0; iter; iter = g_slist_next (iter)) {
		NMIP6Address *addr = (NMIP6Address *) iter->data;
		guint32 ip_prefix = nm_ip6_address_get_prefix (addr);
		char *addrtmp;

		nm_utils_inet6_ntop (nm_ip6_address_get_address (addr), str_addr);
		nm_utils_inet6_ntop (nm_ip6_address_get_gateway (addr), str_gw);

		addrtmp = g_strdup_printf ("%sIP6_ADDRESS_%d=%s/%d %s", prefix, num++, str_addr, ip_prefix, str_gw);
		items = g_slist_prepend (items, addrtmp);
	}
	if (num)
		items = g_slist_prepend (items, g_strdup_printf ("%sIP6_NUM_ADDRESSES=%d", prefix, num));
	if (addresses)
		g_slist_free_full (addresses, (GDestroyNotify) nm_ip6_address_unref);

	/* DNS servers */
	val = g_hash_table_lookup (ip6_config, "nameservers");
	if (val)
		dns = nm_utils_ip6_dns_from_gvalue (val);

	if (g_slist_length (dns)) {
		gboolean first = TRUE;

		tmp = g_string_new (NULL);
		g_string_append_printf (tmp, "%sIP6_NAMESERVERS=", prefix);

		for (iter = dns; iter; iter = g_slist_next (iter)) {
			const struct in6_addr *addr = iter->data;

			if (!first)
				g_string_append_c (tmp, ' ');
			g_string_append (tmp, nm_utils_inet6_ntop (addr, NULL));
			first = FALSE;
		}

		items = g_slist_prepend (items, tmp->str);
		g_string_free (tmp, FALSE);
	}

	/* Search domains */
	items = add_domains (items, ip6_config, prefix, '6');

	/* Static routes */
	val = g_hash_table_lookup (ip6_config, "routes");
	if (val)
		routes = nm_utils_ip6_routes_from_gvalue (val);

	for (iter = routes, num = 0; iter; iter = g_slist_next (iter)) {
		NMIP6Route *route = (NMIP6Route *) iter->data;
		guint32 ip_prefix = nm_ip6_route_get_prefix (route);
		guint32 metric = nm_ip6_route_get_metric (route);
		char *routetmp;

		nm_utils_inet6_ntop (nm_ip6_route_get_dest (route), str_addr);
		nm_utils_inet6_ntop (nm_ip6_route_get_next_hop (route), str_gw);

		routetmp = g_strdup_printf ("%sIP6_ROUTE_%d=%s/%d %s %d", prefix, num++, str_addr, ip_prefix, str_gw, metric);
		items = g_slist_prepend (items, routetmp);
	}
	if (num)
		items = g_slist_prepend (items, g_strdup_printf ("%sIP6_NUM_ROUTES=%d", prefix, num));
	if (routes)
		g_slist_free_full (routes, (GDestroyNotify) nm_ip6_route_unref);

	return items;
}

static GSList *
construct_device_dhcp6_items (GSList *items, GHashTable *dhcp6_config)
{
	GHashTableIter iter;
	const char *key, *tmp;
	GValue *val;
	char *ucased;

	if (dhcp6_config == NULL)
		return items;

	g_hash_table_iter_init (&iter, dhcp6_config);
	while (g_hash_table_iter_next (&iter, (gpointer) &key, (gpointer) &val)) {
		ucased = g_ascii_strup (key, -1);
		tmp = g_value_get_string (val);
		items = g_slist_prepend (items, g_strdup_printf ("DHCP6_%s=%s", ucased, tmp));
		g_free (ucased);
	}
	return items;
}

char **
nm_dispatcher_utils_construct_envp (const char *action,
                                    GHashTable *connection_hash,
                                    GHashTable *connection_props,
                                    GHashTable *device_props,
                                    GHashTable *device_ip4_props,
                                    GHashTable *device_ip6_props,
                                    GHashTable *device_dhcp4_props,
                                    GHashTable *device_dhcp6_props,
                                    const char *vpn_ip_iface,
                                    GHashTable *vpn_ip4_props,
                                    GHashTable *vpn_ip6_props,
                                    char **out_iface)
{
	const char *iface = NULL, *ip_iface = NULL;
	const char *uuid = NULL, *id = NULL, *path;
	NMDeviceState dev_state = NM_DEVICE_STATE_UNKNOWN;
	GValue *value;
	char **envp = NULL, *path_item;
	GSList *items = NULL, *iter;
	guint i;
	GHashTable *con_setting_hash;

	g_return_val_if_fail (action != NULL, NULL);
	g_return_val_if_fail (out_iface != NULL, NULL);
	g_return_val_if_fail (*out_iface == NULL, NULL);

	/* Hostname changes don't require a device nor contain a connection */
	if (!strcmp (action, "hostname"))
		goto done;

	/* Canonicalize the VPN interface name; "" is used when passing it through
	 * D-Bus so make sure that's fixed up here.
	 */
	if (vpn_ip_iface && !strlen (vpn_ip_iface))
		vpn_ip_iface = NULL;

	con_setting_hash = g_hash_table_lookup (connection_hash, NM_SETTING_CONNECTION_SETTING_NAME);
	if (!con_setting_hash) {
		g_warning ("Failed to read connection setting");
		return NULL;
	}

	value = g_hash_table_lookup (con_setting_hash, NM_SETTING_CONNECTION_UUID);
	if (!value || !G_VALUE_HOLDS (value, G_TYPE_STRING)) {
		g_warning ("Connection hash did not contain the UUID");
		return NULL;
	}
	uuid = g_value_get_string (value);

	value = g_hash_table_lookup (con_setting_hash, NM_SETTING_CONNECTION_ID);
	if (!value || !G_VALUE_HOLDS (value, G_TYPE_STRING)) {
		g_warning ("Connection hash did not contain the ID");
		return NULL;
	}
	id = g_value_get_string (value);

	/* interface name */
	value = g_hash_table_lookup (device_props, NMD_DEVICE_PROPS_INTERFACE);
	if (!value || !G_VALUE_HOLDS_STRING (value)) {
		g_warning ("Missing or invalid required value " NMD_DEVICE_PROPS_INTERFACE "!");
		return NULL;
	}
	iface = g_value_get_string (value);
	if (iface && !strlen (iface))
		iface = NULL;

	/* IP interface name */
	value = g_hash_table_lookup (device_props, NMD_DEVICE_PROPS_IP_INTERFACE);
	if (value) {
		if (!G_VALUE_HOLDS_STRING (value)) {
			g_warning ("Invalid required value " NMD_DEVICE_PROPS_IP_INTERFACE "!");
			return NULL;
		}
		ip_iface = g_value_get_string (value);
	}

	/* Device type */
	value = g_hash_table_lookup (device_props, NMD_DEVICE_PROPS_TYPE);
	if (!value || !G_VALUE_HOLDS_UINT (value)) {
		g_warning ("Missing or invalid required value " NMD_DEVICE_PROPS_TYPE "!");
		return NULL;
	}

	/* Device state */
	value = g_hash_table_lookup (device_props, NMD_DEVICE_PROPS_STATE);
	if (!value || !G_VALUE_HOLDS_UINT (value)) {
		g_warning ("Missing or invalid required value " NMD_DEVICE_PROPS_STATE "!");
		return NULL;
	}
	dev_state = g_value_get_uint (value);

	/* device itself */
	value = g_hash_table_lookup (device_props, NMD_DEVICE_PROPS_PATH);
	if (!value || (G_VALUE_TYPE (value) != DBUS_TYPE_G_OBJECT_PATH)) {
		g_warning ("Missing or invalid required value " NMD_DEVICE_PROPS_PATH "!");
		return NULL;
	}

	items = construct_basic_items (items, uuid, id, iface, ip_iface);

	/* Device it's aren't valid if the device isn't activated */
	if (iface && (dev_state == NM_DEVICE_STATE_ACTIVATED)) {
		items = construct_ip4_items (items, device_ip4_props, NULL);
		items = construct_ip6_items (items, device_ip6_props, NULL);
		items = construct_device_dhcp4_items (items, device_dhcp4_props);
		items = construct_device_dhcp6_items (items, device_dhcp6_props);
	}

	if (vpn_ip_iface) {
		items = g_slist_prepend (items, g_strdup_printf ("VPN_IP_IFACE=%s", vpn_ip_iface));
		items = construct_ip4_items (items, vpn_ip4_props, "VPN_");
		items = construct_ip6_items (items, vpn_ip6_props, "VPN_");
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
	path = g_getenv ("PATH");
	if (path) {
		path_item = g_strdup_printf ("PATH=%s", path);
		items = g_slist_prepend (items, path_item);
	}

	/* Convert the list to an environment pointer */
	envp = g_new0 (char *, g_slist_length (items) + 1);
	for (iter = items, i = 0; iter; iter = g_slist_next (iter), i++)
		envp[i] = (char *) iter->data;
	g_slist_free (items);

	return envp;
}

