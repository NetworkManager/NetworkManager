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

#include "config.h"

#include <string.h>


#include <nm-dbus-interface.h>
#include <nm-connection.h>
#include <nm-setting-ip4-config.h>
#include <nm-setting-ip6-config.h>
#include <nm-setting-connection.h>

#include "nm-default.h"
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

static GSList *_list_append_val_strv (GSList *items, char **values, const char *format, ...) G_GNUC_PRINTF(3, 4);

static GSList *
_list_append_val_strv (GSList *items, char **values, const char *format, ...)
{
	if (!values)
		g_return_val_if_reached (items);

	/*  Only add an item if the list of @values is not empty */
	if (values[0]) {
		va_list args;
		guint i;
		GString *str = g_string_new (NULL);

		va_start (args, format);
		g_string_append_vprintf (str, format, args);
		va_end (args);

		g_string_append (str, values[0]);
		for (i = 1; values[i]; i++) {
			g_string_append_c (str, ' ');
			g_string_append (str, values[i]);
		}
		items = g_slist_prepend (items, g_string_free (str, FALSE));
	}

	/* we take ownership of the values array and free it. */
	g_strfreev (values);
	return items;
}

static GSList *
add_domains (GSList *items,
             GVariant *dict,
             const char *prefix,
             const char four_or_six)
{
	GVariant *val;

	/* Search domains */
	val = g_variant_lookup_value (dict, "domains", G_VARIANT_TYPE_STRING_ARRAY);
	if (val) {
		items = _list_append_val_strv (items, g_variant_dup_strv (val, NULL),
		                               "%sIP%c_DOMAINS=", prefix, four_or_six);
		g_variant_unref (val);
	}
	return items;
}

static GSList *
construct_ip4_items (GSList *items, GVariant *ip4_config, const char *prefix)
{
	GPtrArray *addresses, *routes;
	char *gateway;
	GVariant *val;
	int i;

	if (ip4_config == NULL)
		return items;

	if (prefix == NULL)
		prefix = "";

	/* IP addresses */
	val = g_variant_lookup_value (ip4_config, "addresses", G_VARIANT_TYPE ("aau"));
	if (val) {
		addresses = nm_utils_ip4_addresses_from_variant (val, &gateway);
		if (!gateway)
			gateway = g_strdup ("0.0.0.0");

		for (i = 0; i < addresses->len; i++) {
			NMIPAddress *addr = addresses->pdata[i];
			char *addrtmp;

			addrtmp = g_strdup_printf ("%sIP4_ADDRESS_%d=%s/%d %s", prefix, i,
			                           nm_ip_address_get_address (addr),
			                           nm_ip_address_get_prefix (addr),
			                           gateway);
			items = g_slist_prepend (items, addrtmp);
		}
		if (addresses->len)
			items = g_slist_prepend (items, g_strdup_printf ("%sIP4_NUM_ADDRESSES=%d", prefix, addresses->len));

		/* Write gateway to a separate variable, too. */
		items = g_slist_prepend (items, g_strdup_printf ("%sIP4_GATEWAY=%s", prefix, gateway));

		g_ptr_array_unref (addresses);
		g_free (gateway);
		g_variant_unref (val);
	}

	/* DNS servers */
	val = g_variant_lookup_value (ip4_config, "nameservers", G_VARIANT_TYPE ("au"));
	if (val) {
		items = _list_append_val_strv (items, nm_utils_ip4_dns_from_variant (val),
		                               "%sIP4_NAMESERVERS=", prefix);
		g_variant_unref (val);
	}

	/* Search domains */
	items = add_domains (items, ip4_config, prefix, '4');

	/* WINS servers */
	val = g_variant_lookup_value (ip4_config, "wins-servers", G_VARIANT_TYPE ("au"));
	if (val) {
		items = _list_append_val_strv (items, nm_utils_ip4_dns_from_variant (val),
		                               "%sIP4_WINS_SERVERS=", prefix);
		g_variant_unref (val);
	}

	/* Static routes */
	val = g_variant_lookup_value (ip4_config, "routes", G_VARIANT_TYPE ("aau"));
	if (val) {
		routes = nm_utils_ip4_routes_from_variant (val);

		for (i = 0; i < routes->len; i++) {
			NMIPRoute *route = routes->pdata[i];
			const char *next_hop;
			char *routetmp;

			next_hop = nm_ip_route_get_next_hop (route);
			if (!next_hop)
				next_hop = "0.0.0.0";

			routetmp = g_strdup_printf ("%sIP4_ROUTE_%d=%s/%d %s %u", prefix, i,
			                            nm_ip_route_get_dest (route),
			                            nm_ip_route_get_prefix (route),
			                            next_hop,
			                            (guint32) MAX (0, nm_ip_route_get_metric (route)));
			items = g_slist_prepend (items, routetmp);
		}
		items = g_slist_prepend (items, g_strdup_printf ("%sIP4_NUM_ROUTES=%d", prefix, routes->len));
		g_ptr_array_unref (routes);
		g_variant_unref (val);
	} else
		items = g_slist_prepend (items, g_strdup_printf ("%sIP4_NUM_ROUTES=0", prefix));

	return items;
}

static GSList *
construct_device_dhcp4_items (GSList *items, GVariant *dhcp4_config)
{
	GVariantIter iter;
	const char *key, *tmp;
	GVariant *val;
	char *ucased;

	if (dhcp4_config == NULL)
		return items;

	g_variant_iter_init (&iter, dhcp4_config);
	while (g_variant_iter_next (&iter, "{&sv}", &key, &val)) {
		ucased = g_ascii_strup (key, -1);
		tmp = g_variant_get_string (val, NULL);
		items = g_slist_prepend (items, g_strdup_printf ("DHCP4_%s=%s", ucased, tmp));
		g_free (ucased);
		g_variant_unref (val);
	}
	return items;
}

static GSList *
construct_ip6_items (GSList *items, GVariant *ip6_config, const char *prefix)
{
	GPtrArray *addresses, *routes;
	char *gateway = NULL;
	GVariant *val;
	int i;

	if (ip6_config == NULL)
		return items;

	if (prefix == NULL)
		prefix = "";

	/* IP addresses */
	val = g_variant_lookup_value (ip6_config, "addresses", G_VARIANT_TYPE ("a(ayuay)"));
	if (val) {
		addresses = nm_utils_ip6_addresses_from_variant (val, &gateway);
		if (!gateway)
			gateway = g_strdup ("::");

		for (i = 0; i < addresses->len; i++) {
			NMIPAddress *addr = addresses->pdata[i];
			char *addrtmp;

			addrtmp = g_strdup_printf ("%sIP6_ADDRESS_%d=%s/%d %s", prefix, i,
			                           nm_ip_address_get_address (addr),
			                           nm_ip_address_get_prefix (addr),
			                           gateway);
			items = g_slist_prepend (items, addrtmp);
		}
		if (addresses->len)
			items = g_slist_prepend (items, g_strdup_printf ("%sIP6_NUM_ADDRESSES=%d", prefix, addresses->len));

		/* Write gateway to a separate variable, too. */
		items = g_slist_prepend (items, g_strdup_printf ("%sIP6_GATEWAY=%s", prefix, gateway));

		g_ptr_array_unref (addresses);
		g_free (gateway);
		g_variant_unref (val);
	}

	/* DNS servers */
	val = g_variant_lookup_value (ip6_config, "nameservers", G_VARIANT_TYPE ("aay"));
	if (val) {
		items = _list_append_val_strv (items, nm_utils_ip6_dns_from_variant (val),
		                               "%sIP6_NAMESERVERS=", prefix);
		g_variant_unref (val);
	}

	/* Search domains */
	items = add_domains (items, ip6_config, prefix, '6');

	/* Static routes */
	val = g_variant_lookup_value (ip6_config, "routes", G_VARIANT_TYPE ("a(ayuayu)"));
	if (val) {
		routes = nm_utils_ip6_routes_from_variant (val);

		for (i = 0; i < routes->len; i++) {
			NMIPRoute *route = routes->pdata[i];
			const char *next_hop;
			char *routetmp;

			next_hop = nm_ip_route_get_next_hop (route);
			if (!next_hop)
				next_hop = "::";

			routetmp = g_strdup_printf ("%sIP6_ROUTE_%d=%s/%d %s %u", prefix, i,
			                            nm_ip_route_get_dest (route),
			                            nm_ip_route_get_prefix (route),
			                            next_hop,
			                            (guint32) MAX (0, nm_ip_route_get_metric (route)));
			items = g_slist_prepend (items, routetmp);
		}
		if (routes->len)
			items = g_slist_prepend (items, g_strdup_printf ("%sIP6_NUM_ROUTES=%d", prefix, routes->len));
		g_ptr_array_unref (routes);
		g_variant_unref (val);
	}

	return items;
}

static GSList *
construct_device_dhcp6_items (GSList *items, GVariant *dhcp6_config)
{
	GVariantIter iter;
	const char *key, *tmp;
	GVariant *val;
	char *ucased;

	if (dhcp6_config == NULL)
		return items;

	g_variant_iter_init (&iter, dhcp6_config);
	while (g_variant_iter_next (&iter, "{&sv}", &key, &val)) {
		ucased = g_ascii_strup (key, -1);
		tmp = g_variant_get_string (val, NULL);
		items = g_slist_prepend (items, g_strdup_printf ("DHCP6_%s=%s", ucased, tmp));
		g_free (ucased);
	}
	return items;
}

char **
nm_dispatcher_utils_construct_envp (const char *action,
                                    GVariant *connection_dict,
                                    GVariant *connection_props,
                                    GVariant *device_props,
                                    GVariant *device_ip4_props,
                                    GVariant *device_ip6_props,
                                    GVariant *device_dhcp4_props,
                                    GVariant *device_dhcp6_props,
                                    const char *vpn_ip_iface,
                                    GVariant *vpn_ip4_props,
                                    GVariant *vpn_ip6_props,
                                    char **out_iface)
{
	const char *iface = NULL, *ip_iface = NULL;
	const char *uuid = NULL, *id = NULL, *path = NULL;
	const char *filename = NULL;
	gboolean external;
	NMDeviceState dev_state = NM_DEVICE_STATE_UNKNOWN;
	GVariant *value;
	char **envp = NULL, *path_item;
	GSList *items = NULL, *iter;
	guint i;
	GVariant *con_setting;

	g_return_val_if_fail (action != NULL, NULL);
	g_return_val_if_fail (out_iface != NULL, NULL);
	g_return_val_if_fail (*out_iface == NULL, NULL);

	/* Hostname changes don't require a device nor contain a connection */
	if (!strcmp (action, "hostname"))
		goto done;

	/* Connection properties */
	if (!g_variant_lookup (connection_props, NMD_CONNECTION_PROPS_PATH, "&o", &path)) {
		g_warning ("Missing or invalid required value " NMD_CONNECTION_PROPS_PATH "!");
		return NULL;
	}
	items = g_slist_prepend (items, g_strdup_printf ("CONNECTION_DBUS_PATH=%s", path));

	if (g_variant_lookup (connection_props, NMD_CONNECTION_PROPS_EXTERNAL, "b", &external) && external)
		items = g_slist_prepend (items, g_strdup ("CONNECTION_EXTERNAL=1"));

	if (g_variant_lookup (connection_props, NMD_CONNECTION_PROPS_FILENAME, "&s", &filename))
		items = g_slist_prepend (items, g_strdup_printf ("CONNECTION_FILENAME=%s", filename));


	/* Canonicalize the VPN interface name; "" is used when passing it through
	 * D-Bus so make sure that's fixed up here.
	 */
	if (vpn_ip_iface && !strlen (vpn_ip_iface))
		vpn_ip_iface = NULL;

	/* interface name */
	if (!g_variant_lookup (device_props, NMD_DEVICE_PROPS_INTERFACE, "&s", &iface)) {
		g_warning ("Missing or invalid required value " NMD_DEVICE_PROPS_INTERFACE "!");
		return NULL;
	}
	if (!*iface)
		iface = NULL;

	/* IP interface name */
	value = g_variant_lookup_value (device_props, NMD_DEVICE_PROPS_IP_INTERFACE, NULL);
	if (value) {
		if (!g_variant_is_of_type (value, G_VARIANT_TYPE_STRING)) {
			g_warning ("Invalid value " NMD_DEVICE_PROPS_IP_INTERFACE "!");
			return NULL;
		}
		g_variant_unref (value);
		(void) g_variant_lookup (device_props, NMD_DEVICE_PROPS_IP_INTERFACE, "&s", &ip_iface);
	}

	/* Device type */
	if (!g_variant_lookup (device_props, NMD_DEVICE_PROPS_TYPE, "u", NULL)) {
		g_warning ("Missing or invalid required value " NMD_DEVICE_PROPS_TYPE "!");
		return NULL;
	}

	/* Device state */
	value = g_variant_lookup_value (device_props, NMD_DEVICE_PROPS_STATE, G_VARIANT_TYPE_UINT32);
	if (!value) {
		g_warning ("Missing or invalid required value " NMD_DEVICE_PROPS_STATE "!");
		return NULL;
	}
	dev_state = g_variant_get_uint32 (value);
	g_variant_unref (value);

	/* device itself */
	if (!g_variant_lookup (device_props, NMD_DEVICE_PROPS_PATH, "o", NULL)) {
		g_warning ("Missing or invalid required value " NMD_DEVICE_PROPS_PATH "!");
		return NULL;
	}

	/* UUID and ID */
	con_setting = g_variant_lookup_value (connection_dict, NM_SETTING_CONNECTION_SETTING_NAME, NM_VARIANT_TYPE_SETTING);
	if (!con_setting) {
		g_warning ("Failed to read connection setting");
		return NULL;
	}

	if (!g_variant_lookup (con_setting, NM_SETTING_CONNECTION_UUID, "&s", &uuid)) {
		g_warning ("Connection hash did not contain the UUID");
		g_variant_unref (con_setting);
		return NULL;
	}

	if (!g_variant_lookup (con_setting, NM_SETTING_CONNECTION_ID, "&s", &id)) {
		g_warning ("Connection hash did not contain the ID");
		g_variant_unref (con_setting);
		return NULL;
	}

	items = construct_basic_items (items, uuid, id, iface, ip_iface);
	g_variant_unref (con_setting);

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

