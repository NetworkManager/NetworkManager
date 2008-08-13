/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

/* NetworkManager -- Network link manager
 *
 * Dan Williams <dcbw@redhat.com>
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
 * (C) Copyright 2004 Red Hat, Inc.
 */

#include <glib.h>
#include <stdio.h>
#include <string.h>

#include "NetworkManagerUtils.h"
#include "nm-utils.h"
#include "nm-device.h"
#include "nm-device-wifi.h"
#include "nm-device-ethernet.h"
#include "nm-dbus-manager.h"
#include "nm-dispatcher-action.h"
#include "nm-dbus-glib-types.h"

#include <netlink/addr.h>
#include <netinet/in.h>

/*
 * nm_ethernet_address_is_valid
 *
 * Compares an Ethernet address against known invalid addresses.
 *
 */
gboolean
nm_ethernet_address_is_valid (const struct ether_addr *test_addr)
{
	guint8 invalid_addr1[ETH_ALEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	guint8 invalid_addr2[ETH_ALEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	guint8 invalid_addr3[ETH_ALEN] = {0x44, 0x44, 0x44, 0x44, 0x44, 0x44};
	guint8 invalid_addr4[ETH_ALEN] = {0x00, 0x30, 0xb4, 0x00, 0x00, 0x00}; /* prism54 dummy MAC */

	g_return_val_if_fail (test_addr != NULL, FALSE);

	/* Compare the AP address the card has with invalid ethernet MAC addresses. */
	if (!memcmp (test_addr->ether_addr_octet, &invalid_addr1, ETH_ALEN))
		return FALSE;

	if (!memcmp (test_addr->ether_addr_octet, &invalid_addr2, ETH_ALEN))
		return FALSE;

	if (!memcmp (test_addr->ether_addr_octet, &invalid_addr3, ETH_ALEN))
		return FALSE;

	if (!memcmp (test_addr->ether_addr_octet, &invalid_addr4, ETH_ALEN))
		return FALSE;

	if (test_addr->ether_addr_octet[0] & 1)			/* Multicast addresses */
		return FALSE;
	
	return TRUE;
}


int
nm_spawn_process (const char *args)
{
	gint num_args;
	char **argv = NULL;
	int status = -1;
	GError *error = NULL;

	g_return_val_if_fail (args != NULL, -1);

	if (!g_shell_parse_argv (args, &num_args, &argv, &error)) {
		nm_warning ("could not parse arguments for '%s': %s", args, error->message);
		g_error_free (error);
		return -1;
	}

	if (!g_spawn_sync ("/", argv, NULL, 0, NULL, NULL, NULL, NULL, &status, &error)) {
		nm_warning ("could not spawn process '%s': %s", args, error->message);
		g_error_free (error);
	}

	g_strfreev (argv);
	return status;
}

void
nm_print_device_capabilities (NMDevice *dev)
{
	gboolean		full_support = TRUE;
	guint32		caps;
	const char *	driver = NULL;

	g_return_if_fail (dev != NULL);

	caps = nm_device_get_capabilities (dev);
	driver = nm_device_get_driver (dev);
	if (!driver)
		driver = "<unknown>";

	if (caps == NM_DEVICE_CAP_NONE || !(NM_DEVICE_CAP_NM_SUPPORTED)) {
		nm_info ("%s: driver '%s' is unsupported",
				nm_device_get_iface (dev), driver);
		return;
	}

	if (NM_IS_DEVICE_ETHERNET (dev)) {
		if (!(caps & NM_DEVICE_CAP_CARRIER_DETECT)) {
			nm_info ("%s: driver '%s' does not support carrier detection.\n"
					"\tYou must switch to it manually.",
					nm_device_get_iface (dev), driver);
			full_support = FALSE;
		}
	} else if (NM_IS_DEVICE_WIFI (dev)) {
		/* Print out WPA support */
	}

	if (full_support) {
		nm_info ("%s: driver is '%s'.",
				nm_device_get_iface (dev), driver);
	}
}


struct nl_addr *
nm_utils_ip4_addr_to_nl_addr (guint32 ip4_addr)
{
	struct nl_addr * nla = NULL;

	if (!(nla = nl_addr_alloc (sizeof (in_addr_t))))
		return NULL;
	nl_addr_set_family (nla, AF_INET);
	nl_addr_set_binary_addr (nla, &ip4_addr, sizeof (guint32));

	return nla;
}

/*
 * nm_utils_ip4_netmask_to_prefix
 *
 * Figure out the network prefix from a netmask.  Netmask
 * MUST be in network byte order.
 *
 */
guint32
nm_utils_ip4_netmask_to_prefix (guint32 netmask)
{
	guchar *p, *end;
	guint32 prefix = 0;

	p = (guchar *) &netmask;
	end = p + sizeof (guint32);

	while ((*p == 0xFF) && p < end) {
		prefix += 8;
		p++;
	}

	if (p < end) {
		guchar v = *p;

		while (v) {
			prefix++;
			v <<= 1;
		}
	}

	return prefix;
}

/*
 * nm_utils_ip4_prefix_to_netmask
 *
 * Figure out the netmask from a prefix.
 *
 */
guint32
nm_utils_ip4_prefix_to_netmask (guint32 prefix)
{
	guint32 msk = 0x80000000;
	guint32 netmask = 0;

	while (prefix > 0) {
		netmask |= msk;
		msk >>= 1;
		prefix--;
	}

	return (guint32) htonl (netmask);
}


/* From hostap, Copyright (c) 2002-2005, Jouni Malinen <jkmaline@cc.hut.fi> */

static int hex2num (char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

static int hex2byte (const char *hex)
{
	int a, b;
	a = hex2num(*hex++);
	if (a < 0)
		return -1;
	b = hex2num(*hex++);
	if (b < 0)
		return -1;
	return (a << 4) | b;
}

char *
nm_utils_hexstr2bin (const char *hex,
                     size_t len)
{
	size_t       i;
	int          a;
	const char * ipos = hex;
	char *       buf = NULL;
	char *       opos;

	/* Length must be a multiple of 2 */
	if ((len % 2) != 0)
		return NULL;

	opos = buf = g_malloc0 ((len / 2) + 1);
	for (i = 0; i < len; i += 2) {
		a = hex2byte (ipos);
		if (a < 0) {
			g_free (buf);
			return NULL;
		}
		*opos++ = a;
		ipos += 2;
	}
	return buf;
}

/* End from hostap */

char *
nm_ether_ntop (const struct ether_addr *mac)
{
	/* we like leading zeros and all-caps, instead
	 * of what glibc's ether_ntop() gives us
	 */
	return g_strdup_printf ("%02X:%02X:%02X:%02X:%02X:%02X",
	                        mac->ether_addr_octet[0], mac->ether_addr_octet[1],
	                        mac->ether_addr_octet[2], mac->ether_addr_octet[3],
	                        mac->ether_addr_octet[4], mac->ether_addr_octet[5]);
}

void
nm_utils_merge_ip4_config (NMIP4Config *ip4_config, NMSettingIP4Config *setting)
{
	GSList *iter;

	if (!setting)
		return; /* Defaults are just fine */

	if (setting->ignore_auto_dns) {
		nm_ip4_config_reset_nameservers (ip4_config);
		nm_ip4_config_reset_searches (ip4_config);
	}

	if (setting->ignore_auto_routes)
		nm_ip4_config_reset_routes (ip4_config);

	if (setting->dns) {
		int i, j;

		for (i = 0; i < setting->dns->len; i++) {
			guint32 ns;
			gboolean found = FALSE;

			/* Avoid dupes */
			ns = g_array_index (setting->dns, guint32, i);
			for (j = 0; j < nm_ip4_config_get_num_nameservers (ip4_config); j++) {
				if (nm_ip4_config_get_nameserver (ip4_config, j) == ns) {
					found = TRUE;
					break;
				}
			}

			if (!found)
				nm_ip4_config_add_nameserver (ip4_config, ns);
		}
	}

	/* DNS search domains */
	for (iter = setting->dns_search; iter; iter = iter->next) {
		int i;
		gboolean found = FALSE;

		/* Avoid dupes */
		for (i = 0; i < nm_ip4_config_get_num_searches (ip4_config); i++) {
			const char *search = nm_ip4_config_get_search (ip4_config, i);

			if (!strcmp (search, (char *) iter->data)) {
				found = TRUE;
				break;
			}
		}

		if (!found)
			nm_ip4_config_add_search (ip4_config, (char *) iter->data);
	}

	/* IPv4 addresses */
	for (iter = setting->addresses; iter; iter = g_slist_next (iter)) {
		NMSettingIP4Address *setting_addr = (NMSettingIP4Address *) iter->data;
		guint32 i, num;

		num = nm_ip4_config_get_num_addresses (ip4_config);
		for (i = 0; i < num; i++) {
			const NMSettingIP4Address *cfg_addr;

			cfg_addr = nm_ip4_config_get_address (ip4_config, i);
			/* Dupe, override with user-specified address */
			if (cfg_addr->address == setting_addr->address) {
				nm_ip4_config_replace_address (ip4_config, i, setting_addr);
				break;
			}
		}

		if (i == num)
			nm_ip4_config_add_address (ip4_config, setting_addr);
	}

	/* IPv4 routes */
	for (iter = setting->routes; iter; iter = g_slist_next (iter)) {
		NMSettingIP4Route *setting_route = (NMSettingIP4Route *) iter->data;
		guint32 i, num;

		num = nm_ip4_config_get_num_routes (ip4_config);
		for (i = 0; i < num; i++) {
			const NMSettingIP4Route *cfg_route;

			cfg_route = nm_ip4_config_get_route (ip4_config, i);
			/* Dupe, override with user-specified route */
			if (   (cfg_route->address == setting_route->address)
			    && (cfg_route->prefix == setting_route->prefix)
			    && (cfg_route->next_hop == setting_route->next_hop)) {
				nm_ip4_config_replace_route (ip4_config, i, setting_route);
				break;
			}
		}

		if (i == num)
			nm_ip4_config_add_route (ip4_config, setting_route);
	}
}

static void
nm_gvalue_destroy (gpointer data)
{
	GValue *value = (GValue *) data;

	g_value_unset (value);
	g_slice_free (GValue, value);
}

static GValue *
str_to_gvalue (const char *str)
{
	GValue *value;

	value = g_slice_new0 (GValue);
	g_value_init (value, G_TYPE_STRING);
	g_value_set_string (value, str);
	return value;
}

static GValue *
op_to_gvalue (const char *op)
{
	GValue *value;

	value = g_slice_new0 (GValue);
	g_value_init (value, DBUS_TYPE_G_OBJECT_PATH);
	g_value_set_boxed (value, op);
	return value;
}

static GValue *
uint_to_gvalue (guint32 val)
{
	GValue *value;

	value = g_slice_new0 (GValue);
	g_value_init (value, G_TYPE_UINT);
	g_value_set_uint (value, val);
	return value;
}

void
nm_utils_call_dispatcher (const char *action,
                          NMConnection *connection,
                          NMDevice *device,
                          const char *vpn_iface)
{
	NMDBusManager *dbus_mgr;
	DBusGProxy *proxy;
	DBusGConnection *g_connection;
	GHashTable *connection_hash;
	GHashTable *connection_props;
	GHashTable *device_props;

	g_return_if_fail (action != NULL);
	g_return_if_fail (NM_IS_DEVICE (device));

	dbus_mgr = nm_dbus_manager_get ();
	g_connection = nm_dbus_manager_get_connection (dbus_mgr);
	proxy = dbus_g_proxy_new_for_name (g_connection,
	                                   NM_DISPATCHER_DBUS_SERVICE,
	                                   NM_DISPATCHER_DBUS_PATH,
	                                   NM_DISPATCHER_DBUS_IFACE);
	if (!proxy) {
		nm_warning ("Error: could not get dispatcher proxy!");
		g_object_unref (dbus_mgr);
		return;
	}

	if (connection) {
		connection_hash = nm_connection_to_hash (connection);

		connection_props = g_hash_table_new_full (g_str_hash, g_str_equal,
		                                          NULL, nm_gvalue_destroy);

		/* Service name */
		if (nm_connection_get_scope (connection) == NM_CONNECTION_SCOPE_USER) {
			g_hash_table_insert (connection_props,
			                     NMD_CONNECTION_PROPS_SERVICE_NAME,
			                     str_to_gvalue (NM_DBUS_SERVICE_USER_SETTINGS));
		} else if (nm_connection_get_scope (connection) == NM_CONNECTION_SCOPE_USER) {
			g_hash_table_insert (connection_props,
			                     NMD_CONNECTION_PROPS_SERVICE_NAME,
			                     str_to_gvalue (NM_DBUS_SERVICE_SYSTEM_SETTINGS));
		}

		/* path */
		g_hash_table_insert (connection_props,
		                     NMD_CONNECTION_PROPS_PATH,
		                     op_to_gvalue (nm_connection_get_path (connection)));
	} else {
		connection_hash = g_hash_table_new (g_direct_hash, g_direct_equal);
		connection_props = g_hash_table_new (g_direct_hash, g_direct_equal);
	}

	device_props = g_hash_table_new_full (g_str_hash, g_str_equal,
	                                      NULL, nm_gvalue_destroy);

	/* interface */
	g_hash_table_insert (device_props, NMD_DEVICE_PROPS_INTERFACE,
	                     str_to_gvalue (nm_device_get_iface (device)));

	/* IP interface */
	if (vpn_iface) {
		g_hash_table_insert (device_props, NMD_DEVICE_PROPS_IP_INTERFACE,
		                     str_to_gvalue (vpn_iface));
	} else if (nm_device_get_ip_iface (device)) {
		g_hash_table_insert (device_props, NMD_DEVICE_PROPS_IP_INTERFACE,
		                     str_to_gvalue (nm_device_get_ip_iface (device)));
	}

	/* type */
	g_hash_table_insert (device_props, NMD_DEVICE_PROPS_TYPE,
	                     uint_to_gvalue (nm_device_get_device_type (device)));

	/* state */
	g_hash_table_insert (device_props, NMD_DEVICE_PROPS_STATE,
	                     uint_to_gvalue (nm_device_get_state (device)));

	g_hash_table_insert (device_props, NMD_DEVICE_PROPS_PATH,
	                     op_to_gvalue (nm_device_get_udi (device)));

	dbus_g_proxy_call_no_reply (proxy, "Action",
	                            G_TYPE_STRING, action,
	                            DBUS_TYPE_G_MAP_OF_MAP_OF_VARIANT, connection_hash,
	                            DBUS_TYPE_G_MAP_OF_VARIANT, connection_props,
	                            DBUS_TYPE_G_MAP_OF_VARIANT, device_props,
	                            G_TYPE_INVALID);

	g_hash_table_destroy (connection_hash);
	g_hash_table_destroy (connection_props);
	g_hash_table_destroy (device_props);
	g_object_unref (proxy);
	g_object_unref (dbus_mgr);
}

