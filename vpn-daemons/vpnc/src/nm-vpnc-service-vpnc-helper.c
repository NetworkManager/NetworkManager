/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */
/* nm-vpnc-service - vpnc integration with NetworkManager
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
 * (C) Copyright 2005 Red Hat, Inc.
 */

#include <glib.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <dbus/dbus-glib.h>
#include <NetworkManager.h>

#include "nm-vpnc-service.h"
#include "nm-utils.h"

/* These are here because nm-dbus-glib-types.h isn't exported */
#define DBUS_TYPE_G_ARRAY_OF_UINT          (dbus_g_type_get_collection ("GArray", G_TYPE_UINT))
#define DBUS_TYPE_G_ARRAY_OF_ARRAY_OF_UINT (dbus_g_type_get_collection ("GPtrArray", DBUS_TYPE_G_ARRAY_OF_UINT))

static void
helper_failed (DBusGConnection *connection, const char *reason)
{
	DBusGProxy *proxy;
	GError *err = NULL;

	nm_warning ("nm-nvpnc-service-vpnc-helper did not receive a valid %s from vpnc", reason);

	proxy = dbus_g_proxy_new_for_name (connection,
								NM_DBUS_SERVICE_VPNC,
								NM_VPN_DBUS_PLUGIN_PATH,
								NM_VPN_DBUS_PLUGIN_INTERFACE);

	dbus_g_proxy_call (proxy, "SetFailure", &err,
				    G_TYPE_STRING, reason,
				    G_TYPE_INVALID,
				    G_TYPE_INVALID);

	if (err) {
		nm_warning ("Could not send failure information: %s", err->message);
		g_error_free (err);
	}

	g_object_unref (proxy);

	exit (1);
}

static void
send_ip4_config (DBusGConnection *connection, GHashTable *config)
{
	DBusGProxy *proxy;
	GError *err = NULL;

	proxy = dbus_g_proxy_new_for_name (connection,
								NM_DBUS_SERVICE_VPNC,
								NM_VPN_DBUS_PLUGIN_PATH,
								NM_VPN_DBUS_PLUGIN_INTERFACE);

	dbus_g_proxy_call (proxy, "SetIp4Config", &err,
				    dbus_g_type_get_map ("GHashTable", G_TYPE_STRING, G_TYPE_VALUE),
				    config,
				    G_TYPE_INVALID,
				    G_TYPE_INVALID);

	if (err) {
		nm_warning ("Could not send failure information: %s", err->message);
		g_error_free (err);
	}

	g_object_unref (proxy);
}

static GValue *
str_to_gvalue (const char *str, gboolean try_convert)
{
	GValue *val;

	/* Empty */
	if (!str || strlen (str) < 1)
		return NULL;

	if (!g_utf8_validate (str, -1, NULL)) {
		if (try_convert && !(str = g_convert (str, -1, "ISO-8859-1", "UTF-8", NULL, NULL, NULL)))
			str = g_convert (str, -1, "C", "UTF-8", NULL, NULL, NULL);

		if (!str)
			/* Invalid */
			return NULL;
	}

	val = g_slice_new0 (GValue);
	g_value_init (val, G_TYPE_STRING);
	g_value_set_string (val, str);

	return val;
}

static GValue *
uint_to_gvalue (guint32 num)
{
	GValue *val;

	if (num == 0)
		return NULL;

	val = g_slice_new0 (GValue);
	g_value_init (val, G_TYPE_UINT);
	g_value_set_uint (val, num);

	return val;
}

static GValue *
addr_to_gvalue (const char *str)
{
	struct in_addr	temp_addr;

	/* Empty */
	if (!str || strlen (str) < 1)
		return NULL;

	if (inet_pton (AF_INET, str, &temp_addr) <= 0)
		return NULL;

	return uint_to_gvalue (temp_addr.s_addr);
}

static GValue *
addr_list_to_gvalue (const char *str)
{
	GValue *val;
	char **split;
	int i;
	GArray *array;

	/* Empty */
	if (!str || strlen (str) < 1)
		return NULL;

	split = g_strsplit (str, " ", -1);
	if (g_strv_length (split) == 0)
		return NULL;

	array = g_array_sized_new (FALSE, TRUE, sizeof (guint32), g_strv_length (split));
	for (i = 0; split[i]; i++) {
		struct in_addr addr;

		if (inet_pton (AF_INET, split[i], &addr) > 0) {
			g_array_append_val (array, addr.s_addr);
		} else {
			g_strfreev (split);
			g_array_free (array, TRUE);
			return NULL;
		}
	}

	g_strfreev (split);

	val = g_slice_new0 (GValue);
	g_value_init (val, DBUS_TYPE_G_UINT_ARRAY);
	g_value_set_boxed (val, array);

	return val;
}

static GValue *
get_routes (void)
{
	GValue *value = NULL;
	GPtrArray *routes;
	char *tmp;
	int num;
	int i;

#define BUFLEN 256

	tmp = getenv ("CISCO_SPLIT_INC");
	if (!tmp || strlen (tmp) < 1)
		return NULL;

	num = atoi (tmp);
	if (!num)
		return NULL;

	routes = g_ptr_array_new ();

	for (i = 0; i < num; i++) {
		GArray *array;
		char buf[BUFLEN];
		struct in_addr network;
		guint32 next_hop = 0; /* no next hop */
		guint32 prefix, metric = 0;

		snprintf (buf, BUFLEN, "CISCO_SPLIT_INC_%d_ADDR", i);
		tmp = getenv (buf);
		if (!tmp || inet_pton (AF_INET, tmp, &network) <= 0) {
			nm_warning ("Ignoring invalid static route address '%s'", tmp ? tmp : "NULL");
			continue;
		}

		snprintf (buf, BUFLEN, "CISCO_SPLIT_INC_%d_MASKLEN", i);
		tmp = getenv (buf);
		if (tmp) {
			long int tmp_prefix;

			errno = 0;
			tmp_prefix = strtol (tmp, NULL, 10);
			if (errno || tmp_prefix <= 0 || tmp_prefix > 32) {
				nm_warning ("Ignoring invalid static route prefix '%s'", tmp ? tmp : "NULL");
				continue;
			}
			prefix = (guint32) tmp_prefix;
		} else {
			struct in_addr netmask;

			snprintf (buf, BUFLEN, "CISCO_SPLIT_INC_%d_MASK", i);
			tmp = getenv (buf);
			if (!tmp || inet_pton (AF_INET, tmp, &netmask) <= 0) {
				nm_warning ("Ignoring invalid static route netmask '%s'", tmp ? tmp : "NULL");
				continue;
			}
			prefix = nm_utils_ip4_netmask_to_prefix (netmask.s_addr);
		}

		array = g_array_sized_new (FALSE, TRUE, sizeof (guint32), 4);
		g_array_append_val (array, network.s_addr);
		g_array_append_val (array, prefix);
		g_array_append_val (array, next_hop);
		g_array_append_val (array, metric);
		g_ptr_array_add (routes, array);
	}

	if (routes->len > 0) {
		value = g_new0 (GValue, 1);
		g_value_init (value, DBUS_TYPE_G_ARRAY_OF_ARRAY_OF_UINT);
		g_value_take_boxed (value, routes);
	} else
		g_ptr_array_free (routes, TRUE);

	return value;
}

/*
 * Environment variables passed back from 'vpnc':
 *
 * VPNGATEWAY             -- vpn gateway address (always present)
 * TUNDEV                 -- tunnel device (always present)
 * INTERNAL_IP4_ADDRESS   -- address (always present)
 * INTERNAL_IP4_NETMASK   -- netmask (often unset)
 * INTERNAL_IP4_DNS       -- list of dns serverss
 * INTERNAL_IP4_NBNS      -- list of wins servers
 * CISCO_DEF_DOMAIN       -- default domain name
 * CISCO_BANNER           -- banner from server
 *
 */
int 
main (int argc, char *argv[])
{
	DBusGConnection *connection;
	char *tmp;
	GHashTable *config;
	GValue *val;
	GError *err = NULL;
	struct in_addr temp_addr;

	g_type_init ();

	/* vpnc 0.3.3 gives us a "reason" code.  If we are given one,
	 * don't proceed unless its "connect".
	 */
	tmp = getenv ("reason");
	if (tmp && strcmp (tmp, "connect") != 0)
		exit (0);

	connection = dbus_g_bus_get (DBUS_BUS_SYSTEM, &err);
	if (!connection) {
		nm_warning ("Could not get the system bus: %s", err->message);
		exit (1);
	}

	config = g_hash_table_new (g_str_hash, g_str_equal);

	/* Gateway */
	val = addr_to_gvalue (getenv ("VPNGATEWAY"));
	if (val)
		g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_GATEWAY, val);
	else
		helper_failed (connection, "VPN Gateway");

	/* Tunnel device */
	val = str_to_gvalue (getenv ("TUNDEV"), FALSE);
	if (val)
		g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_TUNDEV, val);
	else
		helper_failed (connection, "Tunnel Device");

	/* IP address */
	val = addr_to_gvalue (getenv ("INTERNAL_IP4_ADDRESS"));
	if (val)
		g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_ADDRESS, val);
	else
		helper_failed (connection, "IP4 Address");

	/* PTP address; for vpnc PTP address == internal IP4 address */
	val = addr_to_gvalue (getenv ("INTERNAL_IP4_ADDRESS"));
	if (val)
		g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_PTP, val);
	else
		helper_failed (connection, "IP4 PTP Address");

	/* Netmask */
	tmp = getenv ("INTERNAL_IP4_NETMASK");
	if (tmp && inet_pton (AF_INET, tmp, &temp_addr) > 0) {
		GValue *val;

		val = g_slice_new0 (GValue);
		g_value_init (val, G_TYPE_UINT);
		g_value_set_uint (val, nm_utils_ip4_netmask_to_prefix (temp_addr.s_addr));

		g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_PREFIX, val);
	}

	/* DNS */
	val = addr_list_to_gvalue (getenv ("INTERNAL_IP4_DNS"));
	if (val)
		g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_DNS, val);

	/* WINS servers */
	val = addr_list_to_gvalue (getenv ("INTERNAL_IP4_NBNS"));
	if (val)
		g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_NBNS, val);

	/* Default domain */
	val = str_to_gvalue (getenv ("CISCO_DEF_DOMAIN"), TRUE);
	if (val)
		g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_DOMAIN, val);

	/* Routes */
	val = get_routes ();
	if (val)
		g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_ROUTES, val);

	/* Banner */
	val = str_to_gvalue (getenv ("CISCO_BANNER"), TRUE);
	if (val)
		g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_BANNER, val);

	/* Set MTU to 1412 */
	val = uint_to_gvalue (1412);
	if (val)
		g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_MTU, val);

	/* Send the config info to nm-vpnc-service */
	send_ip4_config (connection, config);

	exit (0);
}
