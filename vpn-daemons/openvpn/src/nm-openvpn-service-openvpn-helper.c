/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */
/* nm-openvpn-service-openvpn-helper - helper called after OpenVPN established
 * a connection, uses DBUS to send information back to nm-openvpn-service
 *
 * Tim Niemueller [www.niemueller.de]
 * Based on work by Dan Williams <dcbw@redhat.com>
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
 * (C) Copyright 2005 Tim Niemueller
 *
 * $Id$
 * 
 */

#include <glib.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <regex.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <dbus/dbus-glib.h>
#include <NetworkManager.h>

#include "nm-openvpn-service.h"
#include "nm-utils.h"

/* These are here because nm-dbus-glib-types.h isn't exported */
#define DBUS_TYPE_G_ARRAY_OF_UINT          (dbus_g_type_get_collection ("GArray", G_TYPE_UINT))
#define DBUS_TYPE_G_ARRAY_OF_ARRAY_OF_UINT (dbus_g_type_get_collection ("GPtrArray", DBUS_TYPE_G_ARRAY_OF_UINT))

static void
helper_failed (DBusGConnection *connection, const char *reason)
{
	DBusGProxy *proxy;
	GError *err = NULL;

	nm_warning ("nm-openvpn-service-openvpn-helper did not receive a valid %s from openvpn", reason);

	proxy = dbus_g_proxy_new_for_name (connection,
								NM_DBUS_SERVICE_OPENVPN,
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
								NM_DBUS_SERVICE_OPENVPN,
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
addr_to_gvalue (const char *str)
{
	struct in_addr	temp_addr;
	GValue *val;

	/* Empty */
	if (!str || strlen (str) < 1)
		return NULL;

	if (inet_pton (AF_INET, str, &temp_addr) <= 0)
		return NULL;

	val = g_slice_new0 (GValue);
	g_value_init (val, G_TYPE_UINT);
	g_value_set_uint (val, temp_addr.s_addr);

	return val;
}

static GValue *
parse_addr_list (GValue *value_array, const char *str)
{
	char **split;
	int i;
	struct in_addr	temp_addr;
	GArray *array;

	/* Empty */
	if (!str || strlen (str) < 1)
		return value_array;

	if (value_array)
		array = (GArray *) g_value_get_boxed (value_array);
	else
		array = g_array_new (FALSE, FALSE, sizeof (guint));

	split = g_strsplit (str, " ", -1);
	for (i = 0; split[i]; i++) {
		if (inet_pton (AF_INET, split[i], &temp_addr) > 0)
			g_array_append_val (array, temp_addr.s_addr);
	}

	g_strfreev (split);

	if (!value_array && array->len > 0) {
		value_array = g_slice_new0 (GValue);
		g_value_init (value_array, DBUS_TYPE_G_UINT_ARRAY);
		g_value_set_boxed (value_array, array);
	}

	return value_array;
}

static GValue *
get_routes (void)
{
	GValue *value = NULL;
	GPtrArray *routes;
	char *tmp;
	int i;

#define BUFLEN 256

	routes = g_ptr_array_new ();

	for (i = 1; i < 256; i++) {
		GArray *array;
		char buf[BUFLEN];
		struct in_addr network;
		struct in_addr netmask;
		struct in_addr gateway = { 0, };
		guint32 prefix, metric = 0;

		snprintf (buf, BUFLEN, "route_network_%d", i);
		tmp = getenv (buf);
		if (!tmp || strlen (tmp) < 1)
			break;

		if (inet_pton (AF_INET, tmp, &network) <= 0) {
			nm_warning ("Ignoring invalid static route address '%s'", tmp ? tmp : "NULL");
			continue;
		}

		snprintf (buf, BUFLEN, "route_netmask_%d", i);
		tmp = getenv (buf);
		if (!tmp || inet_pton (AF_INET, tmp, &netmask) <= 0) {
			nm_warning ("Ignoring invalid static route netmask '%s'", tmp ? tmp : "NULL");
			continue;
		}

		snprintf (buf, BUFLEN, "route_gateway_%d", i);
		tmp = getenv (buf);
		/* gateway can be missing */
		if (tmp && (inet_pton (AF_INET, tmp, &gateway) <= 0)) {
			nm_warning ("Ignoring invalid static route gateway '%s'", tmp ? tmp : "NULL");
			continue;
		}

		snprintf (buf, BUFLEN, "route_metric_%d", i);
		tmp = getenv (buf);
		/* metric can be missing */
		if (tmp && strlen (tmp)) {
			long int tmp_metric;

			errno = 0;
			tmp_metric = strtol (tmp, NULL, 10);
			if (errno || tmp_metric < 0 || tmp_metric > G_MAXUINT32) {
				nm_warning ("Ignoring invalid static route metric '%s'", tmp);
				continue;
			}
			metric = (guint32) tmp_metric;
		}

		array = g_array_sized_new (FALSE, TRUE, sizeof (guint32), 4);
		g_array_append_val (array, network.s_addr);
		prefix = nm_utils_ip4_netmask_to_prefix (netmask.s_addr);
		g_array_append_val (array, prefix);
		g_array_append_val (array, gateway.s_addr);
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

int
main (int argc, char *argv[])
{
	DBusGConnection *connection;
	GHashTable *config;
	char *tmp;
	GValue *val;
	int i;
	GError *err = NULL;
	GValue *dns_list = NULL;
	GValue *nbns_list = NULL;
	GValue *dns_domain = NULL;
	struct in_addr temp_addr;

	g_type_init ();

	connection = dbus_g_bus_get (DBUS_BUS_SYSTEM, &err);
	if (!connection) {
		nm_warning ("Could not get the system bus: %s", err->message);
		exit (1);
	}

	config = g_hash_table_new (g_str_hash, g_str_equal);

	/* Gateway */
	val = addr_to_gvalue (getenv ("trusted_ip"));
	if (val)
		g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_GATEWAY, val);
	else
		helper_failed (connection, "VPN Gateway");

	/* Tunnel device */
	val = str_to_gvalue (getenv ("dev"), FALSE);
	if (val)
		g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_TUNDEV, val);
	else
		helper_failed (connection, "Tunnel Device");

	/* IP address */
	val = addr_to_gvalue (getenv ("ifconfig_local"));
	if (val)
		g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_ADDRESS, val);
	else
		helper_failed (connection, "IP4 Address");

	/* PTP address; for vpnc PTP address == internal IP4 address */
	val = addr_to_gvalue (getenv ("ifconfig_remote"));
	if (val)
		g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_PTP, val);

	/* Netmask */
	tmp = getenv ("route_netmask_1");
	if (tmp && inet_pton (AF_INET, tmp, &temp_addr) > 0) {
		GValue *val;

		val = g_slice_new0 (GValue);
		g_value_init (val, G_TYPE_UINT);
		g_value_set_uint (val, nm_utils_ip4_netmask_to_prefix (temp_addr.s_addr));

		g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_PREFIX, val);
	}

	val = get_routes ();
	if (val)
		g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_ROUTES, val);

    	/* DNS and WINS servers */
	for (i = 1; i < 256; i++) {
		char *env_name;

		env_name = g_strdup_printf ("foreign_option_%d", i);
		tmp = getenv (env_name);
		g_free (env_name);

		if (!tmp || strlen (tmp) < 1)
			break;

		if (!g_str_has_prefix (tmp, "dhcp-option "))
			continue;

		tmp += 12; /* strlen ("dhcp-option ") */

		if (g_str_has_prefix (tmp, "DNS "))
			dns_list = parse_addr_list (dns_list, tmp + 4);
		else if (g_str_has_prefix (tmp, "WINS "))
			nbns_list = parse_addr_list (nbns_list, tmp + 5);
		else if (g_str_has_prefix (tmp, "DOMAIN ") && !dns_domain)
			dns_domain = str_to_gvalue (tmp + 7, FALSE);
	}

	if (dns_list)
		g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_DNS, dns_list);
	if (nbns_list)
		g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_NBNS, nbns_list);
	if (dns_domain)
		g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_DOMAIN, dns_domain);

	/* Send the config info to nm-openvpn-service */
	send_ip4_config (connection, config);

	return 0;
}
