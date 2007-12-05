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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
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

	if (!inet_aton (str, &temp_addr))
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
		if (inet_aton (split[i], &temp_addr))
			g_array_append_val (array, temp_addr.s_addr);
	}

	g_strfreev (split);

	if (!value_array && array->len > 1) {
		value_array = g_slice_new0 (GValue);
		g_value_init (value_array, DBUS_TYPE_G_UINT_ARRAY);
		g_value_set_boxed (value_array, array);
	}

	return value_array;
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
	else
		helper_failed (connection, "IP4 PTP Address");

	/* Netmask */
	val = addr_to_gvalue (getenv ("route_netmask_1"));
	if (val)
		g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_NETMASK, val);

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
	}

	if (dns_list)
		g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_DNS, dns_list);
	if (nbns_list)
		g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_NBNS, nbns_list);

	/* Send the config info to nm-openvpn-service */
	send_ip4_config (connection, config);

	return 0;
}
