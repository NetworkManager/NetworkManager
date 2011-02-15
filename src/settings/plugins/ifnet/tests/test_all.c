/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager system settings service (ifnet)
 *
 * Mu Qiao <qiaomuf@gmail.com>
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
 * Copyright (C) 1999-2010 Gentoo Foundation, Inc.
 */

#include <stdio.h>
#include <string.h>
#include <glib.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <nm-utils.h>

#include "net_parser.h"
#include "nm-test-helpers.h"
#include "net_utils.h"
#include "wpa_parser.h"
#include "connection_parser.h"

static void
test_getdata ()
{
	ASSERT (ifnet_get_data ("eth1", "config")
		&& strcmp (ifnet_get_data ("eth1", "config"), "dhcp") == 0,
		"get data", "config_eth1 is not correct");
	ASSERT (ifnet_get_data ("ppp0", "username")
		&& strcmp (ifnet_get_data ("ppp0", "username"), "user") == 0,
		"get data", "config_ppp0 username is not correctly read");
	ASSERT (ifnet_get_data ("ppp0", "password")
		&& strcmp (ifnet_get_data ("ppp0", "password"),
			   "password") == 0, "get data",
		"config_ppp0 password is not correctly read");
}

static void
test_read_hostname ()
{
	gchar *hostname = read_hostname ("hostname");

	ASSERT (hostname != NULL, "get hostname", "hostname is NULL");
	ASSERT (strcmp ("gentoo", hostname) == 0,
		"get hostname",
		"hostname is not correctly read, read:%s, expected: gentoo",
		hostname);
	g_free (hostname);
}

static void
test_write_hostname ()
{
	gchar *hostname = read_hostname ("hostname");
	gchar *tmp;

	write_hostname ("gentoo-nm", "hostname");
	tmp = read_hostname ("hostname");
	ASSERT (strcmp (tmp, "gentoo-nm") == 0,
		"write hostname", "write hostname error");
	write_hostname (hostname, "hostname");
	g_free (tmp);
	g_free (hostname);
}

static void
test_is_static ()
{
	ASSERT (is_static_ip4 ("eth1") == FALSE, "is static",
		"a dhcp interface is recognized as static");
	ASSERT (is_static_ip4 ("eth0") == TRUE, "is static",
		"a static interface is recognized as dhcp");
	ASSERT (!is_static_ip6 ("eth0") == TRUE, "is static",
		"a static interface is recognized as dhcp");
}

static void
test_has_default_route ()
{
	ASSERT (has_default_ip4_route ("eth0"),
		"has default route", "eth0 should have a default ipv4 route");
	ASSERT (has_default_ip6_route ("eth4"),
		"has default route", "eth4 should have a default ipv6 route");
	ASSERT (!has_default_ip4_route ("eth5")
		&& !has_default_ip6_route ("eth5"),
		"has default route", "eth5 shouldn't have a default route");
}

static void
test_has_ip6_address ()
{
	ASSERT (has_ip6_address ("eth2"), "has ip6 address",
		"eth2 should have a ipv6 address");
	ASSERT (!has_ip6_address ("eth0"), "has ip6 address",
		"eth0 shouldn't have a ipv6 address")

}

static void
test_is_ip4_address ()
{
	gchar *address1 = "192.168.4.232/24";
	gchar *address2 = "192.168.100.{1..254}/24";
	gchar *address3 = "192.168.4.2555/24";

	ASSERT (is_ip4_address (address1), "is ip4 address",
		"%s should be a valid address", address1);
	ASSERT (is_ip4_address (address2), "is ip4 address",
		"%s should be a valid address", address2);
	ASSERT (!is_ip4_address (address3), "is ip4 address",
		"%s should be an invalid address", address3);
}

static void
test_is_ip6_address ()
{
	gchar *address1 = "4321:0:1:2:3:4:567:89ac/24";

	ASSERT (is_ip6_address (address1), "is ip6 address",
		"%s should be a valid address", address1);
}

static void
check_ip_block (ip_block * iblock, gchar * ip, gchar * netmask, gchar * gateway)
{
	char *str;
	struct in_addr tmp_ip4_addr;

	str = malloc (INET_ADDRSTRLEN);
	tmp_ip4_addr.s_addr = iblock->ip;
	inet_ntop (AF_INET, &tmp_ip4_addr, str, INET_ADDRSTRLEN);
	ASSERT (strcmp (ip, str) == 0, "check ip",
		"ip expected:%s, find:%s", ip, str);
	tmp_ip4_addr.s_addr = iblock->netmask;
	inet_ntop (AF_INET, &tmp_ip4_addr, str, INET_ADDRSTRLEN);
	ASSERT (strcmp (netmask, str) == 0, "check netmask",
		"netmask expected:%s, find:%s", netmask, str);
	tmp_ip4_addr.s_addr = iblock->gateway;
	inet_ntop (AF_INET, &tmp_ip4_addr, str, INET_ADDRSTRLEN);
	ASSERT (strcmp (gateway, str) == 0, "check gateway",
		"gateway expected:%s, find:%s", gateway, str);
	free (str);
}

static void
test_convert_ipv4_config_block ()
{
	ip_block *iblock = convert_ip4_config_block ("eth0");
	ip_block *tmp = iblock;

	ASSERT (iblock != NULL, "convert ipv4 block",
		"block eth0 should not be NULL");
	check_ip_block (iblock, "202.117.16.121", "255.255.255.0",
			"202.117.16.1");
	iblock = iblock->next;
	destroy_ip_block (tmp);
	ASSERT (iblock != NULL, "convert ipv4 block",
		"block eth0 should have a second IP address");
	check_ip_block (iblock, "192.168.4.121", "255.255.255.0",
			"202.117.16.1");
	destroy_ip_block (iblock);
	iblock = convert_ip4_config_block ("eth2");
	ASSERT (iblock != NULL
		&& iblock->next == NULL,
		"convert error IPv4 address", "should only get one address");
	check_ip_block (iblock, "192.168.4.121", "255.255.255.0", "0.0.0.0");
	destroy_ip_block (iblock);
	iblock = convert_ip4_config_block ("eth3");
	ASSERT (iblock == NULL, "convert config_block",
		"convert error configuration");
	destroy_ip_block (iblock);
	iblock = convert_ip4_config_block ("eth6");
	ASSERT (iblock != NULL, "convert config_block",
		"convert error configuration");
	destroy_ip_block (iblock);
}

static void
test_convert_ipv4_routes_block ()
{
	ip_block *iblock = convert_ip4_routes_block ("eth0");
	ip_block *tmp = iblock;

	ASSERT (iblock != NULL, "convert ip4 routes", "should get one route");
	check_ip_block (iblock, "192.168.4.0", "255.255.255.0", "192.168.4.1");
	iblock = iblock->next;
	destroy_ip_block (tmp);
	ASSERT (iblock == NULL, "convert ip4 routes",
		"should only get one route");
}

static void
test_wpa_parser ()
{
	const char *value;

	ASSERT (exist_ssid ("example"), "get wsec",
		"ssid myxjtu2 is not found");
	ASSERT (exist_ssid ("static-wep-test"), "exist_ssid",
		"ssid static-wep-test is not found");
	value = wpa_get_value ("static-wep-test", "key_mgmt");
	ASSERT (value
		&& strcmp (value, "NONE") == 0, "get wpa data",
		"key_mgmt of static-wep-test should be NONE, find %s", value);
	value = wpa_get_value ("static-wep-test", "wep_key0");
	ASSERT (value
		&& strcmp (value, "\"abcde\"") == 0,
		"get wpa data",
		"wep_key0 of static-wep-test should be abcde, find %s", value);
	ASSERT (exist_ssid ("leap-example"), "get wsec",
		"ssid leap-example is not found");
}

static void
test_strip_string ()
{
	gchar *str = "( \"default via     202.117.16.1\" )";
	gchar *result = g_strdup (str);
	gchar *result_b = result;

	result = strip_string (result, '(');
	result = strip_string (result, ')');
	result = strip_string (result, '"');
	ASSERT (strcmp (result, "default via     202.117.16.1") ==
		0, "strip_string",
		"string isn't stripped, result is: %s", result);
	g_free (result_b);
}

static void
test_is_unmanaged ()
{
	ASSERT (is_managed ("eth0"), "test_is_unmanaged",
		"eth0 should be managed");
	ASSERT (!is_managed ("eth4"), "test_is_unmanaged",
		"eth4 should be unmanaged");
}

static void
test_new_connection ()
{
	GError **error = NULL;
	NMConnection *connection;

	connection = ifnet_update_connection_from_config_block ("eth2", error);
	ASSERT (connection != NULL, "new connection",
		"new connection failed: %s",
		error == NULL ? "None" : (*error)->message);
	g_object_unref (connection);
	connection =
	    ifnet_update_connection_from_config_block ("qiaomuf", error);
	ASSERT (connection != NULL, "new connection",
		"new connection failed: %s", error
		&& (*error) ? (*error)->message : "NONE");
	g_object_unref (connection);
	connection =
	    ifnet_update_connection_from_config_block ("myxjtu2", error);
	ASSERT (connection != NULL, "new connection",
		"new connection failed: %s", error
		&& (*error) ? (*error)->message : "NONE");
	g_object_unref (connection);
}

#define NET_GEN_NAME "net.generate"
#define SUP_GEN_NAME "wpa_supplicant.conf.generate"

static void
test_update_connection ()
{
	GError **error = NULL;
	NMConnection *connection;
	gboolean success;

	connection = ifnet_update_connection_from_config_block ("eth0", error);
	ASSERT (connection != NULL, "get connection",
		"get connection failed: %s",
		error == NULL ? "None" : (*error)->message);

	success = ifnet_update_parsers_by_connection (connection, "eth0",
	                                              NET_GEN_NAME,
	                                              SUP_GEN_NAME,
	                                              NULL,
	                                              error);
	ASSERT (success, "update connection", "update connection failed %s", "eth0");
	g_object_unref (connection);

	connection = ifnet_update_connection_from_config_block ("0xab3ace", error);
	ASSERT (connection != NULL, "get connection", "get connection failed: %s",
		error == NULL ? "None" : (*error)->message);

	success = ifnet_update_parsers_by_connection (connection, "0xab3ace",
	                                              NET_GEN_NAME,
	                                              SUP_GEN_NAME,
	                                              NULL,
	                                              error);
	ASSERT (success, "update connection", "update connection failed %s", "0xab3ace");
	g_object_unref (connection);

	unlink (NET_GEN_NAME);
	unlink (SUP_GEN_NAME);
}

static void
test_add_connection ()
{
	NMConnection *connection;

	connection = ifnet_update_connection_from_config_block ("eth0", NULL);
	ASSERT (ifnet_add_new_connection (connection, NET_GEN_NAME, SUP_GEN_NAME, NULL),
	        "add connection", "add connection failed: %s", "eth0");
	g_object_unref (connection);
	connection = ifnet_update_connection_from_config_block ("myxjtu2", NULL);
	ASSERT (ifnet_add_new_connection (connection, NET_GEN_NAME, SUP_GEN_NAME, NULL),
	        "add connection", "add connection failed: %s", "myxjtu2");
	g_object_unref (connection);

	unlink (NET_GEN_NAME);
	unlink (SUP_GEN_NAME);
}

static void
test_delete_connection ()
{
	GError *error = NULL;
	NMConnection *connection;

	connection = ifnet_update_connection_from_config_block ("eth7", &error);
	ASSERT (connection != NULL, "get connection",
	        "get connection failed: %s",
	        error ? error->message : "None");
	ASSERT (ifnet_delete_connection_in_parsers ("eth7", NET_GEN_NAME, SUP_GEN_NAME),
	        "delete connection", "delete connection failed: %s", "eth7");
	g_object_unref (connection);
	connection = ifnet_update_connection_from_config_block ("qiaomuf", &error);
	ASSERT (connection != NULL, "get connection",
	        "get connection failed: %s",
	        error ? error->message : "None");
	ASSERT (ifnet_delete_connection_in_parsers ("qiaomuf", NET_GEN_NAME, SUP_GEN_NAME),
	        "delete connection", "delete connection failed: %s", "qiaomuf");
	g_object_unref (connection);

	unlink (NET_GEN_NAME);
	unlink (SUP_GEN_NAME);
}

static void
run_all (gboolean run)
{
	if (run) {
		test_strip_string ();
		test_is_static ();
		test_has_ip6_address ();
		test_has_default_route ();
		test_getdata ();
		test_read_hostname ();
		test_write_hostname ();
		test_is_ip4_address ();
		test_is_ip6_address ();
		test_convert_ipv4_config_block ();
		test_convert_ipv4_routes_block ();
		test_is_unmanaged ();
		test_wpa_parser ();
		test_convert_ipv4_routes_block ();
		test_new_connection ();
		test_update_connection ();
		test_add_connection ();
		test_delete_connection ();
	}
}

int
main (void)
{
//      g_mem_set_vtable(glib_mem_profiler_table);
//      g_atexit(g_mem_profile);
	g_type_init ();
	ifnet_destroy ();
	wpa_parser_destroy ();
	ifnet_init ("net");
	wpa_parser_init ("wpa_supplicant.conf");
	printf ("Initialization complete\n");
	run_all (TRUE);
	ifnet_destroy ();
	wpa_parser_destroy ();
	return 0;
}
