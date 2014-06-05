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
#include <unistd.h>
#include <nm-utils.h>

#include "nm-linux-platform.h"
#include "nm-logging.h"

#include "net_parser.h"
#include "net_utils.h"
#include "wpa_parser.h"
#include "connection_parser.h"
#include "nm-config.h"

#include "nm-test-utils.h"

/* Fake NMConfig handling; the values it returns don't matter, so this
 * is easier than forcing it to read our own config file, etc.
 */
NMConfig *
nm_config_get (void)
{
	return NULL;
}

const char *
nm_config_get_dhcp_client (NMConfig *config)
{
	return "dhclient";
}

static void
test_getdata ()
{
	ASSERT (ifnet_get_data ("eth1", "config")
		&& strcmp (ifnet_get_data ("eth1", "config"), "( \"dhcp\" )") == 0,
		"get data", "config_eth1 is not correct");
	ASSERT (ifnet_get_data ("ppp0", "username")
		&& strcmp (ifnet_get_data ("ppp0", "username"), "user") == 0,
		"get data", "config_ppp0 username is not correctly read");
	ASSERT (ifnet_get_data ("ppp0", "password")
		&& strcmp (ifnet_get_data ("ppp0", "password"),
			   "password") == 0, "get data",
		"config_ppp0 password is not correctly read");
	ASSERT (ifnet_get_global_data ("modules")
		&& strcmp ("!wpa_supplicant", ifnet_get_global_data ("modules")) == 0,
		"get data", "config_eth1 is not correct");
}

static void
test_read_hostname (const char *base_path)
{
	char *hostname_path, *hostname;

	hostname_path = g_build_filename (base_path, "hostname", NULL);
	hostname = read_hostname (hostname_path);

	g_assert_cmpstr (hostname, ==, "gentoo");

	g_free (hostname);
	g_free (hostname_path);
}

static void
test_write_hostname (const char *temp_path)
{
	char *hostname_path, *hostname;

	hostname_path = g_build_filename (temp_path, "hostname-test", NULL);
	write_hostname (hostname_path, "gentoo-nm");
	hostname = read_hostname (hostname_path);

	g_assert_cmpstr (hostname, ==, "gentoo-nm");

	g_free (hostname);
	unlink (hostname_path);
	g_free (hostname_path);
}

static void
test_is_static ()
{
	ASSERT (is_static_ip4 ("eth1") == FALSE, "is static",
		"a dhcp interface is recognized as static");
	ASSERT (is_static_ip4 ("eth0") == TRUE, "is static",
		"a static interface is recognized as dhcp");
	ASSERT (!is_static_ip6 ("eth0") == TRUE, "is static",
		"a dhcp interface is recognized as static");
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
	guint32 tmp_ip4_addr;

	str = malloc (INET_ADDRSTRLEN);
	tmp_ip4_addr = iblock->ip;
	inet_ntop (AF_INET, &tmp_ip4_addr, str, INET_ADDRSTRLEN);
	ASSERT (strcmp (ip, str) == 0, "check ip",
		"ip expected:%s, find:%s", ip, str);
	tmp_ip4_addr = iblock->netmask;
	inet_ntop (AF_INET, &tmp_ip4_addr, str, INET_ADDRSTRLEN);
	ASSERT (strcmp (netmask, str) == 0, "check netmask",
		"netmask expected:%s, find:%s", netmask, str);
	tmp_ip4_addr = iblock->gateway;
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

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_WARNING,
	                       "*Can't handle IPv4 address*202.117.16.1211*");
	iblock = convert_ip4_config_block ("eth2");
	g_test_assert_expected_messages ();
	ASSERT (iblock != NULL
		&& iblock->next == NULL,
		"convert error IPv4 address", "should only get one address");
	check_ip_block (iblock, "192.168.4.121", "255.255.255.0", "0.0.0.0");
	destroy_ip_block (iblock);

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_WARNING,
	                       "*missing netmask or prefix*");
	iblock = convert_ip4_config_block ("eth3");
	ASSERT (iblock == NULL, "convert config_block",
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

	iblock = convert_ip4_routes_block ("eth9");
	tmp = iblock;

	ASSERT (iblock != NULL, "convert ip4 routes", "should get one route");
	check_ip_block (iblock, "10.0.0.0", "255.0.0.0", "192.168.0.1");
	iblock = iblock->next;
	destroy_ip_block (tmp);
	ASSERT (iblock == NULL, "convert ip4 routes",
		"should only get one route");
}

static void
test_wpa_parser ()
{
	const char *value;

	g_assert (exist_ssid ("example"));

	g_assert (exist_ssid ("static-wep-test"));
	value = wpa_get_value ("static-wep-test", "key_mgmt");
	g_assert_cmpstr (value, ==, "NONE");
	value = wpa_get_value ("static-wep-test", "wep_key0");
	g_assert_cmpstr (value, ==, "\"abcde\"");

	g_assert (exist_ssid ("leap-example"));

	value = wpa_get_value ("test-with-hash-in-psk", "psk");
	g_assert_cmpstr (value, ==, "\"xjtudlc3731###asdfasdfasdf\"");
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
	GError *error = NULL;
	NMConnection *connection;

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_WARNING,
	                       "*Can't handle IPv4 address*202.117.16.1211*");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_WARNING,
	                       "*Can't handle IPv6 address*202.117.16.1211*");
	connection = ifnet_update_connection_from_config_block ("eth2", NULL, &error);
	g_test_assert_expected_messages ();
	ASSERT (connection != NULL, "new connection",
		"new connection failed: %s",
		error ? error->message : "None");
	g_object_unref (connection);

	connection = ifnet_update_connection_from_config_block ("qiaomuf", NULL, &error);
	ASSERT (connection != NULL, "new connection",
		"new connection failed: %s",
		error ? error->message : "NONE");
	g_object_unref (connection);

	connection = ifnet_update_connection_from_config_block ("myxjtu2", NULL, &error);
	ASSERT (connection != NULL, "new connection",
		"new connection failed: %s",
		error ? error->message : "NONE");
	g_object_unref (connection);

	connection = ifnet_update_connection_from_config_block ("eth9", NULL, &error);
	ASSERT (connection != NULL, "new connection",
		"new connection(eth9) failed: %s",
		error ? error->message : "NONE");
	g_object_unref (connection);

	connection = ifnet_update_connection_from_config_block ("eth10", NULL, &error);
	ASSERT (connection != NULL, "new connection",
		"new connection(eth10) failed: %s",
		error ? error->message : "NONE");
	g_object_unref (connection);
}

static void
kill_backup (char **path)
{
	if (path) {
		unlink (*path);
		g_free (*path);
		*path = NULL;
	}
}

#define NET_GEN_NAME "net.generate"
#define SUP_GEN_NAME "wpa_supplicant.conf.generate"

static void
test_update_connection (const char *basepath)
{
	GError *error = NULL;
	NMConnection *connection;
	gboolean success;
	char *backup = NULL;

	connection = ifnet_update_connection_from_config_block ("eth0", basepath, &error);
	ASSERT (connection != NULL, "get connection",
		"get connection failed: %s",
		error ? error->message : "None");

	success = ifnet_update_parsers_by_connection (connection, "eth0",
	                                              NET_GEN_NAME,
	                                              SUP_GEN_NAME,
	                                              NULL,
	                                              &backup,
	                                              &error);
	kill_backup (&backup);
	ASSERT (success, "update connection", "update connection failed %s", "eth0");
	g_object_unref (connection);

	connection = ifnet_update_connection_from_config_block ("0xab3ace", basepath, &error);
	ASSERT (connection != NULL, "get connection", "get connection failed: %s",
		error ? error->message : "None");

	success = ifnet_update_parsers_by_connection (connection, "0xab3ace",
	                                              NET_GEN_NAME,
	                                              SUP_GEN_NAME,
	                                              NULL,
	                                              &backup,
	                                              &error);
	kill_backup (&backup);
	ASSERT (success, "update connection", "update connection failed %s", "0xab3ace");
	g_object_unref (connection);

	unlink (NET_GEN_NAME);
	unlink (SUP_GEN_NAME);
}

static void
test_add_connection (const char *basepath)
{
	NMConnection *connection;
	char *backup = NULL;

	connection = ifnet_update_connection_from_config_block ("eth0", basepath, NULL);
	ASSERT (ifnet_add_new_connection (connection, NET_GEN_NAME, SUP_GEN_NAME, NULL, &backup, NULL),
	        "add connection", "add connection failed: %s", "eth0");
	kill_backup (&backup);
	g_object_unref (connection);

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_WARNING,
	                       "*Can't handle ipv4 address: brd, missing netmask or prefix*");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_WARNING,
	                       "*Can't handle ipv4 address: 202.117.16.255, missing netmask or prefix*");
	connection = ifnet_update_connection_from_config_block ("myxjtu2", basepath, NULL);
	g_test_assert_expected_messages ();
	ASSERT (ifnet_add_new_connection (connection, NET_GEN_NAME, SUP_GEN_NAME, NULL, &backup, NULL),
	        "add connection", "add connection failed: %s", "myxjtu2");
	kill_backup (&backup);
	g_object_unref (connection);

	unlink (NET_GEN_NAME);
	unlink (SUP_GEN_NAME);
}

static void
test_delete_connection ()
{
	GError *error = NULL;
	NMConnection *connection;
	char *backup = NULL;

	connection = ifnet_update_connection_from_config_block ("eth7", NULL, &error);
	ASSERT (connection != NULL, "get connection",
	        "get connection failed: %s",
	        error ? error->message : "None");
	ASSERT (ifnet_delete_connection_in_parsers ("eth7", NET_GEN_NAME, SUP_GEN_NAME, &backup),
	        "delete connection", "delete connection failed: %s", "eth7");
	kill_backup (&backup);
	g_object_unref (connection);

	connection = ifnet_update_connection_from_config_block ("qiaomuf", NULL, &error);
	ASSERT (connection != NULL, "get connection",
	        "get connection failed: %s",
	        error ? error->message : "None");
	ASSERT (ifnet_delete_connection_in_parsers ("qiaomuf", NET_GEN_NAME, SUP_GEN_NAME, &backup),
	        "delete connection", "delete connection failed: %s", "qiaomuf");
	kill_backup (&backup);
	g_object_unref (connection);

	unlink (NET_GEN_NAME);
	unlink (SUP_GEN_NAME);
}

static void
test_missing_config ()
{
	GError *error = NULL;
	NMConnection *connection;

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_WARNING,
	                       "*Unknown config for eth8*");
	connection = ifnet_update_connection_from_config_block ("eth8", NULL, &error);
	g_test_assert_expected_messages ();
	ASSERT (connection == NULL && error != NULL, "get connection",
	        "get connection should fail with 'Unknown config for eth8'");
}

NMTST_DEFINE ();

int
main (int argc, char **argv)
{
	char *f;

	nm_linux_platform_setup ();

	nmtst_init_assert_logging (&argc, &argv);
	nm_logging_setup ("WARN", "DEFAULT", NULL, NULL);

	f = g_build_filename (argv[1], "net", NULL);
	ifnet_init (f);
	g_free (f);

	f = g_build_filename (argv[1], "wpa_supplicant.conf", NULL);
	wpa_parser_init (f);
	g_free (f);

	test_strip_string ();
	test_is_static ();
	test_has_ip6_address ();
	test_has_default_route ();
	test_getdata ();
	test_read_hostname (argv[1]);
	test_write_hostname (argv[2]);
	test_is_ip4_address ();
	test_is_ip6_address ();
	test_convert_ipv4_config_block ();
	test_convert_ipv4_routes_block ();
	test_is_unmanaged ();
	test_wpa_parser ();
	test_convert_ipv4_routes_block ();
	test_new_connection ();
	test_update_connection (argv[1]);
	test_add_connection (argv[1]);
	test_delete_connection ();
	test_missing_config ();

	ifnet_destroy ();
	wpa_parser_destroy ();

	f = g_path_get_basename (argv[0]);
	fprintf (stdout, "%s: SUCCESS\n", f);
	g_free (f);
	return 0;
}
