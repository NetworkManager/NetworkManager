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

#include "nm-default.h"

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>

#include "nm-utils.h"

#include "nm-linux-platform.h"

#include "net_parser.h"
#include "net_utils.h"
#include "wpa_parser.h"
#include "connection_parser.h"
#include "nm-config.h"

#include "nm-test-utils-core.h"

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
test_getdata (void)
{
	g_assert (ifnet_get_data ("eth1", "config") &&
	          strcmp (ifnet_get_data ("eth1", "config"), "( \"dhcp\" )") == 0);
	g_assert (ifnet_get_data ("ppp0", "username") &&
	          strcmp (ifnet_get_data ("ppp0", "username"), "user") == 0);
	g_assert (ifnet_get_data ("ppp0", "password") &&
	          strcmp (ifnet_get_data ("ppp0", "password"), "password") == 0);
	g_assert (ifnet_get_global_data ("modules") &&
	          strcmp ("!wpa_supplicant", ifnet_get_global_data ("modules")) == 0);
}

static void
test_is_static (void)
{
	g_assert (!is_static_ip4 ("eth1"));
	g_assert (is_static_ip4 ("eth0"));
	g_assert (!is_static_ip6 ("eth0"));
}

static void
test_has_default_route (void)
{
	g_assert (has_default_ip4_route ("eth0"));
	g_assert (has_default_ip6_route ("eth4"));
	g_assert (!has_default_ip4_route ("eth5") &&
	          !has_default_ip6_route ("eth5"));
}

static void
test_has_ip6_address (void)
{
	g_assert (has_ip6_address ("eth2"));
	g_assert (!has_ip6_address ("eth0"));
}

static void
test_is_ip4_address (void)
{
	gchar *address1 = "192.168.4.232/24";
	gchar *address2 = "192.168.100.{1..254}/24";
	gchar *address3 = "192.168.4.2555/24";

	g_assert (is_ip4_address (address1));
	g_assert (is_ip4_address (address2));
	g_assert (!is_ip4_address (address3));
}

static void
test_is_ip6_address (void)
{
	gchar *address1 = "4321:0:1:2:3:4:567:89ac/24";

	g_assert (is_ip6_address (address1));
}

static void
check_ip_block (ip_block * iblock, gchar * ip, guint32 prefix, gchar * gateway)
{
	g_assert_cmpstr (ip, ==, iblock->ip);
	g_assert (prefix == iblock->prefix);
	g_assert_cmpstr (gateway, ==, iblock->next_hop);
}

static void
test_convert_ipv4_config_block (void)
{
	ip_block *iblock = convert_ip4_config_block ("eth0");
	ip_block *tmp = iblock;

	g_assert (iblock != NULL);
	check_ip_block (iblock, "202.117.16.121", 24, "202.117.16.1");
	iblock = iblock->next;
	destroy_ip_block (tmp);
	g_assert (iblock != NULL);
	check_ip_block (iblock, "192.168.4.121", 24, "202.117.16.1");
	destroy_ip_block (iblock);

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*Can't handle IPv4 address*202.117.16.1211*");
	iblock = convert_ip4_config_block ("eth2");
	g_test_assert_expected_messages ();
	g_assert (iblock != NULL && iblock->next == NULL);
	check_ip_block (iblock, "192.168.4.121", 24, NULL);
	destroy_ip_block (iblock);

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*missing netmask or prefix*");
	iblock = convert_ip4_config_block ("eth3");
	g_assert (iblock == NULL);
}

static void
test_convert_ipv4_routes_block (void)
{
	ip_block *iblock = convert_ip4_routes_block ("eth0");
	ip_block *tmp = iblock;

	g_assert (iblock != NULL);
	check_ip_block (iblock, "192.168.4.0", 24, "192.168.4.1");
	iblock = iblock->next;
	destroy_ip_block (tmp);
	g_assert (iblock == NULL);

	iblock = convert_ip4_routes_block ("eth9");
	tmp = iblock;

	g_assert (iblock != NULL);
	check_ip_block (iblock, "10.0.0.0", 8, "192.168.0.1");
	iblock = iblock->next;
	destroy_ip_block (tmp);
	g_assert (iblock == NULL);
}

static void
test_wpa_parser (void)
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
test_strip_string (void)
{
	gchar *str = "( \"default via     202.117.16.1\" )";
	gchar *result = g_strdup (str);
	gchar *result_b = result;

	result = strip_string (result, '(');
	result = strip_string (result, ')');
	result = strip_string (result, '"');
	g_assert_cmpstr (result, ==, "default via     202.117.16.1");
	g_free (result_b);
}

static void
test_is_unmanaged (void)
{
	g_assert (is_managed ("eth0"));
	g_assert (!is_managed ("eth4"));
}

static void
test_new_connection (void)
{
	GError *error = NULL;
	NMConnection *connection;

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*Can't handle IPv4 address*202.117.16.1211*");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*Can't handle IPv6 address*202.117.16.1211*");
	connection = ifnet_update_connection_from_config_block ("eth2", NULL, &error);
	g_test_assert_expected_messages ();
	g_assert (connection != NULL);
	g_object_unref (connection);

	connection = ifnet_update_connection_from_config_block ("qiaomuf", NULL, &error);
	g_assert (connection != NULL);
	g_object_unref (connection);

	connection = ifnet_update_connection_from_config_block ("myxjtu2", NULL, &error);
	g_assert (connection != NULL);
	g_object_unref (connection);

	connection = ifnet_update_connection_from_config_block ("eth9", NULL, &error);
	g_assert (connection != NULL);
	g_object_unref (connection);

	connection = ifnet_update_connection_from_config_block ("eth10", NULL, &error);
	g_assert (connection != NULL);
	g_object_unref (connection);
}

static void
kill_backup (char **path)
{
	if (*path) {
		unlink (*path);
		g_free (*path);
		*path = NULL;
	}
}

#define NET_GEN_NAME "net.generate"
#define SUP_GEN_NAME "wpa_supplicant.conf.generate"

static void
test_update_connection (void)
{
	GError *error = NULL;
	NMConnection *connection;
	gboolean success;
	char *backup = NULL;
	char *basepath = TEST_IFNET_DIR;

	connection = ifnet_update_connection_from_config_block ("eth0", basepath, &error);
	g_assert (connection != NULL);

	success = ifnet_update_parsers_by_connection (connection, "eth0",
	                                              NET_GEN_NAME,
	                                              SUP_GEN_NAME,
	                                              NULL,
	                                              &backup,
	                                              &error);
	kill_backup (&backup);
	g_assert (success);
	g_object_unref (connection);

	connection = ifnet_update_connection_from_config_block ("0xab3ace", basepath, &error);
	g_assert (connection != NULL);

	success = ifnet_update_parsers_by_connection (connection, "0xab3ace",
	                                              NET_GEN_NAME,
	                                              SUP_GEN_NAME,
	                                              NULL,
	                                              &backup,
	                                              &error);
	kill_backup (&backup);
	g_assert (success);
	g_object_unref (connection);

	unlink (NET_GEN_NAME);
	unlink (SUP_GEN_NAME);
}

static void
test_add_connection (void)
{
	NMConnection *connection;
	char *backup = NULL;
	const char *basepath = TEST_IFNET_DIR;

	connection = ifnet_update_connection_from_config_block ("eth0", basepath, NULL);
	g_assert (ifnet_add_new_connection (connection, NET_GEN_NAME, SUP_GEN_NAME, NULL, &backup, NULL));
	kill_backup (&backup);
	g_object_unref (connection);

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*Can't handle ipv4 address: brd, missing netmask or prefix*");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*Can't handle ipv4 address: 202.117.16.255, missing netmask or prefix*");
	connection = ifnet_update_connection_from_config_block ("myxjtu2", basepath, NULL);
	g_test_assert_expected_messages ();
	g_assert (ifnet_add_new_connection (connection, NET_GEN_NAME, SUP_GEN_NAME, NULL, &backup, NULL));
	kill_backup (&backup);
	g_object_unref (connection);

	unlink (NET_GEN_NAME);
	unlink (SUP_GEN_NAME);
}

static void
test_delete_connection (void)
{
	GError *error = NULL;
	NMConnection *connection;
	char *backup = NULL;

	connection = ifnet_update_connection_from_config_block ("eth7", NULL, &error);
	g_assert (connection != NULL);
	g_assert (ifnet_delete_connection_in_parsers ("eth7", NET_GEN_NAME, SUP_GEN_NAME, &backup));
	kill_backup (&backup);
	g_object_unref (connection);

	connection = ifnet_update_connection_from_config_block ("qiaomuf", NULL, &error);
	g_assert (connection != NULL);
	g_assert (ifnet_delete_connection_in_parsers ("qiaomuf", NET_GEN_NAME, SUP_GEN_NAME, &backup));
	kill_backup (&backup);
	g_object_unref (connection);

	unlink (NET_GEN_NAME);
	unlink (SUP_GEN_NAME);
}

static void
test_missing_config (void)
{
	gs_free_error GError *error = NULL;
	NMConnection *connection;

	connection = ifnet_update_connection_from_config_block ("eth8", NULL, &error);
	g_assert_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION);
	g_assert (connection == NULL && error != NULL);
}

NMTST_DEFINE ();

#define TPATH "/settings/plugins/ifnet/"

int
main (int argc, char **argv)
{
	int ret;

	nm_linux_platform_setup ();

	nmtst_init_assert_logging (&argc, &argv, "WARN", "DEFAULT");

	ifnet_init (TEST_IFNET_DIR "/net");
	wpa_parser_init (TEST_IFNET_DIR "/wpa_supplicant.conf");

	g_test_add_func (TPATH "strip-string", test_strip_string);
	g_test_add_func (TPATH "is-static", test_is_static);
	g_test_add_func (TPATH "has-ip6-address", test_has_ip6_address);
	g_test_add_func (TPATH "has-default-route", test_has_default_route);
	g_test_add_func (TPATH "get-data", test_getdata);
	g_test_add_func (TPATH "is-ip4-address", test_is_ip4_address);
	g_test_add_func (TPATH "is-ip6-address", test_is_ip6_address);
	g_test_add_func (TPATH "convert-ip4-config", test_convert_ipv4_config_block);
	g_test_add_func (TPATH "convert-ip4-routes", test_convert_ipv4_routes_block);
	g_test_add_func (TPATH "is-unmanaged", test_is_unmanaged);
	g_test_add_func (TPATH "wpa-parser", test_wpa_parser);
	g_test_add_func (TPATH "new-connection", test_new_connection);
	g_test_add_func (TPATH "update-connection", test_update_connection);
	g_test_add_func (TPATH "add-connection", test_add_connection);
	g_test_add_func (TPATH "delete-connection", test_delete_connection);
	g_test_add_func (TPATH "missing-config", test_missing_config);

	ret = g_test_run ();

	ifnet_destroy ();
	wpa_parser_destroy ();

	return ret;
}
