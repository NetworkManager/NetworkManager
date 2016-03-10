/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager system settings service - keyfile plugin
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
 * Copyright (C) 2008 - 2014 Red Hat, Inc.
 */

#include "nm-default.h"

#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "nm-core-internal.h"

#include "reader.h"
#include "writer.h"
#include "utils.h"

#include "nm-test-utils.h"

static void
check_ip_address (NMSettingIPConfig *config, int idx, const char *address, int plen)
{
	NMIPAddress *ip4 = nm_setting_ip_config_get_address (config, idx);

	g_assert (ip4);
	g_assert_cmpstr (nm_ip_address_get_address (ip4), ==, address);
	g_assert_cmpint (nm_ip_address_get_prefix (ip4), ==, plen);
}

static void
check_ip_route (NMSettingIPConfig *config, int idx, const char *destination, int plen,
                const char *next_hop, gint64 metric)
{
	NMIPRoute *route = nm_setting_ip_config_get_route (config, idx);

	g_assert (route);
	g_assert_cmpstr (nm_ip_route_get_dest (route), ==, destination);
	g_assert_cmpint (nm_ip_route_get_prefix (route), ==, plen);
	g_assert_cmpstr (nm_ip_route_get_next_hop (route), ==, next_hop);
	g_assert_cmpint (nm_ip_route_get_metric (route), ==, metric);
}

static NMConnection *
keyfile_read_connection_from_file (const char *filename)
{
	GError *error = NULL;
	NMConnection *connection;

	g_assert (filename);

	connection = nm_keyfile_plugin_connection_from_file (filename, &error);
	g_assert_no_error (error);

	nmtst_assert_connection_verifies_without_normalization (connection);

	return connection;
}

static void
test_read_valid_wired_connection (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	GError *error = NULL;
	const char *mac;
	char expected_mac_address[ETH_ALEN] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
	gboolean success;

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_INFO,
	                       "*ipv4.addresses:*semicolon at the end*addresses1*");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_INFO,
	                       "*ipv4.addresses:*semicolon at the end*addresses2*");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*missing prefix length*address4*");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*missing prefix length*address5*");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_INFO,
	                       "*ipv4.routes*semicolon at the end*routes2*");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_INFO,
	                       "*ipv4.routes*semicolon at the end*routes3*");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_INFO,
	                       "*ipv4.routes*semicolon at the end*routes5*");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_INFO,
	                       "*ipv4.routes*semicolon at the end*routes8*");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*missing prefix length*address4*");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_INFO,
	                       "*ipv6.address*semicolon at the end*address5*");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*missing prefix length*address5*");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_INFO,
	                       "*ipv6.address*semicolon at the end*address7*");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_INFO,
	                       "*ipv6.routes*semicolon at the end*routes1*");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_INFO,
	                       "*ipv6.route*semicolon at the end*route6*");
	connection = nm_keyfile_plugin_connection_from_file (TEST_KEYFILES_DIR "/Test_Wired_Connection", NULL);
	g_test_assert_expected_messages ();
	g_assert (connection);

	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	/* ===== CONNECTION SETTING ===== */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "Test Wired Connection");
	g_assert_cmpstr (nm_setting_connection_get_uuid (s_con), ==, "4e80a56d-c99f-4aad-a6dd-b449bc398c57");
	g_assert_cmpuint (nm_setting_connection_get_timestamp (s_con), ==, 6654332);
	g_assert (nm_setting_connection_get_autoconnect (s_con));

	/* ===== WIRED SETTING ===== */
	s_wired = nm_connection_get_setting_wired (connection);
	g_assert (s_wired);

	mac = nm_setting_wired_get_mac_address (s_wired);
	g_assert (mac);
	g_assert (nm_utils_hwaddr_matches (mac, -1, expected_mac_address, sizeof (expected_mac_address)));
	g_assert_cmpint (nm_setting_wired_get_mtu (s_wired), ==, 1400);

	/* ===== IPv4 SETTING ===== */
	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_MANUAL);
	g_assert_cmpint (nm_setting_ip_config_get_num_dns (s_ip4), ==, 2);
	g_assert_cmpstr (nm_setting_ip_config_get_dns (s_ip4, 0), ==, "4.2.2.1");
	g_assert_cmpstr (nm_setting_ip_config_get_dns (s_ip4, 1), ==, "4.2.2.2");

	/* IPv4 addresses */
	g_assert_cmpint (nm_setting_ip_config_get_num_addresses (s_ip4), ==, 6);
	check_ip_address (s_ip4, 0, "2.3.4.5", 24);
	check_ip_address (s_ip4, 1, "192.168.0.5", 24);
	check_ip_address (s_ip4, 2, "1.2.3.4", 16);
	check_ip_address (s_ip4, 3, "3.4.5.6", 16);
	check_ip_address (s_ip4, 4, "4.5.6.7", 24);
	check_ip_address (s_ip4, 5, "5.6.7.8", 24);

	/* IPv4 gateway */
	g_assert_cmpstr (nm_setting_ip_config_get_gateway (s_ip4), ==, "2.3.4.6");

	/* IPv4 routes */
	g_assert_cmpint (nm_setting_ip_config_get_num_routes (s_ip4), ==, 12);
	check_ip_route (s_ip4, 0, "5.6.7.8", 32, NULL, -1);
	check_ip_route (s_ip4, 1, "1.2.3.0", 24, "2.3.4.8", 99);
	check_ip_route (s_ip4, 2, "1.1.1.2", 12, NULL, -1);
	check_ip_route (s_ip4, 3, "1.1.1.3", 13, NULL, -1);
	check_ip_route (s_ip4, 4, "1.1.1.4", 14, "2.2.2.4", -1);
	check_ip_route (s_ip4, 5, "1.1.1.5", 15, "2.2.2.5", -1);
	check_ip_route (s_ip4, 6, "1.1.1.6", 16, "2.2.2.6", -1);
	check_ip_route (s_ip4, 7, "1.1.1.7", 17, NULL, -1);
	check_ip_route (s_ip4, 8, "1.1.1.8", 18, NULL, -1);
	check_ip_route (s_ip4, 9, "1.1.1.9", 19, NULL, -1);
	check_ip_route (s_ip4, 10, "1.1.1.10", 20, NULL, -1);
	check_ip_route (s_ip4, 11, "1.1.1.11", 21, NULL, 21);

	/* ===== IPv6 SETTING ===== */
	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	g_assert (s_ip6);

	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip6), ==, NM_SETTING_IP6_CONFIG_METHOD_MANUAL);

	g_assert_cmpint (nm_setting_ip_config_get_num_dns (s_ip6), ==, 2);
	g_assert_cmpstr (nm_setting_ip_config_get_dns (s_ip6, 0), ==, "1111:dddd::aaaa");
	g_assert_cmpstr (nm_setting_ip_config_get_dns (s_ip6, 1), ==, "1::cafe");
	g_assert_cmpint (nm_setting_ip_config_get_num_dns_searches (s_ip6), ==, 3);
	g_assert_cmpstr (nm_setting_ip_config_get_dns_search (s_ip6, 0), ==, "super-domain.com");
	g_assert_cmpstr (nm_setting_ip_config_get_dns_search (s_ip6, 1), ==, "redhat.com");
	g_assert_cmpstr (nm_setting_ip_config_get_dns_search (s_ip6, 2), ==, "gnu.org");

	/* IPv6 addresses */
	g_assert_cmpint (nm_setting_ip_config_get_num_addresses (s_ip6), ==, 10);
	check_ip_address (s_ip6, 0, "2:3:4:5:6:7:8:9", 64);
	check_ip_address (s_ip6, 1, "abcd:1234:ffff::cdde", 64);
	check_ip_address (s_ip6, 2, "1:2:3:4:5:6:7:8", 96);
	check_ip_address (s_ip6, 3, "3:4:5:6:7:8:9:0", 128);
	check_ip_address (s_ip6, 4, "3:4:5:6:7:8:9:14", 64);
	check_ip_address (s_ip6, 5, "3:4:5:6:7:8:9:15", 64);
	check_ip_address (s_ip6, 6, "3:4:5:6:7:8:9:16", 66);
	check_ip_address (s_ip6, 7, "3:4:5:6:7:8:9:17", 67);
	check_ip_address (s_ip6, 8, "3:4:5:6:7:8:9:18", 68);
	check_ip_address (s_ip6, 9, "3:4:5:6:7:8:9:19", 69);

	/* IPv6 gateway */
	g_assert_cmpstr (nm_setting_ip_config_get_gateway (s_ip6), ==, "2:3:4:5:1:2:3:4");

	/* Routes */
	g_assert_cmpint (nm_setting_ip_config_get_num_routes (s_ip6), ==, 7);
	check_ip_route (s_ip6, 0, "d:e:f:0:1:2:3:4", 64, "f:e:d:c:1:2:3:4", -1);
	check_ip_route (s_ip6, 1, "a:b:c:d::", 64, "f:e:d:c:1:2:3:4", 99);
	check_ip_route (s_ip6, 2, "8:7:6:5:4:3:2:1", 128, NULL, -1);
	check_ip_route (s_ip6, 3, "6:7:8:9:0:1:2:3", 126, NULL, 1);
	check_ip_route (s_ip6, 4, "7:8:9:0:1:2:3:4", 125, NULL, 5);
	check_ip_route (s_ip6, 5, "8:9:0:1:2:3:4:5", 124, NULL, 6);
	check_ip_route (s_ip6, 6, "8:9:0:1:2:3:4:6", 123, NULL, -1);
	g_object_unref (connection);
}

static void
add_one_ip_address (NMSettingIPConfig *s_ip,
                    const char *addr,
                    guint32 prefix)
{
	NMIPAddress *ip_addr;
	GError *error = NULL;

	ip_addr = nm_ip_address_new (NM_IS_SETTING_IP4_CONFIG (s_ip) ? AF_INET : AF_INET6,
	                             addr, prefix, &error);
	g_assert_no_error (error);
	nm_setting_ip_config_add_address (s_ip, ip_addr);
	nm_ip_address_unref (ip_addr);
}

static void
add_one_ip_route (NMSettingIPConfig *s_ip,
                  const char *dest,
                  const char *nh,
                  guint32 prefix,
                  gint64 metric)
{
	NMIPRoute *route;
	GError *error = NULL;

	g_assert (prefix > 0);
	route = nm_ip_route_new (NM_IS_SETTING_IP4_CONFIG (s_ip) ? AF_INET : AF_INET6,
	                         dest, prefix, nh, metric, &error);
	g_assert_no_error (error);
	nm_setting_ip_config_add_route (s_ip, route);
	nm_ip_route_unref (route);
}


static void
test_write_wired_connection (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	char *uuid;
	const char *mac = "99:88:77:66:55:44";
	gboolean success;
	NMConnection *reread;
	char *testfile = NULL;
	GError *error = NULL;
	pid_t owner_grp;
	uid_t owner_uid;
	const char *dns1 = "4.2.2.1";
	const char *dns2 = "4.2.2.2";
	const char *address1 = "192.168.0.5";
	const char *address2 = "1.2.3.4";
	const char *gw = "192.168.0.1";
	const char *route1 = "10.10.10.2";
	const char *route1_nh = "10.10.10.1";
	const char *route2 = "1.1.1.1";
	const char *route2_nh = "1.2.1.1";
	const char *route3 = "2.2.2.2";
	const char *route3_nh = NULL;
	const char *route4 = "3.3.3.3";
	const char *route4_nh = NULL;
	const char *dns6_1 = "1::cafe";
	const char *dns6_2 = "2::cafe";
	const char *address6_1 = "abcd::beef";
	const char *address6_2 = "dcba::beef";
	const char *route6_1 = "1:2:3:4:5:6:7:8";
	const char *route6_1_nh = "8:7:6:5:4:3:2:1";
	const char *route6_2 = "2001::1000";
	const char *route6_2_nh = "2001::1111";
	const char *route6_3 = "4:5:6:7:8:9:0:1";
	const char *route6_3_nh = "::";
	const char *route6_4 = "5:6:7:8:9:0:1:2";
	const char *route6_4_nh = "::";
	guint64 timestamp = 0x12345678L;

	connection = nm_simple_connection_new ();

	/* Connection setting */

	s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Work Wired",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, FALSE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
	              NM_SETTING_CONNECTION_TIMESTAMP, timestamp,
	              NULL);
	g_free (uuid);

	/* Wired setting */

	s_wired = NM_SETTING_WIRED (nm_setting_wired_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_wired));

	g_object_set (s_wired,
	              NM_SETTING_WIRED_MAC_ADDRESS, mac,
	              NM_SETTING_WIRED_MTU, 900,
	              NULL);

	/* IP4 setting */

	s_ip4 = NM_SETTING_IP_CONFIG (nm_setting_ip4_config_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_MANUAL,
	              NM_SETTING_IP_CONFIG_GATEWAY, gw,
	              NULL);

	/* Addresses */
	add_one_ip_address (s_ip4, address1, 24);
	add_one_ip_address (s_ip4, address2, 8);

	/* Routes */
	add_one_ip_route (s_ip4, route1, route1_nh, 24, 3);
	add_one_ip_route (s_ip4, route2, route2_nh, 8, 1);
	add_one_ip_route (s_ip4, route3, route3_nh, 7, -1);
	add_one_ip_route (s_ip4, route4, route4_nh, 6, 4);

	/* DNS servers */
	nm_setting_ip_config_add_dns (s_ip4, dns1);
	nm_setting_ip_config_add_dns (s_ip4, dns2);

	/* IP6 setting */

	s_ip6 = NM_SETTING_IP_CONFIG (nm_setting_ip6_config_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_MANUAL,
	              NULL);

	/* Addresses */
	add_one_ip_address (s_ip6, address6_1, 64);
	add_one_ip_address (s_ip6, address6_2, 56);

	/* Routes */
	add_one_ip_route (s_ip6, route6_1, route6_1_nh, 64, 3);
	add_one_ip_route (s_ip6, route6_2, route6_2_nh, 56, 1);
	add_one_ip_route (s_ip6, route6_3, route6_3_nh, 63, 5);
	add_one_ip_route (s_ip6, route6_4, route6_4_nh, 62, -1);

	/* DNS servers */
	nm_setting_ip_config_add_dns (s_ip6, dns6_1);
	nm_setting_ip_config_add_dns (s_ip6, dns6_2);

	/* DNS searches */
	nm_setting_ip_config_add_dns_search (s_ip6, "wallaceandgromit.com");

	/* Write out the connection */
	owner_uid = geteuid ();
	owner_grp = getegid ();
	success = nm_keyfile_plugin_write_test_connection (connection, TEST_SCRATCH_DIR, owner_uid, owner_grp, &testfile, &error);
	g_assert_no_error (error);
	g_assert (success);
	g_assert (testfile);

	/* Read the connection back in and compare it to the one we just wrote out */
	reread = nm_keyfile_plugin_connection_from_file (testfile, NULL);
	g_assert (reread);
	g_assert (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT));

	g_clear_error (&error);
	unlink (testfile);
	g_free (testfile);

	g_object_unref (reread);
	g_object_unref (connection);
}

static void
test_read_ip6_wired_connection (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	GError *error = NULL;
	gboolean success;

	connection = nm_keyfile_plugin_connection_from_file (TEST_KEYFILES_DIR "/Test_Wired_Connection_IP6", NULL);
	g_assert (connection);
	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	/* ===== CONNECTION SETTING ===== */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "Test Wired Connection IP6");
	g_assert_cmpstr (nm_setting_connection_get_uuid (s_con), ==, "4e80a56d-c99f-4aad-a6dd-b449bc398c57");

	/* ===== WIRED SETTING ===== */
	s_wired = nm_connection_get_setting_wired (connection);
	g_assert (s_wired);

	/* ===== IPv4 SETTING ===== */
	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_DISABLED);
	g_assert_cmpint (nm_setting_ip_config_get_num_addresses (s_ip4), ==, 0);

	/* ===== IPv6 SETTING ===== */
	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	g_assert (s_ip6);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip6), ==, NM_SETTING_IP6_CONFIG_METHOD_MANUAL);
	g_assert_cmpint (nm_setting_ip_config_get_num_addresses (s_ip6), ==, 1);
	check_ip_address (s_ip6, 0, "abcd:1234:ffff::cdde", 64);
	g_assert_cmpstr (nm_setting_ip_config_get_gateway (s_ip6), ==, "abcd:1234:ffff::cdd1");

	g_object_unref (connection);
}

static void
test_write_ip6_wired_connection (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	char *uuid;
	gboolean success;
	NMConnection *reread;
	char *testfile = NULL;
	GError *error = NULL;
	pid_t owner_grp;
	uid_t owner_uid;
	const char *dns = "1::cafe";
	const char *address = "abcd::beef";
	const char *gw = "dcba::beef";

	connection = nm_simple_connection_new ();

	/* Connection setting */

	s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Work Wired IP6",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, FALSE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* Wired setting */

	s_wired = NM_SETTING_WIRED (nm_setting_wired_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_wired));

	/* IP4 setting */

	s_ip4 = NM_SETTING_IP_CONFIG (nm_setting_ip4_config_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_DISABLED,
	              NULL);

	/* IP6 setting */

	s_ip6 = NM_SETTING_IP_CONFIG (nm_setting_ip6_config_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_MANUAL,
	              NM_SETTING_IP_CONFIG_GATEWAY, gw,
	              NULL);

	/* Addresses */
	add_one_ip_address (s_ip6, address, 64);

	/* DNS servers */
	nm_setting_ip_config_add_dns (s_ip6, dns);

	/* DNS searches */
	nm_setting_ip_config_add_dns_search (s_ip6, "wallaceandgromit.com");

	/* Write out the connection */
	owner_uid = geteuid ();
	owner_grp = getegid ();
	success = nm_keyfile_plugin_write_test_connection (connection, TEST_SCRATCH_DIR, owner_uid, owner_grp, &testfile, &error);
	g_assert_no_error (error);
	g_assert (success);
	g_assert (testfile);

	/* Read the connection back in and compare it to the one we just wrote out */
	reread = nm_keyfile_plugin_connection_from_file (testfile, NULL);
	g_assert (reread);
	g_assert (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT));

	g_clear_error (&error);
	unlink (testfile);
	g_free (testfile);

	g_object_unref (reread);
	g_object_unref (connection);
}

static void
test_read_wired_mac_case (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	GError *error = NULL;
	const char *mac;
	char expected_mac_address[ETH_ALEN] = { 0x00, 0x11, 0xaa, 0xbb, 0xcc, 0x55 };
	gboolean success;

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_INFO,
	                       "*ipv4.addresses*semicolon at the end*addresses1*");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_INFO,
	                       "*ipv4.addresses*semicolon at the end*addresses2*");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_INFO,
	                       "*ipv6.routes*semicolon at the end*routes1*");
	connection = nm_keyfile_plugin_connection_from_file (TEST_KEYFILES_DIR "/Test_Wired_Connection_MAC_Case", NULL);
	g_test_assert_expected_messages ();
	g_assert (connection);
	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	/* ===== CONNECTION SETTING ===== */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "Test Wired Connection MAC Case");
	g_assert_cmpstr (nm_setting_connection_get_uuid (s_con), ==, "4e80a56d-c99f-4aad-a6dd-b449bc398c57");

	/* ===== WIRED SETTING ===== */
	s_wired = nm_connection_get_setting_wired (connection);
	g_assert (s_wired);
	mac = nm_setting_wired_get_mac_address (s_wired);
	g_assert (mac);
	g_assert (nm_utils_hwaddr_matches (mac, -1, expected_mac_address, sizeof (expected_mac_address)));

	g_object_unref (connection);
}

static void
test_read_mac_old_format (void)
{
	NMConnection *connection;
	NMSettingWired *s_wired;
	GError *error = NULL;
	gboolean success;
	const char *mac;
	char expected_mac[ETH_ALEN] = { 0x00, 0x11, 0xaa, 0xbb, 0xcc, 0x55 };
	char expected_cloned_mac[ETH_ALEN] = { 0x00, 0x16, 0xaa, 0xbb, 0xcc, 0xfe };

	connection = nm_keyfile_plugin_connection_from_file (TEST_KEYFILES_DIR "/Test_MAC_Old_Format", &error);
	g_assert_no_error (error);
	g_assert (connection);

	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	s_wired = nm_connection_get_setting_wired (connection);
	g_assert (s_wired);

	/* MAC address */
	mac = nm_setting_wired_get_mac_address (s_wired);
	g_assert (mac);
	g_assert (nm_utils_hwaddr_matches (mac, -1, expected_mac, ETH_ALEN));

	/* Cloned MAC address */
	mac = nm_setting_wired_get_cloned_mac_address (s_wired);
	g_assert (mac);
	g_assert (nm_utils_hwaddr_matches (mac, -1, expected_cloned_mac, ETH_ALEN));

	g_object_unref (connection);
}

static void
test_read_mac_ib_old_format (void)
{
	NMConnection *connection;
	NMSettingInfiniband *s_ib;
	GError *error = NULL;
	gboolean success;
	const char *mac;
	guint8 expected_mac[INFINIBAND_ALEN] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
		0x77, 0x88, 0x99, 0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89,
		0x90 };

	connection = nm_keyfile_plugin_connection_from_file (TEST_KEYFILES_DIR "/Test_MAC_IB_Old_Format", &error);
	g_assert_no_error (error);
	g_assert (connection);

	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	s_ib = nm_connection_get_setting_infiniband (connection);
	g_assert (s_ib);

	/* MAC address */
	mac = nm_setting_infiniband_get_mac_address (s_ib);
	g_assert (mac);
	g_assert (nm_utils_hwaddr_matches (mac, -1, expected_mac, sizeof (expected_mac)));

	g_object_unref (connection);
}

static void
test_read_valid_wireless_connection (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	NMSettingIPConfig *s_ip4;
	GError *error = NULL;
	const char *bssid;
	const guint8 expected_bssid[ETH_ALEN] = { 0x00, 0x1a, 0x33, 0x44, 0x99, 0x82 };
	gboolean success;

	connection = nm_keyfile_plugin_connection_from_file (TEST_KEYFILES_DIR "/Test_Wireless_Connection", NULL);
	g_assert (connection);
	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	/* ===== CONNECTION SETTING ===== */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "Test Wireless Connection");
	g_assert_cmpstr (nm_setting_connection_get_uuid (s_con), ==, "2f962388-e5f3-45af-a62c-ac220b8f7baa");
	g_assert_cmpuint (nm_setting_connection_get_timestamp (s_con), ==, 1226604314);
	g_assert (nm_setting_connection_get_autoconnect (s_con) == FALSE);

	/* ===== WIRELESS SETTING ===== */
	s_wireless = nm_connection_get_setting_wireless (connection);
	g_assert (s_wireless);
	bssid = nm_setting_wireless_get_bssid (s_wireless);
	g_assert (bssid);
	g_assert (nm_utils_hwaddr_matches (bssid, -1, expected_bssid, sizeof (expected_bssid)));

	/* ===== IPv4 SETTING ===== */
	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_AUTO);

	g_object_unref (connection);
}

static void
test_write_wireless_connection (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	char *uuid;
	const char *bssid = "aa:b9:a1:74:55:44";
	GBytes *ssid;
	unsigned char tmpssid[] = { 0x31, 0x33, 0x33, 0x37 };
	gboolean success;
	NMConnection *reread;
	char *testfile = NULL;
	GError *error = NULL;
	pid_t owner_grp;
	uid_t owner_uid;
	guint64 timestamp = 0x12344433L;

	connection = nm_simple_connection_new ();

	/* Connection setting */

	s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Work Wireless",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, FALSE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRELESS_SETTING_NAME,
	              NM_SETTING_CONNECTION_TIMESTAMP, timestamp,
	              NULL);
	g_free (uuid);

	/* Wireless setting */

	s_wireless = NM_SETTING_WIRELESS (nm_setting_wireless_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_wireless));

	ssid = g_bytes_new (tmpssid, sizeof (tmpssid));

	g_object_set (s_wireless,
	              NM_SETTING_WIRELESS_BSSID, bssid,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRED_MTU, 1000,
	              NULL);

	g_bytes_unref (ssid);

	/* IP4 setting */

	s_ip4 = NM_SETTING_IP_CONFIG (nm_setting_ip4_config_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
	              NULL);

	/* IP6 setting */

	s_ip6 = NM_SETTING_IP_CONFIG (nm_setting_ip6_config_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_AUTO,
	              NULL);

	/* Write out the connection */
	owner_uid = geteuid ();
	owner_grp = getegid ();
	success = nm_keyfile_plugin_write_test_connection (connection, TEST_SCRATCH_DIR, owner_uid, owner_grp, &testfile, &error);
	g_assert_no_error (error);
	g_assert (success);
	g_assert (testfile);

	/* Read the connection back in and compare it to the one we just wrote out */
	reread = nm_keyfile_plugin_connection_from_file (testfile, NULL);
	g_assert (reread);
	g_assert (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT));

	g_clear_error (&error);
	unlink (testfile);
	g_free (testfile);

	g_object_unref (reread);
	g_object_unref (connection);
}

static void
test_read_string_ssid (void)
{
	NMConnection *connection;
	NMSettingWireless *s_wireless;
	GError *error = NULL;
	GBytes *ssid;
	const guint8 *ssid_data;
	gsize ssid_len;
	const char *expected_ssid = "blah blah ssid 1234";
	gboolean success;

	connection = nm_keyfile_plugin_connection_from_file (TEST_KEYFILES_DIR "/Test_String_SSID", NULL);
	g_assert (connection);
	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	/* ===== WIRELESS SETTING ===== */
	s_wireless = nm_connection_get_setting_wireless (connection);
	g_assert (s_wireless);
	ssid = nm_setting_wireless_get_ssid (s_wireless);
	g_assert (ssid);
	ssid_data = g_bytes_get_data (ssid, &ssid_len);
	g_assert_cmpmem (ssid_data, ssid_len, expected_ssid, strlen (expected_ssid));

	g_object_unref (connection);
}

static void
test_write_string_ssid (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	NMSettingIPConfig *s_ip4;
	char *uuid, *testfile = NULL, *tmp;
	GBytes *ssid;
	unsigned char tmpssid[] = { 65, 49, 50, 51, 32, 46, 92, 46, 36, 37, 126, 93 };
	gboolean success;
	NMConnection *reread;
	GError *error = NULL;
	pid_t owner_grp;
	uid_t owner_uid;
	GKeyFile *keyfile;

	connection = nm_simple_connection_new ();

	/* Connection setting */

	s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "String SSID Test",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRELESS_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* Wireless setting */

	s_wireless = NM_SETTING_WIRELESS (nm_setting_wireless_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_wireless));

	ssid = g_bytes_new (tmpssid, sizeof (tmpssid));
	g_object_set (s_wireless, NM_SETTING_WIRELESS_SSID, ssid, NULL);
	g_bytes_unref (ssid);

	/* IP4 setting */

	s_ip4 = NM_SETTING_IP_CONFIG (nm_setting_ip4_config_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
	              NULL);

	/* Write out the connection */
	owner_uid = geteuid ();
	owner_grp = getegid ();
	success = nm_keyfile_plugin_write_test_connection (connection, TEST_SCRATCH_DIR, owner_uid, owner_grp, &testfile, &error);
	g_assert_no_error (error);
	g_assert (success);
	g_assert (testfile);

	/* Ensure the SSID was written out as a string */
	keyfile = g_key_file_new ();
	g_assert (g_key_file_load_from_file (keyfile, testfile, 0, NULL));
	tmp = g_key_file_get_string (keyfile, "wifi", NM_SETTING_WIRELESS_SSID, NULL);
	g_assert (tmp);
	g_assert_cmpmem (tmp, strlen (tmp), tmpssid, sizeof (tmpssid));
	g_free (tmp);
	g_key_file_free (keyfile);

	/* Read the connection back in and compare it to the one we just wrote out */
	reread = nm_keyfile_plugin_connection_from_file (testfile, NULL);
	g_assert (reread);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

	g_clear_error (&error);
	unlink (testfile);
	g_free (testfile);

	g_object_unref (reread);
	g_object_unref (connection);
}

static void
test_read_intlist_ssid (void)
{
	NMConnection *connection;
	NMSettingWireless *s_wifi;
	GError *error = NULL;
	gboolean success;
	GBytes *ssid;
	const guint8 *ssid_data;
	gsize ssid_len;
	const char *expected_ssid = "blah1234";

	connection = nm_keyfile_plugin_connection_from_file (TEST_KEYFILES_DIR "/Test_Intlist_SSID", &error);
	g_assert_no_error (error);
	g_assert (connection);

	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	/* SSID */
	s_wifi = nm_connection_get_setting_wireless (connection);
	g_assert (s_wifi);

	ssid = nm_setting_wireless_get_ssid (s_wifi);
	g_assert (ssid != NULL);
	ssid_data = g_bytes_get_data (ssid, &ssid_len);
	g_assert_cmpmem (ssid_data, ssid_len, expected_ssid, strlen (expected_ssid));

	g_object_unref (connection);
}

static void
test_write_intlist_ssid (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wifi;
	NMSettingIPConfig *s_ip4;
	char *uuid, *testfile = NULL;
	GBytes *ssid;
	unsigned char tmpssid[] = { 65, 49, 50, 51, 0, 50, 50 };
	gboolean success;
	NMConnection *reread;
	GError *error = NULL;
	pid_t owner_grp;
	uid_t owner_uid;
	GKeyFile *keyfile;
	gint *intlist;
	gsize len = 0, i;

	connection = nm_simple_connection_new ();
	g_assert (connection);

	/* Connection setting */

	s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());
	g_assert (s_con);
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Intlist SSID Test",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRELESS_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* Wireless setting */
	s_wifi = NM_SETTING_WIRELESS (nm_setting_wireless_new ());
	g_assert (s_wifi);
	nm_connection_add_setting (connection, NM_SETTING (s_wifi));

	ssid = g_bytes_new (tmpssid, sizeof (tmpssid));
	g_object_set (s_wifi, NM_SETTING_WIRELESS_SSID, ssid, NULL);
	g_bytes_unref (ssid);

	/* IP4 setting */
	s_ip4 = NM_SETTING_IP_CONFIG (nm_setting_ip4_config_new ());
	g_assert (s_ip4);
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));
	g_object_set (s_ip4, NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

	/* Write out the connection */
	owner_uid = geteuid ();
	owner_grp = getegid ();
	success = nm_keyfile_plugin_write_test_connection (connection, TEST_SCRATCH_DIR, owner_uid, owner_grp, &testfile, &error);
	g_assert_no_error (error);
	g_assert (success);
	g_assert (testfile != NULL);

	/* Ensure the SSID was written out as an int list */
	keyfile = g_key_file_new ();
	success = g_key_file_load_from_file (keyfile, testfile, 0, &error);
	g_assert_no_error (error);
	g_assert (success);

	intlist = g_key_file_get_integer_list (keyfile, "wifi", NM_SETTING_WIRELESS_SSID, &len, &error);
	g_assert_no_error (error);
	g_assert (intlist);
	g_assert_cmpint (len, ==, sizeof (tmpssid));

	for (i = 0; i < len; i++)
		g_assert_cmpint (intlist[i], ==, tmpssid[i]);
	g_free (intlist);

	g_key_file_free (keyfile);

	/* Read the connection back in and compare it to the one we just wrote out */
	reread = nm_keyfile_plugin_connection_from_file (testfile, &error);
	g_assert_no_error (error);
	g_assert (reread);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

	g_clear_error (&error);
	unlink (testfile);
	g_free (testfile);

	g_object_unref (reread);
	g_object_unref (connection);
}

static void
test_read_intlike_ssid (void)
{
	NMConnection *connection;
	NMSettingWireless *s_wifi;
	GError *error = NULL;
	gboolean success;
	GBytes *ssid;
	const guint8 *ssid_data;
	gsize ssid_len;
	const char *expected_ssid = "101";

	connection = nm_keyfile_plugin_connection_from_file (TEST_KEYFILES_DIR "/Test_Intlike_SSID", &error);
	g_assert_no_error (error);
	g_assert (connection);

	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	/* SSID */
	s_wifi = nm_connection_get_setting_wireless (connection);
	g_assert (s_wifi);

	ssid = nm_setting_wireless_get_ssid (s_wifi);
	g_assert (ssid != NULL);
	ssid_data = g_bytes_get_data (ssid, &ssid_len);
	g_assert_cmpint (ssid_len, ==, strlen (expected_ssid));
	g_assert_cmpint (memcmp (ssid_data, expected_ssid, strlen (expected_ssid)), ==, 0);

	g_object_unref (connection);
}

static void
test_read_intlike_ssid_2 (void)
{
	NMConnection *connection;
	NMSettingWireless *s_wifi;
	GError *error = NULL;
	gboolean success;
	GBytes *ssid;
	const guint8 *ssid_data;
	gsize ssid_len;
	const char *expected_ssid = "11;12;13;";

	connection = nm_keyfile_plugin_connection_from_file (TEST_KEYFILES_DIR "/Test_Intlike_SSID_2", &error);
	g_assert_no_error (error);
	g_assert (connection);

	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	/* SSID */
	s_wifi = nm_connection_get_setting_wireless (connection);
	g_assert (s_wifi);

	ssid = nm_setting_wireless_get_ssid (s_wifi);
	g_assert (ssid != NULL);
	ssid_data = g_bytes_get_data (ssid, &ssid_len);
	g_assert_cmpint (ssid_len, ==, strlen (expected_ssid));
	g_assert_cmpint (memcmp (ssid_data, expected_ssid, strlen (expected_ssid)), ==, 0);

	g_object_unref (connection);
}

static void
test_write_intlike_ssid (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wifi;
	NMSettingIPConfig *s_ip4;
	char *uuid, *testfile = NULL;
	GBytes *ssid;
	unsigned char tmpssid[] = { 49, 48, 49 };
	gboolean success;
	NMConnection *reread;
	GError *error = NULL;
	pid_t owner_grp;
	uid_t owner_uid;
	GKeyFile *keyfile;
	char *tmp;

	connection = nm_simple_connection_new ();
	g_assert (connection);

	/* Connection setting */

	s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());
	g_assert (s_con);
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Intlike SSID Test",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRELESS_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* Wireless setting */
	s_wifi = NM_SETTING_WIRELESS (nm_setting_wireless_new ());
	g_assert (s_wifi);
	nm_connection_add_setting (connection, NM_SETTING (s_wifi));

	ssid = g_bytes_new (tmpssid, sizeof (tmpssid));
	g_object_set (s_wifi, NM_SETTING_WIRELESS_SSID, ssid, NULL);
	g_bytes_unref (ssid);

	/* IP4 setting */
	s_ip4 = NM_SETTING_IP_CONFIG (nm_setting_ip4_config_new ());
	g_assert (s_ip4);
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));
	g_object_set (s_ip4, NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

	/* Write out the connection */
	owner_uid = geteuid ();
	owner_grp = getegid ();
	success = nm_keyfile_plugin_write_test_connection (connection, TEST_SCRATCH_DIR, owner_uid, owner_grp, &testfile, &error);
	g_assert_no_error (error);
	g_assert (success);
	g_assert (testfile != NULL);

	/* Ensure the SSID was written out as a plain "101" */
	keyfile = g_key_file_new ();
	success = g_key_file_load_from_file (keyfile, testfile, 0, &error);
	g_assert_no_error (error);
	g_assert (success);

	tmp = g_key_file_get_string (keyfile, "wifi", NM_SETTING_WIRELESS_SSID, &error);
	g_assert_no_error (error);
	g_assert (tmp);
	g_assert_cmpstr (tmp, ==, "101");
	g_free (tmp);

	g_key_file_free (keyfile);

	/* Read the connection back in and compare it to the one we just wrote out */
	reread = nm_keyfile_plugin_connection_from_file (testfile, &error);
	g_assert_no_error (error);
	g_assert (reread);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

	g_clear_error (&error);
	unlink (testfile);
	g_free (testfile);

	g_object_unref (reread);
	g_object_unref (connection);
}

static void
test_write_intlike_ssid_2 (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wifi;
	NMSettingIPConfig *s_ip4;
	char *uuid, *testfile = NULL;
	GBytes *ssid;
	unsigned char tmpssid[] = { 49, 49, 59, 49, 50, 59, 49, 51, 59};
	gboolean success;
	NMConnection *reread;
	GError *error = NULL;
	pid_t owner_grp;
	uid_t owner_uid;
	GKeyFile *keyfile;
	char *tmp;

	connection = nm_simple_connection_new ();
	g_assert (connection);

	/* Connection setting */

	s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());
	g_assert (s_con);
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Intlike SSID Test 2",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRELESS_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* Wireless setting */
	s_wifi = NM_SETTING_WIRELESS (nm_setting_wireless_new ());
	g_assert (s_wifi);
	nm_connection_add_setting (connection, NM_SETTING (s_wifi));

	ssid = g_bytes_new (tmpssid, sizeof (tmpssid));
	g_object_set (s_wifi, NM_SETTING_WIRELESS_SSID, ssid, NULL);
	g_bytes_unref (ssid);

	/* IP4 setting */
	s_ip4 = NM_SETTING_IP_CONFIG (nm_setting_ip4_config_new ());
	g_assert (s_ip4);
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));
	g_object_set (s_ip4, NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

	/* Write out the connection */
	owner_uid = geteuid ();
	owner_grp = getegid ();
	success = nm_keyfile_plugin_write_test_connection (connection, TEST_SCRATCH_DIR, owner_uid, owner_grp, &testfile, &error);
	g_assert_no_error (error);
	g_assert (success);
	g_assert (testfile != NULL);

	/* Ensure the SSID was written out as a plain "11;12;13;" */
	keyfile = g_key_file_new ();
	success = g_key_file_load_from_file (keyfile, testfile, 0, &error);
	g_assert_no_error (error);
	g_assert (success);

	tmp = g_key_file_get_string (keyfile, "wifi", NM_SETTING_WIRELESS_SSID, &error);
	g_assert_no_error (error);
	g_assert (tmp);
	g_assert_cmpstr (tmp, ==, "11\\;12\\;13\\;");
	g_free (tmp);

	g_key_file_free (keyfile);

	/* Read the connection back in and compare it to the one we just wrote out */
	reread = nm_keyfile_plugin_connection_from_file (testfile, &error);
	g_assert_no_error (error);
	g_assert (reread);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

	g_clear_error (&error);
	unlink (testfile);
	g_free (testfile);

	g_object_unref (reread);
	g_object_unref (connection);
}

static void
test_read_bt_dun_connection (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingBluetooth *s_bluetooth;
	NMSettingSerial *s_serial;
	NMSettingGsm *s_gsm;
	GError *error = NULL;
	const char *bdaddr;
	const guint8 expected_bdaddr[ETH_ALEN] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
	gboolean success;

	connection = nm_keyfile_plugin_connection_from_file (TEST_KEYFILES_DIR "/ATT_Data_Connect_BT", NULL);
	g_assert (connection);
	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	/* ===== CONNECTION SETTING ===== */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "AT&T Data Connect BT");
	g_assert_cmpstr (nm_setting_connection_get_uuid (s_con), ==, "089130ab-ce28-46e4-ad77-d44869b03d19");

	/* ===== BLUETOOTH SETTING ===== */
	s_bluetooth = nm_connection_get_setting_bluetooth (connection);
	g_assert (s_bluetooth);
	bdaddr = nm_setting_bluetooth_get_bdaddr (s_bluetooth);
	g_assert (bdaddr);
	g_assert (nm_utils_hwaddr_matches (bdaddr, -1, expected_bdaddr, sizeof (expected_bdaddr)));
	g_assert_cmpstr (nm_setting_bluetooth_get_connection_type (s_bluetooth), ==, NM_SETTING_BLUETOOTH_TYPE_DUN);

	/* ===== GSM SETTING ===== */
	s_gsm = nm_connection_get_setting_gsm (connection);
	g_assert (s_gsm);
	g_assert_cmpstr (nm_setting_gsm_get_apn (s_gsm), ==, "ISP.CINGULAR");
	g_assert_cmpstr (nm_setting_gsm_get_username (s_gsm), ==, "ISP@CINGULARGPRS.COM");
	g_assert_cmpstr (nm_setting_gsm_get_password (s_gsm), ==, "CINGULAR1");

	/* ===== SERIAL SETTING ===== */
	s_serial = nm_connection_get_setting_serial (connection);
	g_assert (s_serial);
	g_assert (nm_setting_serial_get_parity (s_serial) == NM_SETTING_SERIAL_PARITY_ODD);

	g_object_unref (connection);
}

static void
test_write_bt_dun_connection (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingBluetooth *s_bt;
	NMSettingIPConfig *s_ip4;
	NMSettingGsm *s_gsm;
	char *uuid;
	const char *bdaddr = "aa:b9:a1:74:55:44";
	gboolean success;
	NMConnection *reread;
	char *testfile = NULL;
	GError *error = NULL;
	pid_t owner_grp;
	uid_t owner_uid;
	guint64 timestamp = 0x12344433L;

	connection = nm_simple_connection_new ();

	/* Connection setting */

	s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "T-Mobile Funkadelic",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, FALSE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_BLUETOOTH_SETTING_NAME,
	              NM_SETTING_CONNECTION_TIMESTAMP, timestamp,
	              NULL);
	g_free (uuid);

	/* Bluetooth setting */

	s_bt = NM_SETTING_BLUETOOTH (nm_setting_bluetooth_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_bt));

	g_object_set (s_bt,
	              NM_SETTING_BLUETOOTH_BDADDR, bdaddr,
	              NM_SETTING_BLUETOOTH_TYPE, NM_SETTING_BLUETOOTH_TYPE_DUN,
	              NULL);

	/* IP4 setting */

	s_ip4 = NM_SETTING_IP_CONFIG (nm_setting_ip4_config_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
	              NULL);

	/* GSM setting */
	s_gsm = NM_SETTING_GSM (nm_setting_gsm_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_gsm));

	g_object_set (s_gsm,
	              NM_SETTING_GSM_APN, "internet2.voicestream.com",
	              NM_SETTING_GSM_USERNAME, "george.clinton",
	              NM_SETTING_GSM_PASSWORD, "parliament",
	              NM_SETTING_GSM_NUMBER,  "*99#",
	              NULL);

	/* Write out the connection */
	owner_uid = geteuid ();
	owner_grp = getegid ();
	success = nm_keyfile_plugin_write_test_connection (connection, TEST_SCRATCH_DIR, owner_uid, owner_grp, &testfile, &error);
	g_assert_no_error (error);
	g_assert (success);
	g_assert (testfile);

	/* Read the connection back in and compare it to the one we just wrote out */
	reread = nm_keyfile_plugin_connection_from_file (testfile, NULL);
	g_assert (reread);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

	g_clear_error (&error);
	unlink (testfile);
	g_free (testfile);

	g_object_unref (reread);
	g_object_unref (connection);
}

static void
test_read_gsm_connection (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingSerial *s_serial;
	NMSettingGsm *s_gsm;
	GError *error = NULL;
	gboolean success;

	connection = nm_keyfile_plugin_connection_from_file (TEST_KEYFILES_DIR "/ATT_Data_Connect_Plain", &error);
	g_assert_no_error (error);
	g_assert (connection);

	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	/* ===== CONNECTION SETTING ===== */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "AT&T Data Connect");
	g_assert_cmpstr (nm_setting_connection_get_connection_type (s_con), ==, NM_SETTING_GSM_SETTING_NAME);

	/* ===== BLUETOOTH SETTING ===== */
	/* Plain GSM, so no BT setting expected */
	g_assert (nm_connection_get_setting_bluetooth (connection) == NULL);

	/* ===== GSM SETTING ===== */
	s_gsm = nm_connection_get_setting_gsm (connection);
	g_assert (s_gsm);
	g_assert_cmpstr (nm_setting_gsm_get_apn (s_gsm), ==, "ISP.CINGULAR");
	g_assert_cmpstr (nm_setting_gsm_get_username (s_gsm), ==, "ISP@CINGULARGPRS.COM");
	g_assert_cmpstr (nm_setting_gsm_get_password (s_gsm), ==, "CINGULAR1");
	g_assert_cmpstr (nm_setting_gsm_get_network_id (s_gsm), ==, "24005");
	g_assert_cmpstr (nm_setting_gsm_get_pin (s_gsm), ==, "2345");
	g_assert_cmpstr (nm_setting_gsm_get_device_id (s_gsm), ==, "da812de91eec16620b06cd0ca5cbc7ea25245222");
	g_assert_cmpstr (nm_setting_gsm_get_sim_id (s_gsm), ==, "89148000000060671234");
	g_assert_cmpstr (nm_setting_gsm_get_sim_operator_id (s_gsm), ==, "310260");

	/* ===== SERIAL SETTING ===== */
	s_serial = nm_connection_get_setting_serial (connection);
	g_assert (s_serial);
	g_assert_cmpint (nm_setting_serial_get_parity (s_serial), ==, NM_SETTING_SERIAL_PARITY_ODD);

	g_object_unref (connection);
}

static void
test_write_gsm_connection (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingIPConfig *s_ip4;
	NMSettingGsm *s_gsm;
	char *uuid;
	gboolean success;
	NMConnection *reread;
	char *testfile = NULL;
	GError *error = NULL;
	pid_t owner_grp;
	uid_t owner_uid;
	guint64 timestamp = 0x12344433L;

	connection = nm_simple_connection_new ();

	/* Connection setting */

	s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "T-Mobile Funkadelic 2",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, FALSE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_GSM_SETTING_NAME,
	              NM_SETTING_CONNECTION_TIMESTAMP, timestamp,
	              NULL);
	g_free (uuid);

	/* IP4 setting */

	s_ip4 = NM_SETTING_IP_CONFIG (nm_setting_ip4_config_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
	              NULL);

	/* GSM setting */
	s_gsm = NM_SETTING_GSM (nm_setting_gsm_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_gsm));

	g_object_set (s_gsm,
	              NM_SETTING_GSM_APN, "internet2.voicestream.com",
	              NM_SETTING_GSM_USERNAME, "george.clinton.again",
	              NM_SETTING_GSM_PASSWORD, "parliament2",
	              NM_SETTING_GSM_NUMBER,  "*99#",
	              NM_SETTING_GSM_PIN, "123456",
	              NM_SETTING_GSM_NETWORK_ID, "254098",
	              NM_SETTING_GSM_HOME_ONLY, TRUE,
	              NM_SETTING_GSM_DEVICE_ID, "da812de91eec16620b06cd0ca5cbc7ea25245222",
	              NM_SETTING_GSM_SIM_ID, "89148000000060671234",
	              NM_SETTING_GSM_SIM_OPERATOR_ID, "310260",
	              NULL);

	/* Write out the connection */
	owner_uid = geteuid ();
	owner_grp = getegid ();
	success = nm_keyfile_plugin_write_test_connection (connection, TEST_SCRATCH_DIR, owner_uid, owner_grp, &testfile, &error);
	g_assert_no_error (error);
	g_assert (success);
	g_assert (testfile != NULL);

	/* Read the connection back in and compare it to the one we just wrote out */
	reread = nm_keyfile_plugin_connection_from_file (testfile, &error);
	g_assert_no_error (error);
	g_assert (reread);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

	g_clear_error (&error);
	unlink (testfile);
	g_free (testfile);

	g_object_unref (reread);
	g_object_unref (connection);
}

static void
test_read_wired_8021x_tls_blob_connection (void)
{
	NMConnection *connection;
	NMSettingWired *s_wired;
	NMSetting8021x *s_8021x;
	GError *error = NULL;
	const char *tmp;
	gboolean success;
	GBytes *blob;

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*<warn> * keyfile: 802-1x.client-cert: certificate or key file '/CASA/dcbw/Desktop/certinfra/client.pem' does not exist*");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*<warn> * keyfile: 802-1x.private-key: certificate or key file '/CASA/dcbw/Desktop/certinfra/client.pem' does not exist*");
	connection = nm_keyfile_plugin_connection_from_file (TEST_KEYFILES_DIR "/Test_Wired_TLS_Blob", &error);
	g_assert_no_error (error);
	g_assert (connection);
	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	/* ===== Wired Setting ===== */
	s_wired = nm_connection_get_setting_wired (connection);
	g_assert (s_wired != NULL);

	/* ===== 802.1x Setting ===== */
	s_8021x = nm_connection_get_setting_802_1x (connection);
	g_assert (s_8021x != NULL);

	g_assert (nm_setting_802_1x_get_num_eap_methods (s_8021x) == 1);
	tmp = nm_setting_802_1x_get_eap_method (s_8021x, 0);
	g_assert (g_strcmp0 (tmp, "tls") == 0);

	tmp = nm_setting_802_1x_get_identity (s_8021x);
	g_assert (g_strcmp0 (tmp, "Bill Smith") == 0);

	tmp = nm_setting_802_1x_get_private_key_password (s_8021x);
	g_assert (g_strcmp0 (tmp, "12345testing") == 0);

	g_assert_cmpint (nm_setting_802_1x_get_ca_cert_scheme (s_8021x), ==, NM_SETTING_802_1X_CK_SCHEME_BLOB);

	/* Make sure it's not a path, since it's a blob */
	g_test_expect_message ("libnm", G_LOG_LEVEL_CRITICAL,
	                       "*assertion*scheme == NM_SETTING_802_1X_CK_SCHEME_PATH*");
	tmp = nm_setting_802_1x_get_ca_cert_path (s_8021x);
	g_test_assert_expected_messages ();
	g_assert (tmp == NULL);

	/* Validate the path */
	blob = nm_setting_802_1x_get_ca_cert_blob (s_8021x);
	g_assert (blob != NULL);
	g_assert_cmpint (g_bytes_get_size (blob), ==, 568);

	tmp = nm_setting_802_1x_get_client_cert_path (s_8021x);
	g_assert_cmpstr (tmp, ==, "/CASA/dcbw/Desktop/certinfra/client.pem");

	tmp = nm_setting_802_1x_get_private_key_path (s_8021x);
	g_assert_cmpstr (tmp, ==, "/CASA/dcbw/Desktop/certinfra/client.pem");

	g_object_unref (connection);
}

static void
test_read_wired_8021x_tls_bad_path_connection (void)
{
	NMConnection *connection;
	NMSettingWired *s_wired;
	NMSetting8021x *s_8021x;
	GError *error = NULL;
	const char *tmp;
	char *tmp2;
	gboolean success;

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*does not exist*");
	connection = nm_keyfile_plugin_connection_from_file (TEST_KEYFILES_DIR "/Test_Wired_TLS_Path_Missing", &error);
	g_test_assert_expected_messages ();
	g_assert_no_error (error);
	g_assert (connection);
	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	/* ===== Wired Setting ===== */
	s_wired = nm_connection_get_setting_wired (connection);
	g_assert (s_wired != NULL);

	/* ===== 802.1x Setting ===== */
	s_8021x = nm_connection_get_setting_802_1x (connection);
	g_assert (s_8021x != NULL);

	g_assert (nm_setting_802_1x_get_num_eap_methods (s_8021x) == 1);
	tmp = nm_setting_802_1x_get_eap_method (s_8021x, 0);
	g_assert (g_strcmp0 (tmp, "tls") == 0);

	tmp = nm_setting_802_1x_get_identity (s_8021x);
	g_assert (g_strcmp0 (tmp, "Bill Smith") == 0);

	tmp = nm_setting_802_1x_get_private_key_password (s_8021x);
	g_assert (g_strcmp0 (tmp, "12345testing") == 0);

	g_assert_cmpint (nm_setting_802_1x_get_ca_cert_scheme (s_8021x), ==, NM_SETTING_802_1X_CK_SCHEME_PATH);

	tmp = nm_setting_802_1x_get_ca_cert_path (s_8021x);
	g_assert_cmpstr (tmp, ==, "/some/random/cert/path.pem");

	tmp2 = g_strdup_printf (TEST_KEYFILES_DIR "/test-key-and-cert.pem");

	tmp = nm_setting_802_1x_get_client_cert_path (s_8021x);
	g_assert_cmpstr (tmp, ==, tmp2);

	tmp = nm_setting_802_1x_get_private_key_path (s_8021x);
	g_assert_cmpstr (tmp, ==, tmp2);

	g_free (tmp2);
	g_object_unref (connection);
}

static void
test_read_wired_8021x_tls_old_connection (void)
{
	NMConnection *connection;
	NMSettingWired *s_wired;
	NMSetting8021x *s_8021x;
	GError *error = NULL;
	const char *tmp;
	gboolean success;

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*<warn> * keyfile: 802-1x.ca-cert: certificate or key file '/CASA/dcbw/Desktop/certinfra/CA/eaptest_ca_cert.pem' does not exist*");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*<warn> * keyfile: 802-1x.client-cert: certificate or key file '/CASA/dcbw/Desktop/certinfra/client.pem' does not exist*");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*<warn> * keyfile: 802-1x.private-key: certificate or key file '/CASA/dcbw/Desktop/certinfra/client.pem' does not exist*");
	connection = nm_keyfile_plugin_connection_from_file (TEST_KEYFILES_DIR "/Test_Wired_TLS_Old", &error);
	g_assert_no_error (error);
	g_assert (connection);
	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	/* ===== Wired Setting ===== */
	s_wired = nm_connection_get_setting_wired (connection);
	g_assert (s_wired != NULL);

	/* ===== 802.1x Setting ===== */
	s_8021x = nm_connection_get_setting_802_1x (connection);
	g_assert (s_8021x != NULL);

	g_assert (nm_setting_802_1x_get_num_eap_methods (s_8021x) == 1);
	tmp = nm_setting_802_1x_get_eap_method (s_8021x, 0);
	g_assert (g_strcmp0 (tmp, "tls") == 0);

	tmp = nm_setting_802_1x_get_identity (s_8021x);
	g_assert (g_strcmp0 (tmp, "Bill Smith") == 0);

	tmp = nm_setting_802_1x_get_private_key_password (s_8021x);
	g_assert (g_strcmp0 (tmp, "12345testing") == 0);

	tmp = nm_setting_802_1x_get_ca_cert_path (s_8021x);
	g_assert (g_strcmp0 (tmp, "/CASA/dcbw/Desktop/certinfra/CA/eaptest_ca_cert.pem") == 0);

	tmp = nm_setting_802_1x_get_client_cert_path (s_8021x);
	g_assert (g_strcmp0 (tmp, "/CASA/dcbw/Desktop/certinfra/client.pem") == 0);

	tmp = nm_setting_802_1x_get_private_key_path (s_8021x);
	g_assert (g_strcmp0 (tmp, "/CASA/dcbw/Desktop/certinfra/client.pem") == 0);

	g_object_unref (connection);
}

static void
test_read_wired_8021x_tls_new_connection (void)
{
	NMConnection *connection;
	NMSettingWired *s_wired;
	NMSetting8021x *s_8021x;
	GError *error = NULL;
	const char *tmp;
	char *tmp2;
	gboolean success;

	connection = nm_keyfile_plugin_connection_from_file (TEST_KEYFILES_DIR "/Test_Wired_TLS_New", &error);
	g_assert_no_error (error);
	g_assert (connection);
	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	/* ===== Wired Setting ===== */
	s_wired = nm_connection_get_setting_wired (connection);
	g_assert (s_wired != NULL);

	/* ===== 802.1x Setting ===== */
	s_8021x = nm_connection_get_setting_802_1x (connection);
	g_assert (s_8021x != NULL);

	g_assert (nm_setting_802_1x_get_num_eap_methods (s_8021x) == 1);
	tmp = nm_setting_802_1x_get_eap_method (s_8021x, 0);
	g_assert (g_strcmp0 (tmp, "tls") == 0);

	tmp = nm_setting_802_1x_get_identity (s_8021x);
	g_assert (g_strcmp0 (tmp, "Bill Smith") == 0);

	tmp = nm_setting_802_1x_get_private_key_password (s_8021x);
	g_assert (g_strcmp0 (tmp, "12345testing") == 0);

	tmp2 = g_strdup_printf (TEST_KEYFILES_DIR "/test-ca-cert.pem");
	tmp = nm_setting_802_1x_get_ca_cert_path (s_8021x);
	g_assert_cmpstr (tmp, ==, tmp2);
	g_free (tmp2);

	tmp2 = g_strdup_printf (TEST_KEYFILES_DIR "/test-key-and-cert.pem");

	tmp = nm_setting_802_1x_get_client_cert_path (s_8021x);
	g_assert_cmpstr (tmp, ==, tmp2);

	tmp = nm_setting_802_1x_get_private_key_path (s_8021x);
	g_assert_cmpstr (tmp, ==, tmp2);

	g_free (tmp2);
	g_object_unref (connection);
}

#define TEST_WIRED_TLS_CA_CERT TEST_KEYFILES_DIR"/test-ca-cert.pem"
#define TEST_WIRED_TLS_CLIENT_CERT TEST_KEYFILES_DIR"/test-key-and-cert.pem"
#define TEST_WIRED_TLS_PRIVKEY TEST_KEYFILES_DIR"/test-key-and-cert.pem"

static NMConnection *
create_wired_tls_connection (NMSetting8021xCKScheme scheme)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingIPConfig *s_ip4;
	NMSetting *s_wired;
	NMSetting8021x *s_8021x;
	char *uuid;
	gboolean success;
	GError *error = NULL;

	connection = nm_simple_connection_new ();
	g_assert (connection != NULL);

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	g_assert (s_con);
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Wired Really Secure TLS",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* IP4 setting */
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	g_assert (s_ip4);
	g_object_set (s_ip4, NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	/* Wired setting */
	s_wired = nm_setting_wired_new ();
	g_assert (s_wired);
	nm_connection_add_setting (connection, s_wired);

	/* 802.1x setting */
	s_8021x = (NMSetting8021x *) nm_setting_802_1x_new ();
	g_assert (s_8021x);
	nm_connection_add_setting (connection, NM_SETTING (s_8021x));

	nm_setting_802_1x_add_eap_method (s_8021x, "tls");
	g_object_set (s_8021x, NM_SETTING_802_1X_IDENTITY, "Bill Smith", NULL);

	success = nm_setting_802_1x_set_ca_cert (s_8021x,
	                                         TEST_WIRED_TLS_CA_CERT,
	                                         scheme,
	                                         NULL,
	                                         &error);
	g_assert_no_error (error);
	g_assert (success);

	success = nm_setting_802_1x_set_client_cert (s_8021x,
	                                             TEST_WIRED_TLS_CLIENT_CERT,
	                                             scheme,
	                                             NULL,
	                                             &error);
	g_assert_no_error (error);
	g_assert (success);

	success = nm_setting_802_1x_set_private_key (s_8021x,
	                                             TEST_WIRED_TLS_PRIVKEY,
	                                             "test1",
	                                             scheme,
	                                             NULL,
	                                             &error);
	g_assert_no_error (error);
	g_assert (success);

	return connection;
}

static char *
get_path (const char *file, gboolean relative)
{
	return relative ? g_path_get_basename (file) : g_strdup (file);
}

static void
test_write_wired_8021x_tls_connection_path (void)
{
	NMConnection *connection;
	char *tmp, *tmp2;
	gboolean success;
	NMConnection *reread;
	char *testfile = NULL;
	GError *error = NULL;
	GKeyFile *keyfile;
	gboolean relative = FALSE;

	connection = create_wired_tls_connection (NM_SETTING_802_1X_CK_SCHEME_PATH);
	g_assert (connection != NULL);

	/* Write out the connection */
	success = nm_keyfile_plugin_write_test_connection (connection, TEST_SCRATCH_DIR, geteuid (), getegid (), &testfile, &error);
	if (!success) {
		g_assert (error);
		g_warning ("Failed to write keyfile: %s", error->message);
		g_assert (success);
	}
	g_assert (testfile);

	/* Read the connection back in and compare it to the one we just wrote out */
	reread = nm_keyfile_plugin_connection_from_file (testfile, &error);
	if (!reread) {
		g_assert (error);
		g_warning ("Failed to re-read test connection: %s", error->message);
		g_assert (reread);
	}

	success = nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT);
	if (!reread) {
		g_warning ("Written and re-read connection weren't the same");
		g_assert (success);
	}

	/* Ensure the cert and key values are properly written out */
	keyfile = g_key_file_new ();
	g_assert (keyfile);
	success = g_key_file_load_from_file (keyfile, testfile, G_KEY_FILE_NONE, &error);
	if (!success) {
		g_assert (error);
		g_warning ("Failed to re-read test file %s: %s", testfile, error->message);
		g_assert (success);
	}

	/* Depending on whether this test is being run from 'make check' or
	 * 'make distcheck' we might be using relative paths (check) or
	 * absolute ones (distcheck).
	 */
	tmp2 = g_path_get_dirname (testfile);
	if (g_strcmp0 (tmp2, TEST_KEYFILES_DIR) == 0)
		relative = TRUE;
	g_free (tmp2);

	/* CA cert */
	tmp = g_key_file_get_string (keyfile,
	                             NM_SETTING_802_1X_SETTING_NAME,
	                             NM_SETTING_802_1X_CA_CERT,
	                             NULL);
	tmp2 = get_path (TEST_WIRED_TLS_CA_CERT, relative);
	g_assert_cmpstr (tmp, ==, tmp2);
	g_free (tmp2);
	g_free (tmp);

	/* Client cert */
	tmp = g_key_file_get_string (keyfile,
	                             NM_SETTING_802_1X_SETTING_NAME,
	                             NM_SETTING_802_1X_CLIENT_CERT,
	                             NULL);
	tmp2 = get_path (TEST_WIRED_TLS_CLIENT_CERT, relative);
	g_assert_cmpstr (tmp, ==, tmp2);
	g_free (tmp2);
	g_free (tmp);

	/* Private key */
	tmp = g_key_file_get_string (keyfile,
	                             NM_SETTING_802_1X_SETTING_NAME,
	                             NM_SETTING_802_1X_PRIVATE_KEY,
	                             NULL);
	tmp2 = get_path (TEST_WIRED_TLS_PRIVKEY, relative);
	g_assert_cmpstr (tmp, ==, tmp2);
	g_free (tmp2);
	g_free (tmp);

	g_key_file_free (keyfile);
	unlink (testfile);
	g_free (testfile);

	g_object_unref (reread);
	g_object_unref (connection);
}

static void
test_write_wired_8021x_tls_connection_blob (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSetting8021x *s_8021x;
	gboolean success;
	NMConnection *reread;
	char *testfile = NULL;
	char *new_ca_cert;
	char *new_client_cert;
	char *new_priv_key;
	const char *uuid;
	GError *error = NULL;
	GBytes *password_raw = NULL;
#define PASSWORD_RAW "password-raw\0test"

	connection = create_wired_tls_connection (NM_SETTING_802_1X_CK_SCHEME_BLOB);
	g_assert (connection != NULL);

	s_8021x = nm_connection_get_setting_802_1x (connection);
	g_assert (s_8021x);

	password_raw = g_bytes_new (PASSWORD_RAW, NM_STRLEN (PASSWORD_RAW));
	g_object_set (s_8021x,
	              NM_SETTING_802_1X_PASSWORD_RAW,
	              password_raw,
	              NULL);
	g_bytes_unref (password_raw);

	/* Write out the connection */
	success = nm_keyfile_plugin_write_test_connection (connection, TEST_SCRATCH_DIR, geteuid (), getegid (), &testfile, &error);
	if (!success) {
		g_assert (error);
		g_warning ("Failed to write keyfile: %s", error->message);
		g_assert (success);
	}
	g_assert (testfile);

	/* Check that the new certs got written out */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	uuid = nm_setting_connection_get_uuid (s_con);
	g_assert (uuid);

	new_ca_cert = g_strdup_printf ("%s/%s-ca-cert.pem", TEST_SCRATCH_DIR, uuid);
	g_assert (new_ca_cert);
	g_assert (g_file_test (new_ca_cert, G_FILE_TEST_EXISTS));

	new_client_cert = g_strdup_printf ("%s/%s-client-cert.pem", TEST_SCRATCH_DIR, uuid);
	g_assert (new_client_cert);
	g_assert (g_file_test (new_client_cert, G_FILE_TEST_EXISTS));

	new_priv_key = g_strdup_printf ("%s/%s-private-key.pem", TEST_SCRATCH_DIR, uuid);
	g_assert (new_priv_key);
	g_assert (g_file_test (new_priv_key, G_FILE_TEST_EXISTS));

	/* Read the connection back in and compare it to the one we just wrote out */
	reread = nm_keyfile_plugin_connection_from_file (testfile, &error);
	if (!reread) {
		g_assert (error);
		g_warning ("Failed to re-read test connection: %s", error->message);
		g_assert (reread);
	}

	/* Ensure the re-read connection's certificates use the path scheme */
	s_8021x = nm_connection_get_setting_802_1x (reread);
	g_assert (s_8021x);
	g_assert (nm_setting_802_1x_get_ca_cert_scheme (s_8021x) == NM_SETTING_802_1X_CK_SCHEME_PATH);
	g_assert (nm_setting_802_1x_get_client_cert_scheme (s_8021x) == NM_SETTING_802_1X_CK_SCHEME_PATH);
	g_assert (nm_setting_802_1x_get_private_key_scheme (s_8021x) == NM_SETTING_802_1X_CK_SCHEME_PATH);

	password_raw = nm_setting_802_1x_get_password_raw (s_8021x);
	g_assert (password_raw);
	g_assert (g_bytes_get_size (password_raw) == NM_STRLEN (PASSWORD_RAW));
	g_assert (!memcmp (g_bytes_get_data (password_raw, NULL), PASSWORD_RAW, NM_STRLEN (PASSWORD_RAW)));

	unlink (testfile);
	g_free (testfile);

	/* Clean up written certs */
	unlink (new_ca_cert);
	g_free (new_ca_cert);

	unlink (new_client_cert);
	g_free (new_client_cert);

	unlink (new_priv_key);
	g_free (new_priv_key);

	g_object_unref (reread);
	g_object_unref (connection);
}

static void
test_read_infiniband_connection (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingInfiniband *s_ib;
	GError *error = NULL;
	const char *mac;
	guint8 expected_mac[INFINIBAND_ALEN] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
		0x77, 0x88, 0x99, 0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89,
		0x90 };
	const char *expected_id = "Test InfiniBand Connection";
	const char *expected_uuid = "4e80a56d-c99f-4aad-a6dd-b449bc398c57";
	gboolean success;

	connection = nm_keyfile_plugin_connection_from_file (TEST_KEYFILES_DIR "/Test_InfiniBand_Connection", &error);
	g_assert_no_error (error);
	g_assert (connection);
	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	/* Connection setting */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, expected_id);
	g_assert_cmpstr (nm_setting_connection_get_uuid (s_con), ==, expected_uuid);

	/* InfiniBand setting */
	s_ib = nm_connection_get_setting_infiniband (connection);
	g_assert (s_ib);

	mac = nm_setting_infiniband_get_mac_address (s_ib);
	g_assert (mac);
	g_assert (nm_utils_hwaddr_matches (mac, -1, expected_mac, sizeof (expected_mac)));

	g_object_unref (connection);
}

static void
test_write_infiniband_connection (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingInfiniband *s_ib;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	char *uuid;
	const char *mac = "99:88:77:66:55:44:ab:bc:cd:de:ef:f0:0a:1b:2c:3d:4e:5f:6f:ba";
	gboolean success;
	NMConnection *reread;
	char *testfile = NULL;
	GError *error = NULL;
	pid_t owner_grp;
	uid_t owner_uid;

	connection = nm_simple_connection_new ();
	g_assert (connection);

	/* Connection setting */

	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	g_assert (s_con);
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Work InfiniBand",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, FALSE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_INFINIBAND_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* InfiniBand setting */
	s_ib = (NMSettingInfiniband *) nm_setting_infiniband_new ();
	g_assert (s_ib);
	nm_connection_add_setting (connection, NM_SETTING (s_ib));

	g_object_set (s_ib,
	              NM_SETTING_INFINIBAND_MAC_ADDRESS, mac,
	              NM_SETTING_INFINIBAND_MTU, 900,
	              NM_SETTING_INFINIBAND_TRANSPORT_MODE, "datagram",
	              NULL);

	/* IP4 setting */
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	g_assert (s_ip4);
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));
	g_object_set (s_ip4, NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	g_assert (s_ip6);
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));
	g_object_set (s_ip6, NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_AUTO, NULL);

	/* Write out the connection */
	owner_uid = geteuid ();
	owner_grp = getegid ();
	success = nm_keyfile_plugin_write_test_connection (connection, TEST_SCRATCH_DIR, owner_uid, owner_grp, &testfile, &error);
	g_assert_no_error (error);
	g_assert (success);
	g_assert (testfile);

	/* Read the connection back in and compare it to the one we just wrote out */
	reread = nm_keyfile_plugin_connection_from_file (testfile, &error);
	g_assert_no_error (error);
	g_assert (reread);

	g_assert (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT));

	unlink (testfile);
	g_free (testfile);

	g_object_unref (reread);
	g_object_unref (connection);
}

static void
test_read_bridge_main (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingIPConfig *s_ip4;
	NMSettingBridge *s_bridge;
	GError *error = NULL;
	const char *expected_id = "Test Bridge Main";
	const char *expected_uuid = "8f061643-fe41-4d4c-a8d9-097d26e2ad3a";
	gboolean success;

	connection = nm_keyfile_plugin_connection_from_file (TEST_KEYFILES_DIR "/Test_Bridge_Main", &error);
	g_assert_no_error (error);
	g_assert (connection);
	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	/* Connection setting */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, expected_id);
	g_assert_cmpstr (nm_setting_connection_get_uuid (s_con), ==, expected_uuid);
	g_assert_cmpstr (nm_setting_connection_get_interface_name (s_con), ==, "br0");

	/* IPv4 setting */
	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_AUTO);

	/* Bridge setting */
	s_bridge = nm_connection_get_setting_bridge (connection);
	g_assert (s_bridge);
	g_assert_cmpuint (nm_setting_bridge_get_forward_delay (s_bridge), ==, 2);
	g_assert_cmpuint (nm_setting_bridge_get_stp (s_bridge), ==, TRUE);
	g_assert_cmpuint (nm_setting_bridge_get_priority (s_bridge), ==, 32744);
	g_assert_cmpuint (nm_setting_bridge_get_hello_time (s_bridge), ==, 7);
	g_assert_cmpuint (nm_setting_bridge_get_max_age (s_bridge), ==, 39);
	g_assert_cmpuint (nm_setting_bridge_get_ageing_time (s_bridge), ==, 235352);
	g_assert_cmpuint (nm_setting_bridge_get_multicast_snooping (s_bridge), ==, FALSE);

	g_object_unref (connection);
}

static void
test_write_bridge_main (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingBridge *s_bridge;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	char *uuid;
	gboolean success;
	NMConnection *reread;
	char *testfile = NULL;
	GError *error = NULL;
	pid_t owner_grp;
	uid_t owner_uid;

	connection = nm_simple_connection_new ();
	g_assert (connection);

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	g_assert (s_con);
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write Bridge Main",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_BRIDGE_SETTING_NAME,
	              NM_SETTING_CONNECTION_INTERFACE_NAME, "br0",
	              NULL);
	g_free (uuid);

	/* Bridge setting */
	s_bridge = (NMSettingBridge *) nm_setting_bridge_new ();
	g_assert (s_bridge);
	nm_connection_add_setting (connection, NM_SETTING (s_bridge));

	/* IP4 setting */
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	g_assert (s_ip4);
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));
	g_object_set (s_ip4,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_MANUAL,
	              NM_SETTING_IP_CONFIG_MAY_FAIL, TRUE,
	              NM_SETTING_IP_CONFIG_GATEWAY, "1.1.1.1",
	              NULL);

	add_one_ip_address (s_ip4, "1.2.3.4", 24);

	/* IP6 setting */
	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	g_assert (s_ip6);
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));
	g_object_set (s_ip6, NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_AUTO, NULL);

	/* Write out the connection */
	owner_uid = geteuid ();
	owner_grp = getegid ();
	success = nm_keyfile_plugin_write_test_connection (connection, TEST_SCRATCH_DIR, owner_uid, owner_grp, &testfile, &error);
	g_assert_no_error (error);
	g_assert (success);
	g_assert (testfile);

	/* Read the connection back in and compare it to the one we just wrote out */
	reread = nm_keyfile_plugin_connection_from_file (testfile, &error);
	g_assert_no_error (error);
	g_assert (reread);

	g_assert (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT));

	unlink (testfile);
	g_free (testfile);

	g_object_unref (reread);
	g_object_unref (connection);
}

static void
test_read_bridge_component (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingBridgePort *s_port;
	NMSettingWired *s_wired;
	const char *mac;
	guint8 expected_mac[ETH_ALEN] = { 0x00, 0x22, 0x15, 0x59, 0x62, 0x97 };
	GError *error = NULL;
	const char *expected_id = "Test Bridge Component";
	const char *expected_uuid = "d7b4f96c-c45e-4298-bef8-f48574f8c1c0";
	gboolean success;

	connection = nm_keyfile_plugin_connection_from_file (TEST_KEYFILES_DIR "/Test_Bridge_Component", &error);
	g_assert_no_error (error);
	g_assert (connection);
	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	/* Connection setting */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, expected_id);
	g_assert_cmpstr (nm_setting_connection_get_uuid (s_con), ==, expected_uuid);
	g_assert_cmpstr (nm_setting_connection_get_master (s_con), ==, "br0");
	g_assert (nm_setting_connection_is_slave_type (s_con, NM_SETTING_BRIDGE_SETTING_NAME));

	/* Wired setting */
	s_wired = nm_connection_get_setting_wired (connection);
	g_assert (s_wired);
	mac = nm_setting_wired_get_mac_address (s_wired);
	g_assert (mac);
	g_assert (nm_utils_hwaddr_matches (mac, -1, expected_mac, sizeof (expected_mac)));

	/* BridgePort setting */
	s_port = nm_connection_get_setting_bridge_port (connection);
	g_assert (s_port);
	g_assert (nm_setting_bridge_port_get_hairpin_mode (s_port));
	g_assert_cmpuint (nm_setting_bridge_port_get_priority (s_port), ==, 28);
	g_assert_cmpuint (nm_setting_bridge_port_get_path_cost (s_port), ==, 100);

	g_object_unref (connection);
}

static void
test_write_bridge_component (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingBridgePort *s_port;
	NMSettingWired *s_wired;
	char *uuid;
	const char *mac = "99:88:77:66:55:44";
	gboolean success;
	NMConnection *reread;
	char *testfile = NULL;
	GError *error = NULL;
	pid_t owner_grp;
	uid_t owner_uid;

	connection = nm_simple_connection_new ();
	g_assert (connection);

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	g_assert (s_con);
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write Bridge Component",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
	              NM_SETTING_CONNECTION_MASTER, "br0",
	              NM_SETTING_CONNECTION_SLAVE_TYPE, NM_SETTING_BRIDGE_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* Wired setting */
	s_wired = NM_SETTING_WIRED (nm_setting_wired_new ());
	g_assert (s_wired);
	nm_connection_add_setting (connection, NM_SETTING (s_wired));

	g_object_set (s_wired,
	              NM_SETTING_WIRED_MAC_ADDRESS, mac,
	              NM_SETTING_WIRED_MTU, 1300,
	              NULL);

	/* BridgePort setting */
	s_port = (NMSettingBridgePort *) nm_setting_bridge_port_new ();
	g_assert (s_port);
	nm_connection_add_setting (connection, NM_SETTING (s_port));

	g_object_set (s_port,
	              NM_SETTING_BRIDGE_PORT_PRIORITY, 3,
	              NM_SETTING_BRIDGE_PORT_PATH_COST, 99,
	              NULL);

	/* Write out the connection */
	owner_uid = geteuid ();
	owner_grp = getegid ();
	success = nm_keyfile_plugin_write_test_connection (connection, TEST_SCRATCH_DIR, owner_uid, owner_grp, &testfile, &error);
	g_assert_no_error (error);
	g_assert (success);
	g_assert (testfile);

	/* Read the connection back in and compare it to the one we just wrote out */
	reread = nm_keyfile_plugin_connection_from_file (testfile, &error);
	g_assert_no_error (error);
	g_assert (reread);

	g_assert (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT));

	unlink (testfile);
	g_free (testfile);

	g_object_unref (reread);
	g_object_unref (connection);
}

static void
test_read_new_wired_group_name (void)
{
	NMConnection *connection;
	NMSettingWired *s_wired;
	const char *mac;
	guint8 expected_mac[ETH_ALEN] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
	GError *error = NULL;
	gboolean success;

	connection = nm_keyfile_plugin_connection_from_file (TEST_KEYFILES_DIR"/Test_New_Wired_Group_Name", &error);
	g_assert_no_error (error);
	g_assert (connection);
	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	/* Wired setting */
	s_wired = nm_connection_get_setting_wired (connection);
	g_assert (s_wired);
	g_assert_cmpint (nm_setting_wired_get_mtu (s_wired), ==, 1400);

	mac = nm_setting_wired_get_mac_address (s_wired);
	g_assert (mac);
	g_assert (nm_utils_hwaddr_matches (mac, -1, expected_mac, sizeof (expected_mac)));

	g_object_unref (connection);
}

static void
test_write_new_wired_group_name (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	char *uuid;
	gboolean success;
	NMConnection *reread;
	char *testfile = NULL;
	GError *error = NULL;
	pid_t owner_grp;
	uid_t owner_uid;
	GKeyFile *kf;
	char *s;
	gint mtu;

	connection = nm_simple_connection_new ();
	g_assert (connection);

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	g_assert (s_con);
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write Wired New Group Name",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* Wired setting */
	s_wired = (NMSettingWired *) nm_setting_wired_new ();
	g_assert (s_wired);
	g_object_set (s_wired, NM_SETTING_WIRED_MTU, 1400, NULL);
	nm_connection_add_setting (connection, NM_SETTING (s_wired));

	/* Write out the connection */
	owner_uid = geteuid ();
	owner_grp = getegid ();
	success = nm_keyfile_plugin_write_test_connection (connection, TEST_SCRATCH_DIR, owner_uid, owner_grp, &testfile, &error);
	g_assert_no_error (error);
	g_assert (success);
	g_assert (testfile);

	/* Read the connection back in and compare it to the one we just wrote out */
	reread = nm_keyfile_plugin_connection_from_file (testfile, &error);
	g_assert_no_error (error);
	g_assert (reread);
	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

	/* Look at the keyfile itself to ensure we wrote out the new group names and type */
	kf = g_key_file_new ();
	success = g_key_file_load_from_file (kf, testfile, G_KEY_FILE_NONE, &error);
	g_assert_no_error (error);
	g_assert (success);

	s = g_key_file_get_string (kf, NM_SETTING_CONNECTION_SETTING_NAME, NM_SETTING_CONNECTION_TYPE, &error);
	g_assert_no_error (error);
	g_assert_cmpstr (s, ==, "ethernet");
	g_free (s);

	mtu = g_key_file_get_integer (kf, "ethernet", NM_SETTING_WIRED_MTU, &error);
	g_assert_no_error (error);
	g_assert_cmpint (mtu, ==, 1400);

	unlink (testfile);
	g_free (testfile);

	g_key_file_unref (kf);
	g_object_unref (reread);
	g_object_unref (connection);
}

static void
test_read_new_wireless_group_names (void)
{
	NMConnection *connection;
	NMSettingWireless *s_wifi;
	NMSettingWirelessSecurity *s_wsec;
	GBytes *ssid;
	const guint8 *ssid_data;
	gsize ssid_len;
	const char *expected_ssid = "foobar";
	GError *error = NULL;
	gboolean success;

	connection = nm_keyfile_plugin_connection_from_file (TEST_KEYFILES_DIR"/Test_New_Wireless_Group_Names", &error);
	g_assert_no_error (error);
	g_assert (connection);
	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	/* Wifi setting */
	s_wifi = nm_connection_get_setting_wireless (connection);
	g_assert (s_wifi);

	ssid = nm_setting_wireless_get_ssid (s_wifi);
	g_assert (ssid);
	ssid_data = g_bytes_get_data (ssid, &ssid_len);
	g_assert_cmpint (ssid_len, ==, strlen (expected_ssid));
	g_assert_cmpint (memcmp (ssid_data, expected_ssid, ssid_len), ==, 0);

	g_assert_cmpstr (nm_setting_wireless_get_mode (s_wifi), ==, NM_SETTING_WIRELESS_MODE_INFRA);

	/* Wifi security setting */
	s_wsec = nm_connection_get_setting_wireless_security (connection);
	g_assert (s_wsec);
	g_assert_cmpstr (nm_setting_wireless_security_get_key_mgmt (s_wsec), ==, "wpa-psk");
	g_assert_cmpstr (nm_setting_wireless_security_get_psk (s_wsec), ==, "s3cu4e passphrase");

	g_object_unref (connection);
}

static void
test_write_new_wireless_group_names (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wifi;
	NMSettingWirelessSecurity *s_wsec;
	char *uuid;
	GBytes *ssid;
	unsigned char tmpssid[] = { 0x31, 0x33, 0x33, 0x37 };
	const char *expected_psk = "asdfasdfasdfa12315";
	gboolean success;
	NMConnection *reread;
	char *testfile = NULL;
	GError *error = NULL;
	pid_t owner_grp;
	uid_t owner_uid;
	GKeyFile *kf;
	char *s;

	connection = nm_simple_connection_new ();

	/* Connection setting */

	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write New Wireless Group Names",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRELESS_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* WiFi setting */
	s_wifi = (NMSettingWireless *) nm_setting_wireless_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wifi));

	ssid = g_bytes_new (tmpssid, sizeof (tmpssid));
	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_MODE, NM_SETTING_WIRELESS_MODE_INFRA,
	              NULL);
	g_bytes_unref (ssid);

	/* WiFi security setting */
	s_wsec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wsec));
	g_object_set (s_wsec,
	              NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "wpa-psk",
	              NM_SETTING_WIRELESS_SECURITY_PSK, expected_psk,
	              NULL);

	/* Write out the connection */
	owner_uid = geteuid ();
	owner_grp = getegid ();
	success = nm_keyfile_plugin_write_test_connection (connection, TEST_SCRATCH_DIR, owner_uid, owner_grp, &testfile, &error);
	g_assert_no_error (error);
	g_assert (success);

	g_assert (testfile);

	/* Read the connection back in and compare it to the one we just wrote out */
	reread = nm_keyfile_plugin_connection_from_file (testfile, &error);
	g_assert_no_error (error);
	g_assert (reread);
	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

	/* Look at the keyfile itself to ensure we wrote out the new group names and type */
	kf = g_key_file_new ();
	success = g_key_file_load_from_file (kf, testfile, G_KEY_FILE_NONE, &error);
	g_assert_no_error (error);
	g_assert (success);

	s = g_key_file_get_string (kf, NM_SETTING_CONNECTION_SETTING_NAME, NM_SETTING_CONNECTION_TYPE, &error);
	g_assert_no_error (error);
	g_assert_cmpstr (s, ==, "wifi");
	g_free (s);

	s = g_key_file_get_string (kf, "wifi", NM_SETTING_WIRELESS_MODE, &error);
	g_assert_no_error (error);
	g_assert_cmpstr (s, ==, NM_SETTING_WIRELESS_MODE_INFRA);
	g_free (s);

	s = g_key_file_get_string (kf, "wifi-security", NM_SETTING_WIRELESS_SECURITY_PSK, &error);
	g_assert_no_error (error);
	g_assert_cmpstr (s, ==, expected_psk);
	g_free (s);

	unlink (testfile);
	g_free (testfile);

	g_key_file_unref (kf);
	g_object_unref (reread);
	g_object_unref (connection);
}

static void
test_read_missing_vlan_setting (void)
{
	NMConnection *connection;
	NMSettingVlan *s_vlan;
	GError *error = NULL;
	gboolean success;

	connection = nm_keyfile_plugin_connection_from_file (TEST_KEYFILES_DIR"/Test_Missing_Vlan_Setting", &error);
	g_assert_no_error (error);
	g_assert (connection);
	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	/* Ensure the VLAN setting exists */
	s_vlan = nm_connection_get_setting_vlan (connection);
	g_assert (s_vlan);
	g_assert_cmpint (nm_setting_vlan_get_id (s_vlan), ==, 0);
	g_assert_cmpint (nm_setting_vlan_get_flags (s_vlan), ==, NM_VLAN_FLAG_REORDER_HEADERS);

	g_object_unref (connection);
}

static void
test_read_missing_vlan_flags (void)
{
	NMConnection *connection;
	NMSettingVlan *s_vlan;
	GError *error = NULL;
	gboolean success;

	connection = nm_keyfile_plugin_connection_from_file (TEST_KEYFILES_DIR"/Test_Missing_Vlan_Flags", &error);
	g_assert_no_error (error);
	g_assert (connection);
	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	/* Ensure the VLAN setting exists */
	s_vlan = nm_connection_get_setting_vlan (connection);
	g_assert (s_vlan);

	g_assert_cmpint (nm_setting_vlan_get_id (s_vlan), ==, 444);
	g_assert_cmpstr (nm_setting_vlan_get_parent (s_vlan), ==, "em1");
	g_assert_cmpint (nm_setting_vlan_get_flags (s_vlan), ==, NM_VLAN_FLAG_REORDER_HEADERS);

	g_object_unref (connection);
}

static void
test_read_missing_id_uuid (void)
{
	NMConnection *connection;
	GError *error = NULL;
	gboolean success;

	connection = nm_keyfile_plugin_connection_from_file (TEST_KEYFILES_DIR"/Test_Missing_ID_UUID", &error);
	g_assert_no_error (error);
	g_assert (connection);
	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	/* Ensure the ID and UUID properties are there */
	g_assert_cmpstr (nm_connection_get_id (connection), ==, "Test_Missing_ID_UUID");
	g_assert (nm_connection_get_uuid (connection));

	g_object_unref (connection);
}

static void
test_read_minimal (void)
{
	NMConnection *connection = NULL;
	gs_unref_object NMConnection *con_archetype = NULL;
	NMSettingConnection *s_con;

	con_archetype = nmtst_create_minimal_connection ("Test_minimal_x",
	                                                 "a15bd68f-c32b-40b8-8d27-49e472a85919",
	                                                 NM_SETTING_WIRED_SETTING_NAME,
	                                                 &s_con);
	nmtst_connection_normalize (con_archetype);


	connection = keyfile_read_connection_from_file (TEST_KEYFILES_DIR"/Test_minimal_1");
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, nm_connection_get_id (connection),
	              NM_SETTING_CONNECTION_UUID, nm_connection_get_uuid (connection),
	              NULL);
	nmtst_assert_connection_equals (con_archetype, FALSE, connection, FALSE);
	g_clear_object (&connection);


	connection = keyfile_read_connection_from_file (TEST_KEYFILES_DIR"/Test_minimal_2");
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, nm_connection_get_id (connection),
	              NM_SETTING_CONNECTION_UUID, nm_connection_get_uuid (connection),
	              NULL);
	nmtst_assert_connection_equals (con_archetype, FALSE, connection, FALSE);
	g_clear_object (&connection);
}

static void
test_read_minimal_slave (void)
{
	NMConnection *connection = NULL;
	gs_unref_object NMConnection *con_archetype = NULL;
	NMSettingConnection *s_con;

	con_archetype = nmtst_create_minimal_connection ("Test_minimal_slave_x",
	                                                 "a56b4ca5-7075-43d4-82c7-5d0cb15f7654",
	                                                 NM_SETTING_WIRED_SETTING_NAME,
	                                                 &s_con);
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_MASTER, "br0",
	              NM_SETTING_CONNECTION_SLAVE_TYPE, "bridge",
	              NULL);
	nmtst_connection_normalize (con_archetype);


	connection = keyfile_read_connection_from_file (TEST_KEYFILES_DIR"/Test_minimal_slave_1");
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, nm_connection_get_id (connection),
	              NM_SETTING_CONNECTION_UUID, nm_connection_get_uuid (connection),
	              NULL);
	nmtst_assert_connection_equals (con_archetype, FALSE, connection, FALSE);
	g_clear_object (&connection);


	connection = keyfile_read_connection_from_file (TEST_KEYFILES_DIR"/Test_minimal_slave_2");
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, nm_connection_get_id (connection),
	              NM_SETTING_CONNECTION_UUID, nm_connection_get_uuid (connection),
	              NULL);
	nmtst_assert_connection_equals (con_archetype, FALSE, connection, FALSE);
	g_clear_object (&connection);

	connection = keyfile_read_connection_from_file (TEST_KEYFILES_DIR"/Test_minimal_slave_3");
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, nm_connection_get_id (connection),
	              NM_SETTING_CONNECTION_UUID, nm_connection_get_uuid (connection),
	              NULL);
	nmtst_assert_connection_equals (con_archetype, FALSE, connection, FALSE);
	g_clear_object (&connection);

	connection = keyfile_read_connection_from_file (TEST_KEYFILES_DIR"/Test_minimal_slave_4");
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, nm_connection_get_id (connection),
	              NM_SETTING_CONNECTION_UUID, nm_connection_get_uuid (connection),
	              NULL);
	nmtst_assert_connection_equals (con_archetype, FALSE, connection, FALSE);
	g_clear_object (&connection);
}

static void
test_read_enum_property (void)
{
	NMConnection *connection;
	NMSettingIPConfig *s_ip6;
	GError *error = NULL;
	gboolean success;

	connection = nm_keyfile_plugin_connection_from_file (TEST_KEYFILES_DIR"/Test_Enum_Property", &error);
	g_assert_no_error (error);
	g_assert (connection);
	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	/* IPv6 setting */
	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	g_assert (s_ip6);
	g_assert_cmpint (nm_setting_ip6_config_get_ip6_privacy (NM_SETTING_IP6_CONFIG (s_ip6)), ==, NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_TEMP_ADDR);

	g_object_unref (connection);
}

static void
test_write_enum_property (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIPConfig *s_ip6;
	char *uuid;
	gboolean success;
	NMConnection *reread;
	char *testfile = NULL;
	GError *error = NULL;
	pid_t owner_grp;
	uid_t owner_uid;

	connection = nm_simple_connection_new ();

	/* Connection setting */

	s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write Enum Property",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* Wired setting */
	s_wired = NM_SETTING_WIRED (nm_setting_wired_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_wired));

	/* IP6 setting */
	s_ip6 = NM_SETTING_IP_CONFIG (nm_setting_ip6_config_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));
	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_AUTO,
	              NM_SETTING_IP6_CONFIG_IP6_PRIVACY, NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_TEMP_ADDR,
	              NULL);

	nmtst_connection_normalize (connection);

	/* Write out the connection */
	owner_uid = geteuid ();
	owner_grp = getegid ();
	success = nm_keyfile_plugin_write_test_connection (connection, TEST_SCRATCH_DIR, owner_uid, owner_grp, &testfile, &error);
	g_assert_no_error (error);
	g_assert (success);
	g_assert (testfile);

	/* Read the connection back in and compare it to the one we just wrote out */
	reread = nm_keyfile_plugin_connection_from_file (testfile, &error);
	g_assert_no_error (error);
	g_assert (reread);

	nmtst_assert_connection_equals (reread, FALSE, connection, FALSE);

	unlink (testfile);
	g_free (testfile);

	g_object_unref (reread);
	g_object_unref (connection);
}

static void
test_read_flags_property (void)
{
	NMConnection *connection;
	NMSettingGsm *s_gsm;
	GError *error = NULL;
	gboolean success;

	connection = nm_keyfile_plugin_connection_from_file (TEST_KEYFILES_DIR"/Test_Flags_Property", &error);
	g_assert_no_error (error);
	g_assert (connection);
	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	/* GSM setting */
	s_gsm = nm_connection_get_setting_gsm (connection);
	g_assert (s_gsm);
	g_assert_cmpint (nm_setting_gsm_get_password_flags (s_gsm), ==,
	                   NM_SETTING_SECRET_FLAG_AGENT_OWNED | NM_SETTING_SECRET_FLAG_NOT_REQUIRED);

	g_object_unref (connection);
}

static void
test_write_flags_property (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSetting *s_gsm;
	char *uuid;
	gboolean success;
	NMConnection *reread;
	char *testfile = NULL;
	GError *error = NULL;
	pid_t owner_grp;
	uid_t owner_uid;

	connection = nm_simple_connection_new ();

	/* Connection setting */

	s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write Flags Property",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_GSM_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* GSM setting */
	s_gsm = nm_setting_gsm_new ();
	nm_connection_add_setting (connection, s_gsm);
	g_object_set (s_gsm,
	              NM_SETTING_GSM_NUMBER, "#99*",
	              NM_SETTING_GSM_APN, "myapn",
	              NM_SETTING_GSM_USERNAME, "adfasdfasdf",
	              NM_SETTING_GSM_PASSWORD_FLAGS, NM_SETTING_SECRET_FLAG_NOT_SAVED | NM_SETTING_SECRET_FLAG_NOT_REQUIRED,
	              NULL);

	nmtst_connection_normalize (connection);

	/* Write out the connection */
	owner_uid = geteuid ();
	owner_grp = getegid ();
	success = nm_keyfile_plugin_write_test_connection (connection, TEST_SCRATCH_DIR, owner_uid, owner_grp, &testfile, &error);
	g_assert_no_error (error);
	g_assert (success);
	g_assert (testfile);

	/* Read the connection back in and compare it to the one we just wrote out */
	reread = nm_keyfile_plugin_connection_from_file (testfile, &error);
	g_assert_no_error (error);
	g_assert (reread);

	nmtst_assert_connection_equals (reread, FALSE, connection, FALSE);

	unlink (testfile);
	g_free (testfile);

	g_object_unref (reread);
	g_object_unref (connection);
}

/*****************************************************************************/

static void
_escape_filename (const char *filename, gboolean would_be_ignored)
{
	gs_free char *esc = NULL;

	g_assert (filename && filename[0]);

	if (!!would_be_ignored != !!nm_keyfile_plugin_utils_should_ignore_file (filename)) {
		if (would_be_ignored)
			g_error ("We expect filename \"%s\" to be ignored, but it isn't", filename);
		else
			g_error ("We expect filename \"%s\" not to be ignored, but it is", filename);
	}

	esc = nm_keyfile_plugin_utils_escape_filename (filename);
	g_assert (esc && esc[0]);
	g_assert (!strchr (esc, '/'));

	if (nm_keyfile_plugin_utils_should_ignore_file (esc))
		g_error ("Escaping filename \"%s\" yielded \"%s\", but this is ignored", filename, esc);
}

static void
test_nm_keyfile_plugin_utils_escape_filename (void)
{
	_escape_filename ("ab", FALSE);
	_escape_filename (".vim-file.swp", TRUE);
	_escape_filename (".vim-file.Swp", TRUE);
	_escape_filename (".vim-file.SWP", TRUE);
	_escape_filename (".vim-file.swpx", TRUE);
	_escape_filename (".vim-file.Swpx", TRUE);
	_escape_filename (".vim-file.SWPX", TRUE);
	_escape_filename (".pem-file.pem", TRUE);
	_escape_filename (".pem-file.Pem", TRUE);
	_escape_filename (".pem-file.PEM", TRUE);
	_escape_filename (".pem-file.der", TRUE);
	_escape_filename (".pem-file.Der", TRUE);
	_escape_filename (".mkstemp.ABCEDF", TRUE);
	_escape_filename (".mkstemp.abcdef", TRUE);
	_escape_filename (".mkstemp.123456", TRUE);
	_escape_filename (".mkstemp.A23456", TRUE);
	_escape_filename (".#emacs-locking", TRUE);
	_escape_filename ("file-with-tilde~", TRUE);
	_escape_filename (".file-with-dot", TRUE);
}

/*****************************************************************************/

NMTST_DEFINE ();

int main (int argc, char **argv)
{
	_nm_utils_set_testing (NM_UTILS_TEST_NO_KEYFILE_OWNER_CHECK);
	nmtst_init_assert_logging (&argc, &argv, "INFO", "DEFAULT");

	/* The tests */
	g_test_add_func ("/keyfile/test_read_valid_wired_connection", test_read_valid_wired_connection);
	g_test_add_func ("/keyfile/test_write_wired_connection", test_write_wired_connection);

	g_test_add_func ("/keyfile/test_read_ip6_wired_connection", test_read_ip6_wired_connection);
	g_test_add_func ("/keyfile/test_write_ip6_wired_connection", test_write_ip6_wired_connection);

	g_test_add_func ("/keyfile/test_read_wired_mac_case", test_read_wired_mac_case);
	g_test_add_func ("/keyfile/test_read_mac_old_format", test_read_mac_old_format);
	g_test_add_func ("/keyfile/test_read_mac_ib_old_format", test_read_mac_ib_old_format);

	g_test_add_func ("/keyfile/test_read_valid_wireless_connection", test_read_valid_wireless_connection);
	g_test_add_func ("/keyfile/test_write_wireless_connection", test_write_wireless_connection);

	g_test_add_func ("/keyfile/test_read_string_ssid", test_read_string_ssid);
	g_test_add_func ("/keyfile/test_write_string_ssid", test_write_string_ssid);

	g_test_add_func ("/keyfile/test_read_intlist_ssid", test_read_intlist_ssid);
	g_test_add_func ("/keyfile/test_write_intlist_ssid", test_write_intlist_ssid);

	g_test_add_func ("/keyfile/test_read_intlike_ssid", test_read_intlike_ssid);
	g_test_add_func ("/keyfile/test_write_intlike_ssid", test_write_intlike_ssid);

	g_test_add_func ("/keyfile/test_read_intlike_ssid_2", test_read_intlike_ssid_2);
	g_test_add_func ("/keyfile/test_write_intlike_ssid_2", test_write_intlike_ssid_2);

	g_test_add_func ("/keyfile/test_read_bt_dun_connection", test_read_bt_dun_connection);
	g_test_add_func ("/keyfile/test_write_bt_dun_connection", test_write_bt_dun_connection);

	g_test_add_func ("/keyfile/test_read_gsm_connection", test_read_gsm_connection);
	g_test_add_func ("/keyfile/test_write_gsm_connection", test_write_gsm_connection);

	g_test_add_func ("/keyfile/test_read_wired_8021x_tls_blob_connection", test_read_wired_8021x_tls_blob_connection);
	g_test_add_func ("/keyfile/test_read_wired_8021x_tls_bad_path_connection", test_read_wired_8021x_tls_bad_path_connection);

	g_test_add_func ("/keyfile/test_read_wired_8021x_tls_old_connection", test_read_wired_8021x_tls_old_connection);
	g_test_add_func ("/keyfile/test_read_wired_8021x_tls_new_connection", test_read_wired_8021x_tls_new_connection);
	g_test_add_func ("/keyfile/test_write_wired_8021x_tls_connection_path", test_write_wired_8021x_tls_connection_path);
	g_test_add_func ("/keyfile/test_write_wired_8021x_tls_connection_blob", test_write_wired_8021x_tls_connection_blob);

	g_test_add_func ("/keyfile/test_read_infiniband_connection", test_read_infiniband_connection);
	g_test_add_func ("/keyfile/test_write_infiniband_connection", test_write_infiniband_connection);

	g_test_add_func ("/keyfile/test_read_bridge_main", test_read_bridge_main);
	g_test_add_func ("/keyfile/test_write_bridge_main", test_write_bridge_main);
	g_test_add_func ("/keyfile/test_read_bridge_component", test_read_bridge_component);
	g_test_add_func ("/keyfile/test_write_bridge_component", test_write_bridge_component);

	g_test_add_func ("/keyfile/test_read_new_wired_group_name", test_read_new_wired_group_name);
	g_test_add_func ("/keyfile/test_write_new_wired_group_name", test_write_new_wired_group_name);
	g_test_add_func ("/keyfile/test_read_new_wireless_group_names", test_read_new_wireless_group_names);
	g_test_add_func ("/keyfile/test_write_new_wireless_group_names", test_write_new_wireless_group_names);

	g_test_add_func ("/keyfile/test_read_missing_vlan_setting", test_read_missing_vlan_setting);
	g_test_add_func ("/keyfile/test_read_missing_vlan_flags", test_read_missing_vlan_flags);
	g_test_add_func ("/keyfile/test_read_missing_id_uuid", test_read_missing_id_uuid);

	g_test_add_func ("/keyfile/test_read_minimal", test_read_minimal);
	g_test_add_func ("/keyfile/test_read_minimal_slave", test_read_minimal_slave);

	g_test_add_func ("/keyfile/test_read_enum_property", test_read_enum_property);
	g_test_add_func ("/keyfile/test_write_enum_property", test_write_enum_property);
	g_test_add_func ("/keyfile/test_read_flags_property", test_read_flags_property);
	g_test_add_func ("/keyfile/test_write_flags_property", test_write_flags_property);

	g_test_add_func ("/keyfile/test_nm_keyfile_plugin_utils_escape_filename", test_nm_keyfile_plugin_utils_escape_filename);

	return g_test_run ();
}

