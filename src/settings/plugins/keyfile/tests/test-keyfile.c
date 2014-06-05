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

#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if_infiniband.h>

#include <nm-utils.h>
#include <nm-setting-connection.h>
#include <nm-setting-wired.h>
#include <nm-setting-wireless.h>
#include <nm-setting-ip4-config.h>
#include <nm-setting-ip6-config.h>
#include <nm-setting-bluetooth.h>
#include <nm-setting-serial.h>
#include <nm-setting-ppp.h>
#include <nm-setting-gsm.h>
#include <nm-setting-8021x.h>
#include <nm-setting-infiniband.h>
#include <nm-logging.h>

#include "reader.h"
#include "writer.h"

#include "nm-test-utils.h"

#define TEST_WIRED_FILE    TEST_KEYFILES_DIR"/Test_Wired_Connection"
#define TEST_WIRELESS_FILE TEST_KEYFILES_DIR"/Test_Wireless_Connection"

static void
check_ip4_address (NMSettingIP4Config *config, int idx, const char *address_str, int plen, const char *gateway_str)
{
	NMIP4Address *ip4 = nm_setting_ip4_config_get_address (config, idx);
	guint32 address, gateway;

	g_assert (inet_pton (AF_INET, address_str, &address) == 1);
	g_assert (inet_pton (AF_INET, gateway_str, &gateway) == 1);

	g_assert (ip4);
	g_assert (nm_ip4_address_get_address (ip4) == address);
	g_assert (nm_ip4_address_get_prefix (ip4) == plen);
	g_assert (nm_ip4_address_get_gateway (ip4) == gateway);
}

static void
check_ip6_address (NMSettingIP6Config *config, int idx, const char *address_str, int plen, const char *gateway_str)
{
	NMIP6Address *ip6 = nm_setting_ip6_config_get_address (config, idx);
	struct in6_addr address;
	struct in6_addr gateway;

	g_assert (inet_pton (AF_INET6, address_str, &address) == 1);
	g_assert (inet_pton (AF_INET6, gateway_str, &gateway) == 1);

	g_assert (ip6);
	g_assert (!memcmp (nm_ip6_address_get_address (ip6), &address, sizeof(address)));
	g_assert (nm_ip6_address_get_prefix (ip6) == plen);
	g_assert (!memcmp (nm_ip6_address_get_gateway (ip6), &gateway, sizeof(gateway)));
}

static void
check_ip4_route (NMSettingIP4Config *config, int idx, const char *destination_str, int plen,
		const char *nexthop_str, int metric)
{
	NMIP4Route *route = nm_setting_ip4_config_get_route (config, idx);
	guint32 destination, nexthop;

	g_assert (inet_pton (AF_INET, destination_str, &destination) == 1);
	g_assert (inet_pton (AF_INET, nexthop_str, &nexthop) == 1);

	g_assert (route);
	g_assert (nm_ip4_route_get_dest (route) == destination);
	g_assert (nm_ip4_route_get_prefix (route) == plen);
	g_assert (nm_ip4_route_get_next_hop (route) == nexthop);
	g_assert (nm_ip4_route_get_metric (route) == metric);
}

static void
check_ip6_route (NMSettingIP6Config *config, int idx, const char *destination_str, int plen,
		const char *next_hop_str, int metric)
{
	NMIP6Route *route = nm_setting_ip6_config_get_route (config, idx);
	struct in6_addr destination;
	struct in6_addr next_hop;

	g_assert (inet_pton (AF_INET6, destination_str, &destination) == 1);
	g_assert (inet_pton (AF_INET6, next_hop_str, &next_hop) == 1);

	g_assert (route);
	g_assert (!memcmp (nm_ip6_route_get_dest (route), &destination, sizeof(destination)));
	g_assert (nm_ip6_route_get_prefix (route) == plen);
	g_assert (!memcmp (nm_ip6_route_get_next_hop (route), &next_hop, sizeof(next_hop)));
	g_assert (nm_ip6_route_get_metric (route) == metric);
}

static void
test_read_valid_wired_connection (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;
	GError *error = NULL;
	const GByteArray *array;
	char expected_mac_address[ETH_ALEN] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
	const char *tmp;
	const char *expected_id = "Test Wired Connection";
	const char *expected_uuid = "4e80a56d-c99f-4aad-a6dd-b449bc398c57";
	const guint64 expected_timestamp = 6654332;
	guint64 timestamp;
	const char *expected_dns1 = "4.2.2.1";
	const char *expected_dns2 = "4.2.2.2";
	guint32 addr;
	struct in6_addr addr6;
	const char *expected6_dns1 = "1111:dddd::aaaa";
	const char *expected6_dns2 = "1::cafe";
	const char *expected6_dnssearch1 = "super-domain.com";
	const char *expected6_dnssearch2 = "redhat.com";
	const char *expected6_dnssearch3 = "gnu.org";

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*ipv4.addresses1*semicolon at the end*");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*ipv4.addresses2*semicolon at the end*");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_WARNING,
	                       "*Missing prefix length*ipv4.address4*");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_WARNING,
	                       "*Missing prefix length*ipv4.address5*");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*ipv4.routes2*semicolon at the end*");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*ipv4.routes3*semicolon at the end*");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*ipv4.routes5*semicolon at the end*");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*ipv4.routes8*semicolon at the end*");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_WARNING,
	                       "*Missing prefix length*ipv6.address4*");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*ipv6.address5*semicolon at the end*");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_WARNING,
	                       "*Missing prefix length*ipv6.address5*");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*ipv6.address7*semicolon at the end*");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*ipv6.routes1*semicolon at the end*");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*ipv6.route6*semicolon at the end*");
	connection = nm_keyfile_plugin_connection_from_file (TEST_WIRED_FILE, NULL);
	g_test_assert_expected_messages ();
	ASSERT (connection != NULL,
			"connection-read", "failed to read %s", TEST_WIRED_FILE);

	ASSERT (nm_connection_verify (connection, &error),
	        "connection-verify", "failed to verify %s: %s", TEST_WIRED_FILE, error->message);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
	        "connection-verify-connection", "failed to verify %s: missing %s setting",
	        TEST_WIRED_FILE,
	        NM_SETTING_CONNECTION_SETTING_NAME);

	/* ID */
	tmp = nm_setting_connection_get_id (s_con);
	ASSERT (tmp != NULL,
	        "connection-verify-connection", "failed to verify %s: missing %s / %s key",
	        TEST_WIRED_FILE,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);
	ASSERT (strcmp (tmp, expected_id) == 0,
	        "connection-verify-connection", "failed to verify %s: unexpected %s / %s key value",
	        TEST_WIRED_FILE,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);

	/* UUID */
	tmp = nm_setting_connection_get_uuid (s_con);
	ASSERT (tmp != NULL,
	        "connection-verify-connection", "failed to verify %s: missing %s / %s key",
	        TEST_WIRED_FILE,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_UUID);
	ASSERT (strcmp (tmp, expected_uuid) == 0,
	        "connection-verify-connection", "failed to verify %s: unexpected %s / %s key value",
	        TEST_WIRED_FILE,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_UUID);

	/* Timestamp */
	timestamp = nm_setting_connection_get_timestamp (s_con);
	ASSERT (timestamp == expected_timestamp,
	        "connection-verify-connection", "failed to verify %s: unexpected %s /%s key value",
	        TEST_WIRED_FILE,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_TIMESTAMP);

	/* Autoconnect */
	ASSERT (nm_setting_connection_get_autoconnect (s_con) == TRUE,
	        "connection-verify-connection", "failed to verify %s: unexpected %s /%s key value",
	        TEST_WIRED_FILE,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_AUTOCONNECT);

	/* ===== WIRED SETTING ===== */

	s_wired = nm_connection_get_setting_wired (connection);
	ASSERT (s_wired != NULL,
	        "connection-verify-wired", "failed to verify %s: missing %s setting",
	        TEST_WIRED_FILE,
	        NM_SETTING_WIRED_SETTING_NAME);

	/* MAC address */
	array = nm_setting_wired_get_mac_address (s_wired);
	ASSERT (array != NULL,
	        "connection-verify-wired", "failed to verify %s: missing %s / %s key",
	        TEST_WIRED_FILE,
	        NM_SETTING_WIRED_SETTING_NAME,
	        NM_SETTING_WIRED_MAC_ADDRESS);
	ASSERT (array->len == ETH_ALEN,
	        "connection-verify-wired", "failed to verify %s: unexpected %s / %s key value length",
	        TEST_WIRED_FILE,
	        NM_SETTING_WIRED_SETTING_NAME,
	        NM_SETTING_WIRED_MAC_ADDRESS);
	ASSERT (memcmp (array->data, &expected_mac_address[0], sizeof (expected_mac_address)) == 0,
	        "connection-verify-wired", "failed to verify %s: unexpected %s / %s key value",
	        TEST_WIRED_FILE,
	        NM_SETTING_WIRED_SETTING_NAME,
	        NM_SETTING_WIRED_MAC_ADDRESS);

	ASSERT (nm_setting_wired_get_mtu (s_wired) == 1400,
	        "connection-verify-wired", "failed to verify %s: unexpected %s / %s key value",
	        TEST_WIRED_FILE,
	        NM_SETTING_WIRED_SETTING_NAME,
	        NM_SETTING_WIRED_MTU);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	ASSERT (s_ip4 != NULL,
	        "connection-verify-ip4", "failed to verify %s: missing %s setting",
	        TEST_WIRED_FILE,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME);

	/* Method */
	tmp = nm_setting_ip4_config_get_method (s_ip4);
	ASSERT (strcmp (tmp, NM_SETTING_IP4_CONFIG_METHOD_MANUAL) == 0,
	        "connection-verify-wired", "failed to verify %s: unexpected %s / %s key value",
	        TEST_WIRED_FILE,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_METHOD);

	/* DNS Addresses */
	ASSERT (nm_setting_ip4_config_get_num_dns (s_ip4) == 2,
	        "connection-verify-wired", "failed to verify %s: unexpected %s / %s key value",
	        TEST_WIRED_FILE,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS);

	ASSERT (inet_pton (AF_INET, expected_dns1, &addr) > 0,
	        "connection-verify-wired", "failed to verify %s: couldn't convert DNS IP address #1",
	        TEST_WIRED_FILE,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS);
	ASSERT (nm_setting_ip4_config_get_dns (s_ip4, 0) == addr,
	        "connection-verify-wired", "failed to verify %s: unexpected %s / %s key value #1",
	        TEST_WIRED_FILE,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS);

	ASSERT (inet_pton (AF_INET, expected_dns2, &addr) > 0,
	        "connection-verify-wired", "failed to verify %s: couldn't convert DNS IP address #2",
	        TEST_WIRED_FILE,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS);
	ASSERT (nm_setting_ip4_config_get_dns (s_ip4, 1) == addr,
	        "connection-verify-wired", "failed to verify %s: unexpected %s / %s key value #2",
	        TEST_WIRED_FILE,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS);

	/* IPv4 addresses */
	g_assert (nm_setting_ip4_config_get_num_addresses (s_ip4) == 6);
	check_ip4_address (s_ip4, 0, "2.3.4.5", 24, "2.3.4.6");
	check_ip4_address (s_ip4, 1, "192.168.0.5", 24, "192.168.0.1");
	check_ip4_address (s_ip4, 2, "1.2.3.4", 16, "1.2.1.1");
	check_ip4_address (s_ip4, 3, "3.4.5.6", 16, "0.0.0.0");
	check_ip4_address (s_ip4, 4, "4.5.6.7", 24, "1.2.3.4");
	check_ip4_address (s_ip4, 5, "5.6.7.8", 24, "0.0.0.0");

	/* IPv4 routes */
	g_assert (nm_setting_ip4_config_get_num_routes (s_ip4) == 12);
	check_ip4_route (s_ip4, 0, "5.6.7.8", 32, "0.0.0.0", 0);
	check_ip4_route (s_ip4, 1, "1.2.3.0", 24, "2.3.4.8", 99);
	check_ip4_route (s_ip4, 2, "1.1.1.2", 12, "0.0.0.0", 0);
	check_ip4_route (s_ip4, 3, "1.1.1.3", 13, "0.0.0.0", 0);
	check_ip4_route (s_ip4, 4, "1.1.1.4", 14, "2.2.2.4", 0);
	check_ip4_route (s_ip4, 5, "1.1.1.5", 15, "2.2.2.5", 0);
	check_ip4_route (s_ip4, 6, "1.1.1.6", 16, "2.2.2.6", 0);
	check_ip4_route (s_ip4, 7, "1.1.1.7", 17, "0.0.0.0", 0);
	check_ip4_route (s_ip4, 8, "1.1.1.8", 18, "0.0.0.0", 0);
	check_ip4_route (s_ip4, 9, "1.1.1.9", 19, "0.0.0.0", 0);
	check_ip4_route (s_ip4, 10, "1.1.1.10", 20, "0.0.0.0", 0);
	check_ip4_route (s_ip4, 11, "1.1.1.11", 21, "0.0.0.0", 21);

	/* ===== IPv6 SETTING ===== */

	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	ASSERT (s_ip6 != NULL,
	        "connection-verify-ip6", "failed to verify %s: missing %s setting",
	        TEST_WIRED_FILE,
	        NM_SETTING_IP6_CONFIG_SETTING_NAME);

	/* Method */
	tmp = nm_setting_ip6_config_get_method (s_ip6);
	ASSERT (strcmp (tmp, NM_SETTING_IP6_CONFIG_METHOD_MANUAL) == 0,
	        "connection-verify-wired", "failed to verify %s: unexpected %s / %s key value",
	        TEST_WIRED_FILE,
	        NM_SETTING_IP6_CONFIG_SETTING_NAME,
	        NM_SETTING_IP6_CONFIG_METHOD);

	/* DNS Addresses */
	ASSERT (nm_setting_ip6_config_get_num_dns (s_ip6) == 2,
	        "connection-verify-wired", "failed to verify %s: unexpected %s / %s key value",
	        TEST_WIRED_FILE,
	        NM_SETTING_IP6_CONFIG_SETTING_NAME,
	        NM_SETTING_IP6_CONFIG_DNS);

	ASSERT (inet_pton (AF_INET6, expected6_dns1, &addr6) > 0,
	        "connection-verify-wired", "failed to verify %s: couldn't convert DNS IP6 address #1",
	        TEST_WIRED_FILE,
	        NM_SETTING_IP6_CONFIG_SETTING_NAME,
	        NM_SETTING_IP6_CONFIG_DNS);
	ASSERT (IN6_ARE_ADDR_EQUAL (nm_setting_ip6_config_get_dns (s_ip6, 0), &addr6),
	        "connection-verify-wired", "failed to verify %s: unexpected %s / %s key value #1",
	        TEST_WIRED_FILE,
	        NM_SETTING_IP6_CONFIG_SETTING_NAME,
	        NM_SETTING_IP6_CONFIG_DNS);

	ASSERT (inet_pton (AF_INET6, expected6_dns2, &addr6) > 0,
	        "connection-verify-wired", "failed to verify %s: couldn't convert DNS IP address #2",
	        TEST_WIRED_FILE,
	        NM_SETTING_IP6_CONFIG_SETTING_NAME,
	        NM_SETTING_IP6_CONFIG_DNS);
	ASSERT (IN6_ARE_ADDR_EQUAL (nm_setting_ip6_config_get_dns (s_ip6, 1), &addr6),
	        "connection-verify-wired", "failed to verify %s: unexpected %s / %s key value #2",
	        TEST_WIRED_FILE,
	        NM_SETTING_IP6_CONFIG_SETTING_NAME,
	        NM_SETTING_IP6_CONFIG_DNS);

	/* DNS Searches */
	ASSERT (nm_setting_ip6_config_get_num_dns_searches (s_ip6) == 3,
	        "connection-verify-wired", "failed to verify %s: unexpected %s / %s key value",
	        TEST_WIRED_FILE,
	        NM_SETTING_IP6_CONFIG_SETTING_NAME,
	        NM_SETTING_IP6_CONFIG_DNS_SEARCH);

	ASSERT (!strcmp (nm_setting_ip6_config_get_dns_search (s_ip6, 0), expected6_dnssearch1),
	        "connection-verify-wired", "failed to verify %s: unexpected %s / %s key value #1",
	        TEST_WIRED_FILE,
	        NM_SETTING_IP6_CONFIG_SETTING_NAME,
	        NM_SETTING_IP6_CONFIG_DNS_SEARCH);
	ASSERT (!strcmp (nm_setting_ip6_config_get_dns_search (s_ip6, 1), expected6_dnssearch2),
	        "connection-verify-wired", "failed to verify %s: unexpected %s / %s key value #2",
	        TEST_WIRED_FILE,
	        NM_SETTING_IP6_CONFIG_SETTING_NAME,
	        NM_SETTING_IP6_CONFIG_DNS_SEARCH);
	ASSERT (!strcmp (nm_setting_ip6_config_get_dns_search (s_ip6, 2), expected6_dnssearch3),
	        "connection-verify-wired", "failed to verify %s: unexpected %s / %s key value #3",
	        TEST_WIRED_FILE,
	        NM_SETTING_IP6_CONFIG_SETTING_NAME,
	        NM_SETTING_IP6_CONFIG_DNS_SEARCH);

	/* IPv6 addresses */
	g_assert (nm_setting_ip6_config_get_num_addresses (s_ip6) == 10);
	check_ip6_address (s_ip6, 0, "2:3:4:5:6:7:8:9", 64, "2:3:4:5:1:2:3:4");
	check_ip6_address (s_ip6, 1, "abcd:1234:ffff::cdde", 64, "::");
	check_ip6_address (s_ip6, 2, "1:2:3:4:5:6:7:8", 96, "::");
	check_ip6_address (s_ip6, 3, "3:4:5:6:7:8:9:0", 128, "::");
	check_ip6_address (s_ip6, 4, "3:4:5:6:7:8:9:14", 64, "::");
	check_ip6_address (s_ip6, 5, "3:4:5:6:7:8:9:15", 64, "::");
	check_ip6_address (s_ip6, 6, "3:4:5:6:7:8:9:16", 66, "::");
	check_ip6_address (s_ip6, 7, "3:4:5:6:7:8:9:17", 67, "::");
	check_ip6_address (s_ip6, 8, "3:4:5:6:7:8:9:18", 68, "::");
	check_ip6_address (s_ip6, 9, "3:4:5:6:7:8:9:19", 69, "1::09");

	/* Route #1 */
	g_assert (nm_setting_ip6_config_get_num_routes (s_ip6) == 7);
	check_ip6_route (s_ip6, 0, "d:e:f:0:1:2:3:4", 64, "f:e:d:c:1:2:3:4", 0);
	check_ip6_route (s_ip6, 1, "a:b:c:d::", 64, "f:e:d:c:1:2:3:4", 99);
	check_ip6_route (s_ip6, 2, "8:7:6:5:4:3:2:1", 128, "::", 0);
	check_ip6_route (s_ip6, 3, "6:7:8:9:0:1:2:3", 126, "::", 1);
	check_ip6_route (s_ip6, 4, "7:8:9:0:1:2:3:4", 125, "::", 5);
	check_ip6_route (s_ip6, 5, "8:9:0:1:2:3:4:5", 124, "::", 6);
	check_ip6_route (s_ip6, 6, "8:9:0:1:2:3:4:6", 123, "::", 0);
	g_object_unref (connection);
}

static void
add_one_ip4_address (NMSettingIP4Config *s_ip4,
                     const char *addr,
                     const char *gw,
                     guint32 prefix)
{
	guint32 tmp;
	NMIP4Address *ip4_addr;

	ip4_addr = nm_ip4_address_new ();
	nm_ip4_address_set_prefix (ip4_addr, prefix);

	inet_pton (AF_INET, addr, &tmp);
	nm_ip4_address_set_address (ip4_addr, tmp);

	inet_pton (AF_INET, gw, &tmp);
	nm_ip4_address_set_gateway (ip4_addr, tmp);

	nm_setting_ip4_config_add_address (s_ip4, ip4_addr);
	nm_ip4_address_unref (ip4_addr);
}

static void
add_one_ip4_route (NMSettingIP4Config *s_ip4,
                   const char *dest,
                   const char *nh,
                   guint32 prefix,
                   guint32 metric)
{
	guint32 addr;
	NMIP4Route *route;

	route = nm_ip4_route_new ();
	nm_ip4_route_set_prefix (route, prefix);
	nm_ip4_route_set_metric (route, metric);

	inet_pton (AF_INET, dest, &addr);
	nm_ip4_route_set_dest (route, addr);

	inet_pton (AF_INET, nh, &addr);
	nm_ip4_route_set_next_hop (route, addr);

	nm_setting_ip4_config_add_route (s_ip4, route);
	nm_ip4_route_unref (route);
}

static void
add_one_ip6_address (NMSettingIP6Config *s_ip6,
                     const char *addr,
                     guint32 prefix,
                     const char *gw)
{
	struct in6_addr tmp;
	NMIP6Address *ip6_addr;

	ip6_addr = nm_ip6_address_new ();
	nm_ip6_address_set_prefix (ip6_addr, prefix);

	inet_pton (AF_INET6, addr, &tmp);
	nm_ip6_address_set_address (ip6_addr, &tmp);

	if (gw) {
		inet_pton (AF_INET6, gw, &tmp);
		nm_ip6_address_set_gateway (ip6_addr, &tmp);
	}

	nm_setting_ip6_config_add_address (s_ip6, ip6_addr);
	nm_ip6_address_unref (ip6_addr);
}

static void
add_one_ip6_route (NMSettingIP6Config *s_ip6,
                   const char *dest,
                   const char *nh,
                   guint32 prefix,
                   guint32 metric)
{
	struct in6_addr addr;
	NMIP6Route *route;

	route = nm_ip6_route_new ();
	nm_ip6_route_set_prefix (route, prefix);
	nm_ip6_route_set_metric (route, metric);

	inet_pton (AF_INET6, dest, &addr);
	nm_ip6_route_set_dest (route, &addr);

	inet_pton (AF_INET6, nh, &addr);
	nm_ip6_route_set_next_hop (route, &addr);

	nm_setting_ip6_config_add_route (s_ip6, route);
	nm_ip6_route_unref (route);
}


static void
test_write_wired_connection (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;
	char *uuid;
	GByteArray *mac;
	unsigned char tmpmac[] = { 0x99, 0x88, 0x77, 0x66, 0x55, 0x44 };
	gboolean success;
	NMConnection *reread;
	char *testfile = NULL;
	GError *error = NULL;
	pid_t owner_grp;
	uid_t owner_uid;
	guint32 addr;
	struct in6_addr addr6;
	const char *dns1 = "4.2.2.1";
	const char *dns2 = "4.2.2.2";
	const char *address1 = "192.168.0.5";
	const char *address1_gw = "192.168.0.1";
	const char *address2 = "1.2.3.4";
	const char *address2_gw = "1.2.1.1";
	const char *route1 = "10.10.10.2";
	const char *route1_nh = "10.10.10.1";
	const char *route2 = "1.1.1.1";
	const char *route2_nh = "1.2.1.1";
	const char *route3 = "2.2.2.2";
	const char *route3_nh = "0.0.0.0";
	const char *route4 = "3.3.3.3";
	const char *route4_nh = "0.0.0.0";
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

	connection = nm_connection_new ();

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

	mac = g_byte_array_sized_new (ETH_ALEN);
	g_byte_array_append (mac, &tmpmac[0], sizeof (tmpmac));
	g_object_set (s_wired,
	              NM_SETTING_WIRED_MAC_ADDRESS, mac,
	              NM_SETTING_WIRED_MTU, 900,
	              NULL);
	g_byte_array_free (mac, TRUE);

	/* IP4 setting */

	s_ip4 = NM_SETTING_IP4_CONFIG (nm_setting_ip4_config_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4,
	              NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_MANUAL,
	              NULL);

	/* Addresses */
	add_one_ip4_address (s_ip4, address1, address1_gw, 24);
	add_one_ip4_address (s_ip4, address2, address2_gw, 8);

	/* Routes */
	add_one_ip4_route (s_ip4, route1, route1_nh, 24, 3);
	add_one_ip4_route (s_ip4, route2, route2_nh, 8, 1);
	add_one_ip4_route (s_ip4, route3, route3_nh, 7, 0);
	add_one_ip4_route (s_ip4, route4, route4_nh, 6, 4);

	/* DNS servers */
	inet_pton (AF_INET, dns1, &addr);
	nm_setting_ip4_config_add_dns (s_ip4, addr);
	inet_pton (AF_INET, dns2, &addr);
	nm_setting_ip4_config_add_dns (s_ip4, addr);

	/* IP6 setting */

	s_ip6 = NM_SETTING_IP6_CONFIG (nm_setting_ip6_config_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_MANUAL,
	              NULL);

	/* Addresses */
	add_one_ip6_address (s_ip6, address6_1, 64, NULL);
	add_one_ip6_address (s_ip6, address6_2, 56, NULL);

	/* Routes */
	add_one_ip6_route (s_ip6, route6_1, route6_1_nh, 64, 3);
	add_one_ip6_route (s_ip6, route6_2, route6_2_nh, 56, 1);
	add_one_ip6_route (s_ip6, route6_3, route6_3_nh, 63, 5);
	add_one_ip6_route (s_ip6, route6_4, route6_4_nh, 62, 0);

	/* DNS servers */
	inet_pton (AF_INET6, dns6_1, &addr6);
	nm_setting_ip6_config_add_dns (s_ip6, &addr6);
	inet_pton (AF_INET6, dns6_2, &addr6);
	nm_setting_ip6_config_add_dns (s_ip6, &addr6);

	/* DNS searches */
	nm_setting_ip6_config_add_dns_search (s_ip6, "wallaceandgromit.com");

	/* Write out the connection */
	owner_uid = geteuid ();
	owner_grp = getegid ();
	success = nm_keyfile_plugin_write_test_connection (connection, TEST_SCRATCH_DIR, owner_uid, owner_grp, &testfile, &error);
	ASSERT (success == TRUE,
			"connection-write", "failed to write keyfile: %s",
			error ? error->message : "(none)");

	ASSERT (testfile != NULL,
			"connection-write", "didn't get keyfile name back after writing connection");

	/* Read the connection back in and compare it to the one we just wrote out */
	reread = nm_keyfile_plugin_connection_from_file (testfile, NULL);
	ASSERT (reread != NULL, "connection-write", "failed to re-read test connection");

	ASSERT (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
			"connection-write", "written and re-read connection weren't the same");

	g_clear_error (&error);
	unlink (testfile);
	g_free (testfile);

	g_object_unref (reread);
	g_object_unref (connection);
}

#define TEST_WIRED_IP6_FILE    TEST_KEYFILES_DIR"/Test_Wired_Connection_IP6"

static void
test_read_ip6_wired_connection (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;
	GError *error = NULL;
	const char *tmp;
	const char *expected_id = "Test Wired Connection IP6";
	const char *expected_uuid = "4e80a56d-c99f-4aad-a6dd-b449bc398c57";

	connection = nm_keyfile_plugin_connection_from_file (TEST_WIRED_IP6_FILE, NULL);
	ASSERT (connection != NULL,
			"connection-read", "failed to read %s", TEST_WIRED_IP6_FILE);

	ASSERT (nm_connection_verify (connection, &error),
	        "connection-verify", "failed to verify %s: %s", TEST_WIRED_IP6_FILE, error->message);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
	        "connection-verify-connection", "failed to verify %s: missing %s setting",
	        TEST_WIRED_IP6_FILE,
	        NM_SETTING_CONNECTION_SETTING_NAME);

	/* ID */
	tmp = nm_setting_connection_get_id (s_con);
	ASSERT (tmp != NULL,
	        "connection-verify-connection", "failed to verify %s: missing %s / %s key",
	        TEST_WIRED_IP6_FILE,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);
	ASSERT (strcmp (tmp, expected_id) == 0,
	        "connection-verify-connection", "failed to verify %s: unexpected %s / %s key value",
	        TEST_WIRED_IP6_FILE,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);

	/* UUID */
	tmp = nm_setting_connection_get_uuid (s_con);
	ASSERT (tmp != NULL,
	        "connection-verify-connection", "failed to verify %s: missing %s / %s key",
	        TEST_WIRED_IP6_FILE,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_UUID);
	ASSERT (strcmp (tmp, expected_uuid) == 0,
	        "connection-verify-connection", "failed to verify %s: unexpected %s / %s key value",
	        TEST_WIRED_IP6_FILE,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_UUID);

	/* ===== WIRED SETTING ===== */

	s_wired = nm_connection_get_setting_wired (connection);
	ASSERT (s_wired != NULL,
	        "connection-verify-wired", "failed to verify %s: missing %s setting",
	        TEST_WIRED_IP6_FILE,
	        NM_SETTING_WIRED_SETTING_NAME);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	ASSERT (s_ip4 != NULL,
	        "connection-verify-ip4", "failed to verify %s: missing %s setting",
	        TEST_WIRED_IP6_FILE,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME);

	/* Method */
	tmp = nm_setting_ip4_config_get_method (s_ip4);
	ASSERT (strcmp (tmp, NM_SETTING_IP4_CONFIG_METHOD_DISABLED) == 0,
	        "connection-verify-wired", "failed to verify %s: unexpected %s / %s key value",
	        TEST_WIRED_IP6_FILE,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_METHOD);

	ASSERT (nm_setting_ip4_config_get_num_addresses (s_ip4) == 0,
	        "connection-verify-wired", "failed to verify %s: unexpected %s / %s key value",
	        TEST_WIRED_IP6_FILE,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS);

	/* ===== IPv6 SETTING ===== */

	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	ASSERT (s_ip6 != NULL,
	        "connection-verify-ip6", "failed to verify %s: missing %s setting",
	        TEST_WIRED_IP6_FILE,
	        NM_SETTING_IP6_CONFIG_SETTING_NAME);

	/* Method */
	tmp = nm_setting_ip6_config_get_method (s_ip6);
	ASSERT (strcmp (tmp, NM_SETTING_IP6_CONFIG_METHOD_MANUAL) == 0,
	        "connection-verify-wired", "failed to verify %s: unexpected %s / %s key value",
	        TEST_WIRED_IP6_FILE,
	        NM_SETTING_IP6_CONFIG_SETTING_NAME,
	        NM_SETTING_IP6_CONFIG_METHOD);

	/* IPv6 address */
	g_assert (nm_setting_ip6_config_get_num_addresses (s_ip6) == 1);
	check_ip6_address (s_ip6, 0, "abcd:1234:ffff::cdde", 64, "abcd:1234:ffff::cdd1");

	g_object_unref (connection);
}

static void
test_write_ip6_wired_connection (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;
	char *uuid;
	gboolean success;
	NMConnection *reread;
	char *testfile = NULL;
	GError *error = NULL;
	pid_t owner_grp;
	uid_t owner_uid;
	struct in6_addr addr6;
	const char *dns = "1::cafe";
	const char *address = "abcd::beef";
	const char *gw = "dcba::beef";

	connection = nm_connection_new ();

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

	s_ip4 = NM_SETTING_IP4_CONFIG (nm_setting_ip4_config_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4,
	              NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_DISABLED,
	              NULL);

	/* IP6 setting */

	s_ip6 = NM_SETTING_IP6_CONFIG (nm_setting_ip6_config_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_MANUAL,
	              NULL);

	/* Addresses */
	add_one_ip6_address (s_ip6, address, 64, gw);

	/* DNS servers */
	inet_pton (AF_INET6, dns, &addr6);
	nm_setting_ip6_config_add_dns (s_ip6, &addr6);

	/* DNS searches */
	nm_setting_ip6_config_add_dns_search (s_ip6, "wallaceandgromit.com");

	/* Write out the connection */
	owner_uid = geteuid ();
	owner_grp = getegid ();
	success = nm_keyfile_plugin_write_test_connection (connection, TEST_SCRATCH_DIR, owner_uid, owner_grp, &testfile, &error);
	ASSERT (success == TRUE,
			"connection-write", "failed to write keyfile: %s",
			error ? error->message : "(none)");

	ASSERT (testfile != NULL,
			"connection-write", "didn't get keyfile name back after writing connection");

	/* Read the connection back in and compare it to the one we just wrote out */
	reread = nm_keyfile_plugin_connection_from_file (testfile, NULL);
	ASSERT (reread != NULL, "connection-write", "failed to re-read test connection");

	ASSERT (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
			"connection-write", "written and re-read connection weren't the same");

	g_clear_error (&error);
	unlink (testfile);
	g_free (testfile);

	g_object_unref (reread);
	g_object_unref (connection);
}

#define TEST_WIRED_MAC_CASE_FILE TEST_KEYFILES_DIR"/Test_Wired_Connection_MAC_Case"

static void
test_read_wired_mac_case (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	GError *error = NULL;
	const GByteArray *array;
	char expected_mac_address[ETH_ALEN] = { 0x00, 0x11, 0xaa, 0xbb, 0xcc, 0x55 };
	const char *tmp;
	const char *expected_id = "Test Wired Connection MAC Case";
	const char *expected_uuid = "4e80a56d-c99f-4aad-a6dd-b449bc398c57";

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*ipv4.addresses1*semicolon at the end*");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*ipv4.addresses2*semicolon at the end*");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*ipv6.routes1*semicolon at the end*");
	connection = nm_keyfile_plugin_connection_from_file (TEST_WIRED_MAC_CASE_FILE, NULL);
	g_test_assert_expected_messages ();
	ASSERT (connection != NULL,
			"connection-read", "failed to read %s", TEST_WIRED_MAC_CASE_FILE);

	ASSERT (nm_connection_verify (connection, &error),
	        "connection-verify", "failed to verify %s: %s", TEST_WIRED_MAC_CASE_FILE, error->message);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
	        "connection-verify-connection", "failed to verify %s: missing %s setting",
	        TEST_WIRED_MAC_CASE_FILE,
	        NM_SETTING_CONNECTION_SETTING_NAME);

	/* ID */
	tmp = nm_setting_connection_get_id (s_con);
	ASSERT (tmp != NULL,
	        "connection-verify-connection", "failed to verify %s: missing %s / %s key",
	        TEST_WIRED_MAC_CASE_FILE,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);
	ASSERT (strcmp (tmp, expected_id) == 0,
	        "connection-verify-connection", "failed to verify %s: unexpected %s / %s key value",
	        TEST_WIRED_MAC_CASE_FILE,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);

	/* UUID */
	tmp = nm_setting_connection_get_uuid (s_con);
	ASSERT (tmp != NULL,
	        "connection-verify-connection", "failed to verify %s: missing %s / %s key",
	        TEST_WIRED_MAC_CASE_FILE,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_UUID);
	ASSERT (strcmp (tmp, expected_uuid) == 0,
	        "connection-verify-connection", "failed to verify %s: unexpected %s / %s key value",
	        TEST_WIRED_MAC_CASE_FILE,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_UUID);

	/* ===== WIRED SETTING ===== */

	s_wired = nm_connection_get_setting_wired (connection);
	ASSERT (s_wired != NULL,
	        "connection-verify-wired", "failed to verify %s: missing %s setting",
	        TEST_WIRED_MAC_CASE_FILE,
	        NM_SETTING_WIRED_SETTING_NAME);

	/* MAC address */
	array = nm_setting_wired_get_mac_address (s_wired);
	ASSERT (array != NULL,
	        "connection-verify-wired", "failed to verify %s: missing %s / %s key",
	        TEST_WIRED_MAC_CASE_FILE,
	        NM_SETTING_WIRED_SETTING_NAME,
	        NM_SETTING_WIRED_MAC_ADDRESS);
	ASSERT (array->len == ETH_ALEN,
	        "connection-verify-wired", "failed to verify %s: unexpected %s / %s key value length",
	        TEST_WIRED_MAC_CASE_FILE,
	        NM_SETTING_WIRED_SETTING_NAME,
	        NM_SETTING_WIRED_MAC_ADDRESS);
	ASSERT (memcmp (array->data, &expected_mac_address[0], sizeof (expected_mac_address)) == 0,
	        "connection-verify-wired", "failed to verify %s: unexpected %s / %s key value",
	        TEST_WIRED_MAC_CASE_FILE,
	        NM_SETTING_WIRED_SETTING_NAME,
	        NM_SETTING_WIRED_MAC_ADDRESS);

	g_object_unref (connection);
}

#define TEST_MAC_OLD_FORMAT_FILE TEST_KEYFILES_DIR"/Test_MAC_Old_Format"

static void
test_read_mac_old_format (void)
{
	NMConnection *connection;
	NMSettingWired *s_wired;
	GError *error = NULL;
	gboolean success;
	const GByteArray *array;
	char expected_mac[ETH_ALEN] = { 0x00, 0x11, 0xaa, 0xbb, 0xcc, 0x55 };
	char expected_cloned_mac[ETH_ALEN] = { 0x00, 0x16, 0xaa, 0xbb, 0xcc, 0xfe };

	connection = nm_keyfile_plugin_connection_from_file (TEST_MAC_OLD_FORMAT_FILE, &error);
	g_assert_no_error (error);
	g_assert (connection);

	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	s_wired = nm_connection_get_setting_wired (connection);
	g_assert (s_wired);

	/* MAC address */
	array = nm_setting_wired_get_mac_address (s_wired);
	g_assert (array);
	g_assert_cmpint (array->len, ==, ETH_ALEN);
	g_assert (memcmp (array->data, expected_mac, ETH_ALEN) == 0);

	/* Cloned MAC address */
	array = nm_setting_wired_get_cloned_mac_address (s_wired);
	g_assert (array);
	g_assert_cmpint (array->len, ==, ETH_ALEN);
	g_assert (memcmp (array->data, expected_cloned_mac, ETH_ALEN) == 0);

	g_object_unref (connection);
}

#define TEST_MAC_IB_OLD_FORMAT_FILE TEST_KEYFILES_DIR"/Test_MAC_IB_Old_Format"

static void
test_read_mac_ib_old_format (void)
{
	NMConnection *connection;
	NMSettingInfiniband *s_ib;
	GError *error = NULL;
	gboolean success;
	const GByteArray *array;
	guint8 expected_mac[INFINIBAND_ALEN] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
		0x77, 0x88, 0x99, 0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89,
		0x90 };

	connection = nm_keyfile_plugin_connection_from_file (TEST_MAC_IB_OLD_FORMAT_FILE, &error);
	g_assert_no_error (error);
	g_assert (connection);

	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	s_ib = nm_connection_get_setting_infiniband (connection);
	g_assert (s_ib);

	/* MAC address */
	array = nm_setting_infiniband_get_mac_address (s_ib);
	g_assert (array);
	g_assert_cmpint (array->len, ==, INFINIBAND_ALEN);
	g_assert_cmpint (memcmp (array->data, expected_mac, sizeof (expected_mac)), ==, 0);

	g_object_unref (connection);
}

static void
test_read_valid_wireless_connection (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	NMSettingIP4Config *s_ip4;
	GError *error = NULL;
	const GByteArray *array;
	char expected_bssid[ETH_ALEN] = { 0x00, 0x1a, 0x33, 0x44, 0x99, 0x82 };
	const char *tmp;
	const char *expected_id = "Test Wireless Connection";
	const char *expected_uuid = "2f962388-e5f3-45af-a62c-ac220b8f7baa";
	const guint64 expected_timestamp = 1226604314;
	guint64 timestamp;

	connection = nm_keyfile_plugin_connection_from_file (TEST_WIRELESS_FILE, NULL);
	ASSERT (connection != NULL,
			"connection-read", "failed to read %s", TEST_WIRELESS_FILE);

	ASSERT (nm_connection_verify (connection, &error),
	        "connection-verify", "failed to verify %s: %s", TEST_WIRELESS_FILE, error->message);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
	        "connection-verify-connection", "failed to verify %s: missing %s setting",
	        TEST_WIRELESS_FILE,
	        NM_SETTING_CONNECTION_SETTING_NAME);

	/* ID */
	tmp = nm_setting_connection_get_id (s_con);
	ASSERT (tmp != NULL,
	        "connection-verify-connection", "failed to verify %s: missing %s / %s key",
	        TEST_WIRELESS_FILE,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);
	ASSERT (strcmp (tmp, expected_id) == 0,
	        "connection-verify-connection", "failed to verify %s: unexpected %s / %s key value",
	        TEST_WIRELESS_FILE,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);

	/* UUID */
	tmp = nm_setting_connection_get_uuid (s_con);
	ASSERT (tmp != NULL,
	        "connection-verify-connection", "failed to verify %s: missing %s / %s key",
	        TEST_WIRELESS_FILE,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_UUID);
	ASSERT (strcmp (tmp, expected_uuid) == 0,
	        "connection-verify-connection", "failed to verify %s: unexpected %s / %s key value",
	        TEST_WIRELESS_FILE,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_UUID);

	/* Timestamp */
	timestamp = nm_setting_connection_get_timestamp (s_con);
	ASSERT (timestamp == expected_timestamp,
	        "connection-verify-connection", "failed to verify %s: unexpected %s /%s key value",
	        TEST_WIRELESS_FILE,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_TIMESTAMP);

	/* Autoconnect */
	ASSERT (nm_setting_connection_get_autoconnect (s_con) == FALSE,
	        "connection-verify-connection", "failed to verify %s: unexpected %s /%s key value",
	        TEST_WIRELESS_FILE,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_AUTOCONNECT);

	/* ===== WIRED SETTING ===== */

	s_wireless = nm_connection_get_setting_wireless (connection);
	ASSERT (s_wireless != NULL,
	        "connection-verify-wireless", "failed to verify %s: missing %s setting",
	        TEST_WIRELESS_FILE,
	        NM_SETTING_WIRED_SETTING_NAME);

	/* BSSID */
	array = nm_setting_wireless_get_bssid (s_wireless);
	ASSERT (array != NULL,
	        "connection-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_WIRELESS_FILE,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_BSSID);
	ASSERT (array->len == ETH_ALEN,
	        "connection-verify-wireless", "failed to verify %s: unexpected %s / %s key value length",
	        TEST_WIRELESS_FILE,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_BSSID);
	ASSERT (memcmp (array->data, &expected_bssid[0], sizeof (expected_bssid)) == 0,
	        "connection-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_WIRELESS_FILE,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_BSSID);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	ASSERT (s_ip4 != NULL,
	        "connection-verify-ip4", "failed to verify %s: missing %s setting",
	        TEST_WIRELESS_FILE,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME);

	/* Method */
	tmp = nm_setting_ip4_config_get_method (s_ip4);
	ASSERT (strcmp (tmp, NM_SETTING_IP4_CONFIG_METHOD_AUTO) == 0,
	        "connection-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_WIRELESS_FILE,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_METHOD);

	g_object_unref (connection);
}

static void
test_write_wireless_connection (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;
	char *uuid;
	GByteArray *bssid;
	unsigned char tmpbssid[] = { 0xaa, 0xb9, 0xa1, 0x74, 0x55, 0x44 };
	GByteArray *ssid;
	unsigned char tmpssid[] = { 0x31, 0x33, 0x33, 0x37 };
	gboolean success;
	NMConnection *reread;
	char *testfile = NULL;
	GError *error = NULL;
	pid_t owner_grp;
	uid_t owner_uid;
	guint64 timestamp = 0x12344433L;

	connection = nm_connection_new ();

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

	bssid = g_byte_array_sized_new (ETH_ALEN);
	g_byte_array_append (bssid, &tmpbssid[0], sizeof (tmpbssid));

	ssid = g_byte_array_sized_new (sizeof (tmpssid));
	g_byte_array_append (ssid, &tmpssid[0], sizeof (tmpssid));

	g_object_set (s_wireless,
	              NM_SETTING_WIRELESS_BSSID, bssid,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRED_MTU, 1000,
	              NULL);

	g_byte_array_free (bssid, TRUE);
	g_byte_array_free (ssid, TRUE);

	/* IP4 setting */

	s_ip4 = NM_SETTING_IP4_CONFIG (nm_setting_ip4_config_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4,
	              NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
	              NULL);

	/* IP6 setting */

	s_ip6 = NM_SETTING_IP6_CONFIG (nm_setting_ip6_config_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_AUTO,
	              NULL);

	/* Write out the connection */
	owner_uid = geteuid ();
	owner_grp = getegid ();
	success = nm_keyfile_plugin_write_test_connection (connection, TEST_SCRATCH_DIR, owner_uid, owner_grp, &testfile, &error);
	ASSERT (success == TRUE,
			"connection-write", "failed to write keyfile: %s",
			error ? error->message : "(none)");

	ASSERT (testfile != NULL,
			"connection-write", "didn't get keyfile name back after writing connection");

	/* Read the connection back in and compare it to the one we just wrote out */
	reread = nm_keyfile_plugin_connection_from_file (testfile, NULL);
	ASSERT (reread != NULL, "connection-write", "failed to re-read test connection");

	ASSERT (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
			"connection-write", "written and re-read connection weren't the same");

	g_clear_error (&error);
	unlink (testfile);
	g_free (testfile);

	g_object_unref (reread);
	g_object_unref (connection);
}

#define TEST_STRING_SSID_FILE TEST_KEYFILES_DIR"/Test_String_SSID"

static void
test_read_string_ssid (void)
{
	NMConnection *connection;
	NMSettingWireless *s_wireless;
	GError *error = NULL;
	const GByteArray *array;
	const char *expected_ssid = "blah blah ssid 1234";

	connection = nm_keyfile_plugin_connection_from_file (TEST_STRING_SSID_FILE, NULL);
	ASSERT (connection != NULL,
			"connection-read", "failed to read %s", TEST_STRING_SSID_FILE);

	ASSERT (nm_connection_verify (connection, &error),
	        "connection-verify", "failed to verify %s: %s", TEST_STRING_SSID_FILE, error->message);

	/* ===== WIRELESS SETTING ===== */

	s_wireless = nm_connection_get_setting_wireless (connection);
	ASSERT (s_wireless != NULL,
	        "connection-verify-wireless", "failed to verify %s: missing %s setting",
	        TEST_STRING_SSID_FILE,
	        NM_SETTING_WIRELESS_SETTING_NAME);

	/* SSID */
	array = nm_setting_wireless_get_ssid (s_wireless);
	ASSERT (array != NULL,
	        "connection-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_STRING_SSID_FILE,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_SSID);
	g_assert_cmpint (array->len, ==, strlen (expected_ssid));
	g_assert (memcmp (array->data, expected_ssid, array->len) == 0);

	g_object_unref (connection);
}

static void
test_write_string_ssid (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	NMSettingIP4Config *s_ip4;
	char *uuid, *testfile = NULL, *tmp;
	GByteArray *ssid;
	unsigned char tmpssid[] = { 65, 49, 50, 51, 32, 46, 92, 46, 36, 37, 126, 93 };
	gboolean success;
	NMConnection *reread;
	GError *error = NULL;
	pid_t owner_grp;
	uid_t owner_uid;
	GKeyFile *keyfile;

	connection = nm_connection_new ();

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

	ssid = g_byte_array_sized_new (sizeof (tmpssid));
	g_byte_array_append (ssid, &tmpssid[0], sizeof (tmpssid));
	g_object_set (s_wireless, NM_SETTING_WIRELESS_SSID, ssid, NULL);
	g_byte_array_free (ssid, TRUE);

	/* IP4 setting */

	s_ip4 = NM_SETTING_IP4_CONFIG (nm_setting_ip4_config_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4,
	              NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
	              NULL);

	/* Write out the connection */
	owner_uid = geteuid ();
	owner_grp = getegid ();
	success = nm_keyfile_plugin_write_test_connection (connection, TEST_SCRATCH_DIR, owner_uid, owner_grp, &testfile, &error);
	ASSERT (success == TRUE,
			"connection-write", "failed to write keyfile: %s",
			error ? error->message : "(none)");

	ASSERT (testfile != NULL,
			"connection-write", "didn't get keyfile name back after writing connection");

	/* Ensure the SSID was written out as a string */
	keyfile = g_key_file_new ();
	ASSERT (g_key_file_load_from_file (keyfile, testfile, 0, NULL) == TRUE,
	        "string-ssid-verify", "failed to load keyfile to verify");
	tmp = g_key_file_get_string (keyfile, "wifi", NM_SETTING_WIRELESS_SSID, NULL);
	ASSERT (tmp, "string-ssid-verify", "failed to load 'ssid' key from file");
	ASSERT (strlen (tmp) == sizeof (tmpssid),
	        "string-ssid-verify", "reread SSID and expected were different sizes");
	ASSERT (memcmp (tmp, tmpssid, sizeof (tmpssid)) == 0,
	        "string-ssid-verify", "reread SSID and expected were different");
	g_free (tmp);
	g_key_file_free (keyfile);

	/* Read the connection back in and compare it to the one we just wrote out */
	reread = nm_keyfile_plugin_connection_from_file (testfile, NULL);
	ASSERT (reread != NULL, "connection-write", "failed to re-read test connection");

	ASSERT (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
			"connection-write", "written and re-read connection weren't the same");

	g_clear_error (&error);
	unlink (testfile);
	g_free (testfile);

	g_object_unref (reread);
	g_object_unref (connection);
}

#define TEST_INTLIST_SSID_FILE TEST_KEYFILES_DIR"/Test_Intlist_SSID"

static void
test_read_intlist_ssid (void)
{
	NMConnection *connection;
	NMSettingWireless *s_wifi;
	GError *error = NULL;
	gboolean success;
	const GByteArray *array;
	const char *expected_ssid = "blah1234";

	connection = nm_keyfile_plugin_connection_from_file (TEST_INTLIST_SSID_FILE, &error);
	g_assert_no_error (error);
	g_assert (connection);

	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	/* SSID */
	s_wifi = nm_connection_get_setting_wireless (connection);
	g_assert (s_wifi);

	array = nm_setting_wireless_get_ssid (s_wifi);
	g_assert (array != NULL);
	g_assert_cmpint (array->len, ==, strlen (expected_ssid));
	g_assert_cmpint (memcmp (array->data, expected_ssid, strlen (expected_ssid)), ==, 0);

	g_object_unref (connection);
}

static void
test_write_intlist_ssid (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wifi;
	NMSettingIP4Config *s_ip4;
	char *uuid, *testfile = NULL;
	GByteArray *ssid;
	unsigned char tmpssid[] = { 65, 49, 50, 51, 0, 50, 50 };
	gboolean success;
	NMConnection *reread;
	GError *error = NULL;
	pid_t owner_grp;
	uid_t owner_uid;
	GKeyFile *keyfile;
	gint *intlist;
	gsize len = 0, i;

	connection = nm_connection_new ();
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

	ssid = g_byte_array_sized_new (sizeof (tmpssid));
	g_byte_array_append (ssid, &tmpssid[0], sizeof (tmpssid));
	g_object_set (s_wifi, NM_SETTING_WIRELESS_SSID, ssid, NULL);
	g_byte_array_free (ssid, TRUE);

	/* IP4 setting */
	s_ip4 = NM_SETTING_IP4_CONFIG (nm_setting_ip4_config_new ());
	g_assert (s_ip4);
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));
	g_object_set (s_ip4, NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

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

	success = nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT);
	g_assert (success);

	g_clear_error (&error);
	unlink (testfile);
	g_free (testfile);

	g_object_unref (reread);
	g_object_unref (connection);
}

#define TEST_INTLIKE_SSID_FILE TEST_KEYFILES_DIR"/Test_Intlike_SSID"

static void
test_read_intlike_ssid (void)
{
	NMConnection *connection;
	NMSettingWireless *s_wifi;
	GError *error = NULL;
	gboolean success;
	const GByteArray *array;
	const char *expected_ssid = "101";

	connection = nm_keyfile_plugin_connection_from_file (TEST_INTLIKE_SSID_FILE, &error);
	g_assert_no_error (error);
	g_assert (connection);

	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	/* SSID */
	s_wifi = nm_connection_get_setting_wireless (connection);
	g_assert (s_wifi);

	array = nm_setting_wireless_get_ssid (s_wifi);
	g_assert (array != NULL);
	g_assert_cmpint (array->len, ==, strlen (expected_ssid));
	g_assert_cmpint (memcmp (array->data, expected_ssid, strlen (expected_ssid)), ==, 0);

	g_object_unref (connection);
}

#define TEST_INTLIKE_SSID_2_FILE TEST_KEYFILES_DIR"/Test_Intlike_SSID_2"

static void
test_read_intlike_ssid_2 (void)
{
	NMConnection *connection;
	NMSettingWireless *s_wifi;
	GError *error = NULL;
	gboolean success;
	const GByteArray *array;
	const char *expected_ssid = "11;12;13;";

	connection = nm_keyfile_plugin_connection_from_file (TEST_INTLIKE_SSID_2_FILE, &error);
	g_assert_no_error (error);
	g_assert (connection);

	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	/* SSID */
	s_wifi = nm_connection_get_setting_wireless (connection);
	g_assert (s_wifi);

	array = nm_setting_wireless_get_ssid (s_wifi);
	g_assert (array != NULL);
	g_assert_cmpint (array->len, ==, strlen (expected_ssid));
	g_assert_cmpint (memcmp (array->data, expected_ssid, strlen (expected_ssid)), ==, 0);

	g_object_unref (connection);
}

static void
test_write_intlike_ssid (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wifi;
	NMSettingIP4Config *s_ip4;
	char *uuid, *testfile = NULL;
	GByteArray *ssid;
	unsigned char tmpssid[] = { 49, 48, 49 };
	gboolean success;
	NMConnection *reread;
	GError *error = NULL;
	pid_t owner_grp;
	uid_t owner_uid;
	GKeyFile *keyfile;
	char *tmp;

	connection = nm_connection_new ();
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

	ssid = g_byte_array_sized_new (sizeof (tmpssid));
	g_byte_array_append (ssid, &tmpssid[0], sizeof (tmpssid));
	g_object_set (s_wifi, NM_SETTING_WIRELESS_SSID, ssid, NULL);
	g_byte_array_free (ssid, TRUE);

	/* IP4 setting */
	s_ip4 = NM_SETTING_IP4_CONFIG (nm_setting_ip4_config_new ());
	g_assert (s_ip4);
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));
	g_object_set (s_ip4, NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

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

	g_key_file_free (keyfile);

	/* Read the connection back in and compare it to the one we just wrote out */
	reread = nm_keyfile_plugin_connection_from_file (testfile, &error);
	g_assert_no_error (error);
	g_assert (reread);

	success = nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT);
	g_assert (success);

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
	NMSettingIP4Config *s_ip4;
	char *uuid, *testfile = NULL;
	GByteArray *ssid;
	unsigned char tmpssid[] = { 49, 49, 59, 49, 50, 59, 49, 51, 59};
	gboolean success;
	NMConnection *reread;
	GError *error = NULL;
	pid_t owner_grp;
	uid_t owner_uid;
	GKeyFile *keyfile;
	char *tmp;

	connection = nm_connection_new ();
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

	ssid = g_byte_array_sized_new (sizeof (tmpssid));
	g_byte_array_append (ssid, &tmpssid[0], sizeof (tmpssid));
	g_object_set (s_wifi, NM_SETTING_WIRELESS_SSID, ssid, NULL);
	g_byte_array_free (ssid, TRUE);

	/* IP4 setting */
	s_ip4 = NM_SETTING_IP4_CONFIG (nm_setting_ip4_config_new ());
	g_assert (s_ip4);
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));
	g_object_set (s_ip4, NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

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

	g_key_file_free (keyfile);

	/* Read the connection back in and compare it to the one we just wrote out */
	reread = nm_keyfile_plugin_connection_from_file (testfile, &error);
	g_assert_no_error (error);
	g_assert (reread);

	success = nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT);
	g_assert (success);

	g_clear_error (&error);
	unlink (testfile);
	g_free (testfile);

	g_object_unref (reread);
	g_object_unref (connection);
}

#define TEST_BT_DUN_FILE TEST_KEYFILES_DIR"/ATT_Data_Connect_BT"

static void
test_read_bt_dun_connection (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingBluetooth *s_bluetooth;
	NMSettingSerial *s_serial;
	NMSettingGsm *s_gsm;
	GError *error = NULL;
	const GByteArray *array;
	char expected_bdaddr[ETH_ALEN] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
	const char *tmp;
	const char *expected_id = "AT&T Data Connect BT";
	const char *expected_uuid = "089130ab-ce28-46e4-ad77-d44869b03d19";
	const char *expected_apn = "ISP.CINGULAR";
	const char *expected_username = "ISP@CINGULARGPRS.COM";
	const char *expected_password = "CINGULAR1";

	connection = nm_keyfile_plugin_connection_from_file (TEST_BT_DUN_FILE, NULL);
	ASSERT (connection != NULL,
			"connection-read", "failed to read %s", TEST_BT_DUN_FILE);

	ASSERT (nm_connection_verify (connection, &error),
	        "connection-verify", "failed to verify %s: %s", TEST_BT_DUN_FILE, error->message);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
	        "connection-verify-connection", "failed to verify %s: missing %s setting",
	        TEST_BT_DUN_FILE,
	        NM_SETTING_CONNECTION_SETTING_NAME);

	/* ID */
	tmp = nm_setting_connection_get_id (s_con);
	ASSERT (tmp != NULL,
	        "connection-verify-connection", "failed to verify %s: missing %s / %s key",
	        TEST_BT_DUN_FILE,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);
	ASSERT (strcmp (tmp, expected_id) == 0,
	        "connection-verify-connection", "failed to verify %s: unexpected %s / %s key value",
	        TEST_BT_DUN_FILE,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);

	/* UUID */
	tmp = nm_setting_connection_get_uuid (s_con);
	ASSERT (tmp != NULL,
	        "connection-verify-connection", "failed to verify %s: missing %s / %s key",
	        TEST_WIRELESS_FILE,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_UUID);
	ASSERT (strcmp (tmp, expected_uuid) == 0,
	        "connection-verify-connection", "failed to verify %s: unexpected %s / %s key value",
	        TEST_WIRELESS_FILE,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_UUID);

	/* ===== BLUETOOTH SETTING ===== */

	s_bluetooth = nm_connection_get_setting_bluetooth (connection);
	ASSERT (s_bluetooth != NULL,
	        "connection-verify-bt", "failed to verify %s: missing %s setting",
	        TEST_WIRELESS_FILE,
	        NM_SETTING_WIRED_SETTING_NAME);

	/* BDADDR */
	array = nm_setting_bluetooth_get_bdaddr (s_bluetooth);
	ASSERT (array != NULL,
	        "connection-verify-bt", "failed to verify %s: missing %s / %s key",
	        TEST_BT_DUN_FILE,
	        NM_SETTING_BLUETOOTH_SETTING_NAME,
	        NM_SETTING_BLUETOOTH_BDADDR);
	ASSERT (array->len == ETH_ALEN,
	        "connection-verify-bt", "failed to verify %s: unexpected %s / %s key value length",
	        TEST_BT_DUN_FILE,
	        NM_SETTING_BLUETOOTH_SETTING_NAME,
	        NM_SETTING_BLUETOOTH_BDADDR);
	ASSERT (memcmp (array->data, &expected_bdaddr[0], sizeof (expected_bdaddr)) == 0,
	        "connection-verify-bt", "failed to verify %s: unexpected %s / %s key value",
	        TEST_BT_DUN_FILE,
	        NM_SETTING_BLUETOOTH_SETTING_NAME,
	        NM_SETTING_BLUETOOTH_BDADDR);

	/* Type */
	tmp = nm_setting_bluetooth_get_connection_type (s_bluetooth);
	ASSERT (tmp != NULL,
	        "connection-verify-bt", "failed to verify %s: missing %s / %s key",
	        TEST_BT_DUN_FILE,
	        NM_SETTING_BLUETOOTH_SETTING_NAME,
	        NM_SETTING_BLUETOOTH_TYPE);
	ASSERT (strcmp (tmp, NM_SETTING_BLUETOOTH_TYPE_DUN) == 0,
	        "connection-verify-bt", "failed to verify %s: unexpected %s / %s key value",
	        TEST_BT_DUN_FILE,
	        NM_SETTING_BLUETOOTH_SETTING_NAME,
	        NM_SETTING_BLUETOOTH_TYPE);

	/* ===== GSM SETTING ===== */

	s_gsm = nm_connection_get_setting_gsm (connection);
	ASSERT (s_gsm != NULL,
	        "connection-verify-gsm", "failed to verify %s: missing %s setting",
	        TEST_BT_DUN_FILE,
	        NM_SETTING_GSM_SETTING_NAME);

	/* APN */
	tmp = nm_setting_gsm_get_apn (s_gsm);
	ASSERT (tmp != NULL,
	        "connection-verify-gsm", "failed to verify %s: missing %s / %s key",
	        TEST_BT_DUN_FILE,
	        NM_SETTING_GSM_SETTING_NAME,
	        NM_SETTING_GSM_APN);
	ASSERT (strcmp (tmp, expected_apn) == 0,
	        "connection-verify-bt", "failed to verify %s: unexpected %s / %s key value",
	        TEST_BT_DUN_FILE,
	        NM_SETTING_GSM_SETTING_NAME,
	        NM_SETTING_GSM_APN);

	/* Username */
	tmp = nm_setting_gsm_get_username (s_gsm);
	ASSERT (tmp != NULL,
	        "connection-verify-gsm", "failed to verify %s: missing %s / %s key",
	        TEST_BT_DUN_FILE,
	        NM_SETTING_GSM_SETTING_NAME,
	        NM_SETTING_GSM_USERNAME);
	ASSERT (strcmp (tmp, expected_username) == 0,
	        "connection-verify-bt", "failed to verify %s: unexpected %s / %s key value",
	        TEST_BT_DUN_FILE,
	        NM_SETTING_GSM_SETTING_NAME,
	        NM_SETTING_GSM_USERNAME);

	/* Password */
	tmp = nm_setting_gsm_get_password (s_gsm);
	ASSERT (tmp != NULL,
	        "connection-verify-gsm", "failed to verify %s: missing %s / %s key",
	        TEST_BT_DUN_FILE,
	        NM_SETTING_GSM_SETTING_NAME,
	        NM_SETTING_GSM_PASSWORD);
	ASSERT (strcmp (tmp, expected_password) == 0,
	        "connection-verify-bt", "failed to verify %s: unexpected %s / %s key value",
	        TEST_BT_DUN_FILE,
	        NM_SETTING_GSM_SETTING_NAME,
	        NM_SETTING_GSM_PASSWORD);

	/* ===== SERIAL SETTING ===== */

	s_serial = nm_connection_get_setting_serial (connection);
	ASSERT (s_serial != NULL,
	        "connection-verify-serial", "failed to verify %s: missing %s setting",
	        TEST_BT_DUN_FILE,
	        NM_SETTING_SERIAL_SETTING_NAME);

	g_object_unref (connection);
}

static void
test_write_bt_dun_connection (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingBluetooth *s_bt;
	NMSettingIP4Config *s_ip4;
	NMSettingGsm *s_gsm;
	char *uuid;
	GByteArray *bdaddr;
	unsigned char tmpbdaddr[] = { 0xaa, 0xb9, 0xa1, 0x74, 0x55, 0x44 };
	gboolean success;
	NMConnection *reread;
	char *testfile = NULL;
	GError *error = NULL;
	pid_t owner_grp;
	uid_t owner_uid;
	guint64 timestamp = 0x12344433L;

	connection = nm_connection_new ();

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

	bdaddr = g_byte_array_sized_new (ETH_ALEN);
	g_byte_array_append (bdaddr, &tmpbdaddr[0], sizeof (tmpbdaddr));

	g_object_set (s_bt,
	              NM_SETTING_BLUETOOTH_BDADDR, bdaddr,
	              NM_SETTING_BLUETOOTH_TYPE, NM_SETTING_BLUETOOTH_TYPE_DUN,
	              NULL);

	g_byte_array_free (bdaddr, TRUE);

	/* IP4 setting */

	s_ip4 = NM_SETTING_IP4_CONFIG (nm_setting_ip4_config_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4,
	              NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
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
	ASSERT (success == TRUE,
			"connection-write", "failed to write keyfile: %s",
			error ? error->message : "(none)");

	ASSERT (testfile != NULL,
			"connection-write", "didn't get keyfile name back after writing connection");

	/* Read the connection back in and compare it to the one we just wrote out */
	reread = nm_keyfile_plugin_connection_from_file (testfile, NULL);
	ASSERT (reread != NULL, "connection-write", "failed to re-read test connection");

	ASSERT (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
			"connection-write", "written and re-read connection weren't the same");

	g_clear_error (&error);
	unlink (testfile);
	g_free (testfile);

	g_object_unref (reread);
	g_object_unref (connection);
}

#define TEST_GSM_FILE TEST_KEYFILES_DIR"/ATT_Data_Connect_Plain"

static void
test_read_gsm_connection (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingSerial *s_serial;
	NMSettingGsm *s_gsm;
	NMSettingBluetooth *s_bluetooth;
	GError *error = NULL;
	const char *tmp;
	const char *expected_id = "AT&T Data Connect";
	const char *expected_apn = "ISP.CINGULAR";
	const char *expected_username = "ISP@CINGULARGPRS.COM";
	const char *expected_password = "CINGULAR1";
	const char *expected_network_id = "24005";
	const char *expected_pin = "2345";

	connection = nm_keyfile_plugin_connection_from_file (TEST_GSM_FILE, NULL);
	ASSERT (connection != NULL,
			"connection-read", "failed to read %s", TEST_GSM_FILE);

	ASSERT (nm_connection_verify (connection, &error),
	        "connection-verify", "failed to verify %s: %s", TEST_GSM_FILE, error->message);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
	        "connection-verify-connection", "failed to verify %s: missing %s setting",
	        TEST_GSM_FILE,
	        NM_SETTING_CONNECTION_SETTING_NAME);

	/* ID */
	tmp = nm_setting_connection_get_id (s_con);
	ASSERT (tmp != NULL,
	        "connection-verify-connection", "failed to verify %s: missing %s / %s key",
	        TEST_GSM_FILE,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);
	ASSERT (strcmp (tmp, expected_id) == 0,
	        "connection-verify-connection", "failed to verify %s: unexpected %s / %s key value",
	        TEST_GSM_FILE,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);

	tmp = nm_setting_connection_get_connection_type (s_con);
	ASSERT (tmp != NULL,
	        "connection-verify-connection", "failed to verify %s: missing %s / %s key",
	        TEST_GSM_FILE,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);
	ASSERT (strcmp (tmp, NM_SETTING_GSM_SETTING_NAME) == 0,
	        "connection-verify-connection", "failed to verify %s: unexpected %s / %s key value",
	        TEST_GSM_FILE,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_TYPE);

	/* ===== BLUETOOTH SETTING ===== */

	/* Plain GSM, so no BT setting expected */
	s_bluetooth = nm_connection_get_setting_bluetooth (connection);
	ASSERT (s_bluetooth == NULL,
	        "connection-verify-bt", "unexpected %s setting",
	        TEST_GSM_FILE,
	        NM_SETTING_BLUETOOTH_SETTING_NAME);

	/* ===== GSM SETTING ===== */

	s_gsm = nm_connection_get_setting_gsm (connection);
	ASSERT (s_gsm != NULL,
	        "connection-verify-gsm", "failed to verify %s: missing %s setting",
	        TEST_GSM_FILE,
	        NM_SETTING_GSM_SETTING_NAME);

	/* APN */
	tmp = nm_setting_gsm_get_apn (s_gsm);
	ASSERT (tmp != NULL,
	        "connection-verify-gsm", "failed to verify %s: missing %s / %s key",
	        TEST_GSM_FILE,
	        NM_SETTING_GSM_SETTING_NAME,
	        NM_SETTING_GSM_APN);
	ASSERT (strcmp (tmp, expected_apn) == 0,
	        "connection-verify-gsm", "failed to verify %s: unexpected %s / %s key value",
	        TEST_GSM_FILE,
	        NM_SETTING_GSM_SETTING_NAME,
	        NM_SETTING_GSM_APN);

	/* Username */
	tmp = nm_setting_gsm_get_username (s_gsm);
	ASSERT (tmp != NULL,
	        "connection-verify-gsm", "failed to verify %s: missing %s / %s key",
	        TEST_GSM_FILE,
	        NM_SETTING_GSM_SETTING_NAME,
	        NM_SETTING_GSM_USERNAME);
	ASSERT (strcmp (tmp, expected_username) == 0,
	        "connection-verify-gsm", "failed to verify %s: unexpected %s / %s key value",
	        TEST_GSM_FILE,
	        NM_SETTING_GSM_SETTING_NAME,
	        NM_SETTING_GSM_USERNAME);

	/* Password */
	tmp = nm_setting_gsm_get_password (s_gsm);
	ASSERT (tmp != NULL,
	        "connection-verify-gsm", "failed to verify %s: missing %s / %s key",
	        TEST_GSM_FILE,
	        NM_SETTING_GSM_SETTING_NAME,
	        NM_SETTING_GSM_PASSWORD);
	ASSERT (strcmp (tmp, expected_password) == 0,
	        "connection-verify-gsm", "failed to verify %s: unexpected %s / %s key value",
	        TEST_GSM_FILE,
	        NM_SETTING_GSM_SETTING_NAME,
	        NM_SETTING_GSM_PASSWORD);

	/* Network ID */
	tmp = nm_setting_gsm_get_network_id (s_gsm);
	ASSERT (tmp != NULL,
	        "connection-verify-gsm", "failed to verify %s: missing %s / %s key",
	        TEST_GSM_FILE,
	        NM_SETTING_GSM_SETTING_NAME,
	        NM_SETTING_GSM_NETWORK_ID);
	ASSERT (strcmp (tmp, expected_network_id) == 0,
	        "connection-verify-gsm", "failed to verify %s: unexpected %s / %s key value",
	        TEST_GSM_FILE,
	        NM_SETTING_GSM_SETTING_NAME,
	        NM_SETTING_GSM_NETWORK_ID);

	/* PIN */
	tmp = nm_setting_gsm_get_pin (s_gsm);
	ASSERT (tmp != NULL,
	        "connection-verify-gsm", "failed to verify %s: missing %s / %s key",
	        TEST_GSM_FILE,
	        NM_SETTING_GSM_SETTING_NAME,
	        NM_SETTING_GSM_PIN);
	ASSERT (strcmp (tmp, expected_pin) == 0,
	        "connection-verify-gsm", "failed to verify %s: unexpected %s / %s key value",
	        TEST_GSM_FILE,
	        NM_SETTING_GSM_SETTING_NAME,
	        NM_SETTING_GSM_PIN);

	/* ===== SERIAL SETTING ===== */

	s_serial = nm_connection_get_setting_serial (connection);
	ASSERT (s_serial != NULL,
	        "connection-verify-serial", "failed to verify %s: missing %s setting",
	        TEST_GSM_FILE,
	        NM_SETTING_SERIAL_SETTING_NAME);

	g_object_unref (connection);
}

static void
test_write_gsm_connection (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingIP4Config *s_ip4;
	NMSettingGsm *s_gsm;
	char *uuid;
	gboolean success;
	NMConnection *reread;
	char *testfile = NULL;
	GError *error = NULL;
	pid_t owner_grp;
	uid_t owner_uid;
	guint64 timestamp = 0x12344433L;

	connection = nm_connection_new ();

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

	s_ip4 = NM_SETTING_IP4_CONFIG (nm_setting_ip4_config_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4,
	              NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
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
	              NM_SETTING_GSM_NETWORK_TYPE, NM_SETTING_GSM_NETWORK_TYPE_PREFER_UMTS_HSPA,
	              NULL);

	/* Write out the connection */
	owner_uid = geteuid ();
	owner_grp = getegid ();
	success = nm_keyfile_plugin_write_test_connection (connection, TEST_SCRATCH_DIR, owner_uid, owner_grp, &testfile, &error);
	ASSERT (success == TRUE,
			"connection-write", "failed to write keyfile: %s",
			error ? error->message : "(none)");

	ASSERT (testfile != NULL,
			"connection-write", "didn't get keyfile name back after writing connection");

	/* Read the connection back in and compare it to the one we just wrote out */
	reread = nm_keyfile_plugin_connection_from_file (testfile, NULL);
	ASSERT (reread != NULL, "connection-write", "failed to re-read test connection");

	ASSERT (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
			"connection-write", "written and re-read connection weren't the same");

	g_clear_error (&error);
	unlink (testfile);
	g_free (testfile);

	g_object_unref (reread);
	g_object_unref (connection);
}

#define TEST_WIRED_TLS_BLOB_FILE TEST_KEYFILES_DIR"/Test_Wired_TLS_Blob"

static void
test_read_wired_8021x_tls_blob_connection (void)
{
	NMConnection *connection;
	NMSettingWired *s_wired;
	NMSetting8021x *s_8021x;
	GError *error = NULL;
	const char *tmp;
	gboolean success;
	const GByteArray *array;

	connection = nm_keyfile_plugin_connection_from_file (TEST_WIRED_TLS_BLOB_FILE, &error);
	if (connection == NULL) {
		g_assert (error);
		g_warning ("Failed to read %s: %s", TEST_WIRED_TLS_BLOB_FILE, error->message);
		g_assert (connection);
	}

	success = nm_connection_verify (connection, &error);
	if (!success) {
		g_assert (error);
		g_warning ("Failed to verify %s: %s", TEST_WIRED_TLS_BLOB_FILE, error->message);
		g_assert (success);
	}

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
	g_test_expect_message ("libnm-util", G_LOG_LEVEL_CRITICAL,
	                       "*assertion*scheme == NM_SETTING_802_1X_CK_SCHEME_PATH*");
	tmp = nm_setting_802_1x_get_ca_cert_path (s_8021x);
	g_test_assert_expected_messages ();
	g_assert (tmp == NULL);

	/* Validate the path */
	array = nm_setting_802_1x_get_ca_cert_blob (s_8021x);
	g_assert (array != NULL);
	g_assert_cmpint (array->len, ==, 568);

	tmp = nm_setting_802_1x_get_client_cert_path (s_8021x);
	g_assert_cmpstr (tmp, ==, "/home/dcbw/Desktop/certinfra/client.pem");

	tmp = nm_setting_802_1x_get_private_key_path (s_8021x);
	g_assert_cmpstr (tmp, ==, "/home/dcbw/Desktop/certinfra/client.pem");

	g_object_unref (connection);
}

#define TEST_WIRED_TLS_PATH_MISSING_FILE TEST_KEYFILES_DIR"/Test_Wired_TLS_Path_Missing"

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

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_WARNING,
	                       "*does not exist*");
	connection = nm_keyfile_plugin_connection_from_file (TEST_WIRED_TLS_PATH_MISSING_FILE, &error);
	g_test_assert_expected_messages ();
	if (connection == NULL) {
		g_assert (error);
		g_warning ("Failed to read %s: %s", TEST_WIRED_TLS_PATH_MISSING_FILE, error->message);
		g_assert (connection);
	}

	success = nm_connection_verify (connection, &error);
	if (!success) {
		g_assert (error);
		g_warning ("Failed to verify %s: %s", TEST_WIRED_TLS_BLOB_FILE, error->message);
		g_assert (success);
	}

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

#define TEST_WIRED_TLS_OLD_FILE TEST_KEYFILES_DIR"/Test_Wired_TLS_Old"

static void
test_read_wired_8021x_tls_old_connection (void)
{
	NMConnection *connection;
	NMSettingWired *s_wired;
	NMSetting8021x *s_8021x;
	GError *error = NULL;
	const char *tmp;
	gboolean success;

	connection = nm_keyfile_plugin_connection_from_file (TEST_WIRED_TLS_OLD_FILE, &error);
	if (connection == NULL) {
		g_assert (error);
		g_warning ("Failed to read %s: %s", TEST_WIRED_TLS_OLD_FILE, error->message);
		g_assert (connection);
	}

	success = nm_connection_verify (connection, &error);
	if (!success) {
		g_assert (error);
		g_warning ("Failed to verify %s: %s", TEST_WIRED_TLS_OLD_FILE, error->message);
		g_assert (success);
	}

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
	g_assert (g_strcmp0 (tmp, "/home/dcbw/Desktop/certinfra/CA/eaptest_ca_cert.pem") == 0);

	tmp = nm_setting_802_1x_get_client_cert_path (s_8021x);
	g_assert (g_strcmp0 (tmp, "/home/dcbw/Desktop/certinfra/client.pem") == 0);

	tmp = nm_setting_802_1x_get_private_key_path (s_8021x);
	g_assert (g_strcmp0 (tmp, "/home/dcbw/Desktop/certinfra/client.pem") == 0);

	g_object_unref (connection);
}

#define TEST_WIRED_TLS_NEW_FILE TEST_KEYFILES_DIR"/Test_Wired_TLS_New"

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

	connection = nm_keyfile_plugin_connection_from_file (TEST_WIRED_TLS_NEW_FILE, &error);
	if (connection == NULL) {
		g_assert (error);
		g_warning ("Failed to read %s: %s", TEST_WIRED_TLS_NEW_FILE, error->message);
		g_assert (connection);
	}

	success = nm_connection_verify (connection, &error);
	if (!success) {
		g_assert (error);
		g_warning ("Failed to verify %s: %s", TEST_WIRED_TLS_NEW_FILE, error->message);
		g_assert (success);
	}

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
	NMSettingIP4Config *s_ip4;
	NMSetting *s_wired;
	NMSetting8021x *s_8021x;
	char *uuid;
	gboolean success;
	GError *error = NULL;

	connection = nm_connection_new ();
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
	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	g_assert (s_ip4);
	g_object_set (s_ip4, NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);
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
	if (!success) {
		g_assert (error);
		g_warning ("Failed to set CA cert %s: %s", TEST_WIRED_TLS_CA_CERT, error->message);
		g_assert (success);
	}

	success = nm_setting_802_1x_set_client_cert (s_8021x,
	                                             TEST_WIRED_TLS_CLIENT_CERT,
	                                             scheme,
	                                             NULL,
	                                             &error);
	if (!success) {
		g_assert (error);
		g_warning ("Failed to set client cert %s: %s", TEST_WIRED_TLS_CA_CERT, error->message);
		g_assert (success);
	}

	success = nm_setting_802_1x_set_private_key (s_8021x,
	                                             TEST_WIRED_TLS_PRIVKEY,
	                                             "test1",
	                                             scheme,
	                                             NULL,
	                                             &error);
	if (!success) {
		g_assert (error);
		g_warning ("Failed to set private key %s: %s", TEST_WIRED_TLS_CA_CERT, error->message);
		g_assert (success);
	}

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

	connection = create_wired_tls_connection (NM_SETTING_802_1X_CK_SCHEME_BLOB);
	g_assert (connection != NULL);

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

#define TEST_INFINIBAND_FILE    TEST_KEYFILES_DIR"/Test_InfiniBand_Connection"

static void
test_read_infiniband_connection (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingInfiniband *s_ib;
	GError *error = NULL;
	const GByteArray *array;
	guint8 expected_mac[INFINIBAND_ALEN] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
		0x77, 0x88, 0x99, 0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89,
		0x90 };
	const char *expected_id = "Test InfiniBand Connection";
	const char *expected_uuid = "4e80a56d-c99f-4aad-a6dd-b449bc398c57";
	gboolean success;

	connection = nm_keyfile_plugin_connection_from_file (TEST_INFINIBAND_FILE, &error);
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

	array = nm_setting_infiniband_get_mac_address (s_ib);
	g_assert (array);
	g_assert_cmpint (array->len, ==, INFINIBAND_ALEN);
	g_assert_cmpint (memcmp (array->data, expected_mac, sizeof (expected_mac)), ==, 0);

	g_object_unref (connection);
}

static void
test_write_infiniband_connection (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingInfiniband *s_ib;
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;
	char *uuid;
	GByteArray *mac;
	guint8 tmpmac[] = { 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0xab, 0xbc,
		0xcd, 0xde, 0xef, 0xf0, 0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x6f, 0xba
	};
	gboolean success;
	NMConnection *reread;
	char *testfile = NULL;
	GError *error = NULL;
	pid_t owner_grp;
	uid_t owner_uid;

	connection = nm_connection_new ();
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

	mac = g_byte_array_sized_new (sizeof (tmpmac));
	g_byte_array_append (mac, &tmpmac[0], sizeof (tmpmac));
	g_object_set (s_ib,
	              NM_SETTING_INFINIBAND_MAC_ADDRESS, mac,
	              NM_SETTING_INFINIBAND_MTU, 900,
	              NM_SETTING_INFINIBAND_TRANSPORT_MODE, "datagram",
	              NULL);
	g_byte_array_free (mac, TRUE);

	/* IP4 setting */
	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	g_assert (s_ip4);
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));
	g_object_set (s_ip4, NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();
	g_assert (s_ip6);
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));
	g_object_set (s_ip6, NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_AUTO, NULL);

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

#define TEST_BRIDGE_MAIN_FILE TEST_KEYFILES_DIR"/Test_Bridge_Main"

static void
test_read_bridge_main (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingIP4Config *s_ip4;
	NMSettingBridge *s_bridge;
	GError *error = NULL;
	const char *expected_id = "Test Bridge Main";
	const char *expected_uuid = "8f061643-fe41-4d4c-a8d9-097d26e2ad3a";
	gboolean success;

	connection = nm_keyfile_plugin_connection_from_file (TEST_BRIDGE_MAIN_FILE, &error);
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

	/* IPv4 setting */
	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip4_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_AUTO);

	/* Bridge setting */
	s_bridge = nm_connection_get_setting_bridge (connection);
	g_assert (s_bridge);
	g_assert_cmpstr (nm_setting_bridge_get_interface_name (s_bridge), ==, "br0");
	g_assert_cmpuint (nm_setting_bridge_get_forward_delay (s_bridge), ==, 0);
	g_assert_cmpuint (nm_setting_bridge_get_stp (s_bridge), ==, TRUE);
	g_assert_cmpuint (nm_setting_bridge_get_priority (s_bridge), ==, 32744);
	g_assert_cmpuint (nm_setting_bridge_get_hello_time (s_bridge), ==, 7);
	g_assert_cmpuint (nm_setting_bridge_get_max_age (s_bridge), ==, 39);
	g_assert_cmpuint (nm_setting_bridge_get_ageing_time (s_bridge), ==, 235352);

	g_object_unref (connection);
}

static void
test_write_bridge_main (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingBridge *s_bridge;
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;
	char *uuid;
	gboolean success;
	NMConnection *reread;
	char *testfile = NULL;
	GError *error = NULL;
	pid_t owner_grp;
	uid_t owner_uid;

	connection = nm_connection_new ();
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

	g_object_set (s_bridge,
	              NM_SETTING_BRIDGE_INTERFACE_NAME, "br0",
	              NULL);

	/* IP4 setting */
	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	g_assert (s_ip4);
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));
	g_object_set (s_ip4,
	              NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_MANUAL,
	              NM_SETTING_IP4_CONFIG_MAY_FAIL, TRUE,
	              NULL);

	add_one_ip4_address (s_ip4, "1.2.3.4", "1.1.1.1", 24);

	/* IP6 setting */
	s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();
	g_assert (s_ip6);
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));
	g_object_set (s_ip6, NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_AUTO, NULL);

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

#define TEST_BRIDGE_COMPONENT_FILE TEST_KEYFILES_DIR"/Test_Bridge_Component"

static void
test_read_bridge_component (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingBridgePort *s_port;
	NMSettingWired *s_wired;
	const GByteArray *array;
	guint8 expected_mac[ETH_ALEN] = { 0x00, 0x22, 0x15, 0x59, 0x62, 0x97 };
	GError *error = NULL;
	const char *expected_id = "Test Bridge Component";
	const char *expected_uuid = "d7b4f96c-c45e-4298-bef8-f48574f8c1c0";
	gboolean success;

	connection = nm_keyfile_plugin_connection_from_file (TEST_BRIDGE_COMPONENT_FILE, &error);
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
	array = nm_setting_wired_get_mac_address (s_wired);
	g_assert (array);
	g_assert_cmpint (array->len, ==, ETH_ALEN);
	g_assert_cmpint (memcmp (array->data, expected_mac, sizeof (expected_mac)), ==, 0);

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
	GByteArray *mac;
	guint8 tmpmac[] = { 0x99, 0x88, 0x77, 0x66, 0x55, 0x44 };
	gboolean success;
	NMConnection *reread;
	char *testfile = NULL;
	GError *error = NULL;
	pid_t owner_grp;
	uid_t owner_uid;

	connection = nm_connection_new ();
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

	mac = g_byte_array_sized_new (ETH_ALEN);
	g_byte_array_append (mac, &tmpmac[0], sizeof (tmpmac));
	g_object_set (s_wired,
	              NM_SETTING_WIRED_MAC_ADDRESS, mac,
	              NM_SETTING_WIRED_MTU, 1300,
	              NULL);
	g_byte_array_free (mac, TRUE);

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
	const GByteArray *array;
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

	array = nm_setting_wired_get_mac_address (s_wired);
	g_assert (array);
	g_assert_cmpint (array->len, ==, ETH_ALEN);
	g_assert_cmpint (memcmp (array->data, expected_mac, sizeof (expected_mac)), ==, 0);

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

	connection = nm_connection_new ();
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
	g_assert (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT));

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

	g_object_unref (reread);
	g_object_unref (connection);
}

static void
test_read_new_wireless_group_names (void)
{
	NMConnection *connection;
	NMSettingWireless *s_wifi;
	NMSettingWirelessSecurity *s_wsec;
	const GByteArray *array;
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

	array = nm_setting_wireless_get_ssid (s_wifi);
	g_assert (array);
	g_assert_cmpint (array->len, ==, strlen (expected_ssid));
	g_assert_cmpint (memcmp (array->data, expected_ssid, array->len), ==, 0);

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
	GByteArray *ssid;
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

	connection = nm_connection_new ();

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

	ssid = g_byte_array_sized_new (sizeof (tmpssid));
	g_byte_array_append (ssid, &tmpssid[0], sizeof (tmpssid));
	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_MODE, NM_SETTING_WIRELESS_MODE_INFRA,
	              NULL);
	g_byte_array_free (ssid, TRUE);

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
	g_assert (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT));

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

	g_object_unref (connection);
}

NMTST_DEFINE ();

int main (int argc, char **argv)
{
	char *base;

	nmtst_init_assert_logging (&argc, &argv);

	/* The tests */
	test_read_valid_wired_connection ();
	test_write_wired_connection ();

	test_read_ip6_wired_connection ();
	test_write_ip6_wired_connection ();

	test_read_wired_mac_case ();
	test_read_mac_old_format ();
	test_read_mac_ib_old_format ();

	test_read_valid_wireless_connection ();
	test_write_wireless_connection ();

	test_read_string_ssid ();
	test_write_string_ssid ();

	test_read_intlist_ssid ();
	test_write_intlist_ssid ();

	test_read_intlike_ssid ();
	test_write_intlike_ssid ();

	test_read_intlike_ssid_2 ();
	test_write_intlike_ssid_2 ();

	test_read_bt_dun_connection ();
	test_write_bt_dun_connection ();

	test_read_gsm_connection ();
	test_write_gsm_connection ();

	test_read_wired_8021x_tls_blob_connection ();
	test_read_wired_8021x_tls_bad_path_connection ();

	test_read_wired_8021x_tls_old_connection ();
	test_read_wired_8021x_tls_new_connection ();
	test_write_wired_8021x_tls_connection_path ();
	test_write_wired_8021x_tls_connection_blob ();

	test_read_infiniband_connection ();
	test_write_infiniband_connection ();

	test_read_bridge_main ();
	test_write_bridge_main ();
	test_read_bridge_component ();
	test_write_bridge_component ();

	test_read_new_wired_group_name ();
	test_write_new_wired_group_name ();
	test_read_new_wireless_group_names ();
	test_write_new_wireless_group_names ();

	test_read_missing_vlan_setting ();

	base = g_path_get_basename (argv[0]);
	fprintf (stdout, "%s: SUCCESS\n", base);
	g_free (base);
	return 0;
}

