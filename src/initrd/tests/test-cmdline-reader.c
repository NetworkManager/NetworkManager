// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "nm-core-internal.h"
#include "NetworkManagerUtils.h"

#include "../nm-initrd-generator.h"

#include "nm-test-utils-core.h"

static void
test_auto (void)
{
	gs_unref_hashtable GHashTable *connections = NULL;
	const char *const*ARGV = NM_MAKE_STRV ("ip=auto");
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;

	connections = nmi_cmdline_reader_parse (TEST_INITRD_DIR "/sysfs", ARGV);
	g_assert (connections);
	g_assert_cmpint (g_hash_table_size (connections), ==, 1);

	connection = g_hash_table_lookup (connections, "default_connection");
	g_assert (connection);
	nmtst_assert_connection_verifies_without_normalization (connection);

	g_assert (!nm_connection_get_setting_vlan (connection));

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_connection_type (s_con), ==, NM_SETTING_WIRED_SETTING_NAME);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "Wired Connection");
	g_assert_cmpint (nm_setting_connection_get_timestamp (s_con), ==, 0);
	g_assert_cmpint (nm_setting_connection_get_multi_connect (s_con), ==, NM_CONNECTION_MULTI_CONNECT_MULTIPLE);

	g_assert (nm_setting_connection_get_autoconnect (s_con));

	s_wired = nm_connection_get_setting_wired (connection);
	g_assert (s_wired);
	g_assert (!nm_setting_wired_get_mac_address (s_wired));
	g_assert_cmpint (nm_setting_wired_get_mtu (s_wired), ==, 0);

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_AUTO);
	g_assert (!nm_setting_ip_config_get_ignore_auto_dns (s_ip4));
	g_assert_cmpint (nm_setting_ip_config_get_num_dns (s_ip4), ==, 0);
	g_assert_cmpint (nm_setting_ip_config_get_num_addresses (s_ip4), ==, 0);
	g_assert (!nm_setting_ip_config_get_gateway (s_ip4));

	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	g_assert (s_ip6);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip6), ==, NM_SETTING_IP6_CONFIG_METHOD_AUTO);
	g_assert (!nm_setting_ip_config_get_ignore_auto_dns (s_ip6));
	g_assert_cmpint (nm_setting_ip_config_get_num_dns (s_ip6), ==, 0);
	g_assert_cmpint (nm_setting_ip_config_get_num_addresses (s_ip6), ==, 0);
	g_assert (!nm_setting_ip_config_get_gateway (s_ip6));
}

static void
test_if_auto_with_mtu (void)
{
	gs_unref_hashtable GHashTable *connections = NULL;
	const char *const*ARGV = NM_MAKE_STRV ("ip=eth0:auto:1666");
	NMConnection *connection;
	NMSettingWired *s_wired;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;

	connections = nmi_cmdline_reader_parse (TEST_INITRD_DIR "/sysfs", ARGV);
	g_assert (connections);
	g_assert_cmpint (g_hash_table_size (connections), ==, 1);

	connection = g_hash_table_lookup (connections, "eth0");
	g_assert (connection);
	nmtst_assert_connection_verifies_without_normalization (connection);
	g_assert_cmpstr (nm_connection_get_id (connection), ==, "eth0");

	s_wired = nm_connection_get_setting_wired (connection);
	g_assert (s_wired);
	g_assert_cmpint (nm_setting_wired_get_mtu (s_wired), ==, 1666);

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_AUTO);
	g_assert (!nm_setting_ip_config_get_ignore_auto_dns (s_ip4));

	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	g_assert (s_ip6);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip6), ==, NM_SETTING_IP6_CONFIG_METHOD_AUTO);
	g_assert (!nm_setting_ip_config_get_ignore_auto_dns (s_ip6));
}


static void
test_if_dhcp6 (void)
{
	gs_unref_hashtable GHashTable *connections = NULL;
	const char *const*ARGV = NM_MAKE_STRV ("ip=eth1:dhcp6");
	NMConnection *connection;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;

	connections = nmi_cmdline_reader_parse (TEST_INITRD_DIR "/sysfs", ARGV);
	g_assert (connections);
	g_assert_cmpint (g_hash_table_size (connections), ==, 1);
	connection = g_hash_table_lookup (connections, "eth1");
	g_assert (connection);
	nmtst_assert_connection_verifies_without_normalization (connection);
	g_assert_cmpstr (nm_connection_get_id (connection), ==, "eth1");

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_DISABLED);
	g_assert (!nm_setting_ip_config_get_ignore_auto_dns (s_ip4));

	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	g_assert (s_ip6);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip6), ==, NM_SETTING_IP6_CONFIG_METHOD_DHCP);
	g_assert (!nm_setting_ip_config_get_ignore_auto_dns (s_ip6));
}


static void
test_if_auto_with_mtu_and_mac (void)
{
	gs_unref_hashtable GHashTable *connections = NULL;
	const char *const*ARGV = NM_MAKE_STRV ("ip=eth2:auto6:2048:00:53:ef:12:34:56");
	NMConnection *connection;
	NMSettingWired *s_wired;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;

	connections = nmi_cmdline_reader_parse (TEST_INITRD_DIR "/sysfs", ARGV);
	g_assert (connections);
	g_assert_cmpint (g_hash_table_size (connections), ==, 1);

	connection = g_hash_table_lookup (connections, "eth2");
	g_assert (connection);
	nmtst_assert_connection_verifies_without_normalization (connection);
	g_assert_cmpstr (nm_connection_get_id (connection), ==, "eth2");

	s_wired = nm_connection_get_setting_wired (connection);
	g_assert (s_wired);
	g_assert_cmpint (nm_setting_wired_get_mtu (s_wired), ==, 2048);
	g_assert_cmpstr (nm_setting_wired_get_cloned_mac_address (s_wired), ==, "00:53:EF:12:34:56");

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_DISABLED);
	g_assert (!nm_setting_ip_config_get_ignore_auto_dns (s_ip4));

	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	g_assert (s_ip6);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip6), ==, NM_SETTING_IP6_CONFIG_METHOD_AUTO);
	g_assert (!nm_setting_ip_config_get_ignore_auto_dns (s_ip6));
}


static void
test_if_ip4_manual (void)
{
	gs_unref_hashtable GHashTable *connections = NULL;
	const char *const*ARGV = NM_MAKE_STRV ("ip=192.0.2.2::192.0.2.1:255.255.255.0:"
	                                       "hostname0.example.com:eth3::192.0.2.53",
	                                       "ip=203.0.113.2::203.0.113.1:26:"
	                                       "hostname1.example.com:eth4");
	NMConnection *connection;
	NMSettingIPConfig *s_ip4;
	NMIPAddress *ip_addr;

	connections = nmi_cmdline_reader_parse (TEST_INITRD_DIR "/sysfs", ARGV);
	g_assert (connections);
	g_assert_cmpint (g_hash_table_size (connections), ==, 2);

	connection = g_hash_table_lookup (connections, "eth3");
	g_assert (connection);
	nmtst_assert_connection_verifies_without_normalization (connection);
	g_assert_cmpstr (nm_connection_get_id (connection), ==, "eth3");

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_MANUAL);
	g_assert (!nm_setting_ip_config_get_ignore_auto_dns (s_ip4));
	g_assert_cmpint (nm_setting_ip_config_get_num_dns (s_ip4), ==, 1);
	g_assert_cmpstr (nm_setting_ip_config_get_dns (s_ip4, 0), ==, "192.0.2.53");
	g_assert_cmpint (nm_setting_ip_config_get_num_routes (s_ip4), ==, 0);
	g_assert_cmpint (nm_setting_ip_config_get_num_addresses (s_ip4), ==, 1);
	ip_addr = nm_setting_ip_config_get_address (s_ip4, 0);
	g_assert (ip_addr);
	g_assert_cmpstr (nm_ip_address_get_address (ip_addr), ==, "192.0.2.2");
	g_assert_cmpint (nm_ip_address_get_prefix (ip_addr), ==, 24);
	g_assert_cmpstr (nm_setting_ip_config_get_gateway (s_ip4), ==, "192.0.2.1");
	g_assert_cmpstr (nm_setting_ip_config_get_dhcp_hostname (s_ip4), ==, "hostname0.example.com");

	connection = g_hash_table_lookup (connections, "eth4");
	g_assert (connection);
	nmtst_assert_connection_verifies_without_normalization (connection);
	g_assert_cmpstr (nm_connection_get_id (connection), ==, "eth4");

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_MANUAL);
	g_assert (!nm_setting_ip_config_get_ignore_auto_dns (s_ip4));
	g_assert_cmpint (nm_setting_ip_config_get_num_dns (s_ip4), ==, 0);
	g_assert_cmpint (nm_setting_ip_config_get_num_routes (s_ip4), ==, 0);
	g_assert_cmpint (nm_setting_ip_config_get_num_addresses (s_ip4), ==, 1);
	ip_addr = nm_setting_ip_config_get_address (s_ip4, 0);
	g_assert (ip_addr);
	g_assert_cmpstr (nm_ip_address_get_address (ip_addr), ==, "203.0.113.2");
	g_assert_cmpint (nm_ip_address_get_prefix (ip_addr), ==, 26);
	g_assert_cmpstr (nm_setting_ip_config_get_gateway (s_ip4), ==, "203.0.113.1");
	g_assert_cmpstr (nm_setting_ip_config_get_dhcp_hostname (s_ip4), ==, "hostname1.example.com");
}

static void
test_if_ip6_manual (void)
{
	gs_unref_hashtable GHashTable *connections = NULL;
	const char *const*ARGV = NM_MAKE_STRV ("ip=[2001:0db8::02]/64::[2001:0db8::01]::"
	                                       "hostname0.example.com:eth4::[2001:0db8::53]");
	NMConnection *connection;
	NMSettingIPConfig *s_ip6;
	NMIPAddress *ip_addr;

	connections = nmi_cmdline_reader_parse (TEST_INITRD_DIR "/sysfs", ARGV);
	g_assert (connections);
	g_assert_cmpint (g_hash_table_size (connections), ==, 1);

	connection = g_hash_table_lookup (connections, "eth4");
	g_assert (connection);
	nmtst_assert_connection_verifies_without_normalization (connection);
	g_assert_cmpstr (nm_connection_get_id (connection), ==, "eth4");

	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	g_assert (s_ip6);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip6), ==, NM_SETTING_IP6_CONFIG_METHOD_MANUAL);
	g_assert (!nm_setting_ip_config_get_ignore_auto_dns (s_ip6));
	g_assert_cmpint (nm_setting_ip_config_get_num_dns (s_ip6), ==, 1);
	g_assert_cmpstr (nm_setting_ip_config_get_dns (s_ip6, 0), ==, "2001:db8::53");
	g_assert_cmpint (nm_setting_ip_config_get_num_routes (s_ip6), ==, 0);
	g_assert_cmpint (nm_setting_ip_config_get_num_addresses (s_ip6), ==, 1);
	ip_addr = nm_setting_ip_config_get_address (s_ip6, 0);
	g_assert (ip_addr);
	g_assert_cmpstr (nm_ip_address_get_address (ip_addr), ==, "2001:db8::2");
	g_assert_cmpint (nm_ip_address_get_prefix (ip_addr), ==, 64);
	g_assert_cmpstr (nm_setting_ip_config_get_gateway (s_ip6), ==, "2001:db8::1");
	g_assert_cmpstr (nm_setting_ip_config_get_dhcp_hostname (s_ip6), ==, "hostname0.example.com");
}

static void
test_multiple (void)
{
	gs_unref_hashtable GHashTable *connections = NULL;
	const char *const*ARGV = NM_MAKE_STRV ("ip=192.0.2.2:::::eth0",
	                                       "ip=[2001:db8::2]:::::eth0",
	                                       "BOOTIF=00:53:AB:cd:02:03");
	NMConnection *connection;
	NMSettingWired *s_wired;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	NMIPAddress *ip_addr;

	connections = nmi_cmdline_reader_parse (TEST_INITRD_DIR "/sysfs", ARGV);
	g_assert (connections);
	g_assert_cmpint (g_hash_table_size (connections), ==, 1);

	connection = g_hash_table_lookup (connections, "eth0");
	g_assert (connection);
	nmtst_assert_connection_verifies_without_normalization (connection);
	g_assert_cmpstr (nm_connection_get_id (connection), ==, "eth0");

	s_wired = nm_connection_get_setting_wired (connection);
	g_assert (s_wired);
	g_assert_cmpstr (nm_setting_wired_get_mac_address (s_wired), ==, "00:53:AB:CD:02:03");

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_MANUAL);
	g_assert (!nm_setting_ip_config_get_ignore_auto_dns (s_ip4));
	g_assert_cmpint (nm_setting_ip_config_get_num_addresses (s_ip4), ==, 1);
	ip_addr = nm_setting_ip_config_get_address (s_ip4, 0);
	g_assert (ip_addr);
	g_assert_cmpstr (nm_ip_address_get_address (ip_addr), ==, "192.0.2.2");

	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	g_assert (s_ip6);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip6), ==, NM_SETTING_IP6_CONFIG_METHOD_MANUAL);
	g_assert (!nm_setting_ip_config_get_ignore_auto_dns (s_ip6));
	g_assert_cmpint (nm_setting_ip_config_get_num_addresses (s_ip6), ==, 1);
	ip_addr = nm_setting_ip_config_get_address (s_ip6, 0);
	g_assert (ip_addr);
	g_assert_cmpstr (nm_ip_address_get_address (ip_addr), ==, "2001:db8::2");
}

static void
test_some_more (void)
{
	gs_unref_hashtable GHashTable *connections = NULL;
	const char *const*ARGV = NM_MAKE_STRV ("bootdev=eth1", "hail", "nameserver=[2001:DB8:3::53]",
	                                       "satan", "nameserver=192.0.2.53", "worship",
	                                       "BOOTIF=01-00-53-AB-cd-02-03", "doom", "rd.peerdns=0",
	                                       "rd.route=[2001:DB8:3::/48]:[2001:DB8:2::1]:ens10");
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	NMIPRoute *ip_route;

	connections = nmi_cmdline_reader_parse (TEST_INITRD_DIR "/sysfs", ARGV);
	g_assert (connections);
	g_assert_cmpint (g_hash_table_size (connections), ==, 2);

	connection = g_hash_table_lookup (connections, "default_connection");
	g_assert (connection);
	nmtst_assert_connection_verifies_without_normalization (connection);

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_connection_type (s_con), ==, NM_SETTING_WIRED_SETTING_NAME);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "Wired Connection");
	g_assert_cmpstr (nm_setting_connection_get_interface_name (s_con), ==, "eth1");
	g_assert_cmpint (nm_setting_connection_get_multi_connect (s_con), ==, NM_CONNECTION_MULTI_CONNECT_MULTIPLE);

	s_wired = nm_connection_get_setting_wired (connection);
	g_assert (s_wired);
	g_assert_cmpstr (nm_setting_wired_get_mac_address (s_wired), ==, "00:53:AB:CD:02:03");

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_AUTO);
	g_assert (nm_setting_ip_config_get_ignore_auto_dns (s_ip4));
	g_assert_cmpint (nm_setting_ip_config_get_num_addresses (s_ip4), ==, 0);
	g_assert (!nm_setting_ip_config_get_gateway (s_ip4));
	g_assert_cmpint (nm_setting_ip_config_get_num_dns (s_ip4), ==, 1);
	g_assert_cmpstr (nm_setting_ip_config_get_dns (s_ip4, 0), ==, "192.0.2.53");


	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	g_assert (s_ip6);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip6), ==, NM_SETTING_IP6_CONFIG_METHOD_AUTO);
	g_assert (nm_setting_ip_config_get_ignore_auto_dns (s_ip6));
	g_assert_cmpint (nm_setting_ip_config_get_num_dns (s_ip6), ==, 1);
	g_assert (!nm_setting_ip_config_get_gateway (s_ip6));
	g_assert_cmpstr (nm_setting_ip_config_get_dns (s_ip6, 0), ==, "2001:db8:3::53");


	connection = g_hash_table_lookup (connections, "ens10");
	g_assert (connection);
	nmtst_assert_connection_verifies_without_normalization (connection);

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_connection_type (s_con), ==, NM_SETTING_WIRED_SETTING_NAME);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "ens10");
	g_assert_cmpstr (nm_setting_connection_get_interface_name (s_con), ==, "ens10");
	g_assert_cmpint (nm_setting_connection_get_multi_connect (s_con), ==, NM_CONNECTION_MULTI_CONNECT_SINGLE);

	s_wired = nm_connection_get_setting_wired (connection);
	g_assert (s_wired);
	g_assert (!nm_setting_wired_get_mac_address (s_wired));

	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	g_assert (s_ip6);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip6), ==, NM_SETTING_IP6_CONFIG_METHOD_AUTO);
	g_assert_cmpint (nm_setting_ip_config_get_num_dns (s_ip6), ==, 0);
	g_assert_cmpint (nm_setting_ip_config_get_num_routes (s_ip6), ==, 1);
	g_assert (!nm_setting_ip_config_get_gateway (s_ip6));
	ip_route = nm_setting_ip_config_get_route (s_ip6, 0);
	g_assert_cmpstr (nm_ip_route_get_dest (ip_route), ==, "2001:db8:3::");
	g_assert_cmpint (nm_ip_route_get_family (ip_route), ==, AF_INET6);
	g_assert_cmpint (nm_ip_route_get_metric (ip_route), ==, -1);
	g_assert_cmpstr (nm_ip_route_get_next_hop (ip_route), ==, "2001:db8:2::1");
	g_assert_cmpint (nm_ip_route_get_prefix (ip_route), ==, 48);
}

static void
test_no_bootif (void)
{
	gs_unref_hashtable GHashTable *connections = NULL;
	const char *const*ARGV = NM_MAKE_STRV ("BOOTIF=01-00-53-AB-cd-02-03", "rd.bootif=0");

	connections = nmi_cmdline_reader_parse (TEST_INITRD_DIR "/sysfs", ARGV);
	g_assert (connections);
	g_assert_cmpint (g_hash_table_size (connections), ==, 0);
}

static void
test_bond (void)
{
	gs_unref_hashtable GHashTable *connections = NULL;
	const char *const*ARGV = NM_MAKE_STRV ("rd.route=192.0.2.53::bong0",
	                                       "bond=bong0:eth0,eth1:mode=balance-rr",
	                                       "nameserver=203.0.113.53");
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	NMSettingBond *s_bond;
	NMIPRoute *ip_route;
	const char *master_uuid;

	connections = nmi_cmdline_reader_parse (TEST_INITRD_DIR "/sysfs", ARGV);
	g_assert (connections);
	g_assert_cmpint (g_hash_table_size (connections), ==, 3);

	connection = g_hash_table_lookup (connections, "bong0");
	g_assert (connection);
	nmtst_assert_connection_verifies_without_normalization (connection);
	g_assert_cmpstr (nm_connection_get_connection_type (connection), ==, NM_SETTING_BOND_SETTING_NAME);
	g_assert_cmpstr (nm_connection_get_id (connection), ==, "bong0");
	master_uuid = nm_connection_get_uuid (connection);
	g_assert (master_uuid);

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_AUTO);
	g_assert (!nm_setting_ip_config_get_ignore_auto_dns (s_ip4));
	g_assert_cmpint (nm_setting_ip_config_get_num_dns (s_ip4), ==, 1);
	g_assert_cmpstr (nm_setting_ip_config_get_dns (s_ip4, 0), ==, "203.0.113.53");
	g_assert (!nm_setting_ip_config_get_gateway (s_ip4));
	g_assert_cmpint (nm_setting_ip_config_get_num_routes (s_ip4), ==, 1);
	ip_route = nm_setting_ip_config_get_route (s_ip4, 0);
	g_assert_cmpstr (nm_ip_route_get_dest (ip_route), ==, "192.0.2.53");
	g_assert_cmpint (nm_ip_route_get_family (ip_route), ==, AF_INET);
	g_assert_cmpint (nm_ip_route_get_metric (ip_route), ==, -1);
	g_assert (!nm_ip_route_get_next_hop (ip_route));
	g_assert_cmpint (nm_ip_route_get_prefix (ip_route), ==, 32);

	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	g_assert (s_ip6);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip6), ==, NM_SETTING_IP6_CONFIG_METHOD_AUTO);
	g_assert (!nm_setting_ip_config_get_ignore_auto_dns (s_ip6));
	g_assert_cmpint (nm_setting_ip_config_get_num_dns (s_ip6), ==, 0);
	g_assert (!nm_setting_ip_config_get_gateway (s_ip6));
	g_assert_cmpint (nm_setting_ip_config_get_num_routes (s_ip6), ==, 0);

	s_bond = nm_connection_get_setting_bond (connection);
	g_assert (s_bond);
	g_assert_cmpint (nm_setting_bond_get_num_options (s_bond), ==, 1);
	g_assert_cmpstr (nm_setting_bond_get_option_by_name (s_bond, "mode"), ==, "balance-rr");

	connection = g_hash_table_lookup (connections, "eth0");
	g_assert (connection);
	nmtst_assert_connection_verifies_without_normalization (connection);
	g_assert_cmpstr (nm_connection_get_id (connection), ==, "eth0");

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_connection_type (s_con), ==, NM_SETTING_WIRED_SETTING_NAME);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "eth0");
	g_assert_cmpstr (nm_setting_connection_get_slave_type (s_con), ==, NM_SETTING_BOND_SETTING_NAME);
	g_assert_cmpstr (nm_setting_connection_get_master (s_con), ==, master_uuid);
	g_assert_cmpint (nm_setting_connection_get_multi_connect (s_con), ==, NM_CONNECTION_MULTI_CONNECT_SINGLE);

	connection = g_hash_table_lookup (connections, "eth1");
	g_assert (connection);
	nmtst_assert_connection_verifies_without_normalization (connection);
	g_assert_cmpstr (nm_connection_get_id (connection), ==, "eth1");

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_connection_type (s_con), ==, NM_SETTING_WIRED_SETTING_NAME);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "eth1");
	g_assert_cmpstr (nm_setting_connection_get_slave_type (s_con), ==, NM_SETTING_BOND_SETTING_NAME);
	g_assert_cmpstr (nm_setting_connection_get_master (s_con), ==, master_uuid);
	g_assert_cmpint (nm_setting_connection_get_multi_connect (s_con), ==, NM_CONNECTION_MULTI_CONNECT_SINGLE);
}

static void
test_bond_default (void)
{
	gs_unref_hashtable GHashTable *connections = NULL;
	const char *const*ARGV = NM_MAKE_STRV ("bond");
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	NMSettingBond *s_bond;
	const char *master_uuid;

	connections = nmi_cmdline_reader_parse (TEST_INITRD_DIR "/sysfs", ARGV);
	g_assert (connections);
	g_assert_cmpint (g_hash_table_size (connections), ==, 2);

	connection = g_hash_table_lookup (connections, "bond0");

	g_assert (connection);
	nmtst_assert_connection_verifies_without_normalization (connection);
	g_assert_cmpstr (nm_connection_get_connection_type (connection), ==, NM_SETTING_BOND_SETTING_NAME);
	g_assert_cmpstr (nm_connection_get_id (connection), ==, "bond0");
	master_uuid = nm_connection_get_uuid (connection);
	g_assert (master_uuid);

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_AUTO);
	g_assert (!nm_setting_ip_config_get_ignore_auto_dns (s_ip4));
	g_assert_cmpint (nm_setting_ip_config_get_num_dns (s_ip4), ==, 0);
	g_assert (!nm_setting_ip_config_get_gateway (s_ip4));
	g_assert_cmpint (nm_setting_ip_config_get_num_routes (s_ip4), ==, 0);

	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	g_assert (s_ip6);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip6), ==, NM_SETTING_IP6_CONFIG_METHOD_AUTO);
	g_assert (!nm_setting_ip_config_get_ignore_auto_dns (s_ip6));
	g_assert_cmpint (nm_setting_ip_config_get_num_dns (s_ip6), ==, 0);
	g_assert (!nm_setting_ip_config_get_gateway (s_ip6));
	g_assert_cmpint (nm_setting_ip_config_get_num_routes (s_ip6), ==, 0);

	s_bond = nm_connection_get_setting_bond (connection);
	g_assert (s_bond);
	g_assert_cmpint (nm_setting_bond_get_num_options (s_bond), ==, 1);
	g_assert_cmpstr (nm_setting_bond_get_option_by_name (s_bond, "mode"), ==, "balance-rr");

	connection = g_hash_table_lookup (connections, "eth0");
	g_assert (connection);
	nmtst_assert_connection_verifies_without_normalization (connection);
	g_assert_cmpstr (nm_connection_get_id (connection), ==, "eth0");

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_connection_type (s_con), ==, NM_SETTING_WIRED_SETTING_NAME);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "eth0");
	g_assert_cmpstr (nm_setting_connection_get_slave_type (s_con), ==, NM_SETTING_BOND_SETTING_NAME);
	g_assert_cmpstr (nm_setting_connection_get_master (s_con), ==, master_uuid);
	g_assert_cmpint (nm_setting_connection_get_multi_connect (s_con), ==, NM_CONNECTION_MULTI_CONNECT_SINGLE);
}

static void
test_bridge (void)
{
	gs_unref_hashtable GHashTable *connections = NULL;
	const char *const*ARGV = NM_MAKE_STRV ("bridge=bridge0:eth0,eth1", "rd.route=192.0.2.53::bridge0");
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	NMSettingBridge *s_bridge;
	NMIPRoute *ip_route;
	const char *master_uuid;

	connections = nmi_cmdline_reader_parse (TEST_INITRD_DIR "/sysfs", ARGV);
	g_assert (connections);
	g_assert_cmpint (g_hash_table_size (connections), ==, 3);

	connection = g_hash_table_lookup (connections, "bridge0");
	g_assert (connection);
	nmtst_assert_connection_verifies_without_normalization (connection);
	g_assert_cmpstr (nm_connection_get_connection_type (connection), ==, NM_SETTING_BRIDGE_SETTING_NAME);
	g_assert_cmpstr (nm_connection_get_id (connection), ==, "bridge0");
	master_uuid = nm_connection_get_uuid (connection);
	g_assert (master_uuid);

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_AUTO);
	g_assert (!nm_setting_ip_config_get_ignore_auto_dns (s_ip4));
	g_assert_cmpint (nm_setting_ip_config_get_num_dns (s_ip4), ==, 0);
	g_assert (!nm_setting_ip_config_get_gateway (s_ip4));
	g_assert_cmpint (nm_setting_ip_config_get_num_routes (s_ip4), ==, 1);
	ip_route = nm_setting_ip_config_get_route (s_ip4, 0);
	g_assert_cmpstr (nm_ip_route_get_dest (ip_route), ==, "192.0.2.53");
	g_assert_cmpint (nm_ip_route_get_family (ip_route), ==, AF_INET);
	g_assert_cmpint (nm_ip_route_get_metric (ip_route), ==, -1);
	g_assert (!nm_ip_route_get_next_hop (ip_route));
	g_assert_cmpint (nm_ip_route_get_prefix (ip_route), ==, 32);

	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	g_assert (s_ip6);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip6), ==, NM_SETTING_IP6_CONFIG_METHOD_AUTO);
	g_assert (!nm_setting_ip_config_get_ignore_auto_dns (s_ip6));
	g_assert_cmpint (nm_setting_ip_config_get_num_dns (s_ip6), ==, 0);
	g_assert (!nm_setting_ip_config_get_gateway (s_ip6));
	g_assert_cmpint (nm_setting_ip_config_get_num_routes (s_ip6), ==, 0);

	s_bridge = nm_connection_get_setting_bridge (connection);
	g_assert (s_bridge);

	connection = g_hash_table_lookup (connections, "eth0");
	g_assert (connection);
	nmtst_assert_connection_verifies_without_normalization (connection);
	g_assert_cmpstr (nm_connection_get_id (connection), ==, "eth0");

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_connection_type (s_con), ==, NM_SETTING_WIRED_SETTING_NAME);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "eth0");
	g_assert_cmpstr (nm_setting_connection_get_slave_type (s_con), ==, NM_SETTING_BRIDGE_SETTING_NAME);
	g_assert_cmpstr (nm_setting_connection_get_master (s_con), ==, master_uuid);
	g_assert_cmpint (nm_setting_connection_get_multi_connect (s_con), ==, NM_CONNECTION_MULTI_CONNECT_SINGLE);

	connection = g_hash_table_lookup (connections, "eth1");
	g_assert (connection);
	nmtst_assert_connection_verifies_without_normalization (connection);
	g_assert_cmpstr (nm_connection_get_id (connection), ==, "eth1");

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_connection_type (s_con), ==, NM_SETTING_WIRED_SETTING_NAME);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "eth1");
	g_assert_cmpstr (nm_setting_connection_get_slave_type (s_con), ==, NM_SETTING_BRIDGE_SETTING_NAME);
	g_assert_cmpstr (nm_setting_connection_get_master (s_con), ==, master_uuid);
	g_assert_cmpint (nm_setting_connection_get_multi_connect (s_con), ==, NM_CONNECTION_MULTI_CONNECT_SINGLE);
}

static void
test_bridge_default (void)
{
	gs_unref_hashtable GHashTable *connections = NULL;
	const char *const*ARGV = NM_MAKE_STRV ("bridge");
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	NMSettingBridge *s_bridge;
	const char *master_uuid;

	connections = nmi_cmdline_reader_parse (TEST_INITRD_DIR "/sysfs", ARGV);
	g_assert (connections);
	g_assert_cmpint (g_hash_table_size (connections), ==, 2);

	connection = g_hash_table_lookup (connections, "bridge0");

	g_assert (connection);
	nmtst_assert_connection_verifies_without_normalization (connection);
	g_assert_cmpstr (nm_connection_get_connection_type (connection), ==, NM_SETTING_BRIDGE_SETTING_NAME);
	g_assert_cmpstr (nm_connection_get_id (connection), ==, "bridge0");
	master_uuid = nm_connection_get_uuid (connection);
	g_assert (master_uuid);

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_AUTO);
	g_assert (!nm_setting_ip_config_get_ignore_auto_dns (s_ip4));
	g_assert_cmpint (nm_setting_ip_config_get_num_dns (s_ip4), ==, 0);
	g_assert (!nm_setting_ip_config_get_gateway (s_ip4));
	g_assert_cmpint (nm_setting_ip_config_get_num_routes (s_ip4), ==, 0);

	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	g_assert (s_ip6);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip6), ==, NM_SETTING_IP6_CONFIG_METHOD_AUTO);
	g_assert (!nm_setting_ip_config_get_ignore_auto_dns (s_ip6));
	g_assert_cmpint (nm_setting_ip_config_get_num_dns (s_ip6), ==, 0);
	g_assert (!nm_setting_ip_config_get_gateway (s_ip6));
	g_assert_cmpint (nm_setting_ip_config_get_num_routes (s_ip6), ==, 0);

	s_bridge = nm_connection_get_setting_bridge (connection);
	g_assert (s_bridge);

	connection = g_hash_table_lookup (connections, "eth0");
	g_assert (connection);
	nmtst_assert_connection_verifies_without_normalization (connection);
	g_assert_cmpstr (nm_connection_get_id (connection), ==, "eth0");

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_connection_type (s_con), ==, NM_SETTING_WIRED_SETTING_NAME);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "eth0");
	g_assert_cmpstr (nm_setting_connection_get_slave_type (s_con), ==, NM_SETTING_BRIDGE_SETTING_NAME);
	g_assert_cmpstr (nm_setting_connection_get_master (s_con), ==, master_uuid);
	g_assert_cmpint (nm_setting_connection_get_multi_connect (s_con), ==, NM_CONNECTION_MULTI_CONNECT_SINGLE);
}

static void
test_team (void)
{
	gs_unref_hashtable GHashTable *connections = NULL;
	const char *const*ARGV = NM_MAKE_STRV ("team=team0:eth0,eth1", "ip=team0:dhcp6");
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	NMSettingTeam *s_team;
	const char *master_uuid;

	connections = nmi_cmdline_reader_parse (TEST_INITRD_DIR "/sysfs", ARGV);
	g_assert (connections);
	g_assert_cmpint (g_hash_table_size (connections), ==, 3);

	connection = g_hash_table_lookup (connections, "team0");
	g_assert (connection);
	nmtst_assert_connection_verifies_without_normalization (connection);
	g_assert_cmpstr (nm_connection_get_connection_type (connection), ==, NM_SETTING_TEAM_SETTING_NAME);
	g_assert_cmpstr (nm_connection_get_id (connection), ==, "team0");
	master_uuid = nm_connection_get_uuid (connection);
	g_assert (master_uuid);

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_DISABLED);
	g_assert (!nm_setting_ip_config_get_ignore_auto_dns (s_ip4));
	g_assert_cmpint (nm_setting_ip_config_get_num_dns (s_ip4), ==, 0);
	g_assert (!nm_setting_ip_config_get_gateway (s_ip4));
	g_assert_cmpint (nm_setting_ip_config_get_num_routes (s_ip4), ==, 0);

	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	g_assert (s_ip6);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip6), ==, NM_SETTING_IP6_CONFIG_METHOD_DHCP);
	g_assert (!nm_setting_ip_config_get_ignore_auto_dns (s_ip6));
	g_assert_cmpint (nm_setting_ip_config_get_num_dns (s_ip6), ==, 0);
	g_assert (!nm_setting_ip_config_get_gateway (s_ip6));
	g_assert_cmpint (nm_setting_ip_config_get_num_routes (s_ip6), ==, 0);

	s_team = nm_connection_get_setting_team (connection);
	g_assert (s_team);

	connection = g_hash_table_lookup (connections, "eth0");
	g_assert (connection);
	nmtst_assert_connection_verifies_without_normalization (connection);
	g_assert_cmpstr (nm_connection_get_id (connection), ==, "eth0");

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_connection_type (s_con), ==, NM_SETTING_WIRED_SETTING_NAME);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "eth0");
	g_assert_cmpstr (nm_setting_connection_get_slave_type (s_con), ==, NM_SETTING_TEAM_SETTING_NAME);
	g_assert_cmpstr (nm_setting_connection_get_master (s_con), ==, master_uuid);
	g_assert_cmpint (nm_setting_connection_get_multi_connect (s_con), ==, NM_CONNECTION_MULTI_CONNECT_SINGLE);

	connection = g_hash_table_lookup (connections, "eth1");
	g_assert (connection);
	nmtst_assert_connection_verifies_without_normalization (connection);
	g_assert_cmpstr (nm_connection_get_id (connection), ==, "eth1");

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_connection_type (s_con), ==, NM_SETTING_WIRED_SETTING_NAME);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "eth1");
	g_assert_cmpstr (nm_setting_connection_get_slave_type (s_con), ==, NM_SETTING_TEAM_SETTING_NAME);
	g_assert_cmpstr (nm_setting_connection_get_master (s_con), ==, master_uuid);
	g_assert_cmpint (nm_setting_connection_get_multi_connect (s_con), ==, NM_CONNECTION_MULTI_CONNECT_SINGLE);
}

static void
test_ibft (void)
{
	gs_unref_hashtable GHashTable *connections = NULL;
	const char *const*ARGV = NM_MAKE_STRV ("ip=ibft");
	NMConnection *connection;

	connections = nmi_cmdline_reader_parse (TEST_INITRD_DIR "/sysfs", ARGV);
	g_assert (connections);
	g_assert_cmpint (g_hash_table_size (connections), ==, 2);

	connection = g_hash_table_lookup (connections, "ibft0");
	g_assert (connection);
	nmtst_assert_connection_verifies_without_normalization (connection);
	g_assert_cmpstr (nm_connection_get_id (connection), ==, "iBFT VLAN Connection 0");

	connection = g_hash_table_lookup (connections, "ibft2");
	g_assert (connection);
	nmtst_assert_connection_verifies_without_normalization (connection);
	g_assert_cmpstr (nm_connection_get_id (connection), ==, "iBFT Connection 2");
}

static void
test_ignore_extra (void)
{
	gs_unref_hashtable GHashTable *connections = NULL;
	const char *const*ARGV = NM_MAKE_STRV ("blabla", "extra", "lalala");

	connections = nmi_cmdline_reader_parse (TEST_INITRD_DIR "/sysfs", ARGV);
	g_assert (connections);
	g_assert_cmpint (g_hash_table_size (connections), ==, 0);
}

static void
test_rd_znet (void)
{
	gs_unref_hashtable GHashTable *connections = NULL;
	const char *const*const ARGV = NM_MAKE_STRV ("ip=10.11.12.13::10.11.12.1:24:foo.example.com:enc800:none",
	                                             "rd.znet=ctc,0.0.0800,0.0.0801,layer2=0,portno=1");
	GHashTableIter h_iter;
	NMConnection *connection;
	NMSettingWired *s_wired;
	const char *const*v_subchannels;
	const NMUtilsNamedValue s390_options[] = {
		{ .name = "layer2", .value_str = "0" },
		{ .name = "portno", .value_str = "1" },
	};
	int i_s390_options_keys;

	connections = nmi_cmdline_reader_parse (TEST_INITRD_DIR "/sysfs", ARGV);
	g_assert (connections);
	g_assert_cmpint (g_hash_table_size (connections), ==, 1);

	g_hash_table_iter_init (&h_iter, connections);
	if (!g_hash_table_iter_next (&h_iter, NULL, (gpointer *) &connection))
		g_assert_not_reached ();
	if (g_hash_table_iter_next (&h_iter, NULL, NULL))
		g_assert_not_reached ();

	g_assert (NM_IS_CONNECTION (connection));
	s_wired = nm_connection_get_setting_wired (connection);
	g_assert (NM_IS_SETTING_WIRED (s_wired));

	v_subchannels = nm_setting_wired_get_s390_subchannels (s_wired);
	g_assert (v_subchannels);
	g_assert_cmpstr (v_subchannels[0], ==, "0.0.0800");
	g_assert_cmpstr (v_subchannels[1], ==, "0.0.0801");
	g_assert_cmpstr (v_subchannels[2], ==, NULL);

	g_assert_cmpint (nm_setting_wired_get_num_s390_options (s_wired), ==, G_N_ELEMENTS (s390_options));
	for (i_s390_options_keys = 0; i_s390_options_keys < G_N_ELEMENTS (s390_options); i_s390_options_keys++) {
		const NMUtilsNamedValue *s390_option = &s390_options[i_s390_options_keys];
		const char *k;
		const char *v;
		const char *v2;

		g_assert (s390_option->name);
		g_assert (s390_option->value_str);
		v = nm_setting_wired_get_s390_option_by_key (s_wired, s390_option->name);
		g_assert (v);
		g_assert_cmpstr (v, ==, s390_option->value_str);

		if (!nm_setting_wired_get_s390_option (s_wired, i_s390_options_keys, &k, &v2))
			g_assert_not_reached ();
		g_assert_cmpstr (k, ==, s390_option->name);
		g_assert (v == v2);
		g_assert_cmpstr (v2, ==, s390_option->value_str);
	}

	nmtst_assert_connection_verifies_without_normalization (connection);
}

NMTST_DEFINE ();

int main (int argc, char **argv)
{
	nmtst_init_assert_logging (&argc, &argv, "INFO", "DEFAULT");

	g_test_add_func ("/initrd/cmdline/auto", test_auto);
	g_test_add_func ("/initrd/cmdline/if_auto_with_mtu", test_if_auto_with_mtu);
	g_test_add_func ("/initrd/cmdline/if_dhcp6", test_if_dhcp6);
	g_test_add_func ("/initrd/cmdline/if_auto_with_mtu_and_mac", test_if_auto_with_mtu_and_mac);
	g_test_add_func ("/initrd/cmdline/if_ip4_manual", test_if_ip4_manual);
	g_test_add_func ("/initrd/cmdline/if_ip6_manual", test_if_ip6_manual);
	g_test_add_func ("/initrd/cmdline/multiple", test_multiple);
	g_test_add_func ("/initrd/cmdline/some_more", test_some_more);
	g_test_add_func ("/initrd/cmdline/no_bootif", test_no_bootif);
	g_test_add_func ("/initrd/cmdline/bond", test_bond);
	g_test_add_func ("/initrd/cmdline/bond/default", test_bond_default);
	g_test_add_func ("/initrd/cmdline/team", test_team);
	g_test_add_func ("/initrd/cmdline/bridge", test_bridge);
	g_test_add_func ("/initrd/cmdline/bridge/default", test_bridge_default);
	g_test_add_func ("/initrd/cmdline/ibft", test_ibft);
	g_test_add_func ("/initrd/cmdline/ignore_extra", test_ignore_extra);
	g_test_add_func ("/initrd/cmdline/rd_zdnet", test_rd_znet);

	return g_test_run ();
}
