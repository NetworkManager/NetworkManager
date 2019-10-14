// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2008 - 2017 Red Hat, Inc.
 */

#include "nm-default.h"

#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/pkt_sched.h>

#include "nm-core-internal.h"

#include "settings/plugins/keyfile/nms-keyfile-reader.h"
#include "settings/plugins/keyfile/nms-keyfile-writer.h"
#include "settings/plugins/keyfile/nms-keyfile-utils.h"

#include "nm-test-utils-core.h"

#define TEST_KEYFILES_DIR       NM_BUILD_SRCDIR"/src/settings/plugins/keyfile/tests/keyfiles"
#define TEST_SCRATCH_DIR        NM_BUILD_BUILDDIR"/src/settings/plugins/keyfile/tests/keyfiles"

/*****************************************************************************/

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

#define keyfile_read_connection_from_file(full_filename) \
({ \
	gs_free_error GError *_error = NULL; \
	NMConnection *_connection; \
	\
	g_assert (full_filename && full_filename[0] == '/'); \
	\
	_connection = nms_keyfile_reader_from_file (full_filename, \
	                                            NULL, \
	                                            NULL, \
	                                            NULL, \
	                                            NULL, \
	                                            NULL, \
	                                            NULL, \
	                                            (nmtst_get_rand_uint32 () % 2) ? &_error : NULL); \
	nmtst_assert_success (_connection, _error); \
	nmtst_assert_connection_verifies_without_normalization (_connection); \
	\
	_connection; \
})

static void
assert_reread (NMConnection *connection, gboolean normalize_connection, const char *testfile)
{
	gs_unref_object NMConnection *reread = NULL;
	gs_unref_object NMConnection *connection_clone = NULL;
	NMSettingConnection *s_con;

	g_assert (NM_IS_CONNECTION (connection));

	reread = keyfile_read_connection_from_file (testfile);

	if (   !normalize_connection
	    && (s_con = nm_connection_get_setting_connection (connection))
	    && !nm_setting_connection_get_master (s_con)
	    && !nm_connection_get_setting_proxy (connection)) {
		connection_clone = nmtst_clone_connection (connection);
		connection = connection_clone;
		nm_connection_add_setting (connection, nm_setting_proxy_new ());
	}

	nmtst_assert_connection_equals (connection, normalize_connection, reread, FALSE);
}

static void
assert_reread_and_unlink (NMConnection *connection, gboolean normalize_connection, const char *testfile)
{
	assert_reread (connection, normalize_connection, testfile);
	unlink (testfile);
}

static void
assert_reread_same (NMConnection *connection,
                    NMConnection *reread)
{
	nmtst_assert_connection_verifies_without_normalization (reread);
	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);
}

static void
write_test_connection_reread (NMConnection *connection,
                              char **testfile,
                              NMConnection **out_reread,
                              gboolean *out_reread_same)
{
	uid_t owner_uid;
	gid_t owner_grp;
	gboolean success;
	GError *error = NULL;
	GError **p_error = (nmtst_get_rand_uint32 () % 2) ? &error : NULL;
	gs_unref_object NMConnection *connection_normalized = NULL;

	g_assert (NM_IS_CONNECTION (connection));
	g_assert (testfile && !*testfile);

	owner_uid = geteuid ();
	owner_grp = getegid ();

	connection_normalized = nmtst_connection_duplicate_and_normalize (connection);

	success = nms_keyfile_writer_test_connection (connection_normalized,
	                                              TEST_SCRATCH_DIR,
	                                              owner_uid,
	                                              owner_grp,
	                                              testfile,
	                                              out_reread,
	                                              out_reread_same,
	                                              p_error);
	g_assert_no_error (error);
	g_assert (success);
	g_assert (*testfile && (*testfile)[0]);
}

static void
write_test_connection (NMConnection *connection, char **testfile)
{
	gs_unref_object NMConnection *reread = NULL;
	gboolean reread_same = FALSE;

	write_test_connection_reread (connection, testfile, &reread, &reread_same);
	assert_reread_same (connection, reread);
	g_assert (reread_same);
}

static void
write_test_connection_and_reread (NMConnection *connection, gboolean normalize_connection)
{
	gs_free char *testfile = NULL;

	g_assert (NM_IS_CONNECTION (connection));

	write_test_connection (connection, &testfile);
	assert_reread_and_unlink (connection, normalize_connection, testfile);
}

static GKeyFile *
keyfile_load_from_file (const char *testfile)
{
	GKeyFile *keyfile;
	GError *error = NULL;
	gboolean success;

	g_assert (testfile && *testfile);

	keyfile = g_key_file_new ();
	success = g_key_file_load_from_file (keyfile, testfile, G_KEY_FILE_NONE, &error);
	g_assert_no_error (error);
	g_assert(success);

	return keyfile;
}

static void
_setting_copy_property_gbytes (NMConnection *src, NMConnection *dst, const char *setting_name, const char *property_name)
{
	gs_unref_bytes GBytes *blob = NULL;
	NMSetting *s_src;
	NMSetting *s_dst;

	g_assert (NM_IS_CONNECTION (src));
	g_assert (NM_IS_CONNECTION (dst));
	g_assert (setting_name);
	g_assert (property_name);

	s_src = nm_connection_get_setting_by_name (src, setting_name);
	g_assert (NM_IS_SETTING (s_src));
	s_dst = nm_connection_get_setting_by_name (dst, setting_name);
	g_assert (NM_IS_SETTING (s_dst));

	g_object_get (s_src, property_name, &blob, NULL);
	g_object_set (s_dst, property_name, blob, NULL);
}

/*****************************************************************************/

static void
test_read_valid_wired_connection (void)
{
	gs_unref_object NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	NMIPRoute *route;
	const char *mac;
	char expected_mac_address[ETH_ALEN] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };

	NMTST_EXPECT_NM_INFO ("*ipv4.addresses:*semicolon at the end*addresses1*");
	NMTST_EXPECT_NM_INFO ("*ipv4.addresses:*semicolon at the end*addresses2*");
	NMTST_EXPECT_NM_WARN ("*missing prefix length*address4*");
	NMTST_EXPECT_NM_WARN ("*missing prefix length*address5*");
	NMTST_EXPECT_NM_WARN ("*ipv4.dns: ignoring invalid DNS server IPv4 address 'bogus'*");
	NMTST_EXPECT_NM_INFO ("*ipv4.routes*semicolon at the end*routes2*");
	NMTST_EXPECT_NM_INFO ("*ipv4.routes*semicolon at the end*routes3*");
	NMTST_EXPECT_NM_INFO ("*ipv4.routes*semicolon at the end*routes5*");
	NMTST_EXPECT_NM_INFO ("*ipv4.routes*semicolon at the end*routes8*");
	NMTST_EXPECT_NM_WARN ("*missing prefix length*address4*");
	NMTST_EXPECT_NM_INFO ("*ipv6.address*semicolon at the end*address5*");
	NMTST_EXPECT_NM_WARN ("*missing prefix length*address5*");
	NMTST_EXPECT_NM_INFO ("*ipv6.address*semicolon at the end*address7*");
	NMTST_EXPECT_NM_INFO ("*ipv6.routes*semicolon at the end*routes1*");
	NMTST_EXPECT_NM_INFO ("*ipv6.route*semicolon at the end*route6*");
	connection = keyfile_read_connection_from_file (TEST_KEYFILES_DIR "/Test_Wired_Connection");
	g_test_assert_expected_messages ();

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "Test Wired Connection");
	g_assert_cmpstr (nm_setting_connection_get_uuid (s_con), ==, "4e80a56d-c99f-4aad-a6dd-b449bc398c57");
	g_assert_cmpuint (nm_setting_connection_get_timestamp (s_con), ==, 6654332);
	g_assert (nm_setting_connection_get_autoconnect (s_con));

	s_wired = nm_connection_get_setting_wired (connection);
	g_assert (s_wired);

	mac = nm_setting_wired_get_mac_address (s_wired);
	g_assert (mac);
	g_assert (nm_utils_hwaddr_matches (mac, -1, expected_mac_address, sizeof (expected_mac_address)));
	g_assert_cmpint (nm_setting_wired_get_mtu (s_wired), ==, 1400);

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_MANUAL);
	g_assert_cmpint (nm_setting_ip_config_get_num_dns (s_ip4), ==, 2);
	g_assert_cmpstr (nm_setting_ip_config_get_dns (s_ip4, 0), ==, "4.2.2.1");
	g_assert_cmpstr (nm_setting_ip_config_get_dns (s_ip4, 1), ==, "4.2.2.2");

	/* IPv4 addresses */
	g_assert_cmpint (nm_setting_ip_config_get_num_addresses (s_ip4), ==, 10);
	check_ip_address (s_ip4, 0, "2.3.4.5", 24);
	check_ip_address (s_ip4, 1, "192.168.0.5", 24);
	check_ip_address (s_ip4, 2, "1.2.3.4", 16);
	check_ip_address (s_ip4, 3, "3.4.5.6", 16);
	check_ip_address (s_ip4, 4, "4.5.6.7", 24);
	check_ip_address (s_ip4, 5, "5.6.7.8", 24);
	check_ip_address (s_ip4, 6, "1.2.3.30", 24);
	check_ip_address (s_ip4, 7, "1.2.3.30", 25);
	check_ip_address (s_ip4, 8, "1.2.3.31", 24);
	check_ip_address (s_ip4, 9, "1.2.3.31", 25);

	/* IPv4 gateway */
	g_assert_cmpstr (nm_setting_ip_config_get_gateway (s_ip4), ==, "2.3.4.6");

	/* IPv4 routes */
	g_assert_cmpint (nm_setting_ip_config_get_num_routes (s_ip4), ==, 13);
	check_ip_route (s_ip4, 0, "5.6.7.8", 32, NULL, -1);
	check_ip_route (s_ip4, 1, "1.2.3.0", 24, "2.3.4.8", 99);
	check_ip_route (s_ip4, 2, "1.1.1.2", 12, NULL, -1);
	check_ip_route (s_ip4, 3, "1.1.1.3", 13, NULL, -1);
	check_ip_route (s_ip4, 4, "1.1.1.4", 14, "2.2.2.4", -1);
	check_ip_route (s_ip4, 5, "1.1.1.5", 15, "2.2.2.5", -1);
	check_ip_route (s_ip4, 6, "1.1.1.6", 16, "2.2.2.6", 0);
	check_ip_route (s_ip4, 7, "1.1.1.7", 17, NULL, -1);
	check_ip_route (s_ip4, 8, "1.1.1.8", 18, NULL, -1);
	check_ip_route (s_ip4, 9, "1.1.1.9", 19, NULL, 0);
	check_ip_route (s_ip4, 10, "1.1.1.10", 21, NULL, 0);
	check_ip_route (s_ip4, 11, "1.1.1.10", 20, NULL, 0);
	check_ip_route (s_ip4, 12, "1.1.1.11", 21, NULL, 21);

	/* Route attributes */
	route = nm_setting_ip_config_get_route (s_ip4, 12);
	g_assert (route);

	nmtst_assert_route_attribute_uint32  (route, NM_IP_ROUTE_ATTRIBUTE_CWND, 10);
	nmtst_assert_route_attribute_uint32  (route, NM_IP_ROUTE_ATTRIBUTE_MTU, 1430);
	nmtst_assert_route_attribute_boolean (route, NM_IP_ROUTE_ATTRIBUTE_LOCK_CWND, TRUE);
	nmtst_assert_route_attribute_string  (route, NM_IP_ROUTE_ATTRIBUTE_SRC, "7.7.7.7");

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

	/* Route attributes */
	route = nm_setting_ip_config_get_route (s_ip6, 6);
	g_assert (route);
	nmtst_assert_route_attribute_string (route, NM_IP_ROUTE_ATTRIBUTE_FROM, "abce::/63");
}

static void
add_one_ip_address (NMSettingIPConfig *s_ip,
                    const char *addr,
                    guint32 prefix)
{
	NMIPAddress *ip_addr;
	gs_free_error GError *error = NULL;

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
	gs_free_error GError *error = NULL;

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
	NMTST_UUID_INIT (uuid);
	gs_unref_object NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	NMIPRoute *rt;
	const char *mac = "99:88:77:66:55:44";
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
	GError *error = NULL;

	connection = nm_simple_connection_new ();

	/* Connection setting */

	s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Work Wired",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, FALSE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
	              NM_SETTING_CONNECTION_TIMESTAMP, timestamp,
	              NULL);

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

	rt = nm_ip_route_new (AF_INET, route4, 6, route4_nh, 4, &error);
	g_assert_no_error (error);
	nm_ip_route_set_attribute (rt, NM_IP_ROUTE_ATTRIBUTE_CWND, g_variant_new_uint32 (10));
	nm_ip_route_set_attribute (rt, NM_IP_ROUTE_ATTRIBUTE_MTU, g_variant_new_uint32 (1492));
	nm_ip_route_set_attribute (rt, NM_IP_ROUTE_ATTRIBUTE_SRC, g_variant_new_string ("1.2.3.4"));
	g_assert (nm_setting_ip_config_add_route (s_ip4, rt));
	nm_ip_route_unref (rt);

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

	write_test_connection_and_reread (connection, FALSE);
}

static void
test_read_ip6_wired_connection (void)
{
	gs_unref_object NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;

	connection = keyfile_read_connection_from_file (TEST_KEYFILES_DIR "/Test_Wired_Connection_IP6");

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "Test Wired Connection IP6");
	g_assert_cmpstr (nm_setting_connection_get_uuid (s_con), ==, "4e80a56d-c99f-4aad-a6dd-b449bc398c57");

	s_wired = nm_connection_get_setting_wired (connection);
	g_assert (s_wired);

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_DISABLED);
	g_assert_cmpint (nm_setting_ip_config_get_num_addresses (s_ip4), ==, 0);

	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	g_assert (s_ip6);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip6), ==, NM_SETTING_IP6_CONFIG_METHOD_MANUAL);
	g_assert_cmpint (nm_setting_ip_config_get_num_addresses (s_ip6), ==, 1);
	check_ip_address (s_ip6, 0, "abcd:1234:ffff::cdde", 64);
	g_assert_cmpstr (nm_setting_ip_config_get_gateway (s_ip6), ==, "abcd:1234:ffff::cdd1");
}

static void
test_write_ip6_wired_connection (void)
{
	NMTST_UUID_INIT (uuid);
	gs_unref_object NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	const char *dns = "1::cafe";
	const char *address = "abcd::beef";
	const char *gw = "dcba::beef";

	connection = nm_simple_connection_new ();

	/* Connection setting */

	s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Work Wired IP6",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, FALSE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
	              NULL);

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

	write_test_connection_and_reread (connection, FALSE);
}

static void
test_read_wired_mac_case (void)
{
	gs_unref_object NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	const char *mac;
	char expected_mac_address[ETH_ALEN] = { 0x00, 0x11, 0xaa, 0xbb, 0xcc, 0x55 };

	NMTST_EXPECT_NM_INFO ("*ipv4.addresses*semicolon at the end*addresses1*");
	NMTST_EXPECT_NM_INFO ("*ipv4.addresses*semicolon at the end*addresses2*");
	NMTST_EXPECT_NM_INFO ("*ipv6.routes*semicolon at the end*routes1*");
	connection = keyfile_read_connection_from_file (TEST_KEYFILES_DIR "/Test_Wired_Connection_MAC_Case");
	g_test_assert_expected_messages ();

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "Test Wired Connection MAC Case");
	g_assert_cmpstr (nm_setting_connection_get_uuid (s_con), ==, "4e80a56d-c99f-4aad-a6dd-b449bc398c57");

	s_wired = nm_connection_get_setting_wired (connection);
	g_assert (s_wired);
	mac = nm_setting_wired_get_mac_address (s_wired);
	g_assert (mac);
	g_assert (nm_utils_hwaddr_matches (mac, -1, expected_mac_address, sizeof (expected_mac_address)));
}

static void
test_read_mac_old_format (void)
{
	gs_unref_object NMConnection *connection = NULL;
	NMSettingWired *s_wired;
	const char *mac;
	char expected_mac[ETH_ALEN] = { 0x00, 0x11, 0xaa, 0xbb, 0xcc, 0x55 };
	char expected_cloned_mac[ETH_ALEN] = { 0x00, 0x16, 0xaa, 0xbb, 0xcc, 0xfe };

	connection = keyfile_read_connection_from_file (TEST_KEYFILES_DIR "/Test_MAC_Old_Format");

	s_wired = nm_connection_get_setting_wired (connection);
	g_assert (s_wired);

	mac = nm_setting_wired_get_mac_address (s_wired);
	g_assert (mac);
	g_assert (nm_utils_hwaddr_matches (mac, -1, expected_mac, ETH_ALEN));

	mac = nm_setting_wired_get_cloned_mac_address (s_wired);
	g_assert (mac);
	g_assert (nm_utils_hwaddr_matches (mac, -1, expected_cloned_mac, ETH_ALEN));
}

static void
test_read_mac_ib_old_format (void)
{
	gs_unref_object NMConnection *connection = NULL;
	NMSettingInfiniband *s_ib;
	const char *mac;
	guint8 expected_mac[INFINIBAND_ALEN] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
	    0x77, 0x88, 0x99, 0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89,
	    0x90 };

	connection = keyfile_read_connection_from_file (TEST_KEYFILES_DIR "/Test_MAC_IB_Old_Format");

	s_ib = nm_connection_get_setting_infiniband (connection);
	g_assert (s_ib);

	/* MAC address */
	mac = nm_setting_infiniband_get_mac_address (s_ib);
	g_assert (mac);
	g_assert (nm_utils_hwaddr_matches (mac, -1, expected_mac, sizeof (expected_mac)));
}

static void
test_read_valid_wireless_connection (void)
{
	gs_unref_object NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	NMSettingIPConfig *s_ip4;
	const char *bssid;
	const guint8 expected_bssid[ETH_ALEN] = { 0x00, 0x1a, 0x33, 0x44, 0x99, 0x82 };

	connection = keyfile_read_connection_from_file (TEST_KEYFILES_DIR "/Test_Wireless_Connection");

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "Test Wireless Connection");
	g_assert_cmpstr (nm_setting_connection_get_uuid (s_con), ==, "2f962388-e5f3-45af-a62c-ac220b8f7baa");
	g_assert_cmpuint (nm_setting_connection_get_timestamp (s_con), ==, 1226604314);
	g_assert (nm_setting_connection_get_autoconnect (s_con) == FALSE);

	s_wireless = nm_connection_get_setting_wireless (connection);
	g_assert (s_wireless);
	bssid = nm_setting_wireless_get_bssid (s_wireless);
	g_assert (bssid);
	g_assert (nm_utils_hwaddr_matches (bssid, -1, expected_bssid, sizeof (expected_bssid)));

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_AUTO);
}

static void
test_write_wireless_connection (void)
{
	NMTST_UUID_INIT (uuid);
	gs_unref_object NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	const char *bssid = "aa:b9:a1:74:55:44";
	GBytes *ssid;
	unsigned char tmpssid[] = { 0x31, 0x33, 0x33, 0x37 };
	guint64 timestamp = 0x12344433L;

	connection = nm_simple_connection_new ();

	/* Connection setting */

	s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Work Wireless",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, FALSE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRELESS_SETTING_NAME,
	              NM_SETTING_CONNECTION_TIMESTAMP, timestamp,
	              NULL);

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

	write_test_connection_and_reread (connection, FALSE);
}

static void
test_read_string_ssid (void)
{
	gs_unref_object NMConnection *connection = NULL;
	NMSettingWireless *s_wireless;
	GBytes *ssid;
	const guint8 *ssid_data;
	gsize ssid_len;
	const char *expected_ssid = "blah blah ssid 1234";

	connection = keyfile_read_connection_from_file (TEST_KEYFILES_DIR "/Test_String_SSID");

	s_wireless = nm_connection_get_setting_wireless (connection);
	g_assert (s_wireless);

	ssid = nm_setting_wireless_get_ssid (s_wireless);
	g_assert (ssid);

	ssid_data = g_bytes_get_data (ssid, &ssid_len);
	g_assert_cmpmem (ssid_data, ssid_len, expected_ssid, strlen (expected_ssid));
}

static void
test_write_string_ssid (void)
{
	NMTST_UUID_INIT (uuid);
	gs_unref_object NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	NMSettingIPConfig *s_ip4;
	char *tmp;
	gs_free char *testfile = NULL;
	GBytes *ssid;
	unsigned char tmpssid[] = { 65, 49, 50, 51, 32, 46, 92, 46, 36, 37, 126, 93 };
	gs_unref_keyfile GKeyFile *keyfile = NULL;

	connection = nm_simple_connection_new ();

	/* Connection setting */

	s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "String SSID Test",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRELESS_SETTING_NAME,
	              NULL);

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

	write_test_connection (connection, &testfile);

	/* Ensure the SSID was written out as a string */
	keyfile = keyfile_load_from_file (testfile);
	tmp = g_key_file_get_string (keyfile, "wifi", NM_SETTING_WIRELESS_SSID, NULL);
	g_assert (tmp);
	g_assert_cmpmem (tmp, strlen (tmp), tmpssid, sizeof (tmpssid));
	g_free (tmp);

	assert_reread_and_unlink (connection, TRUE, testfile);
}

static void
test_read_intlist_ssid (void)
{
	gs_unref_object NMConnection *connection = NULL;
	NMSettingWireless *s_wifi;
	GBytes *ssid;
	const guint8 *ssid_data;
	gsize ssid_len;
	const char *expected_ssid = "blah1234";

	connection = keyfile_read_connection_from_file (TEST_KEYFILES_DIR "/Test_Intlist_SSID");

	s_wifi = nm_connection_get_setting_wireless (connection);
	g_assert (s_wifi);

	ssid = nm_setting_wireless_get_ssid (s_wifi);
	g_assert (ssid != NULL);
	ssid_data = g_bytes_get_data (ssid, &ssid_len);
	g_assert_cmpmem (ssid_data, ssid_len, expected_ssid, strlen (expected_ssid));
}

static void
test_write_intlist_ssid (void)
{
	NMTST_UUID_INIT (uuid);
	gs_unref_object NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wifi;
	NMSettingIPConfig *s_ip4;
	gs_free char *testfile = NULL;
	GBytes *ssid;
	unsigned char tmpssid[] = { 65, 49, 50, 51, 0, 50, 50 };
	gs_free_error GError *error = NULL;
	gs_unref_keyfile GKeyFile *keyfile = NULL;
	int *intlist;
	gsize len = 0, i;

	connection = nm_simple_connection_new ();
	g_assert (connection);

	/* Connection setting */

	s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());
	g_assert (s_con);
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Intlist SSID Test",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRELESS_SETTING_NAME,
	              NULL);

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

	write_test_connection (connection, &testfile);

	/* Ensure the SSID was written out as an int list */
	keyfile = keyfile_load_from_file (testfile);

	intlist = g_key_file_get_integer_list (keyfile, "wifi", NM_SETTING_WIRELESS_SSID, &len, &error);
	g_assert_no_error (error);
	g_assert (intlist);
	g_assert_cmpint (len, ==, sizeof (tmpssid));

	for (i = 0; i < len; i++)
		g_assert_cmpint (intlist[i], ==, tmpssid[i]);
	g_free (intlist);

	assert_reread_and_unlink (connection, TRUE, testfile);
}

static void
test_read_intlike_ssid (void)
{
	gs_unref_object NMConnection *connection = NULL;
	NMSettingWireless *s_wifi;
	GBytes *ssid;
	const char *expected_ssid = "101";

	connection = keyfile_read_connection_from_file (TEST_KEYFILES_DIR "/Test_Intlike_SSID");

	s_wifi = nm_connection_get_setting_wireless (connection);
	g_assert (s_wifi);

	ssid = nm_setting_wireless_get_ssid (s_wifi);
	g_assert (ssid);
	g_assert (nm_utils_gbytes_equal_mem (ssid, expected_ssid, strlen (expected_ssid)));
}

static void
test_read_intlike_ssid_2 (void)
{
	gs_unref_object NMConnection *connection = NULL;
	NMSettingWireless *s_wifi;
	GBytes *ssid;
	const char *expected_ssid = "11;12;13;";

	connection = keyfile_read_connection_from_file (TEST_KEYFILES_DIR "/Test_Intlike_SSID_2");

	s_wifi = nm_connection_get_setting_wireless (connection);
	g_assert (s_wifi);

	ssid = nm_setting_wireless_get_ssid (s_wifi);
	g_assert (ssid);
	g_assert (nm_utils_gbytes_equal_mem (ssid, expected_ssid, strlen (expected_ssid)));
}

static void
test_write_intlike_ssid (void)
{
	NMTST_UUID_INIT (uuid);
	gs_unref_object NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wifi;
	NMSettingIPConfig *s_ip4;
	gs_free char *testfile = NULL;
	GBytes *ssid;
	unsigned char tmpssid[] = { 49, 48, 49 };
	gs_free_error GError *error = NULL;
	gs_unref_keyfile GKeyFile *keyfile = NULL;
	char *tmp;

	connection = nm_simple_connection_new ();

	/* Connection setting */

	s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());
	g_assert (s_con);
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Intlike SSID Test",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRELESS_SETTING_NAME,
	              NULL);

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

	write_test_connection (connection, &testfile);

	/* Ensure the SSID was written out as a plain "101" */
	keyfile = keyfile_load_from_file (testfile);

	tmp = g_key_file_get_string (keyfile, "wifi", NM_SETTING_WIRELESS_SSID, &error);
	g_assert_no_error (error);
	g_assert (tmp);
	g_assert_cmpstr (tmp, ==, "101");
	g_free (tmp);

	assert_reread_and_unlink (connection, TRUE, testfile);
}

static void
test_write_intlike_ssid_2 (void)
{
	NMTST_UUID_INIT (uuid);
	gs_unref_object NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wifi;
	NMSettingIPConfig *s_ip4;
	gs_free char *testfile = NULL;
	GBytes *ssid;
	unsigned char tmpssid[] = { 49, 49, 59, 49, 50, 59, 49, 51, 59};
	gs_free_error GError *error = NULL;
	gs_unref_keyfile GKeyFile *keyfile = NULL;
	char *tmp;

	connection = nm_simple_connection_new ();
	g_assert (connection);

	/* Connection setting */

	s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());
	g_assert (s_con);
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Intlike SSID Test 2",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRELESS_SETTING_NAME,
	              NULL);

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

	write_test_connection (connection, &testfile);

	/* Ensure the SSID was written out as a plain "11;12;13;" */
	keyfile = keyfile_load_from_file (testfile);

	tmp = g_key_file_get_string (keyfile, "wifi", NM_SETTING_WIRELESS_SSID, &error);
	g_assert_no_error (error);
	g_assert (tmp);
	g_assert_cmpstr (tmp, ==, "11\\;12\\;13\\;");
	g_free (tmp);

	assert_reread_and_unlink (connection, TRUE, testfile);
}

static void
test_read_bt_dun_connection (void)
{
	gs_unref_object NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	NMSettingBluetooth *s_bluetooth;
	NMSettingSerial *s_serial;
	NMSettingGsm *s_gsm;
	const char *bdaddr;
	const guint8 expected_bdaddr[ETH_ALEN] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };

	connection = keyfile_read_connection_from_file (TEST_KEYFILES_DIR "/ATT_Data_Connect_BT");

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "AT&T Data Connect BT");
	g_assert_cmpstr (nm_setting_connection_get_uuid (s_con), ==, "089130ab-ce28-46e4-ad77-d44869b03d19");

	s_bluetooth = nm_connection_get_setting_bluetooth (connection);
	g_assert (s_bluetooth);
	bdaddr = nm_setting_bluetooth_get_bdaddr (s_bluetooth);
	g_assert (bdaddr);
	g_assert (nm_utils_hwaddr_matches (bdaddr, -1, expected_bdaddr, sizeof (expected_bdaddr)));
	g_assert_cmpstr (nm_setting_bluetooth_get_connection_type (s_bluetooth), ==, NM_SETTING_BLUETOOTH_TYPE_DUN);

	s_gsm = nm_connection_get_setting_gsm (connection);
	g_assert (s_gsm);
	g_assert_cmpstr (nm_setting_gsm_get_apn (s_gsm), ==, "ISP.CINGULAR");
	g_assert_cmpstr (nm_setting_gsm_get_username (s_gsm), ==, "ISP@CINGULARGPRS.COM");
	g_assert_cmpstr (nm_setting_gsm_get_password (s_gsm), ==, "CINGULAR1");

	s_serial = nm_connection_get_setting_serial (connection);
	g_assert (s_serial);
	g_assert (nm_setting_serial_get_parity (s_serial) == NM_SETTING_SERIAL_PARITY_ODD);
}

static void
test_write_bt_dun_connection (void)
{
	NMTST_UUID_INIT (uuid);
	gs_unref_object NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	NMSettingBluetooth *s_bt;
	NMSettingIPConfig *s_ip4;
	NMSettingGsm *s_gsm;
	const char *bdaddr = "aa:b9:a1:74:55:44";
	guint64 timestamp = 0x12344433L;

	connection = nm_simple_connection_new ();

	/* Connection setting */

	s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "T-Mobile Funkadelic",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, FALSE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_BLUETOOTH_SETTING_NAME,
	              NM_SETTING_CONNECTION_TIMESTAMP, timestamp,
	              NULL);

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
	              NULL);

	write_test_connection_and_reread (connection, TRUE);
}

static void
test_read_gsm_connection (void)
{
	gs_unref_object NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	NMSettingSerial *s_serial;
	NMSettingGsm *s_gsm;

	connection = keyfile_read_connection_from_file (TEST_KEYFILES_DIR "/ATT_Data_Connect_Plain");

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "AT&T Data Connect");
	g_assert_cmpstr (nm_setting_connection_get_connection_type (s_con), ==, NM_SETTING_GSM_SETTING_NAME);

	/* Plain GSM, so no BT setting expected */
	g_assert (nm_connection_get_setting_bluetooth (connection) == NULL);

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

	s_serial = nm_connection_get_setting_serial (connection);
	g_assert (s_serial);
	g_assert_cmpint (nm_setting_serial_get_parity (s_serial), ==, NM_SETTING_SERIAL_PARITY_ODD);
}

static void
test_write_gsm_connection (void)
{
	NMTST_UUID_INIT (uuid);
	gs_unref_object NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	NMSettingIPConfig *s_ip4;
	NMSettingGsm *s_gsm;
	guint64 timestamp = 0x12344433L;

	connection = nm_simple_connection_new ();

	/* Connection setting */

	s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "T-Mobile Funkadelic 2",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, FALSE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_GSM_SETTING_NAME,
	              NM_SETTING_CONNECTION_TIMESTAMP, timestamp,
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
	              NM_SETTING_GSM_USERNAME, "george.clinton.again",
	              NM_SETTING_GSM_PASSWORD, "parliament2",
	              NM_SETTING_GSM_PIN, "123456",
	              NM_SETTING_GSM_NETWORK_ID, "254098",
	              NM_SETTING_GSM_HOME_ONLY, TRUE,
	              NM_SETTING_GSM_DEVICE_ID, "da812de91eec16620b06cd0ca5cbc7ea25245222",
	              NM_SETTING_GSM_SIM_ID, "89148000000060671234",
	              NM_SETTING_GSM_SIM_OPERATOR_ID, "310260",
	              NULL);

	write_test_connection_and_reread (connection, TRUE);
}

static void
test_read_wired_8021x_tls_blob_connection (void)
{
	gs_unref_object NMConnection *connection = NULL;
	NMSettingWired *s_wired;
	NMSetting8021x *s_8021x;
	const char *tmp;
	GBytes *blob;

	NMTST_EXPECT_NM_WARN ("keyfile: 802-1x.client-cert: certificate or key file '/CASA/dcbw/Desktop/certinfra/client.pem' does not exist*");
	NMTST_EXPECT_NM_WARN ("keyfile: 802-1x.private-key: certificate or key file '/CASA/dcbw/Desktop/certinfra/client.pem' does not exist*");
	connection = keyfile_read_connection_from_file (TEST_KEYFILES_DIR "/Test_Wired_TLS_Blob");

	s_wired = nm_connection_get_setting_wired (connection);
	g_assert (s_wired != NULL);

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
	NMTST_EXPECT_LIBNM_CRITICAL (NMTST_G_RETURN_MSG (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH));
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
}

static void
test_read_wired_8021x_tls_bad_path_connection (void)
{
	gs_unref_object NMConnection *connection = NULL;
	NMSettingWired *s_wired;
	NMSetting8021x *s_8021x;
	const char *tmp;
	char *tmp2;

	NMTST_EXPECT_NM_WARN ("*does not exist*");
	connection = keyfile_read_connection_from_file (TEST_KEYFILES_DIR "/Test_Wired_TLS_Path_Missing");
	g_test_assert_expected_messages ();

	s_wired = nm_connection_get_setting_wired (connection);
	g_assert (s_wired != NULL);

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
}

static void
test_read_wired_8021x_tls_old_connection (void)
{
	gs_unref_object NMConnection *connection = NULL;
	NMSettingWired *s_wired;
	NMSetting8021x *s_8021x;
	const char *tmp;

	NMTST_EXPECT_NM_WARN ("keyfile: 802-1x.ca-cert: certificate or key file '/CASA/dcbw/Desktop/certinfra/CA/eaptest_ca_cert.pem' does not exist*");
	NMTST_EXPECT_NM_WARN ("keyfile: 802-1x.client-cert: certificate or key file '/CASA/dcbw/Desktop/certinfra/client.pem' does not exist*");
	NMTST_EXPECT_NM_WARN ("keyfile: 802-1x.private-key: certificate or key file '/CASA/dcbw/Desktop/certinfra/client.pem' does not exist*");
	connection = keyfile_read_connection_from_file (TEST_KEYFILES_DIR "/Test_Wired_TLS_Old");

	s_wired = nm_connection_get_setting_wired (connection);
	g_assert (s_wired != NULL);

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
}

static void
test_read_wired_8021x_tls_new_connection (void)
{
	gs_unref_object NMConnection *connection = NULL;
	NMSettingWired *s_wired;
	NMSetting8021x *s_8021x;
	const char *tmp;
	char *tmp2;

	connection = keyfile_read_connection_from_file (TEST_KEYFILES_DIR "/Test_Wired_TLS_New");

	s_wired = nm_connection_get_setting_wired (connection);
	g_assert (s_wired != NULL);

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
}

#define TEST_WIRED_TLS_CA_CERT TEST_KEYFILES_DIR"/test-ca-cert.pem"
#define TEST_WIRED_TLS_CLIENT_CERT TEST_KEYFILES_DIR"/test-key-and-cert.pem"
#define TEST_WIRED_TLS_PRIVKEY TEST_KEYFILES_DIR"/test-key-and-cert.pem"

static NMConnection *
create_wired_tls_connection (NMSetting8021xCKScheme scheme)
{
	NMTST_UUID_INIT (uuid);
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingIPConfig *s_ip4;
	NMSetting *s_wired;
	NMSetting8021x *s_8021x;
	gboolean success;
	gs_free_error GError *error = NULL;

	connection = nm_simple_connection_new ();
	g_assert (connection != NULL);

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	g_assert (s_con);
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Wired Really Secure TLS",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
	              NULL);

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
	gs_unref_object NMConnection *connection = NULL;
	gs_unref_object NMConnection *reread = NULL;
	char *tmp, *tmp2;
	gboolean success;
	gs_free char *testfile = NULL;
	gs_unref_keyfile GKeyFile *keyfile = NULL;
	gboolean relative = FALSE;
	gboolean reread_same = FALSE;

	connection = create_wired_tls_connection (NM_SETTING_802_1X_CK_SCHEME_PATH);
	g_assert (connection != NULL);

	write_test_connection_reread (connection, &testfile, &reread, &reread_same);
	nmtst_assert_connection_verifies_without_normalization (reread);
	_setting_copy_property_gbytes (connection, reread, NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_CA_CERT);
	_setting_copy_property_gbytes (connection, reread, NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_CLIENT_CERT);
	_setting_copy_property_gbytes (connection, reread, NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_PRIVATE_KEY);
	assert_reread_same (connection, reread);
	g_clear_object (&reread);

	/* Read the connection back in and compare it to the one we just wrote out */
	reread = keyfile_read_connection_from_file (testfile);

	success = nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT);
	if (!reread) {
		g_warning ("Written and re-read connection weren't the same");
		g_assert (success);
	}

	/* Ensure the cert and key values are properly written out */
	keyfile = keyfile_load_from_file (testfile);

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

	unlink (testfile);
}

static void
test_write_wired_8021x_tls_connection_blob (void)
{
	gs_unref_object NMConnection *connection = NULL;
	gs_unref_object NMConnection *reread = NULL;
	NMSettingConnection *s_con;
	NMSetting8021x *s_8021x;
	gs_free char *testfile = NULL;
	char *new_ca_cert;
	char *new_client_cert;
	char *new_priv_key;
	const char *uuid;
	gboolean reread_same = FALSE;
	GBytes *password_raw;

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

	write_test_connection_reread (connection, &testfile, &reread, &reread_same);
	nmtst_assert_connection_verifies_without_normalization (reread);
	_setting_copy_property_gbytes (connection, reread, NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_CA_CERT);
	_setting_copy_property_gbytes (connection, reread, NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_CLIENT_CERT);
	_setting_copy_property_gbytes (connection, reread, NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_PRIVATE_KEY);
	assert_reread_same (connection, reread);
	g_clear_object (&reread);

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
	reread = keyfile_read_connection_from_file (testfile);

	/* Ensure the re-read connection's certificates use the path scheme */
	s_8021x = nm_connection_get_setting_802_1x (reread);
	g_assert (s_8021x);
	g_assert (nm_setting_802_1x_get_ca_cert_scheme (s_8021x) == NM_SETTING_802_1X_CK_SCHEME_PATH);
	g_assert (nm_setting_802_1x_get_client_cert_scheme (s_8021x) == NM_SETTING_802_1X_CK_SCHEME_PATH);
	g_assert (nm_setting_802_1x_get_private_key_scheme (s_8021x) == NM_SETTING_802_1X_CK_SCHEME_PATH);

	password_raw = nm_setting_802_1x_get_password_raw (s_8021x);
	g_assert (password_raw);
	g_assert (nm_utils_gbytes_equal_mem (password_raw, PASSWORD_RAW, NM_STRLEN (PASSWORD_RAW)));

	unlink (testfile);

	/* Clean up written certs */
	unlink (new_ca_cert);
	g_free (new_ca_cert);

	unlink (new_client_cert);
	g_free (new_client_cert);

	unlink (new_priv_key);
	g_free (new_priv_key);
}

static void
test_read_dcb_connection (void)
{
	gs_unref_object NMConnection *connection = NULL;

	connection = keyfile_read_connection_from_file (TEST_KEYFILES_DIR"/Test_dcb_connection");
}

static void
test_read_infiniband_connection (void)
{
	gs_unref_object NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	NMSettingInfiniband *s_ib;
	const char *mac;
	guint8 expected_mac[INFINIBAND_ALEN] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
	    0x77, 0x88, 0x99, 0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89,
	    0x90 };
	const char *expected_id = "Test InfiniBand Connection";
	const char *expected_uuid = "4e80a56d-c99f-4aad-a6dd-b449bc398c57";

	connection = keyfile_read_connection_from_file (TEST_KEYFILES_DIR "/Test_InfiniBand_Connection");

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, expected_id);
	g_assert_cmpstr (nm_setting_connection_get_uuid (s_con), ==, expected_uuid);

	s_ib = nm_connection_get_setting_infiniband (connection);
	g_assert (s_ib);

	mac = nm_setting_infiniband_get_mac_address (s_ib);
	g_assert (mac);
	g_assert (nm_utils_hwaddr_matches (mac, -1, expected_mac, sizeof (expected_mac)));
}

static void
test_write_infiniband_connection (void)
{
	NMTST_UUID_INIT (uuid);
	gs_unref_object NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	NMSettingInfiniband *s_ib;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	const char *mac = "99:88:77:66:55:44:ab:bc:cd:de:ef:f0:0a:1b:2c:3d:4e:5f:6f:ba";

	connection = nm_simple_connection_new ();

	/* Connection setting */

	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	g_assert (s_con);
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Work InfiniBand",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, FALSE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_INFINIBAND_SETTING_NAME,
	              NULL);

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

	write_test_connection_and_reread (connection, FALSE);
}

static void
test_read_bridge_main (void)
{
	gs_unref_object NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	NMSettingIPConfig *s_ip4;
	NMSettingBridge *s_bridge;
	const char *expected_id = "Test Bridge Main";
	const char *expected_uuid = "8f061643-fe41-4d4c-a8d9-097d26e2ad3a";

	connection = keyfile_read_connection_from_file (TEST_KEYFILES_DIR "/Test_Bridge_Main");

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, expected_id);
	g_assert_cmpstr (nm_setting_connection_get_uuid (s_con), ==, expected_uuid);
	g_assert_cmpstr (nm_setting_connection_get_interface_name (s_con), ==, "br0");

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_AUTO);

	s_bridge = nm_connection_get_setting_bridge (connection);
	g_assert (s_bridge);
	g_assert_cmpuint (nm_setting_bridge_get_forward_delay (s_bridge), ==, 2);
	g_assert_cmpuint (nm_setting_bridge_get_stp (s_bridge), ==, TRUE);
	g_assert_cmpuint (nm_setting_bridge_get_priority (s_bridge), ==, 32744);
	g_assert_cmpuint (nm_setting_bridge_get_hello_time (s_bridge), ==, 7);
	g_assert_cmpuint (nm_setting_bridge_get_max_age (s_bridge), ==, 39);
	g_assert_cmpuint (nm_setting_bridge_get_ageing_time (s_bridge), ==, 235352);
	g_assert_cmpuint (nm_setting_bridge_get_multicast_snooping (s_bridge), ==, FALSE);
}

static void
test_write_bridge_main (void)
{
	NMTST_UUID_INIT (uuid);
	gs_unref_object NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	NMSettingBridge *s_bridge;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;

	connection = nm_simple_connection_new ();
	g_assert (connection);

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	g_assert (s_con);
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write Bridge Main",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_BRIDGE_SETTING_NAME,
	              NM_SETTING_CONNECTION_INTERFACE_NAME, "br0",
	              NULL);

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

	write_test_connection_and_reread (connection, FALSE);
}

static void
test_read_bridge_component (void)
{
	gs_unref_object NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	NMSettingBridgePort *s_port;
	NMSettingWired *s_wired;
	const char *mac;
	guint8 expected_mac[ETH_ALEN] = { 0x00, 0x22, 0x15, 0x59, 0x62, 0x97 };
	const char *expected_id = "Test Bridge Component";
	const char *expected_uuid = "d7b4f96c-c45e-4298-bef8-f48574f8c1c0";

	connection = keyfile_read_connection_from_file (TEST_KEYFILES_DIR "/Test_Bridge_Component");

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, expected_id);
	g_assert_cmpstr (nm_setting_connection_get_uuid (s_con), ==, expected_uuid);
	g_assert_cmpstr (nm_setting_connection_get_master (s_con), ==, "br0");
	g_assert (nm_setting_connection_is_slave_type (s_con, NM_SETTING_BRIDGE_SETTING_NAME));

	s_wired = nm_connection_get_setting_wired (connection);
	g_assert (s_wired);
	mac = nm_setting_wired_get_mac_address (s_wired);
	g_assert (mac);
	g_assert (nm_utils_hwaddr_matches (mac, -1, expected_mac, sizeof (expected_mac)));

	s_port = nm_connection_get_setting_bridge_port (connection);
	g_assert (s_port);
	g_assert (nm_setting_bridge_port_get_hairpin_mode (s_port));
	g_assert_cmpuint (nm_setting_bridge_port_get_priority (s_port), ==, 28);
	g_assert_cmpuint (nm_setting_bridge_port_get_path_cost (s_port), ==, 100);
}

static void
test_write_bridge_component (void)
{
	NMTST_UUID_INIT (uuid);
	gs_unref_object NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	NMSettingBridgePort *s_port;
	NMSettingWired *s_wired;
	const char *mac = "99:88:77:66:55:44";

	connection = nm_simple_connection_new ();
	g_assert (connection);

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	g_assert (s_con);
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write Bridge Component",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
	              NM_SETTING_CONNECTION_MASTER, "br0",
	              NM_SETTING_CONNECTION_SLAVE_TYPE, NM_SETTING_BRIDGE_SETTING_NAME,
	              NULL);

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

	write_test_connection_and_reread (connection, FALSE);
}

static void
test_read_new_wired_group_name (void)
{
	gs_unref_object NMConnection *connection = NULL;
	NMSettingWired *s_wired;
	const char *mac;
	guint8 expected_mac[ETH_ALEN] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };

	connection = keyfile_read_connection_from_file (TEST_KEYFILES_DIR"/Test_New_Wired_Group_Name");

	s_wired = nm_connection_get_setting_wired (connection);
	g_assert (s_wired);
	g_assert_cmpint (nm_setting_wired_get_mtu (s_wired), ==, 1400);

	mac = nm_setting_wired_get_mac_address (s_wired);
	g_assert (mac);
	g_assert (nm_utils_hwaddr_matches (mac, -1, expected_mac, sizeof (expected_mac)));
}

static void
test_write_new_wired_group_name (void)
{
	NMTST_UUID_INIT (uuid);
	gs_unref_object NMConnection *connection = NULL;
	gs_unref_keyfile GKeyFile *kf = NULL;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	gs_free char *testfile = NULL;
	gs_free_error GError *error = NULL;
	char *s;
	int mtu;

	connection = nm_simple_connection_new ();
	g_assert (connection);

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	g_assert (s_con);
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write Wired New Group Name",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
	              NULL);

	/* Wired setting */
	s_wired = (NMSettingWired *) nm_setting_wired_new ();
	g_assert (s_wired);
	g_object_set (s_wired, NM_SETTING_WIRED_MTU, 1400, NULL);
	nm_connection_add_setting (connection, NM_SETTING (s_wired));

	write_test_connection (connection, &testfile);

	assert_reread (connection, TRUE, testfile);

	/* Look at the keyfile itself to ensure we wrote out the new group names and type */
	kf = keyfile_load_from_file (testfile);

	s = g_key_file_get_string (kf, NM_SETTING_CONNECTION_SETTING_NAME, NM_SETTING_CONNECTION_TYPE, &error);
	g_assert_no_error (error);
	g_assert_cmpstr (s, ==, "ethernet");
	g_free (s);

	mtu = g_key_file_get_integer (kf, "ethernet", NM_SETTING_WIRED_MTU, &error);
	g_assert_no_error (error);
	g_assert_cmpint (mtu, ==, 1400);

	unlink (testfile);
}

static void
test_read_new_wireless_group_names (void)
{
	gs_unref_object NMConnection *connection = NULL;
	NMSettingWireless *s_wifi;
	NMSettingWirelessSecurity *s_wsec;
	GBytes *ssid;
	const char *expected_ssid = "foobar";

	connection = keyfile_read_connection_from_file (TEST_KEYFILES_DIR"/Test_New_Wireless_Group_Names");

	s_wifi = nm_connection_get_setting_wireless (connection);
	g_assert (s_wifi);

	ssid = nm_setting_wireless_get_ssid (s_wifi);
	g_assert (ssid);
	g_assert (nm_utils_gbytes_equal_mem (ssid, expected_ssid, strlen (expected_ssid)));

	g_assert_cmpstr (nm_setting_wireless_get_mode (s_wifi), ==, NM_SETTING_WIRELESS_MODE_INFRA);

	s_wsec = nm_connection_get_setting_wireless_security (connection);
	g_assert (s_wsec);
	g_assert_cmpstr (nm_setting_wireless_security_get_key_mgmt (s_wsec), ==, "wpa-psk");
	g_assert_cmpstr (nm_setting_wireless_security_get_psk (s_wsec), ==, "s3cu4e passphrase");
}

static void
test_write_new_wireless_group_names (void)
{
	NMTST_UUID_INIT (uuid);
	gs_unref_object NMConnection *connection = NULL;
	gs_unref_keyfile GKeyFile *kf = NULL;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wifi;
	NMSettingWirelessSecurity *s_wsec;
	GBytes *ssid;
	unsigned char tmpssid[] = { 0x31, 0x33, 0x33, 0x37 };
	const char *expected_psk = "asdfasdfasdfa12315";
	gs_free char *testfile = NULL;
	gs_free_error GError *error = NULL;
	char *s;

	connection = nm_simple_connection_new ();

	/* Connection setting */

	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write New Wireless Group Names",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRELESS_SETTING_NAME,
	              NULL);

	/* Wi-Fi setting */
	s_wifi = (NMSettingWireless *) nm_setting_wireless_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wifi));

	ssid = g_bytes_new (tmpssid, sizeof (tmpssid));
	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_MODE, NM_SETTING_WIRELESS_MODE_INFRA,
	              NULL);
	g_bytes_unref (ssid);

	/* Wi-Fi security setting */
	s_wsec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wsec));
	g_object_set (s_wsec,
	              NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "wpa-psk",
	              NM_SETTING_WIRELESS_SECURITY_PSK, expected_psk,
	              NULL);

	write_test_connection (connection, &testfile);

	assert_reread (connection, TRUE, testfile);

	/* Look at the keyfile itself to ensure we wrote out the new group names and type */
	kf = keyfile_load_from_file (testfile);

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
}

static void
test_read_missing_vlan_setting (void)
{
	gs_unref_object NMConnection *connection = NULL;
	NMSettingVlan *s_vlan;

	connection = keyfile_read_connection_from_file (TEST_KEYFILES_DIR"/Test_Missing_Vlan_Setting");

	s_vlan = nm_connection_get_setting_vlan (connection);
	g_assert (s_vlan);
	g_assert_cmpint (nm_setting_vlan_get_id (s_vlan), ==, 0);
	g_assert_cmpint (nm_setting_vlan_get_flags (s_vlan), ==, NM_VLAN_FLAG_REORDER_HEADERS);
}

static void
test_read_missing_vlan_flags (void)
{
	gs_unref_object NMConnection *connection = NULL;
	NMSettingVlan *s_vlan;

	connection = keyfile_read_connection_from_file (TEST_KEYFILES_DIR"/Test_Missing_Vlan_Flags");

	s_vlan = nm_connection_get_setting_vlan (connection);
	g_assert (s_vlan);

	g_assert_cmpint (nm_setting_vlan_get_id (s_vlan), ==, 444);
	g_assert_cmpstr (nm_setting_vlan_get_parent (s_vlan), ==, "em1");
	g_assert_cmpint (nm_setting_vlan_get_flags (s_vlan), ==, NM_VLAN_FLAG_REORDER_HEADERS);
}

static void
test_read_missing_id_uuid (void)
{
	gs_unref_object NMConnection *connection = NULL;
	gs_free char *expected_uuid = NULL;
	const char *FILENAME = TEST_KEYFILES_DIR"/Test_Missing_ID_UUID";

	expected_uuid = _nm_utils_uuid_generate_from_strings ("keyfile", FILENAME, NULL);

	connection = keyfile_read_connection_from_file (FILENAME);

	g_assert_cmpstr (nm_connection_get_id (connection), ==, "Test_Missing_ID_UUID");
	g_assert_cmpstr (nm_connection_get_uuid (connection), ==, expected_uuid);
}

static void
test_read_minimal (void)
{
	gs_unref_object NMConnection *connection = NULL;
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
	gs_unref_object NMConnection *connection = NULL;
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
	gs_unref_object NMConnection *connection = NULL;
	NMSettingIPConfig *s_ip6;

	connection = keyfile_read_connection_from_file (TEST_KEYFILES_DIR"/Test_Enum_Property");

	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	g_assert (s_ip6);
	g_assert_cmpint (nm_setting_ip6_config_get_ip6_privacy (NM_SETTING_IP6_CONFIG (s_ip6)), ==, NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_TEMP_ADDR);
}

static void
test_write_enum_property (void)
{
	NMTST_UUID_INIT (uuid);
	gs_unref_object NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIPConfig *s_ip6;

	connection = nm_simple_connection_new ();

	/* Connection setting */

	s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write Enum Property",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
	              NULL);

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

	write_test_connection_and_reread (connection, FALSE);
}

static void
test_read_flags_property (void)
{
	gs_unref_object NMConnection *connection = NULL;
	NMSettingGsm *s_gsm;

	connection = keyfile_read_connection_from_file (TEST_KEYFILES_DIR"/Test_Flags_Property");

	s_gsm = nm_connection_get_setting_gsm (connection);
	g_assert (s_gsm);
	g_assert_cmpint (nm_setting_gsm_get_password_flags (s_gsm), ==,
	                   NM_SETTING_SECRET_FLAG_AGENT_OWNED | NM_SETTING_SECRET_FLAG_NOT_REQUIRED);
}

static void
test_write_flags_property (void)
{
	NMTST_UUID_INIT (uuid);
	gs_unref_object NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	NMSetting *s_gsm;

	connection = nm_simple_connection_new ();

	/* Connection setting */

	s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write Flags Property",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_GSM_SETTING_NAME,
	              NULL);

	/* GSM setting */
	s_gsm = nm_setting_gsm_new ();
	nm_connection_add_setting (connection, s_gsm);
	g_object_set (s_gsm,
	              NM_SETTING_GSM_APN, "myapn",
	              NM_SETTING_GSM_USERNAME, "adfasdfasdf",
	              NM_SETTING_GSM_PASSWORD_FLAGS, NM_SETTING_SECRET_FLAG_NOT_SAVED | NM_SETTING_SECRET_FLAG_NOT_REQUIRED,
	              NULL);

	nmtst_connection_normalize (connection);

	write_test_connection_and_reread (connection, FALSE);
}

/*****************************************************************************/

static void
test_read_tc_config (void)
{
	gs_unref_object NMConnection *connection = NULL;
	NMSettingTCConfig *s_tc;
	NMTCQdisc *qdisc1, *qdisc2;
	NMTCAction *action1, *action2;
	NMTCTfilter *tfilter1, *tfilter2;

	connection = keyfile_read_connection_from_file (TEST_KEYFILES_DIR "/Test_TC_Config");

	s_tc = nm_connection_get_setting_tc_config (connection);
	g_assert (s_tc);

	g_assert (nm_setting_tc_config_get_num_qdiscs (s_tc) == 2);

	qdisc1 = nm_setting_tc_config_get_qdisc (s_tc, 0);
	g_assert (qdisc1);
	g_assert (g_strcmp0 (nm_tc_qdisc_get_kind (qdisc1), "fq_codel") == 0);
	g_assert (nm_tc_qdisc_get_handle (qdisc1) == TC_H_MAKE (0x1234 << 16, 0x0000));
	g_assert (nm_tc_qdisc_get_parent (qdisc1) == TC_H_ROOT);

	qdisc2 = nm_setting_tc_config_get_qdisc (s_tc, 1);
	g_assert (qdisc2);
	g_assert (g_strcmp0 (nm_tc_qdisc_get_kind (qdisc2), "ingress") == 0);
	g_assert (nm_tc_qdisc_get_handle (qdisc2) == TC_H_MAKE (TC_H_INGRESS, 0));
	g_assert (nm_tc_qdisc_get_parent (qdisc2) == TC_H_INGRESS);

	g_assert (nm_setting_tc_config_get_num_tfilters (s_tc) == 2);

	tfilter1 = nm_setting_tc_config_get_tfilter (s_tc, 0);
	g_assert (tfilter1);
	g_assert (g_strcmp0 (nm_tc_tfilter_get_kind (tfilter1), "matchall") == 0);
	g_assert (nm_tc_tfilter_get_handle (tfilter1) == TC_H_UNSPEC);
	g_assert (nm_tc_tfilter_get_parent (tfilter1) == TC_H_MAKE (0x1234 << 16, 0x0000));

	action1 = nm_tc_tfilter_get_action (tfilter1);
	g_assert (action1);
	g_assert (g_strcmp0 (nm_tc_action_get_kind (action1), "drop") == 0);

	tfilter2 = nm_setting_tc_config_get_tfilter (s_tc, 1);
	g_assert (tfilter2);
	g_assert (g_strcmp0 (nm_tc_tfilter_get_kind (tfilter2), "matchall") == 0);
	g_assert (nm_tc_tfilter_get_handle (tfilter2) == TC_H_UNSPEC);
	g_assert (nm_tc_tfilter_get_parent (tfilter2) == TC_H_MAKE (TC_H_INGRESS, 0));

	action2 = nm_tc_tfilter_get_action (tfilter2);
	g_assert (action2);
	g_assert (g_strcmp0 (nm_tc_action_get_kind (action2), "simple") == 0);
	g_assert (g_strcmp0 (g_variant_get_bytestring (nm_tc_action_get_attribute (action2, "sdata")),
	                     "Hello") == 0);
}

static void
test_write_tc_config (void)
{
	gs_unref_object NMConnection *connection = NULL;
	NMSetting *s_tc;
	NMTCQdisc *qdisc1, *qdisc2;
	NMTCTfilter *tfilter1, *tfilter2;
	NMTCAction *action;
	GError *error = NULL;

	connection = nmtst_create_minimal_connection ("Test TC",
	                                               NULL,
	                                               NM_SETTING_WIRED_SETTING_NAME,
	                                               NULL);
	s_tc = nm_setting_tc_config_new ();

	qdisc1 = nm_tc_qdisc_new ("fq_codel", TC_H_ROOT, &error);
	nmtst_assert_success (qdisc1, error);
	nm_tc_qdisc_set_handle (qdisc1, TC_H_MAKE (0x1234 << 16, 0x0000));
	nm_setting_tc_config_add_qdisc (NM_SETTING_TC_CONFIG (s_tc), qdisc1);

	qdisc2 = nm_tc_qdisc_new ("ingress", TC_H_INGRESS, &error);
	nmtst_assert_success (qdisc2, error);
	nm_tc_qdisc_set_handle (qdisc2, TC_H_MAKE (TC_H_INGRESS, 0));
	nm_setting_tc_config_add_qdisc (NM_SETTING_TC_CONFIG (s_tc), qdisc2);

	tfilter1 = nm_tc_tfilter_new ("matchall",
	                              TC_H_MAKE (0x1234 << 16, 0x0000),
	                              &error);
	nmtst_assert_success (tfilter1, error);
	action = nm_tc_action_new ("drop", &error);
	nmtst_assert_success (action, error);
	nm_tc_tfilter_set_action (tfilter1, action);
	nm_tc_action_unref (action);
	nm_setting_tc_config_add_tfilter (NM_SETTING_TC_CONFIG (s_tc), tfilter1);
	nm_tc_tfilter_unref (tfilter1);

	tfilter2 = nm_tc_tfilter_new ("matchall",
	                              TC_H_MAKE (TC_H_INGRESS, 0),
	                              &error);
	nmtst_assert_success (tfilter2, error);
	action = nm_tc_action_new ("simple", &error);
	nmtst_assert_success (action, error);
	nm_tc_action_set_attribute (action, "sdata", g_variant_new_bytestring ("Hello"));
	nm_tc_tfilter_set_action (tfilter2, action);
	nm_tc_action_unref (action);
	nm_setting_tc_config_add_tfilter (NM_SETTING_TC_CONFIG (s_tc), tfilter2);
	nm_tc_tfilter_unref (tfilter2);

	nm_connection_add_setting (connection, s_tc);

	nmtst_connection_normalize (connection);
	write_test_connection_and_reread (connection, FALSE);

	nm_tc_qdisc_unref (qdisc1);
	nm_tc_qdisc_unref (qdisc2);
}

/*****************************************************************************/

static void
_escape_filename (gboolean with_extension, const char *filename, gboolean would_be_ignored)
{
	gs_free char *esc = NULL;

	g_assert (filename && filename[0]);

	if (!!would_be_ignored != !!nm_keyfile_utils_ignore_filename (filename, with_extension)) {
		if (would_be_ignored)
			g_error ("We expect filename \"%s\" to be ignored, but it isn't", filename);
		else
			g_error ("We expect filename \"%s\" not to be ignored, but it is", filename);
	}

	esc = nm_keyfile_utils_create_filename (filename, with_extension);
	g_assert (esc && esc[0]);
	g_assert (!strchr (esc, '/'));

	if (nm_keyfile_utils_ignore_filename (esc, with_extension))
		g_error ("Escaping filename \"%s\" yielded \"%s\", but this is ignored", filename, esc);
}

static void
test_nm_keyfile_plugin_utils_escape_filename (void)
{
	_escape_filename (FALSE, "ab", FALSE);
	_escape_filename (FALSE, ".vim-file.swp", TRUE);
	_escape_filename (FALSE, ".vim-file.Swp", TRUE);
	_escape_filename (FALSE, ".vim-file.SWP", TRUE);
	_escape_filename (FALSE, ".vim-file.swpx", TRUE);
	_escape_filename (FALSE, ".vim-file.Swpx", TRUE);
	_escape_filename (FALSE, ".vim-file.SWPX", TRUE);
	_escape_filename (FALSE, ".pem-file.pem", TRUE);
	_escape_filename (FALSE, ".pem-file.Pem", TRUE);
	_escape_filename (FALSE, ".pem-file.PEM", TRUE);
	_escape_filename (FALSE, ".pem-file.der", TRUE);
	_escape_filename (FALSE, ".pem-file.Der", TRUE);
	_escape_filename (FALSE, ".mkstemp.ABCEDF", TRUE);
	_escape_filename (FALSE, ".mkstemp.abcdef", TRUE);
	_escape_filename (FALSE, ".mkstemp.123456", TRUE);
	_escape_filename (FALSE, ".mkstemp.A23456", TRUE);
	_escape_filename (FALSE, ".#emacs-locking", TRUE);
	_escape_filename (FALSE, "file-with-tilde~", TRUE);
	_escape_filename (FALSE, ".file-with-dot", TRUE);
	_escape_filename (FALSE, "/some/path/with/trailing/slash/", TRUE);
	_escape_filename (FALSE, "/some/path/without/trailing/slash", FALSE);

	_escape_filename (TRUE, "lala", TRUE);
}

/*****************************************************************************/

static void
_assert_keyfile_nmmeta (const char *dirname,
                        const char *uuid,
                        const char *loaded_path,
                        gboolean allow_relative,
                        const char *exp_full_filename,
                        const char *exp_uuid,
                        const char *exp_symlink_target,
                        const char *exp_loaded_path)
{
	gs_free char *full_filename = NULL;
	gs_free char *symlink_target = NULL;
	gs_free char *uuid2 = NULL;
	gs_free char *loaded_path2 = NULL;
	gs_free char *dirname3 = NULL;
	gs_free char *filename3 = NULL;
	gs_free char *uuid3 = NULL;
	gs_free char *loaded_path3 = NULL;
	gboolean success;
	gs_free char *filename = NULL;

	g_assert (dirname && dirname[0] == '/');
	g_assert (exp_full_filename && exp_full_filename[0]);
	g_assert (!exp_loaded_path || exp_loaded_path[0] == '/');

	filename = g_path_get_basename (exp_full_filename);

	full_filename = nms_keyfile_nmmeta_filename (dirname, uuid, FALSE);
	g_assert_cmpstr (full_filename, ==, full_filename);
	nm_clear_g_free (&full_filename);


	g_assert_cmpint (nms_keyfile_nmmeta_write (dirname, uuid, loaded_path, allow_relative, NULL, &full_filename), ==, 0);
	g_assert_cmpstr (full_filename, ==, exp_full_filename);
	nm_clear_g_free (&full_filename);

	if (exp_symlink_target)
		g_assert (g_file_test (exp_full_filename, G_FILE_TEST_EXISTS | G_FILE_TEST_IS_SYMLINK));
	else
		g_assert (!g_file_test (exp_full_filename, G_FILE_TEST_EXISTS));
	symlink_target = g_file_read_link (exp_full_filename, NULL);
	g_assert_cmpstr (symlink_target, ==, exp_symlink_target);


	success = nms_keyfile_nmmeta_read (dirname, filename, &full_filename, &uuid2, &loaded_path2, NULL, NULL);
	g_assert_cmpint (!!exp_uuid, ==, success);
	if (success)
		g_assert_cmpstr (full_filename, ==, exp_full_filename);
	else
		g_assert_cmpstr (full_filename, ==, NULL);
	nm_clear_g_free (&full_filename);
	g_assert_cmpstr (uuid2, ==, exp_uuid);
	g_assert_cmpstr (loaded_path2, ==, exp_loaded_path);


	success = nms_keyfile_nmmeta_read_from_file (exp_full_filename, &dirname3, &filename3, &uuid3, &loaded_path3, NULL);
	g_assert_cmpint (!!exp_uuid, ==, success);
	if (success) {
		g_assert_cmpstr (dirname3, ==, dirname);
		g_assert_cmpstr (filename3, ==, filename);
	} else {
		g_assert_cmpstr (dirname3, ==, NULL);
		g_assert_cmpstr (filename3, ==, NULL);
	}
	g_assert_cmpstr (uuid3, ==, exp_uuid);
	g_assert_cmpstr (loaded_path3, ==, exp_loaded_path);
}

static void
test_nmmeta (void)
{
	const char *uuid = "3c03fd17-ddc3-4100-a954-88b6fafff959";
	gs_free char *filename = g_strdup_printf ("%s%s",
	                                          uuid,
	                                          NM_KEYFILE_PATH_SUFFIX_NMMETA);
	gs_free char *full_filename = g_strdup_printf ("%s/%s",
	                                               TEST_SCRATCH_DIR,
	                                               filename);
	const char *loaded_path0 = NM_KEYFILE_PATH_NMMETA_SYMLINK_NULL;
	const char *loaded_path1 = "/some/where/but/not/scratch/dir";
	const char *filename2 = "foo1";
	gs_free char *loaded_path2 = g_strdup_printf ("%s/%s",
	                                              TEST_SCRATCH_DIR,
	                                              filename2);

	_assert_keyfile_nmmeta (TEST_SCRATCH_DIR, uuid, NULL,         FALSE, full_filename, NULL, NULL,         NULL);
	_assert_keyfile_nmmeta (TEST_SCRATCH_DIR, uuid, NULL,         TRUE,  full_filename, NULL, NULL,         NULL);

	_assert_keyfile_nmmeta (TEST_SCRATCH_DIR, uuid, loaded_path0, FALSE, full_filename, uuid, loaded_path0, loaded_path0);
	_assert_keyfile_nmmeta (TEST_SCRATCH_DIR, uuid, loaded_path0, TRUE,  full_filename, uuid, loaded_path0, loaded_path0);

	_assert_keyfile_nmmeta (TEST_SCRATCH_DIR, uuid, loaded_path1, FALSE, full_filename, uuid, loaded_path1, loaded_path1);
	_assert_keyfile_nmmeta (TEST_SCRATCH_DIR, uuid, loaded_path1, TRUE,  full_filename, uuid, loaded_path1, loaded_path1);

	_assert_keyfile_nmmeta (TEST_SCRATCH_DIR, uuid, loaded_path2, FALSE, full_filename, uuid, loaded_path2, loaded_path2);
	_assert_keyfile_nmmeta (TEST_SCRATCH_DIR, uuid, loaded_path2, TRUE,  full_filename, uuid, filename2,    loaded_path2);

	(void) unlink (full_filename);
}

/*****************************************************************************/

NMTST_DEFINE ();

int main (int argc, char **argv)
{
	int errsv;

	_nm_utils_set_testing (NM_UTILS_TEST_NO_KEYFILE_OWNER_CHECK);

	nmtst_init_assert_logging (&argc, &argv, "INFO", "DEFAULT");

	if (g_mkdir_with_parents (TEST_SCRATCH_DIR, 0755) != 0) {
		errsv = errno;
		g_error ("failure to create test directory \"%s\": %s", TEST_SCRATCH_DIR, nm_strerror_native (errsv));
	}

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

	g_test_add_func ("/keyfile/test_read_dcb_connection", test_read_dcb_connection);

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

	g_test_add_func ("/keyfile/test_read_tc_config", test_read_tc_config);
	g_test_add_func ("/keyfile/test_write_tc_config", test_write_tc_config);

	g_test_add_func ("/keyfile/test_nm_keyfile_plugin_utils_escape_filename", test_nm_keyfile_plugin_utils_escape_filename);

	g_test_add_func ("/keyfile/test_nmmeta", test_nmmeta);

	return g_test_run ();
}
