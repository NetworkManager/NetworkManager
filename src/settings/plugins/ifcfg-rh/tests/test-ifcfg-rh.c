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
 * Copyright (C) 2008 - 2011 Red Hat, Inc.
 */

#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <netinet/ether.h>
#include <linux/if_infiniband.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <nm-utils.h>
#include <nm-setting-connection.h>
#include <nm-setting-wired.h>
#include <nm-setting-wireless.h>
#include <nm-setting-wireless-security.h>
#include <nm-setting-ip4-config.h>
#include <nm-setting-ip6-config.h>
#include <nm-setting-8021x.h>
#include <nm-setting-pppoe.h>
#include <nm-setting-ppp.h>
#include <nm-setting-vpn.h>
#include <nm-setting-gsm.h>
#include <nm-setting-cdma.h>
#include <nm-setting-serial.h>
#include <nm-setting-vlan.h>
#include <nm-setting-dcb.h>
#include <nm-utils-private.h>

#include "NetworkManagerUtils.h"

#include "common.h"
#include "reader.h"
#include "writer.h"
#include "utils.h"
#include "nm-logging.h"

#include "nm-test-utils.h"

#if 0
static void
connection_diff (NMConnection *a, NMConnection *b)
{
	GHashTable *hash;
	GHashTableIter iter, siter;
	const char *setting_name, *key;
	GHashTable *setting_hash = NULL;

	if (!nm_connection_diff (a, b, NM_SETTING_COMPARE_FLAG_EXACT, &hash)) {
		g_hash_table_iter_init (&iter, hash);
		while (g_hash_table_iter_next (&iter, (gpointer) &setting_name, (gpointer) &setting_hash)) {
			g_hash_table_iter_init (&siter, setting_hash);
			while (g_hash_table_iter_next (&siter, (gpointer) &key, NULL))
				g_message (":: %s :: %s", setting_name,key);
		}
		g_hash_table_destroy (hash);
	}
}
#endif

static gboolean
verify_cert_or_key (NMSetting8021x *s_compare,
                    const char *file,
                    const char *privkey_password,
                    const char *property)
{
	NMSetting8021x *s_8021x;
	GError *error = NULL;
	gboolean success = FALSE;
	const char *expected = NULL, *setting = NULL;
	gboolean phase2 = FALSE;
	NMSetting8021xCKScheme scheme = NM_SETTING_802_1X_CK_SCHEME_UNKNOWN;

	if (strstr (property, "phase2"))
		phase2 = TRUE;

	s_8021x = (NMSetting8021x *) nm_setting_802_1x_new ();

	/* Load the certificate into an empty setting */
	if (strstr (property, "ca-cert")) {
		if (phase2)
			success = nm_setting_802_1x_set_phase2_ca_cert (s_8021x, file, NM_SETTING_802_1X_CK_SCHEME_PATH, NULL, &error);
		else
			success = nm_setting_802_1x_set_ca_cert (s_8021x, file, NM_SETTING_802_1X_CK_SCHEME_PATH, NULL, &error);
	} else if (strstr (property, "client-cert")) {
		if (phase2)
			success = nm_setting_802_1x_set_phase2_client_cert (s_8021x, file, NM_SETTING_802_1X_CK_SCHEME_PATH, NULL, &error);
		else
			success = nm_setting_802_1x_set_client_cert (s_8021x, file, NM_SETTING_802_1X_CK_SCHEME_PATH, NULL, &error);
	} else if (strstr (property, "private-key")) {
		if (phase2)
			success = nm_setting_802_1x_set_phase2_private_key (s_8021x, file, privkey_password, NM_SETTING_802_1X_CK_SCHEME_PATH, NULL, &error);
		else
			success = nm_setting_802_1x_set_private_key (s_8021x, file, privkey_password, NM_SETTING_802_1X_CK_SCHEME_PATH, NULL, &error);
	}
	g_assert_no_error (error);
	g_assert_cmpint (success, ==, TRUE);

	/* Ensure it was loaded using the PATH scheme */
	if (strstr (property, "ca-cert")) {
		if (phase2)
			scheme = nm_setting_802_1x_get_phase2_ca_cert_scheme (s_8021x);
		else
			scheme = nm_setting_802_1x_get_ca_cert_scheme (s_8021x);
	} else if (strstr (property, "client-cert")) {
		if (phase2)
			scheme = nm_setting_802_1x_get_phase2_client_cert_scheme (s_8021x);
		else
			scheme = nm_setting_802_1x_get_client_cert_scheme (s_8021x);
	} else if (strstr (property, "private-key")) {
		if (phase2)
			scheme = nm_setting_802_1x_get_phase2_private_key_scheme (s_8021x);
		else
			scheme = nm_setting_802_1x_get_private_key_scheme (s_8021x);
	}
	g_assert_cmpint (scheme, ==, NM_SETTING_802_1X_CK_SCHEME_PATH);

	/* Grab the path back out */
	if (strstr (property, "ca-cert")) {
		if (phase2)
			expected = nm_setting_802_1x_get_phase2_ca_cert_path (s_8021x);
		else
			expected = nm_setting_802_1x_get_ca_cert_path (s_8021x);
	} else if (strstr (property, "client-cert")) {
		if (phase2)
			expected = nm_setting_802_1x_get_phase2_client_cert_path (s_8021x);
		else
			expected = nm_setting_802_1x_get_client_cert_path (s_8021x);
	} else if (strstr (property, "private-key")) {
		if (phase2)
			expected = nm_setting_802_1x_get_phase2_private_key_path (s_8021x);
		else
			expected = nm_setting_802_1x_get_private_key_path (s_8021x);
	}
	g_assert_cmpstr (expected, ==, file);

	/* Compare the path with the expected path from the real setting */
	if (strstr (property, "ca-cert")) {
		if (phase2)
			setting = nm_setting_802_1x_get_phase2_ca_cert_path (s_compare);
		else
			setting = nm_setting_802_1x_get_ca_cert_path (s_compare);
	} else if (strstr (property, "client-cert")) {
		if (phase2)
			setting = nm_setting_802_1x_get_phase2_client_cert_path (s_compare);
		else
			setting = nm_setting_802_1x_get_client_cert_path (s_compare);
	} else if (strstr (property, "private-key")) {
		if (phase2)
			setting = nm_setting_802_1x_get_phase2_private_key_path (s_compare);
		else
			setting = nm_setting_802_1x_get_private_key_path (s_compare);
	}
	g_assert_cmpstr (setting, ==, expected);

	g_object_unref (s_8021x);
	return TRUE;
}


static void
test_read_basic (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;
	GError *error = NULL;
	const GByteArray *array;
	char expected_mac_address[ETH_ALEN] = { 0x00, 0x16, 0x41, 0x11, 0x22, 0x33 };
	const char *expected_id = "System test-minimal";
	guint64 expected_timestamp = 0;
	gboolean success;

	connection = connection_from_file (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-minimal",
	                                   NULL, TYPE_ETHERNET, NULL, NULL, NULL, NULL, NULL, &error, NULL);
	g_assert_no_error (error);
	g_assert (connection);
	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	/* ===== CONNECTION SETTING ===== */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, expected_id);
	g_assert_cmpint (nm_setting_connection_get_timestamp (s_con), ==, expected_timestamp);
	g_assert (nm_setting_connection_get_autoconnect (s_con));

	/* UUID can't be tested if the ifcfg does not contain the UUID key, because
	 * the UUID is generated on the full path of the ifcfg file, which can change
	 * depending on where the tests are run.
	 */

	/* ===== WIRED SETTING ===== */
	s_wired = nm_connection_get_setting_wired (connection);
	g_assert (s_wired);
	g_assert_cmpint (nm_setting_wired_get_mtu (s_wired), ==, 0);

	/* MAC address */
	array = nm_setting_wired_get_mac_address (s_wired);
	g_assert (array);
	g_assert_cmpint (array->len, ==, ETH_ALEN);
	g_assert (memcmp (array->data, &expected_mac_address[0], ETH_ALEN) == 0);

	/* ===== IPv4 SETTING ===== */
	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip4_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_DISABLED);
	g_assert (nm_setting_ip4_config_get_never_default (s_ip4) == FALSE);

	/* ===== IPv6 SETTING ===== */
	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	g_assert (s_ip6);
	g_assert_cmpstr (nm_setting_ip6_config_get_method (s_ip6), ==, NM_SETTING_IP6_CONFIG_METHOD_IGNORE);
	g_assert (nm_setting_ip6_config_get_never_default (s_ip6) == FALSE);

	g_object_unref (connection);
}

static void
test_read_variables_corner_cases (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIP4Config *s_ip4;
	GError *error = NULL;
	const GByteArray *array;
	char expected_mac_address[ETH_ALEN] = { 0x00, 0x16, 0x41, 0x11, 0x22, 0x33 };
	const char *expected_zone = "'";
	const char *expected_id = "\"";
	guint64 expected_timestamp = 0;
	gboolean success;

	connection = connection_from_file (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-variables-corner-cases-1",
	                                   NULL, TYPE_ETHERNET, NULL, NULL, NULL, NULL, NULL, &error, NULL);
	g_assert_no_error (error);
	g_assert (connection);
	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	/* ===== CONNECTION SETTING ===== */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, expected_id);
	g_assert_cmpstr (nm_setting_connection_get_zone (s_con), ==, expected_zone);
	g_assert_cmpint (nm_setting_connection_get_timestamp (s_con), ==, expected_timestamp);
	g_assert (nm_setting_connection_get_autoconnect (s_con));

	/* ===== WIRED SETTING ===== */
	s_wired = nm_connection_get_setting_wired (connection);
	g_assert (s_wired);
	g_assert_cmpint (nm_setting_wired_get_mtu (s_wired), ==, 0);

	/* MAC address */
	array = nm_setting_wired_get_mac_address (s_wired);
	g_assert (array);
	g_assert_cmpint (array->len, ==, ETH_ALEN);
	g_assert (memcmp (array->data, &expected_mac_address[0], ETH_ALEN) == 0);

	/* ===== IPv4 SETTING ===== */
	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip4_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_DISABLED);
	g_assert (nm_setting_ip4_config_get_never_default (s_ip4) == FALSE);

	g_object_unref (connection);
}

static void
test_read_unmanaged (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	char *unhandled_spec = NULL;
	GError *error = NULL;
	const char *expected_id = "System test-nm-controlled";
	guint64 expected_timestamp = 0;
	gboolean success;

	connection = connection_from_file (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-nm-controlled",
	                                   NULL, TYPE_ETHERNET, NULL,
	                                   &unhandled_spec,
	                                   NULL, NULL, NULL, &error, NULL);
	g_assert_no_error (error);
	g_assert (connection);
	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);
	g_assert_cmpstr (unhandled_spec, ==, "unmanaged:mac:00:11:22:33:f8:9f");

	/* ===== CONNECTION SETTING ===== */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, expected_id);
	g_assert_cmpint (nm_setting_connection_get_timestamp (s_con), ==, expected_timestamp);
	g_assert (nm_setting_connection_get_autoconnect (s_con));

	g_free (unhandled_spec);
	g_object_unref (connection);
}

static void
test_read_unmanaged_unrecognized (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	char *unhandled_spec = NULL;
	GError *error = NULL;
	const char *expected_id = "PigeonNet";
	guint64 expected_timestamp = 0;
	gboolean success;

	connection = connection_from_file (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-nm-controlled-unrecognized",
	                                   NULL, NULL, NULL,
	                                   &unhandled_spec,
	                                   NULL, NULL, NULL, &error, NULL);
	g_assert_no_error (error);
	g_assert (connection);
	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);
	g_assert_cmpstr (unhandled_spec, ==, "unmanaged:interface-name:ipoac0");

	/* ===== CONNECTION SETTING ===== */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, expected_id);
	g_assert_cmpint (nm_setting_connection_get_timestamp (s_con), ==, expected_timestamp);

	g_object_unref (connection);
}

static void
test_read_unrecognized (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	char *unhandled_spec = NULL;
	GError *error = NULL;
	const char *expected_id = "U Can't Touch This";
	guint64 expected_timestamp = 0;
	gboolean success;

	connection = connection_from_file (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-unrecognized",
	                                   NULL, NULL, NULL,
	                                   &unhandled_spec,
	                                   NULL, NULL, NULL, &error, NULL);
	g_assert_no_error (error);
	g_assert (connection);
	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);
	g_assert_cmpstr (unhandled_spec, ==, "unrecognized:mac:00:11:22:33");

	/* ===== CONNECTION SETTING ===== */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, expected_id);
	g_assert_cmpint (nm_setting_connection_get_timestamp (s_con), ==, expected_timestamp);

	g_object_unref (connection);
}

static void
test_read_wired_static (const char *file,
                        const char *expected_id,
                        gboolean expect_ip6)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;
	char *unmanaged = NULL;
	GError *error = NULL;
	const GByteArray *array;
	char expected_mac_address[ETH_ALEN] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0xee };
	const char *expected_dns1 = "4.2.2.1";
	const char *expected_dns2 = "4.2.2.2";
	guint32 addr;
	struct in6_addr addr6;
	const char *expected_address1 = "192.168.1.5";
	const char *expected_address1_gw = "192.168.1.1";
	const char *expected6_address1 = "dead:beaf::1";
	const char *expected6_address2 = "dead:beaf::2";
	const char *expected6_dns1 = "1:2:3:4::a";
	const char *expected6_dns2 = "1:2:3:4::b";
	NMIP4Address *ip4_addr;
	NMIP6Address *ip6_addr;
	gboolean success;

	connection = connection_from_file (file, NULL, TYPE_ETHERNET, NULL,
	                                   &unmanaged, NULL, NULL, NULL, &error, NULL);
	g_assert_no_error (error);
	g_assert (connection);
	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);
	g_assert_cmpstr (unmanaged, ==, NULL);

	/* ===== CONNECTION SETTING ===== */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, expected_id);
	g_assert_cmpint (nm_setting_connection_get_timestamp (s_con), ==, 0);
	g_assert (nm_setting_connection_get_autoconnect (s_con));

	/* ===== WIRED SETTING ===== */
	s_wired = nm_connection_get_setting_wired (connection);
	g_assert (s_wired);
	g_assert_cmpint (nm_setting_wired_get_mtu (s_wired), ==, 1492);

	/* MAC address */
	array = nm_setting_wired_get_mac_address (s_wired);
	g_assert (array);
	g_assert_cmpint (array->len, ==, ETH_ALEN);
	g_assert (memcmp (array->data, &expected_mac_address[0], ETH_ALEN) == 0);

	/* ===== IPv4 SETTING ===== */
	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip4_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_MANUAL);
	g_assert (nm_setting_ip4_config_get_may_fail (s_ip4));

	/* DNS Addresses */
	g_assert_cmpint (nm_setting_ip4_config_get_num_dns (s_ip4), ==, 2);
	g_assert_cmpint (inet_pton (AF_INET, expected_dns1, &addr), >, 0);
	g_assert_cmpint (nm_setting_ip4_config_get_dns (s_ip4, 0), ==, addr);
	g_assert_cmpint (inet_pton (AF_INET, expected_dns2, &addr), >, 0);
	g_assert_cmpint (nm_setting_ip4_config_get_dns (s_ip4, 1), ==, addr);

	/* IP addresses */
	g_assert_cmpint (nm_setting_ip4_config_get_num_addresses (s_ip4), ==, 1);
	ip4_addr = nm_setting_ip4_config_get_address (s_ip4, 0);
	g_assert (ip4_addr);
	g_assert_cmpint (nm_ip4_address_get_prefix (ip4_addr), ==, 24);
	g_assert_cmpint (inet_pton (AF_INET, expected_address1, &addr), >, 0);
	g_assert_cmpint (nm_ip4_address_get_address (ip4_addr), ==, addr);
	g_assert_cmpint (inet_pton (AF_INET, expected_address1_gw, &addr), >, 0);
	g_assert_cmpint (nm_ip4_address_get_gateway (ip4_addr), ==, addr);

	/* ===== IPv6 SETTING ===== */
	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	g_assert (s_ip6);
	if (expect_ip6) {
		g_assert_cmpstr (nm_setting_ip6_config_get_method (s_ip6), ==, NM_SETTING_IP6_CONFIG_METHOD_MANUAL);
		g_assert (nm_setting_ip6_config_get_may_fail (s_ip6));

		/* DNS Addresses */
		g_assert_cmpint (nm_setting_ip6_config_get_num_dns (s_ip6), ==, 2);
		g_assert_cmpint (inet_pton (AF_INET6, expected6_dns1, &addr6), >, 0);
		g_assert (IN6_ARE_ADDR_EQUAL (nm_setting_ip6_config_get_dns (s_ip6, 0), &addr6));
		g_assert_cmpint (inet_pton (AF_INET6, expected6_dns2, &addr6), >, 0);
		g_assert (IN6_ARE_ADDR_EQUAL (nm_setting_ip6_config_get_dns (s_ip6, 1), &addr6));

		/* IP addresses */
		g_assert_cmpint (nm_setting_ip6_config_get_num_addresses (s_ip6), ==, 2);

		ip6_addr = nm_setting_ip6_config_get_address (s_ip6, 0);
		g_assert (ip6_addr);
		g_assert_cmpint (nm_ip6_address_get_prefix (ip6_addr), ==, 64);
		g_assert_cmpint (inet_pton (AF_INET6, expected6_address1, &addr6), >, 0);
		g_assert (IN6_ARE_ADDR_EQUAL (nm_ip6_address_get_address (ip6_addr), &addr6));

		ip6_addr = nm_setting_ip6_config_get_address (s_ip6, 1);
		g_assert (ip6_addr);
		g_assert_cmpint (nm_ip6_address_get_prefix (ip6_addr), ==, 56);
		g_assert_cmpint (inet_pton (AF_INET6, expected6_address2, &addr6), >, 0);
		g_assert (IN6_ARE_ADDR_EQUAL (nm_ip6_address_get_address (ip6_addr), &addr6));
	} else {
		g_assert_cmpstr (nm_setting_ip6_config_get_method (s_ip6), ==, NM_SETTING_IP6_CONFIG_METHOD_IGNORE);
	}

	g_free (unmanaged);
	g_object_unref (connection);
}

static void
test_read_wired_static_no_prefix (gconstpointer user_data)
{
	guint32 expected_prefix = GPOINTER_TO_UINT (user_data);
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingIP4Config *s_ip4;
	GError *error = NULL;
	NMIP4Address *ip4_addr;
	char *file, *expected_id;

	file = g_strdup_printf (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-wired-static-no-prefix-%u", expected_prefix);
	expected_id = g_strdup_printf ("System test-wired-static-no-prefix-%u", expected_prefix);

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_WARNING,
	                       "*missing PREFIX, assuming*");
	connection = connection_from_file (file, NULL, TYPE_ETHERNET, NULL, NULL,
	                                   NULL, NULL, NULL, &error, NULL);
	g_test_assert_expected_messages ();
	g_assert_no_error (error);
	g_assert (connection);
	g_assert (nm_connection_verify (connection, &error));

	/* ===== CONNECTION SETTING ===== */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, expected_id);

	/* ===== IPv4 SETTING ===== */
	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip4_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_MANUAL);

	g_assert_cmpint (nm_setting_ip4_config_get_num_addresses (s_ip4), ==, 1);
	ip4_addr = nm_setting_ip4_config_get_address (s_ip4, 0);
	g_assert (ip4_addr);
	g_assert_cmpint (nm_ip4_address_get_prefix (ip4_addr), ==, expected_prefix);

	g_free (file);
	g_free (expected_id);
	g_object_unref (connection);
}

#define TEST_IFCFG_WIRED_DHCP TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-dhcp"

static void
test_read_wired_dhcp (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIP4Config *s_ip4;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	const GByteArray *array;
	char expected_mac_address[ETH_ALEN] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0xee };
	const char *tmp;
	const char *expected_id = "System test-wired-dhcp";
	const char *expected_dns1 = "4.2.2.1";
	const char *expected_dns2 = "4.2.2.2";
	guint32 addr;
	const char *expected_dhcp_hostname = "foobar";

	connection = connection_from_file (TEST_IFCFG_WIRED_DHCP,
	                                   NULL,
	                                   TYPE_ETHERNET,
	                                   NULL,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &routefile,
	                                   &route6file,
	                                   &error,
	                                   &ignore_error);
	ASSERT (connection != NULL,
	        "wired-dhcp-read", "failed to read %s: %s", TEST_IFCFG_WIRED_DHCP, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "wired-dhcp-verify", "failed to verify %s: %s", TEST_IFCFG_WIRED_DHCP, error->message);

	ASSERT (unmanaged == NULL,
	        "wired-dhcp-verify", "failed to verify %s: unexpected unmanaged value", TEST_IFCFG_WIRED_DHCP);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
	        "wired-dhcp-verify-connection", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIRED_DHCP,
	        NM_SETTING_CONNECTION_SETTING_NAME);

	/* ID */
	tmp = nm_setting_connection_get_id (s_con);
	ASSERT (tmp != NULL,
	        "wired-dhcp-verify-connection", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIRED_DHCP,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);
	ASSERT (strcmp (tmp, expected_id) == 0,
	        "wired-dhcp-verify-connection", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_DHCP,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);

	/* Timestamp */
	ASSERT (nm_setting_connection_get_timestamp (s_con) == 0,
	        "wired-dhcp-verify-connection", "failed to verify %s: unexpected %s /%s key value",
	        TEST_IFCFG_WIRED_DHCP,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_TIMESTAMP);

	/* Autoconnect */
	ASSERT (nm_setting_connection_get_autoconnect (s_con) == TRUE,
	        "wired-dhcp-verify-connection", "failed to verify %s: unexpected %s /%s key value",
	        TEST_IFCFG_WIRED_DHCP,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_AUTOCONNECT);

	/* ===== WIRED SETTING ===== */

	s_wired = nm_connection_get_setting_wired (connection);
	ASSERT (s_wired != NULL,
	        "wired-dhcp-verify-wired", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIRED_DHCP,
	        NM_SETTING_WIRED_SETTING_NAME);

	/* MAC address */
	array = nm_setting_wired_get_mac_address (s_wired);
	ASSERT (array != NULL,
	        "wired-dhcp-verify-wired", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIRED_DHCP,
	        NM_SETTING_WIRED_SETTING_NAME,
	        NM_SETTING_WIRED_MAC_ADDRESS);
	ASSERT (array->len == ETH_ALEN,
	        "wired-dhcp-verify-wired", "failed to verify %s: unexpected %s / %s key value length",
	        TEST_IFCFG_WIRED_DHCP,
	        NM_SETTING_WIRED_SETTING_NAME,
	        NM_SETTING_WIRED_MAC_ADDRESS);
	ASSERT (memcmp (array->data, &expected_mac_address[0], sizeof (expected_mac_address)) == 0,
	        "wired-dhcp-verify-wired", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_DHCP,
	        NM_SETTING_WIRED_SETTING_NAME,
	        NM_SETTING_WIRED_MAC_ADDRESS);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	ASSERT (s_ip4 != NULL,
	        "wired-dhcp-verify-ip4", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIRED_DHCP,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME);

	/* Method */
	tmp = nm_setting_ip4_config_get_method (s_ip4);
	ASSERT (strcmp (tmp, NM_SETTING_IP4_CONFIG_METHOD_AUTO) == 0,
	        "wired-dhcp-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_DHCP,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_METHOD);

	tmp = nm_setting_ip4_config_get_dhcp_hostname (s_ip4);
	ASSERT (tmp != NULL,
	        "wired-dhcp-verify-ip4", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIRED_DHCP,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DHCP_HOSTNAME);
	ASSERT (strcmp (tmp, expected_dhcp_hostname) == 0,
	        "wired-dhcp-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_DHCP,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DHCP_HOSTNAME);

	ASSERT (nm_setting_ip4_config_get_ignore_auto_dns (s_ip4) == TRUE,
	        "wired-dhcp-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_DHCP,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_IGNORE_AUTO_DNS);

	/* DNS Addresses */
	ASSERT (nm_setting_ip4_config_get_num_dns (s_ip4) == 2,
	        "wired-dhcp-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_DHCP,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS);

	ASSERT (inet_pton (AF_INET, expected_dns1, &addr) > 0,
	        "wired-dhcp-verify-ip4", "failed to verify %s: couldn't convert DNS IP address #1",
	        TEST_IFCFG_WIRED_DHCP,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS);
	ASSERT (nm_setting_ip4_config_get_dns (s_ip4, 0) == addr,
	        "wired-dhcp-verify-ip4", "failed to verify %s: unexpected %s / %s key value #1",
	        TEST_IFCFG_WIRED_DHCP,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS);

	ASSERT (inet_pton (AF_INET, expected_dns2, &addr) > 0,
	        "wired-dhcp-verify-ip4", "failed to verify %s: couldn't convert DNS IP address #2",
	        TEST_IFCFG_WIRED_DHCP,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS);
	ASSERT (nm_setting_ip4_config_get_dns (s_ip4, 1) == addr,
	        "wired-dhcp-verify-ip4", "failed to verify %s: unexpected %s / %s key value #2",
	        TEST_IFCFG_WIRED_DHCP,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS);

	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
}

static void
test_read_wired_dhcp_plus_ip (void)
{
	NMConnection *connection;
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;
	GError *error = NULL;
	guint32 addr4;
	struct in6_addr addr6;
	NMIP4Address *ip4_addr;
	NMIP6Address *ip6_addr;
	gboolean success;

	connection = connection_from_file (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-dhcp-plus-ip",
	                                   NULL, TYPE_ETHERNET, NULL, NULL,
	                                   NULL, NULL, NULL, &error, NULL);
	g_assert_no_error (error);
	g_assert (connection);
	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	/* ===== IPv4 SETTING ===== */
	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip4_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_AUTO);
	g_assert (nm_setting_ip4_config_get_may_fail (s_ip4));

	/* DNS Addresses */
	g_assert_cmpint (nm_setting_ip4_config_get_num_dns (s_ip4), ==, 2);
	g_assert_cmpint (inet_pton (AF_INET, "4.2.2.1", &addr4), >, 0);
	g_assert_cmpint (nm_setting_ip4_config_get_dns (s_ip4, 0), ==, addr4);
	g_assert_cmpint (inet_pton (AF_INET, "4.2.2.2", &addr4), >, 0);
	g_assert_cmpint (nm_setting_ip4_config_get_dns (s_ip4, 1), ==, addr4);

	/* IP addresses */
	g_assert_cmpint (nm_setting_ip4_config_get_num_addresses (s_ip4), ==, 2);
	ip4_addr = nm_setting_ip4_config_get_address (s_ip4, 0);
	g_assert (ip4_addr);
	g_assert_cmpint (nm_ip4_address_get_prefix (ip4_addr), ==, 24);
	g_assert_cmpint (inet_pton (AF_INET, "1.2.3.4", &addr4), >, 0);
	g_assert_cmpint (nm_ip4_address_get_address (ip4_addr), ==, addr4);
	g_assert_cmpint (inet_pton (AF_INET, "1.1.1.1", &addr4), >, 0);
	g_assert_cmpint (nm_ip4_address_get_gateway (ip4_addr), ==, addr4);

	ip4_addr = nm_setting_ip4_config_get_address (s_ip4, 1);
	g_assert (ip4_addr);
	g_assert_cmpint (nm_ip4_address_get_prefix (ip4_addr), ==, 16);
	g_assert_cmpint (inet_pton (AF_INET, "9.8.7.6", &addr4), >, 0);
	g_assert_cmpint (nm_ip4_address_get_address (ip4_addr), ==, addr4);

	/* ===== IPv6 SETTING ===== */
	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	g_assert (s_ip6);
	g_assert_cmpstr (nm_setting_ip6_config_get_method (s_ip6), ==, NM_SETTING_IP6_CONFIG_METHOD_AUTO);
	g_assert (nm_setting_ip6_config_get_may_fail (s_ip6));

	/* DNS Addresses */
	g_assert_cmpint (nm_setting_ip6_config_get_num_dns (s_ip6), ==, 2);
	g_assert_cmpint (inet_pton (AF_INET6, "1:2:3:4::a", &addr6), >, 0);
	g_assert (IN6_ARE_ADDR_EQUAL (nm_setting_ip6_config_get_dns (s_ip6, 0), &addr6));
	g_assert_cmpint (inet_pton (AF_INET6, "1:2:3:4::b", &addr6), >, 0);
	g_assert (IN6_ARE_ADDR_EQUAL (nm_setting_ip6_config_get_dns (s_ip6, 1), &addr6));

	/* IP addresses */
	g_assert_cmpint (nm_setting_ip6_config_get_num_addresses (s_ip6), ==, 3);
	ip6_addr = nm_setting_ip6_config_get_address (s_ip6, 0);
	g_assert (ip6_addr);
	g_assert_cmpint (nm_ip6_address_get_prefix (ip6_addr), ==, 56);
	g_assert_cmpint (inet_pton (AF_INET6, "1001:abba::1234", &addr6), >, 0);
	g_assert (IN6_ARE_ADDR_EQUAL (nm_ip6_address_get_address (ip6_addr), &addr6));

	ip6_addr = nm_setting_ip6_config_get_address (s_ip6, 1);
	g_assert (ip6_addr);
	g_assert_cmpint (nm_ip6_address_get_prefix (ip6_addr), ==, 64);
	g_assert_cmpint (inet_pton (AF_INET6, "2001:abba::2234", &addr6), >, 0);
	g_assert (IN6_ARE_ADDR_EQUAL (nm_ip6_address_get_address (ip6_addr), &addr6));

	ip6_addr = nm_setting_ip6_config_get_address (s_ip6, 2);
	g_assert (ip6_addr);
	g_assert_cmpint (nm_ip6_address_get_prefix (ip6_addr), ==, 96);
	g_assert_cmpint (inet_pton (AF_INET6, "3001:abba::3234", &addr6), >, 0);
	g_assert (IN6_ARE_ADDR_EQUAL (nm_ip6_address_get_address (ip6_addr), &addr6));

	g_object_unref (connection);
}

#define TEST_IFCFG_WIRED_GLOBAL_GATEWAY TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-global-gateway"
#define TEST_NETWORK_WIRED_GLOBAL_GATEWAY TEST_IFCFG_DIR"/network-scripts/network-test-wired-global-gateway"

static void
test_read_wired_global_gateway (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIP4Config *s_ip4;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	const char *tmp;
	const char *expected_id = "System test-wired-global-gateway";
	guint32 addr;
	const char *expected_address1 = "192.168.1.5";
	const char *expected_address1_gw = "192.168.1.2";
	NMIP4Address *ip4_addr;

	connection = connection_from_file (TEST_IFCFG_WIRED_GLOBAL_GATEWAY,
	                                   TEST_NETWORK_WIRED_GLOBAL_GATEWAY,
	                                   TYPE_ETHERNET,
	                                   NULL,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &routefile,
	                                   &route6file,
	                                   &error,
	                                   &ignore_error);
	ASSERT (connection != NULL,
	        "wired-global-gateway-read", "failed to read %s: %s", TEST_IFCFG_WIRED_GLOBAL_GATEWAY, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "wired-global-gateway-verify", "failed to verify %s: %s", TEST_IFCFG_WIRED_GLOBAL_GATEWAY, error->message);

	ASSERT (unmanaged == NULL,
	        "wired-global-gateway-verify", "failed to verify %s: unexpected unmanaged value", TEST_IFCFG_WIRED_GLOBAL_GATEWAY);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
	        "wired-global-gateway-verify-connection", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIRED_GLOBAL_GATEWAY,
	        NM_SETTING_CONNECTION_SETTING_NAME);

	/* ID */
	tmp = nm_setting_connection_get_id (s_con);
	ASSERT (tmp != NULL,
	        "wired-global-gateway-verify-connection", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIRED_GLOBAL_GATEWAY,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);
	ASSERT (strcmp (tmp, expected_id) == 0,
	        "wired-global-gateway-verify-connection", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_GLOBAL_GATEWAY,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);

	/* ===== WIRED SETTING ===== */

	s_wired = nm_connection_get_setting_wired (connection);
	ASSERT (s_wired != NULL,
	        "wired-global-gateway-verify-wired", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIRED_GLOBAL_GATEWAY,
	        NM_SETTING_WIRED_SETTING_NAME);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	ASSERT (s_ip4 != NULL,
	        "wired-global-gateway-verify-ip4", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIRED_GLOBAL_GATEWAY,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME);

	/* Method */
	tmp = nm_setting_ip4_config_get_method (s_ip4);
	ASSERT (strcmp (tmp, NM_SETTING_IP4_CONFIG_METHOD_MANUAL) == 0,
	        "wired-global-gateway-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_GLOBAL_GATEWAY,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_METHOD);

	/* Address #1 */
	ip4_addr = nm_setting_ip4_config_get_address (s_ip4, 0);
	ASSERT (ip4_addr,
	        "wired-global-gateway-verify-ip4", "failed to verify %s: missing IP4 address #1",
	        TEST_IFCFG_WIRED_GLOBAL_GATEWAY,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_ADDRESSES);

	ASSERT (nm_ip4_address_get_prefix (ip4_addr) == 24,
	        "wired-global-gateway-verify-ip4", "failed to verify %s: unexpected IP4 address #1 prefix",
	        TEST_IFCFG_WIRED_GLOBAL_GATEWAY,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_ADDRESSES);

	ASSERT (inet_pton (AF_INET, expected_address1, &addr) > 0,
	        "wired-global-gateway-verify-ip4", "failed to verify %s: couldn't convert IP address #1",
	        TEST_IFCFG_WIRED_GLOBAL_GATEWAY,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS);
	ASSERT (nm_ip4_address_get_address (ip4_addr) == addr,
	        "wired-global-gateway-verify-ip4", "failed to verify %s: unexpected IP4 address #1",
	        TEST_IFCFG_WIRED_GLOBAL_GATEWAY,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_ADDRESSES);

	ASSERT (inet_pton (AF_INET, expected_address1_gw, &addr) > 0,
	        "wired-global-gateway-verify-ip4", "failed to verify %s: couldn't convert IP address #1 gateway",
	        TEST_IFCFG_WIRED_GLOBAL_GATEWAY,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_ADDRESSES);
	ASSERT (nm_ip4_address_get_gateway (ip4_addr) == addr,
	        "wired-global-gateway-verify-ip4", "failed to verify %s: unexpected IP4 address #1 gateway",
	        TEST_IFCFG_WIRED_GLOBAL_GATEWAY,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_ADDRESSES);

	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
}

#define TEST_IFCFG_WIRED_NEVER_DEFAULT TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-never-default"
#define TEST_NETWORK_WIRED_NEVER_DEFAULT TEST_IFCFG_DIR"/network-scripts/network-test-wired-never-default"

static void
test_read_wired_never_default (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	const char *tmp;
	const char *expected_id = "System test-wired-never-default";

	connection = connection_from_file (TEST_IFCFG_WIRED_NEVER_DEFAULT,
	                                   TEST_NETWORK_WIRED_NEVER_DEFAULT,
	                                   TYPE_ETHERNET,
	                                   NULL,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &routefile,
	                                   &route6file,
	                                   &error,
	                                   &ignore_error);
	ASSERT (connection != NULL,
	        "wired-never-default-read", "failed to read %s: %s", TEST_IFCFG_WIRED_NEVER_DEFAULT, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "wired-never-default-verify", "failed to verify %s: %s", TEST_IFCFG_WIRED_NEVER_DEFAULT, error->message);

	ASSERT (unmanaged == NULL,
	        "wired-never-default-verify", "failed to verify %s: unexpected unmanaged value", TEST_IFCFG_WIRED_NEVER_DEFAULT);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
	        "wired-never-default-verify-connection", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIRED_NEVER_DEFAULT,
	        NM_SETTING_CONNECTION_SETTING_NAME);

	/* ID */
	tmp = nm_setting_connection_get_id (s_con);
	ASSERT (tmp != NULL,
	        "wired-never-default-verify-connection", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIRED_NEVER_DEFAULT,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);
	ASSERT (strcmp (tmp, expected_id) == 0,
	        "wired-never-default-verify-connection", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_NEVER_DEFAULT,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);

	/* ===== WIRED SETTING ===== */

	s_wired = nm_connection_get_setting_wired (connection);
	ASSERT (s_wired != NULL,
	        "wired-never-default-verify-wired", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIRED_NEVER_DEFAULT,
	        NM_SETTING_WIRED_SETTING_NAME);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	ASSERT (s_ip4 != NULL,
	        "wired-never-default-verify-ip4", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIRED_NEVER_DEFAULT,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME);

	/* Method */
	tmp = nm_setting_ip4_config_get_method (s_ip4);
	ASSERT (strcmp (tmp, NM_SETTING_IP4_CONFIG_METHOD_AUTO) == 0,
	        "wired-never-default-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_NEVER_DEFAULT,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_METHOD);

	ASSERT (nm_setting_ip4_config_get_never_default (s_ip4) == TRUE,
	        "wired-never-default-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_NEVER_DEFAULT,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_NEVER_DEFAULT);

	/* DNS Addresses */
	ASSERT (nm_setting_ip4_config_get_num_dns (s_ip4) == 0,
	        "wired-never-default-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_NEVER_DEFAULT,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS);

	/* ===== IPv6 SETTING ===== */

	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	ASSERT (s_ip6 != NULL,
	        "wired-never-default-verify-ip6", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIRED_NEVER_DEFAULT,
	        NM_SETTING_IP6_CONFIG_SETTING_NAME);

	/* Method */
	tmp = nm_setting_ip6_config_get_method (s_ip6);
	ASSERT (strcmp (tmp, NM_SETTING_IP6_CONFIG_METHOD_AUTO) == 0,
	        "wired-never-default-verify-ip6", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_NEVER_DEFAULT,
	        NM_SETTING_IP6_CONFIG_SETTING_NAME,
	        NM_SETTING_IP6_CONFIG_METHOD);

	ASSERT (nm_setting_ip6_config_get_never_default (s_ip6) == TRUE,
	        "wired-never-default-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_NEVER_DEFAULT,
	        NM_SETTING_IP6_CONFIG_SETTING_NAME,
	        NM_SETTING_IP6_CONFIG_NEVER_DEFAULT);

	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
}

#define TEST_IFCFG_WIRED_DEFROUTE_NO TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-defroute-no"

static void
test_read_wired_defroute_no (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	const char *tmp;
	const char *expected_id = "System test-wired-defroute-no";

	connection = connection_from_file (TEST_IFCFG_WIRED_DEFROUTE_NO,
	                                   NULL,
	                                   TYPE_ETHERNET,
	                                   NULL,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &routefile,
	                                   &route6file,
	                                   &error,
	                                   &ignore_error);
	ASSERT (connection != NULL,
	        "wired-defroute-no-read", "failed to read %s: %s", TEST_IFCFG_WIRED_DEFROUTE_NO, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "wired-defroute-no-verify", "failed to verify %s: %s", TEST_IFCFG_WIRED_DEFROUTE_NO, error->message);

	ASSERT (unmanaged == NULL,
	        "wired-defroute-no-verify", "failed to verify %s: unexpected unmanaged value", TEST_IFCFG_WIRED_DEFROUTE_NO);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
	        "wired-defroute-no-verify-connection", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIRED_DEFROUTE_NO,
	        NM_SETTING_CONNECTION_SETTING_NAME);

	/* ID */
	tmp = nm_setting_connection_get_id (s_con);
	ASSERT (tmp != NULL,
	        "wired-defroute-no-verify-connection", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIRED_DEFROUTE_NO,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);
	ASSERT (strcmp (tmp, expected_id) == 0,
	        "wired-defroute-no-verify-connection", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_DEFROUTE_NO,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);

	/* ===== WIRED SETTING ===== */

	s_wired = nm_connection_get_setting_wired (connection);
	ASSERT (s_wired != NULL,
	        "wired-defroute-no-verify-wired", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIRED_DEFROUTE_NO,
	        NM_SETTING_WIRED_SETTING_NAME);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	ASSERT (s_ip4 != NULL,
	        "wired-defroute-no-verify-ip4", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIRED_DEFROUTE_NO,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME);

	/* Method */
	tmp = nm_setting_ip4_config_get_method (s_ip4);
	ASSERT (strcmp (tmp, NM_SETTING_IP4_CONFIG_METHOD_AUTO) == 0,
	        "wired-defroute-no-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_DEFROUTE_NO,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_METHOD);

	ASSERT (nm_setting_ip4_config_get_never_default (s_ip4) == TRUE,
	        "wired-defroute-no-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_DEFROUTE_NO,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_NEVER_DEFAULT);

	/* ===== IPv6 SETTING ===== */

	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	ASSERT (s_ip6 != NULL,
	        "wired-defroute-no-verify-ip6", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIRED_DEFROUTE_NO,
	        NM_SETTING_IP6_CONFIG_SETTING_NAME);

	/* Method */
	tmp = nm_setting_ip6_config_get_method (s_ip6);
	ASSERT (strcmp (tmp, NM_SETTING_IP6_CONFIG_METHOD_AUTO) == 0,
	        "wired-defroute-no-verify-ip6", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_DEFROUTE_NO,
	        NM_SETTING_IP6_CONFIG_SETTING_NAME,
	        NM_SETTING_IP6_CONFIG_METHOD);

	ASSERT (nm_setting_ip6_config_get_never_default (s_ip6) == TRUE,
	        "wired-defroute-no-verify-ip6", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_DEFROUTE_NO,
	        NM_SETTING_IP6_CONFIG_SETTING_NAME,
	        NM_SETTING_IP6_CONFIG_NEVER_DEFAULT);

	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
}

#define TEST_IFCFG_WIRED_DEFROUTE_NO_GATEWAYDEV_YES TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-defroute-no-gatewaydev-yes"
#define TEST_NETWORK_WIRED_DEFROUTE_NO_GATEWAYDEV_YES TEST_IFCFG_DIR"/network-scripts/network-test-wired-defroute-no-gatewaydev-yes"

static void
test_read_wired_defroute_no_gatewaydev_yes (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	const char *tmp;
	const char *expected_id = "System test-wired-defroute-no-gatewaydev-yes";

	connection = connection_from_file (TEST_IFCFG_WIRED_DEFROUTE_NO_GATEWAYDEV_YES,
	                                   TEST_NETWORK_WIRED_DEFROUTE_NO_GATEWAYDEV_YES,
	                                   TYPE_ETHERNET,
	                                   NULL,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &routefile,
	                                   &route6file,
	                                   &error,
	                                   &ignore_error);
	ASSERT (connection != NULL,
	        "wired-defroute-no-gatewaydev-yes-read",
	        "failed to read %s: %s",
	        TEST_IFCFG_WIRED_DEFROUTE_NO_GATEWAYDEV_YES,
	        error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "wired-defroute-no-gatewaydev-yes-verify",
	        "failed to verify %s: %s",
	        TEST_IFCFG_WIRED_DEFROUTE_NO_GATEWAYDEV_YES,
	        error->message);

	ASSERT (unmanaged == NULL,
	        "wired-defroute-no-gatewaydev-yes-verify",
	        "failed to verify %s: unexpected unmanaged value",
	        TEST_IFCFG_WIRED_DEFROUTE_NO_GATEWAYDEV_YES);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
	        "wired-defroute-no-gatewaydev-yes-verify-connection", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIRED_DEFROUTE_NO_GATEWAYDEV_YES,
	        NM_SETTING_CONNECTION_SETTING_NAME);

	/* ID */
	tmp = nm_setting_connection_get_id (s_con);
	ASSERT (tmp != NULL,
	        "wired-defroute-no-gatewaydev-yes-verify-connection", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIRED_DEFROUTE_NO_GATEWAYDEV_YES,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);
	ASSERT (strcmp (tmp, expected_id) == 0,
	        "wired-defroute-no-gatewaydev-yes-verify-connection", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_DEFROUTE_NO_GATEWAYDEV_YES,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);

	/* ===== WIRED SETTING ===== */

	s_wired = nm_connection_get_setting_wired (connection);
	ASSERT (s_wired != NULL,
	        "wired-defroute-no-gatewaydev-yes-verify-wired", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIRED_DEFROUTE_NO_GATEWAYDEV_YES,
	        NM_SETTING_WIRED_SETTING_NAME);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	ASSERT (s_ip4 != NULL,
	        "wired-defroute-no-gatewaydev-yes-verify-ip4", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIRED_DEFROUTE_NO_GATEWAYDEV_YES,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME);

	/* Method */
	tmp = nm_setting_ip4_config_get_method (s_ip4);
	ASSERT (strcmp (tmp, NM_SETTING_IP4_CONFIG_METHOD_AUTO) == 0,
	        "wired-defroute-no-gatewaydev-yes-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_DEFROUTE_NO_GATEWAYDEV_YES,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_METHOD);

	ASSERT (nm_setting_ip4_config_get_never_default (s_ip4) == FALSE,
	        "wired-defroute-no-gatewaydev-yes-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_DEFROUTE_NO_GATEWAYDEV_YES,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_NEVER_DEFAULT);

	/* ===== IPv6 SETTING ===== */

	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	ASSERT (s_ip6 != NULL,
	        "wired-defroute-no-gatewaydev-yes-verify-ip6", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIRED_DEFROUTE_NO_GATEWAYDEV_YES,
	        NM_SETTING_IP6_CONFIG_SETTING_NAME);

	/* Method */
	tmp = nm_setting_ip6_config_get_method (s_ip6);
	ASSERT (strcmp (tmp, NM_SETTING_IP4_CONFIG_METHOD_AUTO) == 0,
	        "wired-defroute-no-gatewaydev-yes-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_DEFROUTE_NO_GATEWAYDEV_YES,
	        NM_SETTING_IP6_CONFIG_SETTING_NAME,
	        NM_SETTING_IP6_CONFIG_METHOD);

	ASSERT (nm_setting_ip6_config_get_never_default (s_ip6) == FALSE,
	        "wired-defroute-no-gatewaydev-yes-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_DEFROUTE_NO_GATEWAYDEV_YES,
	        NM_SETTING_IP6_CONFIG_SETTING_NAME,
	        NM_SETTING_IP6_CONFIG_NEVER_DEFAULT);

	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
}

#define TEST_IFCFG_WIRED_STATIC_ROUTES TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-static-routes"

static void
test_read_wired_static_routes (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIP4Config *s_ip4;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	const char *tmp;
	NMIP4Route *ip4_route;
	guint32 addr;
	const char *expected_id = "System test-wired-static-routes";
	const char *expected_dst1 = "11.22.33.0";
	const char *expected_dst2 = "44.55.66.77";
	const char *expected_gw1 = "192.168.1.5";
	const char *expected_gw2 = "192.168.1.7";

	connection = connection_from_file (TEST_IFCFG_WIRED_STATIC_ROUTES,
	                                   NULL,
	                                   TYPE_ETHERNET,
	                                   NULL,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &routefile,
	                                   &route6file,
	                                   &error,
	                                   &ignore_error);

	ASSERT (connection != NULL,
	        "wired-static-routes-read",
	        "failed to read %s: %s",
	        TEST_IFCFG_WIRED_STATIC_ROUTES, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "wired-static-routes-verify", "failed to verify %s: %s",
	        TEST_IFCFG_WIRED_STATIC_ROUTES, error->message);

	ASSERT (unmanaged == NULL,
	        "wired-static-routes-verify",
	        "failed to verify %s: unexpected unmanaged value",
	        TEST_IFCFG_WIRED_STATIC_ROUTES);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
	        "wired-static-routes-verify-connection", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIRED_STATIC_ROUTES,
	        NM_SETTING_CONNECTION_SETTING_NAME);

	/* ID */
	tmp = nm_setting_connection_get_id (s_con);
	ASSERT (tmp != NULL,
	        "wired-static-routes-verify-connection", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIRED_STATIC_ROUTES,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);
	ASSERT (strcmp (tmp, expected_id) == 0,
	        "wired-static-routes-verify-connection", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_STATIC_ROUTES,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);

	/* ===== WIRED SETTING ===== */

	s_wired = nm_connection_get_setting_wired (connection);
	ASSERT (s_wired != NULL,
	        "wired-static-routes-verify-wired", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIRED_STATIC_ROUTES,
	        NM_SETTING_WIRED_SETTING_NAME);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	ASSERT (s_ip4 != NULL,
	        "wired-static-routes-verify-ip4", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIRED_STATIC_ROUTES,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME);

	/* Method */
	tmp = nm_setting_ip4_config_get_method (s_ip4);
	ASSERT (strcmp (tmp, NM_SETTING_IP4_CONFIG_METHOD_MANUAL) == 0,
	        "wired-static-routes-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_STATIC_ROUTES,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_METHOD);

	/* Routes */
	ASSERT (nm_setting_ip4_config_get_num_routes (s_ip4) == 2,
	        "wired-static-routes-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_STATIC_ROUTES,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_ROUTES);

	ip4_route = nm_setting_ip4_config_get_route (s_ip4, 0);
	ASSERT (ip4_route,
	        "wired-static-routes-verify-ip4", "failed to verify %s: missing IP4 route #1",
	        TEST_IFCFG_WIRED_STATIC_ROUTES);

	ASSERT (inet_pton (AF_INET, expected_dst1, &addr) > 0,
	        "wired-static-routes-verify-ip4", "failed to verify %s: couldn't convert destination IP address #1",
	        TEST_IFCFG_WIRED_STATIC_ROUTES);
	ASSERT (nm_ip4_route_get_dest (ip4_route) == addr,
	        "wired-static-routes-verify-ip4", "failed to verify %s: unexpected %s / %s key value #1",
	        TEST_IFCFG_WIRED_STATIC_ROUTES,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_ROUTES);

	ASSERT (nm_ip4_route_get_prefix (ip4_route) == 24,
	        "wired-static-routes-verify-ip4", "failed to verify %s: unexpected destination route #1 prefix",
	        TEST_IFCFG_WIRED_STATIC_ROUTES);

	ASSERT (inet_pton (AF_INET, expected_gw1, &addr) > 0,
	        "wired-static-routes-verify-ip4", "failed to verify %s: couldn't convert next hop IP address #1",
	        TEST_IFCFG_WIRED_STATIC_ROUTES);
	ASSERT (nm_ip4_route_get_next_hop (ip4_route) == addr,
	        "wired-static-routes-verify-ip4", "failed to verify %s: unexpected %s / %s key value #1",
	        TEST_IFCFG_WIRED_STATIC_ROUTES,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_ROUTES);

	ip4_route = nm_setting_ip4_config_get_route (s_ip4, 1);
	ASSERT (ip4_route,
	        "wired-static-routes-verify-ip4", "failed to verify %s: missing IP4 route #2",
	        TEST_IFCFG_WIRED_STATIC_ROUTES);

	ASSERT (inet_pton (AF_INET, expected_dst2, &addr) > 0,
	        "wired-static-routes-verify-ip4", "failed to verify %s: couldn't convert destination IP address #2",
	        TEST_IFCFG_WIRED_STATIC_ROUTES);
	ASSERT (nm_ip4_route_get_dest (ip4_route) == addr,
	        "wired-static-routes-verify-ip4", "failed to verify %s: unexpected %s / %s key value #2",
	        TEST_IFCFG_WIRED_STATIC_ROUTES,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_ROUTES);

	ASSERT (nm_ip4_route_get_prefix (ip4_route) == 32,
	        "wired-static-routes-verify-ip4", "failed to verify %s: unexpected destination route #2 prefix",
	        TEST_IFCFG_WIRED_STATIC_ROUTES);

	ASSERT (inet_pton (AF_INET, expected_gw2, &addr) > 0,
	        "wired-static-routes-verify-ip4", "failed to verify %s: couldn't convert next hop IP address #2",
	        TEST_IFCFG_WIRED_STATIC_ROUTES);
	ASSERT (nm_ip4_route_get_next_hop (ip4_route) == addr,
	        "wired-static-routes-verify-ip4", "failed to verify %s: unexpected %s / %s key value #2",
	        TEST_IFCFG_WIRED_STATIC_ROUTES,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_ROUTES);
	ASSERT (nm_ip4_route_get_metric (ip4_route) == 3,
	        "wired-static-routes-verify-ip4", "failed to verify %s: unexpected route metric #2",
	        TEST_IFCFG_WIRED_STATIC_ROUTES);

	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
}

#define TEST_IFCFG_WIRED_STATIC_ROUTES_LEGACY TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-static-routes-legacy"

static void
test_read_wired_static_routes_legacy (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIP4Config *s_ip4;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	const char *tmp;
	NMIP4Route *ip4_route;
	guint32 addr;
	const char *expected_id = "System test-wired-static-routes-legacy";
	const char *expected_dst1 = "21.31.41.0";
	const char *expected_dst2 = "32.42.52.62";
	const char *expected_dst3 = "43.53.0.0";
	const char *expected_gw1 = "9.9.9.9";
	const char *expected_gw2 = "8.8.8.8";
	const char *expected_gw3 = "7.7.7.7";

	connection = connection_from_file (TEST_IFCFG_WIRED_STATIC_ROUTES_LEGACY,
	                                   NULL,
	                                   TYPE_ETHERNET,
	                                   NULL,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &routefile,
	                                   &route6file,
	                                   &error,
	                                   &ignore_error);

	ASSERT (connection != NULL,
	        "wired-static-routes-legacy-read",
	        "failed to read %s: %s",
	        TEST_IFCFG_WIRED_STATIC_ROUTES_LEGACY, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "wired-static-routes-legacy-verify", "failed to verify %s: %s",
	        TEST_IFCFG_WIRED_STATIC_ROUTES_LEGACY, error->message);

	ASSERT (unmanaged == NULL,
	        "wired-static-routes-legacy-verify",
	        "failed to verify %s: unexpected unmanaged value",
	        TEST_IFCFG_WIRED_STATIC_ROUTES_LEGACY);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
	        "wired-static-routes-legacy-verify-connection", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIRED_STATIC_ROUTES_LEGACY,
	        NM_SETTING_CONNECTION_SETTING_NAME);

	/* ID */
	tmp = nm_setting_connection_get_id (s_con);
	ASSERT (tmp != NULL,
	        "wired-static-routes-legacy-verify-connection", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIRED_STATIC_ROUTES_LEGACY,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);
	ASSERT (strcmp (tmp, expected_id) == 0,
	        "wired-static-routes-legacy-verify-connection", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_STATIC_ROUTES_LEGACY,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);

	/* ===== WIRED SETTING ===== */

	s_wired = nm_connection_get_setting_wired (connection);
	ASSERT (s_wired != NULL,
	        "wired-static-routes-legacy-verify-wired", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIRED_STATIC_ROUTES_LEGACY,
	        NM_SETTING_WIRED_SETTING_NAME);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	ASSERT (s_ip4 != NULL,
	        "wired-static-routes-legacy-verify-ip4", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIRED_STATIC_ROUTES_LEGACY,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME);

	/* Method */
	tmp = nm_setting_ip4_config_get_method (s_ip4);
	ASSERT (strcmp (tmp, NM_SETTING_IP4_CONFIG_METHOD_MANUAL) == 0,
	        "wired-static-routes-legacy-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_STATIC_ROUTES_LEGACY,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_METHOD);

	/* Routes */
	ASSERT (nm_setting_ip4_config_get_num_routes (s_ip4) == 3,
	        "wired-static-routes-legacy-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_STATIC_ROUTES_LEGACY,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_ROUTES);

	/* Route #1 */
	ip4_route = nm_setting_ip4_config_get_route (s_ip4, 0);
	ASSERT (ip4_route,
	        "wired-static-routes-legacy-verify-ip4", "failed to verify %s: missing IP4 route #1",
	        TEST_IFCFG_WIRED_STATIC_ROUTES_LEGACY);

	ASSERT (inet_pton (AF_INET, expected_dst1, &addr) > 0,
	        "wired-static-routes-legacy-verify-ip4", "failed to verify %s: couldn't convert destination IP address #1",
	        TEST_IFCFG_WIRED_STATIC_ROUTES_LEGACY);
	ASSERT (nm_ip4_route_get_dest (ip4_route) == addr,
	        "wired-static-routes-legacy-verify-ip4", "failed to verify %s: unexpected %s / %s key value #1",
	        TEST_IFCFG_WIRED_STATIC_ROUTES_LEGACY,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_ROUTES);

	ASSERT (nm_ip4_route_get_prefix (ip4_route) == 24,
	        "wired-static-routes-legacy-verify-ip4", "failed to verify %s: unexpected destination route #1 prefix",
	        TEST_IFCFG_WIRED_STATIC_ROUTES_LEGACY);

	ASSERT (inet_pton (AF_INET, expected_gw1, &addr) > 0,
	        "wired-static-routes-legacy-verify-ip4", "failed to verify %s: couldn't convert next hop IP address #1",
	        TEST_IFCFG_WIRED_STATIC_ROUTES_LEGACY);
	ASSERT (nm_ip4_route_get_next_hop (ip4_route) == addr,
	        "wired-static-routes-legacy-verify-ip4", "failed to verify %s: unexpected %s / %s key value #1",
	        TEST_IFCFG_WIRED_STATIC_ROUTES_LEGACY,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_ROUTES);

	ASSERT (nm_ip4_route_get_metric (ip4_route) == 1,
	        "wired-static-routes-legacy-verify-ip4", "failed to verify %s: unexpected destination route #1 metric",
	        TEST_IFCFG_WIRED_STATIC_ROUTES_LEGACY);

	/* Route #2 */
	ip4_route = nm_setting_ip4_config_get_route (s_ip4, 1);
	ASSERT (ip4_route,
	        "wired-static-routes-legacy-verify-ip4", "failed to verify %s: missing IP4 route #2",
	        TEST_IFCFG_WIRED_STATIC_ROUTES_LEGACY);

	ASSERT (inet_pton (AF_INET, expected_dst2, &addr) > 0,
	        "wired-static-routes-legacy-verify-ip4", "failed to verify %s: couldn't convert destination IP address #2",
	        TEST_IFCFG_WIRED_STATIC_ROUTES_LEGACY);
	ASSERT (nm_ip4_route_get_dest (ip4_route) == addr,
	        "wired-static-routes-legacy-verify-ip4", "failed to verify %s: unexpected %s / %s key value #2",
	        TEST_IFCFG_WIRED_STATIC_ROUTES_LEGACY,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_ROUTES);

	ASSERT (nm_ip4_route_get_prefix (ip4_route) == 32,
	        "wired-static-routes-legacy-verify-ip4", "failed to verify %s: unexpected destination route #2 prefix",
	        TEST_IFCFG_WIRED_STATIC_ROUTES_LEGACY);

	ASSERT (inet_pton (AF_INET, expected_gw2, &addr) > 0,
	        "wired-static-routes-legacy-verify-ip4", "failed to verify %s: couldn't convert next hop IP address #2",
	        TEST_IFCFG_WIRED_STATIC_ROUTES_LEGACY);
	ASSERT (nm_ip4_route_get_next_hop (ip4_route) == addr,
	        "wired-static-routes-legacy-verify-ip4", "failed to verify %s: unexpected %s / %s key value #2",
	        TEST_IFCFG_WIRED_STATIC_ROUTES_LEGACY,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_ROUTES);

	ASSERT (nm_ip4_route_get_metric (ip4_route) == 0,
	        "wired-static-routes-legacy-verify-ip4", "failed to verify %s: unexpected destination route #2 metric",
	        TEST_IFCFG_WIRED_STATIC_ROUTES_LEGACY);

	/* Route #3 */
	ip4_route = nm_setting_ip4_config_get_route (s_ip4, 2);
	ASSERT (ip4_route,
	        "wired-static-routes-legacy-verify-ip4", "failed to verify %s: missing IP4 route #3",
	        TEST_IFCFG_WIRED_STATIC_ROUTES_LEGACY);

	ASSERT (inet_pton (AF_INET, expected_dst3, &addr) > 0,
	        "wired-static-routes-legacy-verify-ip4", "failed to verify %s: couldn't convert destination IP address #3",
	        TEST_IFCFG_WIRED_STATIC_ROUTES_LEGACY);
	ASSERT (nm_ip4_route_get_dest (ip4_route) == addr,
	        "wired-static-routes-legacy-verify-ip4", "failed to verify %s: unexpected %s / %s key value #3",
	        TEST_IFCFG_WIRED_STATIC_ROUTES_LEGACY,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_ROUTES);

	ASSERT (nm_ip4_route_get_prefix (ip4_route) == 16,
	        "wired-static-routes-legacy-verify-ip4", "failed to verify %s: unexpected destination route #3 prefix",
	        TEST_IFCFG_WIRED_STATIC_ROUTES_LEGACY);

	ASSERT (inet_pton (AF_INET, expected_gw3, &addr) > 0,
	        "wired-static-routes-legacy-verify-ip4", "failed to verify %s: couldn't convert next hop IP address #3",
	        TEST_IFCFG_WIRED_STATIC_ROUTES_LEGACY);
	ASSERT (nm_ip4_route_get_next_hop (ip4_route) == addr,
	        "wired-static-routes-legacy-verify-ip4", "failed to verify %s: unexpected %s / %s key value #3",
	        TEST_IFCFG_WIRED_STATIC_ROUTES_LEGACY,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_ROUTES);

	ASSERT (nm_ip4_route_get_metric (ip4_route) == 3,
	        "wired-static-routes-legacy-verify-ip4", "failed to verify %s: unexpected destination route #3 metric",
	        TEST_IFCFG_WIRED_STATIC_ROUTES_LEGACY);

	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
}

static void
test_read_wired_ipv4_manual (const char *file, const char *expected_id)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIP4Config *s_ip4;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	const char *tmp;
	const char *expected_address1 = "1.2.3.4";
	const char *expected_address2 = "9.8.7.6";
	const char *expected_address3 = "3.3.3.3";
	guint32 expected_prefix1 = 24;
	guint32 expected_prefix2 = 16;
	guint32 expected_prefix3 = 8;
	NMIP4Address *ip4_addr;
	guint32 addr;

	connection = connection_from_file (file,
	                                   NULL,
	                                   TYPE_ETHERNET,
	                                   NULL,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &routefile,
	                                   &route6file,
	                                   &error,
	                                   &ignore_error);
	ASSERT (connection != NULL,
	        "wired-ipv4-manual-read", "failed to read %s: %s", file, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "wired-ipv4-manual-verify", "failed to verify %s: %s", file, error->message);

	ASSERT (unmanaged == NULL,
	        "wired-ipv4-manual-verify", "failed to verify %s: unexpected unmanaged value", file);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
	        "wired-ipv4-manual-verify-connection", "failed to verify %s: missing %s setting",
	        file,
	        NM_SETTING_CONNECTION_SETTING_NAME);

	/* ID */
	tmp = nm_setting_connection_get_id (s_con);
	ASSERT (tmp != NULL,
	        "wired-ipv4-manual-verify-connection", "failed to verify %s: missing %s / %s key",
	        file,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);
	ASSERT (strcmp (tmp, expected_id) == 0,
	        "wired-ipv4-manual-verify-connection", "failed to verify %s: unexpected %s / %s key value",
	        file,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);

	/* ===== WIRED SETTING ===== */

	s_wired = nm_connection_get_setting_wired (connection);
	ASSERT (s_wired != NULL,
	        "wired-ipv4-manual-verify-wired", "failed to verify %s: missing %s setting",
	        file,
	        NM_SETTING_WIRED_SETTING_NAME);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	ASSERT (s_ip4 != NULL,
	        "wired-ipv4-manual-verify-ip4", "failed to verify %s: missing %s setting",
	        file,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME);

	/* Method */
	tmp = nm_setting_ip4_config_get_method (s_ip4);
	ASSERT (strcmp (tmp, NM_SETTING_IP4_CONFIG_METHOD_MANUAL) == 0,
	        "wired-ipv4-manual-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        file,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_METHOD);

	/* IP addresses */
	ASSERT (nm_setting_ip4_config_get_num_addresses (s_ip4) == 3,
		"wired-ipv4-manual-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
		file,
		NM_SETTING_IP4_CONFIG_SETTING_NAME,
		NM_SETTING_IP4_CONFIG_ADDRESSES);

	/* Address #1 */
	ip4_addr = nm_setting_ip4_config_get_address (s_ip4, 0);
	ASSERT (ip4_addr,
		"wired-ipv4-manual-verify-ip4", "failed to verify %s: missing IP4 address #1",
		file);

	ASSERT (nm_ip4_address_get_prefix (ip4_addr) == expected_prefix1,
		"wired-ipv4-manual-verify-ip4", "failed to verify %s: unexpected IP4 address #1 prefix",
		file);

	ASSERT (inet_pton (AF_INET, expected_address1, &addr) > 0,
		"wired-ipv4-manual-verify-ip4", "failed to verify %s: couldn't convert IP address #1",
		file);
	ASSERT (nm_ip4_address_get_address (ip4_addr) == addr,
		"wired-ipv4-manual-verify-ip4", "failed to verify %s: unexpected IP4 address #1",
		file);

	/* Address #2 */
	ip4_addr = nm_setting_ip4_config_get_address (s_ip4, 1);
	ASSERT (ip4_addr,
		"wired-ipv4-manual-verify-ip4", "failed to verify %s: missing IP4 address #2",
		file);

	ASSERT (nm_ip4_address_get_prefix (ip4_addr) == expected_prefix2,
		"wired-ipv4-manual-verify-ip4", "failed to verify %s: unexpected IP4 address #2 prefix",
		file);

	ASSERT (inet_pton (AF_INET, expected_address2, &addr) > 0,
		"wired-ipv4-manual-verify-ip4", "failed to verify %s: couldn't convert IP address #2",
		file);
	ASSERT (nm_ip4_address_get_address (ip4_addr) == addr,
		"wired-ipv4-manual-verify-ip4", "failed to verify %s: unexpected IP4 address #2",
		file);

	/* Address #3 */
	ip4_addr = nm_setting_ip4_config_get_address (s_ip4, 2);
	ASSERT (ip4_addr,
		"wired-ipv4-manual-verify-ip4", "failed to verify %s: missing IP4 address #3",
		file);

	ASSERT (nm_ip4_address_get_prefix (ip4_addr) == expected_prefix3,
		"wired-ipv4-manual-verify-ip4", "failed to verify %s: unexpected IP4 address #3 prefix",
		file);

	ASSERT (inet_pton (AF_INET, expected_address3, &addr) > 0,
		"wired-ipv4-manual-verify-ip4", "failed to verify %s: couldn't convert IP address #3",
		file);
	ASSERT (nm_ip4_address_get_address (ip4_addr) == addr,
		"wired-ipv4-manual-verify-ip4", "failed to verify %s: unexpected IP4 address #3",
		file);

	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
}

#define TEST_IFCFG_WIRED_IPV6_MANUAL TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-ipv6-manual"

static void
test_read_wired_ipv6_manual (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	const char *tmp;
	const char *expected_id = "System test-wired-ipv6-manual";
	const char *expected_address1 = "1001:abba::1234";
	const char *expected_address2 = "2001:abba::2234";
	const char *expected_address3 = "3001:abba::3234";
	guint32 expected_prefix1 = 56;
	guint32 expected_prefix2 = 64;
	guint32 expected_prefix3 = 96;
	const char *expected_dns1 = "1:2:3:4::a";
	const char *expected_dns2 = "1:2:3:4::b";
	NMIP6Address *ip6_addr;
	NMIP6Route *ip6_route;
	struct in6_addr addr;

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_WARNING,
	                       "*ignoring manual default route*");
	connection = connection_from_file (TEST_IFCFG_WIRED_IPV6_MANUAL,
	                                   NULL,
	                                   TYPE_ETHERNET,
	                                   NULL,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &routefile,
	                                   &route6file,
	                                   &error,
	                                   &ignore_error);
	g_test_assert_expected_messages ();

	ASSERT (connection != NULL,
	        "wired-ipv6-manual-read", "failed to read %s: %s", TEST_IFCFG_WIRED_IPV6_MANUAL, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "wired-ipv6-manual-verify", "failed to verify %s: %s", TEST_IFCFG_WIRED_IPV6_MANUAL, error->message);

	ASSERT (unmanaged == NULL,
	        "wired-ipv6-manual-verify", "failed to verify %s: unexpected unmanaged value", TEST_IFCFG_WIRED_IPV6_MANUAL);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
	        "wired-ipv6-manual-verify-connection", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIRED_IPV6_MANUAL,
	        NM_SETTING_CONNECTION_SETTING_NAME);

	/* ID */
	tmp = nm_setting_connection_get_id (s_con);
	ASSERT (tmp != NULL,
	        "wired-ipv6-manual-verify-connection", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIRED_IPV6_MANUAL,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);
	ASSERT (strcmp (tmp, expected_id) == 0,
	        "wired-ipv6-manual-verify-connection", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_IPV6_MANUAL,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);

	/* ===== WIRED SETTING ===== */

	s_wired = nm_connection_get_setting_wired (connection);
	ASSERT (s_wired != NULL,
	        "wired-ipv6-manual-verify-wired", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIRED_IPV6_MANUAL,
	        NM_SETTING_WIRED_SETTING_NAME);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	ASSERT (s_ip4 != NULL,
	        "wired-ipv6-manual-verify-ip4", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIRED_IPV6_MANUAL,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME);

	/* DNS Addresses */
	ASSERT (nm_setting_ip4_config_get_num_dns (s_ip4) == 2,
	        "wired-ipv6-manual-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_IPV6_MANUAL,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS);

	/* DNS search domains */
	ASSERT (nm_setting_ip4_config_get_num_dns_searches (s_ip4) == 3,
	        "wired-ipv6-manual-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_IPV6_MANUAL,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS);

	tmp = nm_setting_ip4_config_get_dns_search (s_ip4, 0);
	ASSERT (tmp != NULL,
	        "wired-ipv6-manual-verify-ip4", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIRED_IPV6_MANUAL,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS_SEARCH);
	ASSERT (strcmp (tmp, "lorem.com") == 0,
	        "wired-ipv6-manual-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_IPV6_MANUAL,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS_SEARCH);

	tmp = nm_setting_ip4_config_get_dns_search (s_ip4, 1);
	ASSERT (tmp != NULL,
	        "wired-ipv6-manual-verify-ip4", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIRED_IPV6_MANUAL,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS_SEARCH);
	ASSERT (strcmp (tmp, "ipsum.org") == 0,
	        "wired-ipv6-manual-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_IPV6_MANUAL,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS_SEARCH);

	tmp = nm_setting_ip4_config_get_dns_search (s_ip4, 2);
	ASSERT (tmp != NULL,
	        "wired-ipv6-manual-verify-ip4", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIRED_IPV6_MANUAL,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS_SEARCH);
	ASSERT (strcmp (tmp, "dolor.edu") == 0,
	        "wired-ipv6-manual-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_IPV6_MANUAL,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS_SEARCH);

	/* ===== IPv6 SETTING ===== */

	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	ASSERT (s_ip6 != NULL,
	        "wired-ipv6-manual-verify-ip6", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIRED_IPV6_MANUAL,
	        NM_SETTING_IP6_CONFIG_SETTING_NAME);

	/* Method */
	tmp = nm_setting_ip6_config_get_method (s_ip6);
	ASSERT (strcmp (tmp, NM_SETTING_IP6_CONFIG_METHOD_MANUAL) == 0,
	        "wired-ipv6-manual-verify-ip6", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_IPV6_MANUAL,
	        NM_SETTING_IP6_CONFIG_SETTING_NAME,
	        NM_SETTING_IP6_CONFIG_METHOD);

	ASSERT (nm_setting_ip6_config_get_never_default (s_ip6) == FALSE,
	        "wired-ipv6-manual-verify-ip6", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_IPV6_MANUAL,
	        NM_SETTING_IP6_CONFIG_SETTING_NAME,
	        NM_SETTING_IP6_CONFIG_NEVER_DEFAULT);

	ASSERT (nm_setting_ip6_config_get_may_fail (s_ip6) == TRUE,
	        "wired-ipv6-manual-verify-ip6", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_IPV6_MANUAL,
	        NM_SETTING_IP6_CONFIG_SETTING_NAME,
	        NM_SETTING_IP6_CONFIG_MAY_FAIL);

	/* IP addresses */
	ASSERT (nm_setting_ip6_config_get_num_addresses (s_ip6) == 3,
		"wired-ipv6-manual-verify-ip6", "failed to verify %s: unexpected %s / %s key value",
		TEST_IFCFG_WIRED_IPV6_MANUAL,
		NM_SETTING_IP6_CONFIG_SETTING_NAME,
		NM_SETTING_IP6_CONFIG_ADDRESSES);

	/* Address #1 */
	ip6_addr = nm_setting_ip6_config_get_address (s_ip6, 0);
	ASSERT (ip6_addr,
		"wired-ipv6-manual-verify-ip6", "failed to verify %s: missing IP6 address #1",
		TEST_IFCFG_WIRED_IPV6_MANUAL);

	ASSERT (nm_ip6_address_get_prefix (ip6_addr) == expected_prefix1,
		"wired-ipv6-manual-verify-ip6", "failed to verify %s: unexpected IP6 address #1 prefix",
		TEST_IFCFG_WIRED_IPV6_MANUAL);

	ASSERT (inet_pton (AF_INET6, expected_address1, &addr) > 0,
		"wired-ipv6-manual-verify-ip6", "failed to verify %s: couldn't convert IP address #1",
		TEST_IFCFG_WIRED_IPV6_MANUAL);
	ASSERT (IN6_ARE_ADDR_EQUAL (nm_ip6_address_get_address (ip6_addr), &addr),
		"wired-ipv6-manual-verify-ip6", "failed to verify %s: unexpected IP6 address #1",
		TEST_IFCFG_WIRED_IPV6_MANUAL);

	/* Address #2 */
	ip6_addr = nm_setting_ip6_config_get_address (s_ip6, 1);
	ASSERT (ip6_addr,
		"wired-ipv6-manual-verify-ip6", "failed to verify %s: missing IP6 address #2",
		TEST_IFCFG_WIRED_IPV6_MANUAL);

	ASSERT (nm_ip6_address_get_prefix (ip6_addr) == expected_prefix2,
		"wired-ipv6-manual-verify-ip6", "failed to verify %s: unexpected IP6 address #2 prefix",
		TEST_IFCFG_WIRED_IPV6_MANUAL);

	ASSERT (inet_pton (AF_INET6, expected_address2, &addr) > 0,
		"wired-ipv6-manual-verify-ip6", "failed to verify %s: couldn't convert IP address #2",
		TEST_IFCFG_WIRED_IPV6_MANUAL);
	ASSERT (IN6_ARE_ADDR_EQUAL (nm_ip6_address_get_address (ip6_addr), &addr),
		"wired-ipv6-manual-verify-ip6", "failed to verify %s: unexpected IP6 address #2",
		TEST_IFCFG_WIRED_IPV6_MANUAL);

	/* Address #3 */
	ip6_addr = nm_setting_ip6_config_get_address (s_ip6, 2);
	ASSERT (ip6_addr,
		"wired-ipv6-manual-verify-ip6", "failed to verify %s: missing IP6 address #3",
		TEST_IFCFG_WIRED_IPV6_MANUAL);

	ASSERT (nm_ip6_address_get_prefix (ip6_addr) == expected_prefix3,
		"wired-ipv6-manual-verify-ip6", "failed to verify %s: unexpected IP6 address #3 prefix",
		TEST_IFCFG_WIRED_IPV6_MANUAL);

	ASSERT (inet_pton (AF_INET6, expected_address3, &addr) > 0,
		"wired-ipv6-manual-verify-ip6", "failed to verify %s: couldn't convert IP address #3",
		TEST_IFCFG_WIRED_IPV6_MANUAL);
	ASSERT (IN6_ARE_ADDR_EQUAL (nm_ip6_address_get_address (ip6_addr), &addr),
		"wired-ipv6-manual-verify-ip6", "failed to verify %s: unexpected IP6 address #3",
		TEST_IFCFG_WIRED_IPV6_MANUAL);

	/* Routes */
	g_assert_cmpint (nm_setting_ip6_config_get_num_routes (s_ip6), ==, 2);
	/* Route #1 */
	ip6_route = nm_setting_ip6_config_get_route (s_ip6, 0);
	g_assert (ip6_route);
	g_assert_cmpint (inet_pton (AF_INET6, "9876::1234", &addr), >, 0);
	g_assert_cmpint (memcmp (nm_ip6_route_get_dest (ip6_route), &addr, sizeof (struct in6_addr)), ==, 0);
	g_assert_cmpint (nm_ip6_route_get_prefix (ip6_route), ==, 96);
	g_assert_cmpint (inet_pton (AF_INET6, "9876::7777", &addr), >, 0);
	g_assert_cmpint (memcmp (nm_ip6_route_get_next_hop (ip6_route), &addr, sizeof (struct in6_addr)), ==, 0);
	g_assert_cmpint (nm_ip6_route_get_metric (ip6_route), ==, 2);
	/* Route #2 */
	ip6_route = nm_setting_ip6_config_get_route (s_ip6, 1);
	g_assert (ip6_route);
	g_assert_cmpint (inet_pton (AF_INET6, "abbe::cafe", &addr), >, 0);
	g_assert_cmpint (memcmp (nm_ip6_route_get_dest (ip6_route), &addr, sizeof (struct in6_addr)), ==, 0);
	g_assert_cmpint (nm_ip6_route_get_prefix (ip6_route), ==, 64);
	g_assert_cmpint (inet_pton (AF_INET6, "::", &addr), >, 0);
	g_assert_cmpint (memcmp (nm_ip6_route_get_next_hop (ip6_route), &addr, sizeof (struct in6_addr)), ==, 0);
	g_assert_cmpint (nm_ip6_route_get_metric (ip6_route), ==, 777);

	/* DNS Addresses */
	ASSERT (nm_setting_ip6_config_get_num_dns (s_ip6) == 2,
	        "wired-ipv6-manual-verify-ip6", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_IPV6_MANUAL,
	        NM_SETTING_IP6_CONFIG_SETTING_NAME,
	        NM_SETTING_IP6_CONFIG_DNS);

	ASSERT (inet_pton (AF_INET6, expected_dns1, &addr) > 0,
		"wired-ipv6-manual-verify-ip6", "failed to verify %s: couldn't convert DNS IP address #1",
		TEST_IFCFG_WIRED_IPV6_MANUAL);
	ASSERT (IN6_ARE_ADDR_EQUAL (nm_setting_ip6_config_get_dns (s_ip6, 0), &addr),
		"wired-ipv6-manual-verify-ip6", "failed to verify %s: unexpected %s / %s key value #1",
		TEST_IFCFG_WIRED_IPV6_MANUAL,
		NM_SETTING_IP6_CONFIG_SETTING_NAME,
		NM_SETTING_IP6_CONFIG_DNS);

	ASSERT (inet_pton (AF_INET6, expected_dns2, &addr) > 0,
		"wired-ipv6-manual-verify-ip6", "failed to verify %s: couldn't convert DNS IP address #2",
		TEST_IFCFG_WIRED_IPV6_MANUAL);
	ASSERT (IN6_ARE_ADDR_EQUAL (nm_setting_ip6_config_get_dns (s_ip6, 1), &addr),
		"wired-ipv6-manual-verify-ip6", "failed to verify %s: unexpected %s / %s key value #2",
		TEST_IFCFG_WIRED_IPV6_MANUAL,
		NM_SETTING_IP6_CONFIG_SETTING_NAME,
		NM_SETTING_IP6_CONFIG_DNS);

	/* DNS domains - none as domains are stuffed to 'ipv4' setting */
	ASSERT (nm_setting_ip6_config_get_num_dns_searches (s_ip6) == 0,
	        "wired-ipv6-manual-verify-ip6", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_IPV6_MANUAL,
	        NM_SETTING_IP6_CONFIG_SETTING_NAME,
	        NM_SETTING_IP6_CONFIG_DNS_SEARCH);

	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
}

#define TEST_IFCFG_WIRED_IPV6_ONLY TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-ipv6-only"

static void
test_read_wired_ipv6_only (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	const char *tmp;
	const char *expected_id = "System test-wired-ipv6-only";
	const char *expected_address1 = "1001:abba::1234";
	guint32 expected_prefix1 = 56;
	const char *expected_dns1 = "1:2:3:4::a";
	NMIP6Address *ip6_addr;
	struct in6_addr addr;
	const char *method;

	connection = connection_from_file (TEST_IFCFG_WIRED_IPV6_ONLY,
	                                   NULL,
	                                   TYPE_ETHERNET,
	                                   NULL,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &routefile,
	                                   &route6file,
	                                   &error,
	                                   &ignore_error);
	ASSERT (connection != NULL,
	        "wired-ipv6-only-read", "failed to read %s: %s", TEST_IFCFG_WIRED_IPV6_ONLY, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "wired-ipv6-only-verify", "failed to verify %s: %s", TEST_IFCFG_WIRED_IPV6_ONLY, error->message);

	ASSERT (unmanaged == NULL,
	        "wired-ipv6-only-verify", "failed to verify %s: unexpected unmanaged value", TEST_IFCFG_WIRED_IPV6_MANUAL);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
	        "wired-ipv6-only-verify-connection", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIRED_IPV6_MANUAL,
	        NM_SETTING_CONNECTION_SETTING_NAME);

	/* ID */
	tmp = nm_setting_connection_get_id (s_con);
	ASSERT (tmp != NULL,
	        "wired-ipv6-only-verify-connection", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIRED_IPV6_MANUAL,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);
	ASSERT (strcmp (tmp, expected_id) == 0,
	        "wired-ipv6-only-verify-connection", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_IPV6_MANUAL,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);

	/* ===== WIRED SETTING ===== */

	s_wired = nm_connection_get_setting_wired (connection);
	ASSERT (s_wired != NULL,
	        "wired-ipv6-only-verify-wired", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIRED_IPV6_MANUAL,
	        NM_SETTING_WIRED_SETTING_NAME);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	ASSERT (s_ip4 != NULL,
	        "wired-ipv6-only-verify-ip4", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIRED_IPV6_MANUAL,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME);

	method = nm_setting_ip4_config_get_method (s_ip4);
	ASSERT (strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_DISABLED) == 0,
	        "wired-ipv6-only-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_IPV6_MANUAL,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_METHOD);

	/* ===== IPv6 SETTING ===== */

	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	ASSERT (s_ip6 != NULL,
	        "wired-ipv6-only-verify-ip6", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIRED_IPV6_MANUAL,
	        NM_SETTING_IP6_CONFIG_SETTING_NAME);

	/* Method */
	tmp = nm_setting_ip6_config_get_method (s_ip6);
	ASSERT (strcmp (tmp, NM_SETTING_IP6_CONFIG_METHOD_MANUAL) == 0,
	        "wired-ipv6-only-verify-ip6", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_IPV6_MANUAL,
	        NM_SETTING_IP6_CONFIG_SETTING_NAME,
	        NM_SETTING_IP6_CONFIG_METHOD);

	/* IP addresses */
	ASSERT (nm_setting_ip6_config_get_num_addresses (s_ip6) == 1,
		"wired-ipv6-only-verify-ip6", "failed to verify %s: unexpected %s / %s key value",
		TEST_IFCFG_WIRED_IPV6_MANUAL,
		NM_SETTING_IP6_CONFIG_SETTING_NAME,
		NM_SETTING_IP6_CONFIG_ADDRESSES);

	/* Address #1 */
	ip6_addr = nm_setting_ip6_config_get_address (s_ip6, 0);
	ASSERT (ip6_addr,
		"wired-ipv6-only-verify-ip6", "failed to verify %s: missing IP6 address #1",
		TEST_IFCFG_WIRED_IPV6_MANUAL);

	ASSERT (nm_ip6_address_get_prefix (ip6_addr) == expected_prefix1,
		"wired-ipv6-only-verify-ip6", "failed to verify %s: unexpected IP6 address #1 prefix",
		TEST_IFCFG_WIRED_IPV6_MANUAL);

	ASSERT (inet_pton (AF_INET6, expected_address1, &addr) > 0,
		"wired-ipv6-only-verify-ip6", "failed to verify %s: couldn't convert IP address #1",
		TEST_IFCFG_WIRED_IPV6_MANUAL);
	ASSERT (IN6_ARE_ADDR_EQUAL (nm_ip6_address_get_address (ip6_addr), &addr),
		"wired-ipv6-only-verify-ip6", "failed to verify %s: unexpected IP6 address #1",
		TEST_IFCFG_WIRED_IPV6_MANUAL);

	/* DNS Addresses */
	ASSERT (nm_setting_ip6_config_get_num_dns (s_ip6) == 1,
	        "wired-ipv6-only-verify-ip6", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_IPV6_MANUAL,
	        NM_SETTING_IP6_CONFIG_SETTING_NAME,
	        NM_SETTING_IP6_CONFIG_DNS);

	ASSERT (inet_pton (AF_INET6, expected_dns1, &addr) > 0,
		"wired-ipv6-only-verify-ip6", "failed to verify %s: couldn't convert DNS IP address #1",
		TEST_IFCFG_WIRED_IPV6_MANUAL);
	ASSERT (IN6_ARE_ADDR_EQUAL (nm_setting_ip6_config_get_dns (s_ip6, 0), &addr),
		"wired-ipv6-only-verify-ip6", "failed to verify %s: unexpected %s / %s key value #1",
		TEST_IFCFG_WIRED_IPV6_MANUAL,
		NM_SETTING_IP6_CONFIG_SETTING_NAME,
		NM_SETTING_IP6_CONFIG_DNS);

	/* DNS domains should be in IPv6, because IPv4 is disabled */
	g_assert_cmpint (nm_setting_ip6_config_get_num_dns_searches (s_ip6), ==, 3);
	g_assert_cmpstr (nm_setting_ip6_config_get_dns_search (s_ip6, 0), ==, "lorem.com");
	g_assert_cmpstr (nm_setting_ip6_config_get_dns_search (s_ip6, 1), ==, "ipsum.org");
	g_assert_cmpstr (nm_setting_ip6_config_get_dns_search (s_ip6, 2), ==, "dolor.edu");

	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
}

#define TEST_IFCFG_WIRED_DHCP6_ONLY TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-dhcp6-only"

static void
test_read_wired_dhcp6_only (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	const char *tmp;
	const char *expected_id = "System test-wired-dhcp6-only";
	const char *method;

	connection = connection_from_file (TEST_IFCFG_WIRED_DHCP6_ONLY,
	                                   NULL,
	                                   TYPE_ETHERNET,
	                                   NULL,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &routefile,
	                                   &route6file,
	                                   &error,
	                                   &ignore_error);
	ASSERT (connection != NULL,
	        "wired-dhcp6-only-read", "failed to read %s: %s", TEST_IFCFG_WIRED_DHCP6_ONLY, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "wired-dhcp6-only-verify", "failed to verify %s: %s", TEST_IFCFG_WIRED_DHCP6_ONLY, error->message);

	ASSERT (unmanaged == NULL,
	        "wired-dhcp6-only-verify", "failed to verify %s: unexpected unmanaged value", TEST_IFCFG_WIRED_DHCP6_ONLY);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
	        "wired-dhcp6-only-verify-connection", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIRED_DHCP6_ONLY,
	        NM_SETTING_CONNECTION_SETTING_NAME);

	/* ID */
	tmp = nm_setting_connection_get_id (s_con);
	ASSERT (tmp != NULL,
	        "wired-dhcp6-only-verify-connection", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIRED_DHCP6_ONLY,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);
	ASSERT (strcmp (tmp, expected_id) == 0,
	        "wired-dhcp6-only-verify-connection", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_DHCP6_ONLY,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);

	/* ===== WIRED SETTING ===== */

	s_wired = nm_connection_get_setting_wired (connection);
	ASSERT (s_wired != NULL,
	        "wired-dhcp6-only-verify-wired", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIRED_DHCP6_ONLY,
	        NM_SETTING_WIRED_SETTING_NAME);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	ASSERT (s_ip4 != NULL,
	        "wired-dhcp6-only-verify-ip4", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIRED_DHCP6_ONLY,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME);

	method = nm_setting_ip4_config_get_method (s_ip4);
	ASSERT (strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_DISABLED) == 0,
	        "wired-dhcp6-only-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_DHCP6_ONLY,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_METHOD);

	/* ===== IPv6 SETTING ===== */

	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	ASSERT (s_ip6 != NULL,
	        "wired-dhcp6-only-verify-ip6", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIRED_DHCP6_ONLY,
	        NM_SETTING_IP6_CONFIG_SETTING_NAME);

	/* Method */
	tmp = nm_setting_ip6_config_get_method (s_ip6);
	ASSERT (strcmp (tmp, NM_SETTING_IP6_CONFIG_METHOD_DHCP) == 0,
	        "wired-dhcp6-only-verify-ip6", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_DHCP6_ONLY,
	        NM_SETTING_IP6_CONFIG_SETTING_NAME,
	        NM_SETTING_IP6_CONFIG_METHOD);

	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
}

#define TEST_IFCFG_ONBOOT_NO TEST_IFCFG_DIR"/network-scripts/ifcfg-test-onboot-no"

static void
test_read_onboot_no (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;

	connection = connection_from_file (TEST_IFCFG_ONBOOT_NO,
	                                   NULL,
	                                   TYPE_ETHERNET,
	                                   NULL,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &routefile,
	                                   &route6file,
	                                   &error,
	                                   &ignore_error);
	ASSERT (connection != NULL,
	        "onboot-no-read", "failed to read %s: %s", TEST_IFCFG_ONBOOT_NO, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "onboot-no-verify", "failed to verify %s: %s", TEST_IFCFG_ONBOOT_NO, error->message);

	ASSERT (unmanaged == NULL,
	        "onboot-no-verify", "failed to verify %s: unexpected unmanaged value", TEST_IFCFG_ONBOOT_NO);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
	        "onboot-no-verify-connection", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_ONBOOT_NO,
	        NM_SETTING_CONNECTION_SETTING_NAME);

	/* Autoconnect */
	ASSERT (nm_setting_connection_get_autoconnect (s_con) == FALSE,
	        "onboot-no-verify-connection", "failed to verify %s: unexpected %s /%s key value",
	        TEST_IFCFG_ONBOOT_NO,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_AUTOCONNECT);

	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
}

#define TEST_IFCFG_NOIP TEST_IFCFG_DIR"/network-scripts/ifcfg-test-noip"

static void
test_read_noip (void)
{
	NMConnection *connection;
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;

	connection = connection_from_file (TEST_IFCFG_NOIP,
	                                   NULL,
	                                   TYPE_ETHERNET,
	                                   NULL,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &routefile,
	                                   &route6file,
	                                   &error,
	                                   &ignore_error);
	g_assert (connection);
	g_assert (nm_connection_verify (connection, &error));
	g_assert_no_error (error);

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip4_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_DISABLED);
	g_assert (nm_setting_ip4_config_get_never_default (s_ip4) == FALSE);

	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	g_assert (s_ip6);
	g_assert_cmpstr (nm_setting_ip6_config_get_method (s_ip6), ==, NM_SETTING_IP6_CONFIG_METHOD_IGNORE);
	g_assert (nm_setting_ip6_config_get_never_default (s_ip6) == FALSE);

	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
}

#define TEST_IFCFG_WIRED_8021x_PEAP_MSCHAPV2 TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-8021x-peap-mschapv2"
#define TEST_IFCFG_WIRED_8021x_PEAP_MSCHAPV2_CA_CERT TEST_IFCFG_DIR"/network-scripts/test_ca_cert.pem"

static void
test_read_wired_8021x_peap_mschapv2 (void)
{
	NMConnection *connection;
	NMSettingWired *s_wired;
	NMSettingIP4Config *s_ip4;
	NMSetting8021x *s_8021x;
	NMSetting8021x *tmp_8021x;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	const char *tmp;
	const char *expected_identity = "David Smith";
	const char *expected_anon_identity = "somebody";
	const char *expected_password = "foobar baz";
	gboolean success = FALSE;
	const char *expected_ca_cert_path;
	const char *read_ca_cert_path;

	connection = connection_from_file (TEST_IFCFG_WIRED_8021x_PEAP_MSCHAPV2,
	                                   NULL,
	                                   TYPE_ETHERNET,
	                                   NULL,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &routefile,
	                                   &route6file,
	                                   &error,
	                                   &ignore_error);
	ASSERT (connection != NULL,
	        "wired-8021x-peap-mschapv2-read", "failed to read %s: %s", TEST_IFCFG_WIRED_8021x_PEAP_MSCHAPV2, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "wired-8021x-peap-mschapv2-verify", "failed to verify %s: %s", TEST_IFCFG_WIRED_8021x_PEAP_MSCHAPV2, error->message);

	ASSERT (unmanaged == NULL,
	        "wired-8021x-peap-mschapv2-verify", "failed to verify %s: unexpected unmanaged value", TEST_IFCFG_WIRED_8021x_PEAP_MSCHAPV2);

	/* ===== WIRED SETTING ===== */

	s_wired = nm_connection_get_setting_wired (connection);
	ASSERT (s_wired != NULL,
	        "wired-8021x-peap-mschapv2-verify-wired", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIRED_8021x_PEAP_MSCHAPV2,
	        NM_SETTING_WIRED_SETTING_NAME);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	ASSERT (s_ip4 != NULL,
	        "wired-8021x-peap-mschapv2-verify-ip4", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIRED_8021x_PEAP_MSCHAPV2,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME);

	/* Method */
	tmp = nm_setting_ip4_config_get_method (s_ip4);
	ASSERT (strcmp (tmp, NM_SETTING_IP4_CONFIG_METHOD_AUTO) == 0,
	        "wired-8021x-peap-mschapv2-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_8021x_PEAP_MSCHAPV2,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_METHOD);

	/* ===== 802.1x SETTING ===== */
	s_8021x = nm_connection_get_setting_802_1x (connection);
	ASSERT (s_8021x != NULL,
	        "wired-8021x-peap-mschapv2-verify-8021x", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIRED_8021x_PEAP_MSCHAPV2,
	        NM_SETTING_802_1X_SETTING_NAME);

	/* EAP methods */
	ASSERT (nm_setting_802_1x_get_num_eap_methods (s_8021x) == 1,
	        "wired-8021x-peap-mschapv2-verify-8021x", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_8021x_PEAP_MSCHAPV2,
	        NM_SETTING_802_1X_SETTING_NAME,
	        NM_SETTING_802_1X_EAP);
	tmp = nm_setting_802_1x_get_eap_method (s_8021x, 0);
	ASSERT (tmp != NULL,
	        "wired-8021x-peap-mschapv2-verify-8021x", "failed to verify %s: missing %s / %s eap method",
	        TEST_IFCFG_WIRED_8021x_PEAP_MSCHAPV2,
	        NM_SETTING_802_1X_SETTING_NAME,
	        NM_SETTING_802_1X_EAP);
	ASSERT (strcmp (tmp, "peap") == 0,
	        "wired-8021x-peap-mschapv2-verify-8021x", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_8021x_PEAP_MSCHAPV2,
	        NM_SETTING_802_1X_SETTING_NAME,
	        NM_SETTING_802_1X_EAP);

	/* Identity */
	tmp = nm_setting_802_1x_get_identity (s_8021x);
	ASSERT (tmp != NULL,
	        "wired-8021x-peap-mschapv2-verify-8021x", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIRED_8021x_PEAP_MSCHAPV2,
	        NM_SETTING_802_1X_SETTING_NAME,
	        NM_SETTING_802_1X_IDENTITY);
	ASSERT (strcmp (tmp, expected_identity) == 0,
	        "wired-8021x-peap-mschapv2-verify-8021x", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_8021x_PEAP_MSCHAPV2,
	        NM_SETTING_802_1X_SETTING_NAME,
	        NM_SETTING_802_1X_IDENTITY);

	/* Anonymous Identity */
	tmp = nm_setting_802_1x_get_anonymous_identity (s_8021x);
	ASSERT (tmp != NULL,
	        "wired-8021x-peap-mschapv2-verify-8021x", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIRED_8021x_PEAP_MSCHAPV2,
	        NM_SETTING_802_1X_SETTING_NAME,
	        NM_SETTING_802_1X_ANONYMOUS_IDENTITY);
	ASSERT (strcmp (tmp, expected_anon_identity) == 0,
	        "wired-8021x-peap-mschapv2-verify-8021x", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_8021x_PEAP_MSCHAPV2,
	        NM_SETTING_802_1X_SETTING_NAME,
	        NM_SETTING_802_1X_ANONYMOUS_IDENTITY);

	/* Password */
	tmp = nm_setting_802_1x_get_password (s_8021x);
	ASSERT (tmp != NULL,
	        "wired-8021x-peap-mschapv2-verify-8021x", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIRED_8021x_PEAP_MSCHAPV2,
	        NM_SETTING_802_1X_SETTING_NAME,
	        NM_SETTING_802_1X_PASSWORD);
	ASSERT (strcmp (tmp, expected_password) == 0,
	        "wired-8021x-peap-mschapv2-verify-8021x", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_8021x_PEAP_MSCHAPV2,
	        NM_SETTING_802_1X_SETTING_NAME,
	        NM_SETTING_802_1X_PASSWORD);

	/* PEAP version */
	tmp = nm_setting_802_1x_get_phase1_peapver (s_8021x);
	ASSERT (tmp != NULL,
	        "wired-8021x-peap-mschapv2-verify-8021x", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIRED_8021x_PEAP_MSCHAPV2,
	        NM_SETTING_802_1X_SETTING_NAME,
	        NM_SETTING_802_1X_PHASE1_PEAPVER);
	ASSERT (strcmp (tmp, "1") == 0,
	        "wired-8021x-peap-mschapv2-verify-8021x", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_8021x_PEAP_MSCHAPV2,
	        NM_SETTING_802_1X_SETTING_NAME,
	        NM_SETTING_802_1X_PHASE1_PEAPVER);

	/* PEAP Label */
	tmp = nm_setting_802_1x_get_phase1_peaplabel (s_8021x);
	ASSERT (tmp != NULL,
	        "wired-8021x-peap-mschapv2-verify-8021x", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIRED_8021x_PEAP_MSCHAPV2,
	        NM_SETTING_802_1X_SETTING_NAME,
	        NM_SETTING_802_1X_PHASE1_PEAPLABEL);
	ASSERT (strcmp (tmp, "1") == 0,
	        "wired-8021x-peap-mschapv2-verify-8021x", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_8021x_PEAP_MSCHAPV2,
	        NM_SETTING_802_1X_SETTING_NAME,
	        NM_SETTING_802_1X_PHASE1_PEAPLABEL);

	/* CA Cert */
	tmp_8021x = (NMSetting8021x *) nm_setting_802_1x_new ();

	success = nm_setting_802_1x_set_ca_cert (tmp_8021x,
	                                         TEST_IFCFG_WIRED_8021x_PEAP_MSCHAPV2_CA_CERT,
	                                         NM_SETTING_802_1X_CK_SCHEME_PATH,
	                                         NULL,
	                                         &error);
	ASSERT (success == TRUE,
	        "wired-8021x-peap-mschapv2-verify-8021x", "failed to verify %s: could not load CA certificate",
	        TEST_IFCFG_WIRED_8021x_PEAP_MSCHAPV2,
	        NM_SETTING_802_1X_SETTING_NAME,
	        NM_SETTING_802_1X_CA_CERT);
	expected_ca_cert_path = nm_setting_802_1x_get_ca_cert_path (tmp_8021x);
	ASSERT (expected_ca_cert_path != NULL,
	        "wired-8021x-peap-mschapv2-verify-8021x", "failed to verify %s: failed to get CA certificate",
	        TEST_IFCFG_WIRED_8021x_PEAP_MSCHAPV2,
	        NM_SETTING_802_1X_SETTING_NAME,
	        NM_SETTING_802_1X_CA_CERT);

	read_ca_cert_path = nm_setting_802_1x_get_ca_cert_path (s_8021x);
	ASSERT (read_ca_cert_path != NULL,
	        "wired-8021x-peap-mschapv2-verify-8021x", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIRED_8021x_PEAP_MSCHAPV2,
	        NM_SETTING_802_1X_SETTING_NAME,
	        NM_SETTING_802_1X_CA_CERT);

	ASSERT (strcmp (read_ca_cert_path, expected_ca_cert_path) == 0,
	        "wired-8021x-peap-mschapv2-verify-8021x", "failed to verify %s: unexpected %s / %s certificate path",
	        TEST_IFCFG_WIRED_8021x_PEAP_MSCHAPV2,
	        NM_SETTING_802_1X_SETTING_NAME,
	        NM_SETTING_802_1X_CA_CERT);

	g_object_unref (tmp_8021x);

	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
}

#define TEST_IFCFG_WIRED_8021X_TLS_AGENT TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-8021x-tls-agent"
#define TEST_IFCFG_WIRED_8021X_TLS_ALWAYS TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-8021x-tls-always"

static void
test_read_wired_8021x_tls_secret_flags (const char *ifcfg, NMSettingSecretFlags expected_flags)
{
	NMConnection *connection;
	NMSettingWired *s_wired;
	NMSetting8021x *s_8021x;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	const char *expected_identity = "David Smith";
	gboolean success = FALSE;
	char *dirname, *tmp;

	connection = connection_from_file (ifcfg,
	                                   NULL,
	                                   TYPE_ETHERNET,
	                                   NULL,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &routefile,
	                                   &route6file,
	                                   &error,
	                                   &ignore_error);
	g_assert_no_error (error);
	g_assert (connection);

	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	/* ===== WIRED SETTING ===== */
	s_wired = nm_connection_get_setting_wired (connection);
	g_assert (s_wired);

	/* ===== 802.1x SETTING ===== */
	s_8021x = nm_connection_get_setting_802_1x (connection);
	g_assert (s_8021x);
	g_assert_cmpint (nm_setting_802_1x_get_num_eap_methods (s_8021x), ==, 1);
	g_assert_cmpstr (nm_setting_802_1x_get_eap_method (s_8021x, 0), ==, "tls");
	g_assert_cmpstr (nm_setting_802_1x_get_identity (s_8021x), ==, expected_identity);
	g_assert_cmpint (nm_setting_802_1x_get_private_key_password_flags (s_8021x), ==, expected_flags);

	dirname = g_path_get_dirname (ifcfg);
	tmp = g_build_path ("/", dirname, "test_ca_cert.pem", NULL);
	g_assert_cmpstr (nm_setting_802_1x_get_ca_cert_path (s_8021x), ==, tmp);
	g_free (tmp);

	tmp = g_build_path ("/", dirname, "test1_key_and_cert.pem", NULL);
	g_assert_cmpstr (nm_setting_802_1x_get_client_cert_path (s_8021x), ==, tmp);
	g_assert_cmpstr (nm_setting_802_1x_get_private_key_path (s_8021x), ==, tmp);
	g_free (tmp);

	g_free (dirname);

	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
}

static void
test_read_write_802_1X_subj_matches (void)
{
	NMConnection *connection, *reread;
	NMSetting8021x *s_8021x;
	char *written = NULL;
	GError *error = NULL;
	gboolean success = FALSE;

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_WARNING,
	                       "*missing IEEE_8021X_CA_CERT*peap*");
	connection = connection_from_file (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-802-1X-subj-matches",
	                                   NULL, TYPE_ETHERNET, NULL, NULL,
	                                   NULL, NULL, NULL, &error, NULL);
	g_test_assert_expected_messages ();
	g_assert_no_error (error);
	g_assert (connection != NULL);

	/* ===== 802.1x SETTING ===== */
	s_8021x = nm_connection_get_setting_802_1x (connection);
	g_assert (s_8021x);
	g_assert_cmpint (nm_setting_802_1x_get_num_eap_methods (s_8021x), ==, 1);
	g_assert_cmpstr (nm_setting_802_1x_get_eap_method (s_8021x, 0), ==, "peap");
	g_assert_cmpstr (nm_setting_802_1x_get_identity (s_8021x), ==, "Jara Cimrman");
	g_assert_cmpstr (nm_setting_802_1x_get_subject_match (s_8021x), ==, "server1.yourdomain.tld");
	g_assert_cmpstr (nm_setting_802_1x_get_phase2_subject_match (s_8021x), ==, "server2.yourdomain.tld");
	g_assert_cmpint (nm_setting_802_1x_get_num_altsubject_matches (s_8021x), ==, 3);
	g_assert_cmpstr (nm_setting_802_1x_get_altsubject_match (s_8021x, 0), ==, "a.yourdomain.tld");
	g_assert_cmpstr (nm_setting_802_1x_get_altsubject_match (s_8021x, 1), ==, "b.yourdomain.tld");
	g_assert_cmpstr (nm_setting_802_1x_get_altsubject_match (s_8021x, 2), ==, "c.yourdomain.tld");
	g_assert_cmpint (nm_setting_802_1x_get_num_phase2_altsubject_matches (s_8021x), ==, 2);
	g_assert_cmpstr (nm_setting_802_1x_get_phase2_altsubject_match (s_8021x, 0), ==, "x.yourdomain.tld");
	g_assert_cmpstr (nm_setting_802_1x_get_phase2_altsubject_match (s_8021x, 1), ==, "y.yourdomain.tld");

	success = writer_new_connection (connection,
	                                 TEST_SCRATCH_DIR "/network-scripts/",
	                                 &written,
	                                 &error);
	g_assert (success);

	/* reread will be normalized, so we must normalize connection too. */
	nm_utils_normalize_connection (connection, TRUE);

	/* re-read the connection for comparison */
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_WARNING,
	                       "*missing IEEE_8021X_CA_CERT*peap*");
	reread = connection_from_file (written, NULL, TYPE_ETHERNET, NULL, NULL,
	                               NULL, NULL, NULL, &error, NULL);
	g_test_assert_expected_messages ();
	unlink (written);
	g_free (written);

	g_assert_no_error (error);
	g_assert (reread != NULL);

	success = nm_connection_verify (reread, &error);
	g_assert_no_error (error);
	g_assert (success);

	success = nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT);
	g_assert (success);

	/* Check 802.1X stuff of the re-read connection. */
	s_8021x = nm_connection_get_setting_802_1x (reread);
	g_assert (s_8021x);
	g_assert_cmpint (nm_setting_802_1x_get_num_eap_methods (s_8021x), ==, 1);
	g_assert_cmpstr (nm_setting_802_1x_get_eap_method (s_8021x, 0), ==, "peap");
	g_assert_cmpstr (nm_setting_802_1x_get_identity (s_8021x), ==, "Jara Cimrman");
	g_assert_cmpstr (nm_setting_802_1x_get_subject_match (s_8021x), ==, "server1.yourdomain.tld");
	g_assert_cmpstr (nm_setting_802_1x_get_phase2_subject_match (s_8021x), ==, "server2.yourdomain.tld");
	g_assert_cmpint (nm_setting_802_1x_get_num_altsubject_matches (s_8021x), ==, 3);
	g_assert_cmpstr (nm_setting_802_1x_get_altsubject_match (s_8021x, 0), ==, "a.yourdomain.tld");
	g_assert_cmpstr (nm_setting_802_1x_get_altsubject_match (s_8021x, 1), ==, "b.yourdomain.tld");
	g_assert_cmpstr (nm_setting_802_1x_get_altsubject_match (s_8021x, 2), ==, "c.yourdomain.tld");
	g_assert_cmpint (nm_setting_802_1x_get_num_phase2_altsubject_matches (s_8021x), ==, 2);
	g_assert_cmpstr (nm_setting_802_1x_get_phase2_altsubject_match (s_8021x, 0), ==, "x.yourdomain.tld");
	g_assert_cmpstr (nm_setting_802_1x_get_phase2_altsubject_match (s_8021x, 1), ==, "y.yourdomain.tld");

	g_object_unref (connection);
	g_object_unref (reread);
}

static void
test_read_802_1x_ttls_eapgtc (void)
{
	NMConnection *connection;
	NMSetting8021x *s_8021x;
	GError *error = NULL;
	gboolean success;

	/* Test that EAP-* inner methods are correctly read into the
	 * NMSetting8021x::autheap property.
	 */

	connection = connection_from_file (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-802-1x-ttls-eapgtc",
	                                   NULL, TYPE_WIRELESS, NULL, NULL, NULL, NULL, NULL, &error, NULL);
	g_assert_no_error (error);
	g_assert (connection);
	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	/* ===== 802.1x SETTING ===== */
	s_8021x = nm_connection_get_setting_802_1x (connection);
	g_assert (s_8021x);

	/* EAP methods */
	g_assert_cmpint (nm_setting_802_1x_get_num_eap_methods (s_8021x), ==, 1);
	g_assert_cmpstr (nm_setting_802_1x_get_eap_method (s_8021x, 0), ==, "ttls");

	/* Auth methods */
	g_assert_cmpstr (nm_setting_802_1x_get_phase2_auth (s_8021x), ==, NULL);
	g_assert_cmpstr (nm_setting_802_1x_get_phase2_autheap (s_8021x), ==, "gtc");

	g_object_unref (connection);
}

#define TEST_IFCFG_ALIASES_GOOD TEST_IFCFG_DIR"/network-scripts/ifcfg-aliasem0"

static void
test_read_wired_aliases_good (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingIP4Config *s_ip4;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	const char *tmp;
	const char *expected_id = "System aliasem0";
	int expected_num_addresses = 4, expected_prefix = 24;
	const char *expected_address[4] = { "192.168.1.5", "192.168.1.6", "192.168.1.9", "192.168.1.99" };
	const char *expected_label[4] = { NULL, "aliasem0:1", "aliasem0:2", "aliasem0:99" };
	const char *expected_gateway[4] = { "192.168.1.1", "192.168.1.1", "192.168.1.1", "192.168.1.1" };
	int i, j;

	connection = connection_from_file (TEST_IFCFG_ALIASES_GOOD,
	                                   NULL,
	                                   TYPE_ETHERNET,
	                                   NULL,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &routefile,
	                                   &route6file,
	                                   &error,
	                                   &ignore_error);
	ASSERT (connection != NULL,
	        "aliases-good-read", "failed to read %s: %s", TEST_IFCFG_ALIASES_GOOD, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "aliases-good-verify", "failed to verify %s: %s", TEST_IFCFG_ALIASES_GOOD, error->message);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
	        "aliases-good-verify-connection", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_ALIASES_GOOD,
	        NM_SETTING_CONNECTION_SETTING_NAME);

	/* ID */
	tmp = nm_setting_connection_get_id (s_con);
	ASSERT (tmp != NULL,
	        "aliases-good-verify-connection", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_ALIASES_GOOD,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);
	ASSERT (strcmp (tmp, expected_id) == 0,
	        "aliases-good-verify-connection", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_ALIASES_GOOD,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	ASSERT (s_ip4 != NULL,
	        "aliases-good-verify-ip4", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_ALIASES_GOOD,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME);

	/* Method */
	tmp = nm_setting_ip4_config_get_method (s_ip4);
	ASSERT (strcmp (tmp, NM_SETTING_IP4_CONFIG_METHOD_MANUAL) == 0,
	        "aliases-good-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_ALIASES_GOOD,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_METHOD);

	ASSERT (nm_setting_ip4_config_get_num_addresses (s_ip4) == expected_num_addresses,
	        "aliases-good-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_ALIASES_GOOD,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_ADDRESSES);

	/* Addresses */
	for (i = 0; i < expected_num_addresses; i++) {
		NMIP4Address *ip4_addr;
		char buf[INET_ADDRSTRLEN];
		struct in_addr addr;

		ip4_addr = nm_setting_ip4_config_get_address (s_ip4, i);
		ASSERT (ip4_addr,
		        "aliases-good-verify-ip4", "failed to verify %s: missing IP4 address #%d",
		        TEST_IFCFG_ALIASES_GOOD,
		        i);

		addr.s_addr = nm_ip4_address_get_address (ip4_addr);
		ASSERT (inet_ntop (AF_INET, &addr, buf, sizeof (buf)) > 0,
		        "aliases-good-verify-ip4", "failed to verify %s: couldn't convert IP address #%d",
		        TEST_IFCFG_ALIASES_GOOD,
		        i);

		for (j = 0; j < expected_num_addresses; j++) {
			if (!g_strcmp0 (buf, expected_address[j]))
				break;
		}

		ASSERT (j < expected_num_addresses,
		        "aliases-good-verify-ip4", "failed to verify %s: unexpected IP4 address #%d",
		        TEST_IFCFG_ALIASES_GOOD,
		        i);

		ASSERT (nm_ip4_address_get_prefix (ip4_addr) == expected_prefix,
		        "aliases-good-verify-ip4", "failed to verify %s: unexpected IP4 address prefix #%d",
		        TEST_IFCFG_ALIASES_GOOD,
		        i);

		if (expected_gateway[j]) {
			ASSERT (inet_pton (AF_INET, expected_gateway[j], &addr) > 0,
			        "aliases-good-verify-ip4", "failed to verify %s: couldn't convert IP address gateway #%d",
			        TEST_IFCFG_ALIASES_GOOD,
			        i);
		} else
			addr.s_addr = 0;
		ASSERT (nm_ip4_address_get_gateway (ip4_addr) == addr.s_addr,
		        "aliases-good-verify-ip4", "failed to verify %s: unexpected IP4 address gateway #%d",
		        TEST_IFCFG_ALIASES_GOOD,
		        i);

		ASSERT (g_strcmp0 (NM_UTILS_PRIVATE_CALL (nm_setting_ip4_config_get_address_label (s_ip4, i)), expected_label[j]) == 0,
		        "aliases-good-verify-ip4", "failed to verify %s: unexpected IP4 address label #%d",
		        TEST_IFCFG_ALIASES_GOOD,
		        i);

		expected_address[j] = NULL;
		expected_gateway[j] = NULL;
		expected_label[j] = NULL;
	}

	for (i = 0; i < expected_num_addresses; i++) {
		ASSERT (expected_address[i] == NULL,
		        "aliases-good-verify-ip4", "failed to verify %s: did not find IP4 address %s",
		        TEST_IFCFG_ALIASES_GOOD,
		        expected_address[i]);
	}

	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
}

static void
test_read_wired_aliases_bad (const char *base, const char *expected_id)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingIP4Config *s_ip4;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	const char *tmp;
	int expected_num_addresses = 1, expected_prefix = 24;
	const char *expected_address = "192.168.1.5";
	const char *expected_label = NULL;
	const char *expected_gateway = "192.168.1.1";
	NMIP4Address *ip4_addr;
	struct in_addr addr;

	connection = connection_from_file (base,
	                                   NULL,
	                                   TYPE_ETHERNET,
	                                   NULL,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &routefile,
	                                   &route6file,
	                                   &error,
	                                   &ignore_error);
	g_test_assert_expected_messages ();
	ASSERT (connection != NULL,
	        "aliases-bad-read", "failed to read %s: %s", base, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "aliases-bad-verify", "failed to verify %s: %s", base, error->message);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
	        "aliases-bad-verify-connection", "failed to verify %s: missing %s setting",
	        base,
	        NM_SETTING_CONNECTION_SETTING_NAME);

	/* ID */
	tmp = nm_setting_connection_get_id (s_con);
	ASSERT (tmp != NULL,
	        "aliases-bad-verify-connection", "failed to verify %s: missing %s / %s key",
	        base,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);
	ASSERT (strcmp (tmp, expected_id) == 0,
	        "aliases-bad-verify-connection", "failed to verify %s: unexpected %s / %s key value",
	        base,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	ASSERT (s_ip4 != NULL,
	        "aliases-bad-verify-ip4", "failed to verify %s: missing %s setting",
	        base,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME);

	/* Method */
	tmp = nm_setting_ip4_config_get_method (s_ip4);
	ASSERT (strcmp (tmp, NM_SETTING_IP4_CONFIG_METHOD_MANUAL) == 0,
	        "aliases-bad-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        base,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_METHOD);

	ASSERT (nm_setting_ip4_config_get_num_addresses (s_ip4) == expected_num_addresses,
	        "aliases-bad-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        base,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_ADDRESSES);

	/* Addresses */
	ip4_addr = nm_setting_ip4_config_get_address (s_ip4, 0);
	ASSERT (ip4_addr,
			"aliases-bad-verify-ip4", "failed to verify %s: missing IP4 address",
			base);

	ASSERT (inet_pton (AF_INET, expected_address, &addr) > 0,
			"aliases-bad-verify-ip4", "failed to verify %s: couldn't convert IP address",
			base);
	ASSERT (nm_ip4_address_get_address (ip4_addr) == addr.s_addr,
			"aliases-bad-verify-ip4", "failed to verify %s: unexpected IP4 address",
			base);

	ASSERT (nm_ip4_address_get_prefix (ip4_addr) == expected_prefix,
			"aliases-bad-verify-ip4", "failed to verify %s: unexpected IP4 address prefix",
			base);

	ASSERT (inet_pton (AF_INET, expected_gateway, &addr) > 0,
			"aliases-bad-verify-ip4", "failed to verify %s: couldn't convert IP address gateway",
			base);
	ASSERT (nm_ip4_address_get_gateway (ip4_addr) == addr.s_addr,
			"aliases-bad-verify-ip4", "failed to verify %s: unexpected IP4 address gateway",
			base);

	ASSERT (g_strcmp0 (NM_UTILS_PRIVATE_CALL (nm_setting_ip4_config_get_address_label (s_ip4, 0)), expected_label) == 0,
			"aliases-bad-verify-ip4", "failed to verify %s: unexpected IP4 address label",
			base);

	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
}

#define TEST_IFCFG_ALIASES_BAD_1  TEST_IFCFG_DIR"/network-scripts/ifcfg-aliasem1"

static void
test_read_wired_aliases_bad_1 (void)
{
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_WARNING,
	                       "*aliasem1:1*has no DEVICE*");
	test_read_wired_aliases_bad (TEST_IFCFG_ALIASES_BAD_1, "System aliasem1");
}

#define TEST_IFCFG_ALIASES_BAD_2  TEST_IFCFG_DIR"/network-scripts/ifcfg-aliasem2"

static void
test_read_wired_aliases_bad_2 (void)
{
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_WARNING,
	                       "*aliasem2:1*has invalid DEVICE*");
	test_read_wired_aliases_bad (TEST_IFCFG_ALIASES_BAD_2, "System aliasem2");
}

#define TEST_IFCFG_WIFI_OPEN TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wifi-open"

static void
test_read_wifi_open (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	NMSettingWirelessSecurity *s_wsec;
	NMSettingIP4Config *s_ip4;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	const char *tmp;
	const GByteArray *array;
	char expected_mac_address[ETH_ALEN] = { 0x00, 0x16, 0x41, 0x11, 0x22, 0x33 };
	const char *expected_id = "System blahblah (test-wifi-open)";
	guint64 expected_timestamp = 0;
	const char *expected_ssid = "blahblah";
	const char *expected_mode = "infrastructure";
	const guint32 expected_channel = 1;

	connection = connection_from_file (TEST_IFCFG_WIFI_OPEN,
	                                   NULL,
	                                   TYPE_WIRELESS,
	                                   NULL,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &routefile,
	                                   &route6file,
	                                   &error,
	                                   &ignore_error);
	ASSERT (connection != NULL,
	        "wifi-open-read", "failed to read %s: %s", TEST_IFCFG_WIFI_OPEN, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "wifi-open-verify", "failed to verify %s: %s", TEST_IFCFG_WIFI_OPEN, error->message);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
	        "wifi-open-verify-connection", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_OPEN,
	        NM_SETTING_CONNECTION_SETTING_NAME);

	/* ID */
	tmp = nm_setting_connection_get_id (s_con);
	ASSERT (tmp != NULL,
	        "wifi-open-verify-connection", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_OPEN,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);
	ASSERT (strcmp (tmp, expected_id) == 0,
	        "wifi-open-verify-connection", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_OPEN,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);

	/* UUID can't be tested if the ifcfg does not contain the UUID key, because
	 * the UUID is generated on the full path of the ifcfg file, which can change
	 * depending on where the tests are run.
	 */

	/* Timestamp */
	ASSERT (nm_setting_connection_get_timestamp (s_con) == expected_timestamp,
	        "wifi-open-verify-connection", "failed to verify %s: unexpected %s /%s key value",
	        TEST_IFCFG_WIFI_OPEN,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_TIMESTAMP);

	/* Autoconnect */
	ASSERT (nm_setting_connection_get_autoconnect (s_con) == TRUE,
	        "wifi-open-verify-connection", "failed to verify %s: unexpected %s /%s key value",
	        TEST_IFCFG_WIFI_OPEN,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_AUTOCONNECT);

	/* ===== WIRELESS SETTING ===== */

	s_wireless = nm_connection_get_setting_wireless (connection);
	ASSERT (s_wireless != NULL,
	        "wifi-open-verify-wireless", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_OPEN,
	        NM_SETTING_WIRELESS_SETTING_NAME);

	/* MAC address */
	array = nm_setting_wireless_get_mac_address (s_wireless);
	ASSERT (array != NULL,
	        "wifi-open-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_OPEN,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_MAC_ADDRESS);
	ASSERT (array->len == ETH_ALEN,
	        "wifi-open-verify-wireless", "failed to verify %s: unexpected %s / %s key value length",
	        TEST_IFCFG_WIFI_OPEN,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_MAC_ADDRESS);
	ASSERT (memcmp (array->data, &expected_mac_address[0], sizeof (expected_mac_address)) == 0,
	        "wifi-open-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_OPEN,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_MAC_ADDRESS);

	ASSERT (nm_setting_wireless_get_mtu (s_wireless) == 0,
	        "wifi-open-verify-wired", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_OPEN,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_MTU);

	array = nm_setting_wireless_get_ssid (s_wireless);
	ASSERT (array != NULL,
	        "wifi-open-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_OPEN,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_SSID);
	ASSERT (array->len == strlen (expected_ssid),
	        "wifi-open-verify-wireless", "failed to verify %s: unexpected %s / %s key value length",
	        TEST_IFCFG_WIFI_OPEN,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_SSID);
	ASSERT (memcmp (array->data, expected_ssid, strlen (expected_ssid)) == 0,
	        "wifi-open-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_OPEN,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_SSID);
	
	ASSERT (nm_setting_wireless_get_bssid (s_wireless) == NULL,
	        "wifi-open-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_OPEN,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_BSSID);

	tmp = nm_setting_wireless_get_mode (s_wireless);
	ASSERT (tmp != NULL,
	        "wifi-open-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_OPEN,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_MODE);
	ASSERT (strcmp (tmp, expected_mode) == 0,
	        "wifi-open-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_OPEN,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_MODE);

	ASSERT (nm_setting_wireless_get_channel (s_wireless) == expected_channel,
	        "wifi-open-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_OPEN,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_CHANNEL);

	/* ===== WiFi SECURITY SETTING ===== */
	s_wsec = nm_connection_get_setting_wireless_security (connection);
	g_assert (s_wsec == NULL);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	ASSERT (s_ip4 != NULL,
	        "wifi-open-verify-ip4", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_OPEN,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME);

	/* Method */
	tmp = nm_setting_ip4_config_get_method (s_ip4);
	ASSERT (strcmp (tmp, NM_SETTING_IP4_CONFIG_METHOD_AUTO) == 0,
	        "wifi-open-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_OPEN,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_METHOD);

	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
}

#define TEST_IFCFG_WIFI_OPEN_AUTO TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wifi-open-auto"

static void
test_read_wifi_open_auto (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	const char *tmp;
	const char *expected_id = "System blahblah (test-wifi-open-auto)";
	const char *expected_mode = "infrastructure";

	connection = connection_from_file (TEST_IFCFG_WIFI_OPEN_AUTO,
	                                   NULL,
	                                   TYPE_WIRELESS,
	                                   NULL,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &routefile,
	                                   &route6file,
	                                   &error,
	                                   &ignore_error);
	ASSERT (connection != NULL,
	        "wifi-open-auto-read", "failed to read %s: %s", TEST_IFCFG_WIFI_OPEN_AUTO, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "wifi-open-auto-verify", "failed to verify %s: %s", TEST_IFCFG_WIFI_OPEN_AUTO, error->message);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
	        "wifi-open-auto-verify-connection", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_OPEN_AUTO,
	        NM_SETTING_CONNECTION_SETTING_NAME);

	/* ID */
	tmp = nm_setting_connection_get_id (s_con);
	ASSERT (tmp != NULL,
	        "wifi-open-auto-verify-connection", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_OPEN_AUTO,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);
	ASSERT (strcmp (tmp, expected_id) == 0,
	        "wifi-open-auto-verify-connection", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_OPEN_AUTO,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);

	/* ===== WIRELESS SETTING ===== */

	s_wireless = nm_connection_get_setting_wireless (connection);
	ASSERT (s_wireless != NULL,
	        "wifi-open-auto-verify-wireless", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_OPEN_AUTO,
	        NM_SETTING_WIRELESS_SETTING_NAME);

	tmp = nm_setting_wireless_get_mode (s_wireless);
	ASSERT (tmp != NULL,
	        "wifi-open-auto-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_OPEN_AUTO,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_MODE);
	ASSERT (strcmp (tmp, expected_mode) == 0,
	        "wifi-open-auto-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_OPEN_AUTO,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_MODE);

	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
}

#define TEST_IFCFG_WIFI_OPEN_SSID_HEX TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wifi-open-ssid-hex"

static void
test_read_wifi_open_ssid_hex (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	const char *tmp;
	const GByteArray *array;
	const char *expected_id = "System blahblah (test-wifi-open-ssid-hex)";
	const char *expected_ssid = "blahblah";

	connection = connection_from_file (TEST_IFCFG_WIFI_OPEN_SSID_HEX,
	                                   NULL,
	                                   TYPE_WIRELESS,
	                                   NULL,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &routefile,
	                                   &route6file,
	                                   &error,
	                                   &ignore_error);
	ASSERT (connection != NULL,
	        "wifi-open-ssid-hex-read", "failed to read %s: %s", TEST_IFCFG_WIFI_OPEN_SSID_HEX, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "wifi-open-ssid-hex-verify", "failed to verify %s: %s", TEST_IFCFG_WIFI_OPEN_SSID_HEX, error->message);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
	        "wifi-open-ssid-hex-verify-connection", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_OPEN_SSID_HEX,
	        NM_SETTING_CONNECTION_SETTING_NAME);

	/* ID */
	tmp = nm_setting_connection_get_id (s_con);
	ASSERT (tmp != NULL,
	        "wifi-open-ssid-hex-verify-connection", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_OPEN_SSID_HEX,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);
	ASSERT (strcmp (tmp, expected_id) == 0,
	        "wifi-open-ssid-hex-verify-connection", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_OPEN_SSID_HEX,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);

	/* ===== WIRELESS SETTING ===== */

	s_wireless = nm_connection_get_setting_wireless (connection);
	ASSERT (s_wireless != NULL,
	        "wifi-open-ssid-hex-verify-wireless", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_OPEN_SSID_HEX,
	        NM_SETTING_WIRELESS_SETTING_NAME);

	/* SSID */
	array = nm_setting_wireless_get_ssid (s_wireless);
	ASSERT (array != NULL,
	        "wifi-open-ssid-hex-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_OPEN_SSID_HEX,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_SSID);
	ASSERT (array->len == strlen (expected_ssid),
	        "wifi-open-ssid-hex-verify-wireless", "failed to verify %s: unexpected %s / %s key value length",
	        TEST_IFCFG_WIFI_OPEN_SSID_HEX,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_SSID);
	ASSERT (memcmp (array->data, expected_ssid, strlen (expected_ssid)) == 0,
	        "wifi-open-ssid-hex-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_OPEN_SSID_HEX,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_SSID);

	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
}

static void
test_read_wifi_open_ssid_bad (const char *file, const char *test)
{
	NMConnection *connection;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;

	connection = connection_from_file (file,
	                                   NULL,
	                                   TYPE_WIRELESS,
	                                   NULL,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &routefile,
	                                   &route6file,
	                                   &error,
	                                   &ignore_error);
	ASSERT (connection == NULL, test, "unexpected success reading %s", file);
	g_clear_error (&error);

	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
}

#define TEST_IFCFG_WIFI_OPEN_SSID_QUOTED TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wifi-open-ssid-quoted"

static void
test_read_wifi_open_ssid_quoted (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	const char *tmp;
	const GByteArray *array;
	const char *expected_id = "System foo\"bar\\ (test-wifi-open-ssid-quoted)";
	const char *expected_ssid = "foo\"bar\\";

	connection = connection_from_file (TEST_IFCFG_WIFI_OPEN_SSID_QUOTED,
	                                   NULL,
	                                   TYPE_WIRELESS,
	                                   NULL,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &routefile,
	                                   &route6file,
	                                   &error,
	                                   &ignore_error);
	ASSERT (connection != NULL,
	        "wifi-open-ssid-quoted-read", "failed to read %s: %s", TEST_IFCFG_WIFI_OPEN_SSID_QUOTED, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "wifi-open-ssid-quoted-verify", "failed to verify %s: %s", TEST_IFCFG_WIFI_OPEN_SSID_QUOTED, error->message);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
	        "wifi-open-ssid-quoted-verify-connection", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_OPEN_SSID_QUOTED,
	        NM_SETTING_CONNECTION_SETTING_NAME);

	/* ID */
	tmp = nm_setting_connection_get_id (s_con);
	ASSERT (tmp != NULL,
	        "wifi-open-ssid-quoted-verify-connection", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_OPEN_SSID_QUOTED,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);
	ASSERT (strcmp (tmp, expected_id) == 0,
	        "wifi-open-ssid-quoted-verify-connection", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_OPEN_SSID_QUOTED,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);

	/* ===== WIRELESS SETTING ===== */

	s_wireless = nm_connection_get_setting_wireless (connection);
	ASSERT (s_wireless != NULL,
	        "wifi-open-ssid-quoted-verify-wireless", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_OPEN_SSID_QUOTED,
	        NM_SETTING_WIRELESS_SETTING_NAME);

	/* SSID */
	array = nm_setting_wireless_get_ssid (s_wireless);
	ASSERT (array != NULL,
	        "wifi-open-ssid-quoted-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_OPEN_SSID_QUOTED,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_SSID);
	ASSERT (array->len == strlen (expected_ssid),
	        "wifi-open-ssid-quoted-verify-wireless", "failed to verify %s: unexpected %s / %s key value length",
	        TEST_IFCFG_WIFI_OPEN_SSID_QUOTED,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_SSID);
	ASSERT (memcmp (array->data, expected_ssid, strlen (expected_ssid)) == 0,
	        "wifi-open-ssid-quoted-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_OPEN_SSID_QUOTED,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_SSID);

	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
}

#define TEST_IFCFG_WIFI_WEP TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wifi-wep"

static void
test_read_wifi_wep (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	NMSettingWirelessSecurity *s_wsec;
	NMSettingIP4Config *s_ip4;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	const char *tmp;
	const GByteArray *array;
	char expected_mac_address[ETH_ALEN] = { 0x00, 0x16, 0x41, 0x11, 0x22, 0x33 };
	const char *expected_id = "System blahblah (test-wifi-wep)";
	guint64 expected_timestamp = 0;
	const char *expected_ssid = "blahblah";
	const char *expected_mode = "infrastructure";
	const guint32 expected_channel = 1;
	const char *expected_wep_key0 = "0123456789abcdef0123456789";
	NMWepKeyType key_type;

	connection = connection_from_file (TEST_IFCFG_WIFI_WEP,
	                                   NULL,
	                                   TYPE_WIRELESS,
	                                   NULL,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &routefile,
	                                   &route6file,
	                                   &error,
	                                   &ignore_error);
	ASSERT (connection != NULL,
	        "wifi-wep-read", "failed to read %s: %s", TEST_IFCFG_WIFI_WEP, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "wifi-wep-verify", "failed to verify %s: %s", TEST_IFCFG_WIFI_WEP, error->message);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
	        "wifi-wep-verify-connection", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_WEP,
	        NM_SETTING_CONNECTION_SETTING_NAME);

	/* ID */
	tmp = nm_setting_connection_get_id (s_con);
	ASSERT (tmp != NULL,
	        "wifi-wep-verify-connection", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WEP,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);
	ASSERT (strcmp (tmp, expected_id) == 0,
	        "wifi-wep-verify-connection", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WEP,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);

	/* UUID can't be tested if the ifcfg does not contain the UUID key, because
	 * the UUID is generated on the full path of the ifcfg file, which can change
	 * depending on where the tests are run.
	 */

	/* Timestamp */
	ASSERT (nm_setting_connection_get_timestamp (s_con) == expected_timestamp,
	        "wifi-wep-verify-connection", "failed to verify %s: unexpected %s /%s key value",
	        TEST_IFCFG_WIFI_WEP,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_TIMESTAMP);

	/* Autoconnect */
	ASSERT (nm_setting_connection_get_autoconnect (s_con) == TRUE,
	        "wifi-wep-verify-connection", "failed to verify %s: unexpected %s /%s key value",
	        TEST_IFCFG_WIFI_WEP,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_AUTOCONNECT);

	/* ===== WIRELESS SETTING ===== */

	s_wireless = nm_connection_get_setting_wireless (connection);
	ASSERT (s_wireless != NULL,
	        "wifi-wep-verify-wireless", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_WEP,
	        NM_SETTING_WIRELESS_SETTING_NAME);

	/* MAC address */
	array = nm_setting_wireless_get_mac_address (s_wireless);
	ASSERT (array != NULL,
	        "wifi-wep-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WEP,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_MAC_ADDRESS);
	ASSERT (array->len == ETH_ALEN,
	        "wifi-wep-verify-wireless", "failed to verify %s: unexpected %s / %s key value length",
	        TEST_IFCFG_WIFI_WEP,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_MAC_ADDRESS);
	ASSERT (memcmp (array->data, &expected_mac_address[0], sizeof (expected_mac_address)) == 0,
	        "wifi-wep-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WEP,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_MAC_ADDRESS);

	/* MTU */
	ASSERT (nm_setting_wireless_get_mtu (s_wireless) == 0,
	        "wifi-wep-verify-wired", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WEP,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_MTU);

	/* SSID */
	array = nm_setting_wireless_get_ssid (s_wireless);
	ASSERT (array != NULL,
	        "wifi-wep-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WEP,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_SSID);
	ASSERT (array->len == strlen (expected_ssid),
	        "wifi-wep-verify-wireless", "failed to verify %s: unexpected %s / %s key value length",
	        TEST_IFCFG_WIFI_WEP,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_SSID);
	ASSERT (memcmp (array->data, expected_ssid, strlen (expected_ssid)) == 0,
	        "wifi-wep-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WEP,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_SSID);

	/* BSSID */
	ASSERT (nm_setting_wireless_get_bssid (s_wireless) == NULL,
	        "wifi-wep-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WEP,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_BSSID);

	/* Mode */
	tmp = nm_setting_wireless_get_mode (s_wireless);
	ASSERT (tmp != NULL,
	        "wifi-wep-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WEP,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_MODE);
	ASSERT (strcmp (tmp, expected_mode) == 0,
	        "wifi-wep-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WEP,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_MODE);

	/* Channel */
	ASSERT (nm_setting_wireless_get_channel (s_wireless) == expected_channel,
	        "wifi-wep-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WEP,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_CHANNEL);

	/* ===== WIRELESS SECURITY SETTING ===== */

	s_wsec = nm_connection_get_setting_wireless_security (connection);
	ASSERT (s_wsec != NULL,
	        "wifi-wep-verify-wireless", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_WEP,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME);

	/* Key management */
	ASSERT (strcmp (nm_setting_wireless_security_get_key_mgmt (s_wsec), "none") == 0,
	        "wifi-wep-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WEP,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_KEY_MGMT);

	/* WEP key index */
	ASSERT (nm_setting_wireless_security_get_wep_tx_keyidx (s_wsec) == 0,
	        "wifi-wep-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WEP,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_WEP_TX_KEYIDX);

	/* WEP key type */
	key_type = nm_setting_wireless_security_get_wep_key_type (s_wsec);
	ASSERT (key_type == NM_WEP_KEY_TYPE_UNKNOWN || key_type == NM_WEP_KEY_TYPE_KEY,
	        "wifi-wep-verify-wireless", "failed to verify %s: unexpected WEP key type %d",
	        TEST_IFCFG_WIFI_WEP,
	        key_type);

	/* WEP key index 0 */
	tmp = nm_setting_wireless_security_get_wep_key (s_wsec, 0);
	ASSERT (tmp != NULL,
	        "wifi-wep-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WEP,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_WEP_KEY0);
	ASSERT (strcmp (tmp, expected_wep_key0) == 0,
	        "wifi-wep-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WEP,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_WEP_KEY0);

	/* WEP key index 1 */
	tmp = nm_setting_wireless_security_get_wep_key (s_wsec, 1);
	ASSERT (tmp == NULL,
	        "wifi-wep-verify-wireless", "failed to verify %s: unexpected %s / %s key",
	        TEST_IFCFG_WIFI_WEP,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_WEP_KEY1);

	/* WEP key index 2 */
	tmp = nm_setting_wireless_security_get_wep_key (s_wsec, 2);
	ASSERT (tmp == NULL,
	        "wifi-wep-verify-wireless", "failed to verify %s: unexpected %s / %s key",
	        TEST_IFCFG_WIFI_WEP,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_WEP_KEY2);

	/* WEP key index 3 */
	tmp = nm_setting_wireless_security_get_wep_key (s_wsec, 3);
	ASSERT (tmp == NULL,
	        "wifi-wep-verify-wireless", "failed to verify %s: unexpected %s / %s key",
	        TEST_IFCFG_WIFI_WEP,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_WEP_KEY3);

	/* WEP Authentication mode */
	tmp = nm_setting_wireless_security_get_auth_alg (s_wsec);
	ASSERT (tmp != NULL,
	        "wifi-wep-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WEP,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_AUTH_ALG);
	ASSERT (strcmp (tmp, "shared") == 0,
	        "wifi-wep-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WEP,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_AUTH_ALG);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	ASSERT (s_ip4 != NULL,
	        "wifi-wep-verify-ip4", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_WEP,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME);

	/* Method */
	tmp = nm_setting_ip4_config_get_method (s_ip4);
	ASSERT (strcmp (tmp, NM_SETTING_IP4_CONFIG_METHOD_AUTO) == 0,
	        "wifi-wep-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WEP,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_METHOD);

	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
}

#define TEST_IFCFG_WIFI_WEP_ADHOC TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wifi-wep-adhoc"

static void
test_read_wifi_wep_adhoc (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	NMSettingWirelessSecurity *s_wsec;
	NMSettingIP4Config *s_ip4;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	const char *tmp;
	const GByteArray *array;
	const char *expected_id = "System blahblah (test-wifi-wep-adhoc)";
	const char *expected_ssid = "blahblah";
	const char *expected_mode = "adhoc";
	const char *expected_wep_key0 = "0123456789abcdef0123456789";
	guint32 addr;
	const char *expected_dns1 = "4.2.2.1";
	const char *expected_dns2 = "4.2.2.2";

	connection = connection_from_file (TEST_IFCFG_WIFI_WEP_ADHOC,
	                                   NULL,
	                                   TYPE_WIRELESS,
	                                   NULL,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &routefile,
	                                   &route6file,
	                                   &error,
	                                   &ignore_error);
	ASSERT (connection != NULL,
	        "wifi-wep-adhoc-read", "failed to read %s: %s", TEST_IFCFG_WIFI_WEP_ADHOC, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "wifi-wep-adhoc-verify", "failed to verify %s: %s", TEST_IFCFG_WIFI_WEP_ADHOC, error->message);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
	        "wifi-wep-adhoc-verify-connection", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_WEP_ADHOC,
	        NM_SETTING_CONNECTION_SETTING_NAME);

	/* ID */
	tmp = nm_setting_connection_get_id (s_con);
	ASSERT (tmp != NULL,
	        "wifi-wep-adhoc-verify-connection", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WEP_ADHOC,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);
	ASSERT (strcmp (tmp, expected_id) == 0,
	        "wifi-wep-adhoc-verify-connection", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WEP_ADHOC,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);

	/* UUID can't be tested if the ifcfg does not contain the UUID key, because
	 * the UUID is generated on the full path of the ifcfg file, which can change
	 * depending on where the tests are run.
	 */

	/* Autoconnect */
	ASSERT (nm_setting_connection_get_autoconnect (s_con) == FALSE,
	        "wifi-wep-adhoc-verify-connection", "failed to verify %s: unexpected %s /%s key value",
	        TEST_IFCFG_WIFI_WEP_ADHOC,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_AUTOCONNECT);

	/* ===== WIRELESS SETTING ===== */

	s_wireless = nm_connection_get_setting_wireless (connection);
	ASSERT (s_wireless != NULL,
	        "wifi-wep-adhoc-verify-wireless", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_WEP_ADHOC,
	        NM_SETTING_WIRELESS_SETTING_NAME);

	/* SSID */
	array = nm_setting_wireless_get_ssid (s_wireless);
	ASSERT (array != NULL,
	        "wifi-wep-adhoc-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WEP_ADHOC,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_SSID);
	ASSERT (array->len == strlen (expected_ssid),
	        "wifi-wep-adhoc-verify-wireless", "failed to verify %s: unexpected %s / %s key value length",
	        TEST_IFCFG_WIFI_WEP_ADHOC,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_SSID);
	ASSERT (memcmp (array->data, expected_ssid, strlen (expected_ssid)) == 0,
	        "wifi-wep-adhoc-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WEP_ADHOC,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_SSID);

	/* BSSID */
	ASSERT (nm_setting_wireless_get_bssid (s_wireless) == NULL,
	        "wifi-wep-adhoc-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WEP_ADHOC,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_BSSID);

	/* Mode */
	tmp = nm_setting_wireless_get_mode (s_wireless);
	ASSERT (tmp != NULL,
	        "wifi-wep-adhoc-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WEP_ADHOC,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_MODE);
	ASSERT (strcmp (tmp, expected_mode) == 0,
	        "wifi-wep-adhoc-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WEP_ADHOC,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_MODE);

	/* Channel */
	ASSERT (nm_setting_wireless_get_channel (s_wireless) == 11,
	        "wifi-wep-adhoc-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WEP_ADHOC,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_CHANNEL);

	/* ===== WIRELESS SECURITY SETTING ===== */

	s_wsec = nm_connection_get_setting_wireless_security (connection);
	ASSERT (s_wsec != NULL,
	        "wifi-wep-adhoc-verify-wireless", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_WEP_ADHOC,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME);

	/* Key management */
	ASSERT (strcmp (nm_setting_wireless_security_get_key_mgmt (s_wsec), "none") == 0,
	        "wifi-wep-adhoc-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WEP_ADHOC,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_KEY_MGMT);

	/* WEP key index */
	ASSERT (nm_setting_wireless_security_get_wep_tx_keyidx (s_wsec) == 0,
	        "wifi-wep-adhoc-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WEP_ADHOC,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_WEP_TX_KEYIDX);

	/* WEP key index 0 */
	tmp = nm_setting_wireless_security_get_wep_key (s_wsec, 0);
	ASSERT (tmp != NULL,
	        "wifi-wep-adhoc-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WEP_ADHOC,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_WEP_KEY0);
	ASSERT (strcmp (tmp, expected_wep_key0) == 0,
	        "wifi-wep-adhoc-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WEP_ADHOC,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_WEP_KEY0);

	/* WEP key index 1 */
	tmp = nm_setting_wireless_security_get_wep_key (s_wsec, 1);
	ASSERT (tmp == NULL,
	        "wifi-wep-adhoc-verify-wireless", "failed to verify %s: unexpected %s / %s key",
	        TEST_IFCFG_WIFI_WEP_ADHOC,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_WEP_KEY1);

	/* WEP key index 2 */
	tmp = nm_setting_wireless_security_get_wep_key (s_wsec, 2);
	ASSERT (tmp == NULL,
	        "wifi-wep-adhoc-verify-wireless", "failed to verify %s: unexpected %s / %s key",
	        TEST_IFCFG_WIFI_WEP_ADHOC,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_WEP_KEY2);

	/* WEP key index 3 */
	tmp = nm_setting_wireless_security_get_wep_key (s_wsec, 3);
	ASSERT (tmp == NULL,
	        "wifi-wep-adhoc-verify-wireless", "failed to verify %s: unexpected %s / %s key",
	        TEST_IFCFG_WIFI_WEP_ADHOC,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_WEP_KEY3);

	/* WEP Authentication mode */
	tmp = nm_setting_wireless_security_get_auth_alg (s_wsec);
	ASSERT (tmp == NULL,
	        "wifi-wep-verify-wireless", "failed to verify %s: unexpected %s / %s key",
	        TEST_IFCFG_WIFI_WEP,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_AUTH_ALG);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	ASSERT (s_ip4 != NULL,
	        "wifi-wep-adhoc-verify-ip4", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_WEP_ADHOC,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME);

	/* Method */
	tmp = nm_setting_ip4_config_get_method (s_ip4);
	ASSERT (strcmp (tmp, NM_SETTING_IP4_CONFIG_METHOD_AUTO) == 0,
	        "wifi-wep-adhoc-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WEP_ADHOC,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_METHOD);

	/* Ignore auto DNS */
	ASSERT (nm_setting_ip4_config_get_ignore_auto_dns (s_ip4) == TRUE,
	        "wifi-wep-adhoc-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WEP_ADHOC,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_IGNORE_AUTO_DNS);

	/* DNS Addresses */
	ASSERT (nm_setting_ip4_config_get_num_dns (s_ip4) == 2,
	        "wifi-wep-adhoc-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WEP_ADHOC,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS);

	ASSERT (inet_pton (AF_INET, expected_dns1, &addr) > 0,
	        "wifi-wep-adhoc-verify-ip4", "failed to verify %s: couldn't convert DNS IP address #1",
	        TEST_IFCFG_WIFI_WEP_ADHOC,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS);
	ASSERT (nm_setting_ip4_config_get_dns (s_ip4, 0) == addr,
	        "wifi-wep-adhoc-verify-ip4", "failed to verify %s: unexpected %s / %s key value #1",
	        TEST_IFCFG_WIFI_WEP_ADHOC,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS);

	ASSERT (inet_pton (AF_INET, expected_dns2, &addr) > 0,
	        "wifi-wep-adhoc-verify-ip4", "failed to verify %s: couldn't convert DNS IP address #2",
	        TEST_IFCFG_WIFI_WEP_ADHOC,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS);
	ASSERT (nm_setting_ip4_config_get_dns (s_ip4, 1) == addr,
	        "wifi-wep-adhoc-verify-ip4", "failed to verify %s: unexpected %s / %s key value #2",
	        TEST_IFCFG_WIFI_WEP_ADHOC,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS);

	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
}

#define TEST_IFCFG_WIFI_WEP_PASSPHRASE TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wifi-wep-passphrase"

static void
test_read_wifi_wep_passphrase (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	NMSettingWirelessSecurity *s_wsec;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	const char *tmp;
	const char *expected_wep_key0 = "foobar222blahblah";
	NMWepKeyType key_type;

	connection = connection_from_file (TEST_IFCFG_WIFI_WEP_PASSPHRASE,
	                                   NULL,
	                                   TYPE_WIRELESS,
	                                   NULL,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &routefile,
	                                   &route6file,
	                                   &error,
	                                   &ignore_error);
	ASSERT (connection != NULL,
	        "wifi-wep-passphrase-read", "failed to read %s: %s",
	        TEST_IFCFG_WIFI_WEP_PASSPHRASE, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "wifi-wep-passphrase-verify", "failed to verify %s: %s",
	        TEST_IFCFG_WIFI_WEP_PASSPHRASE, error->message);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
	        "wifi-wep-passphrase-verify-connection", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_WEP_PASSPHRASE,
	        NM_SETTING_CONNECTION_SETTING_NAME);

	/* ===== WIRELESS SETTING ===== */

	s_wireless = nm_connection_get_setting_wireless (connection);
	ASSERT (s_wireless != NULL,
	        "wifi-wep-passphrase-verify-wireless", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_WEP_PASSPHRASE,
	        NM_SETTING_WIRELESS_SETTING_NAME);

	/* ===== WIRELESS SECURITY SETTING ===== */

	s_wsec = nm_connection_get_setting_wireless_security (connection);
	ASSERT (s_wsec != NULL,
	        "wifi-wep-passphrase-verify-wireless", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_WEP_PASSPHRASE,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME);

	/* Key management */
	ASSERT (strcmp (nm_setting_wireless_security_get_key_mgmt (s_wsec), "none") == 0,
	        "wifi-wep-passphrase-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WEP_PASSPHRASE,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_KEY_MGMT);

	/* WEP key index */
	ASSERT (nm_setting_wireless_security_get_wep_tx_keyidx (s_wsec) == 0,
	        "wifi-wep-passphrase-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WEP_PASSPHRASE,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_WEP_TX_KEYIDX);

	/* WEP key type */
	key_type = nm_setting_wireless_security_get_wep_key_type (s_wsec);
	ASSERT (key_type == NM_WEP_KEY_TYPE_PASSPHRASE,
	        "wifi-wep-passphrase-verify-wireless", "failed to verify %s: unexpected WEP key type %d",
	        TEST_IFCFG_WIFI_WEP_PASSPHRASE,
	        key_type);

	/* WEP key index 0 */
	tmp = nm_setting_wireless_security_get_wep_key (s_wsec, 0);
	ASSERT (tmp != NULL,
	        "wifi-wep-passphrase-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WEP_PASSPHRASE,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_WEP_KEY0);
	ASSERT (strcmp (tmp, expected_wep_key0) == 0,
	        "wifi-wep-passphrase-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WEP_PASSPHRASE,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_WEP_KEY0);

	/* WEP key index 1 */
	tmp = nm_setting_wireless_security_get_wep_key (s_wsec, 1);
	ASSERT (tmp == NULL,
	        "wifi-wep-passphrase-verify-wireless", "failed to verify %s: unexpected %s / %s key",
	        TEST_IFCFG_WIFI_WEP_PASSPHRASE,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_WEP_KEY1);

	/* WEP key index 2 */
	tmp = nm_setting_wireless_security_get_wep_key (s_wsec, 2);
	ASSERT (tmp == NULL,
	        "wifi-wep-passphrase-verify-wireless", "failed to verify %s: unexpected %s / %s key",
	        TEST_IFCFG_WIFI_WEP_PASSPHRASE,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_WEP_KEY2);

	/* WEP key index 3 */
	tmp = nm_setting_wireless_security_get_wep_key (s_wsec, 3);
	ASSERT (tmp == NULL,
	        "wifi-wep-passphrase-verify-wireless", "failed to verify %s: unexpected %s / %s key",
	        TEST_IFCFG_WIFI_WEP_PASSPHRASE,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_WEP_KEY3);

	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
}

#define TEST_IFCFG_WIFI_WEP_40_ASCII TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wifi-wep-40-ascii"

static void
test_read_wifi_wep_40_ascii (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	NMSettingWirelessSecurity *s_wsec;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	const char *tmp;
	const char *expected_wep_key0 = "Lorem";
	NMWepKeyType key_type;

	connection = connection_from_file (TEST_IFCFG_WIFI_WEP_40_ASCII,
	                                   NULL,
	                                   TYPE_WIRELESS,
	                                   NULL,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &routefile,
	                                   &route6file,
	                                   &error,
	                                   &ignore_error);
	ASSERT (connection != NULL,
	        "wifi-wep-40-ascii-read", "failed to read %s: %s", TEST_IFCFG_WIFI_WEP_40_ASCII, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "wifi-wep-40-ascii-verify", "failed to verify %s: %s", TEST_IFCFG_WIFI_WEP_40_ASCII, error->message);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
	        "wifi-wep-40-ascii-verify-connection", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_WEP_40_ASCII,
	        NM_SETTING_CONNECTION_SETTING_NAME);

	/* ===== WIRELESS SETTING ===== */

	s_wireless = nm_connection_get_setting_wireless (connection);
	ASSERT (s_wireless != NULL,
	        "wifi-wep-40-ascii-verify-wireless", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_WEP_40_ASCII,
	        NM_SETTING_WIRELESS_SETTING_NAME);

	/* ===== WIRELESS SECURITY SETTING ===== */

	s_wsec = nm_connection_get_setting_wireless_security (connection);
	ASSERT (s_wsec != NULL,
	        "wifi-wep-40-ascii-verify-wireless", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_WEP_40_ASCII,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME);

	/* Key management */
	ASSERT (strcmp (nm_setting_wireless_security_get_key_mgmt (s_wsec), "none") == 0,
	        "wifi-wep-40-ascii-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WEP_40_ASCII,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_KEY_MGMT);

	/* WEP key index */
	ASSERT (nm_setting_wireless_security_get_wep_tx_keyidx (s_wsec) == 0,
	        "wifi-wep-40-ascii-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WEP_40_ASCII,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_WEP_TX_KEYIDX);

	/* WEP key type */
	key_type = nm_setting_wireless_security_get_wep_key_type (s_wsec);
	ASSERT (key_type == NM_WEP_KEY_TYPE_UNKNOWN || key_type == NM_WEP_KEY_TYPE_KEY,
	        "wifi-wep-40-ascii-verify-wireless", "failed to verify %s: unexpected WEP key type %d",
	        TEST_IFCFG_WIFI_WEP_40_ASCII,
	        key_type);

	/* WEP key index 0 */
	tmp = nm_setting_wireless_security_get_wep_key (s_wsec, 0);
	ASSERT (tmp != NULL,
	        "wifi-wep-40-ascii-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WEP_40_ASCII,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_WEP_KEY0);
	ASSERT (strcmp (tmp, expected_wep_key0) == 0,
	        "wifi-wep-40-ascii-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WEP_40_ASCII,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_WEP_KEY0);

	/* WEP key index 1 */
	tmp = nm_setting_wireless_security_get_wep_key (s_wsec, 1);
	ASSERT (tmp == NULL,
	        "wifi-wep-40-ascii-verify-wireless", "failed to verify %s: unexpected %s / %s key",
	        TEST_IFCFG_WIFI_WEP_40_ASCII,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_WEP_KEY1);

	/* WEP key index 2 */
	tmp = nm_setting_wireless_security_get_wep_key (s_wsec, 2);
	ASSERT (tmp == NULL,
	        "wifi-wep-40-ascii-verify-wireless", "failed to verify %s: unexpected %s / %s key",
	        TEST_IFCFG_WIFI_WEP_40_ASCII,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_WEP_KEY2);

	/* WEP key index 3 */
	tmp = nm_setting_wireless_security_get_wep_key (s_wsec, 3);
	ASSERT (tmp == NULL,
	        "wifi-wep-40-ascii-verify-wireless", "failed to verify %s: unexpected %s / %s key",
	        TEST_IFCFG_WIFI_WEP_40_ASCII,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_WEP_KEY3);

	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
}

#define TEST_IFCFG_WIFI_WEP_104_ASCII TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wifi-wep-104-ascii"

static void
test_read_wifi_wep_104_ascii (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	NMSettingWirelessSecurity *s_wsec;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	const char *tmp;
	const char *expected_wep_key0 = "LoremIpsumSit";
	NMWepKeyType key_type;

	connection = connection_from_file (TEST_IFCFG_WIFI_WEP_104_ASCII,
	                                   NULL,
	                                   TYPE_WIRELESS,
	                                   NULL,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &routefile,
	                                   &route6file,
	                                   &error,
	                                   &ignore_error);
	ASSERT (connection != NULL,
	        "wifi-wep-104-ascii-read", "failed to read %s: %s", TEST_IFCFG_WIFI_WEP_104_ASCII, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "wifi-wep-104-ascii-verify", "failed to verify %s: %s", TEST_IFCFG_WIFI_WEP_104_ASCII, error->message);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
	        "wifi-wep-104-ascii-verify-connection", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_WEP_104_ASCII,
	        NM_SETTING_CONNECTION_SETTING_NAME);

	/* ===== WIRELESS SETTING ===== */

	s_wireless = nm_connection_get_setting_wireless (connection);
	ASSERT (s_wireless != NULL,
	        "wifi-wep-104-ascii-verify-wireless", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_WEP_104_ASCII,
	        NM_SETTING_WIRELESS_SETTING_NAME);

	/* ===== WIRELESS SECURITY SETTING ===== */

	s_wsec = nm_connection_get_setting_wireless_security (connection);
	ASSERT (s_wsec != NULL,
	        "wifi-wep-104-ascii-verify-wireless", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_WEP_104_ASCII,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME);

	/* Key management */
	ASSERT (strcmp (nm_setting_wireless_security_get_key_mgmt (s_wsec), "none") == 0,
	        "wifi-wep-104-ascii-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WEP_104_ASCII,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_KEY_MGMT);

	/* WEP key index */
	ASSERT (nm_setting_wireless_security_get_wep_tx_keyidx (s_wsec) == 0,
	        "wifi-wep-104-ascii-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WEP_104_ASCII,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_WEP_TX_KEYIDX);

	/* WEP key type */
	key_type = nm_setting_wireless_security_get_wep_key_type (s_wsec);
	ASSERT (key_type == NM_WEP_KEY_TYPE_UNKNOWN || key_type == NM_WEP_KEY_TYPE_KEY,
	        "wifi-wep-104-ascii-verify-wireless", "failed to verify %s: unexpected WEP key type %d",
	        TEST_IFCFG_WIFI_WEP_104_ASCII,
	        key_type);

	/* WEP key index 0 */
	tmp = nm_setting_wireless_security_get_wep_key (s_wsec, 0);
	ASSERT (tmp != NULL,
	        "wifi-wep-104-ascii-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WEP_104_ASCII,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_WEP_KEY0);
	ASSERT (strcmp (tmp, expected_wep_key0) == 0,
	        "wifi-wep-104-ascii-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WEP_104_ASCII,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_WEP_KEY0);

	/* WEP key index 1 */
	tmp = nm_setting_wireless_security_get_wep_key (s_wsec, 1);
	ASSERT (tmp == NULL,
	        "wifi-wep-104-ascii-verify-wireless", "failed to verify %s: unexpected %s / %s key",
	        TEST_IFCFG_WIFI_WEP_104_ASCII,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_WEP_KEY1);

	/* WEP key index 2 */
	tmp = nm_setting_wireless_security_get_wep_key (s_wsec, 2);
	ASSERT (tmp == NULL,
	        "wifi-wep-104-ascii-verify-wireless", "failed to verify %s: unexpected %s / %s key",
	        TEST_IFCFG_WIFI_WEP_104_ASCII,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_WEP_KEY2);

	/* WEP key index 3 */
	tmp = nm_setting_wireless_security_get_wep_key (s_wsec, 3);
	ASSERT (tmp == NULL,
	        "wifi-wep-104-ascii-verify-wireless", "failed to verify %s: unexpected %s / %s key",
	        TEST_IFCFG_WIFI_WEP_104_ASCII,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_WEP_KEY3);

	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
}

#define TEST_IFCFG_WIFI_LEAP TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wifi-leap"

static void
test_read_wifi_leap (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	NMSettingWirelessSecurity *s_wsec;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	const char *tmp;
	const char *expected_id = "System blahblah (test-wifi-leap)";
	const char *expected_identity = "Bill Smith";
	const char *expected_password = "foobarblah";

	connection = connection_from_file (TEST_IFCFG_WIFI_LEAP,
	                                   NULL,
	                                   TYPE_WIRELESS,
	                                   NULL,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &routefile,
	                                   &route6file,
	                                   &error,
	                                   &ignore_error);
	ASSERT (connection != NULL,
	        "wifi-leap-read", "failed to read %s: %s", TEST_IFCFG_WIFI_LEAP, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "wifi-leap-verify", "failed to verify %s: %s", TEST_IFCFG_WIFI_LEAP, error->message);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
	        "wifi-leap-verify-connection", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_LEAP,
	        NM_SETTING_CONNECTION_SETTING_NAME);

	/* ID */
	tmp = nm_setting_connection_get_id (s_con);
	ASSERT (tmp != NULL,
	        "wifi-leap-verify-connection", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_LEAP,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);
	ASSERT (strcmp (tmp, expected_id) == 0,
	        "wifi-leap-verify-connection", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_LEAP,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);

	/* ===== WIRELESS SETTING ===== */

	s_wireless = nm_connection_get_setting_wireless (connection);
	ASSERT (s_wireless != NULL,
	        "wifi-leap-verify-wireless", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_LEAP,
	        NM_SETTING_WIRELESS_SETTING_NAME);

	/* ===== WIRELESS SECURITY SETTING ===== */

	s_wsec = nm_connection_get_setting_wireless_security (connection);
	ASSERT (s_wsec != NULL,
	        "wifi-leap-verify-wireless", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_LEAP,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME);

	/* Key management */
	ASSERT (strcmp (nm_setting_wireless_security_get_key_mgmt (s_wsec), "ieee8021x") == 0,
	        "wifi-leap-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_LEAP,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_KEY_MGMT);

	/* WEP Authentication mode */
	tmp = nm_setting_wireless_security_get_auth_alg (s_wsec);
	ASSERT (tmp != NULL,
	        "wifi-leap-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_LEAP,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_AUTH_ALG);
	ASSERT (strcmp (tmp, "leap") == 0,
	        "wifi-leap-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_LEAP,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_AUTH_ALG);

	/* LEAP Username */
	tmp = nm_setting_wireless_security_get_leap_username (s_wsec);
	ASSERT (tmp != NULL,
	        "wifi-leap-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_LEAP,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_LEAP_USERNAME);
	ASSERT (strcmp (tmp, expected_identity) == 0,
	        "wifi-leap-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_LEAP,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_LEAP_USERNAME);

	/* LEAP Password */
	tmp = nm_setting_wireless_security_get_leap_password (s_wsec);
	ASSERT (tmp != NULL,
	        "wifi-leap-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_LEAP,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_LEAP_PASSWORD);
	ASSERT (strcmp (tmp, expected_password) == 0,
	        "wifi-leap-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_LEAP,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_LEAP_PASSWORD);

	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
}

#define TEST_IFCFG_WIFI_LEAP_AGENT TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wifi-leap-agent"
#define TEST_IFCFG_WIFI_LEAP_ALWAYS TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wifi-leap-always-ask"

static void
test_read_wifi_leap_secret_flags (const char *file, NMSettingSecretFlags expected_flags)
{
	NMConnection *connection;
	NMSettingWireless *s_wifi;
	NMSettingWirelessSecurity *s_wsec;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	const char *expected_identity = "Bill Smith";
	gboolean success;

	connection = connection_from_file (file,
	                                   NULL,
	                                   TYPE_WIRELESS,
	                                   NULL,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &routefile,
	                                   &route6file,
	                                   &error,
	                                   &ignore_error);
	g_assert_no_error (error);
	g_assert (connection);

	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	/* ===== WIRELESS SETTING ===== */
	s_wifi = nm_connection_get_setting_wireless (connection);
	g_assert (s_wifi);

	/* ===== WIRELESS SECURITY SETTING ===== */
	s_wsec = nm_connection_get_setting_wireless_security (connection);
	g_assert (s_wsec);

	g_assert (g_strcmp0 (nm_setting_wireless_security_get_key_mgmt (s_wsec), "ieee8021x") == 0);
	g_assert (g_strcmp0 (nm_setting_wireless_security_get_auth_alg (s_wsec), "leap") == 0);
	g_assert (g_strcmp0 (nm_setting_wireless_security_get_leap_username (s_wsec), expected_identity) == 0);
	/* password blank as it's not system-owned */
	g_assert (nm_setting_wireless_security_get_leap_password_flags (s_wsec) == expected_flags);
	g_assert (nm_setting_wireless_security_get_leap_password (s_wsec) == NULL);

	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
}

#define TEST_IFCFG_WIFI_WPA_PSK TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wifi-wpa-psk"

static void
test_read_wifi_wpa_psk (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	NMSettingWirelessSecurity *s_wsec;
	NMSettingIP4Config *s_ip4;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	const char *tmp;
	const GByteArray *array;
	char expected_mac_address[ETH_ALEN] = { 0x00, 0x16, 0x41, 0x11, 0x22, 0x33 };
	const char *expected_id = "System blahblah (test-wifi-wpa-psk)";
	guint64 expected_timestamp = 0;
	const char *expected_ssid = "blahblah";
	const char *expected_mode = "infrastructure";
	const guint32 expected_channel = 1;
	const char *expected_key_mgmt = "wpa-psk";
	const char *expected_psk = "I wonder what the king is doing tonight?";
	guint32 n, i;
	gboolean found_pair_tkip = FALSE;
	gboolean found_pair_ccmp = FALSE;
	gboolean found_group_tkip = FALSE;
	gboolean found_group_ccmp = FALSE;
	gboolean found_group_wep40 = FALSE;
	gboolean found_group_wep104 = FALSE;
	gboolean found_proto_wpa = FALSE;
	gboolean found_proto_rsn = FALSE;

	connection = connection_from_file (TEST_IFCFG_WIFI_WPA_PSK,
	                                   NULL,
	                                   TYPE_WIRELESS,
	                                   NULL,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &routefile,
	                                   &route6file,
	                                   &error,
	                                   &ignore_error);
	ASSERT (connection != NULL,
	        "wifi-wpa-psk-read", "failed to read %s: %s", TEST_IFCFG_WIFI_WPA_PSK, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "wifi-wpa-psk-verify", "failed to verify %s: %s", TEST_IFCFG_WIFI_WPA_PSK, error->message);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
	        "wifi-wpa-psk-verify-connection", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_WPA_PSK,
	        NM_SETTING_CONNECTION_SETTING_NAME);

	/* ID */
	tmp = nm_setting_connection_get_id (s_con);
	ASSERT (tmp != NULL,
	        "wifi-wpa-psk-verify-connection", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WPA_PSK,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);
	ASSERT (strcmp (tmp, expected_id) == 0,
	        "wifi-wpa-psk-verify-connection", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WPA_PSK,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);

	/* UUID can't be tested if the ifcfg does not contain the UUID key, because
	 * the UUID is generated on the full path of the ifcfg file, which can change
	 * depending on where the tests are run.
	 */

	/* Timestamp */
	ASSERT (nm_setting_connection_get_timestamp (s_con) == expected_timestamp,
	        "wifi-wpa-psk-verify-connection", "failed to verify %s: unexpected %s /%s key value",
	        TEST_IFCFG_WIFI_WPA_PSK,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_TIMESTAMP);

	/* Autoconnect */
	ASSERT (nm_setting_connection_get_autoconnect (s_con) == TRUE,
	        "wifi-wpa-psk-verify-connection", "failed to verify %s: unexpected %s /%s key value",
	        TEST_IFCFG_WIFI_WPA_PSK,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_AUTOCONNECT);

	/* ===== WIRELESS SETTING ===== */

	s_wireless = nm_connection_get_setting_wireless (connection);
	ASSERT (s_wireless != NULL,
	        "wifi-wpa-psk-verify-wireless", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_WPA_PSK,
	        NM_SETTING_WIRELESS_SETTING_NAME);

	/* MAC address */
	array = nm_setting_wireless_get_mac_address (s_wireless);
	ASSERT (array != NULL,
	        "wifi-wpa-psk-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WPA_PSK,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_MAC_ADDRESS);
	ASSERT (array->len == ETH_ALEN,
	        "wifi-wpa-psk-verify-wireless", "failed to verify %s: unexpected %s / %s key value length",
	        TEST_IFCFG_WIFI_WPA_PSK,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_MAC_ADDRESS);
	ASSERT (memcmp (array->data, &expected_mac_address[0], sizeof (expected_mac_address)) == 0,
	        "wifi-wpa-psk-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WPA_PSK,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_MAC_ADDRESS);

	/* MTU */
	ASSERT (nm_setting_wireless_get_mtu (s_wireless) == 0,
	        "wifi-wpa-psk-verify-wired", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WPA_PSK,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_MTU);

	/* SSID */
	array = nm_setting_wireless_get_ssid (s_wireless);
	ASSERT (array != NULL,
	        "wifi-wpa-psk-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WPA_PSK,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_SSID);
	ASSERT (array->len == strlen (expected_ssid),
	        "wifi-wpa-psk-verify-wireless", "failed to verify %s: unexpected %s / %s key value length",
	        TEST_IFCFG_WIFI_WPA_PSK,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_SSID);
	ASSERT (memcmp (array->data, expected_ssid, strlen (expected_ssid)) == 0,
	        "wifi-wpa-psk-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WPA_PSK,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_SSID);

	/* BSSID */
	ASSERT (nm_setting_wireless_get_bssid (s_wireless) == NULL,
	        "wifi-wpa-psk-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WPA_PSK,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_BSSID);

	/* Mode */
	tmp = nm_setting_wireless_get_mode (s_wireless);
	ASSERT (tmp != NULL,
	        "wifi-wpa-psk-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WPA_PSK,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_MODE);
	ASSERT (strcmp (tmp, expected_mode) == 0,
	        "wifi-wpa-psk-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WPA_PSK,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_MODE);

	/* Channel */
	ASSERT (nm_setting_wireless_get_channel (s_wireless) == expected_channel,
	        "wifi-wpa-psk-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WPA_PSK,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_CHANNEL);

	/* ===== WIRELESS SECURITY SETTING ===== */

	s_wsec = nm_connection_get_setting_wireless_security (connection);
	ASSERT (s_wsec != NULL,
	        "wifi-wpa-psk-verify-wireless", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_WPA_PSK,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME);

	/* Key management */
	tmp = nm_setting_wireless_security_get_key_mgmt (s_wsec);
	ASSERT (tmp != NULL,
	        "wifi-wpa-psk-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WPA_PSK,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_KEY_MGMT);
	ASSERT (strcmp (tmp, expected_key_mgmt) == 0,
	        "wifi-wpa-psk-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WPA_PSK,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_KEY_MGMT);

	/* PSK */
	tmp = nm_setting_wireless_security_get_psk (s_wsec);
	ASSERT (tmp != NULL,
	        "wifi-wpa-psk-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WPA_PSK,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_PSK);
	ASSERT (strcmp (tmp, expected_psk) == 0,
	        "wifi-wpa-psk-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WPA_PSK,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_PSK);

	/* WEP Authentication mode */
	tmp = nm_setting_wireless_security_get_auth_alg (s_wsec);
	ASSERT (tmp == NULL,
	        "wifi-wpa-psk-verify-wireless", "failed to verify %s: unexpected %s / %s key",
	        TEST_IFCFG_WIFI_WPA_PSK,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_AUTH_ALG);

	/* Pairwise ciphers */
	n = nm_setting_wireless_security_get_num_pairwise (s_wsec);
	ASSERT (n == 2,
	        "wifi-wpa-psk-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WPA_PSK,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_PAIRWISE);
	for (i = 0; i < n; i++) {
		tmp = nm_setting_wireless_security_get_pairwise (s_wsec, i);
		ASSERT (tmp, "wifi-wpa-psk-verify-wireless", "failed to verify %s: missing pairwise cipher",
		        TEST_IFCFG_WIFI_WPA_PSK);
		if (strcmp (tmp, "tkip") == 0)
			found_pair_tkip = TRUE;
		else if (strcmp (tmp, "ccmp") == 0)
			found_pair_ccmp = TRUE;
	}
	ASSERT (found_pair_tkip, "wifi-wpa-psk-verify-wireless", "failed to verify %s: missing pairwise TKIP cipher",
	        TEST_IFCFG_WIFI_WPA_PSK);
	ASSERT (found_pair_ccmp, "wifi-wpa-psk-verify-wireless", "failed to verify %s: missing pairwise CCMP cipher",
	        TEST_IFCFG_WIFI_WPA_PSK);

	/* Group ciphers */
	n = nm_setting_wireless_security_get_num_groups (s_wsec);
	ASSERT (n == 4,
	        "wifi-wpa-psk-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WPA_PSK,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_GROUP);
	for (i = 0; i < n; i++) {
		tmp = nm_setting_wireless_security_get_group (s_wsec, i);
		ASSERT (tmp, "wifi-wpa-psk-verify-wireless", "failed to verify %s: missing group cipher",
		        TEST_IFCFG_WIFI_WPA_PSK);
		if (strcmp (tmp, "tkip") == 0)
			found_group_tkip = TRUE;
		else if (strcmp (tmp, "ccmp") == 0)
			found_group_ccmp = TRUE;
		else if (strcmp (tmp, "wep40") == 0)
			found_group_wep40 = TRUE;
		else if (strcmp (tmp, "wep104") == 0)
			found_group_wep104 = TRUE;
	}
	ASSERT (found_group_tkip, "wifi-wpa-psk-verify-wireless", "failed to verify %s: missing group TKIP cipher",
	        TEST_IFCFG_WIFI_WPA_PSK);
	ASSERT (found_group_ccmp, "wifi-wpa-psk-verify-wireless", "failed to verify %s: missing group CCMP cipher",
	        TEST_IFCFG_WIFI_WPA_PSK);
	ASSERT (found_group_wep40, "wifi-wpa-psk-verify-wireless", "failed to verify %s: missing group WEP-40 cipher",
	        TEST_IFCFG_WIFI_WPA_PSK);
	ASSERT (found_group_wep104, "wifi-wpa-psk-verify-wireless", "failed to verify %s: missing group WEP-104 cipher",
	        TEST_IFCFG_WIFI_WPA_PSK);

	/* Protocols */
	n = nm_setting_wireless_security_get_num_protos (s_wsec);
	ASSERT (n == 2,
	        "wifi-wpa-psk-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WPA_PSK,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_PROTO);
	for (i = 0; i < n; i++) {
		tmp = nm_setting_wireless_security_get_proto (s_wsec, i);
		ASSERT (tmp, "wifi-wpa-psk-verify-wireless", "failed to verify %s: missing protocol",
		        TEST_IFCFG_WIFI_WPA_PSK);
		if (strcmp (tmp, "wpa") == 0)
			found_proto_wpa = TRUE;
		else if (strcmp (tmp, "rsn") == 0)
			found_proto_rsn = TRUE;
	}
	ASSERT (found_proto_wpa, "wifi-wpa-psk-verify-wireless", "failed to verify %s: missing protoocl WPA",
	        TEST_IFCFG_WIFI_WPA_PSK);
	ASSERT (found_proto_rsn, "wifi-wpa-psk-verify-wireless", "failed to verify %s: missing protocol RSN",
	        TEST_IFCFG_WIFI_WPA_PSK);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	ASSERT (s_ip4 != NULL,
	        "wifi-wpa-psk-verify-ip4", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_WPA_PSK,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME);

	/* Method */
	tmp = nm_setting_ip4_config_get_method (s_ip4);
	ASSERT (strcmp (tmp, NM_SETTING_IP4_CONFIG_METHOD_AUTO) == 0,
	        "wifi-wpa-psk-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WPA_PSK,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_METHOD);

	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
}

#define TEST_IFCFG_WIFI_WPA_PSK_2 TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wifi-wpa-psk-2"

static void
test_read_wifi_wpa_psk_2 (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	NMSettingWirelessSecurity *s_wsec;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	const char *tmp;
	const char *expected_id = "System ipsum (test-wifi-wpa-psk-2)";
	const char *expected_psk = "They're really saying I love you. >>`<< \\";

	connection = connection_from_file (TEST_IFCFG_WIFI_WPA_PSK_2,
                                     NULL,
                                     TYPE_WIRELESS,
                                     NULL,
                                     &unmanaged,
                                     &keyfile,
                                     &routefile,
                                     &route6file,
                                     &error,
                                     &ignore_error);
	ASSERT (connection != NULL,
	        "wifi-wpa-psk-2-read", "failed to read %s: %s", TEST_IFCFG_WIFI_WPA_PSK_2, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "wifi-wpa-psk-2-verify", "failed to verify %s: %s", TEST_IFCFG_WIFI_WPA_PSK_2, error->message);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
	        "wifi-wpa-psk-2-verify-connection", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_WPA_PSK_2,
	        NM_SETTING_CONNECTION_SETTING_NAME);

	/* ID */
	tmp = nm_setting_connection_get_id (s_con);
	ASSERT (tmp != NULL,
	        "wifi-wpa-psk-2-verify-connection", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WPA_PSK_2,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);
	ASSERT (strcmp (tmp, expected_id) == 0,
	        "wifi-wpa-psk-2-verify-connection", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WPA_PSK_2,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);

	/* ===== WIRELESS SETTING ===== */

	s_wireless = nm_connection_get_setting_wireless (connection);
	ASSERT (s_wireless != NULL,
	        "wifi-wpa-psk-2-verify-wireless", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_WPA_PSK_2,
	        NM_SETTING_WIRELESS_SETTING_NAME);

	/* ===== WIRELESS SECURITY SETTING ===== */

	s_wsec = nm_connection_get_setting_wireless_security (connection);
	ASSERT (s_wsec != NULL,
	        "wifi-wpa-psk-2-verify-wireless", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_WPA_PSK_2,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME);

	/* PSK */
	tmp = nm_setting_wireless_security_get_psk (s_wsec);
	ASSERT (tmp != NULL,
	        "wifi-wpa-psk-2-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WPA_PSK_2,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_PSK);
	ASSERT (strcmp (tmp, expected_psk) == 0,
	        "wifi-wpa-psk-2-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WPA_PSK_2,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_PSK);

	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
}

#define TEST_IFCFG_WIFI_WPA_PSK_UNQUOTED TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wifi-wpa-psk-unquoted"

static void
test_read_wifi_wpa_psk_unquoted (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	NMSettingWirelessSecurity *s_wsec;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	const char *tmp;
	const char *expected_id = "System blahblah (test-wifi-wpa-psk-unquoted)";
	const char *expected_psk = "54336845e2f3f321c4c7";

	connection = connection_from_file (TEST_IFCFG_WIFI_WPA_PSK_UNQUOTED,
	                                   NULL,
	                                   TYPE_WIRELESS,
	                                   NULL,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &routefile,
	                                   &route6file,
	                                   &error,
	                                   &ignore_error);
	ASSERT (connection != NULL,
	        "wifi-wpa-psk-unquoted-read", "failed to read %s: %s", TEST_IFCFG_WIFI_WPA_PSK_UNQUOTED, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "wifi-wpa-psk-unquoted-verify", "failed to verify %s: %s", TEST_IFCFG_WIFI_WPA_PSK_UNQUOTED, error->message);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
	        "wifi-wpa-psk-unquoted-verify-connection", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_WPA_PSK_UNQUOTED,
	        NM_SETTING_CONNECTION_SETTING_NAME);

	/* ID */
	tmp = nm_setting_connection_get_id (s_con);
	ASSERT (tmp != NULL,
	        "wifi-wpa-psk-unquoted-verify-connection", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WPA_PSK_UNQUOTED,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);
	ASSERT (strcmp (tmp, expected_id) == 0,
	        "wifi-wpa-psk-unquoted-verify-connection", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WPA_PSK_UNQUOTED,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);

	/* ===== WIRELESS SETTING ===== */

	s_wireless = nm_connection_get_setting_wireless (connection);
	ASSERT (s_wireless != NULL,
	        "wifi-wpa-psk-unquoted-verify-wireless", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_WPA_PSK_UNQUOTED,
	        NM_SETTING_WIRELESS_SETTING_NAME);

	/* ===== WIRELESS SECURITY SETTING ===== */

	s_wsec = nm_connection_get_setting_wireless_security (connection);
	ASSERT (s_wsec != NULL,
	        "wifi-wpa-psk-unquoted-verify-wireless", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_WPA_PSK_UNQUOTED,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME);

	/* PSK */
	tmp = nm_setting_wireless_security_get_psk (s_wsec);
	ASSERT (tmp != NULL,
	        "wifi-wpa-psk-unquoted-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WPA_PSK_UNQUOTED,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_PSK);
	ASSERT (strcmp (tmp, expected_psk) == 0,
	        "wifi-wpa-psk-unquoted-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WPA_PSK_UNQUOTED,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_PSK);

	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
}

#define TEST_IFCFG_WIFI_WPA_PSK_UNQUOTED2 TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wifi-wpa-psk-unquoted2"

static void
test_read_wifi_wpa_psk_unquoted2 (void)
{
	NMConnection *connection;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;

	/* Ensure a quoted 64-character WPA passphrase will fail since passphrases
	 * must be between 8 and 63 ASCII characters inclusive per the WPA spec.
	 */

	connection = connection_from_file (TEST_IFCFG_WIFI_WPA_PSK_UNQUOTED2,
	                                   NULL,
	                                   TYPE_WIRELESS,
	                                   NULL,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &routefile,
	                                   &route6file,
	                                   &error,
	                                   &ignore_error);
	ASSERT (connection == NULL,
	        "wifi-wpa-psk-unquoted-read", "unexpected success reading %s", TEST_IFCFG_WIFI_WPA_PSK_UNQUOTED2);
	g_clear_error (&error);

	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
}

#define TEST_IFCFG_WIFI_WPA_PSK_ADHOC TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wifi-wpa-psk-adhoc"

static void
test_read_wifi_wpa_psk_adhoc (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	NMSettingWirelessSecurity *s_wsec;
	NMSettingIP4Config *s_ip4;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	const char *tmp;
	const char *expected_id = "System blahblah (test-wifi-wpa-psk-adhoc)";
	const char *expected_mode = "adhoc";
	const char *expected_key_mgmt = "wpa-none";
	const char *expected_psk = "I wonder what the king is doing tonight?";
	const char *expected_group = "ccmp";
	const char *expected_proto = "wpa";

	connection = connection_from_file (TEST_IFCFG_WIFI_WPA_PSK_ADHOC,
	                                   NULL,
	                                   TYPE_WIRELESS,
	                                   NULL,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &routefile,
	                                   &route6file,
	                                   &error,
	                                   &ignore_error);
	ASSERT (connection != NULL,
	        "wifi-wpa-psk-adhoc-read", "failed to read %s: %s", TEST_IFCFG_WIFI_WPA_PSK_ADHOC, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "wifi-wpa-psk-adhoc-verify", "failed to verify %s: %s", TEST_IFCFG_WIFI_WPA_PSK_ADHOC, error->message);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
	        "wifi-wpa-psk-adhoc-verify-connection", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_WPA_PSK_ADHOC,
	        NM_SETTING_CONNECTION_SETTING_NAME);

	/* ID */
	tmp = nm_setting_connection_get_id (s_con);
	ASSERT (tmp != NULL,
	        "wifi-wpa-psk-adhoc-verify-connection", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WPA_PSK_ADHOC,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);
	ASSERT (strcmp (tmp, expected_id) == 0,
	        "wifi-wpa-psk-adhoc-verify-connection", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WPA_PSK_ADHOC,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);

	/* ===== WIRELESS SETTING ===== */

	s_wireless = nm_connection_get_setting_wireless (connection);
	ASSERT (s_wireless != NULL,
	        "wifi-wpa-psk-adhoc-verify-wireless", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_WPA_PSK_ADHOC,
	        NM_SETTING_WIRELESS_SETTING_NAME);

	/* Mode */
	tmp = nm_setting_wireless_get_mode (s_wireless);
	ASSERT (tmp != NULL,
	        "wifi-wpa-psk-adhoc-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WPA_PSK_ADHOC,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_MODE);
	ASSERT (strcmp (tmp, expected_mode) == 0,
	        "wifi-wpa-psk-adhoc-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WPA_PSK_ADHOC,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_MODE);

	/* ===== WIRELESS SECURITY SETTING ===== */

	s_wsec = nm_connection_get_setting_wireless_security (connection);
	ASSERT (s_wsec != NULL,
	        "wifi-wpa-psk-adhoc-verify-wireless", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_WPA_PSK_ADHOC,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME);

	/* Key management */
	tmp = nm_setting_wireless_security_get_key_mgmt (s_wsec);
	ASSERT (tmp != NULL,
	        "wifi-wpa-psk-adhoc-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WPA_PSK_ADHOC,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_KEY_MGMT);
	ASSERT (strcmp (tmp, expected_key_mgmt) == 0,
	        "wifi-wpa-psk-adhoc-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WPA_PSK_ADHOC,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_KEY_MGMT);

	/* PSK */
	tmp = nm_setting_wireless_security_get_psk (s_wsec);
	ASSERT (tmp != NULL,
	        "wifi-wpa-psk-adhoc-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WPA_PSK_ADHOC,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_PSK);
	ASSERT (strcmp (tmp, expected_psk) == 0,
	        "wifi-wpa-psk-adhoc-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WPA_PSK_ADHOC,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_PSK);

	/* Pairwise cipher: unused in adhoc mode */
	ASSERT (nm_setting_wireless_security_get_num_pairwise (s_wsec) == 0,
	        "wifi-wpa-psk-adhoc-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WPA_PSK_ADHOC,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_PAIRWISE);

	/* Group cipher */
	ASSERT (nm_setting_wireless_security_get_num_groups (s_wsec) == 1,
	        "wifi-wpa-psk-adhoc-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WPA_PSK_ADHOC,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_GROUP);

	tmp = nm_setting_wireless_security_get_group (s_wsec, 0);
	ASSERT (tmp != NULL,
	        "wifi-wpa-psk-adhoc-verify-wireless", "failed to verify %s: missing group cipher",
	        TEST_IFCFG_WIFI_WPA_PSK_ADHOC);
	ASSERT (strcmp (tmp, expected_group) == 0,
	        "wifi-wpa-psk-adhoc-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WPA_PSK_ADHOC,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_GROUP);

	/* Protocols */
	ASSERT (nm_setting_wireless_security_get_num_protos (s_wsec) == 1,
	        "wifi-wpa-psk-adhoc-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WPA_PSK_ADHOC,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_PROTO);
	tmp = nm_setting_wireless_security_get_proto (s_wsec, 0);
	ASSERT (tmp != NULL,
	        "wifi-wpa-psk-adhoc-verify-wireless", "failed to verify %s: missing proto",
	        TEST_IFCFG_WIFI_WPA_PSK_ADHOC);
	ASSERT (strcmp (tmp, expected_proto) == 0,
	        "wifi-wpa-psk-adhoc-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WPA_PSK_ADHOC,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_PROTO);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	ASSERT (s_ip4 != NULL,
	        "wifi-wpa-psk-adhoc-verify-ip4", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_WPA_PSK_ADHOC,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME);

	/* Method */
	tmp = nm_setting_ip4_config_get_method (s_ip4);
	ASSERT (strcmp (tmp, NM_SETTING_IP4_CONFIG_METHOD_AUTO) == 0,
	        "wifi-wpa-psk-adhoc-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WPA_PSK_ADHOC,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_METHOD);

	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
}

#define TEST_IFCFG_WIFI_WPA_PSK_HEX TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wifi-wpa-psk-hex"

static void
test_read_wifi_wpa_psk_hex (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	NMSettingWirelessSecurity *s_wsec;
	NMSettingIP4Config *s_ip4;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	const char *tmp;
	const GByteArray *array;
	const char *expected_id = "System blahblah (test-wifi-wpa-psk-hex)";
	const char *expected_ssid = "blahblah";
	const char *expected_key_mgmt = "wpa-psk";
	const char *expected_psk = "1da190379817bc360dda52e85c388c439a21ea5c7bf819c64e9da051807deae6";

	connection = connection_from_file (TEST_IFCFG_WIFI_WPA_PSK_HEX,
	                                   NULL,
	                                   TYPE_WIRELESS,
	                                   NULL,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &routefile,
	                                   &route6file,
	                                   &error,
	                                   &ignore_error);
	ASSERT (connection != NULL,
	        "wifi-wpa-psk-hex-read", "failed to read %s: %s", TEST_IFCFG_WIFI_WPA_PSK_HEX, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "wifi-wpa-psk-hex-verify", "failed to verify %s: %s", TEST_IFCFG_WIFI_WPA_PSK_HEX, error->message);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
	        "wifi-wpa-psk-hex-verify-connection", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_WPA_PSK_HEX,
	        NM_SETTING_CONNECTION_SETTING_NAME);

	/* ID */
	tmp = nm_setting_connection_get_id (s_con);
	ASSERT (tmp != NULL,
	        "wifi-wpa-psk-hex-verify-connection", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WPA_PSK_HEX,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);
	ASSERT (strcmp (tmp, expected_id) == 0,
	        "wifi-wpa-psk-hex-verify-connection", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WPA_PSK_HEX,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);

	/* ===== WIRELESS SETTING ===== */

	s_wireless = nm_connection_get_setting_wireless (connection);
	ASSERT (s_wireless != NULL,
	        "wifi-wpa-psk-hex-verify-wireless", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_WPA_PSK_HEX,
	        NM_SETTING_WIRELESS_SETTING_NAME);

	/* SSID */
	array = nm_setting_wireless_get_ssid (s_wireless);
	ASSERT (array != NULL,
	        "wifi-wpa-psk-hex-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WPA_PSK_HEX,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_SSID);
	ASSERT (array->len == strlen (expected_ssid),
	        "wifi-wpa-psk-hex-verify-wireless", "failed to verify %s: unexpected %s / %s key value length",
	        TEST_IFCFG_WIFI_WPA_PSK_HEX,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_SSID);
	ASSERT (memcmp (array->data, expected_ssid, strlen (expected_ssid)) == 0,
	        "wifi-wpa-psk-hex-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WPA_PSK_HEX,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_SSID);

	/* ===== WIRELESS SECURITY SETTING ===== */

	s_wsec = nm_connection_get_setting_wireless_security (connection);
	ASSERT (s_wsec != NULL,
	        "wifi-wpa-psk-hex-verify-wireless", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_WPA_PSK_HEX,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME);

	/* Key management */
	tmp = nm_setting_wireless_security_get_key_mgmt (s_wsec);
	ASSERT (tmp != NULL,
	        "wifi-wpa-psk-hex-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WPA_PSK_HEX,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_KEY_MGMT);
	ASSERT (strcmp (tmp, expected_key_mgmt) == 0,
	        "wifi-wpa-psk-hex-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WPA_PSK_HEX,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_KEY_MGMT);

	/* PSK */
	tmp = nm_setting_wireless_security_get_psk (s_wsec);
	ASSERT (tmp != NULL,
	        "wifi-wpa-psk-hex-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WPA_PSK_HEX,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_PSK);
	ASSERT (strcmp (tmp, expected_psk) == 0,
	        "wifi-wpa-psk-hex-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WPA_PSK_HEX,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_PSK);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	ASSERT (s_ip4 != NULL,
	        "wifi-wpa-psk-hex-verify-ip4", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_WPA_PSK_HEX,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME);

	/* Method */
	tmp = nm_setting_ip4_config_get_method (s_ip4);
	ASSERT (strcmp (tmp, NM_SETTING_IP4_CONFIG_METHOD_AUTO) == 0,
	        "wifi-wpa-psk-hex-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WPA_PSK_HEX,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_METHOD);

	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
}

#define TEST_IFCFG_WIFI_WPA_EAP_TLS TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wifi-wpa-eap-tls"
#define TEST_IFCFG_WIFI_WPA_EAP_TLS_CA_CERT TEST_IFCFG_DIR"/network-scripts/test_ca_cert.pem"
#define TEST_IFCFG_WIFI_WPA_EAP_TLS_CLIENT_CERT TEST_IFCFG_DIR"/network-scripts/test1_key_and_cert.pem"
#define TEST_IFCFG_WIFI_WPA_EAP_TLS_PRIVATE_KEY TEST_IFCFG_DIR"/network-scripts/test1_key_and_cert.pem"

static void
test_read_wifi_wpa_eap_tls (void)
{
	NMConnection *connection;
	NMSettingWireless *s_wireless;
	NMSettingIP4Config *s_ip4;
	NMSetting8021x *s_8021x;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	const char *tmp, *password;
	const char *expected_identity = "Bill Smith";
	const char *expected_privkey_password = "test1";

	connection = connection_from_file (TEST_IFCFG_WIFI_WPA_EAP_TLS,
	                                   NULL,
	                                   TYPE_ETHERNET,
	                                   NULL,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &routefile,
	                                   &route6file,
	                                   &error,
	                                   &ignore_error);
	ASSERT (connection != NULL,
	        "wifi-wpa-eap-tls-read", "failed to read %s: %s", TEST_IFCFG_WIFI_WPA_EAP_TLS, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "wifi-wpa-eap-tls-verify", "failed to verify %s: %s", TEST_IFCFG_WIFI_WPA_EAP_TLS, error->message);

	ASSERT (unmanaged == NULL,
	        "wifi-wpa-eap-tls-verify", "failed to verify %s: unexpected unmanaged value", TEST_IFCFG_WIFI_WPA_EAP_TLS);

	/* ===== WIRELESS SETTING ===== */

	s_wireless = nm_connection_get_setting_wireless (connection);
	ASSERT (s_wireless != NULL,
	        "wifi-wpa-eap-tls-verify-wireless", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_WPA_EAP_TLS,
	        NM_SETTING_WIRELESS_SETTING_NAME);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	ASSERT (s_ip4 != NULL,
	        "wifi-wpa-eap-tls-verify-ip4", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_WPA_EAP_TLS,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME);

	/* Method */
	tmp = nm_setting_ip4_config_get_method (s_ip4);
	ASSERT (strcmp (tmp, NM_SETTING_IP4_CONFIG_METHOD_AUTO) == 0,
	        "wifi-wpa-eap-tls-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WPA_EAP_TLS,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_METHOD);

	/* ===== 802.1x SETTING ===== */
	s_8021x = nm_connection_get_setting_802_1x (connection);
	ASSERT (s_8021x != NULL,
	        "wifi-wpa-eap-tls-verify-8021x", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_WPA_EAP_TLS,
	        NM_SETTING_802_1X_SETTING_NAME);

	/* EAP methods */
	ASSERT (nm_setting_802_1x_get_num_eap_methods (s_8021x) == 1,
	        "wifi-wpa-eap-tls-verify-8021x", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WPA_EAP_TLS,
	        NM_SETTING_802_1X_SETTING_NAME,
	        NM_SETTING_802_1X_EAP);
	tmp = nm_setting_802_1x_get_eap_method (s_8021x, 0);
	ASSERT (tmp != NULL,
	        "wifi-wpa-eap-tls-verify-8021x", "failed to verify %s: missing %s / %s eap method",
	        TEST_IFCFG_WIFI_WPA_EAP_TLS,
	        NM_SETTING_802_1X_SETTING_NAME,
	        NM_SETTING_802_1X_EAP);
	ASSERT (strcmp (tmp, "tls") == 0,
	        "wifi-wpa-eap-tls-verify-8021x", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WPA_EAP_TLS,
	        NM_SETTING_802_1X_SETTING_NAME,
	        NM_SETTING_802_1X_EAP);

	/* Identity */
	tmp = nm_setting_802_1x_get_identity (s_8021x);
	ASSERT (tmp != NULL,
	        "wifi-wpa-eap-tls-verify-8021x", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WPA_EAP_TLS,
	        NM_SETTING_802_1X_SETTING_NAME,
	        NM_SETTING_802_1X_IDENTITY);
	ASSERT (strcmp (tmp, expected_identity) == 0,
	        "wifi-wpa-eap-tls-verify-8021x", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WPA_EAP_TLS,
	        NM_SETTING_802_1X_SETTING_NAME,
	        NM_SETTING_802_1X_IDENTITY);

	/* CA Cert */
	verify_cert_or_key (s_8021x,
	                    TEST_IFCFG_WIFI_WPA_EAP_TLS_CA_CERT,
	                    NULL,
	                    NM_SETTING_802_1X_CA_CERT);

	/* Client Cert */
	verify_cert_or_key (s_8021x,
	                    TEST_IFCFG_WIFI_WPA_EAP_TLS_CLIENT_CERT,
	                    NULL,
	                    NM_SETTING_802_1X_CLIENT_CERT);

	/* Private Key Password */
	password = nm_setting_802_1x_get_private_key_password (s_8021x);
	ASSERT (password != NULL,
	        "wifi-wpa-eap-tls-verify-8021x", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WPA_EAP_TLS,
	        NM_SETTING_802_1X_SETTING_NAME,
	        NM_SETTING_802_1X_PRIVATE_KEY_PASSWORD);

	ASSERT (strcmp (password, expected_privkey_password) == 0,
	        "wifi-wpa-eap-tls-verify-8021x", "failed to verify %s: unexpected %s / %s key",
	        TEST_IFCFG_WIFI_WPA_EAP_TLS,
	        NM_SETTING_802_1X_SETTING_NAME,
	        NM_SETTING_802_1X_PRIVATE_KEY_PASSWORD);

	/* Private key */
	verify_cert_or_key (s_8021x,
	                    TEST_IFCFG_WIFI_WPA_EAP_TLS_PRIVATE_KEY,
	                    expected_privkey_password,
	                    NM_SETTING_802_1X_PRIVATE_KEY);

	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
}

#define TEST_IFCFG_WIFI_WPA_EAP_TTLS_TLS TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wifi-wpa-eap-ttls-tls"
#define TEST_IFCFG_WIFI_WPA_EAP_TTLS_TLS_CA_CERT TEST_IFCFG_DIR"/network-scripts/test_ca_cert.pem"
/* Also use TLS defines from the previous test */

static void
test_read_wifi_wpa_eap_ttls_tls (void)
{
	NMConnection *connection;
	NMSettingWireless *s_wireless;
	NMSettingIP4Config *s_ip4;
	NMSetting8021x *s_8021x;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	const char *tmp, *password;
	const char *expected_identity = "Chuck Shumer";
	const char *expected_privkey_password = "test1";

	connection = connection_from_file (TEST_IFCFG_WIFI_WPA_EAP_TTLS_TLS,
	                                   NULL,
	                                   TYPE_WIRELESS,
	                                   NULL,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &routefile,
	                                   &route6file,
	                                   &error,
	                                   &ignore_error);
	ASSERT (connection != NULL,
	        "wifi-wpa-eap-ttls-tls-read", "failed to read %s: %s", TEST_IFCFG_WIFI_WPA_EAP_TTLS_TLS, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "wifi-wpa-eap-ttls-tls-verify", "failed to verify %s: %s", TEST_IFCFG_WIFI_WPA_EAP_TTLS_TLS, error->message);

	ASSERT (unmanaged == NULL,
	        "wifi-wpa-eap-ttls-tls-verify", "failed to verify %s: unexpected unmanaged value", TEST_IFCFG_WIFI_WPA_EAP_TTLS_TLS);

	/* ===== WIRELESS SETTING ===== */

	s_wireless = nm_connection_get_setting_wireless (connection);
	ASSERT (s_wireless != NULL,
	        "wifi-wpa-eap-ttls-tls-verify-wireless", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_WPA_EAP_TTLS_TLS,
	        NM_SETTING_WIRELESS_SETTING_NAME);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	ASSERT (s_ip4 != NULL,
	        "wifi-wpa-eap-ttls-tls-verify-ip4", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_WPA_EAP_TTLS_TLS,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME);

	/* Method */
	tmp = nm_setting_ip4_config_get_method (s_ip4);
	ASSERT (strcmp (tmp, NM_SETTING_IP4_CONFIG_METHOD_AUTO) == 0,
	        "wifi-wpa-eap-ttls-tls-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WPA_EAP_TTLS_TLS,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_METHOD);

	/* ===== 802.1x SETTING ===== */
	s_8021x = nm_connection_get_setting_802_1x (connection);
	ASSERT (s_8021x != NULL,
	        "wifi-wpa-eap-ttls-tls-verify-8021x", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_WPA_EAP_TTLS_TLS,
	        NM_SETTING_802_1X_SETTING_NAME);

	/* EAP methods */
	ASSERT (nm_setting_802_1x_get_num_eap_methods (s_8021x) == 1,
	        "wifi-wpa-eap-ttls-tls-verify-8021x", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WPA_EAP_TTLS_TLS,
	        NM_SETTING_802_1X_SETTING_NAME,
	        NM_SETTING_802_1X_EAP);
	tmp = nm_setting_802_1x_get_eap_method (s_8021x, 0);
	ASSERT (tmp != NULL,
	        "wifi-wpa-eap-ttls-tls-verify-8021x", "failed to verify %s: missing %s / %s eap method",
	        TEST_IFCFG_WIFI_WPA_EAP_TTLS_TLS,
	        NM_SETTING_802_1X_SETTING_NAME,
	        NM_SETTING_802_1X_EAP);
	ASSERT (strcmp (tmp, "ttls") == 0,
	        "wifi-wpa-eap-ttls-tls-verify-8021x", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WPA_EAP_TTLS_TLS,
	        NM_SETTING_802_1X_SETTING_NAME,
	        NM_SETTING_802_1X_EAP);

	/* CA Cert */
	verify_cert_or_key (s_8021x,
	                    TEST_IFCFG_WIFI_WPA_EAP_TTLS_TLS_CA_CERT,
	                    NULL,
	                    NM_SETTING_802_1X_CA_CERT);

	/* Inner auth method */
	tmp = nm_setting_802_1x_get_phase2_autheap (s_8021x);
	ASSERT (tmp != NULL,
	        "wifi-wpa-eap-ttls-tls-verify-8021x", "failed to verify %s: missing %s / %s eap method",
	        TEST_IFCFG_WIFI_WPA_EAP_TTLS_TLS,
	        NM_SETTING_802_1X_SETTING_NAME,
	        NM_SETTING_802_1X_PHASE2_AUTHEAP);
	ASSERT (strcmp (tmp, "tls") == 0,
	        "wifi-wpa-eap-ttls-tls-verify-8021x", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WPA_EAP_TTLS_TLS,
	        NM_SETTING_802_1X_SETTING_NAME,
	        NM_SETTING_802_1X_PHASE2_AUTHEAP);

	/* Inner CA Cert */
	verify_cert_or_key (s_8021x,
	                    TEST_IFCFG_WIFI_WPA_EAP_TLS_CA_CERT,
	                    NULL,
	                    NM_SETTING_802_1X_PHASE2_CA_CERT);

	/* Inner Client Cert */
	verify_cert_or_key (s_8021x,
	                    TEST_IFCFG_WIFI_WPA_EAP_TLS_CLIENT_CERT,
	                    NULL,
	                    NM_SETTING_802_1X_PHASE2_CLIENT_CERT);

	/* Inner Private Key Password */
	password = nm_setting_802_1x_get_phase2_private_key_password (s_8021x);
	ASSERT (password != NULL,
	        "wifi-wpa-eap-ttls-tls-verify-8021x", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WPA_EAP_TTLS_TLS,
	        NM_SETTING_802_1X_SETTING_NAME,
	        NM_SETTING_802_1X_PHASE2_PRIVATE_KEY_PASSWORD);

	ASSERT (strcmp (password, expected_privkey_password) == 0,
	        "wifi-wpa-eap-ttls-tls-verify-8021x", "failed to verify %s: unexpected %s / %s key",
	        TEST_IFCFG_WIFI_WPA_EAP_TTLS_TLS,
	        NM_SETTING_802_1X_SETTING_NAME,
	        NM_SETTING_802_1X_PHASE2_PRIVATE_KEY_PASSWORD);

	/* Inner private key */
	verify_cert_or_key (s_8021x,
	                    TEST_IFCFG_WIFI_WPA_EAP_TLS_PRIVATE_KEY,
	                    expected_privkey_password,
	                    NM_SETTING_802_1X_PHASE2_PRIVATE_KEY);

	/* Identity */
	tmp = nm_setting_802_1x_get_identity (s_8021x);
	ASSERT (tmp != NULL,
	        "wifi-wpa-eap-ttls-tls-verify-8021x", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WPA_EAP_TTLS_TLS,
	        NM_SETTING_802_1X_SETTING_NAME,
	        NM_SETTING_802_1X_IDENTITY);
	ASSERT (strcmp (tmp, expected_identity) == 0,
	        "wifi-wpa-eap-ttls-tls-verify-8021x", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WPA_EAP_TTLS_TLS,
	        NM_SETTING_802_1X_SETTING_NAME,
	        NM_SETTING_802_1X_IDENTITY);

	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
}

#define TEST_IFCFG_WIFI_DYNAMIC_WEP_LEAP TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wifi-dynamic-wep-leap"

static void
test_read_wifi_dynamic_wep_leap (void)
{
	NMConnection *connection;
	NMSettingWireless *s_wifi;
	NMSettingWirelessSecurity *s_wsec;
	NMSetting8021x *s_8021x;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE, success;
	GError *error = NULL;

	connection = connection_from_file (TEST_IFCFG_WIFI_DYNAMIC_WEP_LEAP,
	                                   NULL,
	                                   TYPE_WIRELESS,
	                                   NULL,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &routefile,
	                                   &route6file,
	                                   &error,
	                                   &ignore_error);
	g_assert_no_error (error);
	g_assert (connection);

	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	/* ===== WIRELESS SETTING ===== */

	s_wifi = nm_connection_get_setting_wireless (connection);
	g_assert (s_wifi);

	/* ===== WiFi SECURITY SETTING ===== */
	s_wsec = nm_connection_get_setting_wireless_security (connection);
	g_assert (s_wsec);

	/* Key management */
	g_assert_cmpstr (nm_setting_wireless_security_get_key_mgmt (s_wsec), ==, "ieee8021x");

	/* Auth alg should be NULL (open) for dynamic WEP with LEAP as the EAP method;
	 * only "old-school" LEAP uses 'leap' for the auth alg.
	 */
	g_assert_cmpstr (nm_setting_wireless_security_get_auth_alg (s_wsec), ==, NULL);

	/* Expect no old-school LEAP username/password, that'll be in the 802.1x setting */
	g_assert_cmpstr (nm_setting_wireless_security_get_leap_username (s_wsec), ==, NULL);
	g_assert_cmpstr (nm_setting_wireless_security_get_leap_password (s_wsec), ==, NULL);

	/* ===== 802.1x SETTING ===== */
	s_8021x = nm_connection_get_setting_802_1x (connection);
	g_assert (s_8021x);

	/* EAP method should be "leap" */
	g_assert_cmpint (nm_setting_802_1x_get_num_eap_methods (s_8021x), ==, 1);
	g_assert_cmpstr (nm_setting_802_1x_get_eap_method (s_8021x, 0), ==, "leap");

	/* username & password */
	g_assert_cmpstr (nm_setting_802_1x_get_identity (s_8021x), ==, "bill smith");
	g_assert_cmpstr (nm_setting_802_1x_get_password (s_8021x), ==, "foobar baz");

	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
}

#define TEST_IFCFG_WIFI_WEP_EAP_TTLS_CHAP TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wifi-wep-eap-ttls-chap"
#define TEST_IFCFG_WIFI_WEP_EAP_TTLS_CHAP_CA_CERT TEST_IFCFG_DIR"/network-scripts/test_ca_cert.pem"

static void
test_read_wifi_wep_eap_ttls_chap (void)
{
	NMConnection *connection;
	NMSettingWireless *s_wireless;
	NMSettingWirelessSecurity *s_wsec;
	NMSettingIP4Config *s_ip4;
	NMSetting8021x *s_8021x;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	const char *tmp;
	const char *expected_password = "foobar baz";
	const char *expected_identity = "David Smith";
	const char *expected_key_mgmt = "ieee8021x";

	connection = connection_from_file (TEST_IFCFG_WIFI_WEP_EAP_TTLS_CHAP,
	                                   NULL,
	                                   TYPE_WIRELESS,
	                                   NULL,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &routefile,
	                                   &route6file,
	                                   &error,
	                                   &ignore_error);
	ASSERT (connection != NULL,
	        "wifi-wep-eap-ttls-chap-read", "failed to read %s: %s", TEST_IFCFG_WIFI_WEP_EAP_TTLS_CHAP, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "wifi-wep-eap-ttls-chap-verify", "failed to verify %s: %s", TEST_IFCFG_WIFI_WEP_EAP_TTLS_CHAP, error->message);

	ASSERT (unmanaged == NULL,
	        "wifi-wep-eap-ttls-chap-verify", "failed to verify %s: unexpected unmanaged value", TEST_IFCFG_WIFI_WEP_EAP_TTLS_CHAP);

	/* ===== WIRELESS SETTING ===== */

	s_wireless = nm_connection_get_setting_wireless (connection);
	ASSERT (s_wireless != NULL,
	        "wifi-wep-eap-ttls-chap-verify-wireless", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_WEP_EAP_TTLS_CHAP,
	        NM_SETTING_WIRELESS_SETTING_NAME);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	ASSERT (s_ip4 != NULL,
	        "wifi-wep-eap-ttls-chap-verify-ip4", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_WEP_EAP_TTLS_CHAP,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME);

	/* Method */
	tmp = nm_setting_ip4_config_get_method (s_ip4);
	ASSERT (strcmp (tmp, NM_SETTING_IP4_CONFIG_METHOD_AUTO) == 0,
	        "wifi-wep-eap-ttls-chap-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WEP_EAP_TTLS_CHAP,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_METHOD);

	/* ===== 802.1x SETTING ===== */
	s_wsec = nm_connection_get_setting_wireless_security (connection);
	ASSERT (s_wsec != NULL,
	        "wifi-wep-eap-ttls-chap-verify-wireless-security", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_WEP_EAP_TTLS_CHAP,
	        NM_SETTING_802_1X_SETTING_NAME);

	/* Key management */
	tmp = nm_setting_wireless_security_get_key_mgmt (s_wsec);
	ASSERT (tmp != NULL,
	        "wifi-wep-eap-ttls-chap-verify-wireless-security", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WPA_PSK,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_KEY_MGMT);
	ASSERT (strcmp (tmp, expected_key_mgmt) == 0,
	        "wifi-wep-eap-ttls-chap-verify-wireless-security", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WPA_PSK,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_KEY_MGMT);

	/* ===== 802.1x SETTING ===== */
	s_8021x = nm_connection_get_setting_802_1x (connection);
	ASSERT (s_8021x != NULL,
	        "wifi-wep-eap-ttls-chap-verify-8021x", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_WEP_EAP_TTLS_CHAP,
	        NM_SETTING_802_1X_SETTING_NAME);

	/* EAP methods */
	ASSERT (nm_setting_802_1x_get_num_eap_methods (s_8021x) == 1,
	        "wifi-wep-eap-ttls-chap-verify-8021x", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WEP_EAP_TTLS_CHAP,
	        NM_SETTING_802_1X_SETTING_NAME,
	        NM_SETTING_802_1X_EAP);
	tmp = nm_setting_802_1x_get_eap_method (s_8021x, 0);
	ASSERT (tmp != NULL,
	        "wifi-wep-eap-ttls-chap-verify-8021x", "failed to verify %s: missing %s / %s eap method",
	        TEST_IFCFG_WIFI_WEP_EAP_TTLS_CHAP,
	        NM_SETTING_802_1X_SETTING_NAME,
	        NM_SETTING_802_1X_EAP);
	ASSERT (strcmp (tmp, "ttls") == 0,
	        "wifi-wep-eap-ttls-chap-verify-8021x", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WEP_EAP_TTLS_CHAP,
	        NM_SETTING_802_1X_SETTING_NAME,
	        NM_SETTING_802_1X_EAP);

	/* CA Cert */
	verify_cert_or_key (s_8021x,
	                    TEST_IFCFG_WIFI_WEP_EAP_TTLS_CHAP_CA_CERT,
	                    NULL,
	                    NM_SETTING_802_1X_CA_CERT);

	/* Inner auth method */
	tmp = nm_setting_802_1x_get_phase2_auth (s_8021x);
	ASSERT (tmp != NULL,
	        "wifi-wep-eap-ttls-chap-verify-8021x", "failed to verify %s: missing %s / %s eap method",
	        TEST_IFCFG_WIFI_WEP_EAP_TTLS_CHAP,
	        NM_SETTING_802_1X_SETTING_NAME,
	        NM_SETTING_802_1X_PHASE2_AUTH);
	ASSERT (strcmp (tmp, "chap") == 0,
	        "wifi-wep-eap-ttls-chap-verify-8021x", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WEP_EAP_TTLS_CHAP,
	        NM_SETTING_802_1X_SETTING_NAME,
	        NM_SETTING_802_1X_PHASE2_AUTH);

	/* Password */
	tmp = nm_setting_802_1x_get_identity (s_8021x);
	ASSERT (tmp != NULL,
	        "wifi-wep-eap-ttls-chap-verify-8021x", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WEP_EAP_TTLS_CHAP,
	        NM_SETTING_802_1X_SETTING_NAME,
	        NM_SETTING_802_1X_IDENTITY);
	ASSERT (strcmp (tmp, expected_identity) == 0,
	        "wifi-wep-eap-ttls-chap-verify-8021x", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WEP_EAP_TTLS_CHAP,
	        NM_SETTING_802_1X_SETTING_NAME,
	        NM_SETTING_802_1X_IDENTITY);

	/* Password */
	tmp = nm_setting_802_1x_get_password (s_8021x);
	ASSERT (tmp != NULL,
	        "wifi-wep-eap-ttls-chap-verify-8021x", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WEP_EAP_TTLS_CHAP,
	        NM_SETTING_802_1X_SETTING_NAME,
	        NM_SETTING_802_1X_PASSWORD);
	ASSERT (strcmp (tmp, expected_password) == 0,
	        "wifi-wep-eap-ttls-chap-verify-8021x", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WEP_EAP_TTLS_CHAP,
	        NM_SETTING_802_1X_SETTING_NAME,
	        NM_SETTING_802_1X_PASSWORD);

	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
}

static void
test_read_wifi_hidden (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wifi;
	gboolean success;
	GError *error = NULL;

	connection = connection_from_file (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wifi-hidden",
	                                   NULL, TYPE_WIRELESS, NULL, NULL, NULL, NULL, NULL, &error, NULL);
	g_assert_no_error (error);
	g_assert (connection);

	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_connection_type (s_con), ==, NM_SETTING_WIRELESS_SETTING_NAME);

	s_wifi = nm_connection_get_setting_wireless (connection);
	g_assert (s_wifi);
	g_assert (nm_setting_wireless_get_hidden (s_wifi) == TRUE);

	g_object_unref (connection);
}

static void
test_write_wifi_hidden (void)
{
	NMConnection *connection, *reread;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wifi;
	char *uuid, *testfile = NULL, *val;
	gboolean success;
	GError *error = NULL;
	shvarFile *f;
	GByteArray *ssid;
	const unsigned char ssid_data[] = { 0x54, 0x65, 0x73, 0x74, 0x20, 0x53, 0x53, 0x49, 0x44 };

	connection = nm_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write WiFi Hidden",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRELESS_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* Wifi setting */
	s_wifi = (NMSettingWireless *) nm_setting_wireless_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wifi));

	ssid = g_byte_array_sized_new (sizeof (ssid_data));
	g_byte_array_append (ssid, ssid_data, sizeof (ssid_data));

	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_MODE, "infrastructure",
	              NM_SETTING_WIRELESS_HIDDEN, TRUE,
	              NULL);

	g_byte_array_free (ssid, TRUE);

	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	/* Save the ifcfg */
	success = writer_new_connection (connection,
	                                 TEST_SCRATCH_DIR "/network-scripts/",
	                                 &testfile,
	                                 &error);
	g_assert_no_error (error);
	g_assert (success);

	f = svOpenFile (testfile, &error);
	g_assert_no_error (error);
	g_assert (f);

	/* re-read the file to check that what key was written. */
	val = svGetValue (f, "SSID_HIDDEN", FALSE);
	g_assert (val);
	g_assert_cmpstr (val, ==, "yes");
	g_free (val);
	svCloseFile (f);

	/* reread will be normalized, so we must normalize connection too. */
	nm_utils_normalize_connection (connection, TRUE);

	/* re-read the connection for comparison */
	reread = connection_from_file (testfile, NULL, TYPE_WIRELESS, NULL,
	                               NULL, NULL, NULL, NULL, &error, NULL);
	unlink (testfile);
	g_assert_no_error (error);
	g_assert (reread);

	success = nm_connection_verify (reread, &error);
	g_assert_no_error (error);
	g_assert (success);

	g_assert (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT));

	g_free (testfile);
	g_object_unref (connection);
	g_object_unref (reread);
}

#define TEST_IFCFG_WIRED_QETH_STATIC TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-qeth-static"

static void
test_read_wired_qeth_static (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIP4Config *s_ip4;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	const char *tmp;
	const char *expected_id = "System test-wired-qeth-static";
	const GByteArray *array;
	const char *expected_channel0 = "0.0.0600";
	const char *expected_channel1 = "0.0.0601";
	const char *expected_channel2 = "0.0.0602";
	const GPtrArray *subchannels;

	connection = connection_from_file (TEST_IFCFG_WIRED_QETH_STATIC,
	                                   NULL,
	                                   TYPE_ETHERNET,
	                                   NULL,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &routefile,
	                                   &route6file,
	                                   &error,
	                                   &ignore_error);
	ASSERT (connection != NULL,
	        "wired-qeth-static-read", "failed to read %s: %s", TEST_IFCFG_WIRED_QETH_STATIC, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "wired-qeth-static-verify", "failed to verify %s: %s", TEST_IFCFG_WIRED_QETH_STATIC, error->message);

	ASSERT (unmanaged == NULL,
	        "wired-qeth-static-verify", "failed to verify %s: unexpected unmanaged value", TEST_IFCFG_WIRED_QETH_STATIC);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
	        "wired-qeth-static-verify-connection", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIRED_QETH_STATIC,
	        NM_SETTING_CONNECTION_SETTING_NAME);

	/* ID */
	tmp = nm_setting_connection_get_id (s_con);
	ASSERT (tmp != NULL,
	        "wired-qeth-static-verify-connection", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIRED_QETH_STATIC,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);
	ASSERT (strcmp (tmp, expected_id) == 0,
	        "wired-qeth-static-verify-connection", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_QETH_STATIC,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);

	/* ===== WIRED SETTING ===== */

	s_wired = nm_connection_get_setting_wired (connection);
	ASSERT (s_wired != NULL,
	        "wired-qeth-static-verify-wired", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIRED_QETH_STATIC,
	        NM_SETTING_WIRED_SETTING_NAME);

	/* MAC address */
	array = nm_setting_wired_get_mac_address (s_wired);
	ASSERT (array == NULL,
	        "wired-qeth-static-verify-wired", "failed to verify %s: unexpected %s / %s key",
	        TEST_IFCFG_WIRED_QETH_STATIC,
	        NM_SETTING_WIRED_SETTING_NAME,
	        NM_SETTING_WIRED_MAC_ADDRESS);

	/* Subchannels */
	subchannels = nm_setting_wired_get_s390_subchannels (s_wired);
	ASSERT (subchannels != NULL,
	        "wired-qeth-static-verify-wired", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIRED_QETH_STATIC,
	        NM_SETTING_WIRED_SETTING_NAME,
	        NM_SETTING_WIRED_S390_SUBCHANNELS);
	ASSERT (subchannels->len == 3,
	        "wired-qeth-static-verify-wired", "failed to verify %s: invalid %s / %s key (not 3 elements)",
	        TEST_IFCFG_WIRED_QETH_STATIC,
	        NM_SETTING_WIRED_SETTING_NAME,
	        NM_SETTING_WIRED_S390_SUBCHANNELS);

	tmp = (const char *) g_ptr_array_index (subchannels, 0);
	ASSERT (strcmp (tmp, expected_channel0) == 0,
	        "wired-qeth-static-verify-wired", "failed to verify %s: unexpected subchannel #0",
	        TEST_IFCFG_WIRED_QETH_STATIC);

	tmp = (const char *) g_ptr_array_index (subchannels, 1);
	ASSERT (strcmp (tmp, expected_channel1) == 0,
	        "wired-qeth-static-verify-wired", "failed to verify %s: unexpected subchannel #1",
	        TEST_IFCFG_WIRED_QETH_STATIC);

	tmp = (const char *) g_ptr_array_index (subchannels, 2);
	ASSERT (strcmp (tmp, expected_channel2) == 0,
	        "wired-qeth-static-verify-wired", "failed to verify %s: unexpected subchannel #2",
	        TEST_IFCFG_WIRED_QETH_STATIC);

	/* Nettype */
	tmp = nm_setting_wired_get_s390_nettype (s_wired);
	ASSERT (tmp != NULL,
	        "wired-qeth-static-verify-wired", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIRED_QETH_STATIC,
	        NM_SETTING_WIRED_SETTING_NAME,
	        NM_SETTING_WIRED_S390_NETTYPE);
	ASSERT (strcmp (tmp, "qeth") == 0,
	        "wired-qeth-static-verify-wired", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_QETH_STATIC,
	        NM_SETTING_WIRED_SETTING_NAME,
	        NM_SETTING_WIRED_S390_NETTYPE);

	/* port name */
	tmp = nm_setting_wired_get_s390_option_by_key (s_wired, "portname");
	ASSERT (tmp != NULL,
	        "wired-qeth-static-verify-wired", "failed to verify %s: missing %s s390 option 'portname'",
	        TEST_IFCFG_WIRED_QETH_STATIC,
	        NM_SETTING_WIRED_SETTING_NAME);
	ASSERT (strcmp (tmp, "OSAPORT") == 0,
	        "wired-qeth-static-verify-wired", "failed to verify %s: unexpected %s s390 option 'portname' value",
	        TEST_IFCFG_WIRED_QETH_STATIC,
	        NM_SETTING_WIRED_SETTING_NAME);

	/* port number */
	tmp = nm_setting_wired_get_s390_option_by_key (s_wired, "portno");
	ASSERT (tmp != NULL,
	        "wired-qeth-static-verify-wired", "failed to verify %s: missing %s s390 option 'portno'",
	        TEST_IFCFG_WIRED_QETH_STATIC,
	        NM_SETTING_WIRED_SETTING_NAME);
	ASSERT (strcmp (tmp, "0") == 0,
	        "wired-qeth-static-verify-wired", "failed to verify %s: unexpected %s s390 option 'portno' value",
	        TEST_IFCFG_WIRED_QETH_STATIC,
	        NM_SETTING_WIRED_SETTING_NAME);

	/* layer */
	tmp = nm_setting_wired_get_s390_option_by_key (s_wired, "layer2");
	ASSERT (tmp != NULL,
	        "wired-qeth-static-verify-wired", "failed to verify %s: missing %s s390 option 'layer2'",
	        TEST_IFCFG_WIRED_QETH_STATIC,
	        NM_SETTING_WIRED_SETTING_NAME);
	ASSERT (strcmp (tmp, "1") == 0,
	        "wired-qeth-static-verify-wired", "failed to verify %s: unexpected %s s390 option 'layer2' value",
	        TEST_IFCFG_WIRED_QETH_STATIC,
	        NM_SETTING_WIRED_SETTING_NAME);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	ASSERT (s_ip4 != NULL,
	        "wired-qeth-static-verify-ip4", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIRED_QETH_STATIC,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME);

	/* Method */
	tmp = nm_setting_ip4_config_get_method (s_ip4);
	ASSERT (strcmp (tmp, NM_SETTING_IP4_CONFIG_METHOD_MANUAL) == 0,
	        "wired-qeth-static-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_QETH_STATIC,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_METHOD);

	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
}

#define TEST_IFCFG_WIRED_CTC_STATIC TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-ctc-static"

static void
test_read_wired_ctc_static (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	const char *tmp;
	const char *expected_id = "System test-wired-ctc-static";
	const char *expected_channel0 = "0.0.1b00";
	const char *expected_channel1 = "0.0.1b01";
	const GPtrArray *subchannels;
	gboolean success;

	connection = connection_from_file (TEST_IFCFG_WIRED_CTC_STATIC,
	                                   NULL,
	                                   TYPE_ETHERNET,
	                                   NULL,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &routefile,
	                                   &route6file,
	                                   &error,
	                                   &ignore_error);
	g_assert_no_error (error);
	g_assert (connection);
	
	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);
	g_assert (unmanaged == NULL);

	/* ===== CONNECTION SETTING ===== */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con != NULL);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, expected_id);

	/* ===== WIRED SETTING ===== */
	s_wired = nm_connection_get_setting_wired (connection);
	g_assert (s_wired != NULL);

	g_assert (nm_setting_wired_get_mac_address (s_wired) == NULL);

	/* Subchannels */
	subchannels = nm_setting_wired_get_s390_subchannels (s_wired);
	g_assert (subchannels != NULL);
	g_assert_cmpint (subchannels->len, ==, 2);

	g_assert_cmpstr (g_ptr_array_index (subchannels, 0), ==, expected_channel0);
	g_assert_cmpstr (g_ptr_array_index (subchannels, 1), ==, expected_channel1);

	/* Nettype */
	g_assert_cmpstr (nm_setting_wired_get_s390_nettype (s_wired), ==, "ctc");

	/* port name */
	tmp = nm_setting_wired_get_s390_option_by_key (s_wired, "ctcprot");
	g_assert (tmp != NULL);
	g_assert_cmpstr (tmp, ==, "0");

	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
}

#define TEST_IFCFG_WIFI_WEP_NO_KEYS TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wifi-wep-no-keys"

static void
test_read_wifi_wep_no_keys (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	NMSettingWirelessSecurity *s_wsec;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	const char *tmp;
	const char *expected_id = "System foobar (test-wifi-wep-no-keys)";
	NMWepKeyType key_type;

	connection = connection_from_file (TEST_IFCFG_WIFI_WEP_NO_KEYS,
	                                   NULL,
	                                   TYPE_WIRELESS,
	                                   NULL,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &routefile,
	                                   &route6file,
	                                   &error,
	                                   &ignore_error);
	ASSERT (connection != NULL,
	        "wifi-wep-no-keys-read", "failed to read %s: %s", TEST_IFCFG_WIFI_WEP_NO_KEYS, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "wifi-wep-no-keys-verify", "failed to verify %s: %s", TEST_IFCFG_WIFI_WEP_NO_KEYS, error->message);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
	        "wifi-wep-no-keys-verify-connection", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_WEP_NO_KEYS,
	        NM_SETTING_CONNECTION_SETTING_NAME);

	/* ID */
	tmp = nm_setting_connection_get_id (s_con);
	ASSERT (tmp != NULL,
	        "wifi-wep-no-keys-verify-connection", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WEP_NO_KEYS,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);
	ASSERT (strcmp (tmp, expected_id) == 0,
	        "wifi-wep-no-keys-verify-connection", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WEP_NO_KEYS,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);

	/* UUID can't be tested if the ifcfg does not contain the UUID key, because
	 * the UUID is generated on the full path of the ifcfg file, which can change
	 * depending on where the tests are run.
	 */

	/* ===== WIRELESS SETTING ===== */

	s_wireless = nm_connection_get_setting_wireless (connection);
	ASSERT (s_wireless != NULL,
	        "wifi-wep-no-keys-verify-wireless", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_WEP_NO_KEYS,
	        NM_SETTING_WIRELESS_SETTING_NAME);

	/* ===== WIRELESS SECURITY SETTING ===== */

	s_wsec = nm_connection_get_setting_wireless_security (connection);
	ASSERT (s_wsec != NULL,
	        "wifi-wep-no-keys-verify-wireless", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_WEP_NO_KEYS,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME);

	/* Key management */
	ASSERT (strcmp (nm_setting_wireless_security_get_key_mgmt (s_wsec), "none") == 0,
	        "wifi-wep-no-keys-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WEP_NO_KEYS,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_KEY_MGMT);

	/* WEP key index */
	ASSERT (nm_setting_wireless_security_get_wep_tx_keyidx (s_wsec) == 0,
	        "wifi-wep-no-keys-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WEP_NO_KEYS,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_WEP_TX_KEYIDX);

	/* WEP key type */
	key_type = nm_setting_wireless_security_get_wep_key_type (s_wsec);
	ASSERT (key_type == NM_WEP_KEY_TYPE_UNKNOWN || key_type == NM_WEP_KEY_TYPE_KEY,
	        "wifi-wep-no-keys-verify-wireless", "failed to verify %s: unexpected WEP key type %d",
	        TEST_IFCFG_WIFI_WEP_NO_KEYS,
	        key_type);

	/* WEP key index 0; we don't expect it to be filled */
	tmp = nm_setting_wireless_security_get_wep_key (s_wsec, 0);
	ASSERT (tmp == NULL,
	        "wifi-wep-no-keys-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WEP_NO_KEYS,
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	        NM_SETTING_WIRELESS_SECURITY_WEP_KEY0);

	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
}

#define TEST_IFCFG_PERMISSIONS TEST_IFCFG_DIR"/network-scripts/ifcfg-test-permissions"

static void
test_read_permissions (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE, success;
	GError *error = NULL;
	guint32 num;
	const char *tmp;

	connection = connection_from_file (TEST_IFCFG_PERMISSIONS,
	                                   NULL,
	                                   TYPE_ETHERNET,
	                                   NULL,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &routefile,
	                                   &route6file,
	                                   &error,
	                                   &ignore_error);
	ASSERT (connection != NULL,
	        "permissions-read", "failed to read %s: %s", TEST_IFCFG_PERMISSIONS, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "permissions-verify", "failed to verify %s: %s", TEST_IFCFG_PERMISSIONS, error->message);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
	        "permissions-verify-connection", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_PERMISSIONS,
	        NM_SETTING_CONNECTION_SETTING_NAME);

	num = nm_setting_connection_get_num_permissions (s_con);
	ASSERT (num == 3,
	        "permissions-verify-permissions", "unexpected number of permissions (%d, expected 3)",
	        num);

	/* verify each permission */
	tmp = NULL;
	success = nm_setting_connection_get_permission (s_con, 0, NULL, &tmp, NULL);
	ASSERT (success == TRUE,
	        "permissions-verify-permissions", "unexpected failure getting permission #1");
	ASSERT (strcmp (tmp, "dcbw") == 0,
	        "permissions-verify-permissions", "unexpected permission #1");

	tmp = NULL;
	success = nm_setting_connection_get_permission (s_con, 1, NULL, &tmp, NULL);
	ASSERT (success == TRUE,
	        "permissions-verify-permissions", "unexpected failure getting permission #2");
	ASSERT (strcmp (tmp, "ssmith") == 0,
	        "permissions-verify-permissions", "unexpected permission #2");

	tmp = NULL;
	success = nm_setting_connection_get_permission (s_con, 2, NULL, &tmp, NULL);
	ASSERT (success == TRUE,
	        "permissions-verify-permissions", "unexpected failure getting permission #3");
	ASSERT (strcmp (tmp, "johnny5") == 0,
	        "permissions-verify-permissions", "unexpected permission #3");

	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
}

#define TEST_IFCFG_WIFI_WEP_AGENT_KEYS TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wifi-wep-agent-keys"

static void
test_read_wifi_wep_agent_keys (void)
{
	NMConnection *connection;
	NMSettingWireless *s_wifi;
	NMSettingWirelessSecurity *s_wsec;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	NMWepKeyType key_type;
	gboolean success;
	NMSettingSecretFlags flags;

	connection = connection_from_file (TEST_IFCFG_WIFI_WEP_AGENT_KEYS,
	                                   NULL,
	                                   TYPE_WIRELESS,
	                                   NULL,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &routefile,
	                                   &route6file,
	                                   &error,
	                                   &ignore_error);
	g_assert (connection != NULL);

	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	/* Ensure the connection is still marked for wifi security even though
	 * we don't have any WEP keys because they are agent owned.
	 */

	/* ===== WIRELESS SETTING ===== */
	s_wifi = nm_connection_get_setting_wireless (connection);
	g_assert (s_wifi);

	/* ===== WIRELESS SECURITY SETTING ===== */
	s_wsec = nm_connection_get_setting_wireless_security (connection);
	g_assert (s_wsec);

	g_assert (strcmp (nm_setting_wireless_security_get_key_mgmt (s_wsec), "none") == 0);
	g_assert (nm_setting_wireless_security_get_wep_tx_keyidx (s_wsec) == 0);

	key_type = nm_setting_wireless_security_get_wep_key_type (s_wsec);
	g_assert (key_type == NM_WEP_KEY_TYPE_UNKNOWN || key_type == NM_WEP_KEY_TYPE_KEY);

	/* We don't expect WEP key0 to be filled */
	g_assert (nm_setting_wireless_security_get_wep_key (s_wsec, 0) == NULL);

	flags = nm_setting_wireless_security_get_wep_key_flags (s_wsec);
	g_assert (flags & NM_SETTING_SECRET_FLAG_AGENT_OWNED);

	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
}

static void
test_write_wired_static (void)
{
	NMConnection *connection;
	NMConnection *reread;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIP4Config *s_ip4, *reread_s_ip4;
	NMSettingIP6Config *s_ip6, *reread_s_ip6;
	static unsigned char tmpmac[] = { 0x31, 0x33, 0x33, 0x37, 0xbe, 0xcd };
	GByteArray *mac;
	guint32 mtu = 1492;
	char *uuid;
	const guint32 ip1 = htonl (0x01010103);
	const guint32 ip2 = htonl (0x01010105);
	const guint32 gw = htonl (0x01010101);
	const guint32 dns1 = htonl (0x04020201);
	const guint32 dns2 = htonl (0x04020202);
	const guint32 prefix = 24;
	const char *dns_search1 = "foobar.com";
	const char *dns_search2 = "lab.foobar.com";
	const char *dns_search3 = "foobar6.com";
	const char *dns_search4 = "lab6.foobar.com";
	struct in6_addr ip6, ip6_1, ip6_2;
	struct in6_addr route1_dest, route2_dest, route1_nexthop, route2_nexthop;
	struct in6_addr dns6_1, dns6_2;
	const guint32 route1_prefix = 64, route2_prefix = 128;
	const guint32 route1_metric = 99, route2_metric = 1;
	NMIP4Address *addr;
	NMIP6Address *addr6;
	NMIP6Route *route6;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;

	inet_pton (AF_INET6, "1003:1234:abcd::1", &ip6);
	inet_pton (AF_INET6, "2003:1234:abcd::2", &ip6_1);
	inet_pton (AF_INET6, "3003:1234:abcd::3", &ip6_2);
	inet_pton (AF_INET6, "2222:aaaa:bbbb:cccc::", &route1_dest);
	inet_pton (AF_INET6, "2222:aaaa:bbbb:cccc:dddd:eeee:5555:6666", &route1_nexthop);
	inet_pton (AF_INET6, "::", &route2_dest);
	inet_pton (AF_INET6, "2222:aaaa::9999", &route2_nexthop);
	inet_pton (AF_INET6, "fade:0102:0103::face", &dns6_1);
	inet_pton (AF_INET6, "cafe:ffff:eeee:dddd:cccc:bbbb:aaaa:feed", &dns6_2);

	connection = nm_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write Wired Static",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* Wired setting */
	s_wired = (NMSettingWired *) nm_setting_wired_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wired));

	mac = g_byte_array_sized_new (sizeof (tmpmac));
	g_byte_array_append (mac, &tmpmac[0], sizeof (tmpmac));

	g_object_set (s_wired,
	              NM_SETTING_WIRED_MAC_ADDRESS, mac,
	              NM_SETTING_WIRED_MTU, mtu,
	              NULL);
	g_byte_array_free (mac, TRUE);

	/* IP4 setting */
	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4,
	              NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_MANUAL,
	              NM_SETTING_IP4_CONFIG_MAY_FAIL, TRUE,
	              NULL);

	addr = nm_ip4_address_new ();
	nm_ip4_address_set_address (addr, ip1);
	nm_ip4_address_set_prefix (addr, prefix);
	nm_ip4_address_set_gateway (addr, gw);
	nm_setting_ip4_config_add_address (s_ip4, addr);
	nm_ip4_address_unref (addr);

	addr = nm_ip4_address_new ();
	nm_ip4_address_set_address (addr, ip2);
	nm_ip4_address_set_prefix (addr, prefix);
	nm_ip4_address_set_gateway (addr, gw);
	nm_setting_ip4_config_add_address (s_ip4, addr);
	nm_ip4_address_unref (addr);

	nm_setting_ip4_config_add_dns (s_ip4, dns1);
	nm_setting_ip4_config_add_dns (s_ip4, dns2);

	nm_setting_ip4_config_add_dns_search (s_ip4, dns_search1);
	nm_setting_ip4_config_add_dns_search (s_ip4, dns_search2);

	/* IP6 setting */
	s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_MANUAL,
	              NM_SETTING_IP6_CONFIG_MAY_FAIL, TRUE,
	              NULL);

	/* Add addresses */
	addr6 = nm_ip6_address_new ();
	nm_ip6_address_set_address (addr6, &ip6);
	nm_ip6_address_set_prefix (addr6, 11);
	nm_setting_ip6_config_add_address (s_ip6, addr6);
	nm_ip6_address_unref (addr6);

	addr6 = nm_ip6_address_new ();
	nm_ip6_address_set_address (addr6, &ip6_1);
	nm_ip6_address_set_prefix (addr6, 22);
	nm_setting_ip6_config_add_address (s_ip6, addr6);
	nm_ip6_address_unref (addr6);

	addr6 = nm_ip6_address_new ();
	nm_ip6_address_set_address (addr6, &ip6_2);
	nm_ip6_address_set_prefix (addr6, 33);
	nm_setting_ip6_config_add_address (s_ip6, addr6);
	nm_ip6_address_unref (addr6);

	/* Add routes */
	route6 = nm_ip6_route_new ();
	nm_ip6_route_set_dest (route6, &route1_dest);
	nm_ip6_route_set_prefix (route6, route1_prefix);
	nm_ip6_route_set_next_hop (route6, &route1_nexthop);
	nm_ip6_route_set_metric (route6, route1_metric);
	nm_setting_ip6_config_add_route (s_ip6, route6);
	nm_ip6_route_unref (route6);

	route6 = nm_ip6_route_new ();
	nm_ip6_route_set_dest (route6, &route2_dest);
	nm_ip6_route_set_prefix (route6, route2_prefix);
	nm_ip6_route_set_next_hop (route6, &route2_nexthop);
	nm_ip6_route_set_metric (route6, route2_metric);
	nm_setting_ip6_config_add_route (s_ip6, route6);
	nm_ip6_route_unref (route6);

	/* DNS servers */
	nm_setting_ip6_config_add_dns (s_ip6, &dns6_1);
	nm_setting_ip6_config_add_dns (s_ip6, &dns6_2);

	/* DNS domains */
	nm_setting_ip6_config_add_dns_search (s_ip6, dns_search3);
	nm_setting_ip6_config_add_dns_search (s_ip6, dns_search4);

	ASSERT (nm_connection_verify (connection, &error) == TRUE,
	        "wired-static-write", "failed to verify connection: %s",
	        (error && error->message) ? error->message : "(unknown)");

	/* Save the ifcfg */
	success = writer_new_connection (connection,
	                                 TEST_SCRATCH_DIR "/network-scripts/",
	                                 &testfile,
	                                 &error);
	ASSERT (success == TRUE,
	        "wired-static-write", "failed to write connection to disk: %s",
	        (error && error->message) ? error->message : "(unknown)");

	ASSERT (testfile != NULL,
	        "wired-static-write", "didn't get ifcfg file path back after writing connection");

	/* reread will be normalized, so we must normalize connection too. */
	nm_utils_normalize_connection (connection, TRUE);

	/* re-read the connection for comparison */
	reread = connection_from_file (testfile,
	                               NULL,
	                               TYPE_ETHERNET,
	                               NULL,
	                               &unmanaged,
	                               &keyfile,
	                               &routefile,
	                               &route6file,
	                               &error,
	                               &ignore_error);
	unlink (testfile);

	ASSERT (reread != NULL,
	        "wired-static-write-reread", "failed to read %s: %s", testfile, error->message);

	ASSERT (nm_connection_verify (reread, &error),
	        "wired-static-write-reread-verify", "failed to verify %s: %s", testfile, error->message);

	/* FIXME: currently DNS domains from IPv6 setting are stored in 'DOMAIN' key in ifcfg-file 
	 * However after re-reading they are dropped into IPv4 setting.
	 * So, in order to comparison succeeded, move DNS domains back to IPv6 setting.
	 */
	reread_s_ip4 = nm_connection_get_setting_ip4_config (reread);
	reread_s_ip6 = nm_connection_get_setting_ip6_config (reread);
	nm_setting_ip6_config_add_dns_search (reread_s_ip6, nm_setting_ip4_config_get_dns_search (reread_s_ip4, 2));
	nm_setting_ip6_config_add_dns_search (reread_s_ip6, nm_setting_ip4_config_get_dns_search (reread_s_ip4, 3));
	nm_setting_ip4_config_remove_dns_search (reread_s_ip4, 3);
	nm_setting_ip4_config_remove_dns_search (reread_s_ip4, 2);

	ASSERT (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "wired-static-write", "written and re-read connection weren't the same.");

	if (route6file)
		unlink (route6file);

	g_free (testfile);
	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
	g_object_unref (reread);
}

static void
test_write_wired_dhcp (void)
{
	NMConnection *connection;
	NMConnection *reread;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;
	char *uuid;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;

	connection = nm_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write Wired DHCP",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* Wired setting */
	s_wired = (NMSettingWired *) nm_setting_wired_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wired));

	/* IP4 setting */
	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4,
	              NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
	              NM_SETTING_IP4_CONFIG_DHCP_CLIENT_ID, "random-client-id-00:22:33",
	              NM_SETTING_IP4_CONFIG_DHCP_HOSTNAME, "awesome-hostname",
	              NM_SETTING_IP4_CONFIG_IGNORE_AUTO_ROUTES, TRUE,
	              NM_SETTING_IP4_CONFIG_IGNORE_AUTO_DNS, TRUE,
	              NULL);

	ASSERT (nm_connection_verify (connection, &error) == TRUE,
	        "wired-dhcp-write", "failed to verify connection: %s",
	        (error && error->message) ? error->message : "(unknown)");

	/* IP6 setting */
	s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NM_SETTING_IP6_CONFIG_MAY_FAIL, TRUE,
	              NULL);

	/* Save the ifcfg */
	success = writer_new_connection (connection,
	                                 TEST_SCRATCH_DIR "/network-scripts/",
	                                 &testfile,
	                                 &error);
	ASSERT (success == TRUE,
	        "wired-dhcp-write", "failed to write connection to disk: %s",
	        (error && error->message) ? error->message : "(unknown)");

	ASSERT (testfile != NULL,
	        "wired-dhcp-write", "didn't get ifcfg file path back after writing connection");

	/* reread will be normalized, so we must normalize connection too. */
	nm_utils_normalize_connection (connection, TRUE);

	/* re-read the connection for comparison */
	reread = connection_from_file (testfile,
	                               NULL,
	                               TYPE_ETHERNET,
	                               NULL,
	                               &unmanaged,
	                               &keyfile,
	                               &routefile,
	                               &route6file,
	                               &error,
	                               &ignore_error);
	unlink (testfile);

	ASSERT (reread != NULL,
	        "wired-dhcp-write-reread", "failed to read %s: %s", testfile, error->message);

	ASSERT (nm_connection_verify (reread, &error),
	        "wired-dhcp-write-reread-verify", "failed to verify %s: %s", testfile, error->message);

	ASSERT (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "wired-dhcp-write", "written and re-read connection weren't the same.");

	g_free (testfile);
	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
	g_object_unref (reread);
}

static void
test_write_wired_dhcp_plus_ip (void)
{
	NMConnection *connection, *reread;
	char *written = NULL;
	GError *error = NULL;
	gboolean success = FALSE;

	connection = connection_from_file (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-dhcp-plus-ip",
	                                   NULL, TYPE_ETHERNET, NULL, NULL,
	                                   NULL, NULL, NULL, &error, NULL);
	g_assert_no_error (error);
	g_assert (connection != NULL);

	success = writer_new_connection (connection,
	                                 TEST_SCRATCH_DIR "/network-scripts/",
	                                 &written,
	                                 &error);
	g_assert (success);

	/* reread will be normalized, so we must normalize connection too. */
	nm_utils_normalize_connection (connection, TRUE);

	/* re-read the connection for comparison */
	reread = connection_from_file (written, NULL, TYPE_ETHERNET, NULL, NULL,
	                               NULL, NULL, NULL, &error, NULL);
	unlink (written);
	g_free (written);

	g_assert_no_error (error);
	g_assert (reread != NULL);

	success = nm_connection_verify (reread, &error);
	g_assert_no_error (error);
	g_assert (success);

	success = nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT);
	g_assert (success);

	g_object_unref (connection);
	g_object_unref (reread);
}

static void
test_read_write_wired_dhcp_send_hostname (void)
{
	NMConnection *connection, *reread;
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;
	const char * dhcp_hostname = "kamil-patka";
	char *written = NULL;
	GError *error = NULL;
	gboolean success = FALSE;

	connection = connection_from_file (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-dhcp-send-hostname",
	                                   NULL, TYPE_ETHERNET, NULL, NULL,
	                                   NULL, NULL, NULL, &error, NULL);
	g_assert_no_error (error);
	g_assert (connection != NULL);

	/* Check dhcp-hostname and dhcp-send-hostname */
	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	g_assert (s_ip4);
	g_assert (s_ip6);
	g_assert (nm_setting_ip4_config_get_dhcp_send_hostname (s_ip4) == TRUE);
	g_assert_cmpstr (nm_setting_ip4_config_get_dhcp_hostname (s_ip4), ==, "svata-pulec");
	g_assert_cmpstr (nm_setting_ip6_config_get_dhcp_hostname (s_ip6), ==, "svata-pulec");

	/* Set dhcp-send-hostname=false dhcp-hostname="kamil-patka" and write the connection. */
	g_object_set (s_ip4, NM_SETTING_IP4_CONFIG_DHCP_SEND_HOSTNAME, FALSE, NULL);
	g_object_set (s_ip4, NM_SETTING_IP4_CONFIG_DHCP_HOSTNAME, dhcp_hostname, NULL);
	g_object_set (s_ip6, NM_SETTING_IP4_CONFIG_DHCP_HOSTNAME, dhcp_hostname, NULL);

	success = writer_new_connection (connection,
	                                 TEST_SCRATCH_DIR "/network-scripts/",
	                                 &written,
	                                 &error);
	g_assert (success);

	/* reread will be normalized, so we must normalize connection too. */
	nm_utils_normalize_connection (connection, TRUE);

	/* re-read the connection for comparison */
	reread = connection_from_file (written, NULL, TYPE_ETHERNET, NULL, NULL,
	                               NULL, NULL, NULL, &error, NULL);
	unlink (written);
	g_free (written);

	g_assert_no_error (error);
	g_assert (reread != NULL);

	success = nm_connection_verify (reread, &error);
	g_assert_no_error (error);
	g_assert (success);

	success = nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT);
	g_assert (success);

	/* Check dhcp-hostname and dhcp-send-hostname from the re-read connection. */
	s_ip4 = nm_connection_get_setting_ip4_config (reread);
	s_ip6 = nm_connection_get_setting_ip6_config (reread);
	g_assert (s_ip4);
	g_assert (s_ip6);
	g_assert (nm_setting_ip4_config_get_dhcp_send_hostname (s_ip4) == FALSE);
	g_assert_cmpstr (nm_setting_ip4_config_get_dhcp_hostname (s_ip4), ==, dhcp_hostname);
	g_assert_cmpstr (nm_setting_ip6_config_get_dhcp_hostname (s_ip6), ==, dhcp_hostname);

	g_object_unref (connection);
	g_object_unref (reread);
}

static void
test_write_wired_static_ip6_only (void)
{
	NMConnection *connection;
	NMConnection *reread;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;
	static unsigned char tmpmac[] = { 0x31, 0x33, 0x33, 0x37, 0xbe, 0xcd };
	GByteArray *mac;
	char *uuid;
	struct in6_addr ip6;
	struct in6_addr dns6;
	NMIP6Address *addr6;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;

	inet_pton (AF_INET6, "1003:1234:abcd::1", &ip6);
	inet_pton (AF_INET6, "fade:0102:0103::face", &dns6);

	connection = nm_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write Wired Static IP6 Only",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* Wired setting */
	s_wired = (NMSettingWired *) nm_setting_wired_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wired));

	mac = g_byte_array_sized_new (sizeof (tmpmac));
	g_byte_array_append (mac, &tmpmac[0], sizeof (tmpmac));
	g_object_set (s_wired, NM_SETTING_WIRED_MAC_ADDRESS, mac, NULL);
	g_byte_array_free (mac, TRUE);

	/* IP4 setting */
	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4,
	              NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_DISABLED,
	              NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_MANUAL,
	              NULL);

	/* Add addresses */
	addr6 = nm_ip6_address_new ();
	nm_ip6_address_set_address (addr6, &ip6);
	nm_ip6_address_set_prefix (addr6, 11);
	nm_setting_ip6_config_add_address (s_ip6, addr6);
	nm_ip6_address_unref (addr6);

	/* DNS server */
	nm_setting_ip6_config_add_dns (s_ip6, &dns6);

	ASSERT (nm_connection_verify (connection, &error) == TRUE,
	        "wired-static-ip6-only-write", "failed to verify connection: %s",
	        (error && error->message) ? error->message : "(unknown)");

	/* Save the ifcfg */
	success = writer_new_connection (connection,
	                                 TEST_SCRATCH_DIR "/network-scripts/",
	                                 &testfile,
	                                 &error);
	ASSERT (success == TRUE,
	        "wired-static-ip6-only-write", "failed to write connection to disk: %s",
	        (error && error->message) ? error->message : "(unknown)");

	ASSERT (testfile != NULL,
	        "wired-static-ip6-only-write", "didn't get ifcfg file path back after writing connection");

	/* reread will be normalized, so we must normalize connection too. */
	nm_utils_normalize_connection (connection, TRUE);

	/* re-read the connection for comparison */
	reread = connection_from_file (testfile,
	                               NULL,
	                               TYPE_ETHERNET,
	                               NULL,
	                               &unmanaged,
	                               &keyfile,
	                               &routefile,
	                               &route6file,
	                               &error,
	                               &ignore_error);
	unlink (testfile);

	ASSERT (reread != NULL,
	        "wired-static-ip6-only-write-reread", "failed to read %s: %s", testfile, error->message);

	ASSERT (nm_connection_verify (reread, &error),
	        "wired-static-ip6-only-write-reread-verify", "failed to verify %s: %s", testfile, error->message);

	ASSERT (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "wired-static-ip6-only-write", "written and re-read connection weren't the same.");

	if (route6file)
		unlink (route6file);

	g_free (testfile);
	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
	g_object_unref (reread);
}

/* Test writing an IPv6 config with varying gateway address.
 * For missing gateway (::), we expect no IPV6_DEFAULTGW to be written
 * to ifcfg-rh.
 *
 * As user_data pass the IPv6 address of the gateway as string. NULL means
 * not to explicitly set the gateway in the configuration before writing it.
 * That way, the gateway actually defaults to "::".
 */
static void
test_write_wired_static_ip6_only_gw (gconstpointer user_data)
{
	NMConnection *connection;
	NMConnection *reread;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;
	static unsigned char tmpmac[] = { 0x31, 0x33, 0x33, 0x37, 0xbe, 0xcd };
	GByteArray *mac;
	char *uuid;
	struct in6_addr ip6;
	struct in6_addr dns6;
	NMIP6Address *addr6;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	char *id = NULL;
	gboolean ignore_error = FALSE;
	char *written_ifcfg_gateway;
	char s_gateway6[INET6_ADDRSTRLEN] = { 0 };
	struct in6_addr gateway6_autovar;
	const struct in6_addr *gateway6 = NULL;

	/* parsing the input argument and set the struct in6_addr "gateway6" to
	 * the gateway address. NULL means "do not set the gateway explicitly". */
	if (user_data) {
		g_assert_cmpint (inet_pton (AF_INET6, user_data, &gateway6_autovar), ==, 1);
		gateway6 = &gateway6_autovar;
	}

	inet_pton (AF_INET6, "1003:1234:abcd::1", &ip6);
	inet_pton (AF_INET6, "fade:0102:0103::face", &dns6);
	if (gateway6)
		inet_ntop (AF_INET6, gateway6, s_gateway6, sizeof (s_gateway6));

	connection = nm_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	id = g_strdup_printf ("Test Write Wired Static IP6 Only With Gateway %s", gateway6 ? s_gateway6 : "NULL");
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, id,
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
	              NULL);
	g_free (uuid);
	g_free (id);

	/* Wired setting */
	s_wired = (NMSettingWired *) nm_setting_wired_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wired));

	mac = g_byte_array_sized_new (sizeof (tmpmac));
	g_byte_array_append (mac, &tmpmac[0], sizeof (tmpmac));
	g_object_set (s_wired, NM_SETTING_WIRED_MAC_ADDRESS, mac, NULL);
	g_byte_array_free (mac, TRUE);

	/* IP4 setting */
	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4,
	              NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_DISABLED,
	              NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_MANUAL,
	              NULL);

	/* Add addresses */
	addr6 = nm_ip6_address_new ();
	nm_ip6_address_set_address (addr6, &ip6);
	nm_ip6_address_set_prefix (addr6, 11);
	if (gateway6)
		nm_ip6_address_set_gateway (addr6, gateway6);
	nm_setting_ip6_config_add_address (s_ip6, addr6);
	nm_ip6_address_unref (addr6);

	/* DNS server */
	nm_setting_ip6_config_add_dns (s_ip6, &dns6);

	g_assert (nm_connection_verify (connection, &error));

	/* Save the ifcfg */
	success = writer_new_connection (connection,
	                                 TEST_SCRATCH_DIR "/network-scripts/",
	                                 &testfile,
	                                 &error);
	g_assert_no_error (error);
	g_assert (success);
	g_assert (testfile);

	/* reread will be normalized, so we must normalize connection too. */
	nm_utils_normalize_connection (connection, TRUE);

	/* re-read the connection for comparison */
	reread = connection_from_file (testfile,
	                               NULL,
	                               TYPE_ETHERNET,
	                               NULL, NULL, NULL,
	                               NULL, NULL,
	                               &error,
	                               &ignore_error);
	g_assert_no_error (error);
	g_assert (reread);
	g_assert (nm_connection_verify (reread, &error));
	g_assert (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT));

	{
		/* re-read the file to check that what key was written. */
		shvarFile *ifcfg = svOpenFile (testfile, &error);

		g_assert_no_error (error);
		g_assert (ifcfg);
		written_ifcfg_gateway = svGetValue (ifcfg, "IPV6_DEFAULTGW", FALSE);
		svCloseFile (ifcfg);
	}

	unlink (testfile);

	/* access the gateway from the loaded connection. */
	s_ip6 = nm_connection_get_setting_ip6_config (reread);
	g_assert (s_ip6 && nm_setting_ip6_config_get_num_addresses (s_ip6)==1);
	addr6 = nm_setting_ip6_config_get_address (s_ip6, 0);
	g_assert (addr6);

	/* assert that the gateway was written and reloaded as expected */
	if (!gateway6 || IN6_IS_ADDR_UNSPECIFIED (gateway6)) {
		g_assert (IN6_IS_ADDR_UNSPECIFIED (nm_ip6_address_get_gateway (addr6)));
		g_assert (written_ifcfg_gateway==NULL);
	} else {
		g_assert (!IN6_IS_ADDR_UNSPECIFIED (nm_ip6_address_get_gateway (addr6)));
		g_assert_cmpint (memcmp (nm_ip6_address_get_gateway (addr6), gateway6, sizeof (struct in6_addr)), ==, 0);
		g_assert_cmpstr (written_ifcfg_gateway, ==, s_gateway6);
	}

	g_free (testfile);
	g_free (written_ifcfg_gateway);
	g_object_unref (connection);
	g_object_unref (reread);
}

#define TEST_IFCFG_READ_WRITE_STATIC_ROUTES_LEGACY TEST_IFCFG_DIR"/network-scripts/ifcfg-test-static-routes-legacy"

static void
test_read_write_static_routes_legacy (void)
{
	NMConnection *connection, *reread;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIP4Config *s_ip4;
	char *unmanaged = NULL;
	char *testfile = NULL;
	char *keyfile = NULL;
	char *keyfile2 = NULL;
	char *routefile = NULL;
	char *routefile2 = NULL;
	char *route6file = NULL;
	char *route6file2 = NULL;
	gboolean ignore_error = FALSE;
	gboolean success;
	GError *error = NULL;
	const char *tmp;

	connection = connection_from_file (TEST_IFCFG_READ_WRITE_STATIC_ROUTES_LEGACY,
	                                   NULL,
	                                   TYPE_ETHERNET,
	                                   NULL,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &routefile,
	                                   &route6file,
	                                   &error,
	                                   &ignore_error);
	ASSERT (connection != NULL,
	        "read-write-static-routes-legacy-read", "failed to read %s: %s",
	        TEST_IFCFG_READ_WRITE_STATIC_ROUTES_LEGACY, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "read-write-static-routes-legacy-verify", "failed to verify %s: %s",
	        TEST_IFCFG_READ_WRITE_STATIC_ROUTES_LEGACY, error->message);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
	        "read-write-static-routes-legacy-verify-connection", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_READ_WRITE_STATIC_ROUTES_LEGACY,
	        NM_SETTING_CONNECTION_SETTING_NAME);

	/* ID */
	tmp = nm_setting_connection_get_id (s_con);
	ASSERT (tmp != NULL,
	        "read-write-static-routes-legacy-verify-connection", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_READ_WRITE_STATIC_ROUTES_LEGACY,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);

	/* Autoconnect */
	ASSERT (nm_setting_connection_get_autoconnect (s_con) == TRUE,
	        "read_write-static-routes-legacy-verify-connection", "failed to verify %s: unexpected %s /%s key value",
	        TEST_IFCFG_READ_WRITE_STATIC_ROUTES_LEGACY,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_AUTOCONNECT);

	/* ===== WIRED SETTING ===== */

	s_wired = nm_connection_get_setting_wired (connection);
	ASSERT (s_wired != NULL,
	        "read-write-static-routes-legacy-verify-wired", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_READ_WRITE_STATIC_ROUTES_LEGACY,
	        NM_SETTING_WIRED_SETTING_NAME);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	ASSERT (s_ip4 != NULL,
	        "read-write-static-routes-legacy-verify-ip4", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_READ_WRITE_STATIC_ROUTES_LEGACY,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME);

	/* Method */
	tmp = nm_setting_ip4_config_get_method (s_ip4);
	ASSERT (strcmp (tmp, NM_SETTING_IP4_CONFIG_METHOD_AUTO) == 0,
	        "read-write-static-routes-legacy-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_READ_WRITE_STATIC_ROUTES_LEGACY,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_METHOD);

	ASSERT (nm_setting_ip4_config_get_never_default (s_ip4) == FALSE,
	        "read-write-static-routes-legacy-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_READ_WRITE_STATIC_ROUTES_LEGACY,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_NEVER_DEFAULT);

	/* Save the ifcfg; use a special different scratch dir to ensure that
	 * we can clean up after the written connection in both the original
	 * source tree and for 'make distcheck'.
	 */
	success = writer_new_connection (connection,
	                                 TEST_SCRATCH_DIR "/network-scripts/tmp",
	                                 &testfile,
	                                 &error);
	ASSERT (success == TRUE,
	        "read-write-static-routes-legacy-write", "failed to write connection to disk: %s",
	        (error && error->message) ? error->message : "(unknown)");

	ASSERT (testfile != NULL,
	        "read-write-static-routes-legacy-write", "didn't get ifcfg file path back after writing connection");

	/* reread will be normalized, so we must normalize connection too. */
	nm_utils_normalize_connection (connection, TRUE);

	/* re-read the connection for comparison */
	reread = connection_from_file (testfile,
	                               NULL,
	                               TYPE_ETHERNET,
	                               NULL,
	                               &unmanaged,
	                               &keyfile2,
	                               &routefile2,
	                               &route6file2,
	                               &error,
	                               &ignore_error);
	unlink (testfile);
	unlink (routefile2);
	unlink (route6file2);

	ASSERT (reread != NULL,
	        "read-write-static-routes-legacy-reread", "failed to read %s: %s", testfile, error->message);

	ASSERT (routefile2 != NULL,
	        "read-write-static-routes-legacy-reread", "expected routefile for '%s'", testfile);

	ASSERT (nm_connection_verify (reread, &error),
	        "read-write-static-routes-legacy-reread-verify", "failed to verify %s: %s", testfile, error->message);

	ASSERT (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "read-write-static-routes-legacy-write", "written and re-read connection weren't the same.");

	g_free (testfile);
	g_free (unmanaged);
	g_free (keyfile);
	g_free (keyfile2);
	g_free (routefile);
	g_free (routefile2);
	g_free (route6file);
	g_free (route6file2);
	g_object_unref (connection);
	g_object_unref (reread);
}

static void
test_write_wired_static_routes (void)
{
	NMConnection *connection;
	NMConnection *reread;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;
	static unsigned char tmpmac[] = { 0x31, 0x33, 0x33, 0x37, 0xbe, 0xcd };
	GByteArray *mac;
	guint32 mtu = 1492;
	char *uuid;
	const guint32 ip1 = htonl (0x01010103);
	const guint32 ip2 = htonl (0x01010105);
	const guint32 gw = htonl (0x01010101);
	const guint32 dns1 = htonl (0x04020201);
	const guint32 dns2 = htonl (0x04020202);
	const guint32 route_dst1 = htonl (0x01020300);
	const guint32 route_dst2= htonl (0x03020100);
	const guint32 route_gw1 = htonl (0xdeadbeef);
	const guint32 route_gw2 = htonl (0xcafeabbe);
	const guint32 prefix = 24;
	const char *dns_search1 = "foobar.com";
	const char *dns_search2 = "lab.foobar.com";
	NMIP4Address *addr;
	NMIP4Route *route;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;

	connection = nm_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write Wired Static Routes",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* Wired setting */
	s_wired = (NMSettingWired *) nm_setting_wired_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wired));

	mac = g_byte_array_sized_new (sizeof (tmpmac));
	g_byte_array_append (mac, &tmpmac[0], sizeof (tmpmac));

	g_object_set (s_wired,
	              NM_SETTING_WIRED_MAC_ADDRESS, mac,
	              NM_SETTING_WIRED_MTU, mtu,
	              NULL);
	g_byte_array_free (mac, TRUE);

	/* IP4 setting */
	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4,
	              NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_MANUAL,
	              NULL);

	addr = nm_ip4_address_new ();
	nm_ip4_address_set_address (addr, ip1);
	nm_ip4_address_set_prefix (addr, prefix);
	nm_ip4_address_set_gateway (addr, gw);
	nm_setting_ip4_config_add_address (s_ip4, addr);
	nm_ip4_address_unref (addr);

	addr = nm_ip4_address_new ();
	nm_ip4_address_set_address (addr, ip2);
	nm_ip4_address_set_prefix (addr, prefix);
	nm_ip4_address_set_gateway (addr, gw);
	nm_setting_ip4_config_add_address (s_ip4, addr);
	nm_ip4_address_unref (addr);

	/* Write out routes */
	route = nm_ip4_route_new ();
	nm_ip4_route_set_dest (route, route_dst1);
	nm_ip4_route_set_prefix (route, prefix);
	nm_ip4_route_set_next_hop (route, route_gw1);
	nm_setting_ip4_config_add_route (s_ip4, route);
	nm_ip4_route_unref (route);

	route = nm_ip4_route_new ();
	nm_ip4_route_set_dest (route, route_dst2);
	nm_ip4_route_set_prefix (route, prefix);
	nm_ip4_route_set_next_hop (route, route_gw2);
	nm_ip4_route_set_metric (route, 77);
	nm_setting_ip4_config_add_route (s_ip4, route);
	nm_ip4_route_unref (route);

	nm_setting_ip4_config_add_dns (s_ip4, dns1);
	nm_setting_ip4_config_add_dns (s_ip4, dns2);

	nm_setting_ip4_config_add_dns_search (s_ip4, dns_search1);
	nm_setting_ip4_config_add_dns_search (s_ip4, dns_search2);

	/* IP6 setting */
	s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NM_SETTING_IP6_CONFIG_MAY_FAIL, TRUE,
	              NULL);

	ASSERT (nm_connection_verify (connection, &error) == TRUE,
	        "wired-static-routes-write", "failed to verify connection: %s",
	        (error && error->message) ? error->message : "(unknown)");

	/* Save the ifcfg */
	success = writer_new_connection (connection,
	                                 TEST_SCRATCH_DIR "/network-scripts/",
	                                 &testfile,
	                                 &error);
	ASSERT (success == TRUE,
	        "wired-static-routes-write", "failed to write connection to disk: %s",
	        (error && error->message) ? error->message : "(unknown)");

	ASSERT (testfile != NULL,
	        "wired-static-routes-write", "didn't get ifcfg file path back after writing connection");

	/* reread will be normalized, so we must normalize connection too. */
	nm_utils_normalize_connection (connection, TRUE);

	/* re-read the connection for comparison */
	reread = connection_from_file (testfile,
	                               NULL,
	                               TYPE_ETHERNET,
	                               NULL,
	                               &unmanaged,
	                               &keyfile,
	                               &routefile,
	                               &route6file,
	                               &error,
	                               &ignore_error);
	unlink (testfile);

	ASSERT (reread != NULL,
	        "wired-static-routes-write-reread", "failed to read %s: %s", testfile, error->message);

	ASSERT (routefile != NULL,
	        "wired-static-routes-write-reread", "expected routefile for '%s'", testfile);
	unlink (routefile);

	ASSERT (nm_connection_verify (reread, &error),
	        "wired-static-routes-write-reread-verify", "failed to verify %s: %s", testfile, error->message);

	ASSERT (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "wired-static-routes-write", "written and re-read connection weren't the same.");

	g_free (testfile);
	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
	g_object_unref (reread);
}

static void
test_write_wired_dhcp_8021x_peap_mschapv2 (void)
{
	NMConnection *connection;
	NMConnection *reread;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;
	NMSetting8021x *s_8021x;
	char *uuid;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;

	connection = nm_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write Wired DHCP 802.1x PEAP MSCHAPv2",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* Wired setting */
	s_wired = (NMSettingWired *) nm_setting_wired_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wired));

	/* IP4 setting */
	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4, NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NM_SETTING_IP6_CONFIG_MAY_FAIL, TRUE,
	              NULL);

	/* 802.1x setting */
	s_8021x = (NMSetting8021x *) nm_setting_802_1x_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_8021x));

	g_object_set (s_8021x,
	              NM_SETTING_802_1X_IDENTITY, "Bob Saget",
	              NM_SETTING_802_1X_ANONYMOUS_IDENTITY, "barney",
	              NM_SETTING_802_1X_PASSWORD, "Kids, it was back in October 2008...",
	              NM_SETTING_802_1X_PHASE1_PEAPVER, "1",
	              NM_SETTING_802_1X_PHASE1_PEAPLABEL, "1",
	              NM_SETTING_802_1X_PHASE2_AUTH, "mschapv2",
	              NULL);

	nm_setting_802_1x_add_eap_method (s_8021x, "peap");

	success = nm_setting_802_1x_set_ca_cert (s_8021x, 
	                                         TEST_IFCFG_WIRED_8021x_PEAP_MSCHAPV2_CA_CERT,
	                                         NM_SETTING_802_1X_CK_SCHEME_PATH,
	                                         NULL,
	                                         &error);
	ASSERT (success == TRUE,
	        "wired-dhcp-8021x-peap-mschapv2write", "failed to verify connection: %s",
	        (error && error->message) ? error->message : "(unknown)");

	ASSERT (nm_connection_verify (connection, &error) == TRUE,
	        "wired-dhcp-8021x-peap-mschapv2write", "failed to verify connection: %s",
	        (error && error->message) ? error->message : "(unknown)");

	/* Save the ifcfg */
	success = writer_new_connection (connection,
	                                 TEST_SCRATCH_DIR "/network-scripts/",
	                                 &testfile,
	                                 &error);
	ASSERT (success == TRUE,
	        "wired-dhcp-8021x-peap-mschapv2write", "failed to write connection to disk: %s",
	        (error && error->message) ? error->message : "(unknown)");

	ASSERT (testfile != NULL,
	        "wired-dhcp-8021x-peap-mschapv2write", "didn't get ifcfg file path back after writing connection");

	/* reread will be normalized, so we must normalize connection too. */
	nm_utils_normalize_connection (connection, TRUE);

	/* re-read the connection for comparison */
	reread = connection_from_file (testfile,
	                               NULL,
	                               TYPE_ETHERNET,
	                               NULL,
	                               &unmanaged,
	                               &keyfile,
	                               &routefile,
	                               &route6file,
	                               &error,
	                               &ignore_error);
	unlink (testfile);

	ASSERT (reread != NULL,
	        "wired-dhcp-8021x-peap-mschapv2write-reread", "failed to read %s: %s", testfile, error->message);

	ASSERT (keyfile != NULL,
	        "wired-dhcp-8021x-peap-mschapv2write-reread", "expected keyfile for '%s'", testfile);
	unlink (keyfile);

	ASSERT (nm_connection_verify (reread, &error),
	        "wired-dhcp-8021x-peap-mschapv2write-reread-verify", "failed to verify %s: %s", testfile, error->message);

	ASSERT (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "wired-dhcp-8021x-peap-mschapv2write", "written and re-read connection weren't the same.");

	g_free (testfile);
	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
	g_object_unref (reread);
}

#if 0
static GByteArray *
file_to_byte_array (const char *filename)
{
	char *contents;
	GByteArray *array = NULL;
	gsize length = 0;

	if (g_file_get_contents (filename, &contents, &length, NULL)) {
		array = g_byte_array_sized_new (length);
		g_byte_array_append (array, (guint8 *) contents, length);
		g_assert (array->len == length);
		g_free (contents);
	}
	return array;
}
#endif

#define TEST_IFCFG_WIRED_TLS_CA_CERT TEST_IFCFG_DIR"/network-scripts/test_ca_cert.pem"
#define TEST_IFCFG_WIRED_TLS_CLIENT_CERT TEST_IFCFG_DIR"/network-scripts/test1_key_and_cert.pem"
#define TEST_IFCFG_WIRED_TLS_PRIVATE_KEY TEST_IFCFG_DIR"/network-scripts/test1_key_and_cert.pem"

static void
test_write_wired_8021x_tls (NMSetting8021xCKScheme scheme,
                            NMSettingSecretFlags flags)
{
	NMConnection *connection;
	NMConnection *reread;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;
	NMSetting8021x *s_8021x;
	char *uuid;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	NMSetting8021xCKFormat format = NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;
	const char *pw;
	char *tmp;

	connection = nm_connection_new ();
	g_assert (connection != NULL);

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	g_assert (s_con);
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write Wired 802.1x TLS Blobs",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* Wired setting */
	s_wired = (NMSettingWired *) nm_setting_wired_new ();
	g_assert (s_wired);
	nm_connection_add_setting (connection, NM_SETTING (s_wired));

	/* IP4 setting */
	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	g_assert (s_ip4);
	g_object_set (s_ip4, NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	/* IP6 setting */
	s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();
	g_assert (s_ip6);
	g_object_set (s_ip6,
	              NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NM_SETTING_IP6_CONFIG_MAY_FAIL, TRUE,
	              NULL);
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	/* 802.1x setting */
	s_8021x = (NMSetting8021x *) nm_setting_802_1x_new ();
	g_assert (s_8021x);
	nm_connection_add_setting (connection, NM_SETTING (s_8021x));

	g_object_set (s_8021x, NM_SETTING_802_1X_IDENTITY, "Bill Smith", NULL);
	nm_setting_802_1x_add_eap_method (s_8021x, "tls");

	/* CA cert */
	success = nm_setting_802_1x_set_ca_cert (s_8021x,
	                                         TEST_IFCFG_WIRED_TLS_CA_CERT,
	                                         scheme,
	                                         &format,
	                                         &error);
	g_assert_no_error (error);
	g_assert (success);
	g_assert (format == NM_SETTING_802_1X_CK_FORMAT_X509);

	/* Client cert */
	format = NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;
	success = nm_setting_802_1x_set_client_cert (s_8021x,
	                                             TEST_IFCFG_WIRED_TLS_CLIENT_CERT,
	                                             scheme,
	                                             &format,
	                                             &error);
	g_assert_no_error (error);
	g_assert (success);
	g_assert (format == NM_SETTING_802_1X_CK_FORMAT_X509);

	/* Private key */
	format = NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;
	success = nm_setting_802_1x_set_private_key (s_8021x,
	                                             TEST_IFCFG_WIRED_TLS_PRIVATE_KEY,
	                                             "test1",
	                                             scheme,
	                                             &format,
	                                             &error);
	g_assert_no_error (error);
	g_assert (success);
	g_assert (format == NM_SETTING_802_1X_CK_FORMAT_RAW_KEY);

	/* Set secret flags */
	g_object_set (s_8021x, NM_SETTING_802_1X_PRIVATE_KEY_PASSWORD_FLAGS, flags, NULL);

	/* Verify finished connection */
	success = nm_connection_verify (connection, &error);
	if (!success) {
		g_assert (error);
		g_warning ("Failed to verify connection: %s", error->message);
	}
	g_assert (success);

	/* Save the ifcfg */
	success = writer_new_connection (connection,
	                                 TEST_SCRATCH_DIR "/network-scripts/",
	                                 &testfile,
	                                 &error);
	if (!success) {
		g_assert (error);
		g_warning ("Failed to write connection: %s", error->message);
	}
	g_assert (success);
	g_assert (testfile != NULL);

	/* reread will be normalized, so we must normalize connection too. */
	nm_utils_normalize_connection (connection, TRUE);

	/* re-read the connection for comparison */
	reread = connection_from_file (testfile,
	                               NULL,
	                               TYPE_WIRELESS,
	                               NULL,
	                               &unmanaged,
	                               &keyfile,
	                               &routefile,
	                               &route6file,
	                               &error,
	                               &ignore_error);
	unlink (testfile);
	g_assert (keyfile != NULL);
	unlink (keyfile);

	g_assert (reread != NULL);

	success = nm_connection_verify (reread, &error);
	if (!success) {
		g_assert (error);
		g_warning ("Failed to verify %s: %s", testfile, error->message);
	}
	g_assert (success);

	/* Ensure the reread connection's certificates and private key are paths; no
	 * matter what scheme was used in the original connection they will be read
	 * back in as paths.
	 */
	s_8021x = nm_connection_get_setting_802_1x (reread);
	g_assert (s_8021x);
	g_assert_cmpint (nm_setting_802_1x_get_ca_cert_scheme (s_8021x), ==, NM_SETTING_802_1X_CK_SCHEME_PATH);
	g_assert_cmpint (nm_setting_802_1x_get_client_cert_scheme (s_8021x), ==, NM_SETTING_802_1X_CK_SCHEME_PATH);
	g_assert_cmpint (nm_setting_802_1x_get_private_key_scheme (s_8021x), ==, NM_SETTING_802_1X_CK_SCHEME_PATH);

	g_assert_cmpint (nm_setting_802_1x_get_private_key_password_flags (s_8021x), ==, flags);
	pw = nm_setting_802_1x_get_private_key_password (s_8021x);
	if (flags == NM_SETTING_SECRET_FLAG_NONE) {
		/* Ensure the private key password is still set */
		g_assert (pw != NULL);
		g_assert_cmpstr (pw, ==, "test1");
	} else {
		/* If the secret isn't owned by system settings, make sure its no longer there */
		g_assert (pw == NULL);
	}

	if (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH) {
		/* Do a direct compare if using the path scheme since then the
		 * certificate and key properties should be the same.  If using blob
		 * scheme the original connection cert/key properties will be blobs
		 * but the re-read connection is always path scheme, so we wouldn't
		 * expect it to compare successfully.
		 */
		if (flags != NM_SETTING_SECRET_FLAG_NONE) {
			/* Clear original connection's private key password because flags
			 * say it's not system-owned, and therefore it should not show up
			 * in the re-read connection.
			 */
			s_8021x = nm_connection_get_setting_802_1x (connection);
			g_object_set (s_8021x, NM_SETTING_802_1X_PRIVATE_KEY_PASSWORD, NULL, NULL);
		}

		g_assert (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT));
	}

	/* Clean up created certs and keys */
	tmp = utils_cert_path (testfile, "ca-cert.der");
	unlink (tmp);
	g_free (tmp);

	tmp = utils_cert_path (testfile, "client-cert.der");
	unlink (tmp);
	g_free (tmp);

	tmp = utils_cert_path (testfile, "private-key.pem");
	unlink (tmp);
	g_free (tmp);

	g_free (testfile);
	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
	g_object_unref (reread);
}

#define TEST_SCRATCH_ALIAS_BASE TEST_SCRATCH_DIR "/network-scripts/ifcfg-alias0"

static void
test_write_wired_aliases (void)
{
	NMConnection *connection;
	NMConnection *reread;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIP4Config *s_ip4;
	char *uuid;
	int num_addresses = 4;
	guint32 ip[] = { 0x01010101, 0x01010102, 0x01010103, 0x01010104 };
	const char *label[] = { NULL, "alias0:2", NULL, "alias0:3" };
	const guint32 gw = htonl (0x01010101);
	const guint32 prefix = 24;
	NMIP4Address *addr;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	shvarFile *ifcfg;
	int i, j;

	connection = nm_connection_new ();
	ASSERT (connection != NULL,
	        "wired-aliases-write", "failed to allocate new connection");

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	ASSERT (s_con != NULL,
	        "wired-aliases-write", "failed to allocate new %s setting",
	        NM_SETTING_CONNECTION_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "alias0",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* Wired setting */
	s_wired = (NMSettingWired *) nm_setting_wired_new ();
	ASSERT (s_wired != NULL,
	        "wired-aliases-write", "failed to allocate new %s setting",
	        NM_SETTING_WIRED_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_wired));

	/* IP4 setting */
	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	ASSERT (s_ip4 != NULL,
	        "wired-aliases-write", "failed to allocate new %s setting",
	        NM_SETTING_IP4_CONFIG_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4,
	              NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_MANUAL,
	              NM_SETTING_IP4_CONFIG_MAY_FAIL, TRUE,
	              NULL);

	for (i = 0; i < num_addresses; i++) {
		addr = nm_ip4_address_new ();
		nm_ip4_address_set_address (addr, ip[i]);
		nm_ip4_address_set_prefix (addr, prefix);
		nm_ip4_address_set_gateway (addr, gw);
		NM_UTILS_PRIVATE_CALL (nm_setting_ip4_config_add_address_with_label (s_ip4, addr, label[i]));
		nm_ip4_address_unref (addr);
	}

	ASSERT (nm_connection_verify (connection, &error) == TRUE,
	        "wired-aliases-write", "failed to verify connection: %s",
	        (error && error->message) ? error->message : "(unknown)");

	/* Create some pre-existing alias files, to make sure they get overwritten / deleted. */
	ifcfg = svCreateFile (TEST_SCRATCH_ALIAS_BASE ":2");
	svSetValue (ifcfg, "DEVICE", "alias0:2", FALSE);
	svSetValue (ifcfg, "IPADDR", "192.168.1.2", FALSE);
	svWriteFile (ifcfg, 0644, NULL);
	svCloseFile (ifcfg);
	ASSERT (g_file_test (TEST_SCRATCH_ALIAS_BASE ":2", G_FILE_TEST_EXISTS),
	        "wired-aliases-write", "failed to write extra alias file");

	ifcfg = svCreateFile (TEST_SCRATCH_ALIAS_BASE ":5");
	svSetValue (ifcfg, "DEVICE", "alias0:5", FALSE);
	svSetValue (ifcfg, "IPADDR", "192.168.1.5", FALSE);
	svWriteFile (ifcfg, 0644, NULL);
	svCloseFile (ifcfg);
	ASSERT (g_file_test (TEST_SCRATCH_ALIAS_BASE ":5", G_FILE_TEST_EXISTS),
	        "wired-aliases-write", "failed to write extra alias file");

	/* Save the ifcfg */
	success = writer_new_connection (connection,
	                                 TEST_SCRATCH_DIR "/network-scripts/",
	                                 &testfile,
	                                 &error);
	ASSERT (success == TRUE,
	        "wired-aliases-write", "failed to write connection to disk: %s",
	        (error && error->message) ? error->message : "(unknown)");

	ASSERT (testfile != NULL,
	        "wired-aliases-write", "didn't get ifcfg file path back after writing connection");

	/* Re-check the alias files */
	ASSERT (g_file_test (TEST_SCRATCH_ALIAS_BASE ":2", G_FILE_TEST_EXISTS),
	        "wired-aliases-write", "saving failed to write ifcfg-alias0:2");
	ASSERT (g_file_test (TEST_SCRATCH_ALIAS_BASE ":3", G_FILE_TEST_EXISTS),
	        "wired-aliases-write", "saving failed to write ifcfg-alias0:3");
	ASSERT (!g_file_test (TEST_SCRATCH_ALIAS_BASE ":5", G_FILE_TEST_EXISTS),
	        "wired-aliases-write", "saving failed to delete unused ifcfg-alias0:5");

	/* re-read the connection for comparison */
	reread = connection_from_file (testfile,
	                               NULL,
	                               TYPE_ETHERNET,
	                               NULL,
	                               &unmanaged,
	                               &keyfile,
	                               &routefile,
	                               &route6file,
	                               &error,
	                               &ignore_error);
	unlink (testfile);
	unlink (TEST_SCRATCH_ALIAS_BASE ":2");
	unlink (TEST_SCRATCH_ALIAS_BASE ":3");

	ASSERT (reread != NULL,
	        "wired-aliases-write-reread", "failed to read %s: %s", testfile, error->message);

	ASSERT (nm_connection_verify (reread, &error),
	        "wired-aliases-write-reread-verify", "failed to verify %s: %s", testfile, error->message);

	/* nm_connection_compare() is not guaranteed to succeed, because the
	 * aliases get read back in essentially random order. So just
	 * verify the aliases manually.
	 */
	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	ASSERT (nm_setting_ip4_config_get_num_addresses (s_ip4) == num_addresses,
	        "wired-aliases-write-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        testfile,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_ADDRESSES);

	/* Addresses */
	for (i = 0; i < num_addresses; i++) {
		guint32 addrbytes;

		addr = nm_setting_ip4_config_get_address (s_ip4, i);
		ASSERT (addr,
		        "wired-aliases-write-verify-ip4", "failed to verify %s: missing IP4 address #%d",
		        testfile,
		        i);

		addrbytes = nm_ip4_address_get_address (addr);
		for (j = 0; j < num_addresses; j++) {
			if (addrbytes == ip[j])
				break;
		}

		ASSERT (j < num_addresses,
		        "wired-aliases-write-verify-ip4", "failed to verify %s: unexpected IP4 address #%d",
		        testfile,
		        i);

		ASSERT (nm_ip4_address_get_prefix (addr) == prefix,
		        "wired-aliases-write-verify-ip4", "failed to verify %s: unexpected IP4 address prefix #%d",
		        testfile,
		        i);

		ASSERT (nm_ip4_address_get_gateway (addr) == gw,
		        "wired-aliases-write-verify-ip4", "failed to verify %s: unexpected IP4 address gateway #%d",
		        testfile,
		        i);

		ASSERT (g_strcmp0 (NM_UTILS_PRIVATE_CALL (nm_setting_ip4_config_get_address_label (s_ip4, i)), label[j]) == 0,
		        "wired-aliases-write-verify-ip4", "failed to verify %s: unexpected IP4 address label #%d",
		        testfile,
		        i);

		ip[j] = 0;
	}

	for (i = 0; i < num_addresses; i++) {
		ASSERT (ip[i] == 0,
		        "wired-aliases-write-verify-ip4", "failed to verify %s: did not find IP4 address 0x%08x",
		        testfile,
		        ip[i]);
	}

	g_free (testfile);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
	g_object_unref (reread);
}

static void
test_write_gateway (void)
{
	NMConnection *connection, *reread;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIP4Config *s_ip4;
	char *uuid, *testfile = NULL, *val;
	gboolean success;
	GError *error = NULL;
	shvarFile *f;
	NMIP4Address *addr;
	const char *ip1_str = "1.1.1.3";
	const char *ip2_str = "2.2.2.5";
	const char *gw1_str = "1.1.1.254";
	const char *gw2_str = "2.2.2.254";
	struct in_addr ip1, ip2, gw1, gw2;
	const guint32 prefix = 24;

	connection = nm_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write Static Addresses Gateway",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* Wired setting */
	s_wired = (NMSettingWired *) nm_setting_wired_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wired));

	/* IP4 setting */
	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4,
	              NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_MANUAL,
	              NM_SETTING_IP4_CONFIG_MAY_FAIL, TRUE,
	              NULL);

	inet_pton (AF_INET, ip1_str, &ip1);
	inet_pton (AF_INET, ip2_str, &ip2);
	inet_pton (AF_INET, gw1_str, &gw1);
	inet_pton (AF_INET, gw2_str, &gw2);

	addr = nm_ip4_address_new ();
	nm_ip4_address_set_address (addr, ip1.s_addr);
	nm_ip4_address_set_prefix (addr, prefix);
	nm_ip4_address_set_gateway (addr, gw1.s_addr);
	nm_setting_ip4_config_add_address (s_ip4, addr);
	nm_ip4_address_unref (addr);

	addr = nm_ip4_address_new ();
	nm_ip4_address_set_address (addr, ip2.s_addr);
	nm_ip4_address_set_prefix (addr, prefix);
	nm_ip4_address_set_gateway (addr, gw2.s_addr);
	nm_setting_ip4_config_add_address (s_ip4, addr);
	nm_ip4_address_unref (addr);

	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	/* Save the ifcfg */
	success = writer_new_connection (connection,
	                                 TEST_SCRATCH_DIR "/network-scripts/",
	                                 &testfile,
	                                 &error);
	g_assert_no_error (error);
	g_assert (success);

	f = svOpenFile (testfile, &error);
	g_assert_no_error (error);
	g_assert (f);

	/* re-read the file to check that the keys was written as IPADDR, GATEWAY and IPADDR1, GATEWAY1 */
	val = svGetValue (f, "IPADDR", FALSE);
	g_assert (val);
	g_assert_cmpstr (val, ==, ip1_str);
	g_free (val);

	val = svGetValue (f, "IPADDR1", FALSE);
	g_assert (val);
	g_assert_cmpstr (val, ==, ip2_str);
	g_free (val);

	val = svGetValue (f, "IPADDR0", FALSE);
	g_assert (val == NULL);

	val = svGetValue (f, "PREFIX", FALSE);
	g_assert (val);
	g_assert_cmpstr (val, ==, "24");
	g_free (val);

	val = svGetValue (f, "PREFIX1", FALSE);
	g_assert (val);
	g_assert_cmpstr (val, ==, "24");
	g_free (val);

	val = svGetValue (f, "PREFIX0", FALSE);
	g_assert (val == NULL);

	val = svGetValue (f, "GATEWAY", FALSE);
	g_assert (val);
	g_assert_cmpstr (val, ==, gw1_str);
	g_free (val);

	val = svGetValue (f, "GATEWAY1", FALSE);
	g_assert (val);
	g_assert_cmpstr (val, ==, gw2_str);
	g_free (val);

	val = svGetValue (f, "GATEWAY0", FALSE);
	g_assert (val == NULL);


	svCloseFile (f);

	/* reread will be normalized, so we must normalize connection too. */
	nm_utils_normalize_connection (connection, TRUE);

	/* re-read the connection for comparison */
	reread = connection_from_file (testfile, NULL, TYPE_WIRELESS, NULL,
	                               NULL, NULL, NULL, NULL, &error, NULL);
	unlink (testfile);
	g_assert_no_error (error);
	g_assert (reread);

	success = nm_connection_verify (reread, &error);
	g_assert_no_error (error);
	g_assert (success);

	g_assert (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT));

	g_free (testfile);
	g_object_unref (connection);
	g_object_unref (reread);
}


static void
test_write_wifi_open (void)
{
	NMConnection *connection;
	NMConnection *reread;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wifi;
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;
	char *uuid;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GByteArray *ssid;
	const unsigned char ssid_data[] = { 0x54, 0x65, 0x73, 0x74, 0x20, 0x53, 0x53, 0x49, 0x44 };
	GByteArray *bssid;
	const unsigned char bssid_data[] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
	guint32 channel = 9, mtu = 1345;
	GByteArray *mac;
	const unsigned char mac_data[] = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
	shvarFile *ifcfg;
	char *tmp;

	connection = nm_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write Wifi Open",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRELESS_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* Wifi setting */
	s_wifi = (NMSettingWireless *) nm_setting_wireless_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wifi));

	ssid = g_byte_array_sized_new (sizeof (ssid_data));
	g_byte_array_append (ssid, ssid_data, sizeof (ssid_data));
	bssid = g_byte_array_sized_new (sizeof (bssid_data));
	g_byte_array_append (bssid, bssid_data, sizeof (bssid_data));
	mac = g_byte_array_sized_new (sizeof (mac_data));
	g_byte_array_append (mac, mac_data, sizeof (mac_data));

	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_BSSID, bssid,
	              NM_SETTING_WIRELESS_MAC_ADDRESS, mac,
	              NM_SETTING_WIRELESS_MODE, "infrastructure",
	              NM_SETTING_WIRELESS_BAND, "bg",
	              NM_SETTING_WIRELESS_CHANNEL, channel,
	              NM_SETTING_WIRELESS_MTU, mtu,
	              NULL);

	g_byte_array_free (ssid, TRUE);
	g_byte_array_free (bssid, TRUE);
	g_byte_array_free (mac, TRUE);

	/* IP4 setting */
	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4, NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NM_SETTING_IP6_CONFIG_MAY_FAIL, TRUE,
	              NULL);

	ASSERT (nm_connection_verify (connection, &error) == TRUE,
	        "wifi-open-write", "failed to verify connection: %s",
	        (error && error->message) ? error->message : "(unknown)");

	/* Save the ifcfg */
	success = writer_new_connection (connection,
	                                 TEST_SCRATCH_DIR "/network-scripts/",
	                                 &testfile,
	                                 &error);
	ASSERT (success == TRUE,
	        "wifi-open-write", "failed to write connection to disk: %s",
	        (error && error->message) ? error->message : "(unknown)");

	ASSERT (testfile != NULL,
	        "wifi-open-write", "didn't get ifcfg file path back after writing connection");

	/* reread will be normalized, so we must normalize connection too. */
	nm_utils_normalize_connection (connection, TRUE);

	/* re-read the connection for comparison */
	reread = connection_from_file (testfile,
	                               NULL,
	                               TYPE_WIRELESS,
	                               NULL,
	                               &unmanaged,
	                               &keyfile,
	                               &routefile,
	                               &route6file,
	                               &error,
	                               &ignore_error);
	g_assert_no_error (error);

	/* Now make sure that the ESSID item isn't double-quoted (rh #606518) */
	ifcfg = svOpenFile (testfile, &error);
	g_assert_no_error (error);
	g_assert (ifcfg != NULL);

	tmp = svGetValue (ifcfg, "ESSID", TRUE);
	ASSERT (tmp != NULL,
	        "wifi-open-write-reread", "failed to read ESSID key from %s", testfile);

	ASSERT (strncmp (tmp, "\"\"", 2) != 0,
	        "wifi-open-write-reread", "unexpected ESSID double-quote in %s", testfile);

	g_free (tmp);
	svCloseFile (ifcfg);

	unlink (testfile);

	ASSERT (reread != NULL,
	        "wifi-open-write-reread", "failed to read %s: %s", testfile, error->message);

	ASSERT (nm_connection_verify (reread, &error),
	        "wifi-open-write-reread-verify", "failed to verify %s: %s", testfile, error->message);

	ASSERT (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "wifi-open-write", "written and re-read connection weren't the same.");

	g_free (testfile);
	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
	g_object_unref (reread);
}

static void
test_write_wifi_open_hex_ssid (void)
{
	NMConnection *connection;
	NMConnection *reread;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wifi;
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;
	char *uuid;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GByteArray *ssid;
	const unsigned char ssid_data[] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd };

	connection = nm_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write Wifi Open Hex SSID",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRELESS_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* Wifi setting */
	s_wifi = (NMSettingWireless *) nm_setting_wireless_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wifi));

	ssid = g_byte_array_sized_new (sizeof (ssid_data));
	g_byte_array_append (ssid, ssid_data, sizeof (ssid_data));

	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_MODE, "infrastructure",
	              NULL);

	g_byte_array_free (ssid, TRUE);

	/* IP4 setting */
	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4, NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NM_SETTING_IP6_CONFIG_MAY_FAIL, TRUE,
	              NULL);

	ASSERT (nm_connection_verify (connection, &error) == TRUE,
	        "wifi-open-hex-ssid-write", "failed to verify connection: %s",
	        (error && error->message) ? error->message : "(unknown)");

	/* Save the ifcfg */
	success = writer_new_connection (connection,
	                                 TEST_SCRATCH_DIR "/network-scripts/",
	                                 &testfile,
	                                 &error);
	ASSERT (success == TRUE,
	        "wifi-open-hex-ssid-write", "failed to write connection to disk: %s",
	        (error && error->message) ? error->message : "(unknown)");

	ASSERT (testfile != NULL,
	        "wifi-open-hex-ssid-write", "didn't get ifcfg file path back after writing connection");

	/* reread will be normalized, so we must normalize connection too. */
	nm_utils_normalize_connection (connection, TRUE);

	/* re-read the connection for comparison */
	reread = connection_from_file (testfile,
	                               NULL,
	                               TYPE_WIRELESS,
	                               NULL,
	                               &unmanaged,
	                               &keyfile,
	                               &routefile,
	                               &route6file,
	                               &error,
	                               &ignore_error);
	unlink (testfile);

	ASSERT (reread != NULL,
	        "wifi-open-hex-ssid-write-reread", "failed to read %s: %s", testfile, error->message);

	ASSERT (nm_connection_verify (reread, &error),
	        "wifi-open-hex-ssid-write-reread-verify", "failed to verify %s: %s", testfile, error->message);

	ASSERT (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "wifi-open-hex-ssid-write", "written and re-read connection weren't the same.");

	g_free (testfile);
	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
	g_object_unref (reread);
}

static void
test_write_wifi_wep (void)
{
	NMConnection *connection;
	NMConnection *reread;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wifi;
	NMSettingWirelessSecurity *s_wsec;
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;
	char *uuid;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GByteArray *ssid;
	const unsigned char ssid_data[] = "blahblah";
	struct stat statbuf;

	connection = nm_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write Wifi WEP",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRELESS_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* Wifi setting */
	s_wifi = (NMSettingWireless *) nm_setting_wireless_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wifi));

	ssid = g_byte_array_sized_new (sizeof (ssid_data));
	g_byte_array_append (ssid, ssid_data, sizeof (ssid_data));

	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_MODE, "infrastructure",
	              NULL);

	g_byte_array_free (ssid, TRUE);

	/* Wireless security setting */
	s_wsec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wsec));

	g_object_set (s_wsec,
	              NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "none",
	              NM_SETTING_WIRELESS_SECURITY_WEP_TX_KEYIDX, 2,
	              NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "shared",
	              NULL);
	nm_setting_wireless_security_set_wep_key (s_wsec, 0, "0123456789abcdef0123456789");
	nm_setting_wireless_security_set_wep_key (s_wsec, 1, "11111111111111111111111111");
	nm_setting_wireless_security_set_wep_key (s_wsec, 2, "aaaaaaaaaaaaaaaaaaaaaaaaaa");
	nm_setting_wireless_security_set_wep_key (s_wsec, 3, "BBBBBBBBBBBBBBBBBBBBBBBBBB");

	/* IP4 setting */
	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4, NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NM_SETTING_IP6_CONFIG_MAY_FAIL, TRUE,
	              NULL);

	ASSERT (nm_connection_verify (connection, &error) == TRUE,
	        "wifi-wep-write", "failed to verify connection: %s",
	        (error && error->message) ? error->message : "(unknown)");

	/* Save the ifcfg */
	success = writer_new_connection (connection,
	                                 TEST_SCRATCH_DIR "/network-scripts/",
	                                 &testfile,
	                                 &error);
	ASSERT (success == TRUE,
	        "wifi-wep-write", "failed to write connection to disk: %s",
	        (error && error->message) ? error->message : "(unknown)");

	ASSERT (testfile != NULL,
	        "wifi-wep-write", "didn't get ifcfg file path back after writing connection");

	/* reread will be normalized, so we must normalize connection too. */
	nm_utils_normalize_connection (connection, TRUE);

	/* re-read the connection for comparison */
	reread = connection_from_file (testfile,
	                               NULL,
	                               TYPE_WIRELESS,
	                               NULL,
	                               &unmanaged,
	                               &keyfile,
	                               &routefile,
	                               &route6file,
	                               &error,
	                               &ignore_error);
	unlink (testfile);

	ASSERT (keyfile != NULL,
	        "wifi-wep-write-reread", "expected keyfile for '%s'", testfile);

	ASSERT (stat (keyfile, &statbuf) == 0,
	        "wifi-wep-write-reread", "couldn't stat() '%s'", keyfile);
	ASSERT (S_ISREG (statbuf.st_mode),
	        "wifi-wep-write-reread", "keyfile '%s' wasn't a normal file", keyfile);
	ASSERT ((statbuf.st_mode & 0077) == 0,
	        "wifi-wep-write-reread", "keyfile '%s' wasn't readable only by its owner", keyfile);

	unlink (keyfile);

	ASSERT (reread != NULL,
	        "wifi-wep-write-reread", "failed to read %s: %s", testfile, error->message);

	ASSERT (nm_connection_verify (reread, &error),
	        "wifi-wep-write-reread-verify", "failed to verify %s: %s", testfile, error->message);

	ASSERT (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "wifi-wep-write", "written and re-read connection weren't the same.");

	g_free (testfile);
	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
	g_object_unref (reread);
}

static void
test_write_wifi_wep_adhoc (void)
{
	NMConnection *connection;
	NMConnection *reread;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wifi;
	NMSettingWirelessSecurity *s_wsec;
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;
	char *uuid;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GByteArray *ssid;
	const unsigned char ssid_data[] = "blahblah";
	struct stat statbuf;
	NMIP4Address *addr;
	const guint32 ip1 = htonl (0x01010103);
	const guint32 gw = htonl (0x01010101);
	const guint32 dns1 = htonl (0x04020201);
	const guint32 prefix = 24;

	connection = nm_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write Wifi WEP AdHoc",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRELESS_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* Wifi setting */
	s_wifi = (NMSettingWireless *) nm_setting_wireless_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wifi));

	ssid = g_byte_array_sized_new (sizeof (ssid_data));
	g_byte_array_append (ssid, ssid_data, sizeof (ssid_data));

	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_MODE, "adhoc",
	              NULL);

	g_byte_array_free (ssid, TRUE);

	/* Wireless security setting */
	s_wsec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wsec));

	g_object_set (s_wsec, NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "none", NULL);
	nm_setting_wireless_security_set_wep_key (s_wsec, 0, "0123456789abcdef0123456789");

	/* IP4 setting */
	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4, NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_MANUAL, NULL);

	/* IP Address */
	addr = nm_ip4_address_new ();
	nm_ip4_address_set_address (addr, ip1);
	nm_ip4_address_set_prefix (addr, prefix);
	nm_ip4_address_set_gateway (addr, gw);
	nm_setting_ip4_config_add_address (s_ip4, addr);
	nm_ip4_address_unref (addr);

	nm_setting_ip4_config_add_dns (s_ip4, dns1);

	/* IP6 setting */
	s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NM_SETTING_IP6_CONFIG_MAY_FAIL, TRUE,
	              NULL);

	ASSERT (nm_connection_verify (connection, &error) == TRUE,
	        "wifi-wep-adhoc-write", "failed to verify connection: %s",
	        (error && error->message) ? error->message : "(unknown)");

	/* Save the ifcfg */
	success = writer_new_connection (connection,
	                                 TEST_SCRATCH_DIR "/network-scripts/",
	                                 &testfile,
	                                 &error);
	ASSERT (success == TRUE,
	        "wifi-wep-adhoc-write", "failed to write connection to disk: %s",
	        (error && error->message) ? error->message : "(unknown)");

	ASSERT (testfile != NULL,
	        "wifi-wep-adhoc-write", "didn't get ifcfg file path back after writing connection");

	/* reread will be normalized, so we must normalize connection too. */
	nm_utils_normalize_connection (connection, TRUE);

	/* re-read the connection for comparison */
	reread = connection_from_file (testfile,
	                               NULL,
	                               TYPE_WIRELESS,
	                               NULL,
	                               &unmanaged,
	                               &keyfile,
	                               &routefile,
	                               &route6file,
	                               &error,
	                               &ignore_error);
	unlink (testfile);

	ASSERT (keyfile != NULL,
	        "wifi-wep-adhoc-write-reread", "expected keyfile for '%s'", testfile);

	ASSERT (stat (keyfile, &statbuf) == 0,
	        "wifi-wep-adhoc-write-reread", "couldn't stat() '%s'", keyfile);
	ASSERT (S_ISREG (statbuf.st_mode),
	        "wifi-wep-adhoc-write-reread", "keyfile '%s' wasn't a normal file", keyfile);
	ASSERT ((statbuf.st_mode & 0077) == 0,
	        "wifi-wep-adhoc-write-reread", "keyfile '%s' wasn't readable only by its owner", keyfile);

	unlink (keyfile);

	ASSERT (reread != NULL,
	        "wifi-wep-adhoc-write-reread", "failed to read %s: %s", testfile, error->message);

	ASSERT (nm_connection_verify (reread, &error),
	        "wifi-wep-adhoc-write-reread-verify", "failed to verify %s: %s", testfile, error->message);

	ASSERT (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "wifi-wep-adhoc-write", "written and re-read connection weren't the same.");

	g_free (testfile);
	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
	g_object_unref (reread);
}

static void
test_write_wifi_wep_passphrase (void)
{
	NMConnection *connection;
	NMConnection *reread;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wifi;
	NMSettingWirelessSecurity *s_wsec;
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;
	char *uuid;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GByteArray *ssid;
	const unsigned char ssid_data[] = "blahblah";
	struct stat statbuf;

	connection = nm_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write Wifi WEP Passphrase",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRELESS_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* Wifi setting */
	s_wifi = (NMSettingWireless *) nm_setting_wireless_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wifi));

	ssid = g_byte_array_sized_new (sizeof (ssid_data));
	g_byte_array_append (ssid, ssid_data, sizeof (ssid_data));

	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_MODE, "infrastructure",
	              NULL);

	g_byte_array_free (ssid, TRUE);

	/* Wireless security setting */
	s_wsec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wsec));

	g_object_set (s_wsec,
	              NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "none",
	              NM_SETTING_WIRELESS_SECURITY_WEP_TX_KEYIDX, 0,
	              NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "shared",
	              NM_SETTING_WIRELESS_SECURITY_WEP_KEY_TYPE, NM_WEP_KEY_TYPE_PASSPHRASE,
	              NULL);
	nm_setting_wireless_security_set_wep_key (s_wsec, 0, "asdfdjaslfjasd;flasjdfl;aksdf");

	/* IP4 setting */
	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4, NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NM_SETTING_IP6_CONFIG_MAY_FAIL, TRUE,
	              NULL);

	ASSERT (nm_connection_verify (connection, &error) == TRUE,
	        "wifi-wep-passphrase-write", "failed to verify connection: %s",
	        (error && error->message) ? error->message : "(unknown)");

	/* Save the ifcfg */
	success = writer_new_connection (connection,
	                                 TEST_SCRATCH_DIR "/network-scripts/",
	                                 &testfile,
	                                 &error);
	ASSERT (success == TRUE,
	        "wifi-wep-passphrase-write", "failed to write connection to disk: %s",
	        (error && error->message) ? error->message : "(unknown)");

	ASSERT (testfile != NULL,
	        "wifi-wep-passphrase-write", "didn't get ifcfg file path back after writing connection");

	/* reread will be normalized, so we must normalize connection too. */
	nm_utils_normalize_connection (connection, TRUE);

	/* re-read the connection for comparison */
	reread = connection_from_file (testfile,
	                               NULL,
	                               TYPE_WIRELESS,
	                               NULL,
	                               &unmanaged,
	                               &keyfile,
	                               &routefile,
	                               &route6file,
	                               &error,
	                               &ignore_error);
	unlink (testfile);

	ASSERT (keyfile != NULL,
	        "wifi-wep-passphrase-write-reread", "expected keyfile for '%s'", testfile);

	ASSERT (stat (keyfile, &statbuf) == 0,
	        "wifi-wep-passphrase-write-reread", "couldn't stat() '%s'", keyfile);
	ASSERT (S_ISREG (statbuf.st_mode),
	        "wifi-wep-passphrase-write-reread", "keyfile '%s' wasn't a normal file", keyfile);
	ASSERT ((statbuf.st_mode & 0077) == 0,
	        "wifi-wep-passphrase-write-reread", "keyfile '%s' wasn't readable only by its owner", keyfile);

	unlink (keyfile);

	ASSERT (reread != NULL,
	        "wifi-wep-passphrase-write-reread", "failed to read %s: %s", testfile, error->message);

	ASSERT (nm_connection_verify (reread, &error),
	        "wifi-wep-passphrase-write-reread-verify", "failed to verify %s: %s", testfile, error->message);

	ASSERT (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "wifi-wep-passphrase-write", "written and re-read connection weren't the same.");

	g_free (testfile);
	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
	g_object_unref (reread);
}

static void
test_write_wifi_wep_40_ascii (void)
{
	NMConnection *connection;
	NMConnection *reread;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wifi;
	NMSettingWirelessSecurity *s_wsec;
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;
	char *uuid;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GByteArray *ssid;
	const unsigned char ssid_data[] = "blahblah40";
	struct stat statbuf;

	connection = nm_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write Wifi WEP 40 ASCII",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRELESS_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* Wifi setting */
	s_wifi = (NMSettingWireless *) nm_setting_wireless_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wifi));

	ssid = g_byte_array_sized_new (sizeof (ssid_data));
	g_byte_array_append (ssid, ssid_data, sizeof (ssid_data));

	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_MODE, "infrastructure",
	              NULL);

	g_byte_array_free (ssid, TRUE);

	/* Wireless security setting */
	s_wsec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wsec));

	g_object_set (s_wsec,
	              NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "none",
	              NM_SETTING_WIRELESS_SECURITY_WEP_TX_KEYIDX, 2,
	              NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "shared",
	              NULL);
	nm_setting_wireless_security_set_wep_key (s_wsec, 0, "lorem");
	nm_setting_wireless_security_set_wep_key (s_wsec, 1, "ipsum");
	nm_setting_wireless_security_set_wep_key (s_wsec, 2, "dolor");
	nm_setting_wireless_security_set_wep_key (s_wsec, 3, "donec");

	/* IP4 setting */
	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4, NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NM_SETTING_IP6_CONFIG_MAY_FAIL, TRUE,
	              NULL);

	ASSERT (nm_connection_verify (connection, &error) == TRUE,
	        "wifi-wep-40-ascii-write", "failed to verify connection: %s",
	        (error && error->message) ? error->message : "(unknown)");

	/* Save the ifcfg */
	success = writer_new_connection (connection,
	                                 TEST_SCRATCH_DIR "/network-scripts/",
	                                 &testfile,
	                                 &error);
	ASSERT (success == TRUE,
	        "wifi-wep-40-ascii-write", "failed to write connection to disk: %s",
	        (error && error->message) ? error->message : "(unknown)");

	ASSERT (testfile != NULL,
	        "wifi-wep-40-ascii-write", "didn't get ifcfg file path back after writing connection");

	/* reread will be normalized, so we must normalize connection too. */
	nm_utils_normalize_connection (connection, TRUE);

	/* re-read the connection for comparison */
	reread = connection_from_file (testfile,
	                               NULL,
	                               TYPE_WIRELESS,
	                               NULL,
	                               &unmanaged,
	                               &keyfile,
	                               &routefile,
	                               &route6file,
	                               &error,
	                               &ignore_error);
	unlink (testfile);

	ASSERT (keyfile != NULL,
	        "wifi-wep-40-ascii-write-reread", "expected keyfile for '%s'", testfile);

	ASSERT (stat (keyfile, &statbuf) == 0,
	        "wifi-wep-40-ascii-write-reread", "couldn't stat() '%s'", keyfile);
	ASSERT (S_ISREG (statbuf.st_mode),
	        "wifi-wep-40-ascii-write-reread", "keyfile '%s' wasn't a normal file", keyfile);
	ASSERT ((statbuf.st_mode & 0077) == 0,
	        "wifi-wep-40-ascii-write-reread", "keyfile '%s' wasn't readable only by its owner", keyfile);

	unlink (keyfile);

	ASSERT (reread != NULL,
	        "wifi-wep-40-ascii-write-reread", "failed to read %s: %s", testfile, error->message);

	ASSERT (nm_connection_verify (reread, &error),
	        "wifi-wep-40-ascii-write-reread-verify", "failed to verify %s: %s", testfile, error->message);

	ASSERT (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "wifi-wep-40-ascii-write", "written and re-read connection weren't the same.");

	g_free (testfile);
	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
	g_object_unref (reread);
}

static void
test_write_wifi_wep_104_ascii (void)
{
	NMConnection *connection;
	NMConnection *reread;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wifi;
	NMSettingWirelessSecurity *s_wsec;
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;
	char *uuid;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GByteArray *ssid;
	const unsigned char ssid_data[] = "blahblah104";
	struct stat statbuf;

	connection = nm_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write Wifi WEP 104 ASCII",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRELESS_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* Wifi setting */
	s_wifi = (NMSettingWireless *) nm_setting_wireless_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wifi));

	ssid = g_byte_array_sized_new (sizeof (ssid_data));
	g_byte_array_append (ssid, ssid_data, sizeof (ssid_data));

	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_MODE, "infrastructure",
	              NULL);

	g_byte_array_free (ssid, TRUE);

	/* Wireless security setting */
	s_wsec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wsec));

	g_object_set (s_wsec,
	              NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "none",
	              NM_SETTING_WIRELESS_SECURITY_WEP_TX_KEYIDX, 0,
	              NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "open",
	              NULL);
	nm_setting_wireless_security_set_wep_key (s_wsec, 0, "LoremIpsumSit");
	nm_setting_wireless_security_set_wep_key (s_wsec, 1, "AlfaBetaGamma");
	nm_setting_wireless_security_set_wep_key (s_wsec, 2, "WEP-104 ASCII");
	nm_setting_wireless_security_set_wep_key (s_wsec, 3, "thisismyascii");

	/* IP4 setting */
	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4, NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NM_SETTING_IP6_CONFIG_MAY_FAIL, TRUE,
	              NULL);

	ASSERT (nm_connection_verify (connection, &error) == TRUE,
	        "wifi-wep-104-ascii-write", "failed to verify connection: %s",
	        (error && error->message) ? error->message : "(unknown)");

	/* Save the ifcfg */
	success = writer_new_connection (connection,
	                                 TEST_SCRATCH_DIR "/network-scripts/",
	                                 &testfile,
	                                 &error);
	ASSERT (success == TRUE,
	        "wifi-wep-104-ascii-write", "failed to write connection to disk: %s",
	        (error && error->message) ? error->message : "(unknown)");

	ASSERT (testfile != NULL,
	        "wifi-wep-104-ascii-write", "didn't get ifcfg file path back after writing connection");

	/* reread will be normalized, so we must normalize connection too. */
	nm_utils_normalize_connection (connection, TRUE);

	/* re-read the connection for comparison */
	reread = connection_from_file (testfile,
	                               NULL,
	                               TYPE_WIRELESS,
	                               NULL,
	                               &unmanaged,
	                               &keyfile,
	                               &routefile,
	                               &route6file,
	                               &error,
	                               &ignore_error);
	unlink (testfile);

	ASSERT (keyfile != NULL,
	        "wifi-wep-104-ascii-write-reread", "expected keyfile for '%s'", testfile);

	ASSERT (stat (keyfile, &statbuf) == 0,
	        "wifi-wep-104-ascii-write-reread", "couldn't stat() '%s'", keyfile);
	ASSERT (S_ISREG (statbuf.st_mode),
	        "wifi-wep-104-ascii-write-reread", "keyfile '%s' wasn't a normal file", keyfile);
	ASSERT ((statbuf.st_mode & 0077) == 0,
	        "wifi-wep-104-ascii-write-reread", "keyfile '%s' wasn't readable only by its owner", keyfile);

	unlink (keyfile);

	ASSERT (reread != NULL,
	        "wifi-wep-104-ascii-write-reread", "failed to read %s: %s", testfile, error->message);

	ASSERT (nm_connection_verify (reread, &error),
	        "wifi-wep-104-ascii-write-reread-verify", "failed to verify %s: %s", testfile, error->message);

	ASSERT (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "wifi-wep-104-ascii-write", "written and re-read connection weren't the same.");

	g_free (testfile);
	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
	g_object_unref (reread);
}

static void
test_write_wifi_leap (void)
{
	NMConnection *connection;
	NMConnection *reread;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wifi;
	NMSettingWirelessSecurity *s_wsec;
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;
	char *uuid;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GByteArray *ssid;
	const unsigned char ssid_data[] = "blahblah";
	struct stat statbuf;

	connection = nm_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write Wifi LEAP",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRELESS_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* Wifi setting */
	s_wifi = (NMSettingWireless *) nm_setting_wireless_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wifi));

	ssid = g_byte_array_sized_new (sizeof (ssid_data));
	g_byte_array_append (ssid, ssid_data, sizeof (ssid_data));

	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_MODE, "infrastructure",
	              NULL);

	g_byte_array_free (ssid, TRUE);

	/* Wireless security setting */
	s_wsec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wsec));

	g_object_set (s_wsec,
	              NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "ieee8021x",
	              NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "leap",
	              NM_SETTING_WIRELESS_SECURITY_LEAP_USERNAME, "Bill Smith",
	              NM_SETTING_WIRELESS_SECURITY_LEAP_PASSWORD, "foobar22",
	              NULL);

	/* IP4 setting */
	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4, NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NM_SETTING_IP6_CONFIG_MAY_FAIL, TRUE,
	              NULL);

	ASSERT (nm_connection_verify (connection, &error) == TRUE,
	        "wifi-leap-write", "failed to verify connection: %s",
	        (error && error->message) ? error->message : "(unknown)");

	/* Save the ifcfg */
	success = writer_new_connection (connection,
	                                 TEST_SCRATCH_DIR "/network-scripts/",
	                                 &testfile,
	                                 &error);
	ASSERT (success == TRUE,
	        "wifi-leap-write", "failed to write connection to disk: %s",
	        (error && error->message) ? error->message : "(unknown)");

	ASSERT (testfile != NULL,
	        "wifi-leap-write", "didn't get ifcfg file path back after writing connection");

	/* reread will be normalized, so we must normalize connection too. */
	nm_utils_normalize_connection (connection, TRUE);

	/* re-read the connection for comparison */
	reread = connection_from_file (testfile,
	                               NULL,
	                               TYPE_WIRELESS,
	                               NULL,
	                               &unmanaged,
	                               &keyfile,
	                               &routefile,
	                               &route6file,
	                               &error,
	                               &ignore_error);
	unlink (testfile);

	ASSERT (keyfile != NULL,
	        "wifi-leap-write-reread", "expected keyfile for '%s'", testfile);

	ASSERT (stat (keyfile, &statbuf) == 0,
	        "wifi-leap-write-reread", "couldn't stat() '%s'", keyfile);
	ASSERT (S_ISREG (statbuf.st_mode),
	        "wifi-leap-write-reread", "keyfile '%s' wasn't a normal file", keyfile);
	ASSERT ((statbuf.st_mode & 0077) == 0,
	        "wifi-leap-write-reread", "keyfile '%s' wasn't readable only by its owner", keyfile);

	unlink (keyfile);

	ASSERT (reread != NULL,
	        "wifi-leap-write-reread", "failed to read %s: %s", testfile, error->message);

	ASSERT (nm_connection_verify (reread, &error),
	        "wifi-leap-write-reread-verify", "failed to verify %s: %s", testfile, error->message);

	ASSERT (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "wifi-leap-write", "written and re-read connection weren't the same.");

	g_free (testfile);
	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
	g_object_unref (reread);
}

static void
test_write_wifi_leap_secret_flags (NMSettingSecretFlags flags)
{
	NMConnection *connection;
	NMConnection *reread;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wifi;
	NMSettingWirelessSecurity *s_wsec;
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;
	char *uuid;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GByteArray *ssid;
	const unsigned char ssid_data[] = "blahblah";

	connection = nm_connection_new ();
	g_assert (connection);

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	g_assert (s_con);
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write Wifi LEAP Secret Flags",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRELESS_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* Wifi setting */
	s_wifi = (NMSettingWireless *) nm_setting_wireless_new ();
	g_assert (s_wifi);
	nm_connection_add_setting (connection, NM_SETTING (s_wifi));

	ssid = g_byte_array_sized_new (sizeof (ssid_data));
	g_byte_array_append (ssid, ssid_data, sizeof (ssid_data));
	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_MODE, "infrastructure",
	              NULL);
	g_byte_array_free (ssid, TRUE);

	/* Wireless security setting */
	s_wsec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
	g_assert (s_wsec);
	nm_connection_add_setting (connection, NM_SETTING (s_wsec));

	g_object_set (s_wsec,
	              NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "ieee8021x",
	              NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "leap",
	              NM_SETTING_WIRELESS_SECURITY_LEAP_USERNAME, "Bill Smith",
	              NM_SETTING_WIRELESS_SECURITY_LEAP_PASSWORD, "foobar22",
	              NM_SETTING_WIRELESS_SECURITY_LEAP_PASSWORD_FLAGS, flags,
	              NULL);

	/* IP4 setting */
	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	g_assert (s_ip4);
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));
	g_object_set (s_ip4, NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();
	g_assert (s_ip6);
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NM_SETTING_IP6_CONFIG_MAY_FAIL, TRUE,
	              NULL);

	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	/* Save the ifcfg */
	success = writer_new_connection (connection,
	                                 TEST_SCRATCH_DIR "/network-scripts/",
	                                 &testfile,
	                                 &error);
	g_assert_no_error (error);
	g_assert (success);
	g_assert (testfile);

	/* reread will be normalized, so we must normalize connection too. */
	nm_utils_normalize_connection (connection, TRUE);

	/* re-read the connection for comparison */
	reread = connection_from_file (testfile,
	                               NULL,
	                               TYPE_WIRELESS,
	                               NULL,
	                               &unmanaged,
	                               &keyfile,
	                               &routefile,
	                               &route6file,
	                               &error,
	                               &ignore_error);
	unlink (testfile);

	g_assert_no_error (error);

	/* No key should be written out since the secret is not system owned */
	g_assert (keyfile);
	g_assert (g_file_test (keyfile, G_FILE_TEST_EXISTS) == FALSE);

	g_assert (reread);

	success = nm_connection_verify (reread, &error);
	g_assert_no_error (error);
	g_assert (success);

	/* Remove the LEAP password from the original connection since it wont' be
	 * in the reread connection, as the password is not system owned.
	 */
	g_object_set (s_wsec, NM_SETTING_WIRELESS_SECURITY_LEAP_PASSWORD, NULL, NULL);
	g_assert (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT));

	g_free (testfile);
	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
	g_object_unref (reread);
}

static void
test_write_wifi_wpa_psk (const char *name,
                         const char *test_name,
                         gboolean wep_group,
                         gboolean wpa,
                         gboolean wpa2,
                         const char *psk)
{
	NMConnection *connection;
	NMConnection *reread;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wifi;
	NMSettingWirelessSecurity *s_wsec;
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;
	char *uuid, *tmp;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GByteArray *ssid;
	const unsigned char ssid_data[] = "blahblah";

	g_return_if_fail (psk != NULL);

	connection = nm_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, name,
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRELESS_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* Wifi setting */
	s_wifi = (NMSettingWireless *) nm_setting_wireless_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wifi));

	ssid = g_byte_array_sized_new (sizeof (ssid_data));
	g_byte_array_append (ssid, ssid_data, sizeof (ssid_data));

	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_MODE, "infrastructure",
	              NULL);

	g_byte_array_free (ssid, TRUE);

	/* Wireless security setting */
	s_wsec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wsec));

	g_object_set (s_wsec,
	              NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "wpa-psk",
	              NM_SETTING_WIRELESS_SECURITY_PSK, psk,
	              NULL);

	if (wep_group) {
		nm_setting_wireless_security_add_group (s_wsec, "wep40");
		nm_setting_wireless_security_add_group (s_wsec, "wep104");
	}
	if (wpa) {
		nm_setting_wireless_security_add_proto (s_wsec, "wpa");
		nm_setting_wireless_security_add_pairwise (s_wsec, "tkip");
		nm_setting_wireless_security_add_group (s_wsec, "tkip");
	}
	if (wpa2) {
		nm_setting_wireless_security_add_proto (s_wsec, "rsn");
		nm_setting_wireless_security_add_pairwise (s_wsec, "ccmp");
		nm_setting_wireless_security_add_group (s_wsec, "ccmp");
	}

	/* IP4 setting */
	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4, NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NM_SETTING_IP6_CONFIG_MAY_FAIL, TRUE,
	              NULL);

	ASSERT (nm_connection_verify (connection, &error) == TRUE,
	        test_name, "failed to verify connection: %s",
	        (error && error->message) ? error->message : "(unknown)");

	/* Save the ifcfg */
	success = writer_new_connection (connection,
	                                 TEST_SCRATCH_DIR "/network-scripts/",
	                                 &testfile,
	                                 &error);
	ASSERT (success == TRUE,
	        test_name, "failed to write connection to disk: %s",
	        (error && error->message) ? error->message : "(unknown)");

	ASSERT (testfile != NULL,
	        test_name, "didn't get ifcfg file path back after writing connection");

	/* reread will be normalized, so we must normalize connection too. */
	nm_utils_normalize_connection (connection, TRUE);

	/* re-read the connection for comparison */
	reread = connection_from_file (testfile,
	                               NULL,
	                               TYPE_WIRELESS,
	                               NULL,
	                               &unmanaged,
	                               &keyfile,
	                               &routefile,
	                               &route6file,
	                               &error,
	                               &ignore_error);
	unlink (testfile);

	tmp = g_strdup_printf ("%s-reread", test_name);
	ASSERT (keyfile != NULL,
	        tmp, "expected keyfile for '%s'", testfile);
	unlink (keyfile);

	ASSERT (reread != NULL,
	        tmp, "failed to read %s: %s", testfile, error->message);

	ASSERT (nm_connection_verify (reread, &error),
	        tmp, "failed to verify %s: %s", testfile, error->message);
	g_free (tmp);

	ASSERT (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        test_name, "written and re-read connection weren't the same.");

	g_free (testfile);
	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
	g_object_unref (reread);
}

static void
test_write_wifi_wpa_psk_adhoc (void)
{
	NMConnection *connection;
	NMConnection *reread;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wifi;
	NMSettingWirelessSecurity *s_wsec;
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;
	char *uuid;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GByteArray *ssid;
	const unsigned char ssid_data[] = "blahblah";
	NMIP4Address *addr;
	const guint32 ip1 = htonl (0x01010103);
	const guint32 gw = htonl (0x01010101);
	const guint32 dns1 = htonl (0x04020201);
	const guint32 prefix = 24;

	connection = nm_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write Wifi WPA PSK",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRELESS_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* Wifi setting */
	s_wifi = (NMSettingWireless *) nm_setting_wireless_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wifi));

	ssid = g_byte_array_sized_new (sizeof (ssid_data));
	g_byte_array_append (ssid, ssid_data, sizeof (ssid_data));

	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_MODE, "adhoc",
	              NM_SETTING_WIRELESS_CHANNEL, 11,
	              NM_SETTING_WIRELESS_BAND, "bg",
	              NULL);

	g_byte_array_free (ssid, TRUE);

	/* Wireless security setting */
	s_wsec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wsec));

	g_object_set (s_wsec,
	              NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "wpa-none",
	              NM_SETTING_WIRELESS_SECURITY_PSK, "7d308b11df1b4243b0f78e5f3fc68cdbb9a264ed0edf4c188edf329ff5b467f0",
	              NULL);

	nm_setting_wireless_security_add_proto (s_wsec, "wpa");
	nm_setting_wireless_security_add_group (s_wsec, "tkip");

	/* IP4 setting */
	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4, NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_MANUAL, NULL);

	/* IP Address */
	addr = nm_ip4_address_new ();
	nm_ip4_address_set_address (addr, ip1);
	nm_ip4_address_set_prefix (addr, prefix);
	nm_ip4_address_set_gateway (addr, gw);
	nm_setting_ip4_config_add_address (s_ip4, addr);
	nm_ip4_address_unref (addr);

	nm_setting_ip4_config_add_dns (s_ip4, dns1);

	/* IP6 setting */
	s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NM_SETTING_IP6_CONFIG_MAY_FAIL, TRUE,
	              NULL);

	ASSERT (nm_connection_verify (connection, &error) == TRUE,
	        "wifi-wpa-psk-adhoc-write", "failed to verify connection: %s",
	        (error && error->message) ? error->message : "(unknown)");

	/* Save the ifcfg */
	success = writer_new_connection (connection,
	                                 TEST_SCRATCH_DIR "/network-scripts/",
	                                 &testfile,
	                                 &error);
	ASSERT (success == TRUE,
	        "wifi-wpa-psk-adhoc-write", "failed to write connection to disk: %s",
	        (error && error->message) ? error->message : "(unknown)");

	ASSERT (testfile != NULL,
	        "wifi-wpa-psk-adhoc-write", "didn't get ifcfg file path back after writing connection");

	/* reread will be normalized, so we must normalize connection too. */
	nm_utils_normalize_connection (connection, TRUE);

	/* re-read the connection for comparison */
	reread = connection_from_file (testfile,
	                               NULL,
	                               TYPE_WIRELESS,
	                               NULL,
	                               &unmanaged,
	                               &keyfile,
	                               &routefile,
	                               &route6file,
	                               &error,
	                               &ignore_error);
	unlink (testfile);

	ASSERT (keyfile != NULL,
	        "wifi-wpa-psk-adhoc-write-reread", "expected keyfile for '%s'", testfile);
	unlink (keyfile);

	ASSERT (reread != NULL,
	        "wifi-wpa-psk-adhoc-write-reread", "failed to read %s: %s", testfile, error->message);

	ASSERT (nm_connection_verify (reread, &error),
	        "wifi-wpa-psk-adhoc-write-reread", "failed to verify %s: %s", testfile, error->message);

	ASSERT (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "wifi-wpa-psk-adhoc-write", "written and re-read connection weren't the same.");

	g_free (testfile);
	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
	g_object_unref (reread);
}

static void
test_write_wifi_wpa_eap_tls (void)
{
	NMConnection *connection;
	NMConnection *reread;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wifi;
	NMSettingWirelessSecurity *s_wsec;
	NMSetting8021x *s_8021x;
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;
	char *uuid;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GByteArray *ssid;
	const char *ssid_data = "blahblah";

	connection = nm_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write Wifi WPA EAP-TLS",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRELESS_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* Wifi setting */
	s_wifi = (NMSettingWireless *) nm_setting_wireless_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wifi));

	ssid = g_byte_array_sized_new (strlen (ssid_data));
	g_byte_array_append (ssid, (const unsigned char *) ssid_data, strlen (ssid_data));

	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_MODE, "infrastructure",
	              NULL);

	g_byte_array_free (ssid, TRUE);

	/* Wireless security setting */
	s_wsec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wsec));

	g_object_set (s_wsec, NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "wpa-eap", NULL);
	nm_setting_wireless_security_add_proto (s_wsec, "wpa");
	nm_setting_wireless_security_add_pairwise (s_wsec, "tkip");
	nm_setting_wireless_security_add_group (s_wsec, "tkip");

	/* Wireless security setting */
	s_8021x = (NMSetting8021x *) nm_setting_802_1x_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_8021x));

	g_object_set (s_8021x, NM_SETTING_802_1X_IDENTITY, "Bill Smith", NULL);

	nm_setting_802_1x_add_eap_method (s_8021x, "tls");

	success = nm_setting_802_1x_set_ca_cert (s_8021x,
	                                         TEST_IFCFG_WIFI_WPA_EAP_TLS_CA_CERT,
	                                         NM_SETTING_802_1X_CK_SCHEME_PATH,
	                                         NULL,
	                                         &error);
	ASSERT (success == TRUE,
	        "wifi-wpa-eap-tls-write", "failed to set CA certificate '%s': %s",
	        TEST_IFCFG_WIFI_WPA_EAP_TLS_CA_CERT, error->message);

	success = nm_setting_802_1x_set_client_cert (s_8021x,
	                                             TEST_IFCFG_WIFI_WPA_EAP_TLS_CLIENT_CERT,
	                                             NM_SETTING_802_1X_CK_SCHEME_PATH,
	                                             NULL,
	                                             &error);
	ASSERT (success == TRUE,
	        "wifi-wpa-eap-tls-write", "failed to set client certificate '%s': %s",
	        TEST_IFCFG_WIFI_WPA_EAP_TLS_CLIENT_CERT, error->message);

	success = nm_setting_802_1x_set_private_key (s_8021x,
	                                             TEST_IFCFG_WIFI_WPA_EAP_TLS_PRIVATE_KEY,
	                                             "test1",
	                                             NM_SETTING_802_1X_CK_SCHEME_PATH,
	                                             NULL,
	                                             &error);
	ASSERT (success == TRUE,
	        "wifi-wpa-eap-tls-write", "failed to set private key '%s': %s",
	        TEST_IFCFG_WIFI_WPA_EAP_TLS_PRIVATE_KEY, error->message);

	/* IP4 setting */
	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4, NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NM_SETTING_IP6_CONFIG_MAY_FAIL, TRUE,
	              NULL);

	ASSERT (nm_connection_verify (connection, &error) == TRUE,
	        "wifi-wpa-eap-tls-write", "failed to verify connection: %s",
	        (error && error->message) ? error->message : "(unknown)");

	/* Save the ifcfg */
	success = writer_new_connection (connection,
	                                 TEST_SCRATCH_DIR "/network-scripts/",
	                                 &testfile,
	                                 &error);
	ASSERT (success == TRUE,
	        "wifi-wpa-eap-tls-write", "failed to write connection to disk: %s",
	        (error && error->message) ? error->message : "(unknown)");

	ASSERT (testfile != NULL,
	        "wifi-wpa-eap-tls-write", "didn't get ifcfg file path back after writing connection");

	/* reread will be normalized, so we must normalize connection too. */
	nm_utils_normalize_connection (connection, TRUE);

	/* re-read the connection for comparison */
	reread = connection_from_file (testfile,
	                               NULL,
	                               TYPE_WIRELESS,
	                               NULL,
	                               &unmanaged,
	                               &keyfile,
	                               &routefile,
	                               &route6file,
	                               &error,
	                               &ignore_error);
	unlink (testfile);

	ASSERT (keyfile != NULL,
	        "wifi-wpa-eap-tls-write-reread", "expected keyfile for '%s'", testfile);
	unlink (keyfile);

	ASSERT (reread != NULL,
	        "wifi-wpa-eap-tls-write-reread", "failed to read %s: %s", testfile, error->message);

	ASSERT (nm_connection_verify (reread, &error),
	        "wifi-wpa-eap-tls-write-reread-verify", "failed to verify %s: %s", testfile, error->message);

	ASSERT (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "wifi-wpa-eap-tls-write", "written and re-read connection weren't the same.");

	g_free (testfile);
	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
	g_object_unref (reread);
}

static void
test_write_wifi_wpa_eap_ttls_tls (void)
{
	NMConnection *connection;
	NMConnection *reread;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wifi;
	NMSettingWirelessSecurity *s_wsec;
	NMSetting8021x *s_8021x;
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;
	char *uuid;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GByteArray *ssid;
	const char *ssid_data = "blahblah";

	connection = nm_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write Wifi WPA EAP-TTLS (TLS)",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRELESS_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* Wifi setting */
	s_wifi = (NMSettingWireless *) nm_setting_wireless_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wifi));

	ssid = g_byte_array_sized_new (strlen (ssid_data));
	g_byte_array_append (ssid, (const unsigned char *) ssid_data, strlen (ssid_data));

	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_MODE, "infrastructure",
	              NULL);

	g_byte_array_free (ssid, TRUE);

	/* Wireless security setting */
	s_wsec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wsec));

	g_object_set (s_wsec, NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "wpa-eap", NULL);
	nm_setting_wireless_security_add_proto (s_wsec, "rsn");
	nm_setting_wireless_security_add_pairwise (s_wsec, "ccmp");
	nm_setting_wireless_security_add_group (s_wsec, "ccmp");

	/* Wireless security setting */
	s_8021x = (NMSetting8021x *) nm_setting_802_1x_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_8021x));

	nm_setting_802_1x_add_eap_method (s_8021x, "ttls");

	g_object_set (s_8021x,
	              NM_SETTING_802_1X_IDENTITY, "Bill Smith",
	              NM_SETTING_802_1X_ANONYMOUS_IDENTITY, "foobar22",
	              NM_SETTING_802_1X_PHASE2_AUTHEAP, "tls",
	              NULL);

	success = nm_setting_802_1x_set_ca_cert (s_8021x,
	                                         TEST_IFCFG_WIFI_WPA_EAP_TLS_CA_CERT,
	                                         NM_SETTING_802_1X_CK_SCHEME_PATH,
	                                         NULL,
	                                         &error);
	ASSERT (success == TRUE,
	        "wifi-wpa-eap-ttls-tls-write", "failed to set CA certificate '%s': %s",
	        TEST_IFCFG_WIFI_WPA_EAP_TLS_CA_CERT, error->message);

	/* Phase 2 TLS stuff */

	/* phase2 CA cert */
	success = nm_setting_802_1x_set_phase2_ca_cert (s_8021x,
	                                                TEST_IFCFG_WIFI_WPA_EAP_TLS_CA_CERT,
	                                                NM_SETTING_802_1X_CK_SCHEME_PATH,
	                                                NULL,
	                                                &error);
	ASSERT (success == TRUE,
	        "wifi-wpa-eap-ttls-tls-write", "failed to set inner CA certificate '%s': %s",
	        TEST_IFCFG_WIFI_WPA_EAP_TLS_CA_CERT, error->message);

	/* phase2 client cert */
	success = nm_setting_802_1x_set_phase2_client_cert (s_8021x,
	                                                    TEST_IFCFG_WIFI_WPA_EAP_TLS_CLIENT_CERT,
	                                                    NM_SETTING_802_1X_CK_SCHEME_PATH,
	                                                    NULL,
	                                                    &error);
	ASSERT (success == TRUE,
	        "wifi-wpa-eap-ttls-tls-write", "failed to set inner client certificate '%s': %s",
	        TEST_IFCFG_WIFI_WPA_EAP_TLS_CLIENT_CERT, error->message);

	/* phase2 private key */
	success = nm_setting_802_1x_set_phase2_private_key (s_8021x,
	                                                    TEST_IFCFG_WIFI_WPA_EAP_TLS_PRIVATE_KEY,
	                                                    "test1",
	                                                    NM_SETTING_802_1X_CK_SCHEME_PATH,
	                                                    NULL,
	                                                    &error);
	ASSERT (success == TRUE,
	        "wifi-wpa-eap-ttls-tls-write", "failed to set private key '%s': %s",
	        TEST_IFCFG_WIFI_WPA_EAP_TLS_PRIVATE_KEY, error->message);

	/* IP4 setting */
	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4, NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NM_SETTING_IP6_CONFIG_MAY_FAIL, TRUE,
	              NULL);

	ASSERT (nm_connection_verify (connection, &error) == TRUE,
	        "wifi-wpa-eap-ttls-tls-write", "failed to verify connection: %s",
	        (error && error->message) ? error->message : "(unknown)");

	/* Save the ifcfg */
	success = writer_new_connection (connection,
	                                 TEST_SCRATCH_DIR "/network-scripts/",
	                                 &testfile,
	                                 &error);
	ASSERT (success == TRUE,
	        "wifi-wpa-eap-ttls-tls-write", "failed to write connection to disk: %s",
	        (error && error->message) ? error->message : "(unknown)");

	ASSERT (testfile != NULL,
	        "wifi-wpa-eap-ttls-tls-write", "didn't get ifcfg file path back after writing connection");

	/* reread will be normalized, so we must normalize connection too. */
	nm_utils_normalize_connection (connection, TRUE);

	/* re-read the connection for comparison */
	reread = connection_from_file (testfile,
	                               NULL,
	                               TYPE_WIRELESS,
	                               NULL,
	                               &unmanaged,
	                               &keyfile,
	                               &routefile,
	                               &route6file,
	                               &error,
	                               &ignore_error);
	unlink (testfile);

	ASSERT (reread != NULL,
	        "wifi-wpa-eap-ttls-tls-write-reread", "failed to read %s: %s", testfile, error->message);

	ASSERT (keyfile != NULL,
	        "wifi-wpa-eap-ttls-tls-write-reread", "expected keyfile for '%s'", testfile);
	unlink (keyfile);

	ASSERT (nm_connection_verify (reread, &error),
	        "wifi-wpa-eap-ttls-tls-write-reread-verify", "failed to verify %s: %s", testfile, error->message);

	ASSERT (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "wifi-wpa-eap-ttls-tls-write", "written and re-read connection weren't the same.");

	g_free (testfile);
	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
	g_object_unref (reread);
}

static void
test_write_wifi_wpa_eap_ttls_mschapv2 (void)
{
	NMConnection *connection;
	NMConnection *reread;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wifi;
	NMSettingWirelessSecurity *s_wsec;
	NMSetting8021x *s_8021x;
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;
	char *uuid;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GByteArray *ssid;
	const char *ssid_data = "blahblah";

	connection = nm_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write Wifi WPA EAP-TTLS (MSCHAPv2)",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRELESS_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* Wifi setting */
	s_wifi = (NMSettingWireless *) nm_setting_wireless_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wifi));

	ssid = g_byte_array_sized_new (strlen (ssid_data));
	g_byte_array_append (ssid, (const unsigned char *) ssid_data, strlen (ssid_data));

	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_MODE, "infrastructure",
	              NULL);

	g_byte_array_free (ssid, TRUE);

	/* Wireless security setting */
	s_wsec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wsec));

	g_object_set (s_wsec, NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "wpa-eap", NULL);
	nm_setting_wireless_security_add_proto (s_wsec, "wpa");
	nm_setting_wireless_security_add_proto (s_wsec, "rsn");
	nm_setting_wireless_security_add_pairwise (s_wsec, "tkip");
	nm_setting_wireless_security_add_pairwise (s_wsec, "ccmp");
	nm_setting_wireless_security_add_group (s_wsec, "tkip");
	nm_setting_wireless_security_add_group (s_wsec, "ccmp");

	/* Wireless security setting */
	s_8021x = (NMSetting8021x *) nm_setting_802_1x_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_8021x));

	nm_setting_802_1x_add_eap_method (s_8021x, "ttls");

	g_object_set (s_8021x,
	              NM_SETTING_802_1X_IDENTITY, "Bill Smith",
	              NM_SETTING_802_1X_PASSWORD, ";alkdfja;dslkfjsad;lkfjsadf",
	              NM_SETTING_802_1X_ANONYMOUS_IDENTITY, "foobar22",
	              NM_SETTING_802_1X_PHASE2_AUTHEAP, "mschapv2",
	              NULL);

	success = nm_setting_802_1x_set_ca_cert (s_8021x,
	                                         TEST_IFCFG_WIFI_WPA_EAP_TLS_CA_CERT,
	                                         NM_SETTING_802_1X_CK_SCHEME_PATH,
	                                         NULL,
	                                         &error);
	ASSERT (success == TRUE,
	        "wifi-wpa-eap-ttls-mschapv2-write", "failed to set CA certificate '%s': %s",
	        TEST_IFCFG_WIFI_WPA_EAP_TLS_CA_CERT, error->message);


	/* IP4 setting */
	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4, NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NM_SETTING_IP6_CONFIG_MAY_FAIL, TRUE,
	              NULL);

	ASSERT (nm_connection_verify (connection, &error) == TRUE,
	        "wifi-wpa-eap-ttls-mschapv2-write", "failed to verify connection: %s",
	        (error && error->message) ? error->message : "(unknown)");

	/* Save the ifcfg */
	success = writer_new_connection (connection,
	                                 TEST_SCRATCH_DIR "/network-scripts/",
	                                 &testfile,
	                                 &error);
	ASSERT (success == TRUE,
	        "wifi-wpa-eap-ttls-mschapv2-write", "failed to write connection to disk: %s",
	        (error && error->message) ? error->message : "(unknown)");

	ASSERT (testfile != NULL,
	        "wifi-wpa-eap-ttls-mschapv2-write", "didn't get ifcfg file path back after writing connection");

	/* reread will be normalized, so we must normalize connection too. */
	nm_utils_normalize_connection (connection, TRUE);

	/* re-read the connection for comparison */
	reread = connection_from_file (testfile,
	                               NULL,
	                               TYPE_WIRELESS,
	                               NULL,
	                               &unmanaged,
	                               &keyfile,
	                               &routefile,
	                               &route6file,
	                               &error,
	                               &ignore_error);
	unlink (testfile);

	ASSERT (reread != NULL,
	        "wifi-wpa-eap-ttls-mschapv2-write-reread", "failed to read %s: %s", testfile, error->message);

	ASSERT (keyfile != NULL,
	        "wifi-wpa-eap-ttls-mschapv2-write-reread", "expected keyfile for '%s'", testfile);
	unlink (keyfile);

	ASSERT (nm_connection_verify (reread, &error),
	        "wifi-wpa-eap-ttls-mschapv2-write-reread-verify", "failed to verify %s: %s", testfile, error->message);

	ASSERT (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "wifi-wpa-eap-ttls-mschapv2-write", "written and re-read connection weren't the same.");

	g_free (testfile);
	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
	g_object_unref (reread);
}

static void
test_write_wifi_wpa_then_open (void)
{
	NMConnection *connection;
	NMConnection *reread;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wifi;
	NMSettingWirelessSecurity *s_wsec;
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;
	char *uuid;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GByteArray *ssid;
	const unsigned char ssid_data[] = "blahblah";

	/* Test that writing out a WPA config then changing that to an open
	 * config doesn't leave various WPA-related keys lying around in the ifcfg.
	 */

	connection = nm_connection_new ();
	g_assert (connection);

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	g_assert (s_con);
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "random wifi connection",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRELESS_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* Wifi setting */
	s_wifi = (NMSettingWireless *) nm_setting_wireless_new ();
	g_assert (s_wifi);
	nm_connection_add_setting (connection, NM_SETTING (s_wifi));

	ssid = g_byte_array_sized_new (sizeof (ssid_data));
	g_byte_array_append (ssid, ssid_data, sizeof (ssid_data));

	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_MODE, "infrastructure",
	              NULL);

	g_byte_array_free (ssid, TRUE);

	/* Wireless security setting */
	s_wsec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
	g_assert (s_wsec);
	nm_connection_add_setting (connection, NM_SETTING (s_wsec));

	g_object_set (s_wsec,
	              NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "wpa-psk",
	              NM_SETTING_WIRELESS_SECURITY_PSK, "some cool PSK",
	              NULL);

	nm_setting_wireless_security_add_proto (s_wsec, "wpa");
	nm_setting_wireless_security_add_pairwise (s_wsec, "tkip");
	nm_setting_wireless_security_add_group (s_wsec, "tkip");

	nm_setting_wireless_security_add_proto (s_wsec, "rsn");
	nm_setting_wireless_security_add_pairwise (s_wsec, "ccmp");
	nm_setting_wireless_security_add_group (s_wsec, "ccmp");

	/* IP4 setting */
	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	g_assert (s_ip4);
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4, NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();
	g_assert (s_ip6);
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NM_SETTING_IP6_CONFIG_MAY_FAIL, TRUE,
	              NULL);

	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	/* Save the ifcfg */
	success = writer_new_connection (connection,
	                                 TEST_SCRATCH_DIR "/network-scripts/",
	                                 &testfile,
	                                 &error);
	g_assert_no_error (error);
	g_assert (success);
	g_assert (testfile);

	/* reread will be normalized, so we must normalize connection too. */
	nm_utils_normalize_connection (connection, TRUE);

	/* re-read the connection for comparison */
	reread = connection_from_file (testfile,
	                               NULL,
	                               TYPE_WIRELESS,
	                               NULL,
	                               &unmanaged,
	                               &keyfile,
	                               &routefile,
	                               &route6file,
	                               &error,
	                               &ignore_error);
	g_assert_no_error (error);
	g_assert (reread);

	success = nm_connection_verify (reread, &error);
	g_assert_no_error (error);

	success = nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT);
	g_assert (success);

	g_free (unmanaged);
	unmanaged = NULL;
	g_free (routefile);
	routefile = NULL;
	g_free (route6file);
	route6file = NULL;
	g_object_unref (reread);

	/* Now change the connection to open and recheck */
	nm_connection_remove_setting (connection, NM_TYPE_SETTING_WIRELESS_SECURITY);

	/* Write it back out */
	success = writer_update_connection (connection,
	                                    TEST_SCRATCH_DIR "/network-scripts/",
	                                    testfile,
	                                    keyfile,
	                                    &error);
	g_assert_no_error (error);
	g_assert (success);

	unlink (keyfile);
	g_free (keyfile);
	keyfile = NULL;

	/* reread will be normalized, so we must normalize connection too. */
	nm_utils_normalize_connection (connection, TRUE);

	/* re-read it for comparison */
	reread = connection_from_file (testfile,
	                               NULL,
	                               TYPE_WIRELESS,
	                               NULL,
	                               &unmanaged,
	                               &keyfile,
	                               &routefile,
	                               &route6file,
	                               &error,
	                               &ignore_error);
	unlink (testfile);
	g_assert_no_error (error);

	g_assert (reread);

	/* No keyfile since it's an open connection this time */
	g_assert (keyfile);
	g_assert (g_file_test (keyfile, G_FILE_TEST_EXISTS) == FALSE);

	success = nm_connection_verify (reread, &error);
	g_assert_no_error (error);

	success = nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT);
	g_assert (success);

	unlink (testfile);
	g_free (testfile);
	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (reread);

	g_object_unref (connection);
}

static void
test_write_wifi_wpa_then_wep_with_perms (void)
{
	NMConnection *connection;
	NMConnection *reread;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wifi;
	NMSettingWirelessSecurity *s_wsec;
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;
	char *uuid;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GByteArray *ssid;
	GSList *perm_list = NULL;
	const unsigned char ssid_data[] = "SomeSSID";

	/* Test that writing out a WPA config then changing that to a WEP
	 * config works and doesn't cause infinite loop or other issues.
	 */

	connection = nm_connection_new ();
	g_assert (connection);

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	g_assert (s_con);
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	perm_list = g_slist_append (perm_list, "user:superman:");
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "random wifi connection 2",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
	              NM_SETTING_CONNECTION_PERMISSIONS, perm_list,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRELESS_SETTING_NAME,
	              NULL);
	g_free (uuid);
	g_slist_free (perm_list);
	ASSERT (nm_setting_connection_get_num_permissions (s_con) == 1,
                "test_write_wifi_wpa_then_wep_with_perms", "unexpected failure adding valid user permisson");

	/* Wifi setting */
	s_wifi = (NMSettingWireless *) nm_setting_wireless_new ();
	g_assert (s_wifi);
	nm_connection_add_setting (connection, NM_SETTING (s_wifi));

	ssid = g_byte_array_sized_new (sizeof (ssid_data));
	g_byte_array_append (ssid, ssid_data, sizeof (ssid_data));

	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_MODE, "infrastructure",
	              NULL);

	g_byte_array_free (ssid, TRUE);

	/* Wireless security setting */
	s_wsec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
	g_assert (s_wsec);
	nm_connection_add_setting (connection, NM_SETTING (s_wsec));

	g_object_set (s_wsec,
	              NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "wpa-psk",
	              NM_SETTING_WIRELESS_SECURITY_PSK, "My cool PSK",
	              NULL);

	nm_setting_wireless_security_add_proto (s_wsec, "wpa");
	nm_setting_wireless_security_add_pairwise (s_wsec, "tkip");
	nm_setting_wireless_security_add_group (s_wsec, "tkip");

	nm_setting_wireless_security_add_proto (s_wsec, "rsn");
	nm_setting_wireless_security_add_pairwise (s_wsec, "ccmp");
	nm_setting_wireless_security_add_group (s_wsec, "ccmp");

	/* IP4 setting */
	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	g_assert (s_ip4);
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4, NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();
	g_assert (s_ip6);
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NM_SETTING_IP6_CONFIG_MAY_FAIL, TRUE,
	              NULL);

	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	/* Save the ifcfg */
	success = writer_new_connection (connection,
	                                 TEST_SCRATCH_DIR "/network-scripts/",
	                                 &testfile,
	                                 &error);
	g_assert_no_error (error);
	g_assert (success);
	g_assert (testfile);

	/* reread will be normalized, so we must normalize connection too. */
	nm_utils_normalize_connection (connection, TRUE);

	/* re-read the connection for comparison */
	reread = connection_from_file (testfile,
	                               NULL,
	                               TYPE_WIRELESS,
	                               NULL,
	                               &unmanaged,
	                               &keyfile,
	                               &routefile,
	                               &route6file,
	                               &error,
	                               &ignore_error);
	g_assert_no_error (error);
	g_assert (reread);

	success = nm_connection_verify (reread, &error);
	g_assert_no_error (error);

	success = nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT);
	g_assert (success);

	g_free (unmanaged);
	unmanaged = NULL;
	g_free (routefile);
	routefile = NULL;
	g_free (route6file);
	route6file = NULL;
	g_object_unref (reread);

	/* Now change the connection to WEP and recheck */
	s_wsec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
	g_assert (s_wsec);
	nm_connection_add_setting (connection, NM_SETTING (s_wsec));

	g_object_set (s_wsec,
	              NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "none",
	              NULL);
	nm_setting_wireless_security_set_wep_key (s_wsec, 0, "abraka  dabra");

	/* Write it back out */
	success = writer_update_connection (connection,
	                                    TEST_SCRATCH_DIR "/network-scripts/",
	                                    testfile,
	                                    keyfile,
	                                    &error);
	g_assert_no_error (error);
	g_assert (success);

	g_free (keyfile);
	keyfile = NULL;

	/* reread will be normalized, so we must normalize connection too. */
	nm_utils_normalize_connection (connection, TRUE);

	/* re-read it for comparison */
	reread = connection_from_file (testfile,
	                               NULL,
	                               TYPE_WIRELESS,
	                               NULL,
	                               &unmanaged,
	                               &keyfile,
	                               &routefile,
	                               &route6file,
	                               &error,
	                               &ignore_error);
	g_assert_no_error (error);

	g_assert (reread);

	success = nm_connection_verify (reread, &error);
	g_assert_no_error (error);

	success = nm_connection_compare (connection, reread,
	                                 NM_SETTING_COMPARE_FLAG_IGNORE_AGENT_OWNED_SECRETS |
	                                 NM_SETTING_COMPARE_FLAG_IGNORE_NOT_SAVED_SECRETS);

	ASSERT (success,
	        "test_write_wifi_wpa_then_wep_with_perms", "failed to compare connections");

	unlink (keyfile);
	unlink (testfile);

	g_free (testfile);
	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (reread);

	g_object_unref (connection);
}

static void
test_write_wifi_dynamic_wep_leap (void)
{
	NMConnection *connection;
	NMConnection *reread;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wifi;
	NMSettingWirelessSecurity *s_wsec;
	NMSetting8021x *s_8021x;
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;
	char *uuid;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GByteArray *ssid;
	const char *ssid_data = "blahblah";
	shvarFile *ifcfg;
	char *tmp;

	connection = nm_connection_new ();
	g_assert (connection);

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	g_assert (s_con);
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write Wifi Dynamic WEP LEAP",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRELESS_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* Wifi setting */
	s_wifi = (NMSettingWireless *) nm_setting_wireless_new ();
	g_assert (s_wifi);
	nm_connection_add_setting (connection, NM_SETTING (s_wifi));

	ssid = g_byte_array_sized_new (strlen (ssid_data));
	g_byte_array_append (ssid, (const unsigned char *) ssid_data, strlen (ssid_data));

	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_MODE, "infrastructure",
	              NULL);

	g_byte_array_free (ssid, TRUE);

	/* Wireless security setting */
	s_wsec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
	g_assert (s_wsec);
	nm_connection_add_setting (connection, NM_SETTING (s_wsec));

	g_object_set (s_wsec, NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "ieee8021x", NULL);

	/* Wireless security setting */
	s_8021x = (NMSetting8021x *) nm_setting_802_1x_new ();
	g_assert (s_8021x);
	nm_connection_add_setting (connection, NM_SETTING (s_8021x));

	nm_setting_802_1x_add_eap_method (s_8021x, "leap");

	g_object_set (s_8021x,
	              NM_SETTING_802_1X_IDENTITY, "Bill Smith",
	              NM_SETTING_802_1X_PASSWORD, ";alkdfja;dslkfjsad;lkfjsadf",
	              NULL);

	/* IP4 setting */
	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	g_assert (s_ip4);
	g_object_set (s_ip4, NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	/* IP6 setting */
	s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();
	g_assert (s_ip6);
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NM_SETTING_IP6_CONFIG_MAY_FAIL, TRUE,
	              NULL);

	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	/* Save the ifcfg */
	success = writer_new_connection (connection,
	                                 TEST_SCRATCH_DIR "/network-scripts/",
	                                 &testfile,
	                                 &error);
	g_assert_no_error (error);
	g_assert (success);
	g_assert (testfile);

	/* reread will be normalized, so we must normalize connection too. */
	nm_utils_normalize_connection (connection, TRUE);

	/* re-read the connection for comparison */
	reread = connection_from_file (testfile,
	                               NULL,
	                               TYPE_WIRELESS,
	                               NULL,
	                               &unmanaged,
	                               &keyfile,
	                               &routefile,
	                               &route6file,
	                               &error,
	                               &ignore_error);
	g_assert_no_error (error);
	g_assert (reread);
	g_assert (keyfile);
	unlink (keyfile);

	success = nm_connection_verify (reread, &error);
	g_assert_no_error (error);
	g_assert (success);

	success = nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT);
	g_assert (success);

	/* Check and make sure that an "old-school" LEAP (Network EAP) connection
	 * did not get written.  Check first that the auth alg is not set to "LEAP"
	 * and next that the only IEEE 802.1x EAP method is "LEAP".
	 */
	ifcfg = svOpenFile (testfile, &error);
	g_assert_no_error (error);
	g_assert (ifcfg);
	tmp = svGetValue (ifcfg, "SECURITYMODE", FALSE);
	g_assert_cmpstr (tmp, ==, NULL);
	g_free (tmp);

	tmp = svGetValue (ifcfg, "IEEE_8021X_EAP_METHODS", FALSE);
	g_assert_cmpstr (tmp, ==, "LEAP");
	g_free (tmp);

	svCloseFile (ifcfg);
	unlink (testfile);

	g_free (testfile);
	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
	g_object_unref (reread);
}

#define TEST_IFCFG_IBFT_DHCP TEST_IFCFG_DIR"/network-scripts/ifcfg-test-ibft-dhcp"

static void
test_read_ibft_dhcp (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIP4Config *s_ip4;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	const char *tmp;
	const GByteArray *array;
	char expected_mac_address[ETH_ALEN] = { 0x00, 0x33, 0x21, 0x98, 0xb9, 0xf1 };
	const char *expected_id = "System test-ibft-dhcp";
	guint64 expected_timestamp = 0;

	connection = connection_from_file (TEST_IFCFG_IBFT_DHCP,
	                                   NULL,
	                                   TYPE_ETHERNET,
	                                   TEST_IFCFG_DIR "/iscsiadm-test-dhcp",
	                                   &unmanaged,
	                                   &keyfile,
	                                   &routefile,
	                                   &route6file,
	                                   &error,
	                                   &ignore_error);
	ASSERT (connection != NULL,
	        "ibft-dhcp-read", "failed to read %s: %s", TEST_IFCFG_IBFT_DHCP, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "ibft-dhcp-verify", "failed to verify %s: %s", TEST_IFCFG_IBFT_DHCP, error->message);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
	        "ibft-dhcp-verify-connection", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_IBFT_DHCP,
	        NM_SETTING_CONNECTION_SETTING_NAME);

	/* ID */
	tmp = nm_setting_connection_get_id (s_con);
	ASSERT (tmp != NULL,
	        "ibft-dhcp-verify-connection", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_IBFT_DHCP,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);
	ASSERT (strcmp (tmp, expected_id) == 0,
	        "ibft-dhcp-verify-connection", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_IBFT_DHCP,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);

	/* UUID can't be tested if the ifcfg does not contain the UUID key, because
	 * the UUID is generated on the full path of the ifcfg file, which can change
	 * depending on where the tests are run.
	 */

	/* Timestamp */
	ASSERT (nm_setting_connection_get_timestamp (s_con) == expected_timestamp,
	        "ibft-dhcp-verify-connection", "failed to verify %s: unexpected %s /%s key value",
	        TEST_IFCFG_IBFT_DHCP,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_TIMESTAMP);

	/* Autoconnect */
	ASSERT (nm_setting_connection_get_autoconnect (s_con) == TRUE,
	        "ibft-dhcp-verify-connection", "failed to verify %s: unexpected %s /%s key value",
	        TEST_IFCFG_IBFT_DHCP,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_AUTOCONNECT);

	/* Read-only */
	ASSERT (nm_setting_connection_get_read_only (s_con) == TRUE,
	        "ibft-dhcp-verify-connection", "failed to verify %s: unexpected %s /%s key value",
	        TEST_IFCFG_IBFT_DHCP,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_READ_ONLY);

	/* ===== WIRED SETTING ===== */

	s_wired = nm_connection_get_setting_wired (connection);
	ASSERT (s_wired != NULL,
	        "ibft-dhcp-verify-wired", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_IBFT_DHCP,
	        NM_SETTING_WIRED_SETTING_NAME);

	/* MAC address */
	array = nm_setting_wired_get_mac_address (s_wired);
	ASSERT (array != NULL,
	        "ibft-dhcp-verify-wired", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_IBFT_DHCP,
	        NM_SETTING_WIRED_SETTING_NAME,
	        NM_SETTING_WIRED_MAC_ADDRESS);
	ASSERT (array->len == ETH_ALEN,
	        "ibft-dhcp-verify-wired", "failed to verify %s: unexpected %s / %s key value length",
	        TEST_IFCFG_IBFT_DHCP,
	        NM_SETTING_WIRED_SETTING_NAME,
	        NM_SETTING_WIRED_MAC_ADDRESS);
	ASSERT (memcmp (array->data, &expected_mac_address[0], sizeof (expected_mac_address)) == 0,
	        "ibft-dhcp-verify-wired", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_IBFT_DHCP,
	        NM_SETTING_WIRED_SETTING_NAME,
	        NM_SETTING_WIRED_MAC_ADDRESS);

	ASSERT (nm_setting_wired_get_mtu (s_wired) == 0,
	        "ibft-dhcp-verify-wired", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_IBFT_DHCP,
	        NM_SETTING_WIRED_SETTING_NAME,
	        NM_SETTING_WIRED_MTU);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	ASSERT (s_ip4 != NULL,
	        "ibft-dhcp-verify-ip4", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_IBFT_DHCP,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME);

	/* Method */
	tmp = nm_setting_ip4_config_get_method (s_ip4);
	ASSERT (strcmp (tmp, NM_SETTING_IP4_CONFIG_METHOD_AUTO) == 0,
	        "ibft-dhcp-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_IBFT_DHCP,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_METHOD);

	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
}

#define TEST_IFCFG_IBFT_STATIC TEST_IFCFG_DIR"/network-scripts/ifcfg-test-ibft-static"

static void
test_read_ibft_static (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIP4Config *s_ip4;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	const char *tmp;
	const GByteArray *array;
	char expected_mac_address[ETH_ALEN] = { 0x00, 0x33, 0x21, 0x98, 0xb9, 0xf0 };
	const char *expected_id = "System test-ibft-static";
	guint64 expected_timestamp = 0;
	const char *expected_dns1 = "10.16.255.2";
	const char *expected_dns2 = "10.16.255.3";
	guint32 addr;
	const char *expected_address1 = "192.168.32.72";
	const char *expected_address1_gw = "192.168.35.254";
	NMIP4Address *ip4_addr;

	connection = connection_from_file (TEST_IFCFG_IBFT_STATIC,
	                                   NULL,
	                                   TYPE_ETHERNET,
	                                   TEST_IFCFG_DIR "/iscsiadm-test-static",
	                                   &unmanaged,
	                                   &keyfile,
	                                   &routefile,
	                                   &route6file,
	                                   &error,
	                                   &ignore_error);
	ASSERT (connection != NULL,
	        "ibft-static-read", "failed to read %s: %s", TEST_IFCFG_IBFT_STATIC, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "ibft-static-verify", "failed to verify %s: %s", TEST_IFCFG_IBFT_STATIC, error->message);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
	        "ibft-static-verify-connection", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_IBFT_STATIC,
	        NM_SETTING_CONNECTION_SETTING_NAME);

	/* ID */
	tmp = nm_setting_connection_get_id (s_con);
	ASSERT (tmp != NULL,
	        "ibft-static-verify-connection", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_IBFT_STATIC,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);
	ASSERT (strcmp (tmp, expected_id) == 0,
	        "ibft-static-verify-connection", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_IBFT_STATIC,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);

	/* UUID can't be tested if the ifcfg does not contain the UUID key, because
	 * the UUID is generated on the full path of the ifcfg file, which can change
	 * depending on where the tests are run.
	 */

	/* Timestamp */
	ASSERT (nm_setting_connection_get_timestamp (s_con) == expected_timestamp,
	        "ibft-static-verify-connection", "failed to verify %s: unexpected %s /%s key value",
	        TEST_IFCFG_IBFT_STATIC,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_TIMESTAMP);

	/* Autoconnect */
	ASSERT (nm_setting_connection_get_autoconnect (s_con) == TRUE,
	        "ibft-static-verify-connection", "failed to verify %s: unexpected %s /%s key value",
	        TEST_IFCFG_IBFT_STATIC,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_AUTOCONNECT);

	/* Read-only */
	ASSERT (nm_setting_connection_get_read_only (s_con) == TRUE,
	        "ibft-static-verify-connection", "failed to verify %s: unexpected %s /%s key value",
	        TEST_IFCFG_IBFT_STATIC,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_READ_ONLY);

	/* ===== WIRED SETTING ===== */

	s_wired = nm_connection_get_setting_wired (connection);
	ASSERT (s_wired != NULL,
	        "ibft-static-verify-wired", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_IBFT_STATIC,
	        NM_SETTING_WIRED_SETTING_NAME);

	/* MAC address */
	array = nm_setting_wired_get_mac_address (s_wired);
	ASSERT (array != NULL,
	        "ibft-static-verify-wired", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_IBFT_STATIC,
	        NM_SETTING_WIRED_SETTING_NAME,
	        NM_SETTING_WIRED_MAC_ADDRESS);
	ASSERT (array->len == ETH_ALEN,
	        "ibft-static-verify-wired", "failed to verify %s: unexpected %s / %s key value length",
	        TEST_IFCFG_IBFT_STATIC,
	        NM_SETTING_WIRED_SETTING_NAME,
	        NM_SETTING_WIRED_MAC_ADDRESS);
	ASSERT (memcmp (array->data, &expected_mac_address[0], sizeof (expected_mac_address)) == 0,
	        "ibft-static-verify-wired", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_IBFT_STATIC,
	        NM_SETTING_WIRED_SETTING_NAME,
	        NM_SETTING_WIRED_MAC_ADDRESS);

	ASSERT (nm_setting_wired_get_mtu (s_wired) == 0,
	        "ibft-static-verify-wired", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_IBFT_STATIC,
	        NM_SETTING_WIRED_SETTING_NAME,
	        NM_SETTING_WIRED_MTU);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	ASSERT (s_ip4 != NULL,
	        "ibft-static-verify-ip4", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_IBFT_STATIC,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME);

	/* Method */
	tmp = nm_setting_ip4_config_get_method (s_ip4);
	ASSERT (strcmp (tmp, NM_SETTING_IP4_CONFIG_METHOD_MANUAL) == 0,
	        "ibft-static-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_IBFT_STATIC,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_METHOD);

	/* DNS Addresses */
	ASSERT (nm_setting_ip4_config_get_num_dns (s_ip4) == 2,
	        "ibft-static-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_IBFT_STATIC,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS);

	ASSERT (inet_pton (AF_INET, expected_dns1, &addr) > 0,
	        "ibft-static-verify-ip4", "failed to verify %s: couldn't convert DNS IP address #1",
	        TEST_IFCFG_IBFT_STATIC,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS);
	ASSERT (nm_setting_ip4_config_get_dns (s_ip4, 0) == addr,
	        "ibft-static-verify-ip4", "failed to verify %s: unexpected %s / %s key value #1",
	        TEST_IFCFG_IBFT_STATIC,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS);

	ASSERT (inet_pton (AF_INET, expected_dns2, &addr) > 0,
	        "ibft-static-verify-ip4", "failed to verify %s: couldn't convert DNS IP address #2",
	        TEST_IFCFG_IBFT_STATIC,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS);
	ASSERT (nm_setting_ip4_config_get_dns (s_ip4, 1) == addr,
	        "ibft-static-verify-ip4", "failed to verify %s: unexpected %s / %s key value #2",
	        TEST_IFCFG_IBFT_STATIC,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS);

	ASSERT (nm_setting_ip4_config_get_num_addresses (s_ip4) == 1,
	        "ibft-static-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_IBFT_STATIC,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS);

	/* Address #1 */
	ip4_addr = nm_setting_ip4_config_get_address (s_ip4, 0);
	ASSERT (ip4_addr,
	        "ibft-static-verify-ip4", "failed to verify %s: missing IP4 address #1",
	        TEST_IFCFG_IBFT_STATIC,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_ADDRESSES);

	ASSERT (nm_ip4_address_get_prefix (ip4_addr) == 22,
	        "ibft-static-verify-ip4", "failed to verify %s: unexpected IP4 address #1 prefix",
	        TEST_IFCFG_IBFT_STATIC,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_ADDRESSES);

	ASSERT (inet_pton (AF_INET, expected_address1, &addr) > 0,
	        "ibft-static-verify-ip4", "failed to verify %s: couldn't convert IP address #1",
	        TEST_IFCFG_IBFT_STATIC,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS);
	ASSERT (nm_ip4_address_get_address (ip4_addr) == addr,
	        "ibft-static-verify-ip4", "failed to verify %s: unexpected IP4 address #1",
	        TEST_IFCFG_IBFT_STATIC,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_ADDRESSES);

	ASSERT (inet_pton (AF_INET, expected_address1_gw, &addr) > 0,
	        "ibft-static-verify-ip4", "failed to verify %s: couldn't convert IP address #1 gateway",
	        TEST_IFCFG_IBFT_STATIC,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_ADDRESSES);
	ASSERT (nm_ip4_address_get_gateway (ip4_addr) == addr,
	        "ibft-static-verify-ip4", "failed to verify %s: unexpected IP4 address #1 gateway",
	        TEST_IFCFG_IBFT_STATIC,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_ADDRESSES);

	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
}

static void
test_read_ibft_malformed (const char *name, const char *iscsiadm_path, gboolean expect_warning)
{
	NMConnection *connection;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;

	g_assert (g_file_test (iscsiadm_path, G_FILE_TEST_EXISTS));

	if (expect_warning) {
		g_test_expect_message ("NetworkManager", G_LOG_LEVEL_WARNING,
		                       "*malformed iscsiadm record*");
	}
	connection = connection_from_file (TEST_IFCFG_IBFT_STATIC,
	                                   NULL,
	                                   TYPE_ETHERNET,
	                                   iscsiadm_path,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &routefile,
	                                   &route6file,
	                                   &error,
	                                   &ignore_error);
	if (expect_warning)
		g_test_assert_expected_messages ();
	ASSERT (connection == NULL,
	        name, "unexpectedly able to read %s", TEST_IFCFG_IBFT_STATIC);

	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
}

static void
test_write_wired_qeth_dhcp (void)
{
	NMConnection *connection;
	NMConnection *reread;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;
	char *uuid;
	GPtrArray *subchans;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;

	connection = nm_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write Wired qeth Static",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* Wired setting */
	s_wired = (NMSettingWired *) nm_setting_wired_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wired));

	subchans = g_ptr_array_sized_new (3);
	g_ptr_array_add (subchans, "0.0.600");
	g_ptr_array_add (subchans, "0.0.601");
	g_ptr_array_add (subchans, "0.0.602");
	g_object_set (s_wired,
	              NM_SETTING_WIRED_S390_SUBCHANNELS, subchans,
	              NM_SETTING_WIRED_S390_NETTYPE, "qeth",
	              NULL);
	g_ptr_array_free (subchans, TRUE);

	nm_setting_wired_add_s390_option (s_wired, "portname", "FOOBAR");
	nm_setting_wired_add_s390_option (s_wired, "portno", "1");
	nm_setting_wired_add_s390_option (s_wired, "layer2", "0");
	nm_setting_wired_add_s390_option (s_wired, "protocol", "blahbalh");

	/* IP4 setting */
	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4,
	              NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
	              NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NM_SETTING_IP6_CONFIG_MAY_FAIL, TRUE,
	              NULL);

	/* Verify */
	ASSERT (nm_connection_verify (connection, &error) == TRUE,
	        "wired-qeth-dhcp-write", "failed to verify connection: %s",
	        (error && error->message) ? error->message : "(unknown)");

	/* Save the ifcfg */
	success = writer_new_connection (connection,
	                                 TEST_SCRATCH_DIR "/network-scripts/",
	                                 &testfile,
	                                 &error);
	ASSERT (success == TRUE,
	        "wired-qeth-dhcp-write", "failed to write connection to disk: %s",
	        (error && error->message) ? error->message : "(unknown)");

	ASSERT (testfile != NULL,
	        "wired-qeth-dhcp-write", "didn't get ifcfg file path back after writing connection");

	/* reread will be normalized, so we must normalize connection too. */
	nm_utils_normalize_connection (connection, TRUE);

	/* re-read the connection for comparison */
	reread = connection_from_file (testfile,
	                               NULL,
	                               TYPE_ETHERNET,
	                               NULL,
	                               &unmanaged,
	                               &keyfile,
	                               &routefile,
	                               &route6file,
	                               &error,
	                               &ignore_error);
	unlink (testfile);

	ASSERT (reread != NULL,
	        "wired-qeth-dhcp-write-reread", "failed to read %s: %s", testfile, error->message);

	ASSERT (nm_connection_verify (reread, &error),
	        "wired-qeth-dhcp-write-reread-verify", "failed to verify %s: %s", testfile, error->message);

	ASSERT (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "wired-qeth-dhcp-write", "written and re-read connection weren't the same.");

	if (route6file)
		unlink (route6file);

	g_free (testfile);
	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
	g_object_unref (reread);
}

static void
test_write_wired_ctc_dhcp (void)
{
	NMConnection *connection;
	NMConnection *reread;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;
	char *uuid;
	GPtrArray *subchans;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	shvarFile *ifcfg;
	char *tmp;

	connection = nm_connection_new ();
	g_assert (connection);

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	g_assert (s_con);
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write Wired ctc Static",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* Wired setting */
	s_wired = (NMSettingWired *) nm_setting_wired_new ();
	g_assert (s_wired);
	nm_connection_add_setting (connection, NM_SETTING (s_wired));

	subchans = g_ptr_array_sized_new (2);
	g_ptr_array_add (subchans, "0.0.600");
	g_ptr_array_add (subchans, "0.0.601");
	g_object_set (s_wired,
	              NM_SETTING_WIRED_S390_SUBCHANNELS, subchans,
	              NM_SETTING_WIRED_S390_NETTYPE, "ctc",
	              NULL);
	g_ptr_array_free (subchans, TRUE);
	nm_setting_wired_add_s390_option (s_wired, "ctcprot", "0");

	/* IP4 setting */
	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	g_assert (s_ip4);
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));
	g_object_set (s_ip4, NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();
	g_assert (s_ip6);
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NM_SETTING_IP6_CONFIG_MAY_FAIL, TRUE,
	              NULL);

	/* Verify */
	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	/* Save the ifcfg */
	success = writer_new_connection (connection,
	                                 TEST_SCRATCH_DIR "/network-scripts/",
	                                 &testfile,
	                                 &error);
	g_assert_no_error (error);
	g_assert (success);
	g_assert (testfile != NULL);

	/* Ensure the CTCPROT item gets written out as it's own option */
	ifcfg = svOpenFile (testfile, &error);
	g_assert_no_error (error);
	g_assert (ifcfg);

	tmp = svGetValue (ifcfg, "CTCPROT", TRUE);
	g_assert (tmp);
	g_assert_cmpstr (tmp, ==, "0");
	g_free (tmp);

	/* And that it's not in the generic OPTIONS string */
	tmp = svGetValue (ifcfg, "OPTIONS", TRUE);
	g_assert (tmp == NULL);
	g_free (tmp);

	svCloseFile (ifcfg);

	/* reread will be normalized, so we must normalize connection too. */
	nm_utils_normalize_connection (connection, TRUE);

	/* re-read the connection for comparison */
	reread = connection_from_file (testfile,
	                               NULL,
	                               TYPE_ETHERNET,
	                               NULL,
	                               &unmanaged,
	                               &keyfile,
	                               &routefile,
	                               &route6file,
	                               &error,
	                               &ignore_error);
	unlink (testfile);

	g_assert (reread);
	success = nm_connection_verify (reread, &error);
	g_assert_no_error (error);
	g_assert (success);

	success = nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT);
	g_assert (success);

	if (route6file)
		unlink (route6file);

	g_free (testfile);
	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
	g_object_unref (reread);
}

static void
test_write_permissions (void)
{
	NMConnection *connection;
	NMConnection *reread;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;
	char *uuid;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;

	connection = nm_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write Permissions",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
	              NULL);
	g_free (uuid);

	nm_setting_connection_add_permission (s_con, "user", "blahblah", NULL);
	nm_setting_connection_add_permission (s_con, "user", "foobar", NULL);
	nm_setting_connection_add_permission (s_con, "user", "asdfasdf", NULL);

	/* Wired setting */
	s_wired = (NMSettingWired *) nm_setting_wired_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wired));

	/* IP4 setting */
	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4,
	              NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
	              NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NM_SETTING_IP6_CONFIG_MAY_FAIL, TRUE,
	              NULL);

	/* Verify */
	ASSERT (nm_connection_verify (connection, &error) == TRUE,
	        "permissions-write", "failed to verify connection: %s",
	        (error && error->message) ? error->message : "(unknown)");

	/* Save the ifcfg */
	success = writer_new_connection (connection,
	                                 TEST_SCRATCH_DIR "/network-scripts/",
	                                 &testfile,
	                                 &error);
	ASSERT (success == TRUE,
	        "permissions-write", "failed to write connection to disk: %s",
	        (error && error->message) ? error->message : "(unknown)");

	ASSERT (testfile != NULL,
	        "permissions-write", "didn't get ifcfg file path back after writing connection");

	/* reread will be normalized, so we must normalize connection too. */
	nm_utils_normalize_connection (connection, TRUE);

	/* re-read the connection for comparison */
	reread = connection_from_file (testfile,
	                               NULL,
	                               TYPE_ETHERNET,
	                               NULL,
	                               &unmanaged,
	                               &keyfile,
	                               &routefile,
	                               &route6file,
	                               &error,
	                               &ignore_error);
	unlink (testfile);

	ASSERT (reread != NULL,
	        "permissions-write-reread", "failed to read %s: %s", testfile, error->message);

	ASSERT (nm_connection_verify (reread, &error),
	        "permissions-write-reread-verify", "failed to verify %s: %s", testfile, error->message);

	ASSERT (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "permissions-write", "written and re-read connection weren't the same.");

	if (route6file)
		unlink (route6file);

	g_free (testfile);
	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
	g_object_unref (reread);
}

static void
test_write_wifi_wep_agent_keys (void)
{
	NMConnection *connection;
	NMConnection *reread;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wifi;
	NMSettingWirelessSecurity *s_wsec;
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;
	char *uuid;
	const char *str_ssid = "foobarbaz";
	GByteArray *ssid;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;

	connection = nm_connection_new ();
	g_assert (connection != NULL);

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	g_assert (s_con);
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write Wifi WEP Agent Owned",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRELESS_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* IP4 setting */
	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	g_assert (s_ip4);
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));
	g_object_set (s_ip4, NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();
	g_assert (s_ip6);
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NM_SETTING_IP6_CONFIG_MAY_FAIL, TRUE,
	              NULL);

	/* Wifi setting */
	s_wifi = (NMSettingWireless *) nm_setting_wireless_new ();
	g_assert (s_wifi);
	nm_connection_add_setting (connection, NM_SETTING (s_wifi));

	ssid = g_byte_array_sized_new (strlen (str_ssid));
	g_byte_array_append (ssid, (guint8 *) str_ssid, strlen (str_ssid));
	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_MODE, "infrastructure",
	              NULL);
	g_byte_array_free (ssid, TRUE);

	/* Wifi security setting */
	s_wsec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
	g_assert (s_wsec);
	nm_connection_add_setting (connection, NM_SETTING (s_wsec));

	g_object_set (s_wsec,
	              NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "none",
	              NM_SETTING_WIRELESS_SECURITY_WEP_KEY_TYPE, NM_WEP_KEY_TYPE_PASSPHRASE,
	              NM_SETTING_WIRELESS_SECURITY_WEP_KEY_FLAGS, NM_SETTING_SECRET_FLAG_AGENT_OWNED,
	              NULL);
	nm_setting_wireless_security_set_wep_key (s_wsec, 0, "asdfdjaslfjasd;flasjdfl;aksdf");

	/* Verify */
	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	/* Save the ifcfg */
	success = writer_new_connection (connection,
	                                 TEST_SCRATCH_DIR "/network-scripts/",
	                                 &testfile,
	                                 &error);
	g_assert_no_error (error);
	g_assert (success);
	g_assert (testfile != NULL);

	/* reread will be normalized, so we must normalize connection too. */
	nm_utils_normalize_connection (connection, TRUE);

	/* re-read the connection for comparison */
	reread = connection_from_file (testfile,
	                               NULL,
	                               TYPE_WIRELESS,
	                               NULL,
	                               &unmanaged,
	                               &keyfile,
	                               &routefile,
	                               &route6file,
	                               &error,
	                               &ignore_error);
	unlink (testfile);

	g_assert_no_error (error);
	g_assert (reread);

	success = nm_connection_verify (reread, &error);
	g_assert_no_error (error);
	g_assert (success);

	/* Remove the WEP key from the original, because it should not have been
	 * written out to disk as it was agent-owned.  The new connection should
	 * not have any WEP keys set.
	 * Also the new connection should not have WEP key type set.
	 */
	nm_setting_wireless_security_set_wep_key (s_wsec, 0, NULL);
	g_object_set (s_wsec,
	              NM_SETTING_WIRELESS_SECURITY_WEP_KEY_TYPE, NM_WEP_KEY_TYPE_UNKNOWN,
	              NULL);

	/* Compare original and reread */
	success = nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT);
	g_assert (success);

	if (route6file)
		unlink (route6file);

	g_free (testfile);
	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
	g_object_unref (reread);
}

static void
test_write_wired_pppoe (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIP4Config *s_ip4;
	NMSettingPPPOE *s_pppoe;
	NMSettingPPP *s_ppp;
	char *uuid;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;

	connection = nm_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write Wired PPPoE",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* Wired setting */
	s_wired = (NMSettingWired *) nm_setting_wired_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wired));

	/* IP4 setting */
	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4,
	              NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
	              NULL);

	/* PPPoE setting */
	s_pppoe = (NMSettingPPPOE *) nm_setting_pppoe_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_pppoe));

	g_object_set (G_OBJECT (s_pppoe),
	              NM_SETTING_PPPOE_SERVICE, "stupid-service",
	              NM_SETTING_PPPOE_USERNAME, "Bill Smith",
	              NM_SETTING_PPPOE_PASSWORD, "test1",
	              NULL);

	/* PPP setting */
	s_ppp = (NMSettingPPP *) nm_setting_ppp_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ppp));

	ASSERT (nm_connection_verify (connection, &error) == TRUE,
	        "wired-pppoe-write", "failed to verify connection: %s",
	        (error && error->message) ? error->message : "(unknown)");

	/* Save the ifcfg */
	success = writer_new_connection (connection,
	                                 TEST_SCRATCH_DIR "/network-scripts/",
	                                 &testfile,
	                                 &error);
	ASSERT (success == FALSE,
	        "wired-pppoe-write", "unexpected success writing connection to disk");

	g_object_unref (connection);
}

static void
test_write_vpn (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingIP4Config *s_ip4;
	NMSettingVPN *s_vpn;
	char *uuid;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;

	connection = nm_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write VPN",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_VPN_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* VPN setting */
	s_vpn = (NMSettingVPN *) nm_setting_vpn_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_vpn));

	g_object_set (s_vpn,
	              NM_SETTING_VPN_SERVICE_TYPE, "awesomevpn",
	              NM_SETTING_VPN_USER_NAME, "Bill Smith",
	              NULL);

	nm_setting_vpn_add_data_item (s_vpn, "server", "vpn.somewhere.com");
	nm_setting_vpn_add_secret (s_vpn, "password", "sup3rs3cr3t");

	/* IP4 setting */
	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4,
	              NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
	              NULL);

	ASSERT (nm_connection_verify (connection, &error) == TRUE,
	        "vpn-write", "failed to verify connection: %s",
	        (error && error->message) ? error->message : "(unknown)");

	/* Save the ifcfg */
	success = writer_new_connection (connection,
	                                 TEST_SCRATCH_DIR "/network-scripts/",
	                                 &testfile,
	                                 &error);
	ASSERT (success == FALSE,
	        "vpn-write", "unexpected success writing connection to disk");

	g_object_unref (connection);
}

static void
test_write_mobile_broadband (gboolean gsm)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingIP4Config *s_ip4;
	NMSettingGsm *s_gsm;
	NMSettingCdma *s_cdma;
	NMSettingPPP *s_ppp;
	NMSettingSerial *s_serial;
	char *uuid;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;

	connection = nm_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, gsm ? "Test Write GSM" : "Test Write CDMA",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
	              NM_SETTING_CONNECTION_TYPE, gsm ? NM_SETTING_GSM_SETTING_NAME : NM_SETTING_CDMA_SETTING_NAME,
	              NULL);
	g_free (uuid);

	if (gsm) {
		/* GSM setting */
		s_gsm = (NMSettingGsm *) nm_setting_gsm_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_gsm));

		g_object_set (s_gsm, NM_SETTING_GSM_NUMBER, "*99#", NULL);
	} else {
		/* CDMA setting */
		s_cdma = (NMSettingCdma *) nm_setting_cdma_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_cdma));

		g_object_set (s_cdma, NM_SETTING_CDMA_NUMBER, "#777", NULL);
	}

	/* Serial setting */
	s_serial = (NMSettingSerial *) nm_setting_serial_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_serial));

	g_object_set (s_serial,
	              NM_SETTING_SERIAL_BAUD, 115200,
	              NM_SETTING_SERIAL_BITS, 8,
	              NM_SETTING_SERIAL_PARITY, 'n',
	              NM_SETTING_SERIAL_STOPBITS, 1,
	              NULL);

	/* IP4 setting */
	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4,
	              NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
	              NULL);

	/* PPP setting */
	s_ppp = (NMSettingPPP *) nm_setting_ppp_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ppp));

	ASSERT (nm_connection_verify (connection, &error) == TRUE,
	        "mobile-broadband-write", "failed to verify connection: %s",
	        (error && error->message) ? error->message : "(unknown)");

	/* Save the ifcfg */
	success = writer_new_connection (connection,
	                                 TEST_SCRATCH_DIR "/network-scripts/",
	                                 &testfile,
	                                 &error);
	ASSERT (success == FALSE,
	        "mobile-broadband-write", "unexpected success writing connection to disk");

	g_object_unref (connection);
}

#define TEST_IFCFG_BRIDGE_MAIN TEST_IFCFG_DIR"/network-scripts/ifcfg-test-bridge-main"

static void
test_read_bridge_main (void)
{
	NMConnection *connection;
	NMSettingBridge *s_bridge;
	const GByteArray *array;
	char expected_mac_address[ETH_ALEN] = { 0x00, 0x16, 0x41, 0x11, 0x22, 0x33 };
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;

	connection = connection_from_file (TEST_IFCFG_BRIDGE_MAIN,
	                                   NULL,
	                                   TYPE_ETHERNET,
	                                   NULL,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &routefile,
	                                   &route6file,
	                                   &error,
	                                   &ignore_error);
	g_assert (connection);
	g_assert (nm_connection_verify (connection, &error));
	g_assert_no_error (error);

	/* ===== Bridging SETTING ===== */

	s_bridge = nm_connection_get_setting_bridge (connection);
	g_assert (s_bridge);
	g_assert_cmpstr (nm_setting_bridge_get_interface_name (s_bridge), ==, "br0");
	g_assert_cmpuint (nm_setting_bridge_get_forward_delay (s_bridge), ==, 0);
	g_assert (nm_setting_bridge_get_stp (s_bridge));
	g_assert_cmpuint (nm_setting_bridge_get_priority (s_bridge), ==, 32744);
	g_assert_cmpuint (nm_setting_bridge_get_hello_time (s_bridge), ==, 7);
	g_assert_cmpuint (nm_setting_bridge_get_max_age (s_bridge), ==, 39);
	g_assert_cmpuint (nm_setting_bridge_get_ageing_time (s_bridge), ==, 235352);
	/* MAC address */
	array = nm_setting_bridge_get_mac_address (s_bridge);
	g_assert (array);
	g_assert_cmpint (array->len, ==, ETH_ALEN);
	g_assert (memcmp (array->data, &expected_mac_address[0], ETH_ALEN) == 0);

	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
}

static void
test_write_bridge_main (void)
{
	NMConnection *connection;
	NMConnection *reread;
	NMSettingConnection *s_con;
	NMSettingBridge *s_bridge;
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;
	char *uuid;
	const guint32 ip1 = htonl (0x01010103);
	const guint32 gw = htonl (0x01010101);
	const guint32 prefix = 24;
	NMIP4Address *addr;
	static unsigned char bridge_mac[] = { 0x31, 0x33, 0x33, 0x37, 0xbe, 0xcd };
	GByteArray *mac_array;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;

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
	              NULL);
	g_free (uuid);

	/* bridge setting */
	s_bridge = (NMSettingBridge *) nm_setting_bridge_new ();
	g_assert (s_bridge);
	nm_connection_add_setting (connection, NM_SETTING (s_bridge));

	mac_array = g_byte_array_sized_new (sizeof (bridge_mac));
	g_byte_array_append (mac_array, bridge_mac, sizeof (bridge_mac));
	g_object_set (s_bridge,
	              NM_SETTING_BRIDGE_INTERFACE_NAME, "br0",
	              NM_SETTING_BRIDGE_MAC_ADDRESS, mac_array,
	              NULL);
	g_byte_array_free (mac_array, TRUE);

	/* IP4 setting */
	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	g_assert (s_ip4);
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4,
	              NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_MANUAL,
	              NM_SETTING_IP4_CONFIG_MAY_FAIL, TRUE,
	              NULL);

	addr = nm_ip4_address_new ();
	nm_ip4_address_set_address (addr, ip1);
	nm_ip4_address_set_prefix (addr, prefix);
	nm_ip4_address_set_gateway (addr, gw);
	nm_setting_ip4_config_add_address (s_ip4, addr);
	nm_ip4_address_unref (addr);

	/* IP6 setting */
	s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();
	g_assert (s_ip6);
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NULL);

	g_assert (nm_connection_verify (connection, &error));
	g_assert_no_error (error);

	/* Save the ifcfg */
	success = writer_new_connection (connection,
	                                 TEST_SCRATCH_DIR "/network-scripts/",
	                                 &testfile,
	                                 &error);
	g_assert (success);
	g_assert_cmpstr (testfile, !=, NULL);

	/* reread will be normalized, so we must normalize connection too. */
	nm_utils_normalize_connection (connection, TRUE);

	/* re-read the connection for comparison */
	reread = connection_from_file (testfile,
	                               NULL,
	                               TYPE_BRIDGE,
	                               NULL,
	                               &unmanaged,
	                               &keyfile,
	                               &routefile,
	                               &route6file,
	                               &error,
	                               &ignore_error);
	unlink (testfile);

	g_assert (reread);
	g_assert (nm_connection_verify (reread, &error));
	g_assert_no_error (error);
	g_assert (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT));

	g_free (testfile);
	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
	g_object_unref (reread);
}

#define TEST_IFCFG_BRIDGE_COMPONENT TEST_IFCFG_DIR"/network-scripts/ifcfg-test-bridge-component"

static void
test_read_bridge_component (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingBridgePort *s_port;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	gboolean success;

	connection = connection_from_file (TEST_IFCFG_BRIDGE_COMPONENT,
	                                   NULL,
	                                   TYPE_ETHERNET,
	                                   NULL,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &routefile,
	                                   &route6file,
	                                   &error,
	                                   &ignore_error);
	g_assert (connection);

	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_master (s_con), ==, "br0");
	g_assert_cmpstr (nm_setting_connection_get_slave_type (s_con), ==, NM_SETTING_BRIDGE_SETTING_NAME);

	s_port = nm_connection_get_setting_bridge_port (connection);
	g_assert (s_port);
	g_assert (nm_setting_bridge_port_get_hairpin_mode (s_port));
	g_assert_cmpuint (nm_setting_bridge_port_get_priority (s_port), ==, 28);
	g_assert_cmpuint (nm_setting_bridge_port_get_path_cost (s_port), ==, 100);

	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
}

static void
test_write_bridge_component (void)
{
	NMConnection *connection;
	NMConnection *reread;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSetting *s_port;
	static unsigned char tmpmac[] = { 0x31, 0x33, 0x33, 0x37, 0xbe, 0xcd };
	GByteArray *mac;
	guint32 mtu = 1492;
	char *uuid;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;

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
	s_wired = (NMSettingWired *) nm_setting_wired_new ();
	g_assert (s_wired);
	nm_connection_add_setting (connection, NM_SETTING (s_wired));

	mac = g_byte_array_sized_new (sizeof (tmpmac));
	g_byte_array_append (mac, &tmpmac[0], sizeof (tmpmac));

	g_object_set (s_wired,
	              NM_SETTING_WIRED_MAC_ADDRESS, mac,
	              NM_SETTING_WIRED_MTU, mtu,
	              NULL);
	g_byte_array_free (mac, TRUE);

	/* Bridge port */
	s_port = nm_setting_bridge_port_new ();
	nm_connection_add_setting (connection, s_port);
	g_object_set (s_port,
	              NM_SETTING_BRIDGE_PORT_PRIORITY, 50,
	              NM_SETTING_BRIDGE_PORT_PATH_COST, 33,
	              NULL);

	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	/* Save the ifcfg */
	success = writer_new_connection (connection,
	                                 TEST_SCRATCH_DIR "/network-scripts/",
	                                 &testfile,
	                                 &error);
	g_assert_no_error (error);
	g_assert (success);
	g_assert (testfile);

	/* reread will be normalized, so we must normalize connection too. */
	nm_utils_normalize_connection (connection, TRUE);

	/* re-read the connection for comparison */
	reread = connection_from_file (testfile,
	                               NULL,
	                               TYPE_ETHERNET,
	                               NULL,
	                               &unmanaged,
	                               &keyfile,
	                               &routefile,
	                               &route6file,
	                               &error,
	                               &ignore_error);
	unlink (testfile);

	g_assert (reread);

	success = nm_connection_verify (reread, &error);
	g_assert_no_error (error);

	g_assert (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT));

	if (route6file)
		unlink (route6file);

	g_free (testfile);
	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
	g_object_unref (reread);
}

static void
test_read_bridge_missing_stp (void)
{
	NMConnection *connection;
	NMSettingBridge *s_bridge;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;

	connection = connection_from_file (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-bridge-missing-stp",
	                                   NULL,
	                                   TYPE_BRIDGE,
	                                   NULL,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &routefile,
	                                   &route6file,
	                                   &error,
	                                   &ignore_error);
	g_assert (connection);
	g_assert (nm_connection_verify (connection, &error));
	g_assert_no_error (error);

	/* ===== Bridging SETTING ===== */

	s_bridge = nm_connection_get_setting_bridge (connection);
	g_assert (s_bridge);
	g_assert_cmpstr (nm_setting_bridge_get_interface_name (s_bridge), ==, "br0");
	g_assert (nm_setting_bridge_get_stp (s_bridge) == FALSE);

	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
}

#define TEST_IFCFG_VLAN_INTERFACE TEST_IFCFG_DIR"/network-scripts/ifcfg-test-vlan-interface"

static void
test_read_vlan_interface (void)
{
	NMConnection *connection;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	NMSettingVlan *s_vlan;
	guint32 from = 0, to = 0;

	connection = connection_from_file (TEST_IFCFG_VLAN_INTERFACE,
	                                   NULL,
	                                   TYPE_ETHERNET,
	                                   NULL,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &routefile,
	                                   &route6file,
	                                   &error,
	                                   &ignore_error);
	g_assert_no_error (error);
	g_assert (connection != NULL);

	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);

	s_vlan = nm_connection_get_setting_vlan (connection);
	g_assert (s_vlan);

	g_assert_cmpstr (nm_setting_vlan_get_interface_name (s_vlan), ==, "vlan43");
	g_assert_cmpstr (nm_setting_vlan_get_parent (s_vlan), ==, "eth9");
	g_assert_cmpint (nm_setting_vlan_get_id (s_vlan), ==, 43);
	g_assert_cmpint (nm_setting_vlan_get_flags (s_vlan), ==,
	                 NM_VLAN_FLAG_GVRP | NM_VLAN_FLAG_LOOSE_BINDING);

	/* Ingress map */
	g_assert_cmpint (nm_setting_vlan_get_num_priorities (s_vlan, NM_VLAN_INGRESS_MAP), ==, 2);

	g_assert (nm_setting_vlan_get_priority (s_vlan, NM_VLAN_INGRESS_MAP, 0, &from, &to));
	g_assert_cmpint (from, ==, 0);
	g_assert_cmpint (to, ==, 1);

	g_assert (nm_setting_vlan_get_priority (s_vlan, NM_VLAN_INGRESS_MAP, 1, &from, &to));
	g_assert_cmpint (from, ==, 2);
	g_assert_cmpint (to, ==, 5);

	/* Egress map */
	g_assert_cmpint (nm_setting_vlan_get_num_priorities (s_vlan, NM_VLAN_EGRESS_MAP), ==, 3);

	g_assert (nm_setting_vlan_get_priority (s_vlan, NM_VLAN_EGRESS_MAP, 0, &from, &to));
	g_assert_cmpint (from, ==, 12);
	g_assert_cmpint (to, ==, 3);

	g_assert (nm_setting_vlan_get_priority (s_vlan, NM_VLAN_EGRESS_MAP, 1, &from, &to));
	g_assert_cmpint (from, ==, 14);
	g_assert_cmpint (to, ==, 7);

	g_assert (nm_setting_vlan_get_priority (s_vlan, NM_VLAN_EGRESS_MAP, 2, &from, &to));
	g_assert_cmpint (from, ==, 3);
	g_assert_cmpint (to, ==, 1);

	g_object_unref (connection);
}

#define TEST_IFCFG_VLAN_ONLY_VLANID TEST_IFCFG_DIR"/network-scripts/ifcfg-test-vlan-only-vlanid"

static void
test_read_vlan_only_vlan_id (void)
{
	NMConnection *connection;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	NMSettingVlan *s_vlan;

	connection = connection_from_file (TEST_IFCFG_VLAN_ONLY_VLANID,
	                                   NULL,
	                                   TYPE_ETHERNET,
	                                   NULL,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &routefile,
	                                   &route6file,
	                                   &error,
	                                   &ignore_error);
	g_assert_no_error (error);
	g_assert (connection != NULL);

	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);

	s_vlan = nm_connection_get_setting_vlan (connection);
	g_assert (s_vlan);

	g_assert (nm_setting_vlan_get_interface_name (s_vlan) == NULL);
	g_assert_cmpstr (nm_setting_vlan_get_parent (s_vlan), ==, "eth9");
	g_assert_cmpint (nm_setting_vlan_get_id (s_vlan), ==, 43);

	g_object_unref (connection);
}

#define TEST_IFCFG_VLAN_ONLY_DEVICE TEST_IFCFG_DIR"/network-scripts/ifcfg-test-vlan-only-device"

static void
test_read_vlan_only_device (void)
{
	NMConnection *connection;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	NMSettingVlan *s_vlan;

	connection = connection_from_file (TEST_IFCFG_VLAN_ONLY_DEVICE,
	                                   NULL,
	                                   TYPE_ETHERNET,
	                                   NULL,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &routefile,
	                                   &route6file,
	                                   &error,
	                                   &ignore_error);
	g_assert_no_error (error);
	g_assert (connection != NULL);

	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);

	s_vlan = nm_connection_get_setting_vlan (connection);
	g_assert (s_vlan);

	g_assert_cmpstr (nm_setting_vlan_get_interface_name (s_vlan), ==, "eth0.9");
	g_assert_cmpstr (nm_setting_vlan_get_parent (s_vlan), ==, "eth0");
	g_assert_cmpint (nm_setting_vlan_get_id (s_vlan), ==, 9);

	g_object_unref (connection);
}

static void
test_read_vlan_physdev (void)
{
	NMConnection *connection;
	GError *error = NULL;
	NMSettingVlan *s_vlan;

	connection = connection_from_file (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-vlan-physdev",
	                                   NULL, TYPE_ETHERNET, NULL, NULL,
	                                   NULL, NULL, NULL, &error, NULL);
	g_assert_no_error (error);
	g_assert (connection);
	g_assert (nm_connection_verify (connection, &error));

	s_vlan = nm_connection_get_setting_vlan (connection);
	g_assert (s_vlan);

	g_assert_cmpstr (nm_setting_vlan_get_interface_name (s_vlan), ==, "vlan0.3");
	g_assert_cmpstr (nm_setting_vlan_get_parent (s_vlan), ==, "eth0");
	g_assert_cmpint (nm_setting_vlan_get_id (s_vlan), ==, 3);

	g_object_unref (connection);
}

static void
test_write_vlan (void)
{
	NMConnection *connection;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	char *written = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	gboolean success = FALSE;

	connection = connection_from_file (TEST_IFCFG_VLAN_INTERFACE,
	                                   NULL,
	                                   TYPE_VLAN,
	                                   NULL,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &routefile,
	                                   &route6file,
	                                   &error,
	                                   &ignore_error);
	g_assert (connection != NULL);

	success = writer_new_connection (connection,
	                                 TEST_SCRATCH_DIR "/network-scripts/",
	                                 &written,
	                                 &error);
	g_assert (success);

	unlink (written);
	g_free (written);

	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
}

static void
test_write_vlan_only_vlanid (void)
{
	NMConnection *connection, *reread;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	char *written = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	gboolean success = FALSE;

	connection = connection_from_file (TEST_IFCFG_VLAN_ONLY_VLANID,
	                                   NULL,
	                                   TYPE_VLAN,
	                                   NULL,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &routefile,
	                                   &route6file,
	                                   &error,
	                                   &ignore_error);
	g_assert_no_error (error);
	g_assert (connection != NULL);

	g_free (unmanaged);
	unmanaged = NULL;
	g_free (keyfile);
	keyfile = NULL;
	g_free (routefile);
	routefile = NULL;
	g_free (route6file);
	route6file = NULL;

	success = writer_new_connection (connection,
	                                 TEST_SCRATCH_DIR "/network-scripts/",
	                                 &written,
	                                 &error);
	g_assert (success);

	/* reread will be normalized, so we must normalize connection too. */
	nm_utils_normalize_connection (connection, TRUE);

	/* re-read the connection for comparison */
	reread = connection_from_file (written,
	                               NULL,
	                               TYPE_ETHERNET,
	                               NULL,
	                               &unmanaged,
	                               &keyfile,
	                               &routefile,
	                               &route6file,
	                               &error,
	                               &ignore_error);
	unlink (written);
	g_free (written);
	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);

	g_assert_no_error (error);
	g_assert (reread != NULL);

	success = nm_connection_verify (reread, &error);
	g_assert_no_error (error);
	g_assert (success);

	success = nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT);
	g_assert (success);

	g_object_unref (connection);
	g_object_unref (reread);
}

static void
test_write_ethernet_missing_ipv6 (void)
{
	NMConnection *connection;
	NMConnection *reread;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;
	char *uuid;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;

	connection = nm_connection_new ();
	g_assert (connection);

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	g_assert (s_con);
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write Ethernet Without IPv6 Setting",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* Wired setting */
	s_wired = (NMSettingWired *) nm_setting_wired_new ();
	g_assert (s_wired);
	nm_connection_add_setting (connection, NM_SETTING (s_wired));

	/* IP4 setting */
	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	g_assert (s_ip4);
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));
	g_object_set (s_ip4,
	              NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
	              NM_SETTING_IP4_CONFIG_DHCP_CLIENT_ID, "random-client-id-00:22:33",
	              NM_SETTING_IP4_CONFIG_IGNORE_AUTO_ROUTES, TRUE,
	              NM_SETTING_IP4_CONFIG_IGNORE_AUTO_DNS, TRUE,
	              NULL);

	/* IP6 setting */
	/*
	 * We intentionally don't add IPv6 setting here. ifcfg-rh plugin should regard
	 * missing IPv6 as IPv6 with NM_SETTING_IP6_CONFIG_METHOD_AUTO method.
	 */

	ASSERT (nm_connection_verify (connection, &error) == TRUE,
	        "ethernet-missing-ipv6", "failed to verify connection: %s",
	        (error && error->message) ? error->message : "(unknown)");

	/* Save the ifcfg */
	success = writer_new_connection (connection,
	                                 TEST_SCRATCH_DIR "/network-scripts/",
	                                 &testfile,
	                                 &error);
	ASSERT (success == TRUE,
	        "ethernet-missing-ipv6", "failed to write connection to disk: %s",
	        (error && error->message) ? error->message : "(unknown)");

	ASSERT (testfile != NULL,
	        "ethernet-missing-ipv6", "didn't get ifcfg file path back after writing connection");

	/* reread will be normalized, so we must normalize connection too. */
	nm_utils_normalize_connection (connection, TRUE);

	/* re-read the connection for comparison */
	reread = connection_from_file (testfile,
	                               NULL,
	                               TYPE_ETHERNET,
	                               NULL,
	                               &unmanaged,
	                               &keyfile,
	                               &routefile,
	                               &route6file,
	                               &error,
	                               &ignore_error);
	unlink (testfile);

	ASSERT (reread != NULL,
	        "ethernet-missing-ipv6-reread", "failed to read %s: %s", testfile, error->message);

	ASSERT (nm_connection_verify (reread, &error),
	        "ethernet-missing-ipv6-reread-verify", "failed to verify %s: %s", testfile, error->message);

	/*
	 * We need to add IPv6 setting to the original connection now so that
	 * the comparison can succeed. Missing IPv6 setting should have been
	 * written out (and re-read) as Automatic IPv6.
	 */
	s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();
	g_assert (s_ip6);
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));
	g_object_set (s_ip6,
	              NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_AUTO,
	              NM_SETTING_IP6_CONFIG_MAY_FAIL, TRUE,
	              NULL);

	ASSERT (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "ethernet-missing-ipv6", "written and re-read connection weren't the same.");

	g_free (testfile);
	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
	g_object_unref (reread);
}

#define TEST_IFCFG_BOND_MAIN TEST_IFCFG_DIR"/network-scripts/ifcfg-test-bond-main"

static void
test_read_bond_main (void)
{
	NMConnection *connection;
	NMSettingBond *s_bond;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;

	connection = connection_from_file (TEST_IFCFG_BOND_MAIN,
	                                   NULL,
	                                   TYPE_ETHERNET,
	                                   NULL,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &routefile,
	                                   &route6file,
	                                   &error,
	                                   &ignore_error);
	ASSERT (connection != NULL,
	        "bond-main-read", "unexpected failure reading %s", TEST_IFCFG_BOND_MAIN);

	ASSERT (nm_connection_verify (connection, &error),
	        "bond-main-read", "failed to verify %s: %s", TEST_IFCFG_BOND_MAIN, error->message);

	/* ===== Bonding SETTING ===== */

	s_bond = nm_connection_get_setting_bond (connection);
	ASSERT (s_bond != NULL,
	        "bond-main", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_BOND_MAIN,
	        NM_SETTING_BOND_SETTING_NAME);

	ASSERT (g_strcmp0 (nm_setting_bond_get_interface_name (s_bond), "bond0") == 0,
	        "bond-main", "failed to verify %s: DEVICE=%s does not match bond0",
	        TEST_IFCFG_BOND_MAIN, nm_setting_bond_get_interface_name (s_bond));

	ASSERT (g_strcmp0 (nm_setting_bond_get_option_by_name (s_bond, NM_SETTING_BOND_OPTION_MIIMON), "100") == 0,
	        "bond-main", "failed to verify %s: miimon=%s does not match 100",
	        TEST_IFCFG_BOND_MAIN, nm_setting_bond_get_option_by_name (s_bond, NM_SETTING_BOND_OPTION_MIIMON));

	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
}

static void
test_write_bond_main (void)
{
	NMConnection *connection;
	NMConnection *reread;
	NMSettingConnection *s_con;
	NMSettingBond *s_bond;
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;
	NMSettingWired *s_wired;
	char *uuid;
	const guint32 ip1 = htonl (0x01010103);
	const guint32 gw = htonl (0x01010101);
	const guint32 prefix = 24;
	NMIP4Address *addr;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;

	connection = nm_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write Bond Main",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_BOND_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* Wired setting */
	s_wired = (NMSettingWired *) nm_setting_wired_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wired));

	/* bond setting */
	s_bond = (NMSettingBond *) nm_setting_bond_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_bond));

	g_object_set (s_bond,
	              NM_SETTING_BOND_INTERFACE_NAME, "bond0",
	              NULL);

	/* IP4 setting */
	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4,
	              NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_MANUAL,
	              NM_SETTING_IP4_CONFIG_MAY_FAIL, TRUE,
	              NULL);

	addr = nm_ip4_address_new ();
	nm_ip4_address_set_address (addr, ip1);
	nm_ip4_address_set_prefix (addr, prefix);
	nm_ip4_address_set_gateway (addr, gw);
	nm_setting_ip4_config_add_address (s_ip4, addr);
	nm_ip4_address_unref (addr);

	/* IP6 setting */
	s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NULL);

	ASSERT (nm_connection_verify (connection, &error) == TRUE,
	        "bond-main-write", "failed to verify connection: %s",
	        (error && error->message) ? error->message : "(unknown)");

	/* Save the ifcfg */
	success = writer_new_connection (connection,
	                                 TEST_SCRATCH_DIR "/network-scripts/",
	                                 &testfile,
	                                 &error);
	ASSERT (success == TRUE,
	        "bond-main-write", "failed to write connection to disk: %s",
	        (error && error->message) ? error->message : "(unknown)");

	ASSERT (testfile != NULL,
	        "bond-main-write", "didn't get ifcfg file path back after writing connection");

	/* reread will be normalized, so we must normalize connection too. */
	nm_utils_normalize_connection (connection, TRUE);

	/* re-read the connection for comparison */
	reread = connection_from_file (testfile,
	                               NULL,
	                               TYPE_BOND,
	                               NULL,
	                               &unmanaged,
	                               &keyfile,
	                               &routefile,
	                               &route6file,
	                               &error,
	                               &ignore_error);
	unlink (testfile);

	ASSERT (reread != NULL,
	        "bond-main-write-reread", "failed to read %s: %s", testfile, error->message);

	ASSERT (nm_connection_verify (reread, &error),
	        "bond-main-write-reread-verify", "failed to verify %s: %s", testfile, error->message);

	ASSERT (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "bond-main-write", "written and re-read connection weren't the same.");

	g_free (testfile);
	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
	g_object_unref (reread);
}

#define TEST_IFCFG_BOND_SLAVE TEST_IFCFG_DIR"/network-scripts/ifcfg-test-bond-slave"

static void
test_read_bond_slave (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_WARNING,
	                       "*ignoring IP4 config on slave*");
	connection = connection_from_file (TEST_IFCFG_BOND_SLAVE,
	                                   NULL,
	                                   TYPE_ETHERNET,
	                                   NULL,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &routefile,
	                                   &route6file,
	                                   &error,
	                                   &ignore_error);
	g_test_assert_expected_messages ();

	ASSERT (connection != NULL,
	        "bond-slave-read", "unexpected failure reading %s", TEST_IFCFG_BOND_SLAVE);

	ASSERT (nm_connection_verify (connection, &error),
	        "bond-slave-read", "failed to verify %s: %s", TEST_IFCFG_BOND_SLAVE, error->message);

	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
	        "bond-slave-read", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_BOND_SLAVE, NM_SETTING_CONNECTION_SETTING_NAME);

	ASSERT (g_strcmp0 (nm_setting_connection_get_master (s_con), "bond0") == 0,
	        "bond-slave-read", "failed to verify %s: master is not bond0",
	        TEST_IFCFG_BOND_SLAVE);

	ASSERT (g_strcmp0 (nm_setting_connection_get_slave_type (s_con), NM_SETTING_BOND_SETTING_NAME) == 0,
	        "bond-slave-read", "failed to verify %s: slave-type is not bond",
	        TEST_IFCFG_BOND_SLAVE);

	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
}

static void
test_write_bond_slave (void)
{
	NMConnection *connection;
	NMConnection *reread;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	static unsigned char tmpmac[] = { 0x31, 0x33, 0x33, 0x37, 0xbe, 0xcd };
	GByteArray *mac;
	guint32 mtu = 1492;
	char *uuid;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;

	connection = nm_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write Bond Slave",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
				  NM_SETTING_CONNECTION_MASTER, "bond0",
				  NM_SETTING_CONNECTION_SLAVE_TYPE, NM_SETTING_BOND_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* Wired setting */
	s_wired = (NMSettingWired *) nm_setting_wired_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wired));

	mac = g_byte_array_sized_new (sizeof (tmpmac));
	g_byte_array_append (mac, &tmpmac[0], sizeof (tmpmac));

	g_object_set (s_wired,
	              NM_SETTING_WIRED_MAC_ADDRESS, mac,
	              NM_SETTING_WIRED_MTU, mtu,
	              NULL);
	g_byte_array_free (mac, TRUE);

	ASSERT (nm_connection_verify (connection, &error) == TRUE,
	        "bond-slave-write", "failed to verify connection: %s",
	        (error && error->message) ? error->message : "(unknown)");

	/* Save the ifcfg */
	success = writer_new_connection (connection,
	                                 TEST_SCRATCH_DIR "/network-scripts/",
	                                 &testfile,
	                                 &error);
	ASSERT (success == TRUE,
	        "bond-slave-write", "failed to write connection to disk: %s",
	        (error && error->message) ? error->message : "(unknown)");

	ASSERT (testfile != NULL,
	        "bond-slave-write", "didn't get ifcfg file path back after writing connection");

	/* reread will be normalized, so we must normalize connection too. */
	nm_utils_normalize_connection (connection, TRUE);

	/* re-read the connection for comparison */
	reread = connection_from_file (testfile,
	                               NULL,
	                               TYPE_ETHERNET,
	                               NULL,
	                               &unmanaged,
	                               &keyfile,
	                               &routefile,
	                               &route6file,
	                               &error,
	                               &ignore_error);
	unlink (testfile);

	ASSERT (reread != NULL,
	        "bond-slave-write-reread", "failed to read %s: %s", testfile, error->message);

	ASSERT (nm_connection_verify (reread, &error),
	        "bond-slave-write-reread-verify", "failed to verify %s: %s", testfile, error->message);

	ASSERT (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "bond-slave-write", "written and re-read connection weren't the same.");

	if (route6file)
		unlink (route6file);

	g_free (testfile);
	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
	g_object_unref (reread);
}

#define TEST_IFCFG_INFINIBAND TEST_IFCFG_DIR"/network-scripts/ifcfg-test-infiniband"

static void
test_read_infiniband (void)
{
	NMConnection *connection;
	NMSettingInfiniband *s_infiniband;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	const GByteArray *array;
	char expected_mac_address[INFINIBAND_ALEN] = { 0x80, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22 };
	const char *transport_mode;

	connection = connection_from_file (TEST_IFCFG_INFINIBAND,
	                                   NULL,
	                                   TYPE_INFINIBAND,
	                                   NULL,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &routefile,
	                                   &route6file,
	                                   &error,
	                                   &ignore_error);
	ASSERT (connection != NULL,
	        "infiniband-read", "failed to read %s: %s", TEST_IFCFG_INFINIBAND, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "infiniband-verify", "failed to verify %s: %s", TEST_IFCFG_INFINIBAND, error->message);

	ASSERT (unmanaged == NULL,
	        "infiniband-verify", "failed to verify %s: unexpected unmanaged value", TEST_IFCFG_INFINIBAND);

	/* ===== INFINIBAND SETTING ===== */

	s_infiniband = nm_connection_get_setting_infiniband (connection);
	ASSERT (s_infiniband != NULL,
	        "infiniband-verify-wired", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_INFINIBAND,
	        NM_SETTING_INFINIBAND_SETTING_NAME);

	/* MAC address */
	array = nm_setting_infiniband_get_mac_address (s_infiniband);
	ASSERT (array != NULL,
	        "infiniband-verify-infiniband", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_INFINIBAND,
	        NM_SETTING_INFINIBAND_SETTING_NAME,
	        NM_SETTING_INFINIBAND_MAC_ADDRESS);
	ASSERT (array->len == INFINIBAND_ALEN,
	        "infiniband-verify-infiniband", "failed to verify %s: unexpected %s / %s key value length",
	        TEST_IFCFG_INFINIBAND,
	        NM_SETTING_INFINIBAND_SETTING_NAME,
	        NM_SETTING_INFINIBAND_MAC_ADDRESS);
	ASSERT (memcmp (array->data, &expected_mac_address[0], sizeof (expected_mac_address)) == 0,
	        "infiniband-verify-infiniband", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_INFINIBAND,
	        NM_SETTING_INFINIBAND_SETTING_NAME,
	        NM_SETTING_INFINIBAND_MAC_ADDRESS);

	/* Transport mode */
	transport_mode = nm_setting_infiniband_get_transport_mode (s_infiniband);
	ASSERT (transport_mode != NULL,
	        "infiniband-verify-infiniband", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_INFINIBAND,
	        NM_SETTING_INFINIBAND_SETTING_NAME,
	        NM_SETTING_INFINIBAND_TRANSPORT_MODE);
	ASSERT (strcmp (transport_mode, "connected") == 0,
	        "infiniband-verify-infiniband", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_INFINIBAND,
	        NM_SETTING_INFINIBAND_SETTING_NAME,
	        NM_SETTING_INFINIBAND_TRANSPORT_MODE);

	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
}

static void
test_write_infiniband (void)
{
	NMConnection *connection;
	NMConnection *reread;
	NMSettingConnection *s_con;
	NMSettingInfiniband *s_infiniband;
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;
	unsigned char tmpmac[INFINIBAND_ALEN] = { 0x80, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22 };
	GByteArray *mac;
	guint32 mtu = 65520;
	char *uuid;
	const guint32 ip1 = htonl (0x01010103);
	const guint32 gw = htonl (0x01010101);
	const guint32 prefix = 24;
	NMIP4Address *addr;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;

	connection = nm_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write InfiniBand",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_INFINIBAND_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* InfiniBand setting */
	s_infiniband = (NMSettingInfiniband *) nm_setting_infiniband_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_infiniband));

	mac = g_byte_array_sized_new (sizeof (tmpmac));
	g_byte_array_append (mac, &tmpmac[0], sizeof (tmpmac));

	g_object_set (s_infiniband,
	              NM_SETTING_INFINIBAND_MAC_ADDRESS, mac,
	              NM_SETTING_INFINIBAND_MTU, mtu,
	              NM_SETTING_INFINIBAND_TRANSPORT_MODE, "connected",
	              NULL);
	g_byte_array_free (mac, TRUE);

	/* IP4 setting */
	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4,
	              NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_MANUAL,
	              NM_SETTING_IP4_CONFIG_MAY_FAIL, TRUE,
	              NULL);

	addr = nm_ip4_address_new ();
	nm_ip4_address_set_address (addr, ip1);
	nm_ip4_address_set_prefix (addr, prefix);
	nm_ip4_address_set_gateway (addr, gw);
	nm_setting_ip4_config_add_address (s_ip4, addr);
	nm_ip4_address_unref (addr);

	/* IP6 setting */
	s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NULL);

	ASSERT (nm_connection_verify (connection, &error) == TRUE,
	        "infiniband-write", "failed to verify connection: %s",
	        (error && error->message) ? error->message : "(unknown)");

	/* Save the ifcfg */
	success = writer_new_connection (connection,
	                                 TEST_SCRATCH_DIR "/network-scripts/",
	                                 &testfile,
	                                 &error);
	ASSERT (success == TRUE,
	        "infiniband-write", "failed to write connection to disk: %s",
	        (error && error->message) ? error->message : "(unknown)");

	ASSERT (testfile != NULL,
	        "infiniband-write", "didn't get ifcfg file path back after writing connection");

	/* reread will be normalized, so we must normalize connection too. */
	nm_utils_normalize_connection (connection, TRUE);

	/* re-read the connection for comparison */
	reread = connection_from_file (testfile,
	                               NULL,
	                               TYPE_INFINIBAND,
	                               NULL,
	                               &unmanaged,
	                               &keyfile,
	                               &routefile,
	                               &route6file,
	                               &error,
	                               &ignore_error);
	unlink (testfile);

	ASSERT (reread != NULL,
	        "infiniband-write-reread", "failed to read %s: %s", testfile, error->message);

	ASSERT (nm_connection_verify (reread, &error),
	        "infiniband-write-reread-verify", "failed to verify %s: %s", testfile, error->message);

	ASSERT (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "infiniband-write", "written and re-read connection weren't the same.");

	g_free (testfile);
	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
	g_object_unref (reread);
}

#define TEST_IFCFG_BOND_SLAVE_IB TEST_IFCFG_DIR"/network-scripts/ifcfg-test-bond-slave-ib"

static void
test_read_bond_slave_ib (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_WARNING,
	                       "*ignoring IP4 config on slave*");
	connection = connection_from_file (TEST_IFCFG_BOND_SLAVE_IB,
	                                   NULL,
	                                   NULL,
	                                   NULL,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &routefile,
	                                   &route6file,
	                                   &error,
	                                   &ignore_error);
	g_test_assert_expected_messages();

	ASSERT (connection != NULL,
	        "bond-slave-read-ib", "unexpected failure reading %s", TEST_IFCFG_BOND_SLAVE_IB);

	ASSERT (nm_connection_verify (connection, &error),
	        "bond-slave-read-ib", "failed to verify %s: %s", TEST_IFCFG_BOND_SLAVE_IB, error->message);

	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
	        "bond-slave-read-ib", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_BOND_SLAVE_IB, NM_SETTING_CONNECTION_SETTING_NAME);

	ASSERT (g_strcmp0 (nm_setting_connection_get_master (s_con), "bond0") == 0,
	        "bond-slave-read-ib", "failed to verify %s: master is not bond0",
	        TEST_IFCFG_BOND_SLAVE_IB);

	ASSERT (g_strcmp0 (nm_setting_connection_get_slave_type (s_con), NM_SETTING_BOND_SETTING_NAME) == 0,
	        "bond-slave-read-ib", "failed to verify %s: slave-type is not bond",
	        TEST_IFCFG_BOND_SLAVE_IB);

	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
}

static void
test_write_bond_slave_ib (void)
{
	NMConnection *connection;
	NMConnection *reread;
	NMSettingConnection *s_con;
	NMSettingInfiniband *s_infiniband;
	static unsigned char tmpmac[] = { 
		0x80, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22
	};
	GByteArray *mac;
	char *uuid;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;

	connection = nm_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write Bond Slave InfiniBand",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_INFINIBAND_SETTING_NAME,
				  NM_SETTING_CONNECTION_MASTER, "bond0",
				  NM_SETTING_CONNECTION_SLAVE_TYPE, NM_SETTING_BOND_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* InfiniBand setting */
	s_infiniband = (NMSettingInfiniband *) nm_setting_infiniband_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_infiniband));

	mac = g_byte_array_sized_new (sizeof (tmpmac));
	g_byte_array_append (mac, &tmpmac[0], sizeof (tmpmac));

	g_object_set (s_infiniband,
	              NM_SETTING_INFINIBAND_MAC_ADDRESS, mac,
	              NM_SETTING_INFINIBAND_MTU, 2044,
	              NM_SETTING_INFINIBAND_TRANSPORT_MODE, "datagram",
	              NULL);
	g_byte_array_free (mac, TRUE);

	ASSERT (nm_connection_verify (connection, &error) == TRUE,
	        "bond-slave-write-ib", "failed to verify connection: %s",
	        (error && error->message) ? error->message : "(unknown)");

	/* Save the ifcfg */
	success = writer_new_connection (connection,
	                                 TEST_SCRATCH_DIR "/network-scripts/",
	                                 &testfile,
	                                 &error);
	ASSERT (success == TRUE,
	        "bond-slave-write-ib", "failed to write connection to disk: %s",
	        (error && error->message) ? error->message : "(unknown)");

	ASSERT (testfile != NULL,
	        "bond-slave-write-ib", "didn't get ifcfg file path back after writing connection");

	/* reread will be normalized, so we must normalize connection too. */
	nm_utils_normalize_connection (connection, TRUE);

	/* re-read the connection for comparison */
	reread = connection_from_file (testfile,
	                               NULL,
	                               NULL,
	                               NULL,
	                               &unmanaged,
	                               &keyfile,
	                               &routefile,
	                               &route6file,
	                               &error,
	                               &ignore_error);
	unlink (testfile);

	ASSERT (reread != NULL,
	        "bond-slave-write-ib-reread", "failed to read %s: %s", testfile, error->message);

	ASSERT (nm_connection_verify (reread, &error),
	        "bond-slave-write-ib-reread-verify", "failed to verify %s: %s", testfile, error->message);

	ASSERT (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "bond-slave-write-ib", "written and re-read connection weren't the same.");

	if (route6file)
		unlink (route6file);

	g_free (testfile);
	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
	g_object_unref (connection);
	g_object_unref (reread);
}

#define DCB_ALL_FLAGS (NM_SETTING_DCB_FLAG_ENABLE | \
                       NM_SETTING_DCB_FLAG_ADVERTISE | \
                       NM_SETTING_DCB_FLAG_WILLING)

static void
test_read_dcb_basic (void)
{
	NMConnection *connection;
	GError *error = NULL;
	NMSettingDcb *s_dcb;
	gboolean success;
	guint i;
	guint expected_group_ids[8] = { 0, 0, 0, 0, 1, 1, 1, 0xF };
	guint expected_group_bandwidths[8] = { 25, 0, 0, 75, 0, 0, 0, 0 };
	guint expected_bandwidths[8] = { 5, 10, 30, 25, 10, 50, 5, 0 };
	gboolean expected_strict[8] = { FALSE, FALSE, TRUE, TRUE, FALSE, TRUE, FALSE, TRUE };
	guint expected_traffic_classes[8] = { 7, 6, 5, 4, 3, 2, 1, 0 };
	gboolean expected_pfcs[8] = { TRUE, FALSE, FALSE, TRUE, TRUE, FALSE, TRUE, FALSE };

	connection = connection_from_file (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-dcb",
	                                   NULL, TYPE_ETHERNET, NULL, NULL, NULL, NULL, NULL, &error, NULL);
	g_assert_no_error (error);
	g_assert (connection);
	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	s_dcb = nm_connection_get_setting_dcb (connection);
	g_assert (s_dcb);

	g_assert_cmpint (nm_setting_dcb_get_app_fcoe_flags (s_dcb), ==, DCB_ALL_FLAGS);
	g_assert_cmpint (nm_setting_dcb_get_app_fcoe_priority (s_dcb), ==, 7);

	g_assert_cmpint (nm_setting_dcb_get_app_iscsi_flags (s_dcb), ==, DCB_ALL_FLAGS);
		g_assert_cmpint (nm_setting_dcb_get_app_iscsi_priority (s_dcb), ==, 6);

	g_assert_cmpint (nm_setting_dcb_get_app_fip_flags (s_dcb), ==, DCB_ALL_FLAGS);
	g_assert_cmpint (nm_setting_dcb_get_app_fip_priority (s_dcb), ==, 2);

	g_assert_cmpint (nm_setting_dcb_get_priority_flow_control_flags (s_dcb), ==, (NM_SETTING_DCB_FLAG_ENABLE | NM_SETTING_DCB_FLAG_ADVERTISE));
	for (i = 0; i < 8; i++)
		g_assert_cmpint (nm_setting_dcb_get_priority_flow_control (s_dcb, i), ==, expected_pfcs[i]);

	g_assert_cmpint (nm_setting_dcb_get_priority_group_flags (s_dcb), ==, DCB_ALL_FLAGS);

	/* Group IDs */
	for (i = 0; i < 8; i++)
		g_assert_cmpint (nm_setting_dcb_get_priority_group_id (s_dcb, i), ==, expected_group_ids[i]);

	/* Group bandwidth */
	for (i = 0; i < 8; i++)
		g_assert_cmpint (nm_setting_dcb_get_priority_group_bandwidth (s_dcb, i), ==, expected_group_bandwidths[i]);

	/* User priority bandwidth */
	for (i = 0; i < 8; i++)
		g_assert_cmpint (nm_setting_dcb_get_priority_bandwidth (s_dcb, i), ==, expected_bandwidths[i]);

	/* Strict bandwidth */
	for (i = 0; i < 8; i++)
		g_assert_cmpint (nm_setting_dcb_get_priority_strict_bandwidth (s_dcb, i), ==, expected_strict[i]);

	/* Traffic class */
	for (i = 0; i < 8; i++)
		g_assert_cmpint (nm_setting_dcb_get_priority_traffic_class (s_dcb, i), ==, expected_traffic_classes[i]);

	g_object_unref (connection);
}

static void
test_write_dcb_basic (void)
{
	NMConnection *connection, *reread;
	GError *error = NULL;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingDcb *s_dcb;
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;
	gboolean success, ignore_error;
	guint i;
	char *uuid, *testfile;
	const guint group_ids[8] = { 4, 0xF, 6, 0xF, 1, 7, 3, 0xF };
	const guint group_bandwidths[8] = { 10, 20, 15, 10, 2, 3, 35, 5 };
	const guint bandwidths[8] = { 10, 20, 30, 40, 50, 10, 0, 25 };
	const gboolean strict[8] = { TRUE, FALSE, TRUE, TRUE, FALSE, FALSE, FALSE, TRUE };
	const guint traffic_classes[8] = { 3, 4, 7, 2, 1, 0, 5, 6 };
	const gboolean pfcs[8] = { TRUE, TRUE, FALSE, TRUE, FALSE, TRUE, TRUE, FALSE };

	connection = nm_connection_new ();

	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));
	uuid = nm_utils_uuid_generate ();
	g_object_set (G_OBJECT (s_con),
	              NM_SETTING_CONNECTION_ID, "dcb-test",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
	              NM_SETTING_CONNECTION_INTERFACE_NAME, "eth0",
	              NULL);
	g_free (uuid);

	/* Wired setting */
	s_wired = (NMSettingWired *) nm_setting_wired_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wired));

	/* IP stuff */
	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	g_object_set (G_OBJECT (s_ip4), NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();
	g_object_set (G_OBJECT (s_ip6), NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_AUTO, NULL);
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	/* DCB */
	s_dcb = (NMSettingDcb *) nm_setting_dcb_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_dcb));

	g_object_set (G_OBJECT (s_dcb),
	              NM_SETTING_DCB_APP_FCOE_FLAGS, DCB_ALL_FLAGS,
	              NM_SETTING_DCB_APP_FCOE_PRIORITY, 5,
	              NM_SETTING_DCB_APP_ISCSI_FLAGS, DCB_ALL_FLAGS,
	              NM_SETTING_DCB_APP_ISCSI_PRIORITY, 1,
	              NM_SETTING_DCB_APP_FIP_FLAGS, DCB_ALL_FLAGS,
	              NM_SETTING_DCB_APP_FIP_PRIORITY, 3,
	              NM_SETTING_DCB_PRIORITY_FLOW_CONTROL_FLAGS, DCB_ALL_FLAGS,
	              NM_SETTING_DCB_PRIORITY_GROUP_FLAGS, DCB_ALL_FLAGS,
	              NULL);

	for (i = 0; i < 8; i++) {
		nm_setting_dcb_set_priority_flow_control (s_dcb, i, pfcs[i]);
		nm_setting_dcb_set_priority_group_id (s_dcb, i, group_ids[i]);
		nm_setting_dcb_set_priority_group_bandwidth (s_dcb, i, group_bandwidths[i]);
		nm_setting_dcb_set_priority_bandwidth (s_dcb, i, bandwidths[i]);
		nm_setting_dcb_set_priority_strict_bandwidth (s_dcb, i, strict[i]);
		nm_setting_dcb_set_priority_traffic_class (s_dcb, i, traffic_classes[i]);
	}

	g_assert (nm_connection_verify (connection, &error));

	/* Save the ifcfg */
	success = writer_new_connection (connection,
	                                 TEST_SCRATCH_DIR "/network-scripts/",
	                                 &testfile,
	                                 &error);
	g_assert_no_error (error);
	g_assert (success);
	g_assert (testfile);

	/* re-read the connection for comparison */
	reread = connection_from_file (testfile,
	                               NULL,
	                               TYPE_ETHERNET,
	                               NULL, NULL, NULL,
	                               NULL, NULL,
	                               &error,
	                               &ignore_error);
	unlink (testfile);

	g_assert_no_error (error);
	g_assert (reread);
	g_assert (nm_connection_verify (reread, &error));
	g_assert (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT));

	g_object_unref (connection);
	g_object_unref (reread);
	g_free (testfile);
}

static void
test_read_dcb_default_app_priorities (void)
{
	NMConnection *connection;
	GError *error = NULL;
	NMSettingDcb *s_dcb;
	gboolean success;

	connection = connection_from_file (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-dcb-default-app-priorities",
	                                   NULL, TYPE_ETHERNET, NULL, NULL, NULL, NULL, NULL, &error, NULL);
	g_assert_no_error (error);
	g_assert (connection);
	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	s_dcb = nm_connection_get_setting_dcb (connection);
	g_assert (s_dcb);

	g_assert_cmpint (nm_setting_dcb_get_app_fcoe_flags (s_dcb), ==, NM_SETTING_DCB_FLAG_ENABLE);
	g_assert_cmpint (nm_setting_dcb_get_app_fcoe_priority (s_dcb), ==, -1);

	g_assert_cmpint (nm_setting_dcb_get_app_iscsi_flags (s_dcb), ==, NM_SETTING_DCB_FLAG_ENABLE);
	g_assert_cmpint (nm_setting_dcb_get_app_iscsi_priority (s_dcb), ==, -1);

	g_assert_cmpint (nm_setting_dcb_get_app_fip_flags (s_dcb), ==, NM_SETTING_DCB_FLAG_ENABLE);
	g_assert_cmpint (nm_setting_dcb_get_app_fip_priority (s_dcb), ==, -1);

	g_object_unref (connection);
}

static void
test_read_dcb_bad_booleans (void)
{
	NMConnection *connection;
	GError *error = NULL;

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_WARNING,
	                       "*invalid DCB_PG_STRICT value*not all 0s and 1s*");
	connection = connection_from_file (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-dcb-bad-booleans",
	                                   NULL, TYPE_ETHERNET, NULL, NULL, NULL, NULL, NULL, &error, NULL);
	g_test_assert_expected_messages ();

	g_assert_error (error, IFCFG_PLUGIN_ERROR, 0);
	g_assert (strstr (error->message, "invalid boolean digit"));
	g_assert (connection == NULL);
}

static void
test_read_dcb_short_booleans (void)
{
	NMConnection *connection;
	GError *error = NULL;

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_WARNING,
	                       "*DCB_PG_STRICT value*8 characters*");
	connection = connection_from_file (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-dcb-short-booleans",
	                                   NULL, TYPE_ETHERNET, NULL, NULL, NULL, NULL, NULL, &error, NULL);
	g_test_assert_expected_messages ();

	g_assert_error (error, IFCFG_PLUGIN_ERROR, 0);
	g_assert (strstr (error->message, "boolean array must be 8 characters"));
	g_assert (connection == NULL);
}

static void
test_read_dcb_bad_uints (void)
{
	NMConnection *connection;
	GError *error = NULL;

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_WARNING,
	                       "*invalid DCB_PG_UP2TC value*not 0 - 7*");
	connection = connection_from_file (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-dcb-bad-uints",
	                                   NULL, TYPE_ETHERNET, NULL, NULL, NULL, NULL, NULL, &error, NULL);
	g_test_assert_expected_messages ();

	g_assert_error (error, IFCFG_PLUGIN_ERROR, 0);
	g_assert (strstr (error->message, "invalid uint digit"));
	g_assert (connection == NULL);
}

static void
test_read_dcb_short_uints (void)
{
	NMConnection *connection;
	GError *error = NULL;

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_WARNING,
	                       "*DCB_PG_UP2TC value*8 characters*");
	connection = connection_from_file (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-dcb-short-uints",
	                                   NULL, TYPE_ETHERNET, NULL, NULL, NULL, NULL, NULL, &error, NULL);
	g_test_assert_expected_messages ();

	g_assert_error (error, IFCFG_PLUGIN_ERROR, 0);
	g_assert (strstr (error->message, "uint array must be 8 characters"));
	g_assert (connection == NULL);
}

static void
test_read_dcb_bad_percent (void)
{
	NMConnection *connection;
	GError *error = NULL;

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_WARNING,
	                       "*invalid DCB_PG_PCT percentage value*");
	connection = connection_from_file (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-dcb-bad-percent",
	                                   NULL, TYPE_ETHERNET, NULL, NULL, NULL, NULL, NULL, &error, NULL);
	g_test_assert_expected_messages ();

	g_assert_error (error, IFCFG_PLUGIN_ERROR, 0);
	g_assert (strstr (error->message, "invalid percent element"));
	g_assert (connection == NULL);
}

static void
test_read_dcb_short_percent (void)
{
	NMConnection *connection;
	GError *error = NULL;

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_WARNING,
	                       "*invalid DCB_PG_PCT percentage list value*");
	connection = connection_from_file (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-dcb-short-percent",
	                                   NULL, TYPE_ETHERNET, NULL, NULL, NULL, NULL, NULL, &error, NULL);
	g_test_assert_expected_messages ();

	g_assert_error (error, IFCFG_PLUGIN_ERROR, 0);
	g_assert (strstr (error->message, "percent array must be 8 elements"));
	g_assert (connection == NULL);
}

static void
test_read_dcb_pgpct_not_100 (void)
{
	NMConnection *connection;
	GError *error = NULL;

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_WARNING,
	                       "*DCB_PG_PCT percentages do not equal 100*");
	connection = connection_from_file (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-dcb-pgpct-not-100",
	                                   NULL, TYPE_ETHERNET, NULL, NULL, NULL, NULL, NULL, &error, NULL);
	g_test_assert_expected_messages ();

	g_assert_error (error, IFCFG_PLUGIN_ERROR, 0);
	g_assert (strstr (error->message, "invalid percentage sum"));
	g_assert (connection == NULL);
}

static void
test_read_fcoe_mode (gconstpointer user_data)
{
	const char *expected_mode = user_data;
	NMConnection *connection;
	GError *error = NULL;
	NMSettingDcb *s_dcb;
	gboolean success;
	char *file;

	file = g_strdup_printf (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-fcoe-%s", expected_mode);
	connection = connection_from_file (file, NULL, TYPE_ETHERNET, NULL, NULL, NULL, NULL, NULL, &error, NULL);
	g_free (file);
	g_assert_no_error (error);
	g_assert (connection);
	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	s_dcb = nm_connection_get_setting_dcb (connection);
	g_assert (s_dcb);

	g_assert_cmpint (nm_setting_dcb_get_app_fcoe_flags (s_dcb), ==, NM_SETTING_DCB_FLAG_ENABLE);
	g_assert_cmpstr (nm_setting_dcb_get_app_fcoe_mode (s_dcb), ==, expected_mode);

	g_object_unref (connection);
}

static void
test_write_fcoe_mode (gconstpointer user_data)
{
	const char *expected_mode = user_data;
	NMConnection *connection, *reread;
	GError *error = NULL;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingDcb *s_dcb;
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;
	gboolean success, ignore_error;
	char *uuid, *testfile;

	connection = nm_connection_new ();

	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));
	uuid = nm_utils_uuid_generate ();
	g_object_set (G_OBJECT (s_con),
	              NM_SETTING_CONNECTION_ID, "fcoe-test",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
	              NM_SETTING_CONNECTION_INTERFACE_NAME, "eth0",
	              NULL);
	g_free (uuid);

	/* Wired setting */
	s_wired = (NMSettingWired *) nm_setting_wired_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wired));

	/* IP stuff */
	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	g_object_set (G_OBJECT (s_ip4), NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();
	g_object_set (G_OBJECT (s_ip6), NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_AUTO, NULL);
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	/* DCB */
	s_dcb = (NMSettingDcb *) nm_setting_dcb_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_dcb));

	g_object_set (G_OBJECT (s_dcb),
	              NM_SETTING_DCB_APP_FCOE_FLAGS, NM_SETTING_DCB_FLAG_ENABLE,
	              NM_SETTING_DCB_APP_FCOE_MODE, expected_mode,
	              NULL);

	g_assert (nm_connection_verify (connection, &error));

	/* Save the ifcfg */
	success = writer_new_connection (connection,
	                                 TEST_SCRATCH_DIR "/network-scripts/",
	                                 &testfile,
	                                 &error);
	g_assert_no_error (error);
	g_assert (success);
	g_assert (testfile);

	{
		shvarFile *ifcfg = svOpenFile (testfile, &error);
		char *written_mode;

		g_assert_no_error (error);
		g_assert (ifcfg);
		written_mode = svGetValue (ifcfg, "DCB_APP_FCOE_MODE", FALSE);
		svCloseFile (ifcfg);
		g_assert_cmpstr (written_mode, ==, expected_mode);
		g_free (written_mode);
	}

	/* re-read the connection for comparison */
	reread = connection_from_file (testfile,
	                               NULL,
	                               TYPE_ETHERNET,
	                               NULL, NULL, NULL,
	                               NULL, NULL,
	                               &error,
	                               &ignore_error);
	unlink (testfile);

	g_assert_no_error (error);
	g_assert (reread);
	g_assert (nm_connection_verify (reread, &error));
	g_assert (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT));

	g_object_unref (connection);
	g_object_unref (reread);
	g_free (testfile);
}

static void
test_read_team_master (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingTeam *s_team;
	gboolean success;
	GError *error = NULL;
	const char *expected_config = "{ \"device\": \"team0\", \"link_watch\": { \"name\": \"ethtool\" } }";

	connection = connection_from_file (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-team-master",
	                                   NULL, TYPE_ETHERNET, NULL, NULL, NULL, NULL, NULL, &error, NULL);
	g_assert_no_error (error);
	g_assert (connection);

	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_connection_type (s_con), ==, NM_SETTING_TEAM_SETTING_NAME);

	s_team = nm_connection_get_setting_team (connection);
	g_assert (s_team);
	g_assert_cmpstr (nm_setting_team_get_interface_name (s_team), ==, "team0");
	g_assert_cmpstr (nm_setting_team_get_config (s_team), ==, expected_config);

	g_object_unref (connection);
}

static void
test_write_team_master (void)
{
	NMConnection *connection, *reread;
	NMSettingConnection *s_con;
	NMSettingTeam *s_team;
	NMSettingWired *s_wired;
	char *uuid, *testfile = NULL, *val;
	gboolean success;
	GError *error = NULL;
	const char *expected_config = "{ \"device\": \"team0\", \"link_watch\": { \"name\": \"ethtool\" } }";
	const char *escaped_expected_config = "\"{ \\\"device\\\": \\\"team0\\\", \\\"link_watch\\\": { \\\"name\\\": \\\"ethtool\\\" } }\"";
	shvarFile *f;

	connection = nm_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write Team Master",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_TEAM_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* Team setting */
	s_team = (NMSettingTeam *) nm_setting_team_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_team));

	g_object_set (s_team,
	              NM_SETTING_TEAM_INTERFACE_NAME, "team0",
	              NM_SETTING_TEAM_CONFIG, expected_config,
	              NULL);

	/* Wired setting */
	s_wired = (NMSettingWired *) nm_setting_wired_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wired));

	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	/* Save the ifcfg */
	success = writer_new_connection (connection,
	                                 TEST_SCRATCH_DIR "/network-scripts/",
	                                 &testfile,
	                                 &error);
	g_assert_no_error (error);
	g_assert (success);

	f = svOpenFile (testfile, &error);
	g_assert_no_error (error);
	g_assert (f);

	/* re-read the file to check that what key was written. */
	val = svGetValue (f, "DEVICETYPE", FALSE);
	g_assert (val);
	g_assert_cmpstr (val, ==, "Team");
	g_free (val);
	val = svGetValue (f, "TEAM_CONFIG", TRUE);
	g_assert (val);
	g_assert_cmpstr (val, ==, escaped_expected_config);
	g_free (val);
	svCloseFile (f);

	/* reread will be normalized, so we must normalize connection too. */
	nm_utils_normalize_connection (connection, TRUE);

	/* re-read the connection for comparison */
	reread = connection_from_file (testfile, NULL, TYPE_ETHERNET, NULL,
	                               NULL, NULL, NULL, NULL, &error, NULL);
	unlink (testfile);
	g_assert_no_error (error);
	g_assert (reread);

	success = nm_connection_verify (reread, &error);
	g_assert_no_error (error);
	g_assert (success);

	g_assert (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT));

	g_free (testfile);
	g_object_unref (connection);
	g_object_unref (reread);
}

static void
test_read_team_port (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingTeamPort *s_team_port;
	gboolean success;
	GError *error = NULL;
	const char *expected_config = "{ \"p4p1\": { \"prio\": -10, \"sticky\": true } }";

	connection = connection_from_file (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-team-port",
	                                   NULL, TYPE_ETHERNET, NULL, NULL, NULL, NULL, NULL, &error, NULL);
	g_assert_no_error (error);
	g_assert (connection);

	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_connection_type (s_con), ==, NM_SETTING_WIRED_SETTING_NAME);
	g_assert_cmpstr (nm_setting_connection_get_master (s_con), ==, "team0");

	s_team_port = nm_connection_get_setting_team_port (connection);
	g_assert (s_team_port);
	g_assert_cmpstr (nm_setting_team_port_get_config (s_team_port), ==, expected_config);

	g_object_unref (connection);
}

static void
test_write_team_port (void)
{
	NMConnection *connection, *reread;
	NMSettingConnection *s_con;
	NMSettingTeamPort *s_team_port;
	NMSettingWired *s_wired;
	char *uuid, *testfile = NULL, *val;
	gboolean success;
	GError *error = NULL;
	const char *expected_config = "{ \"p4p1\": { \"prio\": -10, \"sticky\": true } }";
	const char *escaped_expected_config = "\"{ \\\"p4p1\\\": { \\\"prio\\\": -10, \\\"sticky\\\": true } }\"";
	shvarFile *f;

	connection = nm_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write Team Port",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
	              NM_SETTING_CONNECTION_MASTER, "team0",
	              NM_SETTING_CONNECTION_SLAVE_TYPE, NM_SETTING_TEAM_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* Team setting */
	s_team_port = (NMSettingTeamPort *) nm_setting_team_port_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_team_port));
	g_object_set (s_team_port, NM_SETTING_TEAM_PORT_CONFIG, expected_config, NULL);

	/* Wired setting */
	s_wired = (NMSettingWired *) nm_setting_wired_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wired));

	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	/* Save the ifcfg */
	success = writer_new_connection (connection,
	                                 TEST_SCRATCH_DIR "/network-scripts/",
	                                 &testfile,
	                                 &error);
	g_assert_no_error (error);
	g_assert (success);

	f = svOpenFile (testfile, &error);
	g_assert_no_error (error);
	g_assert (f);

	/* re-read the file to check that what key was written. */
	val = svGetValue (f, "TYPE", FALSE);
	g_assert (!val);
	val = svGetValue (f, "DEVICETYPE", FALSE);
	g_assert (val);
	g_assert_cmpstr (val, ==, "TeamPort");
	g_free (val);
	val = svGetValue (f, "TEAM_PORT_CONFIG", TRUE);
	g_assert (val);
	g_assert_cmpstr (val, ==, escaped_expected_config);
	val = svGetValue (f, "TEAM_MASTER", TRUE);
	g_assert (val);
	g_assert_cmpstr (val, ==, "team0");
	g_free (val);
	svCloseFile (f);

	/* reread will be normalized, so we must normalize connection too. */
	nm_utils_normalize_connection (connection, TRUE);

	/* re-read the connection for comparison */
	reread = connection_from_file (testfile, NULL, TYPE_ETHERNET, NULL,
	                               NULL, NULL, NULL, NULL, &error, NULL);
	unlink (testfile);
	g_assert_no_error (error);
	g_assert (reread);

	success = nm_connection_verify (reread, &error);
	g_assert_no_error (error);
	g_assert (success);

	g_assert (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT));

	g_free (testfile);
	g_object_unref (connection);
	g_object_unref (reread);
}

static void
test_read_team_port_empty_config (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	gboolean success;
	GError *error = NULL;

	connection = connection_from_file (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-team-port-empty-config",
	                                   NULL, TYPE_ETHERNET, NULL, NULL, NULL, NULL, NULL, &error, NULL);
	g_assert_no_error (error);
	g_assert (connection);

	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_connection_type (s_con), ==, NM_SETTING_WIRED_SETTING_NAME);
	g_assert_cmpstr (nm_setting_connection_get_master (s_con), ==, "team0");

	/* Empty TEAM_PORT_CONFIG means no team-port setting */
	g_assert (nm_connection_get_setting_team_port (connection) == NULL);

	g_object_unref (connection);
}

/* Old algorithm for "remove escaped characters in place".
 *
 * This function is obsolete because it has O(n^2) runtime
 * complexity and got replaced. Keep it here for testing,
 * that both functions behave identical.
 **/
static void
svUnescape_On2 (char *s)
{
	int len, i;

	len = strlen(s);
	if (len >= 2 && (s[0] == '"' || s[0] == '\'') && s[0] == s[len-1]) {
		i = len - 2;
		if (i == 0)
			s[0] = '\0';
		else {
			memmove(s, s+1, i);
			s[i+1] = '\0';
			len = i;
		}
	}
	for (i = 0; i < len; i++) {
		if (s[i] == '\\') {
			memmove(s+i, s+i+1, len-(i+1));
			len--;
		}
		s[len] = '\0';
	}
}

static void
test_svUnescape_assert (const char *str)
{
	char *s1 = g_strdup (str);
	char *s2 = g_strdup (str);

	svUnescape (s1);
	svUnescape_On2 (s2);

	g_assert_cmpstr (s1, ==, s2);

	g_free (s1);
	g_free (s2);
}

static void
test_svUnescape ()
{
	int len, repeat, i, k;
	GRand *rand = g_rand_new ();
	guint32 seed = g_random_int ();

	g_rand_set_seed (rand, seed);

	test_svUnescape_assert ("");
	test_svUnescape_assert ("'");
	test_svUnescape_assert ("\"");
	test_svUnescape_assert ("\\");
	test_svUnescape_assert ("x");
	test_svUnescape_assert (" ");
	test_svUnescape_assert ("'  '");
	test_svUnescape_assert ("'x'");
	test_svUnescape_assert ("\'some string\'");
	test_svUnescape_assert ("Bob outside LAN");
	test_svUnescape_assert ("{ \"device\": \"team0\", \"link_watch\": { \"name\": \"ethtool\" } }");

	for (len = 1; len < 25; len++) {
		char *s = g_new0 (char, len+1);

		for (repeat = 0; repeat < MAX (4*len, 20); repeat++) {

			/* fill the entire string with random. */
			for (i = 0; i < len; i++)
				s[i] = g_rand_int (rand);

			/* randomly place escape characters into the string */
			k = g_rand_int (rand) % (len);
			while (k-- > 0)
				s[g_rand_int (rand) % len] = '\\';

			if (len > 1) {
				/* quote the string. */
				k = g_rand_int (rand) % (10);
				if (k < 4) {
					char quote = k < 2 ? '"' : '\'';

					s[0] = quote;
					s[len-1] = quote;
				}
			}

			/*g_message (">>%s<<", s);*/
			test_svUnescape_assert (s);
		}

		g_free (s);
	}

	g_rand_free (rand);
}


#define TEST_IFCFG_WIFI_OPEN_SSID_BAD_HEX TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wifi-open-ssid-bad-hex"
#define TEST_IFCFG_WIFI_OPEN_SSID_LONG_QUOTED TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wifi-open-ssid-long-quoted"
#define TEST_IFCFG_WIFI_OPEN_SSID_LONG_HEX TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wifi-open-ssid-long-hex"


#define TEST_IFCFG_WIRED_STATIC           TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-static"
#define TEST_IFCFG_WIRED_STATIC_BOOTPROTO TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-static-bootproto"

#define TEST_IFCFG_WIRED_IPV4_MANUAL_1 TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-ipv4-manual-1"
#define TEST_IFCFG_WIRED_IPV4_MANUAL_2 TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-ipv4-manual-2"
#define TEST_IFCFG_WIRED_IPV4_MANUAL_3 TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-ipv4-manual-3"
#define TEST_IFCFG_WIRED_IPV4_MANUAL_4 TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-ipv4-manual-4"

#define DEFAULT_HEX_PSK "7d308b11df1b4243b0f78e5f3fc68cdbb9a264ed0edf4c188edf329ff5b467f0"

#define TPATH "/settings/plugins/ifcfg-rh/"

NMTST_DEFINE ();

int main (int argc, char **argv)
{
	nmtst_init_assert_logging (&argc, &argv);

	g_test_add_func (TPATH "svUnescape", test_svUnescape);

	g_test_add_func (TPATH "unmanaged", test_read_unmanaged);
	g_test_add_func (TPATH "unmanaged-unrecognized", test_read_unmanaged_unrecognized);
	g_test_add_func (TPATH "unrecognized", test_read_unrecognized);
	g_test_add_func (TPATH "basic", test_read_basic);
	g_test_add_func (TPATH "variables-corner-cases", test_read_variables_corner_cases);
	g_test_add_data_func (TPATH "no-prefix/8", GUINT_TO_POINTER (8), test_read_wired_static_no_prefix);
	g_test_add_data_func (TPATH "no-prefix/16", GUINT_TO_POINTER (16), test_read_wired_static_no_prefix);
	g_test_add_data_func (TPATH "no-prefix/24", GUINT_TO_POINTER (24), test_read_wired_static_no_prefix);
	g_test_add_data_func (TPATH "static-ip6-only-gw/_NULL_", NULL, test_write_wired_static_ip6_only_gw);
	g_test_add_data_func (TPATH "static-ip6-only-gw/::", "::", test_write_wired_static_ip6_only_gw);
	g_test_add_data_func (TPATH "static-ip6-only-gw/2001:db8:8:4::2", "2001:db8:8:4::2", test_write_wired_static_ip6_only_gw);
	g_test_add_data_func (TPATH "static-ip6-only-gw/ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255", "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255", test_write_wired_static_ip6_only_gw);

	test_read_wired_static (TEST_IFCFG_WIRED_STATIC, "System test-wired-static", TRUE);
	test_read_wired_static (TEST_IFCFG_WIRED_STATIC_BOOTPROTO, "System test-wired-static-bootproto", FALSE);
	test_read_wired_dhcp ();
	g_test_add_func (TPATH "dhcp-plus-ip", test_read_wired_dhcp_plus_ip);
	g_test_add_func (TPATH "dhcp-send-hostname", test_read_write_wired_dhcp_send_hostname);
	test_read_wired_global_gateway ();
	test_read_wired_never_default ();
	test_read_wired_defroute_no ();
	test_read_wired_defroute_no_gatewaydev_yes ();
	test_read_wired_static_routes ();
	test_read_wired_static_routes_legacy ();
	test_read_wired_ipv4_manual (TEST_IFCFG_WIRED_IPV4_MANUAL_1, "System test-wired-ipv4-manual-1");
	test_read_wired_ipv4_manual (TEST_IFCFG_WIRED_IPV4_MANUAL_2, "System test-wired-ipv4-manual-2");
	test_read_wired_ipv4_manual (TEST_IFCFG_WIRED_IPV4_MANUAL_3, "System test-wired-ipv4-manual-3");
	test_read_wired_ipv4_manual (TEST_IFCFG_WIRED_IPV4_MANUAL_4, "System test-wired-ipv4-manual-4");
	test_read_wired_ipv6_manual ();
	test_read_wired_ipv6_only ();
	test_read_wired_dhcp6_only ();
	test_read_onboot_no ();
	test_read_noip ();
	test_read_wired_8021x_peap_mschapv2 ();
	test_read_wired_8021x_tls_secret_flags (TEST_IFCFG_WIRED_8021X_TLS_AGENT, NM_SETTING_SECRET_FLAG_AGENT_OWNED);
	test_read_wired_8021x_tls_secret_flags (TEST_IFCFG_WIRED_8021X_TLS_ALWAYS,
	                                        NM_SETTING_SECRET_FLAG_AGENT_OWNED | NM_SETTING_SECRET_FLAG_NOT_SAVED);
	g_test_add_func (TPATH "802-1x/subj-matches", test_read_write_802_1X_subj_matches);
	g_test_add_func (TPATH "802-1x/ttls-eapgtc", test_read_802_1x_ttls_eapgtc);
	test_read_wired_aliases_good ();
	test_read_wired_aliases_bad_1 ();
	test_read_wired_aliases_bad_2 ();
	test_read_wifi_open ();
	test_read_wifi_open_auto ();
	test_read_wifi_open_ssid_hex ();
	test_read_wifi_open_ssid_bad (TEST_IFCFG_WIFI_OPEN_SSID_BAD_HEX, "wifi-open-ssid-bad-hex-read");
	test_read_wifi_open_ssid_bad (TEST_IFCFG_WIFI_OPEN_SSID_LONG_HEX, "wifi-open-ssid-long-hex-read");
	test_read_wifi_open_ssid_bad (TEST_IFCFG_WIFI_OPEN_SSID_LONG_QUOTED, "wifi-open-ssid-long-quoted-read");
	test_read_wifi_open_ssid_quoted ();
	test_read_wifi_wep ();
	test_read_wifi_wep_adhoc ();
	test_read_wifi_wep_passphrase ();
	test_read_wifi_wep_40_ascii ();
	test_read_wifi_wep_104_ascii ();
	test_read_wifi_leap ();
	test_read_wifi_leap_secret_flags (TEST_IFCFG_WIFI_LEAP_AGENT, NM_SETTING_SECRET_FLAG_AGENT_OWNED);
	test_read_wifi_leap_secret_flags (TEST_IFCFG_WIFI_LEAP_ALWAYS,
	                                  NM_SETTING_SECRET_FLAG_AGENT_OWNED | NM_SETTING_SECRET_FLAG_NOT_SAVED);
	test_read_wifi_wpa_psk ();
	test_read_wifi_wpa_psk_2 ();
	test_read_wifi_wpa_psk_unquoted ();
	test_read_wifi_wpa_psk_unquoted2 ();
	test_read_wifi_wpa_psk_adhoc ();
	test_read_wifi_wpa_psk_hex ();
	test_read_wifi_dynamic_wep_leap ();
	test_read_wifi_wpa_eap_tls ();
	test_read_wifi_wpa_eap_ttls_tls ();
	test_read_wifi_wep_eap_ttls_chap ();
	g_test_add_func (TPATH "wifi/read-hidden", test_read_wifi_hidden);
	test_read_wired_qeth_static ();
	test_read_wired_ctc_static ();
	test_read_wifi_wep_no_keys ();
	test_read_permissions ();
	test_read_wifi_wep_agent_keys ();
	test_read_infiniband ();
	test_read_vlan_interface ();
	test_read_vlan_only_vlan_id ();
	test_read_vlan_only_device ();
	g_test_add_func (TPATH "vlan/physdev", test_read_vlan_physdev);

	test_write_wired_static ();
	test_write_wired_static_ip6_only ();
	test_write_wired_static_routes ();
	test_read_write_static_routes_legacy ();
	test_write_wired_dhcp ();
	g_test_add_func (TPATH "dhcp-plus-ip", test_write_wired_dhcp_plus_ip);
	test_write_wired_dhcp_8021x_peap_mschapv2 ();
	test_write_wired_8021x_tls (NM_SETTING_802_1X_CK_SCHEME_PATH, NM_SETTING_SECRET_FLAG_AGENT_OWNED);
	test_write_wired_8021x_tls (NM_SETTING_802_1X_CK_SCHEME_PATH, NM_SETTING_SECRET_FLAG_NOT_SAVED);
	test_write_wired_8021x_tls (NM_SETTING_802_1X_CK_SCHEME_PATH, NM_SETTING_SECRET_FLAG_AGENT_OWNED | NM_SETTING_SECRET_FLAG_NOT_SAVED);
	test_write_wired_8021x_tls (NM_SETTING_802_1X_CK_SCHEME_BLOB, NM_SETTING_SECRET_FLAG_NONE);
	test_write_wired_aliases ();
	g_test_add_func (TPATH "ipv4/write-static-addresses-GATEWAY", test_write_gateway);
	test_write_wifi_open ();
	test_write_wifi_open_hex_ssid ();
	test_write_wifi_wep ();
	test_write_wifi_wep_adhoc ();
	test_write_wifi_wep_passphrase ();
	test_write_wifi_wep_40_ascii ();
	test_write_wifi_wep_104_ascii ();
	test_write_wifi_leap ();
	test_write_wifi_leap_secret_flags (NM_SETTING_SECRET_FLAG_AGENT_OWNED);
	test_write_wifi_leap_secret_flags (NM_SETTING_SECRET_FLAG_NOT_SAVED);
	test_write_wifi_leap_secret_flags (NM_SETTING_SECRET_FLAG_AGENT_OWNED | NM_SETTING_SECRET_FLAG_NOT_SAVED);
	test_write_wifi_wpa_psk ("Test Write Wifi WPA PSK",
	                         "wifi-wpa-psk-write",
	                         FALSE,
	                         TRUE,
	                         FALSE,
	                         DEFAULT_HEX_PSK);
	test_write_wifi_wpa_psk ("Test Write Wifi WPA2 PSK",
	                         "wifi-wpa2-psk-write",
	                         FALSE,
	                         FALSE,
	                         TRUE,
	                         DEFAULT_HEX_PSK);
	test_write_wifi_wpa_psk ("Test Write Wifi WPA WPA2 PSK",
	                         "wifi-wpa-wpa2-psk-write",
	                         FALSE,
	                         TRUE,
	                         TRUE,
	                         DEFAULT_HEX_PSK);
	test_write_wifi_wpa_psk ("Test Write Wifi WEP WPA WPA2 PSK",
	                         "wifi-wep-wpa-wpa2-psk-write",
	                         TRUE,
	                         TRUE,
	                         TRUE,
	                         DEFAULT_HEX_PSK);
	test_write_wifi_wpa_psk ("Test Write Wifi WPA WPA2 PSK Passphrase",
	                         "wifi-wpa-wpa2-psk-passphrase-write",
	                         FALSE,
	                         TRUE,
	                         TRUE,
	                         "really insecure passphrase04!");
	test_write_wifi_wpa_psk ("Test Write Wifi WPA WPA2 PSK Passphrase Special Chars",
	                         "wifi-wpa-wpa2-psk-passphrase-write-spec-chars",
	                         FALSE,
	                         TRUE,
	                         TRUE,
	                         "blah`oops\"grr'$*@~!%\\");
	test_write_wifi_wpa_psk_adhoc ();
	test_write_wifi_wpa_eap_tls ();
	test_write_wifi_wpa_eap_ttls_tls ();
	test_write_wifi_wpa_eap_ttls_mschapv2 ();
	test_write_wifi_dynamic_wep_leap ();
	test_write_wifi_wpa_then_open ();
	test_write_wifi_wpa_then_wep_with_perms ();
	g_test_add_func (TPATH "wifi/write-hidden", test_write_wifi_hidden);
	test_write_wired_qeth_dhcp ();
	test_write_wired_ctc_dhcp ();
	test_write_permissions ();
	test_write_wifi_wep_agent_keys ();
	test_write_infiniband ();
	test_write_vlan ();
	test_write_vlan_only_vlanid ();
	test_write_ethernet_missing_ipv6 ();

	/* iSCSI / ibft */
	test_read_ibft_dhcp ();
	test_read_ibft_static ();
	test_read_ibft_malformed ("ibft-bad-record-read", TEST_IFCFG_DIR "/iscsiadm-test-bad-record", FALSE);
	test_read_ibft_malformed ("ibft-bad-entry-read", TEST_IFCFG_DIR "/iscsiadm-test-bad-entry", TRUE);
	test_read_ibft_malformed ("ibft-bad-ipaddr-read", TEST_IFCFG_DIR "/iscsiadm-test-bad-ipaddr", TRUE);
	test_read_ibft_malformed ("ibft-bad-gateway-read", TEST_IFCFG_DIR "/iscsiadm-test-bad-gateway", TRUE);
	test_read_ibft_malformed ("ibft-bad-dns1-read", TEST_IFCFG_DIR "/iscsiadm-test-bad-dns1", TRUE);
	test_read_ibft_malformed ("ibft-bad-dns2-read", TEST_IFCFG_DIR "/iscsiadm-test-bad-dns2", TRUE);
	g_test_add_func (TPATH "dcb/read-basic", test_read_dcb_basic);
	g_test_add_func (TPATH "dcb/write-basic", test_write_dcb_basic);
	g_test_add_func (TPATH "dcb/default-app-priorities", test_read_dcb_default_app_priorities);
	g_test_add_func (TPATH "dcb/bad-booleans", test_read_dcb_bad_booleans);
	g_test_add_func (TPATH "dcb/short-booleans", test_read_dcb_short_booleans);
	g_test_add_func (TPATH "dcb/bad-uints", test_read_dcb_bad_uints);
	g_test_add_func (TPATH "dcb/short-uints", test_read_dcb_short_uints);
	g_test_add_func (TPATH "dcb/bad-percent", test_read_dcb_bad_percent);
	g_test_add_func (TPATH "dcb/short-percent", test_read_dcb_short_percent);
	g_test_add_func (TPATH "dcb/pgpct-not-100", test_read_dcb_pgpct_not_100);
	g_test_add_data_func (TPATH "fcoe/fabric", (gpointer) NM_SETTING_DCB_FCOE_MODE_FABRIC, test_read_fcoe_mode);
	g_test_add_data_func (TPATH "fcoe/vn2vn", (gpointer) NM_SETTING_DCB_FCOE_MODE_VN2VN, test_read_fcoe_mode);
	g_test_add_data_func (TPATH "fcoe/write-fabric", (gpointer) NM_SETTING_DCB_FCOE_MODE_FABRIC, test_write_fcoe_mode);
	g_test_add_data_func (TPATH "fcoe/write-vn2vn", (gpointer) NM_SETTING_DCB_FCOE_MODE_VN2VN, test_write_fcoe_mode);

	/* bonding */
	test_read_bond_main ();
	test_read_bond_slave ();
	test_read_bond_slave_ib ();
	test_write_bond_main ();
	test_write_bond_slave ();
	test_write_bond_slave_ib ();

	/* bridging */
	test_read_bridge_main ();
	test_write_bridge_main ();
	test_read_bridge_component ();
	test_write_bridge_component ();
	test_read_bridge_missing_stp ();

	/* Team */
	g_test_add_func (TPATH "team/read-master", test_read_team_master);
	g_test_add_func (TPATH "team/write-master", test_write_team_master);
	g_test_add_func (TPATH "team/read-port", test_read_team_port);
	g_test_add_func (TPATH "team/write-port", test_write_team_port);
	g_test_add_func (TPATH "team/read-port-empty-config", test_read_team_port_empty_config);

	/* Stuff we expect to fail for now */
	test_write_wired_pppoe ();
	test_write_vpn ();
	test_write_mobile_broadband (TRUE);
	test_write_mobile_broadband (FALSE);

	return g_test_run ();
}

