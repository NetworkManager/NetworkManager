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

#include "config.h"

#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
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
#include "nm-core-internal.h"

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
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	GError *error = NULL;
	const char *mac;
	char expected_mac_address[ETH_ALEN] = { 0x00, 0x16, 0x41, 0x11, 0x22, 0x33 };
	const char *expected_id = "System test-minimal";
	guint64 expected_timestamp = 0;
	gboolean success;

	connection = connection_from_file_test (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-minimal",
	                                        NULL, TYPE_ETHERNET, NULL, &error);
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
	mac = nm_setting_wired_get_mac_address (s_wired);
	g_assert (mac);
	g_assert (nm_utils_hwaddr_matches (mac, -1, expected_mac_address, ETH_ALEN));

	/* ===== IPv4 SETTING ===== */
	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_DISABLED);
	g_assert (nm_setting_ip_config_get_never_default (s_ip4) == FALSE);

	/* ===== IPv6 SETTING ===== */
	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	g_assert (s_ip6);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip6), ==, NM_SETTING_IP6_CONFIG_METHOD_IGNORE);
	g_assert (nm_setting_ip_config_get_never_default (s_ip6) == FALSE);

	g_object_unref (connection);
}

static void
test_read_miscellaneous_variables (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIPConfig *s_ip4;
	GError *error = NULL;
	char *expected_mac_blacklist[3] = { "00:16:41:11:22:88", "00:16:41:11:22:99", "6a:5d:5a:fa:dd:f0" };
	int mac_blacklist_num, i;
	guint64 expected_timestamp = 0;
	gboolean success;

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_WARNING,
	                       "*invalid MAC in HWADDR_BLACKLIST 'XX:aa:invalid'*");
	connection = connection_from_file_test (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-misc-variables",
	                                        NULL, TYPE_ETHERNET, NULL, &error);
	g_test_assert_expected_messages ();
	g_assert_no_error (error);
	g_assert (connection);
	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	/* ===== CONNECTION SETTING ===== */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpint (nm_setting_connection_get_timestamp (s_con), ==, expected_timestamp);
	g_assert (nm_setting_connection_get_autoconnect (s_con));

	/* ===== WIRED SETTING ===== */
	s_wired = nm_connection_get_setting_wired (connection);
	g_assert (s_wired);
	g_assert_cmpint (nm_setting_wired_get_mtu (s_wired), ==, 0);

	/* MAC blacklist */
	mac_blacklist_num = nm_setting_wired_get_num_mac_blacklist_items (s_wired);
	g_assert_cmpint (mac_blacklist_num, ==, 3);
	for (i = 0; i < mac_blacklist_num; i++)
		g_assert (nm_utils_hwaddr_matches (nm_setting_wired_get_mac_blacklist_item (s_wired, i), -1, expected_mac_blacklist[i], -1));

	/* ===== IPv4 SETTING ===== */
	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_DISABLED);
	g_assert (nm_setting_ip_config_get_never_default (s_ip4) == FALSE);

	g_object_unref (connection);
}

static void
test_read_variables_corner_cases (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIPConfig *s_ip4;
	GError *error = NULL;
	const char *mac;
	char expected_mac_address[ETH_ALEN] = { 0x00, 0x16, 0x41, 0x11, 0x22, 0x33 };
	const char *expected_zone = "'";
	const char *expected_id = "\"";
	guint64 expected_timestamp = 0;
	gboolean success;

	connection = connection_from_file_test (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-variables-corner-cases-1",
	                                        NULL, TYPE_ETHERNET, NULL, &error);
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
	mac = nm_setting_wired_get_mac_address (s_wired);
	g_assert (mac);
	g_assert (nm_utils_hwaddr_matches (mac, -1, expected_mac_address, ETH_ALEN));

	/* ===== IPv4 SETTING ===== */
	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_DISABLED);
	g_assert (nm_setting_ip_config_get_never_default (s_ip4) == FALSE);

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

	connection = connection_from_file_test (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-nm-controlled",
	                                        NULL, TYPE_ETHERNET,
	                                        &unhandled_spec,
	                                        &error);
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
	gs_free char *unhandled_spec = NULL;
	GError *error = NULL;
	const char *expected_id = "PigeonNet";
	guint64 expected_timestamp = 0;
	gboolean success;

	connection = connection_from_file_test (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-nm-controlled-unrecognized",
	                                        NULL, NULL,
	                                        &unhandled_spec,
	                                        &error);
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
	gs_free char *unhandled_spec = NULL;
	GError *error = NULL;
	const char *expected_id = "U Can't Touch This";
	guint64 expected_timestamp = 0;
	gboolean success;

	connection = connection_from_file_test (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-unrecognized",
	                                        NULL, NULL,
	                                        &unhandled_spec,
	                                        &error);
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
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	char *unmanaged = NULL;
	GError *error = NULL;
	const char *mac;
	char expected_mac_address[ETH_ALEN] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0xee };
	NMIPAddress *ip4_addr;
	NMIPAddress *ip6_addr;
	gboolean success;

	connection = connection_from_file_test (file, NULL, TYPE_ETHERNET,
	                                        &unmanaged, &error);
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
	mac = nm_setting_wired_get_mac_address (s_wired);
	g_assert (mac);
	g_assert (nm_utils_hwaddr_matches (mac, -1, expected_mac_address, ETH_ALEN));

	/* ===== IPv4 SETTING ===== */
	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_MANUAL);
	g_assert (nm_setting_ip_config_get_may_fail (s_ip4));

	g_assert (nm_setting_ip_config_has_dns_options (s_ip4));
	g_assert_cmpint (nm_setting_ip_config_get_num_dns_options (s_ip4), ==, 0);

	/* DNS Addresses */
	g_assert_cmpint (nm_setting_ip_config_get_num_dns (s_ip4), ==, 2);
	g_assert_cmpstr (nm_setting_ip_config_get_dns (s_ip4, 0), ==, "4.2.2.1");
	g_assert_cmpstr (nm_setting_ip_config_get_dns (s_ip4, 1), ==, "4.2.2.2");

	/* IP addresses */
	g_assert_cmpint (nm_setting_ip_config_get_num_addresses (s_ip4), ==, 1);
	ip4_addr = nm_setting_ip_config_get_address (s_ip4, 0);
	g_assert (ip4_addr);
	g_assert_cmpint (nm_ip_address_get_prefix (ip4_addr), ==, 24);
	g_assert_cmpstr (nm_ip_address_get_address (ip4_addr), ==, "192.168.1.5");

	/* Gateway */
	g_assert_cmpstr (nm_setting_ip_config_get_gateway (s_ip4), ==, "192.168.1.1");

	/* ===== IPv6 SETTING ===== */
	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	g_assert (s_ip6);
	if (expect_ip6) {
		g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip6), ==, NM_SETTING_IP6_CONFIG_METHOD_MANUAL);
		g_assert (nm_setting_ip_config_get_may_fail (s_ip6));

		g_assert (nm_setting_ip_config_has_dns_options (s_ip6));
		g_assert_cmpint (nm_setting_ip_config_get_num_dns_options (s_ip6), ==, 0);

		/* DNS Addresses */
		g_assert_cmpint (nm_setting_ip_config_get_num_dns (s_ip6), ==, 2);
		g_assert_cmpstr (nm_setting_ip_config_get_dns (s_ip6, 0), ==, "1:2:3:4::a");
		g_assert_cmpstr (nm_setting_ip_config_get_dns (s_ip6, 1), ==, "1:2:3:4::b");

		/* IP addresses */
		g_assert_cmpint (nm_setting_ip_config_get_num_addresses (s_ip6), ==, 2);

		ip6_addr = nm_setting_ip_config_get_address (s_ip6, 0);
		g_assert (ip6_addr);
		g_assert_cmpint (nm_ip_address_get_prefix (ip6_addr), ==, 64);
		g_assert_cmpstr (nm_ip_address_get_address (ip6_addr), ==, "dead:beaf::1");

		ip6_addr = nm_setting_ip_config_get_address (s_ip6, 1);
		g_assert (ip6_addr);
		g_assert_cmpint (nm_ip_address_get_prefix (ip6_addr), ==, 56);
		g_assert_cmpstr (nm_ip_address_get_address (ip6_addr), ==, "dead:beaf::2");
	} else {
		g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip6), ==, NM_SETTING_IP6_CONFIG_METHOD_IGNORE);
		g_assert (!nm_setting_ip_config_has_dns_options (s_ip6));
	}

	g_object_unref (connection);
}

static void
test_read_wired_static_no_prefix (gconstpointer user_data)
{
	guint32 expected_prefix = GPOINTER_TO_UINT (user_data);
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingIPConfig *s_ip4;
	GError *error = NULL;
	NMIPAddress *ip4_addr;
	char *file, *expected_id;

	file = g_strdup_printf (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-wired-static-no-prefix-%u", expected_prefix);
	expected_id = g_strdup_printf ("System test-wired-static-no-prefix-%u", expected_prefix);

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_WARNING,
	                       "*missing PREFIX, assuming*");
	connection = connection_from_file_test (file, NULL, TYPE_ETHERNET, NULL,
	                                        &error);
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
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_MANUAL);

	g_assert (!nm_setting_ip_config_has_dns_options (s_ip4));
	g_assert_cmpint (nm_setting_ip_config_get_num_dns_options (s_ip4), ==, 0);

	g_assert_cmpint (nm_setting_ip_config_get_num_addresses (s_ip4), ==, 1);
	ip4_addr = nm_setting_ip_config_get_address (s_ip4, 0);
	g_assert (ip4_addr);
	g_assert_cmpint (nm_ip_address_get_prefix (ip4_addr), ==, expected_prefix);

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
	NMSettingIPConfig *s_ip4;
	char *unmanaged = NULL;
	GError *error = NULL;
	const char *mac;
	char expected_mac_address[ETH_ALEN] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0xee };
	const char *tmp;
	const char *expected_id = "System test-wired-dhcp";
	const char *expected_dhcp_hostname = "foobar";

	connection = connection_from_file_test (TEST_IFCFG_WIRED_DHCP,
	                                        NULL,
	                                        TYPE_ETHERNET,
	                                        &unmanaged,
	                                        &error);
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
	mac = nm_setting_wired_get_mac_address (s_wired);
	ASSERT (mac != NULL,
	        "wired-dhcp-verify-wired", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIRED_DHCP,
	        NM_SETTING_WIRED_SETTING_NAME,
	        NM_SETTING_WIRED_MAC_ADDRESS);
	ASSERT (nm_utils_hwaddr_matches (mac, -1, expected_mac_address, sizeof (expected_mac_address)),
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
	tmp = nm_setting_ip_config_get_method (s_ip4);
	ASSERT (strcmp (tmp, NM_SETTING_IP4_CONFIG_METHOD_AUTO) == 0,
	        "wired-dhcp-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_DHCP,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP_CONFIG_METHOD);

	tmp = nm_setting_ip_config_get_dhcp_hostname (s_ip4);
	ASSERT (tmp != NULL,
	        "wired-dhcp-verify-ip4", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIRED_DHCP,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP_CONFIG_DHCP_HOSTNAME);
	ASSERT (strcmp (tmp, expected_dhcp_hostname) == 0,
	        "wired-dhcp-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_DHCP,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP_CONFIG_DHCP_HOSTNAME);

	ASSERT (nm_setting_ip_config_get_ignore_auto_dns (s_ip4) == TRUE,
	        "wired-dhcp-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_DHCP,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP_CONFIG_IGNORE_AUTO_DNS);

	/* DNS Addresses */
	ASSERT (nm_setting_ip_config_get_num_dns (s_ip4) == 2,
	        "wired-dhcp-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_DHCP,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP_CONFIG_DNS);

	ASSERT (strcmp (nm_setting_ip_config_get_dns (s_ip4, 0), "4.2.2.1") == 0,
	        "wired-dhcp-verify-ip4", "failed to verify %s: unexpected %s / %s key value #1",
	        TEST_IFCFG_WIRED_DHCP,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP_CONFIG_DNS);

	ASSERT (strcmp (nm_setting_ip_config_get_dns (s_ip4, 1), "4.2.2.2") == 0,
	        "wired-dhcp-verify-ip4", "failed to verify %s: unexpected %s / %s key value #2",
	        TEST_IFCFG_WIRED_DHCP,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP_CONFIG_DNS);

	g_object_unref (connection);
}

static void
test_read_wired_dhcp_plus_ip (void)
{
	NMConnection *connection;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	GError *error = NULL;
	NMIPAddress *ip4_addr;
	NMIPAddress *ip6_addr;
	gboolean success;

	connection = connection_from_file_test (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-dhcp-plus-ip",
	                                        NULL, TYPE_ETHERNET, NULL,
	                                        &error);
	g_assert_no_error (error);
	g_assert (connection);
	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	/* ===== IPv4 SETTING ===== */
	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_AUTO);
	g_assert (nm_setting_ip_config_get_may_fail (s_ip4));

	/* DNS Addresses */
	g_assert_cmpint (nm_setting_ip_config_get_num_dns (s_ip4), ==, 2);
	g_assert_cmpstr (nm_setting_ip_config_get_dns (s_ip4, 0), ==, "4.2.2.1");
	g_assert_cmpstr (nm_setting_ip_config_get_dns (s_ip4, 1), ==, "4.2.2.2");

	/* IP addresses */
	g_assert_cmpint (nm_setting_ip_config_get_num_addresses (s_ip4), ==, 2);
	ip4_addr = nm_setting_ip_config_get_address (s_ip4, 0);
	g_assert (ip4_addr);
	g_assert_cmpint (nm_ip_address_get_prefix (ip4_addr), ==, 24);
	g_assert_cmpstr (nm_ip_address_get_address (ip4_addr), ==, "1.2.3.4");

	/* Gateway */
	g_assert_cmpstr (nm_setting_ip_config_get_gateway (s_ip4), ==, "1.1.1.1");

	ip4_addr = nm_setting_ip_config_get_address (s_ip4, 1);
	g_assert (ip4_addr);
	g_assert_cmpint (nm_ip_address_get_prefix (ip4_addr), ==, 16);
	g_assert_cmpstr (nm_ip_address_get_address (ip4_addr), ==, "9.8.7.6");

	/* ===== IPv6 SETTING ===== */
	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	g_assert (s_ip6);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip6), ==, NM_SETTING_IP6_CONFIG_METHOD_AUTO);
	g_assert (nm_setting_ip_config_get_may_fail (s_ip6));

	/* DNS Addresses */
	g_assert_cmpint (nm_setting_ip_config_get_num_dns (s_ip6), ==, 2);
	g_assert_cmpstr (nm_setting_ip_config_get_dns (s_ip6, 0), ==, "1:2:3:4::a");
	g_assert_cmpstr (nm_setting_ip_config_get_dns (s_ip6, 1), ==, "1:2:3:4::b");

	/* IP addresses */
	g_assert_cmpint (nm_setting_ip_config_get_num_addresses (s_ip6), ==, 3);
	ip6_addr = nm_setting_ip_config_get_address (s_ip6, 0);
	g_assert (ip6_addr);
	g_assert_cmpint (nm_ip_address_get_prefix (ip6_addr), ==, 56);
	g_assert_cmpstr (nm_ip_address_get_address (ip6_addr), ==, "1001:abba::1234");

	ip6_addr = nm_setting_ip_config_get_address (s_ip6, 1);
	g_assert (ip6_addr);
	g_assert_cmpint (nm_ip_address_get_prefix (ip6_addr), ==, 64);
	g_assert_cmpstr (nm_ip_address_get_address (ip6_addr), ==, "2001:abba::2234");

	ip6_addr = nm_setting_ip_config_get_address (s_ip6, 2);
	g_assert (ip6_addr);
	g_assert_cmpint (nm_ip_address_get_prefix (ip6_addr), ==, 96);
	g_assert_cmpstr (nm_ip_address_get_address (ip6_addr), ==, "3001:abba::3234");

	g_object_unref (connection);
}

static void
test_read_wired_shared_plus_ip (void)
{
	NMConnection *connection;
	NMSettingIPConfig *s_ip4;
	GError *error = NULL;
	NMIPAddress *ip4_addr;

	connection = connection_from_file_test (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-shared-plus-ip",
	                                        NULL, TYPE_ETHERNET, NULL,
	                                        &error);
	nmtst_assert_connection_verifies_without_normalization (connection);

	/* ===== IPv4 SETTING ===== */
	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_SHARED);
	g_assert (nm_setting_ip_config_get_may_fail (s_ip4));

	/* IP addresses */
	g_assert_cmpint (nm_setting_ip_config_get_num_addresses (s_ip4), ==, 1);
	ip4_addr = nm_setting_ip_config_get_address (s_ip4, 0);
	g_assert (ip4_addr);
	g_assert_cmpint (nm_ip_address_get_prefix (ip4_addr), ==, 24);
	g_assert_cmpstr (nm_ip_address_get_address (ip4_addr), ==, "10.20.30.5");

	/* Gateway */
	g_assert_cmpstr (nm_setting_ip_config_get_gateway (s_ip4), ==, "1.1.1.1");

	g_object_unref (connection);
}

static void
test_read_wired_global_gateway (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIPConfig *s_ip4;
	GError *error = NULL;
	NMIPAddress *ip4_addr;
	char *unmanaged = NULL;

	connection = connection_from_file_test (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-global-gateway",
	                                        TEST_IFCFG_DIR"/network-scripts/network-test-wired-global-gateway",
	                                        TYPE_ETHERNET, &unmanaged, &error);
	nmtst_assert_connection_verifies_without_normalization (connection);
	g_assert (unmanaged == NULL);

	/* ===== CONNECTION SETTING ===== */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "System test-wired-global-gateway");

	/* ===== WIRED SETTING ===== */
	s_wired = nm_connection_get_setting_wired (connection);
	g_assert (s_wired);

	/* ===== IPv4 SETTING ===== */
	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_MANUAL);

	/* Address #1 */
	ip4_addr = nm_setting_ip_config_get_address (s_ip4, 0);
	g_assert (ip4_addr);
	g_assert_cmpint (nm_ip_address_get_prefix (ip4_addr), ==, 24);
	g_assert_cmpstr (nm_ip_address_get_address (ip4_addr), ==, "192.168.1.5");

	/* Gateway */
	g_assert_cmpstr (nm_setting_ip_config_get_gateway (s_ip4), ==, "192.168.1.2");

	g_object_unref (connection);
}

static void
test_read_wired_obsolete_gateway_n (void)
{
	NMConnection *connection;
	NMSettingIPConfig *s_ip4;
	GError *error = NULL;
	NMIPAddress *ip4_addr;

	connection = connection_from_file_test (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-obsolete-gateway-n",
	                                        NULL, TYPE_ETHERNET, NULL,
	                                        &error);
	nmtst_assert_connection_verifies_without_normalization (connection);

	/* ===== IPv4 SETTING ===== */
	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_MANUAL);

	/* IP addresses */
	g_assert_cmpint (nm_setting_ip_config_get_num_addresses (s_ip4), ==, 1);
	ip4_addr = nm_setting_ip_config_get_address (s_ip4, 0);
	g_assert (ip4_addr);
	g_assert_cmpint (nm_ip_address_get_prefix (ip4_addr), ==, 24);
	g_assert_cmpstr (nm_ip_address_get_address (ip4_addr), ==, "1.2.3.4");

	/* Gateway */
	g_assert_cmpstr (nm_setting_ip_config_get_gateway (s_ip4), ==, "1.1.1.1");

	g_object_unref (connection);
}

static void
test_read_wired_never_default (void)
{
	NMConnection *connection;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	GError *error = NULL;

	connection = connection_from_file_test (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-never-default",
	                                        TEST_IFCFG_DIR"/network-scripts/network-test-wired-never-default",
	                                        TYPE_ETHERNET, NULL, &error);
	nmtst_assert_connection_verifies_without_normalization (connection);

	/* ===== WIRED SETTING ===== */
	g_assert (nm_connection_get_setting_wired (connection));

	/* ===== IPv4 SETTING ===== */
	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_AUTO);
	g_assert (nm_setting_ip_config_get_never_default (s_ip4));
	g_assert_cmpint (nm_setting_ip_config_get_num_dns (s_ip4), ==, 0);

	/* ===== IPv6 SETTING ===== */
	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	g_assert (s_ip6);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip6), ==, NM_SETTING_IP6_CONFIG_METHOD_AUTO);
	g_assert (nm_setting_ip_config_get_never_default (s_ip6));

	g_object_unref (connection);
}

#define TEST_IFCFG_WIRED_DEFROUTE_NO TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-defroute-no"

static void
test_read_wired_defroute_no (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	char *unmanaged = NULL;
	GError *error = NULL;
	const char *tmp;
	const char *expected_id = "System test-wired-defroute-no";

	connection = connection_from_file_test (TEST_IFCFG_WIRED_DEFROUTE_NO,
	                                        NULL,
	                                        TYPE_ETHERNET,
	                                        &unmanaged,
	                                        &error);
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
	tmp = nm_setting_ip_config_get_method (s_ip4);
	ASSERT (strcmp (tmp, NM_SETTING_IP4_CONFIG_METHOD_AUTO) == 0,
	        "wired-defroute-no-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_DEFROUTE_NO,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP_CONFIG_METHOD);

	ASSERT (nm_setting_ip_config_get_never_default (s_ip4) == TRUE,
	        "wired-defroute-no-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_DEFROUTE_NO,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP_CONFIG_NEVER_DEFAULT);

	/* ===== IPv6 SETTING ===== */

	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	ASSERT (s_ip6 != NULL,
	        "wired-defroute-no-verify-ip6", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIRED_DEFROUTE_NO,
	        NM_SETTING_IP6_CONFIG_SETTING_NAME);

	/* Method */
	tmp = nm_setting_ip_config_get_method (s_ip6);
	ASSERT (strcmp (tmp, NM_SETTING_IP6_CONFIG_METHOD_AUTO) == 0,
	        "wired-defroute-no-verify-ip6", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_DEFROUTE_NO,
	        NM_SETTING_IP6_CONFIG_SETTING_NAME,
	        NM_SETTING_IP_CONFIG_METHOD);

	ASSERT (nm_setting_ip_config_get_never_default (s_ip6) == TRUE,
	        "wired-defroute-no-verify-ip6", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_DEFROUTE_NO,
	        NM_SETTING_IP6_CONFIG_SETTING_NAME,
	        NM_SETTING_IP_CONFIG_NEVER_DEFAULT);

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
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	char *unmanaged = NULL;
	GError *error = NULL;
	const char *tmp;
	const char *expected_id = "System test-wired-defroute-no-gatewaydev-yes";

	connection = connection_from_file_test (TEST_IFCFG_WIRED_DEFROUTE_NO_GATEWAYDEV_YES,
	                                        TEST_NETWORK_WIRED_DEFROUTE_NO_GATEWAYDEV_YES,
	                                        TYPE_ETHERNET,
	                                        &unmanaged,
	                                        &error);
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
	tmp = nm_setting_ip_config_get_method (s_ip4);
	ASSERT (strcmp (tmp, NM_SETTING_IP4_CONFIG_METHOD_AUTO) == 0,
	        "wired-defroute-no-gatewaydev-yes-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_DEFROUTE_NO_GATEWAYDEV_YES,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP_CONFIG_METHOD);

	ASSERT (nm_setting_ip_config_get_never_default (s_ip4) == FALSE,
	        "wired-defroute-no-gatewaydev-yes-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_DEFROUTE_NO_GATEWAYDEV_YES,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP_CONFIG_NEVER_DEFAULT);

	/* ===== IPv6 SETTING ===== */

	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	ASSERT (s_ip6 != NULL,
	        "wired-defroute-no-gatewaydev-yes-verify-ip6", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIRED_DEFROUTE_NO_GATEWAYDEV_YES,
	        NM_SETTING_IP6_CONFIG_SETTING_NAME);

	/* Method */
	tmp = nm_setting_ip_config_get_method (s_ip6);
	ASSERT (strcmp (tmp, NM_SETTING_IP6_CONFIG_METHOD_AUTO) == 0,
	        "wired-defroute-no-gatewaydev-yes-verify-ip6", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_DEFROUTE_NO_GATEWAYDEV_YES,
	        NM_SETTING_IP6_CONFIG_SETTING_NAME,
	        NM_SETTING_IP_CONFIG_METHOD);

	ASSERT (nm_setting_ip_config_get_never_default (s_ip6) == FALSE,
	        "wired-defroute-no-gatewaydev-yes-verify-ip6", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_DEFROUTE_NO_GATEWAYDEV_YES,
	        NM_SETTING_IP6_CONFIG_SETTING_NAME,
	        NM_SETTING_IP_CONFIG_NEVER_DEFAULT);

	g_object_unref (connection);
}

static void
test_read_wired_static_routes (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIPConfig *s_ip4;
	GError *error = NULL;
	NMIPRoute *ip4_route;

	connection = connection_from_file_test (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-static-routes",
	                                        NULL, TYPE_ETHERNET, NULL, &error);
	nmtst_assert_connection_verifies_without_normalization (connection);

	/* ===== CONNECTION SETTING ===== */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "System test-wired-static-routes");

	/* ===== WIRED SETTING ===== */
	s_wired = nm_connection_get_setting_wired (connection);
	g_assert (s_wired);

	/* ===== IPv4 SETTING ===== */
	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_MANUAL);

	/* Routes */
	g_assert_cmpint (nm_setting_ip_config_get_num_routes (s_ip4), ==, 2);

	ip4_route = nm_setting_ip_config_get_route (s_ip4, 0);
	g_assert (ip4_route);
	g_assert_cmpstr (nm_ip_route_get_dest (ip4_route), ==, "11.22.33.0");
	g_assert_cmpint (nm_ip_route_get_prefix (ip4_route), ==, 24);
	g_assert_cmpstr (nm_ip_route_get_next_hop (ip4_route), ==, "192.168.1.5");
	g_assert_cmpint (nm_ip_route_get_metric (ip4_route), ==, -1);

	ip4_route = nm_setting_ip_config_get_route (s_ip4, 1);
	g_assert (ip4_route);
	g_assert_cmpstr (nm_ip_route_get_dest (ip4_route), ==, "44.55.66.77");
	g_assert_cmpint (nm_ip_route_get_prefix (ip4_route), ==, 32);
	g_assert_cmpstr (nm_ip_route_get_next_hop (ip4_route), ==, "192.168.1.7");
	g_assert_cmpint (nm_ip_route_get_metric (ip4_route), ==, 3);

	g_object_unref (connection);
}

#define TEST_IFCFG_WIRED_STATIC_ROUTES_LEGACY TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-static-routes-legacy"

static void
test_read_wired_static_routes_legacy (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIPConfig *s_ip4;
	char *unmanaged = NULL;
	GError *error = NULL;
	const char *tmp;
	NMIPRoute *ip4_route;
	const char *expected_id = "System test-wired-static-routes-legacy";

	connection = connection_from_file_test (TEST_IFCFG_WIRED_STATIC_ROUTES_LEGACY,
	                                        NULL,
	                                        TYPE_ETHERNET,
	                                        &unmanaged,
	                                        &error);

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
	tmp = nm_setting_ip_config_get_method (s_ip4);
	ASSERT (strcmp (tmp, NM_SETTING_IP4_CONFIG_METHOD_MANUAL) == 0,
	        "wired-static-routes-legacy-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_STATIC_ROUTES_LEGACY,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP_CONFIG_METHOD);

	/* Routes */
	ASSERT (nm_setting_ip_config_get_num_routes (s_ip4) == 3,
	        "wired-static-routes-legacy-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_STATIC_ROUTES_LEGACY,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP_CONFIG_ROUTES);

	/* Route #1 */
	ip4_route = nm_setting_ip_config_get_route (s_ip4, 0);
	g_assert (ip4_route != NULL);
	g_assert_cmpstr (nm_ip_route_get_dest (ip4_route), ==, "21.31.41.0");
	g_assert_cmpint (nm_ip_route_get_prefix (ip4_route), ==, 24);
	g_assert_cmpstr (nm_ip_route_get_next_hop (ip4_route), ==, "9.9.9.9");
	g_assert_cmpint (nm_ip_route_get_metric (ip4_route), ==, 1);

	/* Route #2 */
	ip4_route = nm_setting_ip_config_get_route (s_ip4, 1);
	g_assert (ip4_route != NULL);
	g_assert_cmpstr (nm_ip_route_get_dest (ip4_route), ==, "32.42.52.62");
	g_assert_cmpint (nm_ip_route_get_prefix (ip4_route), ==, 32);
	g_assert_cmpstr (nm_ip_route_get_next_hop (ip4_route), ==, "8.8.8.8");
	g_assert_cmpint (nm_ip_route_get_metric (ip4_route), ==, -1);

	/* Route #3 */
	ip4_route = nm_setting_ip_config_get_route (s_ip4, 2);
	g_assert (ip4_route != NULL);
	g_assert_cmpstr (nm_ip_route_get_dest (ip4_route), ==, "43.53.0.0");
	g_assert_cmpint (nm_ip_route_get_prefix (ip4_route), ==, 16);
	g_assert_cmpstr (nm_ip_route_get_next_hop (ip4_route), ==, "7.7.7.7");
	g_assert_cmpint (nm_ip_route_get_metric (ip4_route), ==, 3);

	g_object_unref (connection);
}

static void
test_read_wired_ipv4_manual (const char *file, const char *expected_id)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIPConfig *s_ip4;
	char *unmanaged = NULL;
	GError *error = NULL;
	const char *tmp;
	NMIPAddress *ip4_addr;

	connection = connection_from_file_test (file,
	                                        NULL,
	                                        TYPE_ETHERNET,
	                                        &unmanaged,
	                                        &error);
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
	tmp = nm_setting_ip_config_get_method (s_ip4);
	ASSERT (strcmp (tmp, NM_SETTING_IP4_CONFIG_METHOD_MANUAL) == 0,
	        "wired-ipv4-manual-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        file,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP_CONFIG_METHOD);

	/* IP addresses */
	ASSERT (nm_setting_ip_config_get_num_addresses (s_ip4) == 3,
		"wired-ipv4-manual-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
		file,
		NM_SETTING_IP4_CONFIG_SETTING_NAME,
		NM_SETTING_IP_CONFIG_ADDRESSES);

	/* Address #1 */
	ip4_addr = nm_setting_ip_config_get_address (s_ip4, 0);
	g_assert (ip4_addr != NULL);
	g_assert_cmpstr (nm_ip_address_get_address (ip4_addr), ==, "1.2.3.4");
	g_assert_cmpint (nm_ip_address_get_prefix (ip4_addr), ==, 24);

	/* Address #2 */
	ip4_addr = nm_setting_ip_config_get_address (s_ip4, 1);
	g_assert (ip4_addr != NULL);
	g_assert_cmpstr (nm_ip_address_get_address (ip4_addr), ==, "9.8.7.6");
	g_assert_cmpint (nm_ip_address_get_prefix (ip4_addr), ==, 16);

	/* Address #3 */
	ip4_addr = nm_setting_ip_config_get_address (s_ip4, 2);
	g_assert (ip4_addr != NULL);
	g_assert_cmpstr (nm_ip_address_get_address (ip4_addr), ==, "3.3.3.3");
	g_assert_cmpint (nm_ip_address_get_prefix (ip4_addr), ==, 8);

	g_object_unref (connection);
}

#define TEST_IFCFG_WIRED_IPV6_MANUAL TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-ipv6-manual"

static void
test_read_wired_ipv6_manual (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	char *unmanaged = NULL;
	GError *error = NULL;
	const char *tmp;
	const char *expected_id = "System test-wired-ipv6-manual";
	NMIPAddress *ip6_addr;
	NMIPRoute *ip6_route;

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_WARNING,
	                       "*ignoring manual default route*");
	connection = connection_from_file_test (TEST_IFCFG_WIRED_IPV6_MANUAL,
	                                        NULL,
	                                        TYPE_ETHERNET,
	                                        &unmanaged,
	                                        &error);
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
	ASSERT (nm_setting_ip_config_get_num_dns (s_ip4) == 2,
	        "wired-ipv6-manual-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_IPV6_MANUAL,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP_CONFIG_DNS);

	/* DNS search domains */
	ASSERT (nm_setting_ip_config_get_num_dns_searches (s_ip4) == 3,
	        "wired-ipv6-manual-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_IPV6_MANUAL,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP_CONFIG_DNS);

	tmp = nm_setting_ip_config_get_dns_search (s_ip4, 0);
	ASSERT (tmp != NULL,
	        "wired-ipv6-manual-verify-ip4", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIRED_IPV6_MANUAL,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP_CONFIG_DNS_SEARCH);
	ASSERT (strcmp (tmp, "lorem.com") == 0,
	        "wired-ipv6-manual-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_IPV6_MANUAL,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP_CONFIG_DNS_SEARCH);

	tmp = nm_setting_ip_config_get_dns_search (s_ip4, 1);
	ASSERT (tmp != NULL,
	        "wired-ipv6-manual-verify-ip4", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIRED_IPV6_MANUAL,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP_CONFIG_DNS_SEARCH);
	ASSERT (strcmp (tmp, "ipsum.org") == 0,
	        "wired-ipv6-manual-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_IPV6_MANUAL,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP_CONFIG_DNS_SEARCH);

	tmp = nm_setting_ip_config_get_dns_search (s_ip4, 2);
	ASSERT (tmp != NULL,
	        "wired-ipv6-manual-verify-ip4", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIRED_IPV6_MANUAL,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP_CONFIG_DNS_SEARCH);
	ASSERT (strcmp (tmp, "dolor.edu") == 0,
	        "wired-ipv6-manual-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_IPV6_MANUAL,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP_CONFIG_DNS_SEARCH);

	/* ===== IPv6 SETTING ===== */

	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	ASSERT (s_ip6 != NULL,
	        "wired-ipv6-manual-verify-ip6", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIRED_IPV6_MANUAL,
	        NM_SETTING_IP6_CONFIG_SETTING_NAME);

	/* Method */
	tmp = nm_setting_ip_config_get_method (s_ip6);
	ASSERT (strcmp (tmp, NM_SETTING_IP6_CONFIG_METHOD_MANUAL) == 0,
	        "wired-ipv6-manual-verify-ip6", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_IPV6_MANUAL,
	        NM_SETTING_IP6_CONFIG_SETTING_NAME,
	        NM_SETTING_IP_CONFIG_METHOD);

	ASSERT (nm_setting_ip_config_get_never_default (s_ip6) == FALSE,
	        "wired-ipv6-manual-verify-ip6", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_IPV6_MANUAL,
	        NM_SETTING_IP6_CONFIG_SETTING_NAME,
	        NM_SETTING_IP_CONFIG_NEVER_DEFAULT);

	ASSERT (nm_setting_ip_config_get_may_fail (s_ip6) == TRUE,
	        "wired-ipv6-manual-verify-ip6", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_IPV6_MANUAL,
	        NM_SETTING_IP6_CONFIG_SETTING_NAME,
	        NM_SETTING_IP_CONFIG_MAY_FAIL);

	/* IP addresses */
	ASSERT (nm_setting_ip_config_get_num_addresses (s_ip6) == 3,
		"wired-ipv6-manual-verify-ip6", "failed to verify %s: unexpected %s / %s key value",
		TEST_IFCFG_WIRED_IPV6_MANUAL,
		NM_SETTING_IP6_CONFIG_SETTING_NAME,
		NM_SETTING_IP_CONFIG_ADDRESSES);

	/* Address #1 */
	ip6_addr = nm_setting_ip_config_get_address (s_ip6, 0);
	g_assert (ip6_addr != NULL);
	g_assert_cmpstr (nm_ip_address_get_address (ip6_addr), ==, "1001:abba::1234");
	g_assert_cmpint (nm_ip_address_get_prefix (ip6_addr), ==, 56);

	/* Address #2 */
	ip6_addr = nm_setting_ip_config_get_address (s_ip6, 1);
	g_assert (ip6_addr != NULL);
	g_assert_cmpstr (nm_ip_address_get_address (ip6_addr), ==, "2001:abba::2234");
	g_assert_cmpint (nm_ip_address_get_prefix (ip6_addr), ==, 64);

	/* Address #3 */
	ip6_addr = nm_setting_ip_config_get_address (s_ip6, 2);
	g_assert (ip6_addr != NULL);
	g_assert_cmpstr (nm_ip_address_get_address (ip6_addr), ==, "3001:abba::3234");
	g_assert_cmpint (nm_ip_address_get_prefix (ip6_addr), ==, 96);

	/* Routes */
	g_assert_cmpint (nm_setting_ip_config_get_num_routes (s_ip6), ==, 2);
	/* Route #1 */
	ip6_route = nm_setting_ip_config_get_route (s_ip6, 0);
	g_assert (ip6_route);
	g_assert_cmpstr (nm_ip_route_get_dest (ip6_route), ==, "9876::1234");
	g_assert_cmpint (nm_ip_route_get_prefix (ip6_route), ==, 96);
	g_assert_cmpstr (nm_ip_route_get_next_hop (ip6_route), ==, "9876::7777");
	g_assert_cmpint (nm_ip_route_get_metric (ip6_route), ==, 2);
	/* Route #2 */
	ip6_route = nm_setting_ip_config_get_route (s_ip6, 1);
	g_assert (ip6_route);
	g_assert_cmpstr (nm_ip_route_get_dest (ip6_route), ==, "abbe::cafe");
	g_assert_cmpint (nm_ip_route_get_prefix (ip6_route), ==, 64);
	g_assert_cmpstr (nm_ip_route_get_next_hop (ip6_route), ==, NULL);
	g_assert_cmpint (nm_ip_route_get_metric (ip6_route), ==, 777);

	/* DNS Addresses */
	ASSERT (nm_setting_ip_config_get_num_dns (s_ip6) == 2,
	        "wired-ipv6-manual-verify-ip6", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_IPV6_MANUAL,
	        NM_SETTING_IP6_CONFIG_SETTING_NAME,
	        NM_SETTING_IP_CONFIG_DNS);

	ASSERT (strcmp (nm_setting_ip_config_get_dns (s_ip6, 0), "1:2:3:4::a") == 0,
		"wired-ipv6-manual-verify-ip6", "failed to verify %s: unexpected %s / %s key value #1",
		TEST_IFCFG_WIRED_IPV6_MANUAL,
		NM_SETTING_IP6_CONFIG_SETTING_NAME,
		NM_SETTING_IP_CONFIG_DNS);

	ASSERT (strcmp (nm_setting_ip_config_get_dns (s_ip6, 1), "1:2:3:4::b") == 0,
		"wired-ipv6-manual-verify-ip6", "failed to verify %s: unexpected %s / %s key value #2",
		TEST_IFCFG_WIRED_IPV6_MANUAL,
		NM_SETTING_IP6_CONFIG_SETTING_NAME,
		NM_SETTING_IP_CONFIG_DNS);

	/* DNS domains - none as domains are stuffed to 'ipv4' setting */
	ASSERT (nm_setting_ip_config_get_num_dns_searches (s_ip6) == 0,
	        "wired-ipv6-manual-verify-ip6", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_IPV6_MANUAL,
	        NM_SETTING_IP6_CONFIG_SETTING_NAME,
	        NM_SETTING_IP_CONFIG_DNS_SEARCH);

	g_object_unref (connection);
}

#define TEST_IFCFG_WIRED_IPV6_ONLY TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-ipv6-only"

static void
test_read_wired_ipv6_only (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	char *unmanaged = NULL;
	GError *error = NULL;
	const char *tmp;
	const char *expected_id = "System test-wired-ipv6-only";
	NMIPAddress *ip6_addr;
	const char *method;

	connection = connection_from_file_test (TEST_IFCFG_WIRED_IPV6_ONLY,
	                                        NULL,
	                                        TYPE_ETHERNET,
	                                        &unmanaged,
	                                        &error);
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

	method = nm_setting_ip_config_get_method (s_ip4);
	ASSERT (strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_DISABLED) == 0,
	        "wired-ipv6-only-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_IPV6_MANUAL,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP_CONFIG_METHOD);

	/* ===== IPv6 SETTING ===== */

	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	ASSERT (s_ip6 != NULL,
	        "wired-ipv6-only-verify-ip6", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIRED_IPV6_MANUAL,
	        NM_SETTING_IP6_CONFIG_SETTING_NAME);

	/* Method */
	tmp = nm_setting_ip_config_get_method (s_ip6);
	ASSERT (strcmp (tmp, NM_SETTING_IP6_CONFIG_METHOD_MANUAL) == 0,
	        "wired-ipv6-only-verify-ip6", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_IPV6_MANUAL,
	        NM_SETTING_IP6_CONFIG_SETTING_NAME,
	        NM_SETTING_IP_CONFIG_METHOD);

	/* IP addresses */
	ASSERT (nm_setting_ip_config_get_num_addresses (s_ip6) == 1,
		"wired-ipv6-only-verify-ip6", "failed to verify %s: unexpected %s / %s key value",
		TEST_IFCFG_WIRED_IPV6_MANUAL,
		NM_SETTING_IP6_CONFIG_SETTING_NAME,
		NM_SETTING_IP_CONFIG_ADDRESSES);

	/* Address #1 */
	ip6_addr = nm_setting_ip_config_get_address (s_ip6, 0);
	g_assert (ip6_addr != NULL);
	g_assert_cmpstr (nm_ip_address_get_address (ip6_addr), ==, "1001:abba::1234");
	g_assert_cmpint (nm_ip_address_get_prefix (ip6_addr), ==, 56);

	/* DNS Addresses */
	ASSERT (nm_setting_ip_config_get_num_dns (s_ip6) == 1,
	        "wired-ipv6-only-verify-ip6", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_IPV6_MANUAL,
	        NM_SETTING_IP6_CONFIG_SETTING_NAME,
	        NM_SETTING_IP_CONFIG_DNS);

	ASSERT (strcmp (nm_setting_ip_config_get_dns (s_ip6, 0), "1:2:3:4::a") == 0,
		"wired-ipv6-only-verify-ip6", "failed to verify %s: unexpected %s / %s key value #1",
		TEST_IFCFG_WIRED_IPV6_MANUAL,
		NM_SETTING_IP6_CONFIG_SETTING_NAME,
		NM_SETTING_IP_CONFIG_DNS);

	/* DNS domains should be in IPv6, because IPv4 is disabled */
	g_assert_cmpint (nm_setting_ip_config_get_num_dns_searches (s_ip6), ==, 3);
	g_assert_cmpstr (nm_setting_ip_config_get_dns_search (s_ip6, 0), ==, "lorem.com");
	g_assert_cmpstr (nm_setting_ip_config_get_dns_search (s_ip6, 1), ==, "ipsum.org");
	g_assert_cmpstr (nm_setting_ip_config_get_dns_search (s_ip6, 2), ==, "dolor.edu");

	g_object_unref (connection);
}

#define TEST_IFCFG_WIRED_DHCP6_ONLY TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-dhcp6-only"

static void
test_read_wired_dhcp6_only (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	char *unmanaged = NULL;
	GError *error = NULL;
	const char *tmp;
	const char *expected_id = "System test-wired-dhcp6-only";
	const char *method;

	connection = connection_from_file_test (TEST_IFCFG_WIRED_DHCP6_ONLY,
	                                        NULL,
	                                        TYPE_ETHERNET,
	                                        &unmanaged,
	                                        &error);
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

	method = nm_setting_ip_config_get_method (s_ip4);
	ASSERT (strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_DISABLED) == 0,
	        "wired-dhcp6-only-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_DHCP6_ONLY,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP_CONFIG_METHOD);

	/* ===== IPv6 SETTING ===== */

	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	ASSERT (s_ip6 != NULL,
	        "wired-dhcp6-only-verify-ip6", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIRED_DHCP6_ONLY,
	        NM_SETTING_IP6_CONFIG_SETTING_NAME);

	/* Method */
	tmp = nm_setting_ip_config_get_method (s_ip6);
	ASSERT (strcmp (tmp, NM_SETTING_IP6_CONFIG_METHOD_DHCP) == 0,
	        "wired-dhcp6-only-verify-ip6", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_DHCP6_ONLY,
	        NM_SETTING_IP6_CONFIG_SETTING_NAME,
	        NM_SETTING_IP_CONFIG_METHOD);

	g_object_unref (connection);
}

#define TEST_IFCFG_ONBOOT_NO TEST_IFCFG_DIR"/network-scripts/ifcfg-test-onboot-no"

static void
test_read_onboot_no (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	char *unmanaged = NULL;
	GError *error = NULL;

	connection = connection_from_file_test (TEST_IFCFG_ONBOOT_NO,
	                                        NULL,
	                                        TYPE_ETHERNET,
	                                        &unmanaged,
	                                        &error);
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

	g_object_unref (connection);
}

#define TEST_IFCFG_NOIP TEST_IFCFG_DIR"/network-scripts/ifcfg-test-noip"

static void
test_read_noip (void)
{
	NMConnection *connection;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	GError *error = NULL;

	connection = connection_from_file_test (TEST_IFCFG_NOIP,
	                                        NULL,
	                                        TYPE_ETHERNET,
	                                        NULL,
	                                        &error);
	g_assert (connection);
	g_assert (nm_connection_verify (connection, &error));
	g_assert_no_error (error);

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_DISABLED);
	g_assert (nm_setting_ip_config_get_never_default (s_ip4) == FALSE);

	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	g_assert (s_ip6);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip6), ==, NM_SETTING_IP6_CONFIG_METHOD_IGNORE);
	g_assert (nm_setting_ip_config_get_never_default (s_ip6) == FALSE);

	g_object_unref (connection);
}

#define TEST_IFCFG_WIRED_8021x_PEAP_MSCHAPV2 TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-8021x-peap-mschapv2"
#define TEST_IFCFG_WIRED_8021x_PEAP_MSCHAPV2_CA_CERT TEST_IFCFG_DIR"/network-scripts/test_ca_cert.pem"

static void
test_read_wired_8021x_peap_mschapv2 (void)
{
	NMConnection *connection;
	NMSettingWired *s_wired;
	NMSettingIPConfig *s_ip4;
	NMSetting8021x *s_8021x;
	NMSetting8021x *tmp_8021x;
	char *unmanaged = NULL;
	GError *error = NULL;
	const char *tmp;
	const char *expected_identity = "David Smith";
	const char *expected_anon_identity = "somebody";
	const char *expected_password = "foobar baz";
	gboolean success = FALSE;
	const char *expected_ca_cert_path;
	const char *read_ca_cert_path;

	connection = connection_from_file_test (TEST_IFCFG_WIRED_8021x_PEAP_MSCHAPV2,
	                                        NULL,
	                                        TYPE_ETHERNET,
	                                        &unmanaged,
	                                        &error);
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
	tmp = nm_setting_ip_config_get_method (s_ip4);
	ASSERT (strcmp (tmp, NM_SETTING_IP4_CONFIG_METHOD_AUTO) == 0,
	        "wired-8021x-peap-mschapv2-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_8021x_PEAP_MSCHAPV2,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP_CONFIG_METHOD);

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
	GError *error = NULL;
	const char *expected_identity = "David Smith";
	gboolean success = FALSE;
	char *dirname, *tmp;

	connection = connection_from_file_test (ifcfg,
	                                        NULL,
	                                        TYPE_ETHERNET,
	                                        NULL,
	                                        &error);
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
	connection = connection_from_file_test (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-802-1X-subj-matches",
	                                        NULL, TYPE_ETHERNET, NULL,
	                                        &error);
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
	nm_connection_normalize (connection, NULL, NULL, NULL);

	/* re-read the connection for comparison */
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_WARNING,
	                       "*missing IEEE_8021X_CA_CERT*peap*");
	reread = connection_from_file_test (written, NULL, TYPE_ETHERNET, NULL,
	                                    &error);
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

	connection = connection_from_file_test (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-802-1x-ttls-eapgtc",
	                                        NULL, TYPE_WIRELESS, NULL, &error);
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
	NMSettingIPConfig *s_ip4;
	GError *error = NULL;
	const char *tmp;
	const char *expected_id = "System aliasem0";
	int expected_num_addresses = 4;
	const char *expected_address[4] = { "192.168.1.5", "192.168.1.6", "192.168.1.9", "192.168.1.99" };
	const char *expected_label[4] = { NULL, "aliasem0:1", "aliasem0:2", "aliasem0:99" };
	const char *expected_gateway = "192.168.1.1";
	int i, j;

	connection = connection_from_file_test (TEST_IFCFG_ALIASES_GOOD,
	                                        NULL,
	                                        TYPE_ETHERNET,
	                                        NULL,
	                                        &error);
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
	tmp = nm_setting_ip_config_get_method (s_ip4);
	ASSERT (strcmp (tmp, NM_SETTING_IP4_CONFIG_METHOD_MANUAL) == 0,
	        "aliases-good-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_ALIASES_GOOD,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP_CONFIG_METHOD);

	ASSERT (nm_setting_ip_config_get_num_addresses (s_ip4) == expected_num_addresses,
	        "aliases-good-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_ALIASES_GOOD,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP_CONFIG_ADDRESSES);

	/* Addresses */
	for (i = 0; i < expected_num_addresses; i++) {
		NMIPAddress *ip4_addr;
		const char *addr;
		GVariant *label;

		ip4_addr = nm_setting_ip_config_get_address (s_ip4, i);
		g_assert (ip4_addr != NULL);

		addr = nm_ip_address_get_address (ip4_addr);
		g_assert (nm_utils_ipaddr_valid (AF_INET, addr));

		for (j = 0; j < expected_num_addresses; j++) {
			if (!g_strcmp0 (addr, expected_address[j]))
				break;
		}
		g_assert (j < expected_num_addresses);

		g_assert_cmpint (nm_ip_address_get_prefix (ip4_addr), ==, 24);
		label = nm_ip_address_get_attribute (ip4_addr, "label");
		if (expected_label[j])
			g_assert_cmpstr (g_variant_get_string (label, NULL), ==, expected_label[j]);
		else
			g_assert (label == NULL);

		expected_address[j] = NULL;
		expected_label[j] = NULL;
	}

	/* Gateway */
	g_assert_cmpstr (nm_setting_ip_config_get_gateway (s_ip4), ==, expected_gateway);

	for (i = 0; i < expected_num_addresses; i++) {
		ASSERT (expected_address[i] == NULL,
		        "aliases-good-verify-ip4", "failed to verify %s: did not find IP4 address %s",
		        TEST_IFCFG_ALIASES_GOOD,
		        expected_address[i]);
	}

	g_object_unref (connection);
}

static void
test_read_wired_aliases_bad (const char *base, const char *expected_id)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingIPConfig *s_ip4;
	GError *error = NULL;
	const char *tmp;
	NMIPAddress *ip4_addr;

	connection = connection_from_file_test (base,
	                                        NULL,
	                                        TYPE_ETHERNET,
	                                        NULL,
	                                        &error);
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
	tmp = nm_setting_ip_config_get_method (s_ip4);
	ASSERT (strcmp (tmp, NM_SETTING_IP4_CONFIG_METHOD_MANUAL) == 0,
	        "aliases-bad-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        base,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP_CONFIG_METHOD);

	ASSERT (nm_setting_ip_config_get_num_addresses (s_ip4) == 1,
	        "aliases-bad-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        base,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP_CONFIG_ADDRESSES);

	/* Addresses */
	ip4_addr = nm_setting_ip_config_get_address (s_ip4, 0);
	g_assert (ip4_addr != NULL);
	g_assert_cmpstr (nm_ip_address_get_address (ip4_addr), ==, "192.168.1.5");
	g_assert_cmpint (nm_ip_address_get_prefix (ip4_addr), ==, 24);
	g_assert (nm_ip_address_get_attribute (ip4_addr, "label") == NULL);

	/* Gateway */
	g_assert_cmpstr (nm_setting_ip_config_get_gateway (s_ip4), ==, "192.168.1.1");

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

#define TEST_IFCFG_DNS_OPTIONS TEST_IFCFG_DIR "/network-scripts/ifcfg-test-dns-options"

static void
test_read_dns_options (void)
{
	NMConnection *connection;
	NMSettingIPConfig *s_ip4, *s_ip6;
	char *unmanaged = NULL;
	const char *option;
	GError *error = NULL;
	const char *options[] = { "ndots:3", "single-request-reopen", "inet6" };
	guint32 i, options_len = sizeof (options) / sizeof (options[0]);

	connection = connection_from_file_test (TEST_IFCFG_DNS_OPTIONS,
	                                        NULL,
	                                        TYPE_ETHERNET,
	                                        &unmanaged,
	                                        &error);
	g_assert (connection);
	g_assert (nm_connection_verify (connection, &error));
	g_assert_cmpstr (unmanaged, ==, NULL);

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);

	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	g_assert (s_ip6);

	i = nm_setting_ip_config_get_num_dns_options (s_ip4);
	g_assert_cmpint (i, ==, options_len);

	i = nm_setting_ip_config_get_num_dns_options (s_ip6);
	g_assert_cmpint (i, ==, options_len);

	for (i = 0; i < options_len; i++) {
		option = nm_setting_ip_config_get_dns_option (s_ip4, i);
		g_assert_cmpstr (options[i], ==, option);

		option = nm_setting_ip_config_get_dns_option (s_ip6, i);
		g_assert_cmpstr (options[i], ==, option);
	}

	g_object_unref (connection);
}

static void
test_write_dns_options (void)
{
	NMConnection *connection;
	NMConnection *reread;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	static const char *mac = "31:33:33:37:be:cd";
	guint32 mtu = 1492;
	char *uuid;
	NMIPAddress *addr;
	NMIPAddress *addr6;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;

	connection = nm_simple_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test DNS options",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* Wired setting */
	s_wired = (NMSettingWired *) nm_setting_wired_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wired));

	g_object_set (s_wired,
	              NM_SETTING_WIRED_MAC_ADDRESS, mac,
	              NM_SETTING_WIRED_MTU, mtu,
	              NULL);

	/* IP4 setting */
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_MANUAL,
	              NM_SETTING_IP_CONFIG_MAY_FAIL, TRUE,
	              NM_SETTING_IP_CONFIG_GATEWAY, "1.1.1.1",
	              NM_SETTING_IP_CONFIG_ROUTE_METRIC, (gint64) 204,
	              NULL);

	addr = nm_ip_address_new (AF_INET, "1.1.1.3", 24, &error);
	nm_setting_ip_config_add_address (s_ip4, addr);
	nm_ip_address_unref (addr);

	/* IP6 setting */
	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_MANUAL,
	              NM_SETTING_IP_CONFIG_MAY_FAIL, TRUE,
	              NM_SETTING_IP_CONFIG_ROUTE_METRIC, (gint64) 206,
	              NULL);

	/* Add addresses */
	addr6 = nm_ip_address_new (AF_INET6, "1003:1234:abcd::1", 11, &error);
	nm_setting_ip_config_add_address (s_ip6, addr6);
	nm_ip_address_unref (addr6);

	nm_setting_ip_config_add_dns_option (s_ip4, "debug");
	nm_setting_ip_config_add_dns_option (s_ip6, "timeout:3");

	g_assert (nm_connection_verify (connection, &error));

	/* Save the ifcfg */
	success = writer_new_connection (connection,
	                                 TEST_SCRATCH_DIR "/network-scripts/",
	                                 &testfile,
	                                 &error);
	g_assert (success);
	g_assert (testfile);

	/* reread will be normalized, so we must normalize connection too. */
	nm_connection_normalize (connection, NULL, NULL, NULL);

	/* re-read the connection for comparison */
	reread = connection_from_file_test (testfile,
	                                    NULL,
	                                    TYPE_ETHERNET,
	                                    NULL,
	                                    &error);
	unlink (testfile);

	/* RES_OPTIONS is copied to both IPv4 and IPv6 settings */
	nm_setting_ip_config_clear_dns_options (s_ip4, TRUE);
	nm_setting_ip_config_add_dns_option (s_ip4, "debug");
	nm_setting_ip_config_add_dns_option (s_ip4, "timeout:3");

	nm_setting_ip_config_clear_dns_options (s_ip6, TRUE);
	nm_setting_ip_config_add_dns_option (s_ip6, "debug");
	nm_setting_ip_config_add_dns_option (s_ip6, "timeout:3");

	g_assert (reread);
	g_assert (nm_connection_verify (reread, &error));
	g_assert (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT));

	g_free (testfile);
	g_object_unref (connection);
	g_object_unref (reread);
}

#define TEST_IFCFG_WIFI_OPEN TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wifi-open"

static void
test_read_wifi_open (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	NMSettingWirelessSecurity *s_wsec;
	NMSettingIPConfig *s_ip4, *s_ip6;
	GError *error = NULL;
	const char *tmp;
	GBytes *ssid;
	const char *mac;
	char expected_mac_address[ETH_ALEN] = { 0x00, 0x16, 0x41, 0x11, 0x22, 0x33 };
	const char *expected_id = "System blahblah (test-wifi-open)";
	guint64 expected_timestamp = 0;
	const char *expected_ssid = "blahblah";
	const char *expected_mode = "infrastructure";
	const guint32 expected_channel = 1;

	connection = connection_from_file_test (TEST_IFCFG_WIFI_OPEN,
	                                        NULL,
	                                        TYPE_WIRELESS,
	                                        NULL,
	                                        &error);
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

	g_assert_cmpint (nm_setting_connection_get_autoconnect_priority (s_con), ==, -1);

	/* ===== WIRELESS SETTING ===== */

	s_wireless = nm_connection_get_setting_wireless (connection);
	ASSERT (s_wireless != NULL,
	        "wifi-open-verify-wireless", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_OPEN,
	        NM_SETTING_WIRELESS_SETTING_NAME);

	/* MAC address */
	mac = nm_setting_wireless_get_mac_address (s_wireless);
	ASSERT (mac != NULL,
	        "wifi-open-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_OPEN,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_MAC_ADDRESS);
	ASSERT (nm_utils_hwaddr_matches (mac, -1, expected_mac_address, sizeof (expected_mac_address)),
	        "wifi-open-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_OPEN,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_MAC_ADDRESS);

	ASSERT (nm_setting_wireless_get_mtu (s_wireless) == 0,
	        "wifi-open-verify-wired", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_OPEN,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_MTU);

	ssid = nm_setting_wireless_get_ssid (s_wireless);
	ASSERT (ssid != NULL,
	        "wifi-open-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_OPEN,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_SSID);
	ASSERT (g_bytes_get_size (ssid) == strlen (expected_ssid),
	        "wifi-open-verify-wireless", "failed to verify %s: unexpected %s / %s key value length",
	        TEST_IFCFG_WIFI_OPEN,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_SSID);
	ASSERT (memcmp (g_bytes_get_data (ssid, NULL), expected_ssid, strlen (expected_ssid)) == 0,
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

	g_assert_cmpint (nm_setting_ip_config_get_route_metric (s_ip4), ==, 104);

	/* Method */
	tmp = nm_setting_ip_config_get_method (s_ip4);
	ASSERT (strcmp (tmp, NM_SETTING_IP4_CONFIG_METHOD_AUTO) == 0,
	        "wifi-open-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_OPEN,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP_CONFIG_METHOD);

	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	g_assert( s_ip6);
	g_assert_cmpint (nm_setting_ip_config_get_route_metric (s_ip6), ==, 106);

	g_object_unref (connection);
}

#define TEST_IFCFG_WIFI_OPEN_AUTO TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wifi-open-auto"

static void
test_read_wifi_open_auto (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	GError *error = NULL;
	const char *tmp;
	const char *expected_id = "System blahblah (test-wifi-open-auto)";
	const char *expected_mode = "infrastructure";

	connection = connection_from_file_test (TEST_IFCFG_WIFI_OPEN_AUTO,
	                                        NULL,
	                                        TYPE_WIRELESS,
	                                        NULL,
	                                        &error);
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

	g_object_unref (connection);
}

#define TEST_IFCFG_WIFI_OPEN_SSID_HEX TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wifi-open-ssid-hex"

static void
test_read_wifi_open_ssid_hex (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	GError *error = NULL;
	const char *tmp;
	GBytes *ssid;
	const char *expected_id = "System blahblah (test-wifi-open-ssid-hex)";
	const char *expected_ssid = "blahblah";

	connection = connection_from_file_test (TEST_IFCFG_WIFI_OPEN_SSID_HEX,
	                                        NULL,
	                                        TYPE_WIRELESS,
	                                        NULL,
	                                        &error);
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
	ssid = nm_setting_wireless_get_ssid (s_wireless);
	ASSERT (ssid != NULL,
	        "wifi-open-ssid-hex-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_OPEN_SSID_HEX,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_SSID);
	ASSERT (g_bytes_get_size (ssid) == strlen (expected_ssid),
	        "wifi-open-ssid-hex-verify-wireless", "failed to verify %s: unexpected %s / %s key value length",
	        TEST_IFCFG_WIFI_OPEN_SSID_HEX,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_SSID);
	ASSERT (memcmp (g_bytes_get_data (ssid, NULL), expected_ssid, strlen (expected_ssid)) == 0,
	        "wifi-open-ssid-hex-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_OPEN_SSID_HEX,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_SSID);

	g_object_unref (connection);
}

static void
test_read_wifi_open_ssid_bad (const char *file, const char *test)
{
	NMConnection *connection;
	GError *error = NULL;

	connection = connection_from_file_test (file,
	                                        NULL,
	                                        TYPE_WIRELESS,
	                                        NULL,
	                                        &error);
	ASSERT (connection == NULL, test, "unexpected success reading %s", file);
	g_clear_error (&error);

}

#define TEST_IFCFG_WIFI_OPEN_SSID_QUOTED TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wifi-open-ssid-quoted"

static void
test_read_wifi_open_ssid_quoted (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	GError *error = NULL;
	const char *tmp;
	GBytes *ssid;
	const char *expected_id = "System foo\"bar\\ (test-wifi-open-ssid-quoted)";
	const char *expected_ssid = "foo\"bar\\";

	connection = connection_from_file_test (TEST_IFCFG_WIFI_OPEN_SSID_QUOTED,
	                                        NULL,
	                                        TYPE_WIRELESS,
	                                        NULL,
	                                        &error);
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
	ssid = nm_setting_wireless_get_ssid (s_wireless);
	ASSERT (ssid != NULL,
	        "wifi-open-ssid-quoted-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_OPEN_SSID_QUOTED,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_SSID);
	ASSERT (g_bytes_get_size (ssid) == strlen (expected_ssid),
	        "wifi-open-ssid-quoted-verify-wireless", "failed to verify %s: unexpected %s / %s key value length",
	        TEST_IFCFG_WIFI_OPEN_SSID_QUOTED,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_SSID);
	ASSERT (memcmp (g_bytes_get_data (ssid, NULL), expected_ssid, strlen (expected_ssid)) == 0,
	        "wifi-open-ssid-quoted-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_OPEN_SSID_QUOTED,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_SSID);

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
	NMSettingIPConfig *s_ip4;
	GError *error = NULL;
	const char *tmp;
	GBytes *ssid;
	const char *mac;
	char expected_mac_address[ETH_ALEN] = { 0x00, 0x16, 0x41, 0x11, 0x22, 0x33 };
	const char *expected_id = "System blahblah (test-wifi-wep)";
	guint64 expected_timestamp = 0;
	const char *expected_ssid = "blahblah";
	const char *expected_mode = "infrastructure";
	const guint32 expected_channel = 1;
	const char *expected_wep_key0 = "0123456789abcdef0123456789";
	NMWepKeyType key_type;

	connection = connection_from_file_test (TEST_IFCFG_WIFI_WEP,
	                                        NULL,
	                                        TYPE_WIRELESS,
	                                        NULL,
	                                        &error);
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
	mac = nm_setting_wireless_get_mac_address (s_wireless);
	ASSERT (mac != NULL,
	        "wifi-wep-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WEP,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_MAC_ADDRESS);
	ASSERT (nm_utils_hwaddr_matches (mac, -1, expected_mac_address, sizeof (expected_mac_address)),
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
	ssid = nm_setting_wireless_get_ssid (s_wireless);
	ASSERT (ssid != NULL,
	        "wifi-wep-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WEP,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_SSID);
	ASSERT (g_bytes_get_size (ssid) == strlen (expected_ssid),
	        "wifi-wep-verify-wireless", "failed to verify %s: unexpected %s / %s key value length",
	        TEST_IFCFG_WIFI_WEP,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_SSID);
	ASSERT (memcmp (g_bytes_get_data (ssid, NULL), expected_ssid, strlen (expected_ssid)) == 0,
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
	tmp = nm_setting_ip_config_get_method (s_ip4);
	ASSERT (strcmp (tmp, NM_SETTING_IP4_CONFIG_METHOD_AUTO) == 0,
	        "wifi-wep-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WEP,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP_CONFIG_METHOD);

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
	NMSettingIPConfig *s_ip4;
	GError *error = NULL;
	const char *tmp;
	GBytes *ssid;
	const char *expected_id = "System blahblah (test-wifi-wep-adhoc)";
	const char *expected_ssid = "blahblah";
	const char *expected_mode = "adhoc";
	const char *expected_wep_key0 = "0123456789abcdef0123456789";

	connection = connection_from_file_test (TEST_IFCFG_WIFI_WEP_ADHOC,
	                                        NULL,
	                                        TYPE_WIRELESS,
	                                        NULL,
	                                        &error);
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
	ssid = nm_setting_wireless_get_ssid (s_wireless);
	ASSERT (ssid != NULL,
	        "wifi-wep-adhoc-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WEP_ADHOC,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_SSID);
	ASSERT (g_bytes_get_size (ssid) == strlen (expected_ssid),
	        "wifi-wep-adhoc-verify-wireless", "failed to verify %s: unexpected %s / %s key value length",
	        TEST_IFCFG_WIFI_WEP_ADHOC,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_SSID);
	ASSERT (memcmp (g_bytes_get_data (ssid, NULL), expected_ssid, strlen (expected_ssid)) == 0,
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
	tmp = nm_setting_ip_config_get_method (s_ip4);
	ASSERT (strcmp (tmp, NM_SETTING_IP4_CONFIG_METHOD_AUTO) == 0,
	        "wifi-wep-adhoc-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WEP_ADHOC,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP_CONFIG_METHOD);

	/* Ignore auto DNS */
	ASSERT (nm_setting_ip_config_get_ignore_auto_dns (s_ip4) == TRUE,
	        "wifi-wep-adhoc-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WEP_ADHOC,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP_CONFIG_IGNORE_AUTO_DNS);

	/* DNS Addresses */
	ASSERT (nm_setting_ip_config_get_num_dns (s_ip4) == 2,
	        "wifi-wep-adhoc-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WEP_ADHOC,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP_CONFIG_DNS);

	ASSERT (strcmp (nm_setting_ip_config_get_dns (s_ip4, 0), "4.2.2.1") == 0,
	        "wifi-wep-adhoc-verify-ip4", "failed to verify %s: unexpected %s / %s key value #1",
	        TEST_IFCFG_WIFI_WEP_ADHOC,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP_CONFIG_DNS);

	ASSERT (strcmp (nm_setting_ip_config_get_dns (s_ip4, 1), "4.2.2.2") == 0,
	        "wifi-wep-adhoc-verify-ip4", "failed to verify %s: unexpected %s / %s key value #2",
	        TEST_IFCFG_WIFI_WEP_ADHOC,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP_CONFIG_DNS);

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
	GError *error = NULL;
	const char *tmp;
	const char *expected_wep_key0 = "foobar222blahblah";
	NMWepKeyType key_type;

	connection = connection_from_file_test (TEST_IFCFG_WIFI_WEP_PASSPHRASE,
	                                        NULL,
	                                        TYPE_WIRELESS,
	                                        NULL,
	                                        &error);
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
	GError *error = NULL;
	const char *tmp;
	const char *expected_wep_key0 = "Lorem";
	NMWepKeyType key_type;

	connection = connection_from_file_test (TEST_IFCFG_WIFI_WEP_40_ASCII,
	                                        NULL,
	                                        TYPE_WIRELESS,
	                                        NULL,
	                                        &error);
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
	GError *error = NULL;
	const char *tmp;
	const char *expected_wep_key0 = "LoremIpsumSit";
	NMWepKeyType key_type;

	connection = connection_from_file_test (TEST_IFCFG_WIFI_WEP_104_ASCII,
	                                        NULL,
	                                        TYPE_WIRELESS,
	                                        NULL,
	                                        &error);
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
	GError *error = NULL;
	const char *tmp;
	const char *expected_id = "System blahblah (test-wifi-leap)";
	const char *expected_identity = "Bill Smith";
	const char *expected_password = "foobarblah";

	connection = connection_from_file_test (TEST_IFCFG_WIFI_LEAP,
	                                        NULL,
	                                        TYPE_WIRELESS,
	                                        NULL,
	                                        &error);
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
	GError *error = NULL;
	const char *expected_identity = "Bill Smith";
	gboolean success;

	connection = connection_from_file_test (file,
	                                        NULL,
	                                        TYPE_WIRELESS,
	                                        NULL,
	                                        &error);
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
	NMSettingIPConfig *s_ip4;
	GError *error = NULL;
	const char *tmp;
	GBytes *ssid;
	const char *mac;
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

	connection = connection_from_file_test (TEST_IFCFG_WIFI_WPA_PSK,
	                                        NULL,
	                                        TYPE_WIRELESS,
	                                        NULL,
	                                        &error);
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
	mac = nm_setting_wireless_get_mac_address (s_wireless);
	ASSERT (mac != NULL,
	        "wifi-wpa-psk-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WPA_PSK,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_MAC_ADDRESS);
	ASSERT (nm_utils_hwaddr_matches (mac, -1, expected_mac_address, sizeof (expected_mac_address)),
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
	ssid = nm_setting_wireless_get_ssid (s_wireless);
	ASSERT (ssid != NULL,
	        "wifi-wpa-psk-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WPA_PSK,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_SSID);
	ASSERT (g_bytes_get_size (ssid) == strlen (expected_ssid),
	        "wifi-wpa-psk-verify-wireless", "failed to verify %s: unexpected %s / %s key value length",
	        TEST_IFCFG_WIFI_WPA_PSK,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_SSID);
	ASSERT (memcmp (g_bytes_get_data (ssid, NULL), expected_ssid, strlen (expected_ssid)) == 0,
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
	tmp = nm_setting_ip_config_get_method (s_ip4);
	ASSERT (strcmp (tmp, NM_SETTING_IP4_CONFIG_METHOD_AUTO) == 0,
	        "wifi-wpa-psk-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WPA_PSK,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP_CONFIG_METHOD);

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
	GError *error = NULL;
	const char *tmp;
	const char *expected_id = "System ipsum (test-wifi-wpa-psk-2)";
	const char *expected_psk = "They're really saying I love you. >>`<< \\";

	connection = connection_from_file_test (TEST_IFCFG_WIFI_WPA_PSK_2,
	                                        NULL,
	                                        TYPE_WIRELESS,
	                                        NULL,
	                                        &error);
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
	GError *error = NULL;
	const char *tmp;
	const char *expected_id = "System blahblah (test-wifi-wpa-psk-unquoted)";
	const char *expected_psk = "54336845e2f3f321c4c7";

	connection = connection_from_file_test (TEST_IFCFG_WIFI_WPA_PSK_UNQUOTED,
	                                        NULL,
	                                        TYPE_WIRELESS,
	                                        NULL,
	                                        &error);
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

	g_object_unref (connection);
}

#define TEST_IFCFG_WIFI_WPA_PSK_UNQUOTED2 TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wifi-wpa-psk-unquoted2"

static void
test_read_wifi_wpa_psk_unquoted2 (void)
{
	NMConnection *connection;
	GError *error = NULL;

	/* Ensure a quoted 64-character WPA passphrase will fail since passphrases
	 * must be between 8 and 63 ASCII characters inclusive per the WPA spec.
	 */

	connection = connection_from_file_test (TEST_IFCFG_WIFI_WPA_PSK_UNQUOTED2,
	                                        NULL,
	                                        TYPE_WIRELESS,
	                                        NULL,
	                                        &error);
	ASSERT (connection == NULL,
	        "wifi-wpa-psk-unquoted-read", "unexpected success reading %s", TEST_IFCFG_WIFI_WPA_PSK_UNQUOTED2);
	g_clear_error (&error);

}

#define TEST_IFCFG_WIFI_WPA_PSK_ADHOC TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wifi-wpa-psk-adhoc"

static void
test_read_wifi_wpa_psk_adhoc (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	NMSettingWirelessSecurity *s_wsec;
	NMSettingIPConfig *s_ip4;
	GError *error = NULL;
	const char *tmp;
	const char *expected_id = "System blahblah (test-wifi-wpa-psk-adhoc)";
	const char *expected_mode = "adhoc";
	const char *expected_key_mgmt = "wpa-none";
	const char *expected_psk = "I wonder what the king is doing tonight?";
	const char *expected_group = "ccmp";
	const char *expected_proto = "wpa";

	connection = connection_from_file_test (TEST_IFCFG_WIFI_WPA_PSK_ADHOC,
	                                        NULL,
	                                        TYPE_WIRELESS,
	                                        NULL,
	                                        &error);
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
	tmp = nm_setting_ip_config_get_method (s_ip4);
	ASSERT (strcmp (tmp, NM_SETTING_IP4_CONFIG_METHOD_AUTO) == 0,
	        "wifi-wpa-psk-adhoc-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WPA_PSK_ADHOC,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP_CONFIG_METHOD);

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
	NMSettingIPConfig *s_ip4;
	GError *error = NULL;
	const char *tmp;
	GBytes *ssid;
	const char *expected_id = "System blahblah (test-wifi-wpa-psk-hex)";
	const char *expected_ssid = "blahblah";
	const char *expected_key_mgmt = "wpa-psk";
	const char *expected_psk = "1da190379817bc360dda52e85c388c439a21ea5c7bf819c64e9da051807deae6";

	connection = connection_from_file_test (TEST_IFCFG_WIFI_WPA_PSK_HEX,
	                                        NULL,
	                                        TYPE_WIRELESS,
	                                        NULL,
	                                        &error);
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
	ssid = nm_setting_wireless_get_ssid (s_wireless);
	ASSERT (ssid != NULL,
	        "wifi-wpa-psk-hex-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WPA_PSK_HEX,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_SSID);
	ASSERT (g_bytes_get_size (ssid) == strlen (expected_ssid),
	        "wifi-wpa-psk-hex-verify-wireless", "failed to verify %s: unexpected %s / %s key value length",
	        TEST_IFCFG_WIFI_WPA_PSK_HEX,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_SSID);
	ASSERT (memcmp (g_bytes_get_data (ssid, NULL), expected_ssid, strlen (expected_ssid)) == 0,
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
	tmp = nm_setting_ip_config_get_method (s_ip4);
	ASSERT (strcmp (tmp, NM_SETTING_IP4_CONFIG_METHOD_AUTO) == 0,
	        "wifi-wpa-psk-hex-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WPA_PSK_HEX,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP_CONFIG_METHOD);

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
	NMSettingIPConfig *s_ip4;
	NMSetting8021x *s_8021x;
	char *unmanaged = NULL;
	GError *error = NULL;
	const char *tmp, *password;
	const char *expected_identity = "Bill Smith";
	const char *expected_privkey_password = "test1";

	connection = connection_from_file_test (TEST_IFCFG_WIFI_WPA_EAP_TLS,
	                                        NULL,
	                                        TYPE_ETHERNET,
	                                        &unmanaged,
	                                        &error);
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
	tmp = nm_setting_ip_config_get_method (s_ip4);
	ASSERT (strcmp (tmp, NM_SETTING_IP4_CONFIG_METHOD_AUTO) == 0,
	        "wifi-wpa-eap-tls-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WPA_EAP_TLS,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP_CONFIG_METHOD);

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
	NMSettingIPConfig *s_ip4;
	NMSetting8021x *s_8021x;
	char *unmanaged = NULL;
	GError *error = NULL;
	const char *tmp, *password;
	const char *expected_identity = "Chuck Shumer";
	const char *expected_privkey_password = "test1";

	connection = connection_from_file_test (TEST_IFCFG_WIFI_WPA_EAP_TTLS_TLS,
	                                        NULL,
	                                        TYPE_WIRELESS,
	                                        &unmanaged,
	                                        &error);
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
	tmp = nm_setting_ip_config_get_method (s_ip4);
	ASSERT (strcmp (tmp, NM_SETTING_IP4_CONFIG_METHOD_AUTO) == 0,
	        "wifi-wpa-eap-ttls-tls-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WPA_EAP_TTLS_TLS,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP_CONFIG_METHOD);

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
	gboolean success;
	GError *error = NULL;

	connection = connection_from_file_test (TEST_IFCFG_WIFI_DYNAMIC_WEP_LEAP,
	                                        NULL,
	                                        TYPE_WIRELESS,
	                                        NULL,
	                                        &error);
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
	NMSettingIPConfig *s_ip4;
	NMSetting8021x *s_8021x;
	char *unmanaged = NULL;
	GError *error = NULL;
	const char *tmp;
	const char *expected_password = "foobar baz";
	const char *expected_identity = "David Smith";
	const char *expected_key_mgmt = "ieee8021x";

	connection = connection_from_file_test (TEST_IFCFG_WIFI_WEP_EAP_TTLS_CHAP,
	                                        NULL,
	                                        TYPE_WIRELESS,
	                                        &unmanaged,
	                                        &error);
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
	tmp = nm_setting_ip_config_get_method (s_ip4);
	ASSERT (strcmp (tmp, NM_SETTING_IP4_CONFIG_METHOD_AUTO) == 0,
	        "wifi-wep-eap-ttls-chap-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WEP_EAP_TTLS_CHAP,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP_CONFIG_METHOD);

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

	connection = connection_from_file_test (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wifi-hidden",
	                                        NULL, TYPE_WIRELESS, NULL, &error);
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
	GBytes *ssid;
	const unsigned char ssid_data[] = { 0x54, 0x65, 0x73, 0x74, 0x20, 0x53, 0x53, 0x49, 0x44 };

	connection = nm_simple_connection_new ();

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

	ssid = g_bytes_new (ssid_data, sizeof (ssid_data));

	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_MODE, "infrastructure",
	              NM_SETTING_WIRELESS_HIDDEN, TRUE,
	              NULL);

	g_bytes_unref (ssid);

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
	nm_connection_normalize (connection, NULL, NULL, NULL);

	/* re-read the connection for comparison */
	reread = connection_from_file_test (testfile, NULL, TYPE_WIRELESS,
	                                    NULL, &error);
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
test_read_wifi_band_a (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wifi;
	gboolean success;
	GError *error = NULL;

	connection = connection_from_file_test (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wifi-band-a",
	                                        NULL, TYPE_WIRELESS, NULL, &error);
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
	g_assert_cmpstr (nm_setting_wireless_get_band (s_wifi), ==, "a");

	g_object_unref (connection);
}

static void
test_write_wifi_band_a (void)
{
	NMConnection *connection, *reread;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wifi;
	char *uuid, *testfile = NULL, *val;
	gboolean success;
	GError *error = NULL;
	shvarFile *f;
	GBytes *ssid;
	const unsigned char ssid_data[] = { 0x54, 0x65, 0x73, 0x74, 0x20, 0x53, 0x53, 0x49, 0x44 };

	connection = nm_simple_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write WiFi Band A",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRELESS_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* Wifi setting */
	s_wifi = (NMSettingWireless *) nm_setting_wireless_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wifi));

	ssid = g_bytes_new (ssid_data, sizeof (ssid_data));

	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_MODE, "infrastructure",
	              NM_SETTING_WIRELESS_BAND, "a",
	              NULL);

	g_bytes_unref (ssid);

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
	val = svGetValue (f, "BAND", FALSE);
	g_assert (val);
	g_assert_cmpstr (val, ==, "a");
	g_free (val);
	svCloseFile (f);

	/* reread will be normalized, so we must normalize connection too. */
	nm_connection_normalize (connection, NULL, NULL, NULL);

	/* re-read the connection for comparison */
	reread = connection_from_file_test (testfile, NULL, TYPE_WIRELESS,
	                                    NULL, &error);
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
test_read_wifi_band_a_channel_mismatch (void)
{
	NMConnection *connection;
	GError *error = NULL;

	connection = connection_from_file_test (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wifi-band-a-channel-mismatch",
	                                        NULL, TYPE_WIRELESS, NULL, &error);
	g_assert (connection == NULL);
	g_assert_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION);
	g_clear_error (&error);
}

static void
test_read_wifi_band_bg_channel_mismatch (void)
{
	NMConnection *connection;
	GError *error = NULL;

	connection = connection_from_file_test (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wifi-band-bg-channel-mismatch",
	                                        NULL, TYPE_WIRELESS, NULL, &error);
	g_assert (connection == NULL);
	g_assert_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION);
	g_clear_error (&error);
}

#define TEST_IFCFG_WIRED_QETH_STATIC TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-qeth-static"

static void
test_read_wired_qeth_static (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIPConfig *s_ip4;
	char *unmanaged = NULL;
	GError *error = NULL;
	const char *tmp;
	const char *expected_id = "System test-wired-qeth-static";
	const char *mac;
	const char *expected_channel0 = "0.0.0600";
	const char *expected_channel1 = "0.0.0601";
	const char *expected_channel2 = "0.0.0602";
	const char * const *subchannels;

	connection = connection_from_file_test (TEST_IFCFG_WIRED_QETH_STATIC,
	                                        NULL,
	                                        TYPE_ETHERNET,
	                                        &unmanaged,
	                                        &error);
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
	mac = nm_setting_wired_get_mac_address (s_wired);
	ASSERT (mac == NULL,
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
	ASSERT (subchannels[0] && subchannels[1] && subchannels[2] && !subchannels[3],
	        "wired-qeth-static-verify-wired", "failed to verify %s: invalid %s / %s key (not 3 elements)",
	        TEST_IFCFG_WIRED_QETH_STATIC,
	        NM_SETTING_WIRED_SETTING_NAME,
	        NM_SETTING_WIRED_S390_SUBCHANNELS);

	ASSERT (strcmp (subchannels[0], expected_channel0) == 0,
	        "wired-qeth-static-verify-wired", "failed to verify %s: unexpected subchannel #0",
	        TEST_IFCFG_WIRED_QETH_STATIC);
	ASSERT (strcmp (subchannels[1], expected_channel1) == 0,
	        "wired-qeth-static-verify-wired", "failed to verify %s: unexpected subchannel #1",
	        TEST_IFCFG_WIRED_QETH_STATIC);
	ASSERT (strcmp (subchannels[2], expected_channel2) == 0,
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
	tmp = nm_setting_ip_config_get_method (s_ip4);
	ASSERT (strcmp (tmp, NM_SETTING_IP4_CONFIG_METHOD_MANUAL) == 0,
	        "wired-qeth-static-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_QETH_STATIC,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP_CONFIG_METHOD);

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
	GError *error = NULL;
	const char *tmp;
	const char *expected_id = "System test-wired-ctc-static";
	const char *expected_channel0 = "0.0.1b00";
	const char *expected_channel1 = "0.0.1b01";
	const char * const *subchannels;
	gboolean success;

	connection = connection_from_file_test (TEST_IFCFG_WIRED_CTC_STATIC,
	                                        NULL,
	                                        TYPE_ETHERNET,
	                                        &unmanaged,
	                                        &error);
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
	g_assert (subchannels[0] && subchannels[1] && !subchannels[2]);

	g_assert_cmpstr (subchannels[0], ==, expected_channel0);
	g_assert_cmpstr (subchannels[1], ==, expected_channel1);

	/* Nettype */
	g_assert_cmpstr (nm_setting_wired_get_s390_nettype (s_wired), ==, "ctc");

	/* port name */
	tmp = nm_setting_wired_get_s390_option_by_key (s_wired, "ctcprot");
	g_assert (tmp != NULL);
	g_assert_cmpstr (tmp, ==, "0");

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
	GError *error = NULL;
	const char *tmp;
	const char *expected_id = "System foobar (test-wifi-wep-no-keys)";
	NMWepKeyType key_type;

	connection = connection_from_file_test (TEST_IFCFG_WIFI_WEP_NO_KEYS,
	                                        NULL,
	                                        TYPE_WIRELESS,
	                                        NULL,
	                                        &error);
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

	g_object_unref (connection);
}

#define TEST_IFCFG_PERMISSIONS TEST_IFCFG_DIR"/network-scripts/ifcfg-test-permissions"

static void
test_read_permissions (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	gboolean success;
	GError *error = NULL;
	guint32 num;
	const char *tmp;

	connection = connection_from_file_test (TEST_IFCFG_PERMISSIONS,
	                                        NULL,
	                                        TYPE_ETHERNET,
	                                        NULL,
	                                        &error);
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

	g_object_unref (connection);
}

#define TEST_IFCFG_WIFI_WEP_AGENT_KEYS TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wifi-wep-agent-keys"

static void
test_read_wifi_wep_agent_keys (void)
{
	NMConnection *connection;
	NMSettingWireless *s_wifi;
	NMSettingWirelessSecurity *s_wsec;
	GError *error = NULL;
	NMWepKeyType key_type;
	gboolean success;
	NMSettingSecretFlags flags;

	connection = connection_from_file_test (TEST_IFCFG_WIFI_WEP_AGENT_KEYS,
	                                        NULL,
	                                        TYPE_WIRELESS,
	                                        NULL,
	                                        &error);
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

	g_object_unref (connection);
}

static void
test_write_wired_static (void)
{
	NMConnection *connection;
	NMConnection *reread;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIPConfig *s_ip4, *reread_s_ip4;
	NMSettingIPConfig *s_ip6, *reread_s_ip6;
	static const char *mac = "31:33:33:37:be:cd";
	guint32 mtu = 1492;
	char *uuid;
	const char *dns1 = "4.2.2.1";
	const char *dns2 = "4.2.2.2";
	const char *dns_search1 = "foobar.com";
	const char *dns_search2 = "lab.foobar.com";
	const char *dns_search3 = "foobar6.com";
	const char *dns_search4 = "lab6.foobar.com";
	const char *dns6_1 = "fade:0102:0103::face";
	const char *dns6_2 = "cafe:ffff:eeee:dddd:cccc:bbbb:aaaa:feed";
	NMIPAddress *addr;
	NMIPAddress *addr6;
	NMIPRoute *route6;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	char *route6file = NULL;

	connection = nm_simple_connection_new ();

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

	g_object_set (s_wired,
	              NM_SETTING_WIRED_MAC_ADDRESS, mac,
	              NM_SETTING_WIRED_MTU, mtu,
	              NULL);

	/* IP4 setting */
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_MANUAL,
	              NM_SETTING_IP_CONFIG_MAY_FAIL, TRUE,
	              NM_SETTING_IP_CONFIG_GATEWAY, "1.1.1.1",
	              NM_SETTING_IP_CONFIG_ROUTE_METRIC, (gint64) 204,
	              NULL);

	addr = nm_ip_address_new (AF_INET, "1.1.1.3", 24, &error);
	g_assert_no_error (error);
	nm_setting_ip_config_add_address (s_ip4, addr);
	nm_ip_address_unref (addr);

	addr = nm_ip_address_new (AF_INET, "1.1.1.5", 24, &error);
	g_assert_no_error (error);
	nm_setting_ip_config_add_address (s_ip4, addr);
	nm_ip_address_unref (addr);

	nm_setting_ip_config_add_dns (s_ip4, dns1);
	nm_setting_ip_config_add_dns (s_ip4, dns2);

	nm_setting_ip_config_add_dns_search (s_ip4, dns_search1);
	nm_setting_ip_config_add_dns_search (s_ip4, dns_search2);

	/* IP6 setting */
	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_MANUAL,
	              NM_SETTING_IP_CONFIG_MAY_FAIL, TRUE,
	              NM_SETTING_IP_CONFIG_ROUTE_METRIC, (gint64) 206,
	              NULL);

	/* Add addresses */
	addr6 = nm_ip_address_new (AF_INET6, "1003:1234:abcd::1", 11, &error);
	g_assert_no_error (error);
	nm_setting_ip_config_add_address (s_ip6, addr6);
	nm_ip_address_unref (addr6);

	addr6 = nm_ip_address_new (AF_INET6, "2003:1234:abcd::2", 22, &error);
	g_assert_no_error (error);
	nm_setting_ip_config_add_address (s_ip6, addr6);
	nm_ip_address_unref (addr6);

	addr6 = nm_ip_address_new (AF_INET6, "3003:1234:abcd::3", 33, &error);
	g_assert_no_error (error);
	nm_setting_ip_config_add_address (s_ip6, addr6);
	nm_ip_address_unref (addr6);

	/* Add routes */
	route6 = nm_ip_route_new (AF_INET6,
	                          "2222:aaaa:bbbb:cccc::", 64,
	                          "2222:aaaa:bbbb:cccc:dddd:eeee:5555:6666", 99, &error);
	g_assert_no_error (error);
	nm_setting_ip_config_add_route (s_ip6, route6);
	nm_ip_route_unref (route6);

	route6 = nm_ip_route_new (AF_INET6, "::", 128, "2222:aaaa::9999", 1, &error);
	g_assert_no_error (error);
	nm_setting_ip_config_add_route (s_ip6, route6);
	nm_ip_route_unref (route6);

	/* DNS servers */
	nm_setting_ip_config_add_dns (s_ip6, dns6_1);
	nm_setting_ip_config_add_dns (s_ip6, dns6_2);

	/* DNS domains */
	nm_setting_ip_config_add_dns_search (s_ip6, dns_search3);
	nm_setting_ip_config_add_dns_search (s_ip6, dns_search4);

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
	nm_connection_normalize (connection, NULL, NULL, NULL);

	/* re-read the connection for comparison */
	reread = connection_from_file_test (testfile,
	                                    NULL,
	                                    TYPE_ETHERNET,
	                                    NULL,
	                                    &error);
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
	nm_setting_ip_config_add_dns_search (reread_s_ip6, nm_setting_ip_config_get_dns_search (reread_s_ip4, 2));
	nm_setting_ip_config_add_dns_search (reread_s_ip6, nm_setting_ip_config_get_dns_search (reread_s_ip4, 3));
	nm_setting_ip_config_remove_dns_search (reread_s_ip4, 3);
	nm_setting_ip_config_remove_dns_search (reread_s_ip4, 2);

	g_assert_cmpint (nm_setting_ip_config_get_route_metric (reread_s_ip4), ==, 204);
	g_assert_cmpint (nm_setting_ip_config_get_route_metric (reread_s_ip6), ==, 206);

	ASSERT (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "wired-static-write", "written and re-read connection weren't the same.");

	route6file = utils_get_route6_path (testfile);
	unlink (route6file);

	g_free (testfile);
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
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	char *uuid;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;

	connection = nm_simple_connection_new ();

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
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
	              NM_SETTING_IP4_CONFIG_DHCP_CLIENT_ID, "random-client-id-00:22:33",
	              NM_SETTING_IP_CONFIG_DHCP_HOSTNAME, "awesome-hostname",
	              NM_SETTING_IP_CONFIG_IGNORE_AUTO_ROUTES, TRUE,
	              NM_SETTING_IP_CONFIG_IGNORE_AUTO_DNS, TRUE,
	              NULL);

	ASSERT (nm_connection_verify (connection, &error) == TRUE,
	        "wired-dhcp-write", "failed to verify connection: %s",
	        (error && error->message) ? error->message : "(unknown)");

	/* IP6 setting */
	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NM_SETTING_IP_CONFIG_MAY_FAIL, TRUE,
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
	nm_connection_normalize (connection, NULL, NULL, NULL);

	/* re-read the connection for comparison */
	reread = connection_from_file_test (testfile,
	                                    NULL,
	                                    TYPE_ETHERNET,
	                                    NULL,
	                                    &error);
	unlink (testfile);

	ASSERT (reread != NULL,
	        "wired-dhcp-write-reread", "failed to read %s: %s", testfile, error->message);

	ASSERT (nm_connection_verify (reread, &error),
	        "wired-dhcp-write-reread-verify", "failed to verify %s: %s", testfile, error->message);

	ASSERT (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "wired-dhcp-write", "written and re-read connection weren't the same.");

	g_free (testfile);
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

	connection = connection_from_file_test (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-dhcp-plus-ip",
	                                        NULL, TYPE_ETHERNET, NULL,
	                                        &error);
	g_assert_no_error (error);
	g_assert (connection != NULL);

	success = writer_new_connection (connection,
	                                 TEST_SCRATCH_DIR "/network-scripts/",
	                                 &written,
	                                 &error);
	g_assert (success);

	/* reread will be normalized, so we must normalize connection too. */
	nm_connection_normalize (connection, NULL, NULL, NULL);

	/* re-read the connection for comparison */
	reread = connection_from_file_test (written, NULL, TYPE_ETHERNET, NULL,
	                                    &error);
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
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	const char * dhcp_hostname = "kamil-patka";
	char *written = NULL;
	GError *error = NULL;
	gboolean success = FALSE;

	connection = connection_from_file_test (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-dhcp-send-hostname",
	                                        NULL, TYPE_ETHERNET, NULL,
	                                        &error);
	g_assert_no_error (error);
	g_assert (connection != NULL);

	/* Check dhcp-hostname and dhcp-send-hostname */
	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	g_assert (s_ip4);
	g_assert (s_ip6);
	g_assert (nm_setting_ip_config_get_dhcp_send_hostname (s_ip4) == TRUE);
	g_assert_cmpstr (nm_setting_ip_config_get_dhcp_hostname (s_ip4), ==, "svata-pulec");
	g_assert_cmpstr (nm_setting_ip_config_get_dhcp_hostname (s_ip6), ==, "svata-pulec");

	/* Set dhcp-send-hostname=false dhcp-hostname="kamil-patka" and write the connection. */
	g_object_set (s_ip4, NM_SETTING_IP_CONFIG_DHCP_SEND_HOSTNAME, FALSE, NULL);
	g_object_set (s_ip4, NM_SETTING_IP_CONFIG_DHCP_HOSTNAME, dhcp_hostname, NULL);
	g_object_set (s_ip6, NM_SETTING_IP_CONFIG_DHCP_HOSTNAME, dhcp_hostname, NULL);

	success = writer_new_connection (connection,
	                                 TEST_SCRATCH_DIR "/network-scripts/",
	                                 &written,
	                                 &error);
	g_assert (success);

	/* reread will be normalized, so we must normalize connection too. */
	nm_connection_normalize (connection, NULL, NULL, NULL);

	/* re-read the connection for comparison */
	reread = connection_from_file_test (written, NULL, TYPE_ETHERNET, NULL,
	                                    &error);
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
	g_assert (nm_setting_ip_config_get_dhcp_send_hostname (s_ip4) == FALSE);
	g_assert_cmpstr (nm_setting_ip_config_get_dhcp_hostname (s_ip4), ==, dhcp_hostname);
	g_assert_cmpstr (nm_setting_ip_config_get_dhcp_hostname (s_ip6), ==, dhcp_hostname);

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
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	static const char *mac = "31:33:33:37:be:cd";
	char *uuid;
	const char *dns6 = "fade:0102:0103::face";
	NMIPAddress *addr6;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;

	connection = nm_simple_connection_new ();

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

	g_object_set (s_wired, NM_SETTING_WIRED_MAC_ADDRESS, mac, NULL);

	/* IP4 setting */
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_DISABLED,
	              NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_MANUAL,
	              NULL);

	/* Add addresses */
	addr6 = nm_ip_address_new (AF_INET6, "1003:1234:abcd::1", 11, &error);
	g_assert_no_error (error);
	nm_setting_ip_config_add_address (s_ip6, addr6);
	nm_ip_address_unref (addr6);

	/* DNS server */
	nm_setting_ip_config_add_dns (s_ip6, dns6);

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
	nm_connection_normalize (connection, NULL, NULL, NULL);

	/* re-read the connection for comparison */
	reread = connection_from_file_test (testfile,
	                                    NULL,
	                                    TYPE_ETHERNET,
	                                    NULL,
	                                    &error);
	unlink (testfile);

	ASSERT (reread != NULL,
	        "wired-static-ip6-only-write-reread", "failed to read %s: %s", testfile, error->message);

	ASSERT (nm_connection_verify (reread, &error),
	        "wired-static-ip6-only-write-reread-verify", "failed to verify %s: %s", testfile, error->message);

	ASSERT (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "wired-static-ip6-only-write", "written and re-read connection weren't the same.");

	g_free (testfile);
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
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	static const char *mac = "31:33:33:37:be:cd";
	char *uuid;
	const char *dns6 = "fade:0102:0103::face";
	NMIPAddress *addr6;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	char *id = NULL;
	char *written_ifcfg_gateway;
	const char *gateway6 = user_data;

	connection = nm_simple_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	id = g_strdup_printf ("Test Write Wired Static IP6 Only With Gateway %s", gateway6 ? gateway6 : "NULL");
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

	g_object_set (s_wired, NM_SETTING_WIRED_MAC_ADDRESS, mac, NULL);

	/* IP4 setting */
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_DISABLED,
	              NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_MANUAL,
	              NM_SETTING_IP_CONFIG_GATEWAY, gateway6,
	              NULL);

	/* Add addresses */
	addr6 = nm_ip_address_new (AF_INET6, "1003:1234:abcd::1", 11, &error);
	g_assert_no_error (error);
	nm_setting_ip_config_add_address (s_ip6, addr6);
	nm_ip_address_unref (addr6);

	/* DNS server */
	nm_setting_ip_config_add_dns (s_ip6, dns6);

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
	nm_connection_normalize (connection, NULL, NULL, NULL);

	/* re-read the connection for comparison */
	reread = connection_from_file_test (testfile,
	                                    NULL,
	                                    TYPE_ETHERNET,
	                                    NULL,
	                                    &error);
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
	g_assert (s_ip6 && nm_setting_ip_config_get_num_addresses (s_ip6)==1);
	addr6 = nm_setting_ip_config_get_address (s_ip6, 0);
	g_assert (addr6);

	/* assert that the gateway was written and reloaded as expected */
	if (!gateway6 || !strcmp (gateway6, "::")) {
		g_assert (nm_setting_ip_config_get_gateway (s_ip6) == NULL);
		g_assert (written_ifcfg_gateway == NULL);
	} else {
		g_assert (nm_setting_ip_config_get_gateway (s_ip6) != NULL);
		g_assert_cmpstr (nm_setting_ip_config_get_gateway (s_ip6), ==, gateway6);
		g_assert_cmpstr (written_ifcfg_gateway, ==, gateway6);
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
	NMSettingIPConfig *s_ip4;
	char *testfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean success;
	GError *error = NULL;
	const char *tmp;

	connection = connection_from_file_test (TEST_IFCFG_READ_WRITE_STATIC_ROUTES_LEGACY,
	                                        NULL,
	                                        TYPE_ETHERNET,
	                                        NULL,
	                                        &error);
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
	tmp = nm_setting_ip_config_get_method (s_ip4);
	ASSERT (strcmp (tmp, NM_SETTING_IP4_CONFIG_METHOD_AUTO) == 0,
	        "read-write-static-routes-legacy-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_READ_WRITE_STATIC_ROUTES_LEGACY,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP_CONFIG_METHOD);

	ASSERT (nm_setting_ip_config_get_never_default (s_ip4) == FALSE,
	        "read-write-static-routes-legacy-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_READ_WRITE_STATIC_ROUTES_LEGACY,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP_CONFIG_NEVER_DEFAULT);

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
	nm_connection_normalize (connection, NULL, NULL, NULL);

	/* re-read the connection for comparison */
	reread = connection_from_file_test (testfile,
	                                    NULL,
	                                    TYPE_ETHERNET,
	                                    NULL,
	                                    &error);
	unlink (testfile);
	routefile = utils_get_route_path (testfile);
	unlink (routefile);
	route6file = utils_get_route6_path (testfile);
	unlink (route6file);

	ASSERT (reread != NULL,
	        "read-write-static-routes-legacy-reread", "failed to read %s: %s", testfile, error->message);

	ASSERT (nm_connection_verify (reread, &error),
	        "read-write-static-routes-legacy-reread-verify", "failed to verify %s: %s", testfile, error->message);

	ASSERT (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "read-write-static-routes-legacy-write", "written and re-read connection weren't the same.");

	g_free (testfile);
	g_free (routefile);
	g_free (route6file);
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
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	static const char *mac = "31:33:33:37:be:cd";
	guint32 mtu = 1492;
	char *uuid;
	const char *dns1 = "4.2.2.1";
	const char *dns2 = "4.2.2.2";
	const char *dns_search1 = "foobar.com";
	const char *dns_search2 = "lab.foobar.com";
	NMIPAddress *addr;
	NMIPRoute *route;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	char *routefile = NULL;

	connection = nm_simple_connection_new ();

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

	g_object_set (s_wired,
	              NM_SETTING_WIRED_MAC_ADDRESS, mac,
	              NM_SETTING_WIRED_MTU, mtu,
	              NULL);

	/* IP4 setting */
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_MANUAL,
	              NM_SETTING_IP_CONFIG_GATEWAY, "1.1.1.1",
	              NULL);

	addr = nm_ip_address_new (AF_INET, "1.1.1.3", 24, &error);
	g_assert_no_error (error);
	nm_setting_ip_config_add_address (s_ip4, addr);
	nm_ip_address_unref (addr);

	addr = nm_ip_address_new (AF_INET, "1.1.1.5", 24, &error);
	g_assert_no_error (error);
	nm_setting_ip_config_add_address (s_ip4, addr);
	nm_ip_address_unref (addr);

	/* Write out routes */
	route = nm_ip_route_new (AF_INET, "1.2.3.0", 24, "222.173.190.239", 0, &error);
	g_assert_no_error (error);
	nm_setting_ip_config_add_route (s_ip4, route);
	nm_ip_route_unref (route);

	route = nm_ip_route_new (AF_INET, "3.2.1.0", 24, "202.254.186.190", 77, &error);
	g_assert_no_error (error);
	nm_setting_ip_config_add_route (s_ip4, route);
	nm_ip_route_unref (route);

	nm_setting_ip_config_add_dns (s_ip4, dns1);
	nm_setting_ip_config_add_dns (s_ip4, dns2);

	nm_setting_ip_config_add_dns_search (s_ip4, dns_search1);
	nm_setting_ip_config_add_dns_search (s_ip4, dns_search2);

	/* IP6 setting */
	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NM_SETTING_IP_CONFIG_MAY_FAIL, TRUE,
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
	nm_connection_normalize (connection, NULL, NULL, NULL);

	/* re-read the connection for comparison */
	reread = connection_from_file_test (testfile,
	                                    NULL,
	                                    TYPE_ETHERNET,
	                                    NULL,
	                                    &error);
	unlink (testfile);

	ASSERT (reread != NULL,
	        "wired-static-routes-write-reread", "failed to read %s: %s", testfile, error->message);

	routefile = utils_get_route_path (testfile);
	unlink (routefile);

	ASSERT (nm_connection_verify (reread, &error),
	        "wired-static-routes-write-reread-verify", "failed to verify %s: %s", testfile, error->message);

	ASSERT (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "wired-static-routes-write", "written and re-read connection weren't the same.");

	g_free (testfile);
	g_free (routefile);
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
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	NMSetting8021x *s_8021x;
	char *uuid;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	char *keyfile = NULL;

	connection = nm_simple_connection_new ();

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
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4, NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NM_SETTING_IP_CONFIG_MAY_FAIL, TRUE,
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
	nm_connection_normalize (connection, NULL, NULL, NULL);

	/* re-read the connection for comparison */
	reread = connection_from_file_test (testfile,
	                                    NULL,
	                                    TYPE_ETHERNET,
	                                    NULL,
	                                    &error);
	unlink (testfile);

	ASSERT (reread != NULL,
	        "wired-dhcp-8021x-peap-mschapv2write-reread", "failed to read %s: %s", testfile, error->message);

	keyfile = utils_get_keys_path (testfile);
	unlink (keyfile);

	ASSERT (nm_connection_verify (reread, &error),
	        "wired-dhcp-8021x-peap-mschapv2write-reread-verify", "failed to verify %s: %s", testfile, error->message);

	ASSERT (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "wired-dhcp-8021x-peap-mschapv2write", "written and re-read connection weren't the same.");

	g_free (testfile);
	g_free (keyfile);
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
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	NMSetting8021x *s_8021x;
	char *uuid;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	char *keyfile = NULL;
	NMSetting8021xCKFormat format = NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;
	const char *pw;
	char *tmp;

	connection = nm_simple_connection_new ();
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
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	g_assert (s_ip4);
	g_object_set (s_ip4, NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	/* IP6 setting */
	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	g_assert (s_ip6);
	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NM_SETTING_IP_CONFIG_MAY_FAIL, TRUE,
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
	nm_connection_normalize (connection, NULL, NULL, NULL);

	/* re-read the connection for comparison */
	reread = connection_from_file_test (testfile,
	                                    NULL,
	                                    TYPE_WIRELESS,
	                                    NULL,
	                                    &error);
	unlink (testfile);
	keyfile = utils_get_keys_path (testfile);
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
	g_free (keyfile);
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
	NMSettingIPConfig *s_ip4;
	char *uuid;
	int num_addresses = 4;
	const char *ip[] = { "1.1.1.1", "1.1.1.2", "1.1.1.3", "1.1.1.4" };
	const char *label[] = { NULL, "alias0:2", NULL, "alias0:3" };
	NMIPAddress *addr;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	shvarFile *ifcfg;
	int i, j;

	connection = nm_simple_connection_new ();
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
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	ASSERT (s_ip4 != NULL,
	        "wired-aliases-write", "failed to allocate new %s setting",
	        NM_SETTING_IP4_CONFIG_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_MANUAL,
	              NM_SETTING_IP_CONFIG_GATEWAY, "1.1.1.1",
	              NM_SETTING_IP_CONFIG_MAY_FAIL, TRUE,
	              NULL);

	for (i = 0; i < num_addresses; i++) {
		addr = nm_ip_address_new (AF_INET, ip[i], 24, &error);
		g_assert_no_error (error);
		if (label[i])
			nm_ip_address_set_attribute (addr, "label", g_variant_new_string (label[i]));
		nm_setting_ip_config_add_address (s_ip4, addr);
		nm_ip_address_unref (addr);
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
	reread = connection_from_file_test (testfile,
	                                    NULL,
	                                    TYPE_ETHERNET,
	                                    NULL,
	                                    &error);
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
	ASSERT (nm_setting_ip_config_get_num_addresses (s_ip4) == num_addresses,
	        "wired-aliases-write-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        testfile,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP_CONFIG_ADDRESSES);

	/* Addresses */
	for (i = 0; i < num_addresses; i++) {
		const char *addrstr;

		addr = nm_setting_ip_config_get_address (s_ip4, i);
		g_assert (addr != NULL);

		addrstr = nm_ip_address_get_address (addr);
		for (j = 0; j < num_addresses; j++) {
			if (!g_strcmp0 (addrstr, ip[j]))
				break;
		}
		g_assert (j < num_addresses);

		g_assert_cmpint (nm_ip_address_get_prefix (addr), ==, 24);
		if (label[j])
			g_assert_cmpstr (g_variant_get_string (nm_ip_address_get_attribute (addr, "label"), NULL), ==, label[j]);
		else
			g_assert (nm_ip_address_get_attribute (addr, "label") == NULL);

		ip[j] = NULL;
	}

	for (i = 0; i < num_addresses; i++) {
		ASSERT (ip[i] == 0,
		        "wired-aliases-write-verify-ip4", "failed to verify %s: did not find IP4 address 0x%08x",
		        testfile,
		        ip[i]);
	}

	/* Gateway */
	g_assert_cmpstr (nm_setting_ip_config_get_gateway (s_ip4), ==, "1.1.1.1");

	g_free (testfile);
	g_object_unref (connection);
	g_object_unref (reread);
}

static void
test_write_gateway (void)
{
	NMConnection *connection, *reread;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIPConfig *s_ip4;
	char *uuid, *testfile = NULL, *val;
	gboolean success;
	GError *error = NULL;
	shvarFile *f;
	NMIPAddress *addr;

	connection = nm_simple_connection_new ();

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
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_MANUAL,
	              NM_SETTING_IP_CONFIG_GATEWAY, "1.1.1.254",
	              NM_SETTING_IP_CONFIG_MAY_FAIL, TRUE,
	              NULL);

	addr = nm_ip_address_new (AF_INET, "1.1.1.3", 24, &error);
	g_assert_no_error (error);
	nm_setting_ip_config_add_address (s_ip4, addr);
	nm_ip_address_unref (addr);

	addr = nm_ip_address_new (AF_INET, "2.2.2.5", 24, &error);
	g_assert_no_error (error);
	nm_setting_ip_config_add_address (s_ip4, addr);
	nm_ip_address_unref (addr);

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
	g_assert_cmpstr (val, ==, "1.1.1.3");
	g_free (val);

	val = svGetValue (f, "IPADDR1", FALSE);
	g_assert (val);
	g_assert_cmpstr (val, ==, "2.2.2.5");
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
	g_assert_cmpstr (val, ==, "1.1.1.254");
	g_free (val);

	val = svGetValue (f, "GATEWAY0", FALSE);
	g_assert (val == NULL);

	val = svGetValue (f, "GATEWAY1", FALSE);
	g_assert (val == NULL);

	svCloseFile (f);

	/* reread will be normalized, so we must normalize connection too. */
	nm_connection_normalize (connection, NULL, NULL, NULL);

	/* re-read the connection for comparison */
	reread = connection_from_file_test (testfile, NULL, TYPE_WIRELESS,
	                                    NULL, &error);
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
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	char *uuid;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	GBytes *ssid;
	const unsigned char ssid_data[] = { 0x54, 0x65, 0x73, 0x74, 0x20, 0x53, 0x53, 0x49, 0x44 };
	const char *bssid = "11:22:33:44:55:66";
	guint32 channel = 9, mtu = 1345;
	const char *mac = "aa:bb:cc:dd:ee:ff";
	shvarFile *ifcfg;
	char *tmp;

	connection = nm_simple_connection_new ();

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

	ssid = g_bytes_new (ssid_data, sizeof (ssid_data));

	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_BSSID, bssid,
	              NM_SETTING_WIRELESS_MAC_ADDRESS, mac,
	              NM_SETTING_WIRELESS_MODE, "infrastructure",
	              NM_SETTING_WIRELESS_BAND, "bg",
	              NM_SETTING_WIRELESS_CHANNEL, channel,
	              NM_SETTING_WIRELESS_MTU, mtu,
	              NULL);

	g_bytes_unref (ssid);

	/* IP4 setting */
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4, NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NM_SETTING_IP_CONFIG_MAY_FAIL, TRUE,
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
	nm_connection_normalize (connection, NULL, NULL, NULL);

	/* re-read the connection for comparison */
	reread = connection_from_file_test (testfile,
	                                    NULL,
	                                    TYPE_WIRELESS,
	                                    NULL,
	                                    &error);
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
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	char *uuid;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	GBytes *ssid;
	const unsigned char ssid_data[] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd };

	connection = nm_simple_connection_new ();

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

	ssid = g_bytes_new (ssid_data, sizeof (ssid_data));

	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_MODE, "infrastructure",
	              NULL);

	g_bytes_unref (ssid);

	/* IP4 setting */
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4, NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NM_SETTING_IP_CONFIG_MAY_FAIL, TRUE,
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
	nm_connection_normalize (connection, NULL, NULL, NULL);

	/* re-read the connection for comparison */
	reread = connection_from_file_test (testfile,
	                                    NULL,
	                                    TYPE_WIRELESS,
	                                    NULL,
	                                    &error);
	unlink (testfile);

	ASSERT (reread != NULL,
	        "wifi-open-hex-ssid-write-reread", "failed to read %s: %s", testfile, error->message);

	ASSERT (nm_connection_verify (reread, &error),
	        "wifi-open-hex-ssid-write-reread-verify", "failed to verify %s: %s", testfile, error->message);

	ASSERT (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "wifi-open-hex-ssid-write", "written and re-read connection weren't the same.");

	g_free (testfile);
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
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	char *uuid;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	char *keyfile = NULL;
	GBytes *ssid;
	const char *ssid_data = "blahblah";
	struct stat statbuf;

	connection = nm_simple_connection_new ();

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

	ssid = g_bytes_new (ssid_data, strlen (ssid_data));

	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_MODE, "infrastructure",
	              NULL);

	g_bytes_unref (ssid);

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
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4, NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NM_SETTING_IP_CONFIG_MAY_FAIL, TRUE,
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
	nm_connection_normalize (connection, NULL, NULL, NULL);

	/* re-read the connection for comparison */
	reread = connection_from_file_test (testfile,
	                                    NULL,
	                                    TYPE_WIRELESS,
	                                    NULL,
	                                    &error);
	unlink (testfile);

	keyfile = utils_get_keys_path (testfile);
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
	g_free (keyfile);
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
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	char *uuid;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	char *keyfile = NULL;
	GBytes *ssid;
	const char *ssid_data = "blahblah";
	struct stat statbuf;
	NMIPAddress *addr;
	const char *dns1 = "4.2.2.1";

	connection = nm_simple_connection_new ();

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

	ssid = g_bytes_new (ssid_data, strlen (ssid_data));

	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_MODE, "adhoc",
	              NULL);

	g_bytes_unref (ssid);

	/* Wireless security setting */
	s_wsec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wsec));

	g_object_set (s_wsec, NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "none", NULL);
	nm_setting_wireless_security_set_wep_key (s_wsec, 0, "0123456789abcdef0123456789");

	/* IP4 setting */
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_MANUAL,
	              NM_SETTING_IP_CONFIG_GATEWAY, "1.1.1.1",
	              NULL);

	/* IP Address */
	addr = nm_ip_address_new (AF_INET, "1.1.1.3", 24, &error);
	g_assert_no_error (error);
	nm_setting_ip_config_add_address (s_ip4, addr);
	nm_ip_address_unref (addr);

	nm_setting_ip_config_add_dns (s_ip4, dns1);

	/* IP6 setting */
	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NM_SETTING_IP_CONFIG_MAY_FAIL, TRUE,
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
	nm_connection_normalize (connection, NULL, NULL, NULL);

	/* re-read the connection for comparison */
	reread = connection_from_file_test (testfile,
	                                    NULL,
	                                    TYPE_WIRELESS,
	                                    NULL,
	                                    &error);
	unlink (testfile);

	keyfile = utils_get_keys_path (testfile);
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
	g_free (keyfile);
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
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	char *uuid;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	char *keyfile = NULL;
	GBytes *ssid;
	const char *ssid_data = "blahblah";
	struct stat statbuf;

	connection = nm_simple_connection_new ();

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

	ssid = g_bytes_new (ssid_data, strlen (ssid_data));

	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_MODE, "infrastructure",
	              NULL);

	g_bytes_unref (ssid);

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
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4, NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NM_SETTING_IP_CONFIG_MAY_FAIL, TRUE,
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
	nm_connection_normalize (connection, NULL, NULL, NULL);

	/* re-read the connection for comparison */
	reread = connection_from_file_test (testfile,
	                                    NULL,
	                                    TYPE_WIRELESS,
	                                    NULL,
	                                    &error);
	unlink (testfile);

	keyfile = utils_get_keys_path (testfile);
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
	g_free (keyfile);
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
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	char *uuid;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	char *keyfile = NULL;
	GBytes *ssid;
	const char *ssid_data = "blahblah40";
	struct stat statbuf;

	connection = nm_simple_connection_new ();

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

	ssid = g_bytes_new (ssid_data, strlen (ssid_data));

	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_MODE, "infrastructure",
	              NULL);

	g_bytes_unref (ssid);

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
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4, NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NM_SETTING_IP_CONFIG_MAY_FAIL, TRUE,
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
	nm_connection_normalize (connection, NULL, NULL, NULL);

	/* re-read the connection for comparison */
	reread = connection_from_file_test (testfile,
	                                    NULL,
	                                    TYPE_WIRELESS,
	                                    NULL,
	                                    &error);
	unlink (testfile);

	keyfile = utils_get_keys_path (testfile);
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
	g_free (keyfile);
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
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	char *uuid;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	char *keyfile = NULL;
	GBytes *ssid;
	const char *ssid_data = "blahblah104";
	struct stat statbuf;

	connection = nm_simple_connection_new ();

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

	ssid = g_bytes_new (ssid_data, strlen (ssid_data));

	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_MODE, "infrastructure",
	              NULL);

	g_bytes_unref (ssid);

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
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4, NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NM_SETTING_IP_CONFIG_MAY_FAIL, TRUE,
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
	nm_connection_normalize (connection, NULL, NULL, NULL);

	/* re-read the connection for comparison */
	reread = connection_from_file_test (testfile,
	                                    NULL,
	                                    TYPE_WIRELESS,
	                                    NULL,
	                                    &error);
	unlink (testfile);

	keyfile = utils_get_keys_path (testfile);
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
	g_free (keyfile);
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
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	char *uuid;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	char *keyfile = NULL;
	GBytes *ssid;
	const char *ssid_data = "blahblah";
	struct stat statbuf;

	connection = nm_simple_connection_new ();

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

	ssid = g_bytes_new (ssid_data, strlen (ssid_data));

	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_MODE, "infrastructure",
	              NULL);

	g_bytes_unref (ssid);

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
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4, NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NM_SETTING_IP_CONFIG_MAY_FAIL, TRUE,
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
	nm_connection_normalize (connection, NULL, NULL, NULL);

	/* re-read the connection for comparison */
	reread = connection_from_file_test (testfile,
	                                    NULL,
	                                    TYPE_WIRELESS,
	                                    NULL,
	                                    &error);
	unlink (testfile);

	keyfile = utils_get_keys_path (testfile);
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
	g_free (keyfile);
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
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	char *uuid;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	char *keyfile = NULL;
	GBytes *ssid;
	const char *ssid_data = "blahblah";

	connection = nm_simple_connection_new ();
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

	ssid = g_bytes_new (ssid_data, strlen (ssid_data));
	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_MODE, "infrastructure",
	              NULL);
	g_bytes_unref (ssid);

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
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	g_assert (s_ip4);
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));
	g_object_set (s_ip4, NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	g_assert (s_ip6);
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NM_SETTING_IP_CONFIG_MAY_FAIL, TRUE,
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
	nm_connection_normalize (connection, NULL, NULL, NULL);

	/* re-read the connection for comparison */
	reread = connection_from_file_test (testfile,
	                                    NULL,
	                                    TYPE_WIRELESS,
	                                    NULL,
	                                    &error);
	unlink (testfile);

	g_assert_no_error (error);

	/* No key should be written out since the secret is not system owned */
	keyfile = utils_get_keys_path (testfile);
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
	g_free (keyfile);
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
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	char *uuid, *tmp;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	char *keyfile = NULL;
	GBytes *ssid;
	const char *ssid_data = "blahblah";

	g_return_if_fail (psk != NULL);

	connection = nm_simple_connection_new ();

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

	ssid = g_bytes_new (ssid_data, strlen (ssid_data));

	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_MODE, "infrastructure",
	              NULL);

	g_bytes_unref (ssid);

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
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4, NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NM_SETTING_IP_CONFIG_MAY_FAIL, TRUE,
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
	nm_connection_normalize (connection, NULL, NULL, NULL);

	/* re-read the connection for comparison */
	reread = connection_from_file_test (testfile,
	                                    NULL,
	                                    TYPE_WIRELESS,
	                                    NULL,
	                                    &error);
	unlink (testfile);

	keyfile = utils_get_keys_path (testfile);
	unlink (keyfile);

	tmp = g_strdup_printf ("%s-reread", test_name);
	ASSERT (reread != NULL,
	        tmp, "failed to read %s: %s", testfile, error->message);

	ASSERT (nm_connection_verify (reread, &error),
	        tmp, "failed to verify %s: %s", testfile, error->message);
	g_free (tmp);

	ASSERT (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        test_name, "written and re-read connection weren't the same.");

	g_free (testfile);
	g_free (keyfile);
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
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	char *uuid;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	char *keyfile = NULL;
	GBytes *ssid;
	const char *ssid_data = "blahblah";
	NMIPAddress *addr;
	const char *dns1 = "4.2.2.1";

	connection = nm_simple_connection_new ();

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

	ssid = g_bytes_new (ssid_data, strlen (ssid_data));

	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_MODE, "adhoc",
	              NM_SETTING_WIRELESS_CHANNEL, 11,
	              NM_SETTING_WIRELESS_BAND, "bg",
	              NULL);

	g_bytes_unref (ssid);

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
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_MANUAL,
	              NM_SETTING_IP_CONFIG_GATEWAY, "1.1.1.1",
	              NULL);

	/* IP Address */
	addr = nm_ip_address_new (AF_INET, "1.1.1.3", 25, &error);
	g_assert_no_error (error);
	nm_setting_ip_config_add_address (s_ip4, addr);
	nm_ip_address_unref (addr);

	nm_setting_ip_config_add_dns (s_ip4, dns1);

	/* IP6 setting */
	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NM_SETTING_IP_CONFIG_MAY_FAIL, TRUE,
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
	nm_connection_normalize (connection, NULL, NULL, NULL);

	/* re-read the connection for comparison */
	reread = connection_from_file_test (testfile,
	                                    NULL,
	                                    TYPE_WIRELESS,
	                                    NULL,
	                                    &error);
	unlink (testfile);

	keyfile = utils_get_keys_path (testfile);
	unlink (keyfile);

	ASSERT (reread != NULL,
	        "wifi-wpa-psk-adhoc-write-reread", "failed to read %s: %s", testfile, error->message);

	ASSERT (nm_connection_verify (reread, &error),
	        "wifi-wpa-psk-adhoc-write-reread", "failed to verify %s: %s", testfile, error->message);

	ASSERT (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "wifi-wpa-psk-adhoc-write", "written and re-read connection weren't the same.");

	g_free (testfile);
	g_free (keyfile);
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
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	char *uuid;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	char *keyfile = NULL;
	GBytes *ssid;
	const char *ssid_data = "blahblah";

	connection = nm_simple_connection_new ();

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

	ssid = g_bytes_new (ssid_data, strlen (ssid_data));

	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_MODE, "infrastructure",
	              NULL);

	g_bytes_unref (ssid);

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
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4, NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NM_SETTING_IP_CONFIG_MAY_FAIL, TRUE,
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
	nm_connection_normalize (connection, NULL, NULL, NULL);

	/* re-read the connection for comparison */
	reread = connection_from_file_test (testfile,
	                                    NULL,
	                                    TYPE_WIRELESS,
	                                    NULL,
	                                    &error);
	unlink (testfile);

	keyfile = utils_get_keys_path (testfile);
	unlink (keyfile);

	ASSERT (reread != NULL,
	        "wifi-wpa-eap-tls-write-reread", "failed to read %s: %s", testfile, error->message);

	ASSERT (nm_connection_verify (reread, &error),
	        "wifi-wpa-eap-tls-write-reread-verify", "failed to verify %s: %s", testfile, error->message);

	ASSERT (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "wifi-wpa-eap-tls-write", "written and re-read connection weren't the same.");

	g_free (testfile);
	g_free (keyfile);
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
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	char *uuid;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	char *keyfile = NULL;
	GBytes *ssid;
	const char *ssid_data = "blahblah";

	connection = nm_simple_connection_new ();

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

	ssid = g_bytes_new (ssid_data, strlen (ssid_data));

	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_MODE, "infrastructure",
	              NULL);

	g_bytes_unref (ssid);

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
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4, NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NM_SETTING_IP_CONFIG_MAY_FAIL, TRUE,
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
	nm_connection_normalize (connection, NULL, NULL, NULL);

	/* re-read the connection for comparison */
	reread = connection_from_file_test (testfile,
	                                    NULL,
	                                    TYPE_WIRELESS,
	                                    NULL,
	                                    &error);
	unlink (testfile);

	ASSERT (reread != NULL,
	        "wifi-wpa-eap-ttls-tls-write-reread", "failed to read %s: %s", testfile, error->message);

	keyfile = utils_get_keys_path (testfile);
	unlink (keyfile);

	ASSERT (nm_connection_verify (reread, &error),
	        "wifi-wpa-eap-ttls-tls-write-reread-verify", "failed to verify %s: %s", testfile, error->message);

	ASSERT (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "wifi-wpa-eap-ttls-tls-write", "written and re-read connection weren't the same.");

	g_free (testfile);
	g_free (keyfile);
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
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	char *uuid;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	char *keyfile = NULL;
	GBytes *ssid;
	const char *ssid_data = "blahblah";

	connection = nm_simple_connection_new ();

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

	ssid = g_bytes_new (ssid_data, strlen (ssid_data));

	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_MODE, "infrastructure",
	              NULL);

	g_bytes_unref (ssid);

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
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4, NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NM_SETTING_IP_CONFIG_MAY_FAIL, TRUE,
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
	nm_connection_normalize (connection, NULL, NULL, NULL);

	/* re-read the connection for comparison */
	reread = connection_from_file_test (testfile,
	                                    NULL,
	                                    TYPE_WIRELESS,
	                                    NULL,
	                                    &error);
	unlink (testfile);

	ASSERT (reread != NULL,
	        "wifi-wpa-eap-ttls-mschapv2-write-reread", "failed to read %s: %s", testfile, error->message);

	keyfile = utils_get_keys_path (testfile);
	unlink (keyfile);

	ASSERT (nm_connection_verify (reread, &error),
	        "wifi-wpa-eap-ttls-mschapv2-write-reread-verify", "failed to verify %s: %s", testfile, error->message);

	ASSERT (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "wifi-wpa-eap-ttls-mschapv2-write", "written and re-read connection weren't the same.");

	g_free (testfile);
	g_free (keyfile);
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
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	char *uuid;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	char *keyfile = NULL;
	GBytes *ssid;
	const char *ssid_data = "blahblah";

	/* Test that writing out a WPA config then changing that to an open
	 * config doesn't leave various WPA-related keys lying around in the ifcfg.
	 */

	connection = nm_simple_connection_new ();
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

	ssid = g_bytes_new (ssid_data, strlen (ssid_data));

	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_MODE, "infrastructure",
	              NULL);

	g_bytes_unref (ssid);

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
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	g_assert (s_ip4);
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4, NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	g_assert (s_ip6);
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NM_SETTING_IP_CONFIG_MAY_FAIL, TRUE,
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
	nm_connection_normalize (connection, NULL, NULL, NULL);

	/* re-read the connection for comparison */
	reread = connection_from_file_test (testfile,
	                                    NULL,
	                                    TYPE_WIRELESS,
	                                    NULL,
	                                    &error);
	g_assert_no_error (error);
	g_assert (reread);

	success = nm_connection_verify (reread, &error);
	g_assert_no_error (error);

	success = nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT);
	g_assert (success);

	g_object_unref (reread);

	/* Now change the connection to open and recheck */
	nm_connection_remove_setting (connection, NM_TYPE_SETTING_WIRELESS_SECURITY);

	/* Write it back out */
	keyfile = utils_get_keys_path (testfile);
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
	nm_connection_normalize (connection, NULL, NULL, NULL);

	/* re-read it for comparison */
	reread = connection_from_file_test (testfile,
	                                    NULL,
	                                    TYPE_WIRELESS,
	                                    NULL,
	                                    &error);
	unlink (testfile);
	g_assert_no_error (error);

	g_assert (reread);

	/* No keyfile since it's an open connection this time */
	keyfile = utils_get_keys_path (testfile);
	g_assert (g_file_test (keyfile, G_FILE_TEST_EXISTS) == FALSE);

	success = nm_connection_verify (reread, &error);
	g_assert_no_error (error);

	success = nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT);
	g_assert (success);

	unlink (testfile);
	g_free (testfile);
	g_free (keyfile);
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
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	char *uuid;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	char *keyfile = NULL;
	GBytes *ssid;
	char **perms;
	const char *ssid_data = "SomeSSID";

	/* Test that writing out a WPA config then changing that to a WEP
	 * config works and doesn't cause infinite loop or other issues.
	 */

	connection = nm_simple_connection_new ();
	g_assert (connection);

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	g_assert (s_con);
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	perms = g_strsplit ("user:superman:", ",", -1);
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "random wifi connection 2",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
	              NM_SETTING_CONNECTION_PERMISSIONS, perms,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRELESS_SETTING_NAME,
	              NULL);
	g_free (uuid);
	g_strfreev (perms);
	ASSERT (nm_setting_connection_get_num_permissions (s_con) == 1,
                "test_write_wifi_wpa_then_wep_with_perms", "unexpected failure adding valid user permisson");

	/* Wifi setting */
	s_wifi = (NMSettingWireless *) nm_setting_wireless_new ();
	g_assert (s_wifi);
	nm_connection_add_setting (connection, NM_SETTING (s_wifi));

	ssid = g_bytes_new (ssid_data, strlen (ssid_data));

	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_MODE, "infrastructure",
	              NULL);

	g_bytes_unref (ssid);

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
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	g_assert (s_ip4);
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4, NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	g_assert (s_ip6);
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NM_SETTING_IP_CONFIG_MAY_FAIL, TRUE,
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
	nm_connection_normalize (connection, NULL, NULL, NULL);

	/* re-read the connection for comparison */
	reread = connection_from_file_test (testfile,
	                                    NULL,
	                                    TYPE_WIRELESS,
	                                    NULL,
	                                    &error);
	g_assert_no_error (error);
	g_assert (reread);

	success = nm_connection_verify (reread, &error);
	g_assert_no_error (error);

	success = nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT);
	g_assert (success);

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
	keyfile = utils_get_keys_path (testfile);
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
	nm_connection_normalize (connection, NULL, NULL, NULL);

	/* re-read it for comparison */
	reread = connection_from_file_test (testfile,
	                                    NULL,
	                                    TYPE_WIRELESS,
	                                    NULL,
	                                    &error);
	g_assert_no_error (error);

	g_assert (reread);

	success = nm_connection_verify (reread, &error);
	g_assert_no_error (error);

	success = nm_connection_compare (connection, reread,
	                                 NM_SETTING_COMPARE_FLAG_IGNORE_AGENT_OWNED_SECRETS |
	                                 NM_SETTING_COMPARE_FLAG_IGNORE_NOT_SAVED_SECRETS);

	ASSERT (success,
	        "test_write_wifi_wpa_then_wep_with_perms", "failed to compare connections");

	keyfile = utils_get_keys_path (testfile);
	unlink (keyfile);
	unlink (testfile);
	g_free (keyfile);

	g_free (testfile);
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
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	char *uuid;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	char *keyfile = NULL;
	GBytes *ssid;
	const char *ssid_data = "blahblah";
	shvarFile *ifcfg;
	char *tmp;

	connection = nm_simple_connection_new ();
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

	ssid = g_bytes_new (ssid_data, strlen (ssid_data));

	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_MODE, "infrastructure",
	              NULL);

	g_bytes_unref (ssid);

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
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	g_assert (s_ip4);
	g_object_set (s_ip4, NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	/* IP6 setting */
	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	g_assert (s_ip6);
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NM_SETTING_IP_CONFIG_MAY_FAIL, TRUE,
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
	nm_connection_normalize (connection, NULL, NULL, NULL);

	/* re-read the connection for comparison */
	reread = connection_from_file_test (testfile,
	                                    NULL,
	                                    TYPE_WIRELESS,
	                                    NULL,
	                                    &error);
	g_assert_no_error (error);
	g_assert (reread);

	keyfile = utils_get_keys_path (testfile);
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
	g_free (keyfile);
	g_object_unref (connection);
	g_object_unref (reread);
}

static void
test_write_wired_qeth_dhcp (void)
{
	NMConnection *connection;
	NMConnection *reread;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	char *uuid;
	char **subchans;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;

	connection = nm_simple_connection_new ();

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

	subchans = g_strsplit ("0.0.600,0.0.601,0.0.602", ",", -1);
	g_object_set (s_wired,
	              NM_SETTING_WIRED_S390_SUBCHANNELS, subchans,
	              NM_SETTING_WIRED_S390_NETTYPE, "qeth",
	              NULL);
	g_strfreev (subchans);

	nm_setting_wired_add_s390_option (s_wired, "portname", "FOOBAR");
	nm_setting_wired_add_s390_option (s_wired, "portno", "1");
	nm_setting_wired_add_s390_option (s_wired, "layer2", "0");
	nm_setting_wired_add_s390_option (s_wired, "protocol", "blahbalh");

	/* IP4 setting */
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
	              NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NM_SETTING_IP_CONFIG_MAY_FAIL, TRUE,
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
	nm_connection_normalize (connection, NULL, NULL, NULL);

	/* re-read the connection for comparison */
	reread = connection_from_file_test (testfile,
	                                    NULL,
	                                    TYPE_ETHERNET,
	                                    NULL,
	                                    &error);
	unlink (testfile);

	ASSERT (reread != NULL,
	        "wired-qeth-dhcp-write-reread", "failed to read %s: %s", testfile, error->message);

	ASSERT (nm_connection_verify (reread, &error),
	        "wired-qeth-dhcp-write-reread-verify", "failed to verify %s: %s", testfile, error->message);

	ASSERT (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "wired-qeth-dhcp-write", "written and re-read connection weren't the same.");

	g_free (testfile);
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
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	char *uuid;
	char **subchans;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	shvarFile *ifcfg;
	char *tmp;

	connection = nm_simple_connection_new ();
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

	subchans = g_strsplit ("0.0.600,0.0.601", ",", -1);
	g_object_set (s_wired,
	              NM_SETTING_WIRED_S390_SUBCHANNELS, subchans,
	              NM_SETTING_WIRED_S390_NETTYPE, "ctc",
	              NULL);
	g_strfreev (subchans);
	nm_setting_wired_add_s390_option (s_wired, "ctcprot", "0");

	/* IP4 setting */
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	g_assert (s_ip4);
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));
	g_object_set (s_ip4, NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	g_assert (s_ip6);
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NM_SETTING_IP_CONFIG_MAY_FAIL, TRUE,
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
	nm_connection_normalize (connection, NULL, NULL, NULL);

	/* re-read the connection for comparison */
	reread = connection_from_file_test (testfile,
	                                    NULL,
	                                    TYPE_ETHERNET,
	                                    NULL,
	                                    &error);
	unlink (testfile);

	g_assert (reread);
	success = nm_connection_verify (reread, &error);
	g_assert_no_error (error);
	g_assert (success);

	success = nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT);
	g_assert (success);

	g_free (testfile);
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
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	char *uuid;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;

	connection = nm_simple_connection_new ();

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
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
	              NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NM_SETTING_IP_CONFIG_MAY_FAIL, TRUE,
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
	nm_connection_normalize (connection, NULL, NULL, NULL);

	/* re-read the connection for comparison */
	reread = connection_from_file_test (testfile,
	                                    NULL,
	                                    TYPE_ETHERNET,
	                                    NULL,
	                                    &error);
	unlink (testfile);

	ASSERT (reread != NULL,
	        "permissions-write-reread", "failed to read %s: %s", testfile, error->message);

	ASSERT (nm_connection_verify (reread, &error),
	        "permissions-write-reread-verify", "failed to verify %s: %s", testfile, error->message);

	ASSERT (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "permissions-write", "written and re-read connection weren't the same.");

	g_free (testfile);
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
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	char *uuid;
	const char *str_ssid = "foobarbaz";
	GBytes *ssid;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;

	connection = nm_simple_connection_new ();
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
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	g_assert (s_ip4);
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));
	g_object_set (s_ip4, NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	g_assert (s_ip6);
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NM_SETTING_IP_CONFIG_MAY_FAIL, TRUE,
	              NULL);

	/* Wifi setting */
	s_wifi = (NMSettingWireless *) nm_setting_wireless_new ();
	g_assert (s_wifi);
	nm_connection_add_setting (connection, NM_SETTING (s_wifi));

	ssid = g_bytes_new (str_ssid, strlen (str_ssid));
	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_MODE, "infrastructure",
	              NULL);
	g_bytes_unref (ssid);

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
	nm_connection_normalize (connection, NULL, NULL, NULL);

	/* re-read the connection for comparison */
	reread = connection_from_file_test (testfile,
	                                    NULL,
	                                    TYPE_WIRELESS,
	                                    NULL,
	                                    &error);
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

	g_free (testfile);
	g_object_unref (connection);
	g_object_unref (reread);
}

static void
test_write_wired_pppoe (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIPConfig *s_ip4;
	NMSettingPppoe *s_pppoe;
	NMSettingPpp *s_ppp;
	char *uuid;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;

	connection = nm_simple_connection_new ();

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
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
	              NULL);

	/* PPPoE setting */
	s_pppoe = (NMSettingPppoe *) nm_setting_pppoe_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_pppoe));

	g_object_set (G_OBJECT (s_pppoe),
	              NM_SETTING_PPPOE_SERVICE, "stupid-service",
	              NM_SETTING_PPPOE_USERNAME, "Bill Smith",
	              NM_SETTING_PPPOE_PASSWORD, "test1",
	              NULL);

	/* PPP setting */
	s_ppp = (NMSettingPpp *) nm_setting_ppp_new ();
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
	g_clear_error (&error);
}

static void
test_write_vpn (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingIPConfig *s_ip4;
	NMSettingVpn *s_vpn;
	char *uuid;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;

	connection = nm_simple_connection_new ();

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
	s_vpn = (NMSettingVpn *) nm_setting_vpn_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_vpn));

	g_object_set (s_vpn,
	              NM_SETTING_VPN_SERVICE_TYPE, "awesomevpn",
	              NM_SETTING_VPN_USER_NAME, "Bill Smith",
	              NULL);

	nm_setting_vpn_add_data_item (s_vpn, "server", "vpn.somewhere.com");
	nm_setting_vpn_add_secret (s_vpn, "password", "sup3rs3cr3t");

	/* IP4 setting */
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
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
	g_clear_error (&error);
}

static void
test_write_mobile_broadband (gboolean gsm)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingIPConfig *s_ip4;
	NMSettingGsm *s_gsm;
	NMSettingCdma *s_cdma;
	NMSettingPpp *s_ppp;
	NMSettingSerial *s_serial;
	char *uuid;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;

	connection = nm_simple_connection_new ();

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
	              NM_SETTING_SERIAL_PARITY, NM_SETTING_SERIAL_PARITY_NONE,
	              NM_SETTING_SERIAL_STOPBITS, 1,
	              NULL);

	/* IP4 setting */
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
	              NULL);

	/* PPP setting */
	s_ppp = (NMSettingPpp *) nm_setting_ppp_new ();
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
	g_clear_error (&error);
}

#define TEST_IFCFG_BRIDGE_MAIN TEST_IFCFG_DIR"/network-scripts/ifcfg-test-bridge-main"

static void
test_read_bridge_main (void)
{
	NMConnection *connection;
	NMSettingBridge *s_bridge;
	const char *mac;
	char expected_mac_address[ETH_ALEN] = { 0x00, 0x16, 0x41, 0x11, 0x22, 0x33 };
	GError *error = NULL;

	connection = connection_from_file_test (TEST_IFCFG_BRIDGE_MAIN,
	                                        NULL,
	                                        TYPE_ETHERNET,
	                                        NULL,
	                                        &error);
	g_assert (connection);
	g_assert (nm_connection_verify (connection, &error));
	g_assert_no_error (error);

	g_assert_cmpstr (nm_connection_get_interface_name (connection), ==, "br0");

	/* ===== Bridging SETTING ===== */

	s_bridge = nm_connection_get_setting_bridge (connection);
	g_assert (s_bridge);
	g_assert_cmpuint (nm_setting_bridge_get_forward_delay (s_bridge), ==, 2);
	g_assert (nm_setting_bridge_get_stp (s_bridge));
	g_assert_cmpuint (nm_setting_bridge_get_priority (s_bridge), ==, 32744);
	g_assert_cmpuint (nm_setting_bridge_get_hello_time (s_bridge), ==, 7);
	g_assert_cmpuint (nm_setting_bridge_get_max_age (s_bridge), ==, 39);
	g_assert_cmpuint (nm_setting_bridge_get_ageing_time (s_bridge), ==, 235352);
	g_assert (!nm_setting_bridge_get_multicast_snooping (s_bridge));

	/* MAC address */
	mac = nm_setting_bridge_get_mac_address (s_bridge);
	g_assert (mac);
	g_assert (nm_utils_hwaddr_matches (mac, -1, expected_mac_address, ETH_ALEN));

	g_object_unref (connection);
}

static void
test_write_bridge_main (void)
{
	NMConnection *connection;
	NMConnection *reread;
	NMSettingConnection *s_con;
	NMSettingBridge *s_bridge;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	char *uuid;
	NMIPAddress *addr;
	static const char *mac = "31:33:33:37:be:cd";
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;

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
	              NM_SETTING_CONNECTION_INTERFACE_NAME, "br0",
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_BRIDGE_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* bridge setting */
	s_bridge = (NMSettingBridge *) nm_setting_bridge_new ();
	g_assert (s_bridge);
	nm_connection_add_setting (connection, NM_SETTING (s_bridge));

	g_object_set (s_bridge,
	              NM_SETTING_BRIDGE_MAC_ADDRESS, mac,
	              NULL);

	/* IP4 setting */
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	g_assert (s_ip4);
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_MANUAL,
	              NM_SETTING_IP_CONFIG_GATEWAY, "1.1.1.1",
	              NM_SETTING_IP_CONFIG_MAY_FAIL, TRUE,
	              NULL);

	addr = nm_ip_address_new (AF_INET, "1.1.1.3", 24, &error);
	g_assert_no_error (error);
	nm_setting_ip_config_add_address (s_ip4, addr);
	nm_ip_address_unref (addr);

	/* IP6 setting */
	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	g_assert (s_ip6);
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NULL);

	nmtst_assert_connection_verifies_without_normalization (connection);

	/* Save the ifcfg */
	success = writer_new_connection (connection,
	                                 TEST_SCRATCH_DIR "/network-scripts/",
	                                 &testfile,
	                                 &error);
	g_assert (success);
	g_assert_cmpstr (testfile, !=, NULL);

	/* reread will be normalized, so we must normalize connection too. */
	nm_connection_normalize (connection, NULL, NULL, NULL);

	/* re-read the connection for comparison */
	reread = connection_from_file_test (testfile,
	                                    NULL,
	                                    TYPE_BRIDGE,
	                                    NULL,
	                                    &error);
	unlink (testfile);

	g_assert (reread);
	g_assert (nm_connection_verify (reread, &error));
	g_assert_no_error (error);
	g_assert (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT));

	g_free (testfile);
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
	GError *error = NULL;
	gboolean success;

	connection = connection_from_file_test (TEST_IFCFG_BRIDGE_COMPONENT,
	                                        NULL,
	                                        TYPE_ETHERNET,
	                                        NULL,
	                                        &error);
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
	static const char *mac = "31:33:33:37:be:cd";
	guint32 mtu = 1492;
	char *uuid;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;

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
	s_wired = (NMSettingWired *) nm_setting_wired_new ();
	g_assert (s_wired);
	nm_connection_add_setting (connection, NM_SETTING (s_wired));

	g_object_set (s_wired,
	              NM_SETTING_WIRED_MAC_ADDRESS, mac,
	              NM_SETTING_WIRED_MTU, mtu,
	              NULL);

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
	nm_connection_normalize (connection, NULL, NULL, NULL);

	/* re-read the connection for comparison */
	reread = connection_from_file_test (testfile,
	                                    NULL,
	                                    TYPE_ETHERNET,
	                                    NULL,
	                                    &error);
	unlink (testfile);

	g_assert (reread);

	success = nm_connection_verify (reread, &error);
	g_assert_no_error (error);

	g_assert (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT));

	g_free (testfile);
	g_object_unref (connection);
	g_object_unref (reread);
}

static void
test_read_bridge_missing_stp (void)
{
	NMConnection *connection;
	NMSettingBridge *s_bridge;
	GError *error = NULL;

	connection = connection_from_file_test (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-bridge-missing-stp",
	                                        NULL,
	                                        TYPE_BRIDGE,
	                                        NULL,
	                                        &error);
	g_assert (connection);
	g_assert (nm_connection_verify (connection, &error));
	g_assert_no_error (error);

	g_assert_cmpstr (nm_connection_get_interface_name (connection), ==, "br0");

	/* ===== Bridging SETTING ===== */

	s_bridge = nm_connection_get_setting_bridge (connection);
	g_assert (s_bridge);
	g_assert (nm_setting_bridge_get_stp (s_bridge) == FALSE);

	g_object_unref (connection);
}

#define TEST_IFCFG_VLAN_INTERFACE TEST_IFCFG_DIR"/network-scripts/ifcfg-test-vlan-interface"

static void
test_read_vlan_interface (void)
{
	NMConnection *connection;
	GError *error = NULL;
	NMSettingVlan *s_vlan;
	guint32 from = 0, to = 0;

	connection = connection_from_file_test (TEST_IFCFG_VLAN_INTERFACE,
	                                        NULL,
	                                        TYPE_ETHERNET,
	                                        NULL,
	                                        &error);
	g_assert_no_error (error);
	g_assert (connection != NULL);


	g_assert_cmpstr (nm_connection_get_interface_name (connection), ==, "vlan43");

	s_vlan = nm_connection_get_setting_vlan (connection);
	g_assert (s_vlan);

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
	GError *error = NULL;
	NMSettingVlan *s_vlan;

	connection = connection_from_file_test (TEST_IFCFG_VLAN_ONLY_VLANID,
	                                        NULL,
	                                        TYPE_ETHERNET,
	                                        NULL,
	                                        &error);
	g_assert_no_error (error);
	g_assert (connection != NULL);


	g_assert (nm_connection_get_interface_name (connection) == NULL);

	s_vlan = nm_connection_get_setting_vlan (connection);
	g_assert (s_vlan);

	g_assert_cmpstr (nm_setting_vlan_get_parent (s_vlan), ==, "eth9");
	g_assert_cmpint (nm_setting_vlan_get_id (s_vlan), ==, 43);

	g_object_unref (connection);
}

#define TEST_IFCFG_VLAN_ONLY_DEVICE TEST_IFCFG_DIR"/network-scripts/ifcfg-test-vlan-only-device"

static void
test_read_vlan_only_device (void)
{
	NMConnection *connection;
	GError *error = NULL;
	NMSettingVlan *s_vlan;

	connection = connection_from_file_test (TEST_IFCFG_VLAN_ONLY_DEVICE,
	                                        NULL,
	                                        TYPE_ETHERNET,
	                                        NULL,
	                                        &error);
	g_assert_no_error (error);
	g_assert (connection != NULL);


	g_assert_cmpstr (nm_connection_get_interface_name (connection), ==, "eth0.9");

	s_vlan = nm_connection_get_setting_vlan (connection);
	g_assert (s_vlan);

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

	connection = connection_from_file_test (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-vlan-physdev",
	                                        NULL, TYPE_ETHERNET, NULL,
	                                        &error);
	g_assert_no_error (error);
	g_assert (connection);
	g_assert (nm_connection_verify (connection, &error));

	g_assert_cmpstr (nm_connection_get_interface_name (connection), ==, "vlan0.3");

	s_vlan = nm_connection_get_setting_vlan (connection);
	g_assert (s_vlan);

	g_assert_cmpstr (nm_setting_vlan_get_parent (s_vlan), ==, "eth0");
	g_assert_cmpint (nm_setting_vlan_get_id (s_vlan), ==, 3);

	g_object_unref (connection);
}

static void
test_write_vlan (void)
{
	NMConnection *connection;
	char *written = NULL;
	GError *error = NULL;
	gboolean success = FALSE;

	connection = connection_from_file_test (TEST_IFCFG_VLAN_INTERFACE,
	                                        NULL,
	                                        TYPE_VLAN,
	                                        NULL,
	                                        &error);
	g_assert (connection != NULL);

	success = writer_new_connection (connection,
	                                 TEST_SCRATCH_DIR "/network-scripts/",
	                                 &written,
	                                 &error);
	g_assert (success);

	unlink (written);
	g_free (written);

	g_object_unref (connection);
}

static void
test_write_vlan_only_vlanid (void)
{
	NMConnection *connection, *reread;
	char *written = NULL;
	GError *error = NULL;
	gboolean success = FALSE;

	connection = connection_from_file_test (TEST_IFCFG_VLAN_ONLY_VLANID,
	                                        NULL,
	                                        TYPE_VLAN,
	                                        NULL,
	                                        &error);
	g_assert_no_error (error);
	g_assert (connection != NULL);

	success = writer_new_connection (connection,
	                                 TEST_SCRATCH_DIR "/network-scripts/",
	                                 &written,
	                                 &error);
	g_assert (success);

	/* reread will be normalized, so we must normalize connection too. */
	nm_connection_normalize (connection, NULL, NULL, NULL);

	/* re-read the connection for comparison */
	reread = connection_from_file_test (written,
	                                    NULL,
	                                    TYPE_ETHERNET,
	                                    NULL,
	                                    &error);
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
test_write_ethernet_missing_ipv6 (void)
{
	NMConnection *connection;
	NMConnection *reread;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	char *uuid;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;

	connection = nm_simple_connection_new ();
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
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	g_assert (s_ip4);
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));
	g_object_set (s_ip4,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
	              NM_SETTING_IP4_CONFIG_DHCP_CLIENT_ID, "random-client-id-00:22:33",
	              NM_SETTING_IP_CONFIG_IGNORE_AUTO_ROUTES, TRUE,
	              NM_SETTING_IP_CONFIG_IGNORE_AUTO_DNS, TRUE,
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
	nm_connection_normalize (connection, NULL, NULL, NULL);

	/* re-read the connection for comparison */
	reread = connection_from_file_test (testfile,
	                                    NULL,
	                                    TYPE_ETHERNET,
	                                    NULL,
	                                    &error);
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
	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	g_assert (s_ip6);
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));
	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_AUTO,
	              NM_SETTING_IP_CONFIG_MAY_FAIL, TRUE,
	              NULL);

	ASSERT (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "ethernet-missing-ipv6", "written and re-read connection weren't the same.");

	g_free (testfile);
	g_object_unref (connection);
	g_object_unref (reread);
}

static void
test_read_ibft_ignored (void)
{
	NMConnection *connection;
	GError *error = NULL;

	connection = connection_from_file_test (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-ibft",
	                                        NULL, TYPE_ETHERNET,
	                                        NULL, &error);
	g_assert_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION);
	g_assert (connection == NULL);
	g_clear_error (&error);
}

#define TEST_IFCFG_BOND_MAIN TEST_IFCFG_DIR"/network-scripts/ifcfg-test-bond-main"

static void
test_read_bond_main (void)
{
	NMConnection *connection;
	NMSettingBond *s_bond;
	GError *error = NULL;

	connection = connection_from_file_test (TEST_IFCFG_BOND_MAIN,
	                                        NULL,
	                                        TYPE_ETHERNET,
	                                        NULL,
	                                        &error);
	ASSERT (connection != NULL,
	        "bond-main-read", "unexpected failure reading %s", TEST_IFCFG_BOND_MAIN);

	ASSERT (nm_connection_verify (connection, &error),
	        "bond-main-read", "failed to verify %s: %s", TEST_IFCFG_BOND_MAIN, error->message);

	ASSERT (g_strcmp0 (nm_connection_get_interface_name (connection), "bond0") == 0,
	        "bond-main", "failed to verify %s: DEVICE=%s does not match bond0",
	        TEST_IFCFG_BOND_MAIN, nm_connection_get_interface_name (connection));

	/* ===== Bonding SETTING ===== */

	s_bond = nm_connection_get_setting_bond (connection);
	ASSERT (s_bond != NULL,
	        "bond-main", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_BOND_MAIN,
	        NM_SETTING_BOND_SETTING_NAME);

	ASSERT (g_strcmp0 (nm_setting_bond_get_option_by_name (s_bond, NM_SETTING_BOND_OPTION_MIIMON), "100") == 0,
	        "bond-main", "failed to verify %s: miimon=%s does not match 100",
	        TEST_IFCFG_BOND_MAIN, nm_setting_bond_get_option_by_name (s_bond, NM_SETTING_BOND_OPTION_MIIMON));

	g_object_unref (connection);
}

static void
test_write_bond_main (void)
{
	NMConnection *connection;
	NMConnection *reread;
	NMSettingConnection *s_con;
	NMSettingBond *s_bond;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	NMSettingWired *s_wired;
	char *uuid;
	NMIPAddress *addr;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;

	connection = nm_simple_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write Bond Main",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
	              NM_SETTING_CONNECTION_INTERFACE_NAME, "bond0",
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_BOND_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* Wired setting */
	s_wired = (NMSettingWired *) nm_setting_wired_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wired));

	/* bond setting */
	s_bond = (NMSettingBond *) nm_setting_bond_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_bond));

	/* IP4 setting */
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_MANUAL,
	              NM_SETTING_IP_CONFIG_GATEWAY, "1.1.1.1",
	              NM_SETTING_IP_CONFIG_MAY_FAIL, TRUE,
	              NULL);

	addr = nm_ip_address_new (AF_INET, "1.1.1.3", 24, &error);
	g_assert_no_error (error);
	nm_setting_ip_config_add_address (s_ip4, addr);
	nm_ip_address_unref (addr);

	/* IP6 setting */
	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NULL);

	nmtst_assert_connection_verifies_without_normalization (connection);

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
	nm_connection_normalize (connection, NULL, NULL, NULL);

	/* re-read the connection for comparison */
	reread = connection_from_file_test (testfile,
	                                    NULL,
	                                    TYPE_BOND,
	                                    NULL,
	                                    &error);
	unlink (testfile);

	ASSERT (reread != NULL,
	        "bond-main-write-reread", "failed to read %s: %s", testfile, error->message);

	ASSERT (nm_connection_verify (reread, &error),
	        "bond-main-write-reread-verify", "failed to verify %s: %s", testfile, error->message);

	ASSERT (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "bond-main-write", "written and re-read connection weren't the same.");

	g_free (testfile);
	g_object_unref (connection);
	g_object_unref (reread);
}

#define TEST_IFCFG_BOND_SLAVE TEST_IFCFG_DIR"/network-scripts/ifcfg-test-bond-slave"

static void
test_read_bond_slave (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	GError *error = NULL;

	connection = connection_from_file_test (TEST_IFCFG_BOND_SLAVE,
	                                        NULL,
	                                        TYPE_ETHERNET,
	                                        NULL,
	                                        &error);
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

	g_object_unref (connection);
}

static void
test_write_bond_slave (void)
{
	NMConnection *connection;
	NMConnection *reread;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	static const char *mac = "31:33:33:37:be:cd";
	guint32 mtu = 1492;
	char *uuid;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;

	connection = nm_simple_connection_new ();

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

	g_object_set (s_wired,
	              NM_SETTING_WIRED_MAC_ADDRESS, mac,
	              NM_SETTING_WIRED_MTU, mtu,
	              NULL);

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
	nm_connection_normalize (connection, NULL, NULL, NULL);

	/* re-read the connection for comparison */
	reread = connection_from_file_test (testfile,
	                                    NULL,
	                                    TYPE_ETHERNET,
	                                    NULL,
	                                    &error);
	unlink (testfile);

	ASSERT (reread != NULL,
	        "bond-slave-write-reread", "failed to read %s: %s", testfile, error->message);

	ASSERT (nm_connection_verify (reread, &error),
	        "bond-slave-write-reread-verify", "failed to verify %s: %s", testfile, error->message);

	ASSERT (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "bond-slave-write", "written and re-read connection weren't the same.");

	g_free (testfile);
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
	GError *error = NULL;
	const char *mac;
	char expected_mac_address[INFINIBAND_ALEN] = { 0x80, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22 };
	const char *transport_mode;

	connection = connection_from_file_test (TEST_IFCFG_INFINIBAND,
	                                        NULL,
	                                        TYPE_INFINIBAND,
	                                        &unmanaged,
	                                        &error);
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
	mac = nm_setting_infiniband_get_mac_address (s_infiniband);
	ASSERT (mac != NULL,
	        "infiniband-verify-infiniband", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_INFINIBAND,
	        NM_SETTING_INFINIBAND_SETTING_NAME,
	        NM_SETTING_INFINIBAND_MAC_ADDRESS);
	ASSERT (nm_utils_hwaddr_matches (mac, -1, expected_mac_address, sizeof (expected_mac_address)),
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

	g_object_unref (connection);
}

static void
test_write_infiniband (void)
{
	NMConnection *connection;
	NMConnection *reread;
	NMSettingConnection *s_con;
	NMSettingInfiniband *s_infiniband;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	const char *mac = "80:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22";
	guint32 mtu = 65520;
	char *uuid;
	NMIPAddress *addr;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;

	connection = nm_simple_connection_new ();

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

	g_object_set (s_infiniband,
	              NM_SETTING_INFINIBAND_MAC_ADDRESS, mac,
	              NM_SETTING_INFINIBAND_MTU, mtu,
	              NM_SETTING_INFINIBAND_TRANSPORT_MODE, "connected",
	              NULL);

	/* IP4 setting */
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_MANUAL,
	              NM_SETTING_IP_CONFIG_GATEWAY, "1.1.1.1",
	              NM_SETTING_IP_CONFIG_MAY_FAIL, TRUE,
	              NULL);

	addr = nm_ip_address_new (AF_INET, "1.1.1.3", 24, &error);
	g_assert_no_error (error);
	nm_setting_ip_config_add_address (s_ip4, addr);
	nm_ip_address_unref (addr);

	/* IP6 setting */
	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
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
	nm_connection_normalize (connection, NULL, NULL, NULL);

	/* re-read the connection for comparison */
	reread = connection_from_file_test (testfile,
	                                    NULL,
	                                    TYPE_INFINIBAND,
	                                    NULL,
	                                    &error);
	unlink (testfile);

	ASSERT (reread != NULL,
	        "infiniband-write-reread", "failed to read %s: %s", testfile, error->message);

	ASSERT (nm_connection_verify (reread, &error),
	        "infiniband-write-reread-verify", "failed to verify %s: %s", testfile, error->message);

	ASSERT (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "infiniband-write", "written and re-read connection weren't the same.");

	g_free (testfile);
	g_object_unref (connection);
	g_object_unref (reread);
}

#define TEST_IFCFG_BOND_SLAVE_IB TEST_IFCFG_DIR"/network-scripts/ifcfg-test-bond-slave-ib"

static void
test_read_bond_slave_ib (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	GError *error = NULL;

	connection = connection_from_file_test (TEST_IFCFG_BOND_SLAVE_IB,
	                                        NULL,
	                                        NULL,
	                                        NULL,
	                                        &error);
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

	g_object_unref (connection);
}

static void
test_write_bond_slave_ib (void)
{
	NMConnection *connection;
	NMConnection *reread;
	NMSettingConnection *s_con;
	NMSettingInfiniband *s_infiniband;
	static const char *mac = "80:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22";
	char *uuid;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;

	connection = nm_simple_connection_new ();

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

	g_object_set (s_infiniband,
	              NM_SETTING_INFINIBAND_MAC_ADDRESS, mac,
	              NM_SETTING_INFINIBAND_MTU, 2044,
	              NM_SETTING_INFINIBAND_TRANSPORT_MODE, "datagram",
	              NULL);

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
	nm_connection_normalize (connection, NULL, NULL, NULL);

	/* re-read the connection for comparison */
	reread = connection_from_file_test (testfile,
	                                    NULL,
	                                    NULL,
	                                    NULL,
	                                    &error);
	unlink (testfile);

	ASSERT (reread != NULL,
	        "bond-slave-write-ib-reread", "failed to read %s: %s", testfile, error->message);

	ASSERT (nm_connection_verify (reread, &error),
	        "bond-slave-write-ib-reread-verify", "failed to verify %s: %s", testfile, error->message);

	ASSERT (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "bond-slave-write-ib", "written and re-read connection weren't the same.");

	g_free (testfile);
	g_object_unref (connection);
	g_object_unref (reread);
}

static void
test_read_bond_opts_mode_numeric (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingBond *s_bond;
	gboolean success;
	GError *error = NULL;

	connection = connection_from_file_test (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-bond-mode-numeric",
	                                        NULL, TYPE_ETHERNET, NULL, &error);
	g_assert_no_error (error);
	g_assert (connection);

	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	g_assert_cmpstr (nm_connection_get_interface_name (connection), ==, "bond0");

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_connection_type (s_con), ==, NM_SETTING_BOND_SETTING_NAME);

	s_bond = nm_connection_get_setting_bond (connection);
	g_assert (s_bond);
	g_assert_cmpstr (nm_setting_bond_get_option_by_name (s_bond, NM_SETTING_BOND_OPTION_MODE), ==, "802.3ad");

	g_object_unref (connection);
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

	connection = connection_from_file_test (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-dcb",
	                                        NULL, TYPE_ETHERNET, NULL, &error);
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
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	gboolean success;
	guint i;
	char *uuid, *testfile;
	const guint group_ids[8] = { 4, 0xF, 6, 0xF, 1, 7, 3, 0xF };
	const guint group_bandwidths[8] = { 10, 20, 15, 10, 2, 3, 35, 5 };
	const guint bandwidths[8] = { 10, 20, 30, 40, 50, 10, 0, 25 };
	const gboolean strict[8] = { TRUE, FALSE, TRUE, TRUE, FALSE, FALSE, FALSE, TRUE };
	const guint traffic_classes[8] = { 3, 4, 7, 2, 1, 0, 5, 6 };
	const gboolean pfcs[8] = { TRUE, TRUE, FALSE, TRUE, FALSE, TRUE, TRUE, FALSE };

	connection = nm_simple_connection_new ();

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
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	g_object_set (G_OBJECT (s_ip4), NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	g_object_set (G_OBJECT (s_ip6), NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_AUTO, NULL);
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
	reread = connection_from_file_test (testfile,
	                                    NULL,
	                                    TYPE_ETHERNET,
	                                    NULL,
	                                    &error);
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

	connection = connection_from_file_test (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-dcb-default-app-priorities",
	                                        NULL, TYPE_ETHERNET, NULL, &error);
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
	connection = connection_from_file_test (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-dcb-bad-booleans",
	                                        NULL, TYPE_ETHERNET, NULL, &error);
	g_test_assert_expected_messages ();

	g_assert_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION);
	g_assert (strstr (error->message, "invalid boolean digit"));
	g_assert (connection == NULL);
	g_clear_error (&error);
}

static void
test_read_dcb_short_booleans (void)
{
	NMConnection *connection;
	GError *error = NULL;

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_WARNING,
	                       "*DCB_PG_STRICT value*8 characters*");
	connection = connection_from_file_test (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-dcb-short-booleans",
	                                        NULL, TYPE_ETHERNET, NULL, &error);
	g_test_assert_expected_messages ();

	g_assert_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION);
	g_assert (strstr (error->message, "boolean array must be 8 characters"));
	g_assert (connection == NULL);
	g_clear_error (&error);
}

static void
test_read_dcb_bad_uints (void)
{
	NMConnection *connection;
	GError *error = NULL;

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_WARNING,
	                       "*invalid DCB_PG_UP2TC value*not 0 - 7*");
	connection = connection_from_file_test (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-dcb-bad-uints",
	                                        NULL, TYPE_ETHERNET, NULL, &error);
	g_test_assert_expected_messages ();

	g_assert_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION);
	g_assert (strstr (error->message, "invalid uint digit"));
	g_assert (connection == NULL);
	g_clear_error (&error);
}

static void
test_read_dcb_short_uints (void)
{
	NMConnection *connection;
	GError *error = NULL;

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_WARNING,
	                       "*DCB_PG_UP2TC value*8 characters*");
	connection = connection_from_file_test (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-dcb-short-uints",
	                                        NULL, TYPE_ETHERNET, NULL, &error);
	g_test_assert_expected_messages ();

	g_assert_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION);
	g_assert (strstr (error->message, "uint array must be 8 characters"));
	g_assert (connection == NULL);
	g_clear_error (&error);
}

static void
test_read_dcb_bad_percent (void)
{
	NMConnection *connection;
	GError *error = NULL;

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_WARNING,
	                       "*invalid DCB_PG_PCT percentage value*");
	connection = connection_from_file_test (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-dcb-bad-percent",
	                                        NULL, TYPE_ETHERNET, NULL, &error);
	g_test_assert_expected_messages ();

	g_assert_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION);
	g_assert (strstr (error->message, "invalid percent element"));
	g_assert (connection == NULL);
	g_clear_error (&error);
}

static void
test_read_dcb_short_percent (void)
{
	NMConnection *connection;
	GError *error = NULL;

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_WARNING,
	                       "*invalid DCB_PG_PCT percentage list value*");
	connection = connection_from_file_test (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-dcb-short-percent",
	                                        NULL, TYPE_ETHERNET, NULL, &error);
	g_test_assert_expected_messages ();

	g_assert_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION);
	g_assert (strstr (error->message, "percent array must be 8 elements"));
	g_assert (connection == NULL);
	g_clear_error (&error);
}

static void
test_read_dcb_pgpct_not_100 (void)
{
	NMConnection *connection;
	GError *error = NULL;

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_WARNING,
	                       "*DCB_PG_PCT percentages do not equal 100*");
	connection = connection_from_file_test (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-dcb-pgpct-not-100",
	                                        NULL, TYPE_ETHERNET, NULL, &error);
	g_test_assert_expected_messages ();

	g_assert_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION);
	g_assert (strstr (error->message, "invalid percentage sum"));
	g_assert (connection == NULL);
	g_clear_error (&error);
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
	connection = connection_from_file_test (file, NULL, TYPE_ETHERNET, NULL, &error);
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
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	gboolean success;
	char *uuid, *testfile;

	connection = nm_simple_connection_new ();

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
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	g_object_set (G_OBJECT (s_ip4), NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	g_object_set (G_OBJECT (s_ip6), NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_AUTO, NULL);
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
	reread = connection_from_file_test (testfile,
	                                    NULL,
	                                    TYPE_ETHERNET,
	                                    NULL,
	                                    &error);
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

	connection = connection_from_file_test (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-team-master",
	                                        NULL, TYPE_ETHERNET, NULL, &error);
	g_assert_no_error (error);
	g_assert (connection);

	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	g_assert_cmpstr (nm_connection_get_interface_name (connection), ==, "team0");

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_connection_type (s_con), ==, NM_SETTING_TEAM_SETTING_NAME);

	s_team = nm_connection_get_setting_team (connection);
	g_assert (s_team);
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
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	char *uuid, *testfile = NULL, *val;
	gboolean success;
	GError *error = NULL;
	const char *expected_config = "{ \"device\": \"team0\", \"link_watch\": { \"name\": \"ethtool\" } }";
	const char *escaped_expected_config = "\"{ \\\"device\\\": \\\"team0\\\", \\\"link_watch\\\": { \\\"name\\\": \\\"ethtool\\\" } }\"";
	shvarFile *f;

	connection = nm_simple_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write Team Master",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_INTERFACE_NAME, "team0",
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_TEAM_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* Team setting */
	s_team = (NMSettingTeam *) nm_setting_team_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_team));

	g_object_set (s_team,
	              NM_SETTING_TEAM_CONFIG, expected_config,
	              NULL);

	/* Wired setting */
	s_wired = (NMSettingWired *) nm_setting_wired_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wired));

	/* IP4 setting */
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	g_assert (s_ip4);
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
	              NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	g_assert (s_ip6);
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_AUTO,
	              NULL);

	nmtst_assert_connection_verifies_without_normalization (connection);

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
	nm_connection_normalize (connection, NULL, NULL, NULL);

	/* re-read the connection for comparison */
	reread = connection_from_file_test (testfile, NULL, TYPE_ETHERNET,
	                                    NULL, &error);
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

	connection = connection_from_file_test (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-team-port",
	                                        NULL, TYPE_ETHERNET, NULL, &error);
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

	connection = nm_simple_connection_new ();

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
	g_free (val);
	val = svGetValue (f, "TEAM_MASTER", TRUE);
	g_assert (val);
	g_assert_cmpstr (val, ==, "team0");
	g_free (val);
	svCloseFile (f);

	/* reread will be normalized, so we must normalize connection too. */
	nm_connection_normalize (connection, NULL, NULL, NULL);

	/* re-read the connection for comparison */
	reread = connection_from_file_test (testfile, NULL, TYPE_ETHERNET,
	                                    NULL, &error);
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

	connection = connection_from_file_test (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-team-port-empty-config",
	                                        NULL, TYPE_ETHERNET, NULL, &error);
	g_assert_no_error (error);
	g_assert (connection);

	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_connection_type (s_con), ==, NM_SETTING_WIRED_SETTING_NAME);
	g_assert_cmpstr (nm_setting_connection_get_master (s_con), ==, "team0");

	/* Normalization adds a team-port setting */
	g_assert (nm_connection_get_setting_team_port (connection));

	/* empty/missing config */
	g_assert (!nm_setting_team_port_get_config (nm_connection_get_setting_team_port (connection)));

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
test_svUnescape (void)
{
	int len, repeat, i, k;
	GRand *r = g_rand_new ();
	guint32 seed = g_random_int ();

	g_rand_set_seed (r, seed);

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
				s[i] = g_rand_int (r);

			/* randomly place escape characters into the string */
			k = g_rand_int (r) % (len);
			while (k-- > 0)
				s[g_rand_int (r) % len] = '\\';

			if (len > 1) {
				/* quote the string. */
				k = g_rand_int (r) % (10);
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

	g_rand_free (r);
}

static void
test_read_vlan_trailing_spaces (void)
{
	const char *testfile = TEST_IFCFG_DIR"/network-scripts/ifcfg-test-vlan-trailing-spaces";
	NMConnection *connection;
	gboolean success;
	GError *error = NULL;
	NMSettingVlan *s_vlan;
	char *contents = NULL;

	/* Ensure there is whitespace at the end of the VLAN interface name,
	 * to prevent the whitespace getting stripped off and committed mistakenly
	 * by something in the future.
	 */
	success = g_file_get_contents (testfile, &contents, NULL, &error);
	g_assert_no_error (error);
	g_assert (success);
	g_assert (contents && contents[0]);
	g_assert (strstr (contents, "DEVICE=\"vlan201\"  \n"));
	g_free (contents);

	connection = connection_from_file_test (testfile, NULL, TYPE_ETHERNET, NULL,
	                                        &error);
	g_assert_no_error (error);
	g_assert (connection != NULL);

	s_vlan = nm_connection_get_setting_vlan (connection);
	g_assert (s_vlan);

	g_assert_cmpstr (nm_connection_get_interface_name (connection), ==, "vlan201");
	g_assert_cmpstr (nm_setting_vlan_get_parent (s_vlan), ==, "enccw0.0.fb00");
	g_assert_cmpint (nm_setting_vlan_get_id (s_vlan), ==, 201);
	g_assert_cmpint (nm_setting_vlan_get_flags (s_vlan), ==, 0);

	g_object_unref (connection);
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
	nmtst_init_assert_logging (&argc, &argv, "INFO", "DEFAULT");

	g_test_add_func (TPATH "svUnescape", test_svUnescape);
	g_test_add_func (TPATH "vlan-trailing-spaces", test_read_vlan_trailing_spaces);

	g_test_add_func (TPATH "unmanaged", test_read_unmanaged);
	g_test_add_func (TPATH "unmanaged-unrecognized", test_read_unmanaged_unrecognized);
	g_test_add_func (TPATH "unrecognized", test_read_unrecognized);
	g_test_add_func (TPATH "basic", test_read_basic);
	g_test_add_func (TPATH "miscellaneous-variables", test_read_miscellaneous_variables);
	g_test_add_func (TPATH "variables-corner-cases", test_read_variables_corner_cases);
	g_test_add_data_func (TPATH "no-prefix/8", GUINT_TO_POINTER (8), test_read_wired_static_no_prefix);
	g_test_add_data_func (TPATH "no-prefix/16", GUINT_TO_POINTER (16), test_read_wired_static_no_prefix);
	g_test_add_data_func (TPATH "no-prefix/24", GUINT_TO_POINTER (24), test_read_wired_static_no_prefix);
	g_test_add_data_func (TPATH "static-ip6-only-gw/_NULL_", NULL, test_write_wired_static_ip6_only_gw);
	g_test_add_data_func (TPATH "static-ip6-only-gw/::", "::", test_write_wired_static_ip6_only_gw);
	g_test_add_data_func (TPATH "static-ip6-only-gw/2001:db8:8:4::2", "2001:db8:8:4::2", test_write_wired_static_ip6_only_gw);
	g_test_add_data_func (TPATH "static-ip6-only-gw/::ffff:255.255.255.255", "::ffff:255.255.255.255", test_write_wired_static_ip6_only_gw);
	g_test_add_func (TPATH "read-dns-options", test_read_dns_options);

	test_read_wired_static (TEST_IFCFG_WIRED_STATIC, "System test-wired-static", TRUE);
	test_read_wired_static (TEST_IFCFG_WIRED_STATIC_BOOTPROTO, "System test-wired-static-bootproto", FALSE);
	test_read_wired_dhcp ();
	g_test_add_func (TPATH "dhcp-plus-ip", test_read_wired_dhcp_plus_ip);
	g_test_add_func (TPATH "shared-plus-ip", test_read_wired_shared_plus_ip);
	g_test_add_func (TPATH "dhcp-send-hostname", test_read_write_wired_dhcp_send_hostname);
	g_test_add_func (TPATH "global-gateway", test_read_wired_global_gateway);
	g_test_add_func (TPATH "obsolete-gateway-n", test_read_wired_obsolete_gateway_n);
	g_test_add_func (TPATH "never-default", test_read_wired_never_default);
	test_read_wired_defroute_no ();
	test_read_wired_defroute_no_gatewaydev_yes ();
	g_test_add_func (TPATH "routes/read-static", test_read_wired_static_routes);
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
	g_test_add_func (TPATH "wifi/read-band-a", test_read_wifi_band_a);
	g_test_add_func (TPATH "wifi/read-band-a-channel-mismatch", test_read_wifi_band_a_channel_mismatch);
	g_test_add_func (TPATH "wifi/read-band-bg-channel-mismatch", test_read_wifi_band_bg_channel_mismatch);
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
	g_test_add_func (TPATH "wifi/write-band-a", test_write_wifi_band_a);
	test_write_wired_qeth_dhcp ();
	test_write_wired_ctc_dhcp ();
	test_write_permissions ();
	test_write_wifi_wep_agent_keys ();
	test_write_infiniband ();
	test_write_vlan ();
	test_write_vlan_only_vlanid ();
	test_write_ethernet_missing_ipv6 ();
	g_test_add_func (TPATH "write-dns-options", test_write_dns_options);

	/* iSCSI / ibft */
	g_test_add_func (TPATH "ibft/ignored", test_read_ibft_ignored);

	/* Data Center Bridging (DCB) */
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
	g_test_add_func (TPATH "bond/bonding-opts-numeric-mode", test_read_bond_opts_mode_numeric);

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

