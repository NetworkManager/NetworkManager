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

#include "nm-default.h"

#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "nm-utils.h"
#include "nm-setting-connection.h"
#include "nm-setting-wired.h"
#include "nm-setting-wireless.h"
#include "nm-setting-wireless-security.h"
#include "nm-setting-ip4-config.h"
#include "nm-setting-ip6-config.h"
#include "nm-setting-8021x.h"
#include "nm-setting-pppoe.h"
#include "nm-setting-ppp.h"
#include "nm-setting-vpn.h"
#include "nm-setting-gsm.h"
#include "nm-setting-cdma.h"
#include "nm-setting-serial.h"
#include "nm-setting-vlan.h"
#include "nm-setting-dcb.h"
#include "nm-core-internal.h"

#include "NetworkManagerUtils.h"

#include "common.h"
#include "reader.h"
#include "writer.h"
#include "utils.h"

#include "nm-test-utils.h"

/*****************************************************************************/

static NMConnection *
_connection_from_file (const char *filename,
                       const char *network_file,
                       const char *test_type,
                       char **out_unhandled)
{
	NMConnection *connection;
	GError *error = NULL;

	g_assert (!out_unhandled || !*out_unhandled);

	connection = connection_from_file_test (filename, network_file, test_type, out_unhandled, &error);
	g_assert_no_error (error);

	if (out_unhandled && *out_unhandled)
		nmtst_assert_connection_verifies (connection);
	else
		nmtst_assert_connection_verifies_without_normalization (connection);
	return connection;
}

static void
_connection_from_file_fail (const char *filename,
                            const char *network_file,
                            const char *test_type,
                            GError **error)
{
	NMConnection *connection;
	GError *local = NULL;
	char *unhandled = NULL;
	char **p_unhandled = (nmtst_get_rand_int () % 2) ? &unhandled : NULL;

	connection = connection_from_file_test (filename, network_file, test_type, p_unhandled, &local);

	g_assert (!connection);
	g_assert (local);
	g_assert (!p_unhandled || !*p_unhandled);
	g_propagate_error (error, local);
}

static void
_writer_new_connection (NMConnection *connection,
                        const char *ifcfg_dir,
                        char **out_filename)
{
	gboolean success;
	GError *error = NULL;
	char *filename = NULL;

	g_assert (NM_IS_CONNECTION (connection));
	g_assert (ifcfg_dir);

	success = writer_new_connection (connection,
	                                 ifcfg_dir,
	                                 &filename,
	                                 &error);
	nmtst_assert_success (success, error);
	g_assert (filename && filename[0]);

	if (out_filename)
		*out_filename = filename;
	else
		g_free (filename);
}

static void
_writer_new_connection_fail (NMConnection *connection,
                             const char *ifcfg_dir,
                             GError **error)
{
	gboolean success;
	GError *local = NULL;
	char *filename = NULL;

	g_assert (NM_IS_CONNECTION (connection));
	g_assert (ifcfg_dir);

	success = writer_new_connection (connection,
	                                 ifcfg_dir,
	                                 &filename,
	                                 &local);
	nmtst_assert_no_success (success, local);
	g_assert (!filename);

	g_propagate_error (error, local);
}

/*****************************************************************************/

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
	const char *mac;
	char expected_mac_address[ETH_ALEN] = { 0x00, 0x16, 0x41, 0x11, 0x22, 0x33 };

	connection = _connection_from_file (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-minimal",
	                                    NULL, TYPE_ETHERNET, NULL);

	/* ===== CONNECTION SETTING ===== */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "System test-minimal");
	g_assert_cmpint (nm_setting_connection_get_timestamp (s_con), ==, 0);
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
	char *expected_mac_blacklist[3] = { "00:16:41:11:22:88", "00:16:41:11:22:99", "6a:5d:5a:fa:dd:f0" };
	int mac_blacklist_num, i;
	guint64 expected_timestamp = 0;

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*invalid MAC in HWADDR_BLACKLIST 'XX:aa:invalid'*");
	connection = _connection_from_file (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-misc-variables",
	                                    NULL, TYPE_ETHERNET, NULL);
	g_test_assert_expected_messages ();

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
	const char *mac;
	char expected_mac_address[ETH_ALEN] = { 0x00, 0x16, 0x41, 0x11, 0x22, 0x33 };

	connection = _connection_from_file (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-variables-corner-cases-1",
	                                    NULL, TYPE_ETHERNET, NULL);

	/* ===== CONNECTION SETTING ===== */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "\"");
	g_assert_cmpstr (nm_setting_connection_get_zone (s_con), ==, "'");
	g_assert_cmpint (nm_setting_connection_get_timestamp (s_con), ==, 0);
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
	guint64 expected_timestamp = 0;

	connection = _connection_from_file (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-nm-controlled",
	                                    NULL, TYPE_ETHERNET,
	                                    &unhandled_spec);
	g_assert_cmpstr (unhandled_spec, ==, "unmanaged:mac:00:11:22:33:f8:9f");

	/* ===== CONNECTION SETTING ===== */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "System test-nm-controlled");
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
	guint64 expected_timestamp = 0;

	connection = _connection_from_file (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-nm-controlled-unrecognized",
	                                    NULL, NULL,
	                                    &unhandled_spec);
	g_assert_cmpstr (unhandled_spec, ==, "unmanaged:interface-name:ipoac0");

	/* ===== CONNECTION SETTING ===== */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "PigeonNet");
	g_assert_cmpint (nm_setting_connection_get_timestamp (s_con), ==, expected_timestamp);

	g_object_unref (connection);
}

static void
test_read_unrecognized (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	gs_free char *unhandled_spec = NULL;
	guint64 expected_timestamp = 0;

	connection = _connection_from_file (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-unrecognized",
	                                    NULL, NULL,
	                                    &unhandled_spec);
	g_assert_cmpstr (unhandled_spec, ==, "unrecognized:mac:00:11:22:33");

	/* ===== CONNECTION SETTING ===== */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "U Can't Touch This");
	g_assert_cmpint (nm_setting_connection_get_timestamp (s_con), ==, expected_timestamp);

	g_object_unref (connection);
}

static void
test_read_wired_static (gconstpointer test_data)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	char *unmanaged = NULL;
	const char *mac;
	char expected_mac_address[ETH_ALEN] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0xee };
	NMIPAddress *ip4_addr;
	NMIPAddress *ip6_addr;
	const char *file, *expected_id;
	gpointer expect_ip6_p;

	nmtst_test_data_unpack (test_data, &file, &expected_id, &expect_ip6_p);

	g_assert (expected_id);

	connection = _connection_from_file (file, NULL, TYPE_ETHERNET,
	                                    &unmanaged);
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
	if (GPOINTER_TO_INT (expect_ip6_p)) {
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
	NMIPAddress *ip4_addr;
	char *file, *expected_id;

	file = g_strdup_printf (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-wired-static-no-prefix-%u", expected_prefix);
	expected_id = g_strdup_printf ("System test-wired-static-no-prefix-%u", expected_prefix);

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*missing PREFIX, assuming*");
	connection = _connection_from_file (file, NULL, TYPE_ETHERNET, NULL);
	g_test_assert_expected_messages ();

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

static void
test_read_wired_dhcp (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIPConfig *s_ip4;
	char *unmanaged = NULL;
	char expected_mac_address[ETH_ALEN] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0xee };
	const char *mac;

	connection = _connection_from_file (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-wired-dhcp",
	                                    NULL, TYPE_ETHERNET,
	                                    &unmanaged);
	g_assert (unmanaged == NULL);

	/* ===== CONNECTION SETTING ===== */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "System test-wired-dhcp");
	g_assert_cmpuint (nm_setting_connection_get_timestamp (s_con), ==, 0);
	g_assert (nm_setting_connection_get_autoconnect (s_con));

	/* ===== WIRED SETTING ===== */
	s_wired = nm_connection_get_setting_wired (connection);
	g_assert (s_wired);

	/* MAC address */
	mac = nm_setting_wired_get_mac_address (s_wired);
	g_assert (mac);
	g_assert (nm_utils_hwaddr_matches (mac, -1, expected_mac_address, sizeof (expected_mac_address)));

	/* ===== IPv4 SETTING ===== */
	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_AUTO);
	g_assert_cmpstr (nm_setting_ip_config_get_dhcp_hostname (s_ip4), ==, "foobar");
	g_assert (nm_setting_ip_config_get_ignore_auto_dns (s_ip4));
	g_assert_cmpuint (nm_setting_ip_config_get_num_dns (s_ip4), ==, 2);
	g_assert_cmpstr (nm_setting_ip_config_get_dns (s_ip4, 0), ==, "4.2.2.1");
	g_assert_cmpstr (nm_setting_ip_config_get_dns (s_ip4, 1), ==, "4.2.2.2");

	g_object_unref (connection);
}

static void
test_read_wired_dhcp_plus_ip (void)
{
	NMConnection *connection;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	NMIPAddress *ip4_addr;
	NMIPAddress *ip6_addr;

	connection = _connection_from_file (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-dhcp-plus-ip",
	                                    NULL, TYPE_ETHERNET, NULL);

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
	NMIPAddress *ip4_addr;

	connection = _connection_from_file (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-shared-plus-ip",
	                                    NULL, TYPE_ETHERNET, NULL);

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
	NMIPAddress *ip4_addr;
	char *unmanaged = NULL;

	connection = _connection_from_file (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-global-gateway",
	                                    TEST_IFCFG_DIR"/network-scripts/network-test-wired-global-gateway",
	                                    TYPE_ETHERNET, &unmanaged);
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

/* Ignore GATEWAY from /etc/sysconfig/network for automatic connections */
static void
test_read_wired_global_gateway_ignore (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIPConfig *s_ip4;
	char *unmanaged = NULL;

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*ignoring GATEWAY (/etc/sysconfig/network) for * because the connection has no static addresses");
	connection = _connection_from_file (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-global-gateway-ignore",
	                                    TEST_IFCFG_DIR"/network-scripts/network-test-wired-global-gateway-ignore",
	                                    TYPE_ETHERNET, &unmanaged);
	g_test_assert_expected_messages ();
	g_assert (unmanaged == NULL);

	/* ===== CONNECTION SETTING ===== */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "System test-wired-global-gateway-ignore");

	/* ===== WIRED SETTING ===== */
	s_wired = nm_connection_get_setting_wired (connection);
	g_assert (s_wired);

	/* ===== IPv4 SETTING ===== */
	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_AUTO);

	/* Addresses */
	g_assert_cmpint (nm_setting_ip_config_get_num_addresses (s_ip4), ==, 0);

	/* Gateway */
	g_assert_cmpstr (nm_setting_ip_config_get_gateway (s_ip4), ==, NULL);

	g_object_unref (connection);
}

static void
test_read_wired_obsolete_gateway_n (void)
{
	NMConnection *connection;
	NMSettingIPConfig *s_ip4;
	NMIPAddress *ip4_addr;

	connection = _connection_from_file (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-obsolete-gateway-n",
	                                    NULL, TYPE_ETHERNET, NULL);

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

	connection = _connection_from_file (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-never-default",
	                                    TEST_IFCFG_DIR"/network-scripts/network-test-wired-never-default",
	                                    TYPE_ETHERNET, NULL);

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

static void
test_read_wired_defroute_no (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	char *unmanaged = NULL;

	connection = _connection_from_file (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-defroute-no",
	                                    NULL, TYPE_ETHERNET, &unmanaged);
	g_assert (unmanaged == NULL);

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "System test-wired-defroute-no");

	g_assert (nm_connection_get_setting_wired (connection));

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_AUTO);
	g_assert (nm_setting_ip_config_get_never_default (s_ip4));

	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	g_assert (s_ip6);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip6), ==, NM_SETTING_IP6_CONFIG_METHOD_AUTO);
	g_assert (nm_setting_ip_config_get_never_default (s_ip6));

	g_object_unref (connection);
}

static void
test_read_wired_defroute_no_gatewaydev_yes (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	char *unmanaged = NULL;

	connection = _connection_from_file (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-defroute-no-gatewaydev-yes",
	                                    TEST_IFCFG_DIR"/network-scripts/network-test-wired-defroute-no-gatewaydev-yes",
	                                    TYPE_ETHERNET,
	                                    &unmanaged);

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "System test-wired-defroute-no-gatewaydev-yes");

	g_assert (nm_connection_get_setting_wired (connection));

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_AUTO);
	g_assert (nm_setting_ip_config_get_never_default (s_ip4) == FALSE);

	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	g_assert (s_ip6);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip6), ==, NM_SETTING_IP6_CONFIG_METHOD_AUTO);
	g_assert (nm_setting_ip_config_get_never_default (s_ip6) == FALSE);

	g_object_unref (connection);
}

static void
test_read_wired_static_routes (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIPConfig *s_ip4;
	NMIPRoute *ip4_route;

	connection = _connection_from_file (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-static-routes",
	                                    NULL, TYPE_ETHERNET, NULL);

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

static void
test_read_wired_static_routes_legacy (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIPConfig *s_ip4;
	char *unmanaged = NULL;
	NMIPRoute *ip4_route;

	connection = _connection_from_file (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-static-routes-legacy",
	                                    NULL, TYPE_ETHERNET, &unmanaged);
	g_assert (!unmanaged);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "System test-wired-static-routes-legacy");

	/* ===== WIRED SETTING ===== */

	s_wired = nm_connection_get_setting_wired (connection);
	g_assert (s_wired);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_MANUAL);

	/* Routes */
	g_assert_cmpint (nm_setting_ip_config_get_num_routes (s_ip4), ==, 3);

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
test_read_wired_ipv4_manual (gconstpointer data)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIPConfig *s_ip4;
	char *unmanaged = NULL;
	NMIPAddress *ip4_addr;
	const char *file, *expected_id;

	nmtst_test_data_unpack (data, &file, &expected_id);

	g_assert (expected_id);

	connection = _connection_from_file (file,
	                                    NULL,
	                                    TYPE_ETHERNET,
	                                    &unmanaged);
	g_assert (!unmanaged);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, expected_id);

	/* ===== WIRED SETTING ===== */

	s_wired = nm_connection_get_setting_wired (connection);
	g_assert (s_wired);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_MANUAL);

	/* IP addresses */
	g_assert_cmpint (nm_setting_ip_config_get_num_addresses (s_ip4), ==, 3);

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

static void
test_read_wired_ipv6_manual (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	char *unmanaged = NULL;
	NMIPAddress *ip6_addr;
	NMIPRoute *ip6_route;

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*ignoring manual default route*");
	connection = _connection_from_file (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-ipv6-manual",
	                                    NULL, TYPE_ETHERNET, &unmanaged);
	g_test_assert_expected_messages ();
	g_assert (!unmanaged);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "System test-wired-ipv6-manual");

	/* ===== WIRED SETTING ===== */

	s_wired = nm_connection_get_setting_wired (connection);
	g_assert (s_wired);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);

	/* DNS Addresses */
	g_assert_cmpint (nm_setting_ip_config_get_num_dns (s_ip4), ==, 2);

	/* DNS search domains */
	g_assert_cmpint (nm_setting_ip_config_get_num_dns_searches (s_ip4), ==, 3);
	g_assert_cmpstr (nm_setting_ip_config_get_dns_search (s_ip4, 0), ==, "lorem.com");
	g_assert_cmpstr (nm_setting_ip_config_get_dns_search (s_ip4, 1), ==, "ipsum.org");
	g_assert_cmpstr (nm_setting_ip_config_get_dns_search (s_ip4, 2), ==, "dolor.edu");

	/* ===== IPv6 SETTING ===== */

	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	g_assert (s_ip6);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip6), ==, NM_SETTING_IP6_CONFIG_METHOD_MANUAL);
	g_assert (!nm_setting_ip_config_get_never_default (s_ip6));
	g_assert (nm_setting_ip_config_get_may_fail (s_ip6));

	/* IP addresses */
	g_assert_cmpint (nm_setting_ip_config_get_num_addresses (s_ip6), ==, 3);

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
	g_assert_cmpint (nm_setting_ip_config_get_num_dns (s_ip6), ==, 2);
	g_assert_cmpstr (nm_setting_ip_config_get_dns (s_ip6, 0), ==, "1:2:3:4::a");
	g_assert_cmpstr (nm_setting_ip_config_get_dns (s_ip6, 1), ==, "1:2:3:4::b");

	/* DNS domains - none as domains are stuffed to 'ipv4' setting */
	g_assert_cmpint (nm_setting_ip_config_get_num_dns_searches (s_ip6), ==, 0);

	g_object_unref (connection);
}

static void
test_read_wired_ipv6_only (gconstpointer test_data)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	char *unmanaged = NULL;
	NMIPAddress *ip6_addr;
	const char *method;
	const char *file, *expected_id;

	nmtst_test_data_unpack (test_data, &file, &expected_id);

	g_assert (expected_id);

	connection = _connection_from_file (file, NULL, TYPE_ETHERNET, &unmanaged);
	g_assert (!unmanaged);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, expected_id);

	/* ===== WIRED SETTING ===== */

	s_wired = nm_connection_get_setting_wired (connection);
	g_assert (s_wired);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);

	method = nm_setting_ip_config_get_method (s_ip4);
	g_assert_cmpstr (method, ==, NM_SETTING_IP4_CONFIG_METHOD_DISABLED);

	/* ===== IPv6 SETTING ===== */

	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	g_assert (s_ip6);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip6), ==, NM_SETTING_IP6_CONFIG_METHOD_MANUAL);

	/* IP addresses */
	g_assert_cmpint (nm_setting_ip_config_get_num_addresses (s_ip6), ==, 1);

	/* Address #1 */
	ip6_addr = nm_setting_ip_config_get_address (s_ip6, 0);
	g_assert (ip6_addr != NULL);
	g_assert_cmpstr (nm_ip_address_get_address (ip6_addr), ==, "1001:abba::1234");
	g_assert_cmpint (nm_ip_address_get_prefix (ip6_addr), ==, 56);

	/* DNS Addresses */
	g_assert_cmpint (nm_setting_ip_config_get_num_dns (s_ip6), ==, 1);
	g_assert_cmpstr (nm_setting_ip_config_get_dns (s_ip6, 0), ==, "1:2:3:4::a");

	/* DNS domains should be in IPv6, because IPv4 is disabled */
	g_assert_cmpint (nm_setting_ip_config_get_num_dns_searches (s_ip6), ==, 3);
	g_assert_cmpstr (nm_setting_ip_config_get_dns_search (s_ip6, 0), ==, "lorem.com");
	g_assert_cmpstr (nm_setting_ip_config_get_dns_search (s_ip6, 1), ==, "ipsum.org");
	g_assert_cmpstr (nm_setting_ip_config_get_dns_search (s_ip6, 2), ==, "dolor.edu");

	g_object_unref (connection);
}

static void
test_read_wired_dhcp6_only (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	char *unmanaged = NULL;
	const char *method;

	connection = _connection_from_file (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-dhcp6-only", NULL, TYPE_ETHERNET, &unmanaged);
	g_assert (!unmanaged);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "System test-wired-dhcp6-only");

	/* ===== WIRED SETTING ===== */

	s_wired = nm_connection_get_setting_wired (connection);
	g_assert (s_wired);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);

	method = nm_setting_ip_config_get_method (s_ip4);
	g_assert_cmpstr (method, ==, NM_SETTING_IP4_CONFIG_METHOD_DISABLED);

	/* ===== IPv6 SETTING ===== */

	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	g_assert (s_ip6);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip6), ==, NM_SETTING_IP6_CONFIG_METHOD_DHCP);

	g_object_unref (connection);
}

static void
test_read_wired_autoip (void)
{
	gs_unref_object NMConnection *connection = NULL;
	NMSettingIPConfig *s_ip4;
	char *unmanaged = NULL;

	connection = _connection_from_file (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-wired-autoip",
	                                    NULL, TYPE_ETHERNET,
	                                    &unmanaged);
	g_assert (unmanaged == NULL);

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_LINK_LOCAL);
	g_assert (!nm_setting_ip_config_get_may_fail (s_ip4));
	g_assert (nm_setting_ip_config_get_ignore_auto_dns (s_ip4));
}

static void
test_read_onboot_no (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	char *unmanaged = NULL;

	connection = _connection_from_file (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-onboot-no", NULL, TYPE_ETHERNET, &unmanaged);
	g_assert (!unmanaged);

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);

	g_assert (!nm_setting_connection_get_autoconnect (s_con));

	g_object_unref (connection);
}

static void
test_read_noip (void)
{
	NMConnection *connection;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;

	connection = _connection_from_file (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-noip", NULL, TYPE_ETHERNET, NULL);

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

#define TEST_IFCFG_WIRED_8021x_PEAP_MSCHAPV2_CA_CERT TEST_IFCFG_DIR "/network-scripts/test_ca_cert.pem"

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
	gboolean success = FALSE;
	const char *expected_ca_cert_path;
	const char *read_ca_cert_path;

	connection = _connection_from_file (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-wired-8021x-peap-mschapv2",
	                                    NULL, TYPE_ETHERNET, &unmanaged);
	g_assert (!unmanaged);

	/* ===== WIRED SETTING ===== */

	s_wired = nm_connection_get_setting_wired (connection);
	g_assert (s_wired);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_AUTO);

	/* ===== 802.1x SETTING ===== */
	s_8021x = nm_connection_get_setting_802_1x (connection);
	g_assert (s_8021x);

	g_assert_cmpint (nm_setting_802_1x_get_num_eap_methods (s_8021x), ==, 1);
	g_assert_cmpstr (nm_setting_802_1x_get_eap_method (s_8021x, 0), ==, "peap");
	g_assert_cmpstr (nm_setting_802_1x_get_identity (s_8021x), ==, "David Smith");
	g_assert_cmpstr (nm_setting_802_1x_get_anonymous_identity (s_8021x), ==, "somebody");
	g_assert_cmpstr (nm_setting_802_1x_get_password (s_8021x), ==, "foobar baz");
	g_assert_cmpstr (nm_setting_802_1x_get_phase1_peapver (s_8021x), ==, "1");
	g_assert_cmpstr (nm_setting_802_1x_get_phase1_peaplabel (s_8021x), ==, "1");

	/* CA Cert */
	tmp_8021x = (NMSetting8021x *) nm_setting_802_1x_new ();

	success = nm_setting_802_1x_set_ca_cert (tmp_8021x,
	                                         TEST_IFCFG_WIRED_8021x_PEAP_MSCHAPV2_CA_CERT,
	                                         NM_SETTING_802_1X_CK_SCHEME_PATH,
	                                         NULL,
	                                         &error);
	g_assert_no_error (error);
	g_assert (success == TRUE);

	expected_ca_cert_path = nm_setting_802_1x_get_ca_cert_path (tmp_8021x);
	g_assert (expected_ca_cert_path);

	read_ca_cert_path = nm_setting_802_1x_get_ca_cert_path (s_8021x);
	g_assert (read_ca_cert_path);

	g_assert_cmpstr (read_ca_cert_path, ==, expected_ca_cert_path);

	g_object_unref (tmp_8021x);

	g_object_unref (connection);
}

static void
test_read_wired_8021x_tls_secret_flags (gconstpointer test_data)
{
	NMConnection *connection;
	NMSettingWired *s_wired;
	NMSetting8021x *s_8021x;
	char *dirname, *tmp;
	const char *ifcfg;
	gpointer expected_flags_p;

	nmtst_test_data_unpack (test_data, &ifcfg, &expected_flags_p);

	connection = _connection_from_file (ifcfg, NULL, TYPE_ETHERNET, NULL);

	/* ===== WIRED SETTING ===== */
	s_wired = nm_connection_get_setting_wired (connection);
	g_assert (s_wired);

	/* ===== 802.1x SETTING ===== */
	s_8021x = nm_connection_get_setting_802_1x (connection);
	g_assert (s_8021x);
	g_assert_cmpint (nm_setting_802_1x_get_num_eap_methods (s_8021x), ==, 1);
	g_assert_cmpstr (nm_setting_802_1x_get_eap_method (s_8021x, 0), ==, "tls");
	g_assert_cmpstr (nm_setting_802_1x_get_identity (s_8021x), ==, "David Smith");
	g_assert_cmpint (nm_setting_802_1x_get_private_key_password_flags (s_8021x), ==, GPOINTER_TO_INT (expected_flags_p));

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

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*missing IEEE_8021X_CA_CERT*peap*");
	connection = _connection_from_file (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-802-1X-subj-matches",
	                                    NULL, TYPE_ETHERNET, NULL);
	g_test_assert_expected_messages ();

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

	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR "/network-scripts/",
	                        &written);

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*missing IEEE_8021X_CA_CERT*peap*");
	reread = _connection_from_file (written, NULL, TYPE_ETHERNET, NULL);
	g_test_assert_expected_messages ();
	unlink (written);
	g_free (written);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

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

	/* Test that EAP-* inner methods are correctly read into the
	 * NMSetting8021x::autheap property.
	 */

	connection = _connection_from_file (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-802-1x-ttls-eapgtc",
	                                    NULL, TYPE_WIRELESS, NULL);

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

static void
test_read_wired_aliases_good (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingIPConfig *s_ip4;
	int expected_num_addresses = 4;
	const char *expected_address[4] = { "192.168.1.5", "192.168.1.6", "192.168.1.9", "192.168.1.99" };
	const char *expected_label[4] = { NULL, "aliasem0:1", "aliasem0:2", "aliasem0:99" };
	int i, j;

	connection = _connection_from_file (TEST_IFCFG_DIR "/network-scripts/ifcfg-aliasem0",
	                                    NULL, TYPE_ETHERNET, NULL);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "System aliasem0");

	/* ===== IPv4 SETTING ===== */

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_MANUAL);
	g_assert_cmpint (nm_setting_ip_config_get_num_addresses (s_ip4), ==, expected_num_addresses);

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
	g_assert_cmpstr (nm_setting_ip_config_get_gateway (s_ip4), ==, "192.168.1.1");

	for (i = 0; i < expected_num_addresses; i++)
		g_assert (!expected_address[i]);

	g_object_unref (connection);
}

static void
test_read_wired_aliases_bad (const char *base, const char *expected_id)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingIPConfig *s_ip4;
	NMIPAddress *ip4_addr;

	g_assert (expected_id);

	connection = _connection_from_file (base, NULL, TYPE_ETHERNET, NULL);
	g_test_assert_expected_messages ();

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, expected_id);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_MANUAL);

	g_assert_cmpint (nm_setting_ip_config_get_num_addresses (s_ip4), ==, 1);

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

static void
test_read_wired_aliases_bad_1 (void)
{
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*aliasem1:1*has no DEVICE*");
	test_read_wired_aliases_bad (TEST_IFCFG_DIR "/network-scripts/ifcfg-aliasem1", "System aliasem1");
}

static void
test_read_wired_aliases_bad_2 (void)
{
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*aliasem2:1*has invalid DEVICE*");
	test_read_wired_aliases_bad (TEST_IFCFG_DIR "/network-scripts/ifcfg-aliasem2", "System aliasem2");
}

static void
test_read_dns_options (void)
{
	NMConnection *connection;
	NMSettingIPConfig *s_ip4, *s_ip6;
	char *unmanaged = NULL;
	const char *option;
	const char *options[] = { "ndots:3", "single-request-reopen", "inet6" };
	guint32 i, options_len = sizeof (options) / sizeof (options[0]);

	connection = _connection_from_file (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-dns-options",
	                                    NULL, TYPE_ETHERNET, &unmanaged);
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

	nmtst_assert_connection_verifies (connection);

	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR "/network-scripts/",
	                        &testfile);

	reread = _connection_from_file (testfile, NULL, TYPE_ETHERNET, NULL);
	unlink (testfile);

	/* RES_OPTIONS is copied to both IPv4 and IPv6 settings */
	nm_setting_ip_config_clear_dns_options (s_ip4, TRUE);
	nm_setting_ip_config_add_dns_option (s_ip4, "debug");
	nm_setting_ip_config_add_dns_option (s_ip4, "timeout:3");

	nm_setting_ip_config_clear_dns_options (s_ip6, TRUE);
	nm_setting_ip_config_add_dns_option (s_ip6, "debug");
	nm_setting_ip_config_add_dns_option (s_ip6, "timeout:3");

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

	g_free (testfile);
	g_object_unref (connection);
	g_object_unref (reread);
}

static void
test_read_wifi_open (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	NMSettingWirelessSecurity *s_wsec;
	NMSettingIPConfig *s_ip4, *s_ip6;
	GBytes *ssid;
	const char *mac;
	char expected_mac_address[ETH_ALEN] = { 0x00, 0x16, 0x41, 0x11, 0x22, 0x33 };
	const char *expected_ssid = "blahblah";

	connection = _connection_from_file (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-wifi-open",
	                                    NULL, TYPE_WIRELESS, NULL);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "System blahblah (test-wifi-open)");

	/* UUID can't be tested if the ifcfg does not contain the UUID key, because
	 * the UUID is generated on the full path of the ifcfg file, which can change
	 * depending on where the tests are run.
	 */

	g_assert_cmpint (nm_setting_connection_get_timestamp (s_con), ==, 0);
	g_assert (nm_setting_connection_get_autoconnect (s_con));
	g_assert_cmpint (nm_setting_connection_get_autoconnect_priority (s_con), ==, -1);

	/* ===== WIRELESS SETTING ===== */

	s_wireless = nm_connection_get_setting_wireless (connection);
	g_assert (s_wireless);

	/* MAC address */
	mac = nm_setting_wireless_get_mac_address (s_wireless);
	g_assert (mac);
	g_assert (nm_utils_hwaddr_matches (mac, -1, expected_mac_address, sizeof (expected_mac_address)));

	g_assert_cmpint (nm_setting_wireless_get_mtu (s_wireless), ==, 0);

	ssid = nm_setting_wireless_get_ssid (s_wireless);
	g_assert (ssid);
	g_assert_cmpmem (g_bytes_get_data (ssid, NULL), g_bytes_get_size (ssid), expected_ssid, strlen (expected_ssid));

	g_assert (!nm_setting_wireless_get_bssid (s_wireless));
	g_assert_cmpstr (nm_setting_wireless_get_mode (s_wireless), ==, "infrastructure");
	g_assert_cmpint (nm_setting_wireless_get_channel (s_wireless), ==, 1);

	/* ===== WiFi SECURITY SETTING ===== */
	s_wsec = nm_connection_get_setting_wireless_security (connection);
	g_assert (s_wsec == NULL);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpint (nm_setting_ip_config_get_route_metric (s_ip4), ==, 104);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_AUTO);

	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	g_assert( s_ip6);
	g_assert_cmpint (nm_setting_ip_config_get_route_metric (s_ip6), ==, 106);

	g_object_unref (connection);
}

static void
test_read_wifi_open_auto (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;

	connection = _connection_from_file (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-wifi-open-auto",
	                                    NULL, TYPE_WIRELESS, NULL);

	/* ===== CONNECTION SETTING ===== */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "System blahblah (test-wifi-open-auto)");

	/* ===== WIRELESS SETTING ===== */
	s_wireless = nm_connection_get_setting_wireless (connection);
	g_assert (s_wireless);
	g_assert_cmpstr (nm_setting_wireless_get_mode (s_wireless), ==, "infrastructure");

	g_object_unref (connection);
}

static void
test_read_wifi_open_ssid_hex (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	GBytes *ssid;
	const char *expected_ssid = "blahblah";

	connection = _connection_from_file (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-wifi-open-ssid-hex",
	                                    NULL, TYPE_WIRELESS, NULL);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "System blahblah (test-wifi-open-ssid-hex)");

	/* ===== WIRELESS SETTING ===== */

	s_wireless = nm_connection_get_setting_wireless (connection);
	g_assert (s_wireless);

	ssid = nm_setting_wireless_get_ssid (s_wireless);
	g_assert (ssid);
	g_assert_cmpmem (g_bytes_get_data (ssid, NULL), g_bytes_get_size (ssid), expected_ssid, strlen (expected_ssid));

	g_object_unref (connection);
}

static void
test_read_wifi_open_ssid_bad (gconstpointer data)
{
	_connection_from_file_fail ((const char *) data, NULL, TYPE_WIRELESS, NULL);
}

static void
test_read_wifi_open_ssid_quoted (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	GBytes *ssid;
	const char *expected_ssid = "foo\"bar\\";

	connection = _connection_from_file (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-wifi-open-ssid-quoted",
	                                    NULL, TYPE_WIRELESS, NULL);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "System foo\"bar\\ (test-wifi-open-ssid-quoted)");

	/* ===== WIRELESS SETTING ===== */

	s_wireless = nm_connection_get_setting_wireless (connection);
	g_assert (s_wireless);

	ssid = nm_setting_wireless_get_ssid (s_wireless);
	g_assert (ssid);
	g_assert_cmpmem (g_bytes_get_data (ssid, NULL), g_bytes_get_size (ssid), expected_ssid, strlen (expected_ssid));

	g_object_unref (connection);
}

static void
test_read_wifi_wep (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	NMSettingWirelessSecurity *s_wsec;
	NMSettingIPConfig *s_ip4;
	GBytes *ssid;
	const char *mac;
	char expected_mac_address[ETH_ALEN] = { 0x00, 0x16, 0x41, 0x11, 0x22, 0x33 };
	const char *expected_ssid = "blahblah";
	NMWepKeyType key_type;

	connection = _connection_from_file (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-wifi-wep",
	                                    NULL, TYPE_WIRELESS, NULL);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "System blahblah (test-wifi-wep)");

	/* UUID can't be tested if the ifcfg does not contain the UUID key, because
	 * the UUID is generated on the full path of the ifcfg file, which can change
	 * depending on where the tests are run.
	 */

	g_assert_cmpint (nm_setting_connection_get_timestamp (s_con), ==, 0);
	g_assert (nm_setting_connection_get_autoconnect (s_con));

	/* ===== WIRELESS SETTING ===== */

	s_wireless = nm_connection_get_setting_wireless (connection);
	g_assert (s_wireless);

	/* MAC address */
	mac = nm_setting_wireless_get_mac_address (s_wireless);
	g_assert (mac);
	g_assert (nm_utils_hwaddr_matches (mac, -1, expected_mac_address, sizeof (expected_mac_address)));

	/* MTU */
	g_assert_cmpint (nm_setting_wireless_get_mtu (s_wireless), ==, 0);

	ssid = nm_setting_wireless_get_ssid (s_wireless);
	g_assert (ssid);
	g_assert_cmpmem (g_bytes_get_data (ssid, NULL), g_bytes_get_size (ssid), expected_ssid, strlen (expected_ssid));

	g_assert (!nm_setting_wireless_get_bssid (s_wireless));
	g_assert_cmpstr (nm_setting_wireless_get_mode (s_wireless), ==, "infrastructure");
	g_assert_cmpint (nm_setting_wireless_get_channel (s_wireless), ==, 1);

	/* ===== WIRELESS SECURITY SETTING ===== */

	s_wsec = nm_connection_get_setting_wireless_security (connection);
	g_assert (s_wsec);
	g_assert_cmpstr (nm_setting_wireless_security_get_key_mgmt (s_wsec), ==, "none");
	g_assert_cmpstr (nm_setting_wireless_security_get_auth_alg (s_wsec), ==, "shared");
	g_assert_cmpint (nm_setting_wireless_security_get_wep_tx_keyidx (s_wsec), ==, 0);

	key_type = nm_setting_wireless_security_get_wep_key_type (s_wsec);
	g_assert (key_type == NM_WEP_KEY_TYPE_UNKNOWN || key_type == NM_WEP_KEY_TYPE_KEY);

	g_assert_cmpstr (nm_setting_wireless_security_get_wep_key (s_wsec, 0), ==, "0123456789abcdef0123456789");
	g_assert (!nm_setting_wireless_security_get_wep_key (s_wsec, 1));
	g_assert (!nm_setting_wireless_security_get_wep_key (s_wsec, 2));
	g_assert (!nm_setting_wireless_security_get_wep_key (s_wsec, 3));

	/* ===== IPv4 SETTING ===== */

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_AUTO);

	g_object_unref (connection);
}

static void
test_read_wifi_wep_adhoc (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	NMSettingWirelessSecurity *s_wsec;
	NMSettingIPConfig *s_ip4;
	GBytes *ssid;
	const char *expected_ssid = "blahblah";

	connection = _connection_from_file (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-wifi-wep-adhoc",
	                                    NULL, TYPE_WIRELESS, NULL);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "System blahblah (test-wifi-wep-adhoc)");

	/* UUID can't be tested if the ifcfg does not contain the UUID key, because
	 * the UUID is generated on the full path of the ifcfg file, which can change
	 * depending on where the tests are run.
	 */

	g_assert (!nm_setting_connection_get_autoconnect (s_con));

	/* ===== WIRELESS SETTING ===== */

	s_wireless = nm_connection_get_setting_wireless (connection);
	g_assert (s_wireless);

	ssid = nm_setting_wireless_get_ssid (s_wireless);
	g_assert (ssid);
	g_assert_cmpmem (g_bytes_get_data (ssid, NULL), g_bytes_get_size (ssid), expected_ssid, strlen (expected_ssid));

	g_assert (!nm_setting_wireless_get_bssid (s_wireless));
	g_assert_cmpstr (nm_setting_wireless_get_mode (s_wireless), ==, "adhoc");
	g_assert_cmpint (nm_setting_wireless_get_channel (s_wireless), ==, 11);

	/* ===== WIRELESS SECURITY SETTING ===== */

	s_wsec = nm_connection_get_setting_wireless_security (connection);
	g_assert (s_wsec);
	g_assert_cmpstr (nm_setting_wireless_security_get_key_mgmt (s_wsec), ==, "none");
	g_assert (!nm_setting_wireless_security_get_auth_alg (s_wsec));
	g_assert_cmpint (nm_setting_wireless_security_get_wep_tx_keyidx (s_wsec), ==, 0);

	g_assert_cmpstr (nm_setting_wireless_security_get_wep_key (s_wsec, 0), ==, "0123456789abcdef0123456789");
	g_assert (!nm_setting_wireless_security_get_wep_key (s_wsec, 1));
	g_assert (!nm_setting_wireless_security_get_wep_key (s_wsec, 2));
	g_assert (!nm_setting_wireless_security_get_wep_key (s_wsec, 3));

	/* ===== IPv4 SETTING ===== */

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_AUTO);

	/* Ignore auto DNS */
	g_assert (nm_setting_ip_config_get_ignore_auto_dns (s_ip4));

	/* DNS Addresses */
	g_assert_cmpint (nm_setting_ip_config_get_num_dns (s_ip4), ==, 2);
	g_assert_cmpstr (nm_setting_ip_config_get_dns (s_ip4, 0), ==, "4.2.2.1");
	g_assert_cmpstr (nm_setting_ip_config_get_dns (s_ip4, 1), ==, "4.2.2.2");

	g_object_unref (connection);
}

static void
test_read_wifi_wep_passphrase (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	NMSettingWirelessSecurity *s_wsec;

	connection = _connection_from_file (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-wifi-wep-passphrase",
	                                    NULL, TYPE_WIRELESS, NULL);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);

	/* ===== WIRELESS SETTING ===== */

	s_wireless = nm_connection_get_setting_wireless (connection);
	g_assert (s_wireless);

	/* ===== WIRELESS SECURITY SETTING ===== */

	s_wsec = nm_connection_get_setting_wireless_security (connection);
	g_assert (s_wsec);
	g_assert_cmpstr (nm_setting_wireless_security_get_key_mgmt (s_wsec), ==, "none");
	g_assert_cmpint (nm_setting_wireless_security_get_wep_tx_keyidx (s_wsec), ==, 0);
	g_assert_cmpint (nm_setting_wireless_security_get_wep_key_type (s_wsec), ==, NM_WEP_KEY_TYPE_PASSPHRASE);
	g_assert_cmpstr (nm_setting_wireless_security_get_wep_key (s_wsec, 0), ==, "foobar222blahblah");
	g_assert (!nm_setting_wireless_security_get_wep_key (s_wsec, 1));
	g_assert (!nm_setting_wireless_security_get_wep_key (s_wsec, 2));
	g_assert (!nm_setting_wireless_security_get_wep_key (s_wsec, 3));

	g_object_unref (connection);
}

static void
test_read_wifi_wep_40_ascii (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	NMSettingWirelessSecurity *s_wsec;
	NMWepKeyType key_type;

	connection = _connection_from_file (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-wifi-wep-40-ascii",
	                                    NULL, TYPE_WIRELESS, NULL);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);

	/* ===== WIRELESS SETTING ===== */

	s_wireless = nm_connection_get_setting_wireless (connection);
	g_assert (s_wireless);

	/* ===== WIRELESS SECURITY SETTING ===== */

	s_wsec = nm_connection_get_setting_wireless_security (connection);
	g_assert (s_wsec);
	g_assert_cmpstr (nm_setting_wireless_security_get_key_mgmt (s_wsec), ==, "none");
	g_assert_cmpint (nm_setting_wireless_security_get_wep_tx_keyidx (s_wsec), ==, 0);

	key_type = nm_setting_wireless_security_get_wep_key_type (s_wsec);
	g_assert (key_type == NM_WEP_KEY_TYPE_UNKNOWN || key_type == NM_WEP_KEY_TYPE_KEY);

	g_assert_cmpstr (nm_setting_wireless_security_get_wep_key (s_wsec, 0), ==, "Lorem");
	g_assert (!nm_setting_wireless_security_get_wep_key (s_wsec, 1));
	g_assert (!nm_setting_wireless_security_get_wep_key (s_wsec, 2));
	g_assert (!nm_setting_wireless_security_get_wep_key (s_wsec, 3));

	g_object_unref (connection);
}

static void
test_read_wifi_wep_104_ascii (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	NMSettingWirelessSecurity *s_wsec;
	NMWepKeyType key_type;

	connection = _connection_from_file (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-wifi-wep-104-ascii",
	                                    NULL, TYPE_WIRELESS, NULL);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);

	/* ===== WIRELESS SETTING ===== */

	s_wireless = nm_connection_get_setting_wireless (connection);
	g_assert (s_wireless);

	/* ===== WIRELESS SECURITY SETTING ===== */

	s_wsec = nm_connection_get_setting_wireless_security (connection);
	g_assert (s_wsec);
	g_assert_cmpstr (nm_setting_wireless_security_get_key_mgmt (s_wsec), ==, "none");
	g_assert_cmpint (nm_setting_wireless_security_get_wep_tx_keyidx (s_wsec), ==, 0);

	key_type = nm_setting_wireless_security_get_wep_key_type (s_wsec);
	g_assert (key_type == NM_WEP_KEY_TYPE_UNKNOWN || key_type == NM_WEP_KEY_TYPE_KEY);

	g_assert_cmpstr (nm_setting_wireless_security_get_wep_key (s_wsec, 0), ==, "LoremIpsumSit");
	g_assert (!nm_setting_wireless_security_get_wep_key (s_wsec, 1));
	g_assert (!nm_setting_wireless_security_get_wep_key (s_wsec, 2));
	g_assert (!nm_setting_wireless_security_get_wep_key (s_wsec, 3));

	g_object_unref (connection);
}

static void
test_read_wifi_leap (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	NMSettingWirelessSecurity *s_wsec;

	connection = _connection_from_file (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-wifi-leap",
	                                    NULL, TYPE_WIRELESS, NULL);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "System blahblah (test-wifi-leap)");

	/* ===== WIRELESS SETTING ===== */

	s_wireless = nm_connection_get_setting_wireless (connection);
	g_assert (s_wireless);

	/* ===== WIRELESS SECURITY SETTING ===== */

	s_wsec = nm_connection_get_setting_wireless_security (connection);
	g_assert (s_wsec);
	g_assert_cmpstr (nm_setting_wireless_security_get_key_mgmt (s_wsec), ==, "ieee8021x");
	g_assert_cmpstr (nm_setting_wireless_security_get_auth_alg (s_wsec), ==, "leap");
	g_assert_cmpstr (nm_setting_wireless_security_get_leap_username (s_wsec), ==, "Bill Smith");
	g_assert_cmpstr (nm_setting_wireless_security_get_leap_password (s_wsec), ==, "foobarblah");

	g_object_unref (connection);
}

static void
test_read_wifi_leap_secret_flags (gconstpointer test_data)
{
	NMConnection *connection;
	NMSettingWireless *s_wifi;
	NMSettingWirelessSecurity *s_wsec;
	const char *file;
	gpointer expected_flags_p;

	nmtst_test_data_unpack (test_data, &file, &expected_flags_p);

	connection = _connection_from_file (file, NULL, TYPE_WIRELESS, NULL);

	/* ===== WIRELESS SETTING ===== */
	s_wifi = nm_connection_get_setting_wireless (connection);
	g_assert (s_wifi);

	/* ===== WIRELESS SECURITY SETTING ===== */
	s_wsec = nm_connection_get_setting_wireless_security (connection);
	g_assert (s_wsec);

	g_assert (g_strcmp0 (nm_setting_wireless_security_get_key_mgmt (s_wsec), "ieee8021x") == 0);
	g_assert (g_strcmp0 (nm_setting_wireless_security_get_auth_alg (s_wsec), "leap") == 0);
	g_assert (g_strcmp0 (nm_setting_wireless_security_get_leap_username (s_wsec), "Bill Smith") == 0);
	/* password blank as it's not system-owned */
	g_assert (nm_setting_wireless_security_get_leap_password_flags (s_wsec) == GPOINTER_TO_INT (expected_flags_p));
	g_assert (nm_setting_wireless_security_get_leap_password (s_wsec) == NULL);

	g_object_unref (connection);
}

static void
test_read_wifi_wpa_psk (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	NMSettingWirelessSecurity *s_wsec;
	NMSettingIPConfig *s_ip4;
	GBytes *ssid;
	const char *mac;
	char expected_mac_address[ETH_ALEN] = { 0x00, 0x16, 0x41, 0x11, 0x22, 0x33 };
	const char *expected_ssid = "blahblah";
	guint32 n, i;
	gboolean found_pair_tkip = FALSE;
	gboolean found_pair_ccmp = FALSE;
	gboolean found_group_tkip = FALSE;
	gboolean found_group_ccmp = FALSE;
	gboolean found_group_wep40 = FALSE;
	gboolean found_group_wep104 = FALSE;
	gboolean found_proto_wpa = FALSE;
	gboolean found_proto_rsn = FALSE;

	connection = _connection_from_file (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-wifi-wpa-psk",
	                                    NULL, TYPE_WIRELESS, NULL);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "System blahblah (test-wifi-wpa-psk)");

	/* UUID can't be tested if the ifcfg does not contain the UUID key, because
	 * the UUID is generated on the full path of the ifcfg file, which can change
	 * depending on where the tests are run.
	 */

	g_assert_cmpint (nm_setting_connection_get_timestamp (s_con), ==, 0);
	g_assert (nm_setting_connection_get_autoconnect (s_con));

	/* ===== WIRELESS SETTING ===== */

	s_wireless = nm_connection_get_setting_wireless (connection);
	g_assert (s_wireless);

	mac = nm_setting_wireless_get_mac_address (s_wireless);
	g_assert (mac);
	g_assert (nm_utils_hwaddr_matches (mac, -1, expected_mac_address, sizeof (expected_mac_address)));

	g_assert_cmpint (nm_setting_wireless_get_mtu (s_wireless), ==, 0);

	ssid = nm_setting_wireless_get_ssid (s_wireless);
	g_assert (ssid);
	g_assert_cmpmem (g_bytes_get_data (ssid, NULL), g_bytes_get_size (ssid), expected_ssid, strlen (expected_ssid));

	g_assert (!nm_setting_wireless_get_bssid (s_wireless));
	g_assert_cmpstr (nm_setting_wireless_get_mode (s_wireless), ==, "infrastructure");
	g_assert_cmpint (nm_setting_wireless_get_channel (s_wireless), ==, 1);

	/* ===== WIRELESS SECURITY SETTING ===== */

	s_wsec = nm_connection_get_setting_wireless_security (connection);
	g_assert (s_wsec);
	g_assert_cmpstr (nm_setting_wireless_security_get_key_mgmt (s_wsec), ==, "wpa-psk");
	g_assert_cmpstr (nm_setting_wireless_security_get_psk (s_wsec), ==, "I wonder what the king is doing tonight?");
	g_assert (!nm_setting_wireless_security_get_auth_alg (s_wsec));

	/* Pairwise ciphers */
	n = nm_setting_wireless_security_get_num_pairwise (s_wsec);
	g_assert_cmpint (n, ==, 2);
	for (i = 0; i < n; i++) {
		const char * tmp = nm_setting_wireless_security_get_pairwise (s_wsec, i);
		g_assert (tmp);
		if (strcmp (tmp, "tkip") == 0)
			found_pair_tkip = TRUE;
		else if (strcmp (tmp, "ccmp") == 0)
			found_pair_ccmp = TRUE;
	}
	g_assert (found_pair_tkip);
	g_assert (found_pair_ccmp);

	/* Group ciphers */
	n = nm_setting_wireless_security_get_num_groups (s_wsec);
	g_assert_cmpint (n, ==, 4);
	for (i = 0; i < n; i++) {
		const char *tmp = nm_setting_wireless_security_get_group (s_wsec, i);
		g_assert (tmp);
		if (strcmp (tmp, "tkip") == 0)
			found_group_tkip = TRUE;
		else if (strcmp (tmp, "ccmp") == 0)
			found_group_ccmp = TRUE;
		else if (strcmp (tmp, "wep40") == 0)
			found_group_wep40 = TRUE;
		else if (strcmp (tmp, "wep104") == 0)
			found_group_wep104 = TRUE;
	}
	g_assert (found_group_tkip);
	g_assert (found_group_ccmp);
	g_assert (found_group_wep40);
	g_assert (found_group_wep104);

	/* Protocols */
	n = nm_setting_wireless_security_get_num_protos (s_wsec);
	g_assert_cmpint (n, ==, 2);
	for (i = 0; i < n; i++) {
		const char *tmp = nm_setting_wireless_security_get_proto (s_wsec, i);
		g_assert (tmp);
		if (strcmp (tmp, "wpa") == 0)
			found_proto_wpa = TRUE;
		else if (strcmp (tmp, "rsn") == 0)
			found_proto_rsn = TRUE;
	}
	g_assert (found_proto_wpa);
	g_assert (found_proto_rsn);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_AUTO);

	g_object_unref (connection);
}

static void
test_read_wifi_wpa_psk_2 (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	NMSettingWirelessSecurity *s_wsec;

	connection = _connection_from_file (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-wifi-wpa-psk-2",
	                                    NULL, TYPE_WIRELESS, NULL);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "System ipsum (test-wifi-wpa-psk-2)");

	/* ===== WIRELESS SETTING ===== */

	s_wireless = nm_connection_get_setting_wireless (connection);
	g_assert (s_wireless);

	/* ===== WIRELESS SECURITY SETTING ===== */

	s_wsec = nm_connection_get_setting_wireless_security (connection);
	g_assert (s_wsec);
	g_assert_cmpstr (nm_setting_wireless_security_get_psk (s_wsec), ==, "They're really saying I love you. >>`<< \\");

	g_object_unref (connection);
}

static void
test_read_wifi_wpa_psk_unquoted (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	NMSettingWirelessSecurity *s_wsec;

	connection = _connection_from_file (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-wifi-wpa-psk-unquoted",
	                                    NULL, TYPE_WIRELESS, NULL);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "System blahblah (test-wifi-wpa-psk-unquoted)");

	/* ===== WIRELESS SETTING ===== */

	s_wireless = nm_connection_get_setting_wireless (connection);
	g_assert (s_wireless);

	/* ===== WIRELESS SECURITY SETTING ===== */

	s_wsec = nm_connection_get_setting_wireless_security (connection);
	g_assert (s_wsec);
	g_assert_cmpstr (nm_setting_wireless_security_get_psk (s_wsec), ==, "54336845e2f3f321c4c7");

	g_object_unref (connection);
}

static void
test_read_wifi_wpa_psk_unquoted2 (void)
{
	/* Ensure a quoted 64-character WPA passphrase will fail since passphrases
	 * must be between 8 and 63 ASCII characters inclusive per the WPA spec.
	 */

	_connection_from_file_fail (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-wifi-wpa-psk-unquoted2",
	                            NULL, TYPE_WIRELESS, NULL);
}

static void
test_read_wifi_wpa_psk_adhoc (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	NMSettingWirelessSecurity *s_wsec;
	NMSettingIPConfig *s_ip4;

	connection = _connection_from_file(TEST_IFCFG_DIR "/network-scripts/ifcfg-test-wifi-wpa-psk-adhoc",
	                                   NULL, TYPE_WIRELESS, NULL);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "System blahblah (test-wifi-wpa-psk-adhoc)");

	/* ===== WIRELESS SETTING ===== */

	s_wireless = nm_connection_get_setting_wireless (connection);
	g_assert (s_wireless);

	g_assert_cmpstr (nm_setting_wireless_get_mode (s_wireless), ==, "adhoc");

	/* ===== WIRELESS SECURITY SETTING ===== */

	s_wsec = nm_connection_get_setting_wireless_security (connection);
	g_assert (s_wsec);
	g_assert_cmpstr (nm_setting_wireless_security_get_key_mgmt (s_wsec), ==, "wpa-none");
	g_assert_cmpstr (nm_setting_wireless_security_get_psk (s_wsec), ==, "I wonder what the king is doing tonight?");

	/* Pairwise cipher is unused in adhoc mode */
	g_assert_cmpint (nm_setting_wireless_security_get_num_pairwise (s_wsec), ==, 0);

	g_assert_cmpint (nm_setting_wireless_security_get_num_groups (s_wsec), ==, 1);
	g_assert_cmpstr (nm_setting_wireless_security_get_group (s_wsec, 0), ==, "ccmp");

	g_assert_cmpint (nm_setting_wireless_security_get_num_protos (s_wsec), ==, 1);
	g_assert_cmpstr (nm_setting_wireless_security_get_proto (s_wsec, 0), ==, "wpa");

	/* ===== IPv4 SETTING ===== */

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_AUTO);

	g_object_unref (connection);
}

static void
test_read_wifi_wpa_psk_hex (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	NMSettingWirelessSecurity *s_wsec;
	NMSettingIPConfig *s_ip4;
	GBytes *ssid;
	const char *expected_ssid = "blahblah";

	connection = _connection_from_file (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-wifi-wpa-psk-hex",
	                                    NULL, TYPE_WIRELESS, NULL);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "System blahblah (test-wifi-wpa-psk-hex)");

	/* ===== WIRELESS SETTING ===== */

	s_wireless = nm_connection_get_setting_wireless (connection);
	g_assert (s_wireless);

	ssid = nm_setting_wireless_get_ssid (s_wireless);
	g_assert (ssid);
	g_assert_cmpint (g_bytes_get_size (ssid), ==, strlen (expected_ssid));
	g_assert (memcmp (g_bytes_get_data (ssid, NULL), expected_ssid, strlen (expected_ssid)) == 0);

	/* ===== WIRELESS SECURITY SETTING ===== */

	s_wsec = nm_connection_get_setting_wireless_security (connection);
	g_assert (s_wsec);
	g_assert_cmpstr (nm_setting_wireless_security_get_key_mgmt (s_wsec), ==, "wpa-psk");
	g_assert_cmpstr (nm_setting_wireless_security_get_psk (s_wsec), ==, "1da190379817bc360dda52e85c388c439a21ea5c7bf819c64e9da051807deae6");

	/* ===== IPv4 SETTING ===== */

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_AUTO);

	g_object_unref (connection);
}

#define TEST_IFCFG_WIFI_WPA_EAP_TLS_CA_CERT TEST_IFCFG_DIR "/network-scripts/test_ca_cert.pem"
#define TEST_IFCFG_WIFI_WPA_EAP_TLS_CLIENT_CERT TEST_IFCFG_DIR "/network-scripts/test1_key_and_cert.pem"
#define TEST_IFCFG_WIFI_WPA_EAP_TLS_PRIVATE_KEY TEST_IFCFG_DIR "/network-scripts/test1_key_and_cert.pem"

static void
test_read_wifi_wpa_eap_tls (void)
{
	NMConnection *connection;
	NMSettingWireless *s_wireless;
	NMSettingIPConfig *s_ip4;
	NMSetting8021x *s_8021x;
	char *unmanaged = NULL;
	const char *expected_privkey_password = "test1";

	connection = _connection_from_file (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-wifi-wpa-eap-tls",
	                                    NULL, TYPE_ETHERNET, &unmanaged);
	g_assert (!unmanaged);

	/* ===== WIRELESS SETTING ===== */

	s_wireless = nm_connection_get_setting_wireless (connection);
	g_assert (s_wireless);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_AUTO);

	/* ===== 802.1x SETTING ===== */
	s_8021x = nm_connection_get_setting_802_1x (connection);
	g_assert (s_8021x);
	g_assert_cmpint (nm_setting_802_1x_get_num_eap_methods (s_8021x), ==, 1);
	g_assert_cmpstr (nm_setting_802_1x_get_eap_method (s_8021x, 0), ==, "tls");
	g_assert_cmpstr (nm_setting_802_1x_get_identity (s_8021x), ==, "Bill Smith");

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
	g_assert_cmpstr (nm_setting_802_1x_get_private_key_password (s_8021x), ==, expected_privkey_password);

	/* Private key */
	verify_cert_or_key (s_8021x,
	                    TEST_IFCFG_WIFI_WPA_EAP_TLS_PRIVATE_KEY,
	                    expected_privkey_password,
	                    NM_SETTING_802_1X_PRIVATE_KEY);

	g_object_unref (connection);
}

/* Also use TLS defines from the previous test */

static void
test_read_wifi_wpa_eap_ttls_tls (void)
{
	NMConnection *connection;
	NMSettingWireless *s_wireless;
	NMSettingIPConfig *s_ip4;
	NMSetting8021x *s_8021x;
	char *unmanaged = NULL;
	const char *expected_privkey_password = "test1";

	connection = _connection_from_file (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-wifi-wpa-eap-ttls-tls",
	                                    NULL, TYPE_WIRELESS, &unmanaged);
	g_assert (!unmanaged);

	/* ===== WIRELESS SETTING ===== */

	s_wireless = nm_connection_get_setting_wireless (connection);
	g_assert (s_wireless);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_AUTO);

	/* ===== 802.1x SETTING ===== */
	s_8021x = nm_connection_get_setting_802_1x (connection);
	g_assert (s_8021x);
	g_assert_cmpint (nm_setting_802_1x_get_num_eap_methods (s_8021x), ==, 1);
	g_assert_cmpstr (nm_setting_802_1x_get_eap_method (s_8021x, 0), ==, "ttls");
	g_assert_cmpstr (nm_setting_802_1x_get_identity (s_8021x), ==, "Chuck Shumer");

	/* CA Cert */
	verify_cert_or_key (s_8021x,
	                    TEST_IFCFG_DIR "/network-scripts/test_ca_cert.pem",
	                    NULL,
	                    NM_SETTING_802_1X_CA_CERT);

	/* Inner auth method */
	g_assert_cmpstr (nm_setting_802_1x_get_phase2_autheap (s_8021x), ==, "tls");

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
	g_assert_cmpstr (nm_setting_802_1x_get_phase2_private_key_password (s_8021x), ==, expected_privkey_password);

	/* Inner private key */
	verify_cert_or_key (s_8021x,
	                    TEST_IFCFG_WIFI_WPA_EAP_TLS_PRIVATE_KEY,
	                    expected_privkey_password,
	                    NM_SETTING_802_1X_PHASE2_PRIVATE_KEY);

	g_object_unref (connection);
}

static void
test_read_wifi_dynamic_wep_leap (void)
{
	NMConnection *connection;
	NMSettingWireless *s_wifi;
	NMSettingWirelessSecurity *s_wsec;
	NMSetting8021x *s_8021x;

	connection = _connection_from_file (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-wifi-dynamic-wep-leap",
	                                    NULL, TYPE_WIRELESS, NULL);

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

static void
test_read_wifi_wep_eap_ttls_chap (void)
{
	NMConnection *connection;
	NMSettingWireless *s_wireless;
	NMSettingWirelessSecurity *s_wsec;
	NMSettingIPConfig *s_ip4;
	NMSetting8021x *s_8021x;
	char *unmanaged = NULL;

	connection = _connection_from_file (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-wifi-wep-eap-ttls-chap",
	                                    NULL, TYPE_WIRELESS, &unmanaged);
	g_assert (!unmanaged);

	/* ===== WIRELESS SETTING ===== */

	s_wireless = nm_connection_get_setting_wireless (connection);
	g_assert (s_wireless);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_AUTO);

	/* ===== 802.1x SETTING ===== */
	s_wsec = nm_connection_get_setting_wireless_security (connection);
	g_assert (s_wsec);
	g_assert_cmpstr (nm_setting_wireless_security_get_key_mgmt (s_wsec), ==, "ieee8021x");

	/* ===== 802.1x SETTING ===== */
	s_8021x = nm_connection_get_setting_802_1x (connection);
	g_assert (s_8021x);

	/* EAP methods */
	g_assert_cmpint (nm_setting_802_1x_get_num_eap_methods (s_8021x), ==, 1);
	g_assert_cmpstr (nm_setting_802_1x_get_eap_method (s_8021x, 0), ==, "ttls");

	/* CA Cert */
	verify_cert_or_key (s_8021x,
	                    TEST_IFCFG_DIR "/network-scripts/test_ca_cert.pem",
	                    NULL,
	                    NM_SETTING_802_1X_CA_CERT);

	g_assert_cmpstr (nm_setting_802_1x_get_phase2_auth (s_8021x), ==, "chap");
	g_assert_cmpstr (nm_setting_802_1x_get_identity (s_8021x), ==, "David Smith");
	g_assert_cmpstr (nm_setting_802_1x_get_password (s_8021x), ==, "foobar baz");

	g_object_unref (connection);
}

static void
test_read_wired_wake_on_lan (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;

	connection = _connection_from_file (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-wake-on-lan",
	                                    NULL, TYPE_WIRELESS, NULL);

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_connection_type (s_con), ==, NM_SETTING_WIRED_SETTING_NAME);

	s_wired = nm_connection_get_setting_wired (connection);
	g_assert (s_wired);
	g_assert_cmpint (nm_setting_wired_get_wake_on_lan (s_wired),
	                 ==,
	                 NM_SETTING_WIRED_WAKE_ON_LAN_ARP |
	                 NM_SETTING_WIRED_WAKE_ON_LAN_PHY |
	                 NM_SETTING_WIRED_WAKE_ON_LAN_MAGIC);

	g_assert_cmpstr (nm_setting_wired_get_wake_on_lan_password (s_wired),
	                 ==,
	                 "00:11:22:33:44:55");

	g_object_unref (connection);
}

static void
test_read_wifi_hidden (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wifi;

	connection = _connection_from_file (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wifi-hidden",
	                                    NULL, TYPE_WIRELESS, NULL);

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

	nmtst_assert_connection_verifies (connection);

	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR "/network-scripts/",
	                        &testfile);

	f = svOpenFile (testfile, &error);
	g_assert_no_error (error);
	g_assert (f);

	/* re-read the file to check that what key was written. */
	val = svGetValue (f, "SSID_HIDDEN", FALSE);
	g_assert (val);
	g_assert_cmpstr (val, ==, "yes");
	g_free (val);
	svCloseFile (f);

	reread = _connection_from_file (testfile, NULL, TYPE_WIRELESS, NULL);
	unlink (testfile);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

	g_free (testfile);
	g_object_unref (connection);
	g_object_unref (reread);
}

static void
test_read_wifi_mac_random (gconstpointer user_data)
{
	NMConnection *connection;
	NMSettingWireless *s_wifi;
	char *path;
	const char *name;
	gpointer value_p;
	NMSettingMacRandomization value;

	nmtst_test_data_unpack (user_data, &name, &value_p);
	value = GPOINTER_TO_INT (value_p);

	path = g_strdup_printf (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wifi-mac-random-%s", name);
	connection = _connection_from_file (path, NULL, TYPE_WIRELESS, NULL);
	g_free (path);

	s_wifi = nm_connection_get_setting_wireless (connection);
	g_assert (s_wifi);
	g_assert_cmpint (nm_setting_wireless_get_mac_address_randomization (s_wifi), ==, value);

	g_object_unref (connection);
}

static void
test_write_wifi_mac_random (gconstpointer user_data)
{
	NMConnection *connection, *reread;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wifi;
	char *uuid, *testfile = NULL, *val;
	GError *error = NULL;
	shvarFile *f;
	GBytes *ssid;
	const unsigned char ssid_data[] = { 0x54, 0x65, 0x73, 0x74, 0x20, 0x53, 0x53, 0x49, 0x44 };
	const char *name, *write_expected;
	gpointer value_p;
	NMSettingMacRandomization value;

	nmtst_test_data_unpack (user_data, &name, &value_p, &write_expected);
	value = GPOINTER_TO_INT (value_p);

	g_assert (write_expected);

	connection = nm_simple_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	val = g_strdup_printf ("Test Write WiFi MAC %s", name);
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, val,
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRELESS_SETTING_NAME,
	              NULL);
	g_free (uuid);
	g_free (val);

	/* Wifi setting */
	s_wifi = (NMSettingWireless *) nm_setting_wireless_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wifi));

	ssid = g_bytes_new (ssid_data, sizeof (ssid_data));
	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_MODE, "infrastructure",
	              NM_SETTING_WIRELESS_MAC_ADDRESS_RANDOMIZATION, value,
	              NULL);
	g_bytes_unref (ssid);

	nmtst_assert_connection_verifies (connection);

	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR "/network-scripts/",
	                        &testfile);

	f = svOpenFile (testfile, &error);
	g_assert_no_error (error);
	g_assert (f);

	/* re-read the file to check that what key was written. */
	val = svGetValue (f, "MAC_ADDRESS_RANDOMIZATION", FALSE);
	g_assert_cmpstr (val, ==, write_expected);
	g_free (val);
	svCloseFile (f);

	reread = _connection_from_file (testfile, NULL, TYPE_WIRELESS, NULL);
	unlink (testfile);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

	g_free (testfile);
	g_object_unref (connection);
	g_object_unref (reread);
}

static void
test_write_wired_wake_on_lan (void)
{
	NMConnection *connection, *reread;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingWiredWakeOnLan wol;
	char *uuid, *testfile = NULL, *val;
	GError *error = NULL;
	shvarFile *f;

	connection = nm_simple_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write Wired Wake-on-LAN",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* Wired setting */
	s_wired = (NMSettingWired *) nm_setting_wired_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wired));

	wol = NM_SETTING_WIRED_WAKE_ON_LAN_MULTICAST |
	      NM_SETTING_WIRED_WAKE_ON_LAN_UNICAST |
	      NM_SETTING_WIRED_WAKE_ON_LAN_MAGIC;

	g_object_set (s_wired,
	              NM_SETTING_WIRED_WAKE_ON_LAN, wol,
	              NM_SETTING_WIRED_WAKE_ON_LAN_PASSWORD, "00:00:00:11:22:33",
	              NULL);

	nmtst_assert_connection_verifies (connection);

	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR "/network-scripts/",
	                        &testfile);

	f = svOpenFile (testfile, &error);
	g_assert_no_error (error);
	g_assert (f);

	/* re-read the file to check that the key was written. */
	val = svGetValue (f, "ETHTOOL_OPTS", FALSE);
	g_assert (val);
	g_assert (strstr (val, "wol"));
	g_assert (strstr (val, "sopass 00:00:00:11:22:33"));
	g_free (val);
	svCloseFile (f);

	reread = _connection_from_file (testfile, NULL, TYPE_ETHERNET, NULL);
	unlink (testfile);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

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

	connection = _connection_from_file (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wifi-band-a",
	                                    NULL, TYPE_WIRELESS, NULL);

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

	nmtst_assert_connection_verifies (connection);

	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR "/network-scripts/",
	                        &testfile);

	f = svOpenFile (testfile, &error);
	g_assert_no_error (error);
	g_assert (f);

	/* re-read the file to check that what key was written. */
	val = svGetValue (f, "BAND", FALSE);
	g_assert (val);
	g_assert_cmpstr (val, ==, "a");
	g_free (val);
	svCloseFile (f);

	reread = _connection_from_file (testfile, NULL, TYPE_WIRELESS, NULL);
	unlink (testfile);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

	g_free (testfile);
	g_object_unref (connection);
	g_object_unref (reread);
}

static void
test_read_wifi_band_a_channel_mismatch (void)
{
	gs_free_error GError *error = NULL;

	_connection_from_file_fail (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wifi-band-a-channel-mismatch",
	                            NULL, TYPE_WIRELESS, &error);
	g_assert_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION);
}

static void
test_read_wifi_band_bg_channel_mismatch (void)
{
	gs_free_error GError *error = NULL;

	_connection_from_file_fail (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wifi-band-bg-channel-mismatch",
	                            NULL, TYPE_WIRELESS, &error);
	g_assert_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION);
}

static void
test_read_wired_qeth_static (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIPConfig *s_ip4;
	char *unmanaged = NULL;
	const char * const *subchannels;

	connection = _connection_from_file (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-wired-qeth-static",
	                                    NULL, TYPE_ETHERNET, &unmanaged);
	g_assert (!unmanaged);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "System test-wired-qeth-static");

	/* ===== WIRED SETTING ===== */

	s_wired = nm_connection_get_setting_wired (connection);
	g_assert (s_wired);

	g_assert (!nm_setting_wired_get_mac_address (s_wired));

	/* Subchannels */
	subchannels = nm_setting_wired_get_s390_subchannels (s_wired);
	g_assert (subchannels);
	g_assert (subchannels[0] && subchannels[1] && subchannels[2] && !subchannels[3]);

	g_assert_cmpstr (subchannels[0], ==, "0.0.0600");
	g_assert_cmpstr (subchannels[1], ==, "0.0.0601");
	g_assert_cmpstr (subchannels[2], ==, "0.0.0602");

	g_assert_cmpstr (nm_setting_wired_get_s390_nettype (s_wired), ==, "qeth");
	g_assert_cmpstr (nm_setting_wired_get_s390_option_by_key (s_wired, "portname"), ==, "OSAPORT");
	g_assert_cmpstr (nm_setting_wired_get_s390_option_by_key (s_wired, "portno"), ==, "0");
	g_assert_cmpstr (nm_setting_wired_get_s390_option_by_key (s_wired, "layer2"), ==, "1");

	/* ===== IPv4 SETTING ===== */

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_MANUAL);

	g_object_unref (connection);
}

static void
test_read_wired_ctc_static (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	char *unmanaged = NULL;
	const char * const *subchannels;

	connection = _connection_from_file (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-wired-ctc-static",
	                                    NULL, TYPE_ETHERNET, &unmanaged);
	g_assert (unmanaged == NULL);

	/* ===== CONNECTION SETTING ===== */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con != NULL);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "System test-wired-ctc-static");

	/* ===== WIRED SETTING ===== */
	s_wired = nm_connection_get_setting_wired (connection);
	g_assert (s_wired != NULL);

	g_assert (nm_setting_wired_get_mac_address (s_wired) == NULL);

	/* Subchannels */
	subchannels = nm_setting_wired_get_s390_subchannels (s_wired);
	g_assert (subchannels != NULL);
	g_assert (subchannels[0] && subchannels[1] && !subchannels[2]);

	g_assert_cmpstr (subchannels[0], ==, "0.0.1b00");
	g_assert_cmpstr (subchannels[1], ==, "0.0.1b01");

	g_assert_cmpstr (nm_setting_wired_get_s390_nettype (s_wired), ==, "ctc");
	g_assert_cmpstr (nm_setting_wired_get_s390_option_by_key (s_wired, "ctcprot"), ==, "0");

	g_object_unref (connection);
}

static void
test_read_wifi_wep_no_keys (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	NMSettingWirelessSecurity *s_wsec;
	NMWepKeyType key_type;

	connection = _connection_from_file (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-wifi-wep-no-keys",
	                                    NULL, TYPE_WIRELESS, NULL);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "System foobar (test-wifi-wep-no-keys)");

	/* UUID can't be tested if the ifcfg does not contain the UUID key, because
	 * the UUID is generated on the full path of the ifcfg file, which can change
	 * depending on where the tests are run.
	 */

	/* ===== WIRELESS SETTING ===== */

	s_wireless = nm_connection_get_setting_wireless (connection);
	g_assert (s_wireless);

	/* ===== WIRELESS SECURITY SETTING ===== */

	s_wsec = nm_connection_get_setting_wireless_security (connection);
	g_assert (s_wsec);

	/* Key management */
	g_assert_cmpstr (nm_setting_wireless_security_get_key_mgmt (s_wsec), ==, "none");

	/* WEP key index */
	g_assert_cmpint (nm_setting_wireless_security_get_wep_tx_keyidx (s_wsec), ==, 0);

	/* WEP key type */
	key_type = nm_setting_wireless_security_get_wep_key_type (s_wsec);
	g_assert (key_type == NM_WEP_KEY_TYPE_UNKNOWN || key_type == NM_WEP_KEY_TYPE_KEY);

	/* WEP key index 0; we don't expect it to be filled */
	g_assert (!nm_setting_wireless_security_get_wep_key (s_wsec, 0));

	g_object_unref (connection);
}

static void
test_read_permissions (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	gboolean success;
	guint32 num;
	const char *tmp;

	connection = _connection_from_file (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-permissions",
	                                    NULL, TYPE_ETHERNET, NULL);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);

	num = nm_setting_connection_get_num_permissions (s_con);
	g_assert_cmpint (num, ==, 3);

	/* verify each permission */
	tmp = NULL;
	success = nm_setting_connection_get_permission (s_con, 0, NULL, &tmp, NULL);
	g_assert (success);
	g_assert_cmpstr (tmp, ==, "dcbw");

	tmp = NULL;
	success = nm_setting_connection_get_permission (s_con, 1, NULL, &tmp, NULL);
	g_assert (success);
	g_assert_cmpstr (tmp, ==, "ssmith");

	tmp = NULL;
	success = nm_setting_connection_get_permission (s_con, 2, NULL, &tmp, NULL);
	g_assert (success);
	g_assert_cmpstr (tmp, ==, "johnny5");

	g_object_unref (connection);
}

static void
test_read_wifi_wep_agent_keys (void)
{
	NMConnection *connection;
	NMSettingWireless *s_wifi;
	NMSettingWirelessSecurity *s_wsec;
	NMWepKeyType key_type;
	NMSettingSecretFlags flags;

	connection = _connection_from_file (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-wifi-wep-agent-keys",
	                                    NULL, TYPE_WIRELESS, NULL);

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
	char *uuid;
	NMIPAddress *addr;
	NMIPAddress *addr6;
	NMIPRoute *route6;
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
	              NM_SETTING_WIRED_MAC_ADDRESS, "31:33:33:37:be:cd",
	              NM_SETTING_WIRED_MTU, (guint32) 1492,
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

	nm_setting_ip_config_add_dns (s_ip4, "4.2.2.1");
	nm_setting_ip_config_add_dns (s_ip4, "4.2.2.2");

	nm_setting_ip_config_add_dns_search (s_ip4, "foobar.com");
	nm_setting_ip_config_add_dns_search (s_ip4, "lab.foobar.com");

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
	nm_setting_ip_config_add_dns (s_ip6, "fade:0102:0103::face");
	nm_setting_ip_config_add_dns (s_ip6, "cafe:ffff:eeee:dddd:cccc:bbbb:aaaa:feed");

	/* DNS domains */
	nm_setting_ip_config_add_dns_search (s_ip6, "foobar6.com");
	nm_setting_ip_config_add_dns_search (s_ip6, "lab6.foobar.com");

	nmtst_assert_connection_verifies (connection);

	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR "/network-scripts/",
	                        &testfile);

	reread = _connection_from_file (testfile, NULL, TYPE_ETHERNET, NULL);
	unlink (testfile);

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

	nmtst_assert_connection_equals (connection, FALSE, reread, FALSE);

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

	nmtst_assert_connection_verifies (connection);

	/* IP6 setting */
	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NM_SETTING_IP_CONFIG_MAY_FAIL, TRUE,
	              NULL);

	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR "/network-scripts/",
	                        &testfile);

	reread = _connection_from_file (testfile, NULL, TYPE_ETHERNET, NULL);
	unlink (testfile);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

	g_free (testfile);
	g_object_unref (connection);
	g_object_unref (reread);
}

static void
test_write_wired_dhcp_plus_ip (void)
{
	NMConnection *connection, *reread;
	char *written = NULL;

	connection = _connection_from_file (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-dhcp-plus-ip",
	                                    NULL, TYPE_ETHERNET, NULL);

	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR "/network-scripts/",
	                        &written);

	reread = _connection_from_file (written, NULL, TYPE_ETHERNET, NULL);
	unlink (written);
	g_free (written);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

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

	connection = _connection_from_file (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-dhcp-send-hostname",
	                                    NULL, TYPE_ETHERNET, NULL);

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

	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR "/network-scripts/",
	                        &written);

	reread = _connection_from_file (written, NULL, TYPE_ETHERNET, NULL);
	unlink (written);
	g_free (written);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

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
	char *uuid;
	NMIPAddress *addr6;
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

	g_object_set (s_wired, NM_SETTING_WIRED_MAC_ADDRESS, "31:33:33:37:be:cd", NULL);

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
	nm_setting_ip_config_add_dns (s_ip6, "fade:0102:0103::face");

	nmtst_assert_connection_verifies (connection);

	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR "/network-scripts/",
	                        &testfile);

	reread = _connection_from_file (testfile, NULL, TYPE_ETHERNET, NULL);
	unlink (testfile);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

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
	char *uuid;
	NMIPAddress *addr6;
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

	g_object_set (s_wired, NM_SETTING_WIRED_MAC_ADDRESS, "31:33:33:37:be:cd", NULL);

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
	nm_setting_ip_config_add_dns (s_ip6, "fade:0102:0103::face");

	nmtst_assert_connection_verifies (connection);

	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR "/network-scripts/",
	                        &testfile);

	reread = _connection_from_file (testfile, NULL, TYPE_ETHERNET, NULL);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

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
	const char *tmp;

	connection = _connection_from_file (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-static-routes-legacy",
	                                    NULL, TYPE_ETHERNET, NULL);

	/* ===== CONNECTION SETTING ===== */

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);

	/* ID */
	tmp = nm_setting_connection_get_id (s_con);
	g_assert (tmp);

	/* Autoconnect */
	g_assert (nm_setting_connection_get_autoconnect (s_con));

	/* ===== WIRED SETTING ===== */

	s_wired = nm_connection_get_setting_wired (connection);
	g_assert (s_wired);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_AUTO);

	g_assert (!nm_setting_ip_config_get_never_default (s_ip4));

	/* Save the ifcfg; use a special different scratch dir to ensure that
	 * we can clean up after the written connection in both the original
	 * source tree and for 'make distcheck'.
	 */
	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR "/network-scripts/tmp",
	                        &testfile);

	reread = _connection_from_file (testfile, NULL, TYPE_ETHERNET, NULL);
	unlink (testfile);
	routefile = utils_get_route_path (testfile);
	unlink (routefile);
	route6file = utils_get_route6_path (testfile);
	unlink (route6file);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

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
	char *uuid;
	NMIPAddress *addr;
	NMIPRoute *route;
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
	              NM_SETTING_WIRED_MAC_ADDRESS, "31:33:33:37:be:cd",
	              NM_SETTING_WIRED_MTU, (guint32) 1492,
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

	nm_setting_ip_config_add_dns (s_ip4, "4.2.2.1");
	nm_setting_ip_config_add_dns (s_ip4, "4.2.2.2");

	nm_setting_ip_config_add_dns_search (s_ip4, "foobar.com");
	nm_setting_ip_config_add_dns_search (s_ip4, "lab.foobar.com");

	/* IP6 setting */
	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NM_SETTING_IP_CONFIG_MAY_FAIL, TRUE,
	              NULL);

	nmtst_assert_connection_verifies (connection);

	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR "/network-scripts/",
	                        &testfile);

	reread = _connection_from_file (testfile, NULL, TYPE_ETHERNET, NULL);
	unlink (testfile);

	routefile = utils_get_route_path (testfile);
	unlink (routefile);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

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
	nmtst_assert_success (success, error);

	nmtst_assert_connection_verifies (connection);

	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR "/network-scripts/",
	                        &testfile);

	reread = _connection_from_file (testfile, NULL, TYPE_ETHERNET, NULL);
	unlink (testfile);

	keyfile = utils_get_keys_path (testfile);
	unlink (keyfile);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

	g_free (testfile);
	g_free (keyfile);
	g_object_unref (connection);
	g_object_unref (reread);
}

static void
test_write_wired_8021x_tls (gconstpointer test_data)
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
	gpointer scheme_p, flags_p;
	NMSetting8021xCKScheme scheme;
	NMSettingSecretFlags flags;

	nmtst_test_data_unpack (test_data, &scheme_p, &flags_p);
	scheme = GPOINTER_TO_INT (scheme_p);
	flags = GPOINTER_TO_INT (flags_p);

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
	                                         TEST_IFCFG_DIR "/network-scripts/test_ca_cert.pem",
	                                         scheme,
	                                         &format,
	                                         &error);
	g_assert_no_error (error);
	g_assert (success);
	g_assert (format == NM_SETTING_802_1X_CK_FORMAT_X509);

	/* Client cert */
	format = NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;
	success = nm_setting_802_1x_set_client_cert (s_8021x,
	                                             TEST_IFCFG_DIR "/network-scripts/test1_key_and_cert.pem",
	                                             scheme,
	                                             &format,
	                                             &error);
	g_assert_no_error (error);
	g_assert (success);
	g_assert (format == NM_SETTING_802_1X_CK_FORMAT_X509);

	/* Private key */
	format = NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;
	success = nm_setting_802_1x_set_private_key (s_8021x,
	                                             TEST_IFCFG_DIR "/network-scripts/test1_key_and_cert.pem",
	                                             "test1",
	                                             scheme,
	                                             &format,
	                                             &error);
	g_assert_no_error (error);
	g_assert (success);
	g_assert (format == NM_SETTING_802_1X_CK_FORMAT_RAW_KEY);

	/* Set secret flags */
	g_object_set (s_8021x, NM_SETTING_802_1X_PRIVATE_KEY_PASSWORD_FLAGS, flags, NULL);

	nmtst_assert_connection_verifies (connection);

	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR "/network-scripts/",
	                        &testfile);

	reread = _connection_from_file (testfile, NULL, TYPE_WIRELESS, NULL);
	unlink (testfile);
	keyfile = utils_get_keys_path (testfile);
	unlink (keyfile);

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

		nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);
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
	GError *error = NULL;
	char *testfile = NULL;
	shvarFile *ifcfg;
	int i, j;

	connection = nm_simple_connection_new ();
	g_assert (connection);

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	g_assert (s_con);
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
	g_assert (s_wired);
	nm_connection_add_setting (connection, NM_SETTING (s_wired));

	/* IP4 setting */
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	g_assert (s_ip4);
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

	nmtst_assert_connection_verifies (connection);

	/* Create some pre-existing alias files, to make sure they get overwritten / deleted. */
	ifcfg = svCreateFile (TEST_SCRATCH_ALIAS_BASE ":2");
	svSetValue (ifcfg, "DEVICE", "alias0:2", FALSE);
	svSetValue (ifcfg, "IPADDR", "192.168.1.2", FALSE);
	svWriteFile (ifcfg, 0644, NULL);
	svCloseFile (ifcfg);
	g_assert (g_file_test (TEST_SCRATCH_ALIAS_BASE ":2", G_FILE_TEST_EXISTS));

	ifcfg = svCreateFile (TEST_SCRATCH_ALIAS_BASE ":5");
	svSetValue (ifcfg, "DEVICE", "alias0:5", FALSE);
	svSetValue (ifcfg, "IPADDR", "192.168.1.5", FALSE);
	svWriteFile (ifcfg, 0644, NULL);
	svCloseFile (ifcfg);
	g_assert (g_file_test (TEST_SCRATCH_ALIAS_BASE ":5", G_FILE_TEST_EXISTS));

	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR "/network-scripts/",
	                        &testfile);

	/* Re-check the alias files */
	g_assert (g_file_test (TEST_SCRATCH_ALIAS_BASE ":2", G_FILE_TEST_EXISTS));
	g_assert (g_file_test (TEST_SCRATCH_ALIAS_BASE ":3", G_FILE_TEST_EXISTS));
	g_assert (!g_file_test (TEST_SCRATCH_ALIAS_BASE ":5", G_FILE_TEST_EXISTS));

	reread = _connection_from_file (testfile, NULL, TYPE_ETHERNET, NULL);
	unlink (testfile);
	unlink (TEST_SCRATCH_ALIAS_BASE ":2");
	unlink (TEST_SCRATCH_ALIAS_BASE ":3");

	/* nm_connection_compare() is not guaranteed to succeed, because the
	 * aliases get read back in essentially random order. So just
	 * verify the aliases manually.
	 */
	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (nm_setting_ip_config_get_num_addresses (s_ip4) == num_addresses);

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

	for (i = 0; i < num_addresses; i++)
		g_assert (!ip[i]);

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

	nmtst_assert_connection_verifies (connection);

	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR "/network-scripts/",
	                        &testfile);

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

	reread = _connection_from_file (testfile, NULL, TYPE_WIRELESS, NULL);
	unlink (testfile);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

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
	GError *error = NULL;
	char *testfile = NULL;
	GBytes *ssid;
	const unsigned char ssid_data[] = { 0x54, 0x65, 0x73, 0x74, 0x20, 0x53, 0x53, 0x49, 0x44 };
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
	              NM_SETTING_WIRELESS_BSSID, "11:22:33:44:55:66",
	              NM_SETTING_WIRELESS_MAC_ADDRESS, "aa:bb:cc:dd:ee:ff",
	              NM_SETTING_WIRELESS_MODE, "infrastructure",
	              NM_SETTING_WIRELESS_BAND, "bg",
	              NM_SETTING_WIRELESS_CHANNEL, (guint32) 9,
	              NM_SETTING_WIRELESS_MTU, (guint32) 1345,
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

	nmtst_assert_connection_verifies (connection);

	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR "/network-scripts/",
	                        &testfile);

	reread = _connection_from_file (testfile, NULL, TYPE_WIRELESS, NULL);

	/* Now make sure that the ESSID item isn't double-quoted (rh #606518) */
	ifcfg = svOpenFile (testfile, &error);
	g_assert_no_error (error);
	g_assert (ifcfg != NULL);

	tmp = svGetValue (ifcfg, "ESSID", TRUE);
	g_assert (tmp);

	g_assert (strncmp (tmp, "\"\"", 2) != 0);

	g_free (tmp);
	svCloseFile (ifcfg);

	unlink (testfile);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

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

	nmtst_assert_connection_verifies (connection);

	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR "/network-scripts/",
	                        &testfile);

	reread = _connection_from_file (testfile, NULL, TYPE_WIRELESS, NULL);
	unlink (testfile);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

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

	nmtst_assert_connection_verifies (connection);

	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR "/network-scripts/",
	                        &testfile);

	reread = _connection_from_file (testfile, NULL, TYPE_WIRELESS, NULL);
	unlink (testfile);

	keyfile = utils_get_keys_path (testfile);
	g_assert_cmpint (stat (keyfile, &statbuf), ==, 0);
	g_assert (S_ISREG (statbuf.st_mode));
	g_assert_cmpint ((statbuf.st_mode & 0077), ==, 0);
	unlink (keyfile);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

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
	GError *error = NULL;
	char *testfile = NULL;
	char *keyfile = NULL;
	GBytes *ssid;
	const char *ssid_data = "blahblah";
	struct stat statbuf;
	NMIPAddress *addr;

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

	nm_setting_ip_config_add_dns (s_ip4, "4.2.2.1");

	/* IP6 setting */
	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NM_SETTING_IP_CONFIG_MAY_FAIL, TRUE,
	              NULL);

	nmtst_assert_connection_verifies (connection);

	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR "/network-scripts/",
	                        &testfile);

	reread = _connection_from_file (testfile, NULL, TYPE_WIRELESS, NULL);
	unlink (testfile);

	keyfile = utils_get_keys_path (testfile);
	g_assert_cmpint (stat (keyfile, &statbuf), ==, 0);
	g_assert (S_ISREG (statbuf.st_mode));
	g_assert_cmpint ((statbuf.st_mode & 0077), ==, 0);
	unlink (keyfile);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

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

	nmtst_assert_connection_verifies (connection);

	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR "/network-scripts/",
	                        &testfile);

	reread = _connection_from_file (testfile, NULL, TYPE_WIRELESS, NULL);
	unlink (testfile);

	keyfile = utils_get_keys_path (testfile);
	g_assert_cmpint (stat (keyfile, &statbuf), ==, 0);
	g_assert (S_ISREG (statbuf.st_mode));
	g_assert_cmpint ((statbuf.st_mode & 0077), ==, 0);
	unlink (keyfile);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

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

	nmtst_assert_connection_verifies (connection);

	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR "/network-scripts/",
	                        &testfile);

	reread = _connection_from_file (testfile, NULL, TYPE_WIRELESS, NULL);
	unlink (testfile);

	keyfile = utils_get_keys_path (testfile);
	g_assert_cmpint (stat (keyfile, &statbuf), ==, 0);
	g_assert (S_ISREG (statbuf.st_mode));
	g_assert_cmpint ((statbuf.st_mode & 0077), ==, 0);
	unlink (keyfile);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

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

	nmtst_assert_connection_verifies (connection);

	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR "/network-scripts/",
	                        &testfile);

	reread = _connection_from_file (testfile, NULL, TYPE_WIRELESS, NULL);
	unlink (testfile);

	keyfile = utils_get_keys_path (testfile);
	g_assert_cmpint (stat (keyfile, &statbuf), ==, 0);
	g_assert (S_ISREG (statbuf.st_mode));
	g_assert_cmpint ((statbuf.st_mode & 0077), ==, 0);
	unlink (keyfile);


	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

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

	nmtst_assert_connection_verifies (connection);

	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR "/network-scripts/",
	                        &testfile);

	reread = _connection_from_file (testfile, NULL, TYPE_WIRELESS, NULL);
	unlink (testfile);

	keyfile = utils_get_keys_path (testfile);
	g_assert_cmpint (stat (keyfile, &statbuf), ==, 0);
	g_assert (S_ISREG (statbuf.st_mode));
	g_assert_cmpint ((statbuf.st_mode & 0077), ==, 0);
	unlink (keyfile);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

	g_free (testfile);
	g_free (keyfile);
	g_object_unref (connection);
	g_object_unref (reread);
}

static void
test_write_wifi_leap_secret_flags (gconstpointer data)
{
	NMConnection *connection;
	NMConnection *reread;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wifi;
	NMSettingWirelessSecurity *s_wsec;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	char *uuid;
	char *testfile = NULL;
	char *keyfile = NULL;
	GBytes *ssid;
	const char *ssid_data = "blahblah";
	NMSettingSecretFlags flags = GPOINTER_TO_UINT (data);

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

	nmtst_assert_connection_verifies (connection);

	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR "/network-scripts/",
	                        &testfile);

	reread = _connection_from_file (testfile, NULL, TYPE_WIRELESS, NULL);
	unlink (testfile);

	/* No key should be written out since the secret is not system owned */
	keyfile = utils_get_keys_path (testfile);
	g_assert (g_file_test (keyfile, G_FILE_TEST_EXISTS) == FALSE);

	/* Remove the LEAP password from the original connection since it wont' be
	 * in the reread connection, as the password is not system owned.
	 */
	g_object_set (s_wsec, NM_SETTING_WIRELESS_SECURITY_LEAP_PASSWORD, NULL, NULL);
	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

	g_free (testfile);
	g_free (keyfile);
	g_object_unref (connection);
	g_object_unref (reread);
}

static void
test_write_wifi_wpa_psk (gconstpointer test_data)
{
	NMConnection *connection;
	NMConnection *reread;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wifi;
	NMSettingWirelessSecurity *s_wsec;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	char *uuid;
	char *testfile = NULL;
	char *keyfile = NULL;
	GBytes *ssid;
	const char *ssid_data = "blahblah";
	struct {
		const char *name, *psk;
		gpointer wep_group_p, wpa_p, wpa2_p;
	} args;

	nmtst_test_data_unpack (test_data, &args.name, &args.wep_group_p, &args.wpa_p, &args.wpa2_p, &args.psk);

	g_assert (args.psk);

	connection = nm_simple_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, args.name,
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
	              NM_SETTING_WIRELESS_SECURITY_PSK, args.psk,
	              NULL);

	if (GPOINTER_TO_INT (args.wep_group_p)) {
		nm_setting_wireless_security_add_group (s_wsec, "wep40");
		nm_setting_wireless_security_add_group (s_wsec, "wep104");
	}
	if (GPOINTER_TO_INT (args.wpa_p)) {
		nm_setting_wireless_security_add_proto (s_wsec, "wpa");
		nm_setting_wireless_security_add_pairwise (s_wsec, "tkip");
		nm_setting_wireless_security_add_group (s_wsec, "tkip");
	}
	if (GPOINTER_TO_INT (args.wpa2_p)) {
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

	nmtst_assert_connection_verifies (connection);

	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR "/network-scripts/",
	                        &testfile);

	reread = _connection_from_file (testfile, NULL, TYPE_WIRELESS, NULL);
	unlink (testfile);

	keyfile = utils_get_keys_path (testfile);
	unlink (keyfile);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

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
	GError *error = NULL;
	char *testfile = NULL;
	char *keyfile = NULL;
	GBytes *ssid;
	const char *ssid_data = "blahblah";
	NMIPAddress *addr;

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

	nm_setting_ip_config_add_dns (s_ip4, "4.2.2.1");

	/* IP6 setting */
	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NM_SETTING_IP_CONFIG_MAY_FAIL, TRUE,
	              NULL);

	nmtst_assert_connection_verifies (connection);

	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR "/network-scripts/",
	                        &testfile);

	reread = _connection_from_file (testfile, NULL, TYPE_WIRELESS, NULL);
	unlink (testfile);

	keyfile = utils_get_keys_path (testfile);
	unlink (keyfile);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

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
	nmtst_assert_success (success, error);

	success = nm_setting_802_1x_set_client_cert (s_8021x,
	                                             TEST_IFCFG_WIFI_WPA_EAP_TLS_CLIENT_CERT,
	                                             NM_SETTING_802_1X_CK_SCHEME_PATH,
	                                             NULL,
	                                             &error);
	nmtst_assert_success (success, error);

	success = nm_setting_802_1x_set_private_key (s_8021x,
	                                             TEST_IFCFG_WIFI_WPA_EAP_TLS_PRIVATE_KEY,
	                                             "test1",
	                                             NM_SETTING_802_1X_CK_SCHEME_PATH,
	                                             NULL,
	                                             &error);
	nmtst_assert_success (success, error);

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

	nmtst_assert_connection_verifies (connection);

	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR "/network-scripts/",
	                        &testfile);

	reread = _connection_from_file (testfile, NULL, TYPE_WIRELESS, NULL);
	unlink (testfile);

	keyfile = utils_get_keys_path (testfile);
	unlink (keyfile);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

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
	nmtst_assert_success (success, error);

	/* Phase 2 TLS stuff */

	/* phase2 CA cert */
	success = nm_setting_802_1x_set_phase2_ca_cert (s_8021x,
	                                                TEST_IFCFG_WIFI_WPA_EAP_TLS_CA_CERT,
	                                                NM_SETTING_802_1X_CK_SCHEME_PATH,
	                                                NULL,
	                                                &error);
	nmtst_assert_success (success, error);

	/* phase2 client cert */
	success = nm_setting_802_1x_set_phase2_client_cert (s_8021x,
	                                                    TEST_IFCFG_WIFI_WPA_EAP_TLS_CLIENT_CERT,
	                                                    NM_SETTING_802_1X_CK_SCHEME_PATH,
	                                                    NULL,
	                                                    &error);
	nmtst_assert_success (success, error);

	/* phase2 private key */
	success = nm_setting_802_1x_set_phase2_private_key (s_8021x,
	                                                    TEST_IFCFG_WIFI_WPA_EAP_TLS_PRIVATE_KEY,
	                                                    "test1",
	                                                    NM_SETTING_802_1X_CK_SCHEME_PATH,
	                                                    NULL,
	                                                    &error);
	nmtst_assert_success (success, error);

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

	nmtst_assert_connection_verifies (connection);

	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR "/network-scripts/",
	                        &testfile);

	reread = _connection_from_file (testfile, NULL, TYPE_WIRELESS, NULL);
	unlink (testfile);

	keyfile = utils_get_keys_path (testfile);
	unlink (keyfile);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

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
	nmtst_assert_success (success, error);

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

	nmtst_assert_connection_verifies (connection);

	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR "/network-scripts/",
	                        &testfile);

	reread = _connection_from_file (testfile, NULL, TYPE_WIRELESS, NULL);
	unlink (testfile);

	keyfile = utils_get_keys_path (testfile);
	unlink (keyfile);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

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

	nmtst_assert_connection_verifies (connection);

	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR "/network-scripts/",
	                        &testfile);

	reread = _connection_from_file (testfile, NULL, TYPE_WIRELESS, NULL);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

	g_object_unref (reread);

	nmtst_connection_normalize (connection);

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

	reread = _connection_from_file (testfile, NULL, TYPE_WIRELESS, NULL);
	unlink (testfile);

	/* No keyfile since it's an open connection this time */
	keyfile = utils_get_keys_path (testfile);
	g_assert (g_file_test (keyfile, G_FILE_TEST_EXISTS) == FALSE);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

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
	g_assert_cmpint (nm_setting_connection_get_num_permissions (s_con), ==, 1);

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

	nmtst_assert_connection_verifies (connection);

	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR "/network-scripts/",
	                        &testfile);

	reread = _connection_from_file (testfile, NULL, TYPE_WIRELESS, NULL);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

	g_object_unref (reread);

	nmtst_connection_normalize (connection);

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

	reread = _connection_from_file (testfile, NULL, TYPE_WIRELESS, NULL);

	nmtst_connection_normalize (connection);
	success = nm_connection_compare (connection, reread,
	                                 NM_SETTING_COMPARE_FLAG_IGNORE_AGENT_OWNED_SECRETS |
	                                 NM_SETTING_COMPARE_FLAG_IGNORE_NOT_SAVED_SECRETS);
	g_assert (success);

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

	nmtst_assert_connection_verifies (connection);

	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR "/network-scripts/",
	                        &testfile);

	reread = _connection_from_file (testfile, NULL, TYPE_WIRELESS, NULL);

	keyfile = utils_get_keys_path (testfile);
	unlink (keyfile);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

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

	nmtst_assert_connection_verifies (connection);

	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR "/network-scripts/",
	                        &testfile);

	reread = _connection_from_file (testfile, NULL, TYPE_ETHERNET, NULL);
	unlink (testfile);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

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

	nmtst_assert_connection_verifies (connection);

	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR "/network-scripts/",
	                        &testfile);

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

	reread = _connection_from_file (testfile, NULL, TYPE_ETHERNET, NULL);
	unlink (testfile);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

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

	nmtst_assert_connection_verifies (connection);

	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR "/network-scripts/",
	                        &testfile);

	reread = _connection_from_file (testfile, NULL, TYPE_ETHERNET, NULL);
	unlink (testfile);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

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

	nmtst_assert_connection_verifies (connection);

	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR "/network-scripts/",
	                        &testfile);

	reread = _connection_from_file (testfile, NULL, TYPE_WIRELESS, NULL);
	unlink (testfile);

	/* Remove the WEP key from the original, because it should not have been
	 * written out to disk as it was agent-owned.  The new connection should
	 * not have any WEP keys set.
	 * Also the new connection should not have WEP key type set.
	 */
	nm_setting_wireless_security_set_wep_key (s_wsec, 0, NULL);
	g_object_set (s_wsec,
	              NM_SETTING_WIRELESS_SECURITY_WEP_KEY_TYPE, NM_WEP_KEY_TYPE_UNKNOWN,
	              NULL);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

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
	GError *error = NULL;

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

	nmtst_assert_connection_verifies (connection);

	_writer_new_connection_fail (connection,
	                             TEST_SCRATCH_DIR "/network-scripts/",
	                             NULL);

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
	GError *error = NULL;

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

	nmtst_assert_connection_verifies (connection);

	_writer_new_connection_fail (connection,
	                             TEST_SCRATCH_DIR "/network-scripts/",
	                             NULL);

	g_object_unref (connection);
	g_clear_error (&error);
}

static void
test_write_mobile_broadband (gconstpointer data)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingIPConfig *s_ip4;
	NMSettingGsm *s_gsm;
	NMSettingCdma *s_cdma;
	NMSettingPpp *s_ppp;
	NMSettingSerial *s_serial;
	char *uuid;
	GError *error = NULL;
	gboolean gsm = GPOINTER_TO_UINT (data);

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

	nmtst_assert_connection_verifies (connection);

	_writer_new_connection_fail (connection,
	                             TEST_SCRATCH_DIR "/network-scripts/",
	                             NULL);

	g_object_unref (connection);
	g_clear_error (&error);
}

static void
test_read_bridge_main (void)
{
	NMConnection *connection;
	NMSettingBridge *s_bridge;
	const char *mac;
	char expected_mac_address[ETH_ALEN] = { 0x00, 0x16, 0x41, 0x11, 0x22, 0x33 };

	connection = _connection_from_file (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-bridge-main",
	                                    NULL, TYPE_ETHERNET, NULL);

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

	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR "/network-scripts/",
	                        &testfile);

	reread = _connection_from_file (testfile, NULL, TYPE_BRIDGE, NULL);
	unlink (testfile);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

	g_free (testfile);
	g_object_unref (connection);
	g_object_unref (reread);
}

static void
test_read_bridge_component (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingBridgePort *s_port;

	connection = _connection_from_file (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-bridge-component",
	                                    NULL, TYPE_ETHERNET, NULL);

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

	nmtst_assert_connection_verifies (connection);

	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR "/network-scripts/",
	                        &testfile);

	reread = _connection_from_file (testfile, NULL, TYPE_ETHERNET, NULL);
	unlink (testfile);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

	g_free (testfile);
	g_object_unref (connection);
	g_object_unref (reread);
}

static void
test_read_bridge_missing_stp (void)
{
	NMConnection *connection;
	NMSettingBridge *s_bridge;

	connection = _connection_from_file (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-bridge-missing-stp",
	                                    NULL, TYPE_BRIDGE, NULL);

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
	NMSettingVlan *s_vlan;
	guint32 from = 0, to = 0;

	connection = _connection_from_file (TEST_IFCFG_VLAN_INTERFACE,
	                                    NULL, TYPE_ETHERNET, NULL);

	g_assert_cmpstr (nm_connection_get_interface_name (connection), ==, "vlan43");

	s_vlan = nm_connection_get_setting_vlan (connection);
	g_assert (s_vlan);

	g_assert_cmpstr (nm_setting_vlan_get_parent (s_vlan), ==, "eth9");
	g_assert_cmpint (nm_setting_vlan_get_id (s_vlan), ==, 43);
	g_assert_cmpint (nm_setting_vlan_get_flags (s_vlan), ==,
	                 NM_VLAN_FLAG_GVRP | NM_VLAN_FLAG_LOOSE_BINDING | NM_VLAN_FLAG_REORDER_HEADERS);

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
	g_assert_cmpint (from, ==, 3);
	g_assert_cmpint (to, ==, 1);

	g_assert (nm_setting_vlan_get_priority (s_vlan, NM_VLAN_EGRESS_MAP, 1, &from, &to));
	g_assert_cmpint (from, ==, 12);
	g_assert_cmpint (to, ==, 3);

	g_assert (nm_setting_vlan_get_priority (s_vlan, NM_VLAN_EGRESS_MAP, 2, &from, &to));
	g_assert_cmpint (from, ==, 14);
	g_assert_cmpint (to, ==, 7);

	g_object_unref (connection);
}

#define TEST_IFCFG_VLAN_ONLY_VLANID TEST_IFCFG_DIR"/network-scripts/ifcfg-test-vlan-only-vlanid"

static void
test_read_vlan_only_vlan_id (void)
{
	NMConnection *connection;
	NMSettingVlan *s_vlan;

	connection = _connection_from_file (TEST_IFCFG_VLAN_ONLY_VLANID, NULL, TYPE_ETHERNET, NULL);

	g_assert (nm_connection_get_interface_name (connection) == NULL);

	s_vlan = nm_connection_get_setting_vlan (connection);
	g_assert (s_vlan);

	g_assert_cmpstr (nm_setting_vlan_get_parent (s_vlan), ==, "eth9");
	g_assert_cmpint (nm_setting_vlan_get_id (s_vlan), ==, 43);
	g_assert_cmpint (nm_setting_vlan_get_flags (s_vlan), ==, NM_VLAN_FLAG_REORDER_HEADERS);

	g_object_unref (connection);
}

static void
test_read_vlan_only_device (void)
{
	NMConnection *connection;
	NMSettingVlan *s_vlan;

	connection = _connection_from_file (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-vlan-only-device",
	                                    NULL, TYPE_ETHERNET, NULL);

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
	NMSettingVlan *s_vlan;

	connection = _connection_from_file (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-vlan-physdev",
	                                    NULL, TYPE_ETHERNET, NULL);

	g_assert_cmpstr (nm_connection_get_interface_name (connection), ==, "vlan0.3");

	s_vlan = nm_connection_get_setting_vlan (connection);
	g_assert (s_vlan);

	g_assert_cmpstr (nm_setting_vlan_get_parent (s_vlan), ==, "eth0");
	g_assert_cmpint (nm_setting_vlan_get_id (s_vlan), ==, 3);

	g_object_unref (connection);
}

static void
test_read_vlan_reorder_hdr_1 (void)
{
	NMConnection *connection;
	NMSettingVlan *s_vlan;

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*REORDER_HDR key is deprecated, use VLAN_FLAGS*");
	connection = _connection_from_file (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-vlan-reorder-hdr-1",
	                                        NULL, TYPE_ETHERNET, NULL);
	g_test_assert_expected_messages ();

	g_assert_cmpstr (nm_connection_get_interface_name (connection), ==, "vlan0.3");

	s_vlan = nm_connection_get_setting_vlan (connection);
	g_assert (s_vlan);

	g_assert_cmpstr (nm_setting_vlan_get_parent (s_vlan), ==, "eth0");
	g_assert_cmpint (nm_setting_vlan_get_id (s_vlan), ==, 3);
	/* Check that REORDER_HDR=0 is ignored */
	g_assert_cmpint (nm_setting_vlan_get_flags (s_vlan), ==, NM_VLAN_FLAG_REORDER_HEADERS);

	g_object_unref (connection);
}

static void
test_read_vlan_reorder_hdr_2 (void)
{
	NMConnection *connection;
	NMSettingVlan *s_vlan;

	connection = _connection_from_file (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-vlan-reorder-hdr-2",
	                                    NULL, TYPE_ETHERNET, NULL);

	g_assert_cmpstr (nm_connection_get_interface_name (connection), ==, "vlan0.3");

	s_vlan = nm_connection_get_setting_vlan (connection);
	g_assert (s_vlan);

	g_assert_cmpstr (nm_setting_vlan_get_parent (s_vlan), ==, "eth0");
	g_assert_cmpint (nm_setting_vlan_get_id (s_vlan), ==, 3);
	/* Check that VLAN_FLAGS=NO_REORDER_HDR works */
	g_assert_cmpint (nm_setting_vlan_get_flags (s_vlan), ==, NM_VLAN_FLAG_LOOSE_BINDING);

	g_object_unref (connection);
}

static void
test_read_vlan_flags_1 (void)
{
	NMConnection *connection;
	NMSettingVlan *s_vlan;

	connection = _connection_from_file (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-vlan-flags-1",
	                                    NULL, TYPE_ETHERNET, NULL);

	g_assert_cmpstr (nm_connection_get_interface_name (connection), ==, "super-vlan");

	s_vlan = nm_connection_get_setting_vlan (connection);
	g_assert (s_vlan);

	g_assert_cmpstr (nm_setting_vlan_get_parent (s_vlan), ==, "eth9");
	g_assert_cmpint (nm_setting_vlan_get_id (s_vlan), ==, 44);
	g_assert_cmpint (nm_setting_vlan_get_flags (s_vlan), ==,
	                                            NM_VLAN_FLAG_LOOSE_BINDING |
	                                            NM_VLAN_FLAG_REORDER_HEADERS);

	g_object_unref (connection);
}

static void
test_read_vlan_flags_2 (void)
{
	NMConnection *connection;
	NMSettingVlan *s_vlan;

	connection = _connection_from_file (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-vlan-flags-2",
	                                    NULL, TYPE_ETHERNET, NULL);

	g_assert_cmpstr (nm_connection_get_interface_name (connection), ==, "super-vlan");

	s_vlan = nm_connection_get_setting_vlan (connection);
	g_assert (s_vlan);

	g_assert_cmpstr (nm_setting_vlan_get_parent (s_vlan), ==, "eth9");
	g_assert_cmpint (nm_setting_vlan_get_id (s_vlan), ==, 44);
	g_assert_cmpint (nm_setting_vlan_get_flags (s_vlan), ==,
	                                            NM_VLAN_FLAG_GVRP |
	                                            NM_VLAN_FLAG_LOOSE_BINDING |
	                                            NM_VLAN_FLAG_REORDER_HEADERS);

	g_object_unref (connection);
}

static void
test_write_vlan (void)
{
	NMConnection *connection;
	char *written = NULL;

	connection = _connection_from_file (TEST_IFCFG_VLAN_INTERFACE,
	                                    NULL, TYPE_VLAN, NULL);

	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR "/network-scripts/",
	                        &written);

	unlink (written);
	g_free (written);

	g_object_unref (connection);
}

static void
test_write_vlan_flags (void)
{
	NMConnection *connection, *reread;
	char *written = NULL;

	connection = _connection_from_file (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-vlan-flags-2",
	                                    NULL, TYPE_VLAN, NULL);

	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR "/network-scripts/",
	                        &written);

	reread = _connection_from_file (written, NULL, TYPE_ETHERNET, NULL);

	unlink (written);
	g_free (written);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

	g_object_unref (connection);
	g_object_unref (reread);
}

static void
test_write_vlan_only_vlanid (void)
{
	NMConnection *connection, *reread;
	char *written = NULL;

	connection = _connection_from_file (TEST_IFCFG_VLAN_ONLY_VLANID,
	                                    NULL, TYPE_VLAN, NULL);

	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR "/network-scripts/",
	                        &written);

	reread = _connection_from_file (written, NULL, TYPE_ETHERNET, NULL);
	unlink (written);
	g_free (written);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

	g_object_unref (connection);
	g_object_unref (reread);
}

static void
test_write_vlan_reorder_hdr (void)
{
	NMConnection *connection, *reread;
	NMSettingConnection *s_con;
	NMSettingVlan *s_vlan;
	NMSettingWired *s_wired;
	char *uuid;
	char *testfile = NULL;

	connection = nm_simple_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write VLAN reorder_hdr",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, FALSE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_VLAN_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* Wired setting */
	s_wired = (NMSettingWired *) nm_setting_wired_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wired));

	/* VLAN setting */
	s_vlan = (NMSettingVlan *) nm_setting_vlan_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_vlan));

	g_object_set (s_vlan,
	              NM_SETTING_VLAN_PARENT, "eth0",
	              NM_SETTING_VLAN_ID, 444,
	              NM_SETTING_VLAN_FLAGS, 1,
	              NULL);

	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR "/network-scripts/",
	                        &testfile);

	reread = _connection_from_file (testfile, NULL, TYPE_ETHERNET, NULL);
	unlink (testfile);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

	g_object_unref (connection);
	g_object_unref (reread);
	g_free (testfile);
}

static void
test_write_ethernet_missing_ipv6 (void)
{
	NMConnection *connection;
	NMConnection *reread;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIPConfig *s_ip4;
	char *uuid;
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

	nmtst_assert_connection_verifies (connection);

	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR "/network-scripts/",
	                        &testfile);

	reread = _connection_from_file (testfile, NULL, TYPE_ETHERNET, NULL);
	unlink (testfile);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

	g_free (testfile);
	g_object_unref (connection);
	g_object_unref (reread);
}

static void
test_read_ibft_ignored (void)
{
	gs_free_error GError *error = NULL;

	_connection_from_file_fail (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-ibft",
	                            NULL, TYPE_ETHERNET, &error);
	g_assert_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION);
}

static void
test_read_bond_main (void)
{
	NMConnection *connection;
	NMSettingBond *s_bond;

	connection = _connection_from_file (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-bond-main",
	                                    NULL, TYPE_ETHERNET,NULL);

	g_assert_cmpstr (nm_connection_get_interface_name (connection), ==, "bond0");

	/* ===== Bonding SETTING ===== */

	s_bond = nm_connection_get_setting_bond (connection);
	g_assert (s_bond);

	g_assert_cmpstr (nm_setting_bond_get_option_by_name (s_bond, NM_SETTING_BOND_OPTION_MIIMON), ==, "100");

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

	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR "/network-scripts/",
	                        &testfile);

	reread = _connection_from_file (testfile, NULL, TYPE_BOND, NULL);
	unlink (testfile);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

	g_free (testfile);
	g_object_unref (connection);
	g_object_unref (reread);
}

static void
test_read_bond_slave (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;

	connection = _connection_from_file (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-bond-slave",
	                                    NULL, TYPE_ETHERNET, NULL);
	g_test_assert_expected_messages ();

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);

	g_assert_cmpstr (nm_setting_connection_get_master (s_con), ==, "bond0");

	g_assert_cmpstr (nm_setting_connection_get_slave_type (s_con), ==, NM_SETTING_BOND_SETTING_NAME);

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

	nmtst_assert_connection_verifies (connection);

	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR "/network-scripts/",
	                        &testfile);

	reread = _connection_from_file (testfile, NULL, TYPE_ETHERNET, NULL);
	unlink (testfile);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

	g_free (testfile);
	g_object_unref (connection);
	g_object_unref (reread);
}

static void
test_read_infiniband (void)
{
	NMConnection *connection;
	NMSettingInfiniband *s_infiniband;
	char *unmanaged = NULL;
	const char *mac;
	char expected_mac_address[INFINIBAND_ALEN] = { 0x80, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22 };
	const char *transport_mode;

	connection = _connection_from_file (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-infiniband",
	                                    NULL, TYPE_INFINIBAND, &unmanaged);
	g_assert (!unmanaged);

	/* ===== INFINIBAND SETTING ===== */

	s_infiniband = nm_connection_get_setting_infiniband (connection);
	g_assert (s_infiniband);

	/* MAC address */
	mac = nm_setting_infiniband_get_mac_address (s_infiniband);
	g_assert (mac);
	g_assert (nm_utils_hwaddr_matches (mac, -1, expected_mac_address, sizeof (expected_mac_address)));

	/* Transport mode */
	transport_mode = nm_setting_infiniband_get_transport_mode (s_infiniband);
	g_assert (transport_mode);
	g_assert_cmpstr (transport_mode, ==, "connected");

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

	nmtst_assert_connection_verifies (connection);

	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR "/network-scripts/",
	                        &testfile);

	reread = _connection_from_file (testfile, NULL, TYPE_INFINIBAND, NULL);
	unlink (testfile);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

	g_free (testfile);
	g_object_unref (connection);
	g_object_unref (reread);
}

static void
test_read_bond_slave_ib (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;

	connection = _connection_from_file (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-bond-slave-ib",
	                                    NULL, NULL, NULL);

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);

	g_assert_cmpstr (nm_setting_connection_get_master (s_con), ==, "bond0");

	g_assert_cmpstr (nm_setting_connection_get_slave_type (s_con), ==, NM_SETTING_BOND_SETTING_NAME);

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

	nmtst_assert_connection_verifies (connection);

	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR "/network-scripts/",
	                        &testfile);

	reread = _connection_from_file (testfile, NULL, NULL, NULL);
	unlink (testfile);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

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

	connection = _connection_from_file (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-bond-mode-numeric",
	                                    NULL, TYPE_ETHERNET, NULL);

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
	NMSettingDcb *s_dcb;
	guint i;
	guint expected_group_ids[8] = { 0, 0, 0, 0, 1, 1, 1, 0xF };
	guint expected_group_bandwidths[8] = { 25, 0, 0, 75, 0, 0, 0, 0 };
	guint expected_bandwidths[8] = { 5, 10, 30, 25, 10, 50, 5, 0 };
	gboolean expected_strict[8] = { FALSE, FALSE, TRUE, TRUE, FALSE, TRUE, FALSE, TRUE };
	guint expected_traffic_classes[8] = { 7, 6, 5, 4, 3, 2, 1, 0 };
	gboolean expected_pfcs[8] = { TRUE, FALSE, FALSE, TRUE, TRUE, FALSE, TRUE, FALSE };

	connection = _connection_from_file (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-dcb",
	                                    NULL, TYPE_ETHERNET, NULL);

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
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingDcb *s_dcb;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
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

	nmtst_assert_connection_verifies (connection);

	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR "/network-scripts/",
	                        &testfile);

	reread = _connection_from_file (testfile, NULL, TYPE_ETHERNET, NULL);
	unlink (testfile);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

	g_object_unref (connection);
	g_object_unref (reread);
	g_free (testfile);
}

static void
test_read_dcb_default_app_priorities (void)
{
	NMConnection *connection;
	NMSettingDcb *s_dcb;

	connection = _connection_from_file (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-dcb-default-app-priorities",
	                                    NULL, TYPE_ETHERNET, NULL);

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
	gs_free_error GError *error = NULL;

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*invalid DCB_PG_STRICT value*not all 0s and 1s*");
	_connection_from_file_fail (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-dcb-bad-booleans",
	                            NULL, TYPE_ETHERNET, &error);
	g_test_assert_expected_messages ();

	g_assert_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION);
	g_assert (strstr (error->message, "invalid boolean digit"));
}

static void
test_read_dcb_short_booleans (void)
{
	gs_free_error GError *error = NULL;

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*DCB_PG_STRICT value*8 characters*");
	_connection_from_file_fail (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-dcb-short-booleans",
	                            NULL, TYPE_ETHERNET, &error);
	g_test_assert_expected_messages ();

	g_assert_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION);
	g_assert (strstr (error->message, "boolean array must be 8 characters"));
}

static void
test_read_dcb_bad_uints (void)
{
	gs_free_error GError *error = NULL;

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*invalid DCB_PG_UP2TC value*not 0 - 7*");
	_connection_from_file_fail (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-dcb-bad-uints",
	                            NULL, TYPE_ETHERNET, &error);
	g_test_assert_expected_messages ();

	g_assert_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION);
	g_assert (strstr (error->message, "invalid uint digit"));
}

static void
test_read_dcb_short_uints (void)
{
	gs_free_error GError *error = NULL;

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*DCB_PG_UP2TC value*8 characters*");
	_connection_from_file_fail (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-dcb-short-uints",
	                            NULL, TYPE_ETHERNET, &error);
	g_test_assert_expected_messages ();

	g_assert_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION);
	g_assert (strstr (error->message, "uint array must be 8 characters"));
}

static void
test_read_dcb_bad_percent (void)
{
	gs_free_error GError *error = NULL;

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*invalid DCB_PG_PCT percentage value*");
	_connection_from_file_fail (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-dcb-bad-percent",
	                            NULL, TYPE_ETHERNET, &error);
	g_test_assert_expected_messages ();

	g_assert_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION);
	g_assert (strstr (error->message, "invalid percent element"));
}

static void
test_read_dcb_short_percent (void)
{
	gs_free_error GError *error = NULL;

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*invalid DCB_PG_PCT percentage list value*");
	_connection_from_file_fail (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-dcb-short-percent",
	                            NULL, TYPE_ETHERNET, &error);
	g_test_assert_expected_messages ();

	g_assert_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION);
	g_assert (strstr (error->message, "percent array must be 8 elements"));
}

static void
test_read_dcb_pgpct_not_100 (void)
{
	gs_free_error GError *error = NULL;

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*DCB_PG_PCT percentages do not equal 100*");
	_connection_from_file_fail (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-dcb-pgpct-not-100",
	                            NULL, TYPE_ETHERNET, &error);
	g_test_assert_expected_messages ();

	g_assert_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION);
	g_assert (strstr (error->message, "invalid percentage sum"));
}

static void
test_read_fcoe_mode (gconstpointer user_data)
{
	const char *expected_mode = user_data;
	NMConnection *connection;
	NMSettingDcb *s_dcb;
	char *file;

	file = g_strdup_printf (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-fcoe-%s", expected_mode);
	connection = _connection_from_file (file, NULL, TYPE_ETHERNET, NULL);
	g_free (file);

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

	nmtst_assert_connection_verifies (connection);

	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR "/network-scripts/",
	                        &testfile);

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

	reread = _connection_from_file (testfile, NULL, TYPE_ETHERNET, NULL);
	unlink (testfile);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

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
	const char *expected_config = "{ \"device\": \"team0\", \"link_watch\": { \"name\": \"ethtool\" } }";

	connection = _connection_from_file (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-team-master",
	                                    NULL, TYPE_ETHERNET, NULL);

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

	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR "/network-scripts/",
	                        &testfile);

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

	reread = _connection_from_file (testfile, NULL, TYPE_ETHERNET, NULL);

	unlink (testfile);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

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
	const char *expected_config = "{ \"p4p1\": { \"prio\": -10, \"sticky\": true } }";

	connection = _connection_from_file (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-team-port",
	                                    NULL, TYPE_ETHERNET, NULL);

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

	nmtst_assert_connection_verifies (connection);

	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR "/network-scripts/",
	                        &testfile);

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

	reread = _connection_from_file (testfile, NULL, TYPE_ETHERNET,
	                                NULL);
	unlink (testfile);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

	g_free (testfile);
	g_object_unref (connection);
	g_object_unref (reread);
}

static void
test_read_team_port_empty_config (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;

	connection = _connection_from_file (TEST_IFCFG_DIR"/network-scripts/ifcfg-test-team-port-empty-config",
	                                    NULL, TYPE_ETHERNET, NULL);

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

	connection = _connection_from_file (testfile, NULL, TYPE_ETHERNET, NULL);

	s_vlan = nm_connection_get_setting_vlan (connection);
	g_assert (s_vlan);

	g_assert_cmpstr (nm_connection_get_interface_name (connection), ==, "vlan201");
	g_assert_cmpstr (nm_setting_vlan_get_parent (s_vlan), ==, "enccw0.0.fb00");
	g_assert_cmpint (nm_setting_vlan_get_id (s_vlan), ==, 201);
	g_assert_cmpint (nm_setting_vlan_get_flags (s_vlan), ==, NM_VLAN_FLAG_REORDER_HEADERS);

	g_object_unref (connection);
}

/*****************************************************************************/

static void
test_sit_read_ignore (void)
{
	gs_free_error GError *error = NULL;

	_connection_from_file_fail (TEST_IFCFG_DIR "/network-scripts/ifcfg-test-sit-ignore",
	                            NULL, TYPE_ETHERNET, &error);
	nmtst_assert_error (error, 0, 0, "*Ignoring unsupported connection due to IPV6TUNNELIPV4*");
}

/*****************************************************************************/


#define TPATH "/settings/plugins/ifcfg-rh/"

#define TEST_IFCFG_WIFI_OPEN_SSID_BAD_HEX TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wifi-open-ssid-bad-hex"
#define TEST_IFCFG_WIFI_OPEN_SSID_LONG_QUOTED TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wifi-open-ssid-long-quoted"
#define TEST_IFCFG_WIFI_OPEN_SSID_LONG_HEX TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wifi-open-ssid-long-hex"

#define DEFAULT_HEX_PSK "7d308b11df1b4243b0f78e5f3fc68cdbb9a264ed0edf4c188edf329ff5b467f0"

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

	nmtst_add_test_func (TPATH "read-static",           test_read_wired_static, TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-static",           "System test-wired-static",           GINT_TO_POINTER (TRUE));
	nmtst_add_test_func (TPATH "read-static-bootproto", test_read_wired_static, TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-static-bootproto", "System test-wired-static-bootproto", GINT_TO_POINTER (FALSE));

	g_test_add_func (TPATH "read-dhcp", test_read_wired_dhcp);
	g_test_add_func (TPATH "read-dhcp-plus-ip", test_read_wired_dhcp_plus_ip);
	g_test_add_func (TPATH "read-shared-plus-ip", test_read_wired_shared_plus_ip);
	g_test_add_func (TPATH "read-dhcp-send-hostname", test_read_write_wired_dhcp_send_hostname);
	g_test_add_func (TPATH "read-global-gateway", test_read_wired_global_gateway);
	g_test_add_func (TPATH "read-global-gateway-ignore", test_read_wired_global_gateway_ignore);
	g_test_add_func (TPATH "read-obsolete-gateway-n", test_read_wired_obsolete_gateway_n);
	g_test_add_func (TPATH "read-never-default", test_read_wired_never_default);
	g_test_add_func (TPATH "read-defroute-no", test_read_wired_defroute_no);
	g_test_add_func (TPATH "read-defroute-no-gatewaydev-yes", test_read_wired_defroute_no_gatewaydev_yes);
	g_test_add_func (TPATH "routes/read-static", test_read_wired_static_routes);
	g_test_add_func (TPATH "routes/read-static-legacy", test_read_wired_static_routes_legacy);

	nmtst_add_test_func (TPATH "wired/read/manual/1", test_read_wired_ipv4_manual, TEST_IFCFG_DIR "/network-scripts/ifcfg-test-wired-ipv4-manual-1", "System test-wired-ipv4-manual-1");
	nmtst_add_test_func (TPATH "wired/read/manual/2", test_read_wired_ipv4_manual, TEST_IFCFG_DIR "/network-scripts/ifcfg-test-wired-ipv4-manual-2", "System test-wired-ipv4-manual-2");
	nmtst_add_test_func (TPATH "wired/read/manual/3", test_read_wired_ipv4_manual, TEST_IFCFG_DIR "/network-scripts/ifcfg-test-wired-ipv4-manual-3", "System test-wired-ipv4-manual-3");
	nmtst_add_test_func (TPATH "wired/read/manual/4", test_read_wired_ipv4_manual, TEST_IFCFG_DIR "/network-scripts/ifcfg-test-wired-ipv4-manual-4", "System test-wired-ipv4-manual-4");

	g_test_add_func (TPATH "wired/ipv6-manual", test_read_wired_ipv6_manual);

	nmtst_add_test_func (TPATH "wired-ipv6-only/0", test_read_wired_ipv6_only, TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-ipv6-only",   "System test-wired-ipv6-only");
	nmtst_add_test_func (TPATH "wired-ipv6-only/1", test_read_wired_ipv6_only, TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-ipv6-only-1", "System test-wired-ipv6-only-1");

	g_test_add_func (TPATH "wired/dhcpv6-only", test_read_wired_dhcp6_only);
	g_test_add_func (TPATH "wired/autoip", test_read_wired_autoip);
	g_test_add_func (TPATH "wired/onboot/no", test_read_onboot_no);
	g_test_add_func (TPATH "wired/no-ip", test_read_noip);
	g_test_add_func (TPATH "802-1x/peap/mschapv2", test_read_wired_8021x_peap_mschapv2);

	nmtst_add_test_func (TPATH "test-wired-8021x-tls/agent",  test_read_wired_8021x_tls_secret_flags, TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-8021x-tls-agent", GINT_TO_POINTER (NM_SETTING_SECRET_FLAG_AGENT_OWNED));
	nmtst_add_test_func (TPATH "test-wired-8021x-tls/always", test_read_wired_8021x_tls_secret_flags, TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-8021x-tls-always", GINT_TO_POINTER (NM_SETTING_SECRET_FLAG_AGENT_OWNED | NM_SETTING_SECRET_FLAG_NOT_SAVED));

	g_test_add_func (TPATH "802-1x/subj-matches", test_read_write_802_1X_subj_matches);
	g_test_add_func (TPATH "802-1x/ttls-eapgtc", test_read_802_1x_ttls_eapgtc);
	g_test_add_func (TPATH "wired/read/aliases", test_read_wired_aliases_good);
	g_test_add_func (TPATH "wired/read/aliases/bad1", test_read_wired_aliases_bad_1);
	g_test_add_func (TPATH "wired/read/aliases/bad2", test_read_wired_aliases_bad_2);
	g_test_add_func (TPATH "wifi/read/open", test_read_wifi_open);
	g_test_add_func (TPATH "wifi/read/open/auto", test_read_wifi_open_auto);
	g_test_add_func (TPATH "wifi/read/open/hex-ssid", test_read_wifi_open_ssid_hex);
	g_test_add_data_func (TPATH "wifi/read/open-ssid/bad-hex", TEST_IFCFG_WIFI_OPEN_SSID_BAD_HEX, test_read_wifi_open_ssid_bad);
	g_test_add_data_func (TPATH "wifi/read/open-ssid/long-hex", TEST_IFCFG_WIFI_OPEN_SSID_LONG_HEX, test_read_wifi_open_ssid_bad);
	g_test_add_data_func (TPATH "wifi/read/open-ssid/long-quoted", TEST_IFCFG_WIFI_OPEN_SSID_LONG_QUOTED, test_read_wifi_open_ssid_bad);
	g_test_add_func (TPATH "wifi/read/open/quoted-ssid", test_read_wifi_open_ssid_quoted);
	g_test_add_func (TPATH "wifi/read/wep", test_read_wifi_wep);
	g_test_add_func (TPATH "wifi/read/wep/adhoc", test_read_wifi_wep_adhoc);
	g_test_add_func (TPATH "wifi/read/wep/passphrase", test_read_wifi_wep_passphrase);
	g_test_add_func (TPATH "wifi/read/wep/40-ascii", test_read_wifi_wep_40_ascii);
	g_test_add_func (TPATH "wifi/read/wep/104-ascii", test_read_wifi_wep_104_ascii);
	g_test_add_func (TPATH "wifi/read/leap", test_read_wifi_leap);

	nmtst_add_test_func (TPATH "wifi-leap-secret-flags/agent", test_read_wifi_leap_secret_flags, TEST_IFCFG_DIR "/network-scripts/ifcfg-test-wifi-leap-agent",      GINT_TO_POINTER (NM_SETTING_SECRET_FLAG_AGENT_OWNED));
	nmtst_add_test_func (TPATH "wifi-leap-secret-flags/ask",   test_read_wifi_leap_secret_flags, TEST_IFCFG_DIR "/network-scripts/ifcfg-test-wifi-leap-always-ask", GINT_TO_POINTER (NM_SETTING_SECRET_FLAG_AGENT_OWNED | NM_SETTING_SECRET_FLAG_NOT_SAVED));

	g_test_add_func (TPATH "wifi/read/wpa-psk", test_read_wifi_wpa_psk);
	g_test_add_func (TPATH "wifi/read/wpa-psk/2", test_read_wifi_wpa_psk_2);
	g_test_add_func (TPATH "wifi/read/wpa-psk/unquoted", test_read_wifi_wpa_psk_unquoted);
	g_test_add_func (TPATH "wifi/read/wpa-psk/unquoted2", test_read_wifi_wpa_psk_unquoted2);
	g_test_add_func (TPATH "wifi/read/wpa-psk/adhoc", test_read_wifi_wpa_psk_adhoc);
	g_test_add_func (TPATH "wifi/read/wpa-psk/hex", test_read_wifi_wpa_psk_hex);
	g_test_add_func (TPATH "wifi/read/dynamic-wep/leap", test_read_wifi_dynamic_wep_leap);
	g_test_add_func (TPATH "wifi/read/wpa/eap/tls", test_read_wifi_wpa_eap_tls);
	g_test_add_func (TPATH "wifi/read/wpa/eap/ttls/tls", test_read_wifi_wpa_eap_ttls_tls);
	g_test_add_func (TPATH "wifi/read/dynamic-wep/eap/ttls/chap", test_read_wifi_wep_eap_ttls_chap);
	g_test_add_func (TPATH "wifi/read-band-a", test_read_wifi_band_a);
	g_test_add_func (TPATH "wifi/read-band-a-channel-mismatch", test_read_wifi_band_a_channel_mismatch);
	g_test_add_func (TPATH "wifi/read-band-bg-channel-mismatch", test_read_wifi_band_bg_channel_mismatch);
	g_test_add_func (TPATH "wifi/read-hidden", test_read_wifi_hidden);

	nmtst_add_test_func (TPATH "wifi/read-mac-random-always",   test_read_wifi_mac_random,  "always",  GINT_TO_POINTER (NM_SETTING_MAC_RANDOMIZATION_ALWAYS));
	nmtst_add_test_func (TPATH "wifi/read-mac-random-never",    test_read_wifi_mac_random,  "never",   GINT_TO_POINTER (NM_SETTING_MAC_RANDOMIZATION_NEVER));
	nmtst_add_test_func (TPATH "wifi/read-mac-random-default",  test_read_wifi_mac_random,  "default", GINT_TO_POINTER (NM_SETTING_MAC_RANDOMIZATION_DEFAULT));
	nmtst_add_test_func (TPATH "wifi/read-mac-random-missing",  test_read_wifi_mac_random,  "missing", GINT_TO_POINTER (NM_SETTING_MAC_RANDOMIZATION_NEVER));

	nmtst_add_test_func (TPATH "wifi/write-mac-random-always",  test_write_wifi_mac_random, "always",  GINT_TO_POINTER (NM_SETTING_MAC_RANDOMIZATION_ALWAYS),  "always");
	nmtst_add_test_func (TPATH "wifi/write-mac-random-never",   test_write_wifi_mac_random, "never",   GINT_TO_POINTER (NM_SETTING_MAC_RANDOMIZATION_NEVER),   "never");
	nmtst_add_test_func (TPATH "wifi/write-mac-random-default", test_write_wifi_mac_random, "default", GINT_TO_POINTER (NM_SETTING_MAC_RANDOMIZATION_DEFAULT), "default");
	nmtst_add_test_func (TPATH "wifi/write-mac-random-missing", test_write_wifi_mac_random, "missing", GINT_TO_POINTER (NM_SETTING_MAC_RANDOMIZATION_NEVER),   "never");

	g_test_add_func (TPATH "wifi/read/wep-no-keys", test_read_wifi_wep_no_keys);
	g_test_add_func (TPATH "wifi/read/wep-agent-keys", test_read_wifi_wep_agent_keys);
	g_test_add_func (TPATH "infiniband/read", test_read_infiniband);
	g_test_add_func (TPATH "vlan/read", test_read_vlan_interface);
	g_test_add_func (TPATH "vlan/read-flags-1", test_read_vlan_flags_1);
	g_test_add_func (TPATH "vlan/read-flags-2", test_read_vlan_flags_2);
	g_test_add_func (TPATH "vlan/read/only-vlanid", test_read_vlan_only_vlan_id);
	g_test_add_func (TPATH "vlan/read/only-device", test_read_vlan_only_device);
	g_test_add_func (TPATH "vlan/read/physdev", test_read_vlan_physdev);
	g_test_add_func (TPATH "vlan/read/reorder-hdr-1", test_read_vlan_reorder_hdr_1);
	g_test_add_func (TPATH "vlan/read/reorder-hdr-2", test_read_vlan_reorder_hdr_2);
	g_test_add_func (TPATH "wired/read/read-wake-on-lan", test_read_wired_wake_on_lan);

	g_test_add_func (TPATH "wired/write/static", test_write_wired_static);
	g_test_add_func (TPATH "wired/write/static-ip6-only", test_write_wired_static_ip6_only);
	g_test_add_func (TPATH "wired/write-static-routes", test_write_wired_static_routes);
	g_test_add_func (TPATH "wired/read-write-static-routes-legacy", test_read_write_static_routes_legacy);
	g_test_add_func (TPATH "wired/write/dhcp", test_write_wired_dhcp);
	g_test_add_func (TPATH "wired/write-dhcp-plus-ip", test_write_wired_dhcp_plus_ip);
	g_test_add_func (TPATH "wired/write/dhcp-8021x-peap-mschapv2", test_write_wired_dhcp_8021x_peap_mschapv2);

#define _add_test_write_wired_8021x_tls(testpath, scheme, flags) \
	nmtst_add_test_func (testpath, test_write_wired_8021x_tls, GINT_TO_POINTER (scheme), GINT_TO_POINTER (flags))
	_add_test_write_wired_8021x_tls (TPATH "wired-8021x-tls/1", NM_SETTING_802_1X_CK_SCHEME_PATH, NM_SETTING_SECRET_FLAG_AGENT_OWNED);
	_add_test_write_wired_8021x_tls (TPATH "wired-8021x-tls/2", NM_SETTING_802_1X_CK_SCHEME_PATH, NM_SETTING_SECRET_FLAG_NOT_SAVED);
	_add_test_write_wired_8021x_tls (TPATH "wired-8021x-tls/3", NM_SETTING_802_1X_CK_SCHEME_PATH, NM_SETTING_SECRET_FLAG_AGENT_OWNED | NM_SETTING_SECRET_FLAG_NOT_SAVED);
	_add_test_write_wired_8021x_tls (TPATH "wired-8021x-tls/4", NM_SETTING_802_1X_CK_SCHEME_BLOB, NM_SETTING_SECRET_FLAG_NONE);

	g_test_add_func (TPATH "wired/write-aliases", test_write_wired_aliases);
	g_test_add_func (TPATH "ipv4/write-static-addresses-GATEWAY", test_write_gateway);
	g_test_add_func (TPATH "wired/write-wake-on-lan", test_write_wired_wake_on_lan);
	g_test_add_func (TPATH "wifi/write/open", test_write_wifi_open);
	g_test_add_func (TPATH "wifi/write/open/hex-ssid", test_write_wifi_open_hex_ssid);
	g_test_add_func (TPATH "wifi/write/wep", test_write_wifi_wep);
	g_test_add_func (TPATH "wifi/write/wep/adhoc", test_write_wifi_wep_adhoc);
	g_test_add_func (TPATH "wifi/write/wep/passphrase", test_write_wifi_wep_passphrase);
	g_test_add_func (TPATH "wifi/write/wep/40-ascii", test_write_wifi_wep_40_ascii);
	g_test_add_func (TPATH "wifi/write/wep/104-ascii", test_write_wifi_wep_104_ascii);
	g_test_add_func (TPATH "wifi/write/leap", test_write_wifi_leap);
	g_test_add_data_func (TPATH "wifi/write/leap/flags/agent",
	                      GUINT_TO_POINTER (NM_SETTING_SECRET_FLAG_AGENT_OWNED),
	                      test_write_wifi_leap_secret_flags);
	g_test_add_data_func (TPATH "wifi/write/leap/flags/not-saved",
	                      GUINT_TO_POINTER (NM_SETTING_SECRET_FLAG_NOT_SAVED),
	                      test_write_wifi_leap_secret_flags);
	g_test_add_data_func (TPATH "wifi/write/leap/flags/agent-and-not-saved",
	                      GUINT_TO_POINTER (NM_SETTING_SECRET_FLAG_AGENT_OWNED | NM_SETTING_SECRET_FLAG_NOT_SAVED),
	                      test_write_wifi_leap_secret_flags);

#define _add_test_write_wifi_wpa_psk(testpath, name, wep_group, wpa, wpa2, psk) \
	nmtst_add_test_func (testpath, test_write_wifi_wpa_psk, name, GPOINTER_TO_INT (wep_group), GPOINTER_TO_INT (wpa), GPOINTER_TO_INT (wpa2), psk)
	_add_test_write_wifi_wpa_psk (TPATH "wifi-wpa-psk/wpa-psk-write",                            "Test Write Wifi WPA PSK",                               FALSE, TRUE,  FALSE, DEFAULT_HEX_PSK);
	_add_test_write_wifi_wpa_psk (TPATH "wifi-wpa-psk/wpa2-psk-write",                           "Test Write Wifi WPA2 PSK",                              FALSE, FALSE, TRUE,  DEFAULT_HEX_PSK);
	_add_test_write_wifi_wpa_psk (TPATH "wifi-wpa-psk/wpa-wpa2-psk-write",                       "Test Write Wifi WPA WPA2 PSK",                          FALSE, TRUE,  TRUE,  DEFAULT_HEX_PSK);
	_add_test_write_wifi_wpa_psk (TPATH "wifi-wpa-psk/wep-wpa-wpa2-psk-write",                   "Test Write Wifi WEP WPA WPA2 PSK",                      TRUE,  TRUE,  TRUE,  DEFAULT_HEX_PSK);
	_add_test_write_wifi_wpa_psk (TPATH "wifi-wpa-psk/wpa-wpa2-psk-passphrase-write",            "Test Write Wifi WPA WPA2 PSK Passphrase",               FALSE, TRUE,  TRUE,  "really insecure passphrase04!");
	_add_test_write_wifi_wpa_psk (TPATH "wifi-wpa-psk/wpa-wpa2-psk-passphrase-write-spec-chars", "Test Write Wifi WPA WPA2 PSK Passphrase Special Chars", FALSE, TRUE,  TRUE,  "blah`oops\"grr'$*@~!%\\");

	g_test_add_func (TPATH "wifi/write/wpa/psk/adhoc", test_write_wifi_wpa_psk_adhoc);
	g_test_add_func (TPATH "wifi/write/wpa/eap/tls", test_write_wifi_wpa_eap_tls);
	g_test_add_func (TPATH "wifi/write/wpa/eap/ttls/tls", test_write_wifi_wpa_eap_ttls_tls);
	g_test_add_func (TPATH "wifi/write/wpa/eap/ttls/mschapv2", test_write_wifi_wpa_eap_ttls_mschapv2);
	g_test_add_func (TPATH "wifi/write/dynamic-wep/leap", test_write_wifi_dynamic_wep_leap);
	g_test_add_func (TPATH "wifi/write-wpa-then-open", test_write_wifi_wpa_then_open);
	g_test_add_func (TPATH "wifi/write-wpa-then-wep-with-perms", test_write_wifi_wpa_then_wep_with_perms);
	g_test_add_func (TPATH "wifi/write-hidden", test_write_wifi_hidden);
	g_test_add_func (TPATH "wifi/write-band-a", test_write_wifi_band_a);

	g_test_add_func (TPATH "s390/read-qeth-static", test_read_wired_qeth_static);
	g_test_add_func (TPATH "s390/write-qeth-dhcp", test_write_wired_qeth_dhcp);
	g_test_add_func (TPATH "s390/read-ctc-static", test_read_wired_ctc_static);
	g_test_add_func (TPATH "s390/write-ctc-dhcp", test_write_wired_ctc_dhcp);

	g_test_add_func (TPATH "permissions/read", test_read_permissions);
	g_test_add_func (TPATH "permissions/write", test_write_permissions);
	g_test_add_func (TPATH "wifi/write-wep-agent-keys", test_write_wifi_wep_agent_keys);
	g_test_add_func (TPATH "infiniband/write", test_write_infiniband);
	g_test_add_func (TPATH "vlan/write", test_write_vlan);
	g_test_add_func (TPATH "vlan/write-flags", test_write_vlan_flags);
	g_test_add_func (TPATH "vlan/write-only-vlanid", test_write_vlan_only_vlanid);
	g_test_add_func (TPATH "vlan/write-vlan-reorder-hdr", test_write_vlan_reorder_hdr);
	g_test_add_func (TPATH "wired/write-missing-ipv6", test_write_ethernet_missing_ipv6);
	g_test_add_func (TPATH "write-dns-options", test_write_dns_options);

	g_test_add_func (TPATH "ibft/ignored", test_read_ibft_ignored);

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

	g_test_add_func (TPATH "bond/read-master", test_read_bond_main);
	g_test_add_func (TPATH "bond/read-slave", test_read_bond_slave);
	g_test_add_func (TPATH "bond/read-slave-ib", test_read_bond_slave_ib);
	g_test_add_func (TPATH "bond/write-master", test_write_bond_main);
	g_test_add_func (TPATH "bond/write-slave", test_write_bond_slave);
	g_test_add_func (TPATH "bond/write-slave-ib", test_write_bond_slave_ib);
	g_test_add_func (TPATH "bond/bonding-opts-numeric-mode", test_read_bond_opts_mode_numeric);

	g_test_add_func (TPATH "bridge/read-master", test_read_bridge_main);
	g_test_add_func (TPATH "bridge/write-master", test_write_bridge_main);
	g_test_add_func (TPATH "bridge/read-component", test_read_bridge_component);
	g_test_add_func (TPATH "bridge/write-component", test_write_bridge_component);
	g_test_add_func (TPATH "bridge/read-missing-stp", test_read_bridge_missing_stp);

	g_test_add_func (TPATH "team/read-master", test_read_team_master);
	g_test_add_func (TPATH "team/write-master", test_write_team_master);
	g_test_add_func (TPATH "team/read-port", test_read_team_port);
	g_test_add_func (TPATH "team/write-port", test_write_team_port);
	g_test_add_func (TPATH "team/read-port-empty-config", test_read_team_port_empty_config);

	g_test_add_func (TPATH "sit/read/ignore", test_sit_read_ignore);

	/* Stuff we expect to fail for now */
	g_test_add_func (TPATH "pppoe/write-wired", test_write_wired_pppoe);
	g_test_add_func (TPATH "vpn/write", test_write_vpn);
	g_test_add_data_func (TPATH "wwan/write-gsm", GUINT_TO_POINTER (TRUE), test_write_mobile_broadband);
	g_test_add_data_func (TPATH "wwan/write-cdma", GUINT_TO_POINTER (FALSE), test_write_mobile_broadband);

	return g_test_run ();
}

