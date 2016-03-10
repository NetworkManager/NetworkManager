/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager system settings service
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
 * Copyright 2014 Red Hat, Inc.
 */

#include "nm-default.h"

#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "nm-core-internal.h"
#include "NetworkManagerUtils.h"

#include "reader.h"

#include "nm-test-utils.h"

static GPtrArray *
read_block (const char *iscsiadm_path, const char *expected_mac)
{
	GSList *blocks = NULL, *iter;
	GPtrArray *block = NULL;
	GError *error = NULL;
	gboolean success;

	success = read_ibft_blocks (iscsiadm_path, &blocks, &error);
	g_assert_no_error (error);
	g_assert (success);
	g_assert (blocks);

	for (iter = blocks; iter; iter = iter->next) {
		const char *s_hwaddr = NULL;

		if (!parse_ibft_config (iter->data, NULL, "iface.hwaddress", &s_hwaddr, NULL))
			continue;
		g_assert (s_hwaddr);
		if (nm_utils_hwaddr_matches (s_hwaddr, -1, expected_mac, -1)) {
			block = g_ptr_array_ref (iter->data);
			break;
		}
	}
	g_assert (block);

	g_slist_free_full (blocks, (GDestroyNotify) g_ptr_array_unref);
	return block;
}

static void
test_read_ibft_dhcp (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIPConfig *s_ip4;
	GError *error = NULL;
	const char *mac_address;
	const char *expected_mac_address = "00:33:21:98:b9:f1";
	GPtrArray *block;

	block = read_block (TEST_IBFT_DIR "/iscsiadm-test-dhcp", expected_mac_address);

	connection = connection_from_block (block, &error);
	g_assert_no_error (error);
	nmtst_assert_connection_verifies_without_normalization (connection);

	g_assert (!nm_connection_get_setting_vlan (connection));

	/* ===== CONNECTION SETTING ===== */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_connection_type (s_con), ==, NM_SETTING_WIRED_SETTING_NAME);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "iBFT eth1");
	g_assert_cmpint (nm_setting_connection_get_timestamp (s_con), ==, 0);
	g_assert (nm_setting_connection_get_autoconnect (s_con));
	g_assert (nm_setting_connection_get_read_only (s_con));

	/* ===== WIRED SETTING ===== */
	s_wired = nm_connection_get_setting_wired (connection);
	g_assert (s_wired);
	mac_address = nm_setting_wired_get_mac_address (s_wired);
	g_assert (mac_address);
	g_assert (nm_utils_hwaddr_matches (mac_address, -1, expected_mac_address, -1));
	g_assert_cmpint (nm_setting_wired_get_mtu (s_wired), ==, 0);

	/* ===== IPv4 SETTING ===== */
	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_AUTO);

	g_object_unref (connection);
	g_ptr_array_unref (block);
}

static void
test_read_ibft_static (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIPConfig *s_ip4;
	GError *error = NULL;
	const char *mac_address;
	const char *expected_mac_address = "00:33:21:98:b9:f0";
	NMIPAddress *ip4_addr;
	GPtrArray *block;

	block = read_block (TEST_IBFT_DIR "/iscsiadm-test-static", expected_mac_address);

	connection = connection_from_block (block, &error);
	g_assert_no_error (error);
	nmtst_assert_connection_verifies_without_normalization (connection);

	g_assert (!nm_connection_get_setting_vlan (connection));

	/* ===== CONNECTION SETTING ===== */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_connection_type (s_con), ==, NM_SETTING_WIRED_SETTING_NAME);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "iBFT eth0");
	g_assert_cmpint (nm_setting_connection_get_timestamp (s_con), ==, 0);
	g_assert (nm_setting_connection_get_autoconnect (s_con));
	g_assert (nm_setting_connection_get_read_only (s_con));

	/* ===== WIRED SETTING ===== */
	s_wired = nm_connection_get_setting_wired (connection);
	g_assert (s_wired);
	mac_address = nm_setting_wired_get_mac_address (s_wired);
	g_assert (mac_address);
	g_assert (nm_utils_hwaddr_matches (mac_address, -1, expected_mac_address, -1));
	g_assert_cmpint (nm_setting_wired_get_mtu (s_wired), ==, 0);

	/* ===== IPv4 SETTING ===== */
	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_MANUAL);

	g_assert_cmpint (nm_setting_ip_config_get_num_dns (s_ip4), ==, 2);
	g_assert_cmpstr (nm_setting_ip_config_get_dns (s_ip4, 0), ==, "10.16.255.2");
	g_assert_cmpstr (nm_setting_ip_config_get_dns (s_ip4, 1), ==, "10.16.255.3");

	g_assert_cmpint (nm_setting_ip_config_get_num_addresses (s_ip4), ==, 1);
	ip4_addr = nm_setting_ip_config_get_address (s_ip4, 0);
	g_assert (ip4_addr);
	g_assert_cmpstr (nm_ip_address_get_address (ip4_addr), ==, "192.168.32.72");
	g_assert_cmpint (nm_ip_address_get_prefix (ip4_addr), ==, 22);

	g_assert_cmpstr (nm_setting_ip_config_get_gateway (s_ip4), ==, "192.168.35.254");

	g_object_unref (connection);
	g_ptr_array_unref (block);
}

static void
test_read_ibft_malformed (gconstpointer user_data)
{
	const char *iscsiadm_path = user_data;
	GSList *blocks = NULL;
	GError *error = NULL;
	gboolean success;

	g_assert (g_file_test (iscsiadm_path, G_FILE_TEST_EXISTS));

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE, "*malformed iscsiadm record*");

	success = read_ibft_blocks (iscsiadm_path, &blocks, &error);
	g_assert_no_error (error);
	g_assert (success);
	g_assert (blocks == NULL);

	g_test_assert_expected_messages ();
}

static void
test_read_ibft_bad_address (gconstpointer user_data)
{
	const char *iscsiadm_path = user_data;
	NMConnection *connection;
	const char *expected_mac_address = "00:33:21:98:b9:f0";
	GPtrArray *block;
	GError *error = NULL;

	g_assert (g_file_test (iscsiadm_path, G_FILE_TEST_EXISTS));

	block = read_block (iscsiadm_path, expected_mac_address);

	connection = connection_from_block (block, &error);
	g_assert_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION);
	g_assert (strstr (error->message, "iBFT: malformed iscsiadm record: invalid"));
	g_clear_error (&error);
	g_assert (connection == NULL);

	g_ptr_array_unref (block);
}

static void
test_read_ibft_vlan (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingVlan *s_vlan;
	NMSettingIPConfig *s_ip4;
	const char *mac_address;
	const char *expected_mac_address = "00:33:21:98:b9:f0";
	NMIPAddress *ip4_addr;
	GError *error = NULL;
	GPtrArray *block;

	block = read_block (TEST_IBFT_DIR "/iscsiadm-test-vlan", expected_mac_address);

	connection = connection_from_block (block, &error);
	g_assert_no_error (error);
	nmtst_assert_connection_verifies_without_normalization (connection);

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_connection_type (s_con), ==, NM_SETTING_VLAN_SETTING_NAME);

	/* ===== WIRED SETTING ===== */
	s_wired = nm_connection_get_setting_wired (connection);
	g_assert (s_wired);
	mac_address = nm_setting_wired_get_mac_address (s_wired);
	g_assert (mac_address);
	g_assert (nm_utils_hwaddr_matches (mac_address, -1, expected_mac_address, -1));

	/* ===== VLAN SETTING ===== */
	s_vlan = nm_connection_get_setting_vlan (connection);
	g_assert (s_vlan);
	g_assert_cmpint (nm_setting_vlan_get_id (s_vlan), ==, 123);
	g_assert_cmpstr (nm_setting_vlan_get_parent (s_vlan), ==, NULL);

	/* ===== IPv4 SETTING ===== */
	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert (s_ip4);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_MANUAL);

	g_assert_cmpint (nm_setting_ip_config_get_num_dns (s_ip4), ==, 0);

	g_assert_cmpint (nm_setting_ip_config_get_num_addresses (s_ip4), ==, 1);
	ip4_addr = nm_setting_ip_config_get_address (s_ip4, 0);
	g_assert (ip4_addr);
	g_assert_cmpstr (nm_ip_address_get_address (ip4_addr), ==, "192.168.6.200");
	g_assert_cmpint (nm_ip_address_get_prefix (ip4_addr), ==, 24);

	g_assert_cmpstr (nm_setting_ip_config_get_gateway (s_ip4), ==, NULL);

	g_object_unref (connection);
	g_ptr_array_unref (block);
}

NMTST_DEFINE ();

#define TPATH "/settings/plugins/ibft/"

int main (int argc, char **argv)
{
	nmtst_init_assert_logging (&argc, &argv, "INFO", "DEFAULT");

	g_test_add_func (TPATH "ibft/dhcp", test_read_ibft_dhcp);
	g_test_add_func (TPATH "ibft/static", test_read_ibft_static);
	g_test_add_func (TPATH "ibft/vlan", test_read_ibft_vlan);
	g_test_add_data_func (TPATH "ibft/bad-record-read", TEST_IBFT_DIR "/iscsiadm-test-bad-record", test_read_ibft_malformed);
	g_test_add_data_func (TPATH "ibft/bad-entry-read", TEST_IBFT_DIR "/iscsiadm-test-bad-entry", test_read_ibft_malformed);
	g_test_add_data_func (TPATH "ibft/bad-ipaddr-read", TEST_IBFT_DIR "/iscsiadm-test-bad-ipaddr", test_read_ibft_bad_address);
	g_test_add_data_func (TPATH "ibft/bad-gateway-read", TEST_IBFT_DIR "/iscsiadm-test-bad-gateway", test_read_ibft_bad_address);
	g_test_add_data_func (TPATH "ibft/bad-dns1-read", TEST_IBFT_DIR "/iscsiadm-test-bad-dns1", test_read_ibft_bad_address);
	g_test_add_data_func (TPATH "ibft/bad-dns2-read", TEST_IBFT_DIR "/iscsiadm-test-bad-dns2", test_read_ibft_bad_address);

	return g_test_run ();
}

