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
 * Copyright (C) 2008 - 2009 Red Hat, Inc.
 */

#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <dbus/dbus-glib.h>

#include <nm-utils.h>
#include <nm-setting-connection.h>
#include <nm-setting-wired.h>
#include <nm-setting-wireless.h>
#include <nm-setting-wireless-security.h>
#include <nm-setting-ip4-config.h>

#include "nm-test-helpers.h"

#include "reader.h"

#define TEST_IFCFG_MINIMAL TEST_DIR"/network-scripts/ifcfg-test-minimal"

static void
test_read_minimal (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIP4Config *s_ip4;
	gboolean unmanaged = FALSE;
	char *keyfile = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	const char *tmp;
	const GByteArray *array;
	char expected_mac_address[ETH_ALEN] = { 0x00, 0x16, 0x41, 0x11, 0x22, 0x33 };
	const char *expected_id = "System test-minimal";
	guint64 expected_timestamp = 0;

	connection = connection_from_file (TEST_IFCFG_MINIMAL,
	                                   NULL,
	                                   TYPE_ETHERNET,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &error,
	                                   &ignore_error);
	ASSERT (connection != NULL,
	        "minimal-wired-read", "failed to read %s: %s", TEST_IFCFG_MINIMAL, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "minimal-wired-verify", "failed to verify %s: %s", TEST_IFCFG_MINIMAL, error->message);

	/* ===== CONNECTION SETTING ===== */

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	ASSERT (s_con != NULL,
	        "minimal-wired-verify-connection", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_MINIMAL,
	        NM_SETTING_CONNECTION_SETTING_NAME);

	/* ID */
	tmp = nm_setting_connection_get_id (s_con);
	ASSERT (tmp != NULL,
	        "minimal-wired-verify-connection", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_MINIMAL,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);
	ASSERT (strcmp (tmp, expected_id) == 0,
	        "minimal-wired-verify-connection", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_MINIMAL,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);

	/* UUID can't be tested if the ifcfg does not contain the UUID key, because
	 * the UUID is generated on the full path of the ifcfg file, which can change
	 * depending on where the tests are run.
	 */

	/* Timestamp */
	ASSERT (nm_setting_connection_get_timestamp (s_con) == expected_timestamp,
	        "minimal-wired-verify-connection", "failed to verify %s: unexpected %s /%s key value",
	        TEST_IFCFG_MINIMAL,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_TIMESTAMP);

	/* Autoconnect */
	ASSERT (nm_setting_connection_get_autoconnect (s_con) == TRUE,
	        "minimal-wired-verify-connection", "failed to verify %s: unexpected %s /%s key value",
	        TEST_IFCFG_MINIMAL,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_AUTOCONNECT);

	/* ===== WIRED SETTING ===== */

	s_wired = NM_SETTING_WIRED (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRED));
	ASSERT (s_wired != NULL,
	        "minimal-wired-verify-wired", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_MINIMAL,
	        NM_SETTING_WIRED_SETTING_NAME);

	/* MAC address */
	array = nm_setting_wired_get_mac_address (s_wired);
	ASSERT (array != NULL,
	        "minimal-wired-verify-wired", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_MINIMAL,
	        NM_SETTING_WIRED_SETTING_NAME,
	        NM_SETTING_WIRED_MAC_ADDRESS);
	ASSERT (array->len == ETH_ALEN,
	        "minimal-wired-verify-wired", "failed to verify %s: unexpected %s / %s key value length",
	        TEST_IFCFG_MINIMAL,
	        NM_SETTING_WIRED_SETTING_NAME,
	        NM_SETTING_WIRED_MAC_ADDRESS);
	ASSERT (memcmp (array->data, &expected_mac_address[0], sizeof (expected_mac_address)) == 0,
	        "minimal-wired-verify-wired", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_MINIMAL,
	        NM_SETTING_WIRED_SETTING_NAME,
	        NM_SETTING_WIRED_MAC_ADDRESS);

	ASSERT (nm_setting_wired_get_mtu (s_wired) == 0,
	        "minimal-wired-verify-wired", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_MINIMAL,
	        NM_SETTING_WIRED_SETTING_NAME,
	        NM_SETTING_WIRED_MTU);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = NM_SETTING_IP4_CONFIG (nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG));
	ASSERT (s_ip4 != NULL,
	        "minimal-wired-verify-ip4", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_MINIMAL,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME);

	/* Method */
	tmp = nm_setting_ip4_config_get_method (s_ip4);
	ASSERT (strcmp (tmp, NM_SETTING_IP4_CONFIG_METHOD_AUTO) == 0,
	        "minimal-wired-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_MINIMAL,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_METHOD);

	g_object_unref (connection);
}

#define TEST_IFCFG_UNMANAGED TEST_DIR"/network-scripts/ifcfg-test-nm-controlled"

static void
test_read_unmanaged (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIP4Config *s_ip4;
	gboolean unmanaged = FALSE;
	char *keyfile = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	const char *tmp;
	const GByteArray *array;
	char expected_mac_address[ETH_ALEN] = { 0x00, 0x11, 0x22, 0x33, 0xf8, 0x9f };
	const char *expected_id = "System test-nm-controlled";
	guint64 expected_timestamp = 0;

	connection = connection_from_file (TEST_IFCFG_UNMANAGED,
	                                   NULL,
	                                   TYPE_ETHERNET,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &error,
	                                   &ignore_error);
	ASSERT (connection != NULL,
	        "unmanaged-read", "failed to read %s: %s", TEST_IFCFG_UNMANAGED, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "unmanaged-verify", "failed to verify %s: %s", TEST_IFCFG_UNMANAGED, error->message);

	ASSERT (unmanaged == TRUE,
	        "unmanaged-verify", "failed to verify %s: expected unmanaged", TEST_IFCFG_UNMANAGED);

	/* ===== CONNECTION SETTING ===== */

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	ASSERT (s_con != NULL,
	        "unmanaged-verify-connection", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_UNMANAGED,
	        NM_SETTING_CONNECTION_SETTING_NAME);

	/* ID */
	tmp = nm_setting_connection_get_id (s_con);
	ASSERT (tmp != NULL,
	        "unmanaged-verify-connection", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_UNMANAGED,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);
	ASSERT (strcmp (tmp, expected_id) == 0,
	        "unmanaged-verify-connection", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_UNMANAGED,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);

	/* Timestamp */
	ASSERT (nm_setting_connection_get_timestamp (s_con) == expected_timestamp,
	        "unmanaged-verify-connection", "failed to verify %s: unexpected %s /%s key value",
	        TEST_IFCFG_UNMANAGED,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_TIMESTAMP);

	/* Autoconnect */
	/* Since the unmanaged connections are not completely read, defaults will
	 * be used for many settings.
	 */
	ASSERT (nm_setting_connection_get_autoconnect (s_con) == TRUE,
	        "unmanaged-verify-connection", "failed to verify %s: unexpected %s /%s key value",
	        TEST_IFCFG_UNMANAGED,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_AUTOCONNECT);

	/* ===== WIRED SETTING ===== */

	s_wired = NM_SETTING_WIRED (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRED));
	ASSERT (s_wired != NULL,
	        "unmanaged-verify-wired", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_UNMANAGED,
	        NM_SETTING_WIRED_SETTING_NAME);

	/* MAC address */
	array = nm_setting_wired_get_mac_address (s_wired);
	ASSERT (array != NULL,
	        "unmanaged-verify-wired", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_UNMANAGED,
	        NM_SETTING_WIRED_SETTING_NAME,
	        NM_SETTING_WIRED_MAC_ADDRESS);
	ASSERT (array->len == ETH_ALEN,
	        "unmanaged-verify-wired", "failed to verify %s: unexpected %s / %s key value length",
	        TEST_IFCFG_UNMANAGED,
	        NM_SETTING_WIRED_SETTING_NAME,
	        NM_SETTING_WIRED_MAC_ADDRESS);
	ASSERT (memcmp (array->data, &expected_mac_address[0], sizeof (expected_mac_address)) == 0,
	        "unmanaged-verify-wired", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_UNMANAGED,
	        NM_SETTING_WIRED_SETTING_NAME,
	        NM_SETTING_WIRED_MAC_ADDRESS);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = NM_SETTING_IP4_CONFIG (nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG));
	ASSERT (s_ip4 == NULL,
	        "unmanaged-verify-ip4", "failed to verify %s: unexpected %s setting",
	        TEST_IFCFG_UNMANAGED,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME);

	g_object_unref (connection);
}

#define TEST_IFCFG_WIRED_STATIC TEST_DIR"/network-scripts/ifcfg-test-wired-static"

static void
test_read_wired_static (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIP4Config *s_ip4;
	gboolean unmanaged = FALSE;
	char *keyfile = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	const GByteArray *array;
	char expected_mac_address[ETH_ALEN] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0xee };
	const char *tmp;
	const char *expected_id = "System test-wired-static";
	const char *expected_dns1 = "4.2.2.1";
	const char *expected_dns2 = "4.2.2.2";
	struct in_addr addr;
	const char *expected_address1 = "192.168.1.5";
	const char *expected_address1_gw = "192.168.1.1";
	NMIP4Address *ip4_addr;

	connection = connection_from_file (TEST_IFCFG_WIRED_STATIC,
	                                   NULL,
	                                   TYPE_ETHERNET,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &error,
	                                   &ignore_error);
	ASSERT (connection != NULL,
	        "wired-static-read", "failed to read %s: %s", TEST_IFCFG_WIRED_STATIC, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "wired-static-verify", "failed to verify %s: %s", TEST_IFCFG_WIRED_STATIC, error->message);

	ASSERT (unmanaged == FALSE,
	        "wired-static-verify", "failed to verify %s: unexpected unmanaged value", TEST_IFCFG_WIRED_STATIC);

	/* ===== CONNECTION SETTING ===== */

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	ASSERT (s_con != NULL,
	        "wired-static-verify-connection", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIRED_STATIC,
	        NM_SETTING_CONNECTION_SETTING_NAME);

	/* ID */
	tmp = nm_setting_connection_get_id (s_con);
	ASSERT (tmp != NULL,
	        "wired-static-verify-connection", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIRED_STATIC,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);
	ASSERT (strcmp (tmp, expected_id) == 0,
	        "wired-static-verify-connection", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_STATIC,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);

	/* Timestamp */
	ASSERT (nm_setting_connection_get_timestamp (s_con) == 0,
	        "wired-static-verify-connection", "failed to verify %s: unexpected %s /%s key value",
	        TEST_IFCFG_WIRED_STATIC,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_TIMESTAMP);

	/* Autoconnect */
	ASSERT (nm_setting_connection_get_autoconnect (s_con) == TRUE,
	        "wired-static-verify-connection", "failed to verify %s: unexpected %s /%s key value",
	        TEST_IFCFG_WIRED_STATIC,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_AUTOCONNECT);

	/* ===== WIRED SETTING ===== */

	s_wired = NM_SETTING_WIRED (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRED));
	ASSERT (s_wired != NULL,
	        "wired-static-verify-wired", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIRED_STATIC,
	        NM_SETTING_WIRED_SETTING_NAME);

	/* MAC address */
	array = nm_setting_wired_get_mac_address (s_wired);
	ASSERT (array != NULL,
	        "wired-static-verify-wired", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIRED_STATIC,
	        NM_SETTING_WIRED_SETTING_NAME,
	        NM_SETTING_WIRED_MAC_ADDRESS);
	ASSERT (array->len == ETH_ALEN,
	        "wired-static-verify-wired", "failed to verify %s: unexpected %s / %s key value length",
	        TEST_IFCFG_WIRED_STATIC,
	        NM_SETTING_WIRED_SETTING_NAME,
	        NM_SETTING_WIRED_MAC_ADDRESS);
	ASSERT (memcmp (array->data, &expected_mac_address[0], sizeof (expected_mac_address)) == 0,
	        "wired-static-verify-wired", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_STATIC,
	        NM_SETTING_WIRED_SETTING_NAME,
	        NM_SETTING_WIRED_MAC_ADDRESS);

	ASSERT (nm_setting_wired_get_mtu (s_wired) == 1492,
	        "wired-static-verify-wired", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_STATIC,
	        NM_SETTING_WIRED_SETTING_NAME,
	        NM_SETTING_WIRED_MTU);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = NM_SETTING_IP4_CONFIG (nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG));
	ASSERT (s_ip4 != NULL,
	        "wired-static-verify-ip4", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIRED_STATIC,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME);

	/* Method */
	tmp = nm_setting_ip4_config_get_method (s_ip4);
	ASSERT (strcmp (tmp, NM_SETTING_IP4_CONFIG_METHOD_MANUAL) == 0,
	        "wired-static-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_STATIC,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_METHOD);

	/* DNS Addresses */
	ASSERT (nm_setting_ip4_config_get_num_dns (s_ip4) == 2,
	        "wired-static-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_STATIC,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS);

	ASSERT (inet_pton (AF_INET, expected_dns1, &addr) > 0,
	        "wired-static-verify-ip4", "failed to verify %s: couldn't convert DNS IP address #1",
	        TEST_IFCFG_WIRED_STATIC,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS);
	ASSERT (nm_setting_ip4_config_get_dns (s_ip4, 0) == addr.s_addr,
	        "wired-static-verify-ip4", "failed to verify %s: unexpected %s / %s key value #1",
	        TEST_IFCFG_WIRED_STATIC,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS);

	ASSERT (inet_pton (AF_INET, expected_dns2, &addr) > 0,
	        "wired-static-verify-ip4", "failed to verify %s: couldn't convert DNS IP address #2",
	        TEST_IFCFG_WIRED_STATIC,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS);
	ASSERT (nm_setting_ip4_config_get_dns (s_ip4, 1) == addr.s_addr,
	        "wired-static-verify-ip4", "failed to verify %s: unexpected %s / %s key value #2",
	        TEST_IFCFG_WIRED_STATIC,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS);

	ASSERT (nm_setting_ip4_config_get_num_addresses (s_ip4) == 1,
	        "wired-static-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_STATIC,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS);

	/* Address #1 */
	ip4_addr = nm_setting_ip4_config_get_address (s_ip4, 0);
	ASSERT (ip4_addr,
	        "wired-static-verify-ip4", "failed to verify %s: missing IP4 address #1",
	        TEST_IFCFG_WIRED_STATIC,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_ADDRESSES);

	ASSERT (nm_ip4_address_get_prefix (ip4_addr) == 24,
	        "wired-static-verify-ip4", "failed to verify %s: unexpected IP4 address #1 gateway",
	        TEST_IFCFG_WIRED_STATIC,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_ADDRESSES);

	ASSERT (inet_pton (AF_INET, expected_address1, &addr) > 0,
	        "wired-static-verify-ip4", "failed to verify %s: couldn't convert IP address #1",
	        TEST_IFCFG_WIRED_STATIC,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS);
	ASSERT (nm_ip4_address_get_address (ip4_addr) == addr.s_addr,
	        "wired-static-verify-ip4", "failed to verify %s: unexpected IP4 address #1",
	        TEST_IFCFG_WIRED_STATIC,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_ADDRESSES);

	ASSERT (inet_pton (AF_INET, expected_address1_gw, &addr) > 0,
	        "wired-static-verify-ip4", "failed to verify %s: couldn't convert IP address #1 gateway",
	        TEST_IFCFG_WIRED_STATIC,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_ADDRESSES);
	ASSERT (nm_ip4_address_get_gateway (ip4_addr) == addr.s_addr,
	        "wired-static-verify-ip4", "failed to verify %s: unexpected IP4 address #1 gateway",
	        TEST_IFCFG_WIRED_STATIC,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_ADDRESSES);

	g_object_unref (connection);
}

#define TEST_IFCFG_WIRED_DHCP TEST_DIR"/network-scripts/ifcfg-test-wired-dhcp"

static void
test_read_wired_dhcp (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIP4Config *s_ip4;
	gboolean unmanaged = FALSE;
	char *keyfile = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	const GByteArray *array;
	char expected_mac_address[ETH_ALEN] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0xee };
	const char *tmp;
	const char *expected_id = "System test-wired-dhcp";
	const char *expected_dns1 = "4.2.2.1";
	const char *expected_dns2 = "4.2.2.2";
	struct in_addr addr;
	const char *expected_dhcp_hostname = "foobar";

	connection = connection_from_file (TEST_IFCFG_WIRED_DHCP,
	                                   NULL,
	                                   TYPE_ETHERNET,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &error,
	                                   &ignore_error);
	ASSERT (connection != NULL,
	        "wired-dhcp-read", "failed to read %s: %s", TEST_IFCFG_WIRED_DHCP, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "wired-dhcp-verify", "failed to verify %s: %s", TEST_IFCFG_WIRED_DHCP, error->message);

	ASSERT (unmanaged == FALSE,
	        "wired-dhcp-verify", "failed to verify %s: unexpected unmanaged value", TEST_IFCFG_WIRED_DHCP);

	/* ===== CONNECTION SETTING ===== */

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
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

	s_wired = NM_SETTING_WIRED (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRED));
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

	s_ip4 = NM_SETTING_IP4_CONFIG (nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG));
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
	ASSERT (nm_setting_ip4_config_get_dns (s_ip4, 0) == addr.s_addr,
	        "wired-dhcp-verify-ip4", "failed to verify %s: unexpected %s / %s key value #1",
	        TEST_IFCFG_WIRED_DHCP,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS);

	ASSERT (inet_pton (AF_INET, expected_dns2, &addr) > 0,
	        "wired-dhcp-verify-ip4", "failed to verify %s: couldn't convert DNS IP address #2",
	        TEST_IFCFG_WIRED_DHCP,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS);
	ASSERT (nm_setting_ip4_config_get_dns (s_ip4, 1) == addr.s_addr,
	        "wired-dhcp-verify-ip4", "failed to verify %s: unexpected %s / %s key value #2",
	        TEST_IFCFG_WIRED_DHCP,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS);


	g_object_unref (connection);
}

#define TEST_IFCFG_WIRED_GLOBAL_GATEWAY TEST_DIR"/network-scripts/ifcfg-test-wired-global-gateway"
#define TEST_NETWORK_WIRED_GLOBAL_GATEWAY TEST_DIR"/network-scripts/network-test-wired-global-gateway"

static void
test_read_wired_global_gateway (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIP4Config *s_ip4;
	gboolean unmanaged = FALSE;
	char *keyfile = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	const char *tmp;
	const char *expected_id = "System test-wired-global-gateway";
	struct in_addr addr;
	const char *expected_address1 = "192.168.1.5";
	const char *expected_address1_gw = "192.168.1.2";
	NMIP4Address *ip4_addr;

	connection = connection_from_file (TEST_IFCFG_WIRED_GLOBAL_GATEWAY,
	                                   TEST_NETWORK_WIRED_GLOBAL_GATEWAY,
	                                   TYPE_ETHERNET,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &error,
	                                   &ignore_error);
	ASSERT (connection != NULL,
	        "wired-global-gateway-read", "failed to read %s: %s", TEST_IFCFG_WIRED_GLOBAL_GATEWAY, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "wired-global-gateway-verify", "failed to verify %s: %s", TEST_IFCFG_WIRED_GLOBAL_GATEWAY, error->message);

	ASSERT (unmanaged == FALSE,
	        "wired-global-gateway-verify", "failed to verify %s: unexpected unmanaged value", TEST_IFCFG_WIRED_GLOBAL_GATEWAY);

	/* ===== CONNECTION SETTING ===== */

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
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

	s_wired = NM_SETTING_WIRED (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRED));
	ASSERT (s_wired != NULL,
	        "wired-global-gateway-verify-wired", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIRED_GLOBAL_GATEWAY,
	        NM_SETTING_WIRED_SETTING_NAME);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = NM_SETTING_IP4_CONFIG (nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG));
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
	        "wired-global-gateway-verify-ip4", "failed to verify %s: unexpected IP4 address #1 gateway",
	        TEST_IFCFG_WIRED_GLOBAL_GATEWAY,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_ADDRESSES);

	ASSERT (inet_pton (AF_INET, expected_address1, &addr) > 0,
	        "wired-global-gateway-verify-ip4", "failed to verify %s: couldn't convert IP address #1",
	        TEST_IFCFG_WIRED_GLOBAL_GATEWAY,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS);
	ASSERT (nm_ip4_address_get_address (ip4_addr) == addr.s_addr,
	        "wired-global-gateway-verify-ip4", "failed to verify %s: unexpected IP4 address #1",
	        TEST_IFCFG_WIRED_GLOBAL_GATEWAY,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_ADDRESSES);

	ASSERT (inet_pton (AF_INET, expected_address1_gw, &addr) > 0,
	        "wired-global-gateway-verify-ip4", "failed to verify %s: couldn't convert IP address #1 gateway",
	        TEST_IFCFG_WIRED_GLOBAL_GATEWAY,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_ADDRESSES);
	ASSERT (nm_ip4_address_get_gateway (ip4_addr) == addr.s_addr,
	        "wired-global-gateway-verify-ip4", "failed to verify %s: unexpected IP4 address #1 gateway",
	        TEST_IFCFG_WIRED_GLOBAL_GATEWAY,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_ADDRESSES);

	g_object_unref (connection);
}

#define TEST_IFCFG_WIRED_NEVER_DEFAULT TEST_DIR"/network-scripts/ifcfg-test-wired-never-default"
#define TEST_NETWORK_WIRED_NEVER_DEFAULT TEST_DIR"/network-scripts/network-test-wired-never-default"

static void
test_read_wired_never_default (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIP4Config *s_ip4;
	gboolean unmanaged = FALSE;
	char *keyfile = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	const char *tmp;
	const char *expected_id = "System test-wired-never-default";

	connection = connection_from_file (TEST_IFCFG_WIRED_NEVER_DEFAULT,
	                                   TEST_NETWORK_WIRED_NEVER_DEFAULT,
	                                   TYPE_ETHERNET,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &error,
	                                   &ignore_error);
	ASSERT (connection != NULL,
	        "wired-never-default-read", "failed to read %s: %s", TEST_IFCFG_WIRED_NEVER_DEFAULT, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "wired-never-default-verify", "failed to verify %s: %s", TEST_IFCFG_WIRED_NEVER_DEFAULT, error->message);

	ASSERT (unmanaged == FALSE,
	        "wired-never-default-verify", "failed to verify %s: unexpected unmanaged value", TEST_IFCFG_WIRED_NEVER_DEFAULT);

	/* ===== CONNECTION SETTING ===== */

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
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

	s_wired = NM_SETTING_WIRED (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRED));
	ASSERT (s_wired != NULL,
	        "wired-never-default-verify-wired", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIRED_NEVER_DEFAULT,
	        NM_SETTING_WIRED_SETTING_NAME);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = NM_SETTING_IP4_CONFIG (nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG));
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

	g_object_unref (connection);
}

#define TEST_IFCFG_ONBOOT_NO TEST_DIR"/network-scripts/ifcfg-test-onboot-no"

static void
test_read_onboot_no (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	gboolean unmanaged = FALSE;
	char *keyfile = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;

	connection = connection_from_file (TEST_IFCFG_ONBOOT_NO,
	                                   NULL,
	                                   TYPE_ETHERNET,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &error,
	                                   &ignore_error);
	ASSERT (connection != NULL,
	        "onboot-no-read", "failed to read %s: %s", TEST_IFCFG_ONBOOT_NO, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "onboot-no-verify", "failed to verify %s: %s", TEST_IFCFG_ONBOOT_NO, error->message);

	ASSERT (unmanaged == FALSE,
	        "onboot-no-verify", "failed to verify %s: unexpected unmanaged value", TEST_IFCFG_WIRED_DHCP);

	/* ===== CONNECTION SETTING ===== */

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	ASSERT (s_con != NULL,
	        "onboot-no-verify-connection", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_ONBOOT_NO,
	        NM_SETTING_CONNECTION_SETTING_NAME);

	/* Autoconnect */
	ASSERT (nm_setting_connection_get_autoconnect (s_con) == FALSE,
	        "wired-dhcp-verify-connection", "failed to verify %s: unexpected %s /%s key value",
	        TEST_IFCFG_ONBOOT_NO,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_AUTOCONNECT);

	g_object_unref (connection);
}

#define TEST_IFCFG_WIFI_OPEN TEST_DIR"/network-scripts/ifcfg-test-wifi-open"

static void
test_read_wifi_unencrypted (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	NMSettingIP4Config *s_ip4;
	gboolean unmanaged = FALSE;
	char *keyfile = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	const char *tmp;
	const GByteArray *array;
	char expected_mac_address[ETH_ALEN] = { 0x00, 0x16, 0x41, 0x11, 0x22, 0x33 };
	const char *expected_id = "System blahblah (test-wifi-open)";
	guint64 expected_timestamp = 0;
	const char *expected_ssid = "blahblah";
	const char *expected_mode = "infrastructure";
	const guint32 expected_channel = 0;

	connection = connection_from_file (TEST_IFCFG_WIFI_OPEN,
	                                   NULL,
	                                   TYPE_WIRELESS,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &error,
	                                   &ignore_error);
	ASSERT (connection != NULL,
	        "wifi-open-read", "failed to read %s: %s", TEST_IFCFG_WIFI_OPEN, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "wifi-open-verify", "failed to verify %s: %s", TEST_IFCFG_WIFI_OPEN, error->message);

	/* ===== CONNECTION SETTING ===== */

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
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

	s_wireless = NM_SETTING_WIRELESS (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRELESS));
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

	ASSERT (nm_setting_wireless_get_security (s_wireless) == NULL,
	        "wifi-open-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_OPEN,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_SEC);

	ASSERT (nm_setting_wireless_get_channel (s_wireless) == expected_channel,
	        "wifi-open-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_OPEN,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_CHANNEL);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = NM_SETTING_IP4_CONFIG (nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG));
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

	g_object_unref (connection);
}

#define TEST_IFCFG_WIFI_WEP TEST_DIR"/network-scripts/ifcfg-test-wifi-wep"

static void
test_read_wifi_wep (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	NMSettingWirelessSecurity *s_wsec;
	NMSettingIP4Config *s_ip4;
	gboolean unmanaged = FALSE;
	char *keyfile = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	const char *tmp;
	const GByteArray *array;
	char expected_mac_address[ETH_ALEN] = { 0x00, 0x16, 0x41, 0x11, 0x22, 0x33 };
	const char *expected_id = "System blahblah (test-wifi-wep)";
	guint64 expected_timestamp = 0;
	const char *expected_ssid = "blahblah";
	const char *expected_mode = "infrastructure";
	const guint32 expected_channel = 0;
	const char *expected_wep_key0 = "0123456789abcdef0123456789";

	connection = connection_from_file (TEST_IFCFG_WIFI_WEP,
	                                   NULL,
	                                   TYPE_WIRELESS,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &error,
	                                   &ignore_error);
	ASSERT (connection != NULL,
	        "wifi-wep-read", "failed to read %s: %s", TEST_IFCFG_WIFI_WEP, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "wifi-wep-verify", "failed to verify %s: %s", TEST_IFCFG_WIFI_WEP, error->message);

	/* ===== CONNECTION SETTING ===== */

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
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

	s_wireless = NM_SETTING_WIRELESS (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRELESS));
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

	/* Security */
	tmp = nm_setting_wireless_get_security (s_wireless);
	ASSERT (tmp != NULL,
	        "wifi-wep-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WEP,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_SEC);
	ASSERT (strcmp (tmp, NM_SETTING_WIRELESS_SECURITY_SETTING_NAME) == 0,
	        "wifi-wep-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WEP,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_SEC);


	/* ===== WIRELESS SECURITY SETTING ===== */

	s_wsec = NM_SETTING_WIRELESS_SECURITY (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRELESS_SECURITY));
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

	s_ip4 = NM_SETTING_IP4_CONFIG (nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG));
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

	g_object_unref (connection);
}

#define TEST_IFCFG_WIFI_WEP_ADHOC TEST_DIR"/network-scripts/ifcfg-test-wifi-wep-adhoc"

static void
test_read_wifi_wep_adhoc (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	NMSettingWirelessSecurity *s_wsec;
	NMSettingIP4Config *s_ip4;
	gboolean unmanaged = FALSE;
	char *keyfile = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	const char *tmp;
	const GByteArray *array;
	const char *expected_id = "System blahblah (test-wifi-wep-adhoc)";
	const char *expected_ssid = "blahblah";
	const char *expected_mode = "adhoc";
	const char *expected_wep_key0 = "0123456789abcdef0123456789";
	struct in_addr addr;
	const char *expected_dns1 = "4.2.2.1";
	const char *expected_dns2 = "4.2.2.2";

	connection = connection_from_file (TEST_IFCFG_WIFI_WEP_ADHOC,
	                                   NULL,
	                                   TYPE_WIRELESS,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &error,
	                                   &ignore_error);
	ASSERT (connection != NULL,
	        "wifi-wep-adhoc-read", "failed to read %s: %s", TEST_IFCFG_WIFI_WEP_ADHOC, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "wifi-wep-adhoc-verify", "failed to verify %s: %s", TEST_IFCFG_WIFI_WEP_ADHOC, error->message);

	/* ===== CONNECTION SETTING ===== */

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
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

	s_wireless = NM_SETTING_WIRELESS (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRELESS));
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

	/* Channel (doesn't work yet) */
	ASSERT (nm_setting_wireless_get_channel (s_wireless) == 0,
	        "wifi-wep-adhoc-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WEP_ADHOC,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_CHANNEL);

	/* Security */
	tmp = nm_setting_wireless_get_security (s_wireless);
	ASSERT (tmp != NULL,
	        "wifi-wep-adhoc-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WEP_ADHOC,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_SEC);
	ASSERT (strcmp (tmp, NM_SETTING_WIRELESS_SECURITY_SETTING_NAME) == 0,
	        "wifi-wep-adhoc-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WEP_ADHOC,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_SEC);


	/* ===== WIRELESS SECURITY SETTING ===== */

	s_wsec = NM_SETTING_WIRELESS_SECURITY (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRELESS_SECURITY));
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

	s_ip4 = NM_SETTING_IP4_CONFIG (nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG));
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
	ASSERT (nm_setting_ip4_config_get_dns (s_ip4, 0) == addr.s_addr,
	        "wifi-wep-adhoc-verify-ip4", "failed to verify %s: unexpected %s / %s key value #1",
	        TEST_IFCFG_WIFI_WEP_ADHOC,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS);

	ASSERT (inet_pton (AF_INET, expected_dns2, &addr) > 0,
	        "wifi-wep-adhoc-verify-ip4", "failed to verify %s: couldn't convert DNS IP address #2",
	        TEST_IFCFG_WIFI_WEP_ADHOC,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS);
	ASSERT (nm_setting_ip4_config_get_dns (s_ip4, 1) == addr.s_addr,
	        "wifi-wep-adhoc-verify-ip4", "failed to verify %s: unexpected %s / %s key value #2",
	        TEST_IFCFG_WIFI_WEP_ADHOC,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS);

	g_object_unref (connection);
}

#define TEST_IFCFG_WIFI_WPA_PSK TEST_DIR"/network-scripts/ifcfg-test-wifi-wpa-psk"

static void
test_read_wifi_wpa_psk (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	NMSettingWirelessSecurity *s_wsec;
	NMSettingIP4Config *s_ip4;
	gboolean unmanaged = FALSE;
	char *keyfile = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	const char *tmp;
	const GByteArray *array;
	char expected_mac_address[ETH_ALEN] = { 0x00, 0x16, 0x41, 0x11, 0x22, 0x33 };
	const char *expected_id = "System blahblah (test-wifi-wpa-psk)";
	guint64 expected_timestamp = 0;
	const char *expected_ssid = "blahblah";
	const char *expected_mode = "infrastructure";
	const guint32 expected_channel = 0;
	const char *expected_key_mgmt = "wpa-psk";
	const char *expected_psk = "1da190379817bc360dda52e85c388c439a21ea5c7bf819c64e9da051807deae6";
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
	                                   &unmanaged,
	                                   &keyfile,
	                                   &error,
	                                   &ignore_error);
	ASSERT (connection != NULL,
	        "wifi-wpa-psk-read", "failed to read %s: %s", TEST_IFCFG_WIFI_WPA_PSK, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "wifi-wpa-psk-verify", "failed to verify %s: %s", TEST_IFCFG_WIFI_WPA_PSK, error->message);

	/* ===== CONNECTION SETTING ===== */

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
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

	s_wireless = NM_SETTING_WIRELESS (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRELESS));
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

	/* Security */
	tmp = nm_setting_wireless_get_security (s_wireless);
	ASSERT (tmp != NULL,
	        "wifi-wpa-psk-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WPA_PSK,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_SEC);
	ASSERT (strcmp (tmp, NM_SETTING_WIRELESS_SECURITY_SETTING_NAME) == 0,
	        "wifi-wpa-psk-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WPA_PSK,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_SEC);

	/* ===== WIRELESS SECURITY SETTING ===== */

	s_wsec = NM_SETTING_WIRELESS_SECURITY (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRELESS_SECURITY));
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

	s_ip4 = NM_SETTING_IP4_CONFIG (nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG));
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

	g_object_unref (connection);
}

#define TEST_IFCFG_WIFI_WPA_PSK_ADHOC TEST_DIR"/network-scripts/ifcfg-test-wifi-wpa-psk-adhoc"

static void
test_read_wifi_wpa_psk_adhoc (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	NMSettingWirelessSecurity *s_wsec;
	NMSettingIP4Config *s_ip4;
	gboolean unmanaged = FALSE;
	char *keyfile = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	const char *tmp;
	const char *expected_id = "System blahblah (test-wifi-wpa-psk-adhoc)";
	const char *expected_mode = "adhoc";
	const char *expected_key_mgmt = "wpa-none";
	const char *expected_psk = "1da190379817bc360dda52e85c388c439a21ea5c7bf819c64e9da051807deae6";
	const char *expected_group = "ccmp";
	const char *expected_proto = "wpa";

	connection = connection_from_file (TEST_IFCFG_WIFI_WPA_PSK_ADHOC,
	                                   NULL,
	                                   TYPE_WIRELESS,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &error,
	                                   &ignore_error);
	ASSERT (connection != NULL,
	        "wifi-wpa-psk-adhoc-read", "failed to read %s: %s", TEST_IFCFG_WIFI_WPA_PSK_ADHOC, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "wifi-wpa-psk-adhoc-verify", "failed to verify %s: %s", TEST_IFCFG_WIFI_WPA_PSK_ADHOC, error->message);

	/* ===== CONNECTION SETTING ===== */

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
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

	s_wireless = NM_SETTING_WIRELESS (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRELESS));
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

	/* Security */
	tmp = nm_setting_wireless_get_security (s_wireless);
	ASSERT (tmp != NULL,
	        "wifi-wpa-psk-adhoc-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WPA_PSK_ADHOC,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_SEC);
	ASSERT (strcmp (tmp, NM_SETTING_WIRELESS_SECURITY_SETTING_NAME) == 0,
	        "wifi-wpa-psk-adhoc-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WPA_PSK_ADHOC,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_SEC);

	/* ===== WIRELESS SECURITY SETTING ===== */

	s_wsec = NM_SETTING_WIRELESS_SECURITY (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRELESS_SECURITY));
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

	s_ip4 = NM_SETTING_IP4_CONFIG (nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG));
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

	g_object_unref (connection);
}

#define TEST_IFCFG_WIFI_WPA_PSK_HEX TEST_DIR"/network-scripts/ifcfg-test-wifi-wpa-psk-hex"

static void
test_read_wifi_wpa_psk_hex (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	NMSettingWirelessSecurity *s_wsec;
	NMSettingIP4Config *s_ip4;
	gboolean unmanaged = FALSE;
	char *keyfile = NULL;
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
	                                   &unmanaged,
	                                   &keyfile,
	                                   &error,
	                                   &ignore_error);
	ASSERT (connection != NULL,
	        "wifi-wpa-psk-hex-read", "failed to read %s: %s", TEST_IFCFG_WIFI_WPA_PSK_HEX, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "wifi-wpa-psk-hex-verify", "failed to verify %s: %s", TEST_IFCFG_WIFI_WPA_PSK_HEX, error->message);

	/* ===== CONNECTION SETTING ===== */

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
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

	s_wireless = NM_SETTING_WIRELESS (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRELESS));
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

	/* Security */
	tmp = nm_setting_wireless_get_security (s_wireless);
	ASSERT (tmp != NULL,
	        "wifi-wpa-psk-hex-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WPA_PSK_HEX,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_SEC);
	ASSERT (strcmp (tmp, NM_SETTING_WIRELESS_SECURITY_SETTING_NAME) == 0,
	        "wifi-wpa-psk-hex-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WPA_PSK_HEX,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_SEC);

	/* ===== WIRELESS SECURITY SETTING ===== */

	s_wsec = NM_SETTING_WIRELESS_SECURITY (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRELESS_SECURITY));
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

	s_ip4 = NM_SETTING_IP4_CONFIG (nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG));
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

	g_object_unref (connection);
}

int main (int argc, char **argv)
{
	GError *error = NULL;
	DBusGConnection *bus;
	char *basename;

	g_type_init ();
	bus = dbus_g_bus_get (DBUS_BUS_SESSION, NULL);

	if (!nm_utils_init (&error))
		FAIL ("nm-utils-init", "failed to initialize libnm-util: %s", error->message);

	/* The tests */
	test_read_unmanaged ();
	test_read_minimal ();
	test_read_wired_static ();
	test_read_wired_dhcp ();
	test_read_wired_global_gateway ();
	test_read_wired_never_default ();
	test_read_onboot_no ();
	test_read_wifi_unencrypted ();
	test_read_wifi_wep ();
	test_read_wifi_wep_adhoc ();
	test_read_wifi_wpa_psk ();
	test_read_wifi_wpa_psk_adhoc ();
	test_read_wifi_wpa_psk_hex ();

	basename = g_path_get_basename (argv[0]);
	fprintf (stdout, "%s: SUCCESS\n", basename);
	g_free (basename);
	return 0;
}

