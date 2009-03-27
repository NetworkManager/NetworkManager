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
#include <nm-setting-8021x.h>

#include "nm-test-helpers.h"

#include "common.h"
#include "reader.h"
#include "writer.h"

typedef enum {
	CK_CA_CERT = 0,
	CK_CLIENT_CERT = 1,
	CK_PRIV_KEY = 2
} CertKeyType;

static gboolean
verify_cert_or_key (CertKeyType ck_type,
                    NMSetting8021x *s_compare,
                    const char *file,
                    const char *privkey_password,
                    const char *ifcfg,
                    const char *test_name,
                    const char *setting_key)
{
	NMSetting8021x *s_8021x;
	GError *error = NULL;
	gboolean success = FALSE;
	const GByteArray *expected = NULL, *setting = NULL;
	gboolean phase2 = FALSE;

	if (strstr (setting_key, "phase2"))
		phase2 = TRUE;

	/* CA Cert */
	s_8021x = (NMSetting8021x *) nm_setting_802_1x_new ();
	ASSERT (s_8021x != NULL,
	        test_name, "failed to verify %s: could not create temp 802.1x setting",
	        ifcfg);

	if (ck_type == CK_CA_CERT) {
		if (phase2)
			success = nm_setting_802_1x_set_phase2_ca_cert_from_file (s_8021x, file, NULL, &error);
		else
			success = nm_setting_802_1x_set_ca_cert_from_file (s_8021x, file, NULL, &error);
	} else if (ck_type == CK_CLIENT_CERT) {
		if (phase2)
			success = nm_setting_802_1x_set_phase2_client_cert_from_file (s_8021x, file, NULL, &error);
		else
			success = nm_setting_802_1x_set_client_cert_from_file (s_8021x, file, NULL, &error);
	} else if (ck_type == CK_PRIV_KEY) {
		if (phase2)
			success = nm_setting_802_1x_set_phase2_private_key_from_file (s_8021x, file, privkey_password, NULL, &error);
		else
			success = nm_setting_802_1x_set_private_key_from_file (s_8021x, file, privkey_password, NULL, &error);
	}
	ASSERT (success == TRUE,
	        test_name, "failed to verify %s: could not load item for %s / %s: %s",
	        ifcfg, NM_SETTING_802_1X_SETTING_NAME, setting_key, error->message);

	if (ck_type == CK_CA_CERT) {
		if (phase2)
			expected = nm_setting_802_1x_get_phase2_ca_cert (s_8021x);
		else
			expected = nm_setting_802_1x_get_ca_cert (s_8021x);
	} else if (ck_type == CK_CLIENT_CERT) {
		if (phase2)
			expected = nm_setting_802_1x_get_phase2_client_cert (s_8021x);
		else
			expected = nm_setting_802_1x_get_client_cert (s_8021x);
	} else if (ck_type == CK_PRIV_KEY) {
		if (phase2)
			expected = nm_setting_802_1x_get_phase2_private_key (s_8021x);
		else
			expected = nm_setting_802_1x_get_private_key (s_8021x);
	}
	ASSERT (expected != NULL,
	        test_name, "failed to verify %s: failed to get read item for %s / %s",
	        ifcfg, NM_SETTING_802_1X_SETTING_NAME, setting_key);

	if (ck_type == CK_CA_CERT) {
		if (phase2)
			setting = nm_setting_802_1x_get_phase2_ca_cert (s_compare);
		else
			setting = nm_setting_802_1x_get_ca_cert (s_compare);
	} else if (ck_type == CK_CLIENT_CERT) {
		if (phase2)
			setting = nm_setting_802_1x_get_phase2_client_cert (s_compare);
		else
			setting = nm_setting_802_1x_get_client_cert (s_compare);
	} else if (ck_type == CK_PRIV_KEY) {
		if (phase2)
			setting = nm_setting_802_1x_get_phase2_private_key (s_compare);
		else
			setting = nm_setting_802_1x_get_private_key (s_compare);
	}
	ASSERT (setting != NULL,
	        test_name, "failed to verify %s: missing %s / %s key",
	        ifcfg, NM_SETTING_802_1X_SETTING_NAME, setting_key);

	ASSERT (setting->len == expected->len,
	        test_name, "failed to verify %s: unexpected %s / %s certificate length",
	        test_name, NM_SETTING_802_1X_SETTING_NAME, setting_key);

	ASSERT (memcmp (setting->data, expected->data, setting->len) == 0,
	        test_name, "failed to verify %s: %s / %s key certificate mismatch",
	        ifcfg, NM_SETTING_802_1X_SETTING_NAME, setting_key);

	g_object_unref (s_8021x);
	return TRUE;
}


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
	        "onboot-no-verify", "failed to verify %s: unexpected unmanaged value", TEST_IFCFG_ONBOOT_NO);

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

#define TEST_IFCFG_WIRED_8021x_PEAP_MSCHAPV2 TEST_DIR"/network-scripts/ifcfg-test-wired-8021x-peap-mschapv2"
#define TEST_IFCFG_WIRED_8021x_PEAP_MSCHAPV2_CA_CERT TEST_DIR"/network-scripts/test_ca_cert.pem"

static void
test_read_wired_8021x_peap_mschapv2 (void)
{
	NMConnection *connection;
	NMSettingWired *s_wired;
	NMSettingIP4Config *s_ip4;
	NMSetting8021x *s_8021x;
	NMSetting8021x *tmp_8021x;
	gboolean unmanaged = FALSE;
	char *keyfile = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	const char *tmp;
	const char *expected_identity = "David Smith";
	const char *expected_password = "foobar baz";
	gboolean success = FALSE;
	const GByteArray *expected_ca_cert;
	const GByteArray *read_ca_cert;

	connection = connection_from_file (TEST_IFCFG_WIRED_8021x_PEAP_MSCHAPV2,
	                                   NULL,
	                                   TYPE_ETHERNET,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &error,
	                                   &ignore_error);
	ASSERT (connection != NULL,
	        "wired-8021x-peap-mschapv2-read", "failed to read %s: %s", TEST_IFCFG_WIRED_8021x_PEAP_MSCHAPV2, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "wired-8021x-peap-mschapv2-verify", "failed to verify %s: %s", TEST_IFCFG_WIRED_8021x_PEAP_MSCHAPV2, error->message);

	ASSERT (unmanaged == FALSE,
	        "wired-8021x-peap-mschapv2-verify", "failed to verify %s: unexpected unmanaged value", TEST_IFCFG_WIRED_8021x_PEAP_MSCHAPV2);

	/* ===== WIRED SETTING ===== */

	s_wired = NM_SETTING_WIRED (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRED));
	ASSERT (s_wired != NULL,
	        "wired-8021x-peap-mschapv2-verify-wired", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIRED_8021x_PEAP_MSCHAPV2,
	        NM_SETTING_WIRED_SETTING_NAME);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = NM_SETTING_IP4_CONFIG (nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG));
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
	s_8021x = NM_SETTING_802_1X (nm_connection_get_setting (connection, NM_TYPE_SETTING_802_1X));
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
	ASSERT (tmp_8021x != NULL,
	        "wired-8021x-peap-mschapv2-verify-8021x", "failed to verify %s: could not create temp 802.1x setting",
	        TEST_IFCFG_WIRED_8021x_PEAP_MSCHAPV2,
	        NM_SETTING_802_1X_SETTING_NAME,
	        NM_SETTING_802_1X_CA_CERT);

	success = nm_setting_802_1x_set_ca_cert_from_file (tmp_8021x,
	                                                   TEST_IFCFG_WIRED_8021x_PEAP_MSCHAPV2_CA_CERT,
	                                                   NULL,
	                                                   &error);
	ASSERT (success == TRUE,
	        "wired-8021x-peap-mschapv2-verify-8021x", "failed to verify %s: could not load CA certificate",
	        TEST_IFCFG_WIRED_8021x_PEAP_MSCHAPV2,
	        NM_SETTING_802_1X_SETTING_NAME,
	        NM_SETTING_802_1X_CA_CERT);
	expected_ca_cert = nm_setting_802_1x_get_ca_cert (tmp_8021x);
	ASSERT (expected_ca_cert != NULL,
	        "wired-8021x-peap-mschapv2-verify-8021x", "failed to verify %s: failed to get CA certificate",
	        TEST_IFCFG_WIRED_8021x_PEAP_MSCHAPV2,
	        NM_SETTING_802_1X_SETTING_NAME,
	        NM_SETTING_802_1X_CA_CERT);

	read_ca_cert = nm_setting_802_1x_get_ca_cert (s_8021x);
	ASSERT (read_ca_cert != NULL,
	        "wired-8021x-peap-mschapv2-verify-8021x", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIRED_8021x_PEAP_MSCHAPV2,
	        NM_SETTING_802_1X_SETTING_NAME,
	        NM_SETTING_802_1X_CA_CERT);

	ASSERT (read_ca_cert->len == expected_ca_cert->len,
	        "wired-8021x-peap-mschapv2-verify-8021x", "failed to verify %s: unexpected %s / %s certificate length",
	        TEST_IFCFG_WIRED_8021x_PEAP_MSCHAPV2,
	        NM_SETTING_802_1X_SETTING_NAME,
	        NM_SETTING_802_1X_CA_CERT);

	ASSERT (memcmp (read_ca_cert->data, expected_ca_cert->data, read_ca_cert->len) == 0,
	        "wired-8021x-peap-mschapv2-verify-8021x", "failed to verify %s: %s / %s key certificate mismatch",
	        TEST_IFCFG_WIRED_8021x_PEAP_MSCHAPV2,
	        NM_SETTING_802_1X_SETTING_NAME,
	        NM_SETTING_802_1X_CA_CERT);

	g_object_unref (tmp_8021x);

	g_object_unref (connection);
}

#define TEST_IFCFG_WIFI_OPEN TEST_DIR"/network-scripts/ifcfg-test-wifi-open"

static void
test_read_wifi_open (void)
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
	const guint32 expected_channel = 1;

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

#define TEST_IFCFG_WIFI_OPEN_SSID_HEX TEST_DIR"/network-scripts/ifcfg-test-wifi-open-ssid-hex"

static void
test_read_wifi_open_ssid_hex (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	gboolean unmanaged = FALSE;
	char *keyfile = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	const char *tmp;
	const GByteArray *array;
	const char *expected_id = "System blahblah (test-wifi-open-ssid-hex)";
	const char *expected_ssid = "blahblah";

	connection = connection_from_file (TEST_IFCFG_WIFI_OPEN_SSID_HEX,
	                                   NULL,
	                                   TYPE_WIRELESS,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &error,
	                                   &ignore_error);
	ASSERT (connection != NULL,
	        "wifi-open-ssid-hex-read", "failed to read %s: %s", TEST_IFCFG_WIFI_OPEN_SSID_HEX, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "wifi-open-ssid-hex-verify", "failed to verify %s: %s", TEST_IFCFG_WIFI_OPEN_SSID_HEX, error->message);

	/* ===== CONNECTION SETTING ===== */

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
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

	s_wireless = NM_SETTING_WIRELESS (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRELESS));
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
	
	g_object_unref (connection);
}

static void
test_read_wifi_open_ssid_bad (const char *file, const char *test)
{
	NMConnection *connection;
	gboolean unmanaged = FALSE;
	char *keyfile = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;

	connection = connection_from_file (file, NULL, TYPE_WIRELESS, &unmanaged, &keyfile, &error, &ignore_error);
	ASSERT (connection == NULL, test, "unexpected success reading %s", file);
	g_clear_error (&error);
}

#define TEST_IFCFG_WIFI_OPEN_SSID_QUOTED TEST_DIR"/network-scripts/ifcfg-test-wifi-open-ssid-quoted"

static void
test_read_wifi_open_ssid_quoted (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	gboolean unmanaged = FALSE;
	char *keyfile = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	const char *tmp;
	const GByteArray *array;
	const char *expected_id = "System foo\"bar\\ (test-wifi-open-ssid-quoted)";
	const char *expected_ssid = "foo\"bar\\";

	connection = connection_from_file (TEST_IFCFG_WIFI_OPEN_SSID_QUOTED,
	                                   NULL,
	                                   TYPE_WIRELESS,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &error,
	                                   &ignore_error);
	ASSERT (connection != NULL,
	        "wifi-open-ssid-quoted-read", "failed to read %s: %s", TEST_IFCFG_WIFI_OPEN_SSID_QUOTED, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "wifi-open-ssid-quoted-verify", "failed to verify %s: %s", TEST_IFCFG_WIFI_OPEN_SSID_QUOTED, error->message);

	/* ===== CONNECTION SETTING ===== */

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
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

	s_wireless = NM_SETTING_WIRELESS (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRELESS));
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
	const guint32 expected_channel = 1;
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

	/* Channel */
	ASSERT (nm_setting_wireless_get_channel (s_wireless) == 11,
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

#define TEST_IFCFG_WIFI_LEAP TEST_DIR"/network-scripts/ifcfg-test-wifi-leap"

static void
test_read_wifi_leap (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	NMSettingWirelessSecurity *s_wsec;
	gboolean unmanaged = FALSE;
	char *keyfile = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	const char *tmp;
	const char *expected_id = "System blahblah (test-wifi-leap)";
	const char *expected_identity = "Bill Smith";
	const char *expected_password = "foobarblah";

	connection = connection_from_file (TEST_IFCFG_WIFI_LEAP,
	                                   NULL,
	                                   TYPE_WIRELESS,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &error,
	                                   &ignore_error);
	ASSERT (connection != NULL,
	        "wifi-leap-read", "failed to read %s: %s", TEST_IFCFG_WIFI_LEAP, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "wifi-leap-verify", "failed to verify %s: %s", TEST_IFCFG_WIFI_LEAP, error->message);

	/* ===== CONNECTION SETTING ===== */

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
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

	s_wireless = NM_SETTING_WIRELESS (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRELESS));
	ASSERT (s_wireless != NULL,
	        "wifi-leap-verify-wireless", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_LEAP,
	        NM_SETTING_WIRELESS_SETTING_NAME);

	/* Security */
	tmp = nm_setting_wireless_get_security (s_wireless);
	ASSERT (tmp != NULL,
	        "wifi-leap-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_LEAP,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_SEC);
	ASSERT (strcmp (tmp, NM_SETTING_WIRELESS_SECURITY_SETTING_NAME) == 0,
	        "wifi-leap-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_LEAP,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_SEC);


	/* ===== WIRELESS SECURITY SETTING ===== */

	s_wsec = NM_SETTING_WIRELESS_SECURITY (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRELESS_SECURITY));
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
	const guint32 expected_channel = 1;
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

#define TEST_IFCFG_WIFI_WPA_EAP_TLS TEST_DIR"/network-scripts/ifcfg-test-wifi-wpa-eap-tls"
#define TEST_IFCFG_WIFI_WPA_EAP_TLS_CA_CERT TEST_DIR"/network-scripts/test_ca_cert.pem"
#define TEST_IFCFG_WIFI_WPA_EAP_TLS_CLIENT_CERT TEST_DIR"/network-scripts/test1_key_and_cert.pem"
#define TEST_IFCFG_WIFI_WPA_EAP_TLS_PRIVATE_KEY TEST_DIR"/network-scripts/test1_key_and_cert.pem"

static void
test_read_wifi_wpa_eap_tls (void)
{
	NMConnection *connection;
	NMSettingWireless *s_wireless;
	NMSettingIP4Config *s_ip4;
	NMSetting8021x *s_8021x;
	gboolean unmanaged = FALSE;
	char *keyfile = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	const char *tmp, *privkey_password;
	const char *expected_private_key_password = "test1";

	connection = connection_from_file (TEST_IFCFG_WIFI_WPA_EAP_TLS,
	                                   NULL,
	                                   TYPE_ETHERNET,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &error,
	                                   &ignore_error);
	ASSERT (connection != NULL,
	        "wifi-wpa-eap-tls-read", "failed to read %s: %s", TEST_IFCFG_WIFI_WPA_EAP_TLS, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "wifi-wpa-eap-tls-verify", "failed to verify %s: %s", TEST_IFCFG_WIFI_WPA_EAP_TLS, error->message);

	ASSERT (unmanaged == FALSE,
	        "wifi-wpa-eap-tls-verify", "failed to verify %s: unexpected unmanaged value", TEST_IFCFG_WIFI_WPA_EAP_TLS);

	/* ===== WIRELESS SETTING ===== */

	s_wireless = NM_SETTING_WIRELESS (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRELESS));
	ASSERT (s_wireless != NULL,
	        "wifi-wpa-eap-tls-verify-wireless", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_WPA_EAP_TLS,
	        NM_SETTING_WIRELESS_SETTING_NAME);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = NM_SETTING_IP4_CONFIG (nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG));
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
	s_8021x = NM_SETTING_802_1X (nm_connection_get_setting (connection, NM_TYPE_SETTING_802_1X));
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

	/* CA Cert */
	verify_cert_or_key (CK_CA_CERT,
	                    s_8021x,
	                    TEST_IFCFG_WIFI_WPA_EAP_TLS_CA_CERT,
	                    NULL,
	                    TEST_IFCFG_WIFI_WPA_EAP_TLS,
	                    "wifi-wpa-eap-tls-verify-8021x",
	                    NM_SETTING_802_1X_CA_CERT);

	/* Client Cert */
	verify_cert_or_key (CK_CLIENT_CERT,
	                    s_8021x,
	                    TEST_IFCFG_WIFI_WPA_EAP_TLS_CLIENT_CERT,
	                    NULL,
	                    TEST_IFCFG_WIFI_WPA_EAP_TLS,
	                    "wifi-wpa-eap-tls-verify-8021x",
	                    NM_SETTING_802_1X_CLIENT_CERT);

	/* Private Key Password */
	privkey_password = nm_setting_802_1x_get_private_key_password (s_8021x);
	ASSERT (privkey_password != NULL,
	        "wifi-wpa-eap-tls-verify-8021x", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WPA_EAP_TLS,
	        NM_SETTING_802_1X_SETTING_NAME,
	        NM_SETTING_802_1X_PRIVATE_KEY_PASSWORD);
	ASSERT (strcmp (privkey_password, expected_private_key_password) == 0,
	        "wifi-wpa-eap-tls-verify-8021x", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WPA_EAP_TLS,
	        NM_SETTING_802_1X_SETTING_NAME,
	        NM_SETTING_802_1X_PRIVATE_KEY_PASSWORD);

	/* Private key */
	verify_cert_or_key (CK_PRIV_KEY,
	                    s_8021x,
	                    TEST_IFCFG_WIFI_WPA_EAP_TLS_PRIVATE_KEY,
	                    privkey_password,
	                    TEST_IFCFG_WIFI_WPA_EAP_TLS,
	                    "wifi-wpa-eap-tls-verify-8021x",
	                    NM_SETTING_802_1X_PRIVATE_KEY);

	g_object_unref (connection);
}

#define TEST_IFCFG_WIFI_WPA_EAP_TTLS_TLS TEST_DIR"/network-scripts/ifcfg-test-wifi-wpa-eap-ttls-tls"
#define TEST_IFCFG_WIFI_WPA_EAP_TTLS_TLS_CA_CERT TEST_DIR"/network-scripts/test_ca_cert.pem"
/* Also use TLS defines from the previous test */

static void
test_read_wifi_wpa_eap_ttls_tls (void)
{
	NMConnection *connection;
	NMSettingWireless *s_wireless;
	NMSettingIP4Config *s_ip4;
	NMSetting8021x *s_8021x;
	gboolean unmanaged = FALSE;
	char *keyfile = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	const char *tmp, *privkey_password;
	const char *expected_private_key_password = "test1";

	connection = connection_from_file (TEST_IFCFG_WIFI_WPA_EAP_TTLS_TLS,
	                                   NULL,
	                                   TYPE_WIRELESS,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &error,
	                                   &ignore_error);
	ASSERT (connection != NULL,
	        "wifi-wpa-eap-ttls-tls-read", "failed to read %s: %s", TEST_IFCFG_WIFI_WPA_EAP_TTLS_TLS, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "wifi-wpa-eap-ttls-tls-verify", "failed to verify %s: %s", TEST_IFCFG_WIFI_WPA_EAP_TTLS_TLS, error->message);

	ASSERT (unmanaged == FALSE,
	        "wifi-wpa-eap-ttls-tls-verify", "failed to verify %s: unexpected unmanaged value", TEST_IFCFG_WIFI_WPA_EAP_TTLS_TLS);

	/* ===== WIRELESS SETTING ===== */

	s_wireless = NM_SETTING_WIRELESS (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRELESS));
	ASSERT (s_wireless != NULL,
	        "wifi-wpa-eap-ttls-tls-verify-wireless", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_WPA_EAP_TTLS_TLS,
	        NM_SETTING_WIRELESS_SETTING_NAME);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = NM_SETTING_IP4_CONFIG (nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG));
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
	s_8021x = NM_SETTING_802_1X (nm_connection_get_setting (connection, NM_TYPE_SETTING_802_1X));
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
	verify_cert_or_key (CK_CA_CERT,
	                    s_8021x,
	                    TEST_IFCFG_WIFI_WPA_EAP_TTLS_TLS_CA_CERT,
	                    NULL,
	                    TEST_IFCFG_WIFI_WPA_EAP_TTLS_TLS,
	                    "wifi-wpa-eap-ttls-tls-verify-8021x",
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
	verify_cert_or_key (CK_CA_CERT,
	                    s_8021x,
	                    TEST_IFCFG_WIFI_WPA_EAP_TLS_CA_CERT,
	                    NULL,
	                    TEST_IFCFG_WIFI_WPA_EAP_TTLS_TLS,
	                    "wifi-wpa-eap-ttls-tls-verify-8021x",
	                    NM_SETTING_802_1X_PHASE2_CA_CERT);

	/* Inner Client Cert */
	verify_cert_or_key (CK_CLIENT_CERT,
	                    s_8021x,
	                    TEST_IFCFG_WIFI_WPA_EAP_TLS_CLIENT_CERT,
	                    NULL,
	                    TEST_IFCFG_WIFI_WPA_EAP_TTLS_TLS,
	                    "wifi-wpa-eap-ttls-tls-verify-8021x",
	                    NM_SETTING_802_1X_PHASE2_CLIENT_CERT);

	/* Inner Private Key Password */
	privkey_password = nm_setting_802_1x_get_phase2_private_key_password (s_8021x);
	ASSERT (privkey_password != NULL,
	        "wifi-wpa-eap-ttls-tls-verify-8021x", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WPA_EAP_TTLS_TLS,
	        NM_SETTING_802_1X_SETTING_NAME,
	        NM_SETTING_802_1X_PHASE2_PRIVATE_KEY_PASSWORD);
	ASSERT (strcmp (privkey_password, expected_private_key_password) == 0,
	        "wifi-wpa-eap-ttls-tls-verify-8021x", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WPA_EAP_TTLS_TLS,
	        NM_SETTING_802_1X_SETTING_NAME,
	        NM_SETTING_802_1X_PHASE2_PRIVATE_KEY_PASSWORD);

	/* Inner private key */
	verify_cert_or_key (CK_PRIV_KEY,
	                    s_8021x,
	                    TEST_IFCFG_WIFI_WPA_EAP_TLS_PRIVATE_KEY,
	                    privkey_password,
	                    TEST_IFCFG_WIFI_WPA_EAP_TTLS_TLS,
	                    "wifi-wpa-eap-ttls-tls-verify-8021x",
	                    NM_SETTING_802_1X_PHASE2_PRIVATE_KEY);

	g_object_unref (connection);
}

#define TEST_IFCFG_WIFI_WEP_EAP_TTLS_CHAP TEST_DIR"/network-scripts/ifcfg-test-wifi-wep-eap-ttls-chap"
#define TEST_IFCFG_WIFI_WEP_EAP_TTLS_CHAP_CA_CERT TEST_DIR"/network-scripts/test_ca_cert.pem"

static void
test_read_wifi_wep_eap_ttls_chap (void)
{
	NMConnection *connection;
	NMSettingWireless *s_wireless;
	NMSettingWirelessSecurity *s_wsec;
	NMSettingIP4Config *s_ip4;
	NMSetting8021x *s_8021x;
	gboolean unmanaged = FALSE;
	char *keyfile = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	const char *tmp;
	const char *expected_password = "foobar baz";
	const char *expected_identity = "David Smith";
	const char *expected_key_mgmt = "ieee8021x";

	connection = connection_from_file (TEST_IFCFG_WIFI_WEP_EAP_TTLS_CHAP,
	                                   NULL,
	                                   TYPE_WIRELESS,
	                                   &unmanaged,
	                                   &keyfile,
	                                   &error,
	                                   &ignore_error);
	ASSERT (connection != NULL,
	        "wifi-wep-eap-ttls-chap-read", "failed to read %s: %s", TEST_IFCFG_WIFI_WEP_EAP_TTLS_CHAP, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "wifi-wep-eap-ttls-chap-verify", "failed to verify %s: %s", TEST_IFCFG_WIFI_WEP_EAP_TTLS_CHAP, error->message);

	ASSERT (unmanaged == FALSE,
	        "wifi-wep-eap-ttls-chap-verify", "failed to verify %s: unexpected unmanaged value", TEST_IFCFG_WIFI_WEP_EAP_TTLS_CHAP);

	/* ===== WIRELESS SETTING ===== */

	s_wireless = NM_SETTING_WIRELESS (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRELESS));
	ASSERT (s_wireless != NULL,
	        "wifi-wep-eap-ttls-chap-verify-wireless", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_WEP_EAP_TTLS_CHAP,
	        NM_SETTING_WIRELESS_SETTING_NAME);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = NM_SETTING_IP4_CONFIG (nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG));
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
	s_wsec = NM_SETTING_WIRELESS_SECURITY (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRELESS_SECURITY));
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
	s_8021x = NM_SETTING_802_1X (nm_connection_get_setting (connection, NM_TYPE_SETTING_802_1X));
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
	verify_cert_or_key (CK_CA_CERT,
	                    s_8021x,
	                    TEST_IFCFG_WIFI_WEP_EAP_TTLS_CHAP_CA_CERT,
	                    NULL,
	                    TEST_IFCFG_WIFI_WEP_EAP_TTLS_CHAP,
	                    "wifi-wep-eap-ttls-chap-verify-8021x",
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
test_write_wired_static (void)
{
	NMConnection *connection;
	NMConnection *reread;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIP4Config *s_ip4;
	static unsigned char tmpmac[] = { 0x31, 0x33, 0x33, 0x37, 0xbe, 0xcd };
	GByteArray *mac;
	guint32 mtu = 1492;
	char *uuid;
	guint64 timestamp = 0x12344433L;
	const guint32 ip1 = htonl (0x01010103);
	const guint32 ip2 = htonl (0x01010105);
	const guint32 gw = htonl (0x01010101);
	const guint32 dns1 = htonl (0x04020201);
	const guint32 dns2 = htonl (0x04020202);
	const guint32 prefix = 24;
	const char *dns_search1 = "foobar.com";
	const char *dns_search2 = "lab.foobar.com";
	NMIP4Address *addr;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	gboolean unmanaged = FALSE;
	char *keyfile = NULL;
	gboolean ignore_error = FALSE;

	connection = nm_connection_new ();
	ASSERT (connection != NULL,
	        "wired-static-write", "failed to allocate new connection");

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	ASSERT (s_con != NULL,
	        "wired-static-write", "failed to allocate new %s setting",
	        NM_SETTING_CONNECTION_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Work Ethernet",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
	              NM_SETTING_CONNECTION_TIMESTAMP, timestamp,
	              NULL);
	g_free (uuid);

	/* Wired setting */
	s_wired = (NMSettingWired *) nm_setting_wired_new ();
	ASSERT (s_wired != NULL,
	        "wired-static-write", "failed to allocate new %s setting",
	        NM_SETTING_WIRED_SETTING_NAME);
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
	ASSERT (s_ip4 != NULL,
			"wired-static-write", "failed to allocate new %s setting",
			NM_SETTING_IP4_CONFIG_SETTING_NAME);
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

	nm_setting_ip4_config_add_dns (s_ip4, dns1);
	nm_setting_ip4_config_add_dns (s_ip4, dns2);

	nm_setting_ip4_config_add_dns_search (s_ip4, dns_search1);
	nm_setting_ip4_config_add_dns_search (s_ip4, dns_search2);

	ASSERT (nm_connection_verify (connection, &error) == TRUE,
	        "wired-static-write", "failed to verify connection: %s",
	        (error && error->message) ? error->message : "(unknown)");

	/* Save the ifcfg */
	success = writer_new_connection (connection,
	                                 TEST_DIR "/network-scripts/",
	                                 &testfile,
	                                 &error);
	ASSERT (success == TRUE,
	        "wired-static-write", "failed to write connection to disk: %s",
	        (error && error->message) ? error->message : "(unknown)");

	ASSERT (testfile != NULL,
	        "wired-static-write", "didn't get ifcfg file path back after writing connection");

	/* re-read the connection for comparison */
	reread = connection_from_file (testfile,
	                               NULL,
	                               TYPE_ETHERNET,
	                               &unmanaged,
	                               &keyfile,
	                               &error,
	                               &ignore_error);
	unlink (testfile);

	ASSERT (reread != NULL,
	        "wired-static-write-reread", "failed to read %s: %s", testfile, error->message);

	ASSERT (nm_connection_verify (reread, &error),
	        "wired-static-write-reread-verify", "failed to verify %s: %s", testfile, error->message);

	ASSERT (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "wired-static-write", "written and re-read connection weren't the same.");

	g_free (testfile);
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
	char *uuid;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	gboolean unmanaged = FALSE;
	char *keyfile = NULL;
	gboolean ignore_error = FALSE;

	connection = nm_connection_new ();
	ASSERT (connection != NULL,
	        "wired-dhcp-write", "failed to allocate new connection");

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	ASSERT (s_con != NULL,
	        "wired-dhcp-write", "failed to allocate new %s setting",
	        NM_SETTING_CONNECTION_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Auto Ethernet",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* Wired setting */
	s_wired = (NMSettingWired *) nm_setting_wired_new ();
	ASSERT (s_wired != NULL,
	        "wired-dhcp-write", "failed to allocate new %s setting",
	        NM_SETTING_WIRED_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_wired));

	/* IP4 setting */
	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	ASSERT (s_ip4 != NULL,
			"wired-dhcp-write", "failed to allocate new %s setting",
			NM_SETTING_IP4_CONFIG_SETTING_NAME);
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

	/* Save the ifcfg */
	success = writer_new_connection (connection,
	                                 TEST_DIR "/network-scripts/",
	                                 &testfile,
	                                 &error);
	ASSERT (success == TRUE,
	        "wired-dhcp-write", "failed to write connection to disk: %s",
	        (error && error->message) ? error->message : "(unknown)");

	ASSERT (testfile != NULL,
	        "wired-dhcp-write", "didn't get ifcfg file path back after writing connection");

	/* re-read the connection for comparison */
	reread = connection_from_file (testfile,
	                               NULL,
	                               TYPE_ETHERNET,
	                               &unmanaged,
	                               &keyfile,
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
	char *uuid;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	gboolean unmanaged = FALSE;
	char *keyfile = NULL;
	gboolean ignore_error = FALSE;
	GByteArray *ssid;
	const unsigned char ssid_data[] = { 0x54, 0x65, 0x73, 0x74, 0x20, 0x53, 0x53, 0x49, 0x44 };
	GByteArray *bssid;
	const unsigned char bssid_data[] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
	guint32 channel = 9, mtu = 1345;
	GByteArray *mac;
	const unsigned char mac_data[] = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };

	connection = nm_connection_new ();
	ASSERT (connection != NULL,
	        "wifi-open-write", "failed to allocate new connection");

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	ASSERT (s_con != NULL,
	        "wifi-open-write", "failed to allocate new %s setting",
	        NM_SETTING_CONNECTION_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "blahblah",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRELESS_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* Wifi setting */
	s_wifi = (NMSettingWireless *) nm_setting_wireless_new ();
	ASSERT (s_wifi != NULL,
	        "wifi-open-write", "failed to allocate new %s setting",
	        NM_SETTING_WIRELESS_SETTING_NAME);
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
	ASSERT (s_ip4 != NULL,
			"wifi-open-write", "failed to allocate new %s setting",
			NM_SETTING_IP4_CONFIG_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4, NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

	ASSERT (nm_connection_verify (connection, &error) == TRUE,
	        "wifi-open-write", "failed to verify connection: %s",
	        (error && error->message) ? error->message : "(unknown)");

	/* Save the ifcfg */
	success = writer_new_connection (connection,
	                                 TEST_DIR "/network-scripts/",
	                                 &testfile,
	                                 &error);
	ASSERT (success == TRUE,
	        "wifi-open-write", "failed to write connection to disk: %s",
	        (error && error->message) ? error->message : "(unknown)");

	ASSERT (testfile != NULL,
	        "wifi-open-write", "didn't get ifcfg file path back after writing connection");

	/* re-read the connection for comparison */
	reread = connection_from_file (testfile,
	                               NULL,
	                               TYPE_WIRELESS,
	                               &unmanaged,
	                               &keyfile,
	                               &error,
	                               &ignore_error);
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
	NMSettingIP4Config *s_ip4;
	char *uuid;
	gboolean success;
	GError *error = NULL;
	char *testfile = NULL;
	gboolean unmanaged = FALSE;
	char *keyfile = NULL;
	gboolean ignore_error = FALSE;
	GByteArray *ssid;
	const unsigned char ssid_data[] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd };

	connection = nm_connection_new ();
	ASSERT (connection != NULL,
	        "wifi-open-hex-ssid-write", "failed to allocate new connection");

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	ASSERT (s_con != NULL,
	        "wifi-open-hex-ssid-write", "failed to allocate new %s setting",
	        NM_SETTING_CONNECTION_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "blahblah",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRELESS_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* Wifi setting */
	s_wifi = (NMSettingWireless *) nm_setting_wireless_new ();
	ASSERT (s_wifi != NULL,
	        "wifi-open-hex-ssid-write", "failed to allocate new %s setting",
	        NM_SETTING_WIRELESS_SETTING_NAME);
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
	ASSERT (s_ip4 != NULL,
			"wifi-open-hex-ssid-write", "failed to allocate new %s setting",
			NM_SETTING_IP4_CONFIG_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4, NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

	ASSERT (nm_connection_verify (connection, &error) == TRUE,
	        "wifi-open-hex-ssid-write", "failed to verify connection: %s",
	        (error && error->message) ? error->message : "(unknown)");

	/* Save the ifcfg */
	success = writer_new_connection (connection,
	                                 TEST_DIR "/network-scripts/",
	                                 &testfile,
	                                 &error);
	ASSERT (success == TRUE,
	        "wifi-open-hex-ssid-write", "failed to write connection to disk: %s",
	        (error && error->message) ? error->message : "(unknown)");

	ASSERT (testfile != NULL,
	        "wifi-open-hex-ssid-write", "didn't get ifcfg file path back after writing connection");

	/* re-read the connection for comparison */
	reread = connection_from_file (testfile,
	                               NULL,
	                               TYPE_WIRELESS,
	                               &unmanaged,
	                               &keyfile,
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
	g_object_unref (connection);
	g_object_unref (reread);
}

#define TEST_IFCFG_WIFI_OPEN_SSID_BAD_HEX TEST_DIR"/network-scripts/ifcfg-test-wifi-open-ssid-bad-hex"
#define TEST_IFCFG_WIFI_OPEN_SSID_LONG_QUOTED TEST_DIR"/network-scripts/ifcfg-test-wifi-open-ssid-long-quoted"
#define TEST_IFCFG_WIFI_OPEN_SSID_LONG_HEX TEST_DIR"/network-scripts/ifcfg-test-wifi-open-ssid-long-hex"

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
	test_read_wired_8021x_peap_mschapv2 ();
	test_read_wifi_open ();
	test_read_wifi_open_ssid_hex ();
	test_read_wifi_open_ssid_bad (TEST_IFCFG_WIFI_OPEN_SSID_BAD_HEX, "wifi-open-ssid-bad-hex-read");
	test_read_wifi_open_ssid_bad (TEST_IFCFG_WIFI_OPEN_SSID_LONG_HEX, "wifi-open-ssid-long-hex-read");
	test_read_wifi_open_ssid_bad (TEST_IFCFG_WIFI_OPEN_SSID_LONG_QUOTED, "wifi-open-ssid-long-quoted-read");
	test_read_wifi_open_ssid_quoted ();
	test_read_wifi_wep ();
	test_read_wifi_wep_adhoc ();
	test_read_wifi_leap ();
	test_read_wifi_wpa_psk ();
	test_read_wifi_wpa_psk_adhoc ();
	test_read_wifi_wpa_psk_hex ();
	test_read_wifi_wpa_eap_tls ();
	test_read_wifi_wpa_eap_ttls_tls ();
	test_read_wifi_wep_eap_ttls_chap ();

	test_write_wired_static ();
	test_write_wired_dhcp ();
	test_write_wifi_open ();
	test_write_wifi_open_hex_ssid ();

	basename = g_path_get_basename (argv[0]);
	fprintf (stdout, "%s: SUCCESS\n", basename);
	g_free (basename);
	return 0;
}

