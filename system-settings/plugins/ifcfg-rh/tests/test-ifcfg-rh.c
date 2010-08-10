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
 * Copyright (C) 2008 - 2010 Red Hat, Inc.
 */

#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <dbus/dbus-glib.h>

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
	const char *expected = NULL, *setting = NULL;
	gboolean phase2 = FALSE;
	NMSetting8021xCKScheme scheme = NM_SETTING_802_1X_CK_SCHEME_UNKNOWN;

	if (strstr (setting_key, "phase2"))
		phase2 = TRUE;

	/* CA Cert */
	s_8021x = (NMSetting8021x *) nm_setting_802_1x_new ();
	ASSERT (s_8021x != NULL,
	        test_name, "failed to verify %s: could not create temp 802.1x setting",
	        ifcfg);

	if (ck_type == CK_CA_CERT) {
		if (phase2)
			success = nm_setting_802_1x_set_phase2_ca_cert (s_8021x, file, NM_SETTING_802_1X_CK_SCHEME_PATH, NULL, &error);
		else
			success = nm_setting_802_1x_set_ca_cert (s_8021x, file, NM_SETTING_802_1X_CK_SCHEME_PATH, NULL, &error);
	} else if (ck_type == CK_CLIENT_CERT) {
		if (phase2)
			success = nm_setting_802_1x_set_phase2_client_cert (s_8021x, file, NM_SETTING_802_1X_CK_SCHEME_PATH, NULL, &error);
		else
			success = nm_setting_802_1x_set_client_cert (s_8021x, file, NM_SETTING_802_1X_CK_SCHEME_PATH, NULL, &error);
	} else if (ck_type == CK_PRIV_KEY) {
		if (phase2)
			success = nm_setting_802_1x_set_phase2_private_key (s_8021x, file, privkey_password, NM_SETTING_802_1X_CK_SCHEME_PATH, NULL, &error);
		else
			success = nm_setting_802_1x_set_private_key (s_8021x, file, privkey_password, NM_SETTING_802_1X_CK_SCHEME_PATH, NULL, &error);
	}
	ASSERT (success == TRUE,
	        test_name, "failed to verify %s: could not load item for %s / %s: %s",
	        ifcfg, NM_SETTING_802_1X_SETTING_NAME, setting_key, error->message);

	if (ck_type == CK_CA_CERT) {
		if (phase2)
			scheme = nm_setting_802_1x_get_phase2_ca_cert_scheme (s_8021x);
		else
			scheme = nm_setting_802_1x_get_ca_cert_scheme (s_8021x);
	} else if (ck_type == CK_CLIENT_CERT) {
		if (phase2)
			scheme = nm_setting_802_1x_get_phase2_client_cert_scheme (s_8021x);
		else
			scheme = nm_setting_802_1x_get_client_cert_scheme (s_8021x);
	} else if (ck_type == CK_PRIV_KEY) {
		if (phase2)
			scheme = nm_setting_802_1x_get_phase2_private_key_scheme (s_8021x);
		else
			scheme = nm_setting_802_1x_get_private_key_scheme (s_8021x);
	}
	ASSERT (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH,
	        test_name, "failed to verify %s: unexpected cert/key scheme for %s / %s",
	        ifcfg, NM_SETTING_802_1X_SETTING_NAME, setting_key);

	if (ck_type == CK_CA_CERT) {
		if (phase2)
			expected = nm_setting_802_1x_get_phase2_ca_cert_path (s_8021x);
		else
			expected = nm_setting_802_1x_get_ca_cert_path (s_8021x);
	} else if (ck_type == CK_CLIENT_CERT) {
		if (phase2)
			expected = nm_setting_802_1x_get_phase2_client_cert_path (s_8021x);
		else
			expected = nm_setting_802_1x_get_client_cert_path (s_8021x);
	} else if (ck_type == CK_PRIV_KEY) {
		if (phase2)
			expected = nm_setting_802_1x_get_phase2_private_key_path (s_8021x);
		else
			expected = nm_setting_802_1x_get_private_key_path (s_8021x);
	}
	ASSERT (expected != NULL,
	        test_name, "failed to verify %s: failed to get read item for %s / %s",
	        ifcfg, NM_SETTING_802_1X_SETTING_NAME, setting_key);

	if (ck_type == CK_CA_CERT) {
		if (phase2)
			setting = nm_setting_802_1x_get_phase2_ca_cert_path (s_compare);
		else
			setting = nm_setting_802_1x_get_ca_cert_path (s_compare);
	} else if (ck_type == CK_CLIENT_CERT) {
		if (phase2)
			setting = nm_setting_802_1x_get_phase2_client_cert_path (s_compare);
		else
			setting = nm_setting_802_1x_get_client_cert_path (s_compare);
	} else if (ck_type == CK_PRIV_KEY) {
		if (phase2)
			setting = nm_setting_802_1x_get_phase2_private_key_path (s_compare);
		else
			setting = nm_setting_802_1x_get_private_key_path (s_compare);
	}
	ASSERT (setting != NULL,
	        test_name, "failed to verify %s: missing %s / %s key",
	        ifcfg, NM_SETTING_802_1X_SETTING_NAME, setting_key);

	ASSERT (strlen (setting) == strlen (expected),
	        test_name, "failed to verify %s: unexpected %s / %s certificate length",
	        test_name, NM_SETTING_802_1X_SETTING_NAME, setting_key);

	ASSERT (strcmp (setting, expected) == 0,
	        test_name, "failed to verify %s: %s / %s key certificate mismatch",
	        ifcfg, NM_SETTING_802_1X_SETTING_NAME, setting_key);

	g_object_unref (s_8021x);
	return TRUE;
}


#define TEST_IFCFG_MINIMAL TEST_IFCFG_DIR"/network-scripts/ifcfg-test-minimal"

static void
test_read_minimal (void)
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
	char expected_mac_address[ETH_ALEN] = { 0x00, 0x16, 0x41, 0x11, 0x22, 0x33 };
	const char *expected_id = "System test-minimal";
	guint64 expected_timestamp = 0;

	connection = connection_from_file (TEST_IFCFG_MINIMAL,
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

	ASSERT (nm_setting_ip4_config_get_never_default (s_ip4) == FALSE,
	        "minimal-wired-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_MINIMAL,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_NEVER_DEFAULT);

	g_object_unref (connection);
}

#define TEST_IFCFG_UNMANAGED TEST_IFCFG_DIR"/network-scripts/ifcfg-test-nm-controlled"

static void
test_read_unmanaged (void)
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
	char expected_mac_address[ETH_ALEN] = { 0x00, 0x11, 0x22, 0x33, 0xf8, 0x9f };
	const char *expected_id = "System test-nm-controlled";
	guint64 expected_timestamp = 0;

	connection = connection_from_file (TEST_IFCFG_UNMANAGED,
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
	        "unmanaged-read", "failed to read %s: %s", TEST_IFCFG_UNMANAGED, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "unmanaged-verify", "failed to verify %s: %s", TEST_IFCFG_UNMANAGED, error->message);

	ASSERT (unmanaged != NULL,
	        "unmanaged-verify", "failed to verify %s: expected unmanaged", TEST_IFCFG_UNMANAGED);

	ASSERT (strcmp (unmanaged, "mac:00:11:22:33:f8:9f") == 0,
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

static void
test_read_wired_static (const char *file, const char *expected_id)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;
	char *unmanaged = FALSE;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	const GByteArray *array;
	char expected_mac_address[ETH_ALEN] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0xee };
	const char *tmp;
	const char *expected_dns1 = "4.2.2.1";
	const char *expected_dns2 = "4.2.2.2";
	struct in_addr addr;
	struct in6_addr addr6;
	const char *expected_address1 = "192.168.1.5";
	const char *expected_address1_gw = "192.168.1.1";
	const char *expected6_address1 = "dead:beaf::1";
	const char *expected6_address2 = "dead:beaf::2";
	const char *expected6_dns1 = "1:2:3:4::a";
	const char *expected6_dns2 = "1:2:3:4::b";
	NMIP4Address *ip4_addr;
	NMIP6Address *ip6_addr;

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
	        "wired-static-read", "failed to read %s: %s", file, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "wired-static-verify", "failed to verify %s: %s", file, error->message);

	ASSERT (unmanaged == FALSE,
	        "wired-static-verify", "failed to verify %s: unexpected unmanaged value", file);

	/* ===== CONNECTION SETTING ===== */

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	ASSERT (s_con != NULL,
	        "wired-static-verify-connection", "failed to verify %s: missing %s setting",
	        file,
	        NM_SETTING_CONNECTION_SETTING_NAME);

	/* ID */
	tmp = nm_setting_connection_get_id (s_con);
	ASSERT (tmp != NULL,
	        "wired-static-verify-connection", "failed to verify %s: missing %s / %s key",
	        file,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);
	ASSERT (strcmp (tmp, expected_id) == 0,
	        "wired-static-verify-connection", "failed to verify %s: unexpected %s / %s key value",
	        file,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);

	/* Timestamp */
	ASSERT (nm_setting_connection_get_timestamp (s_con) == 0,
	        "wired-static-verify-connection", "failed to verify %s: unexpected %s /%s key value",
	        file,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_TIMESTAMP);

	/* Autoconnect */
	ASSERT (nm_setting_connection_get_autoconnect (s_con) == TRUE,
	        "wired-static-verify-connection", "failed to verify %s: unexpected %s /%s key value",
	        file,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_AUTOCONNECT);

	/* ===== WIRED SETTING ===== */

	s_wired = NM_SETTING_WIRED (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRED));
	ASSERT (s_wired != NULL,
	        "wired-static-verify-wired", "failed to verify %s: missing %s setting",
	        file,
	        NM_SETTING_WIRED_SETTING_NAME);

	/* MAC address */
	array = nm_setting_wired_get_mac_address (s_wired);
	ASSERT (array != NULL,
	        "wired-static-verify-wired", "failed to verify %s: missing %s / %s key",
	        file,
	        NM_SETTING_WIRED_SETTING_NAME,
	        NM_SETTING_WIRED_MAC_ADDRESS);
	ASSERT (array->len == ETH_ALEN,
	        "wired-static-verify-wired", "failed to verify %s: unexpected %s / %s key value length",
	        file,
	        NM_SETTING_WIRED_SETTING_NAME,
	        NM_SETTING_WIRED_MAC_ADDRESS);
	ASSERT (memcmp (array->data, &expected_mac_address[0], sizeof (expected_mac_address)) == 0,
	        "wired-static-verify-wired", "failed to verify %s: unexpected %s / %s key value",
	        file,
	        NM_SETTING_WIRED_SETTING_NAME,
	        NM_SETTING_WIRED_MAC_ADDRESS);

	ASSERT (nm_setting_wired_get_mtu (s_wired) == 1492,
	        "wired-static-verify-wired", "failed to verify %s: unexpected %s / %s key value",
	        file,
	        NM_SETTING_WIRED_SETTING_NAME,
	        NM_SETTING_WIRED_MTU);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = NM_SETTING_IP4_CONFIG (nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG));
	ASSERT (s_ip4 != NULL,
	        "wired-static-verify-ip4", "failed to verify %s: missing %s setting",
	        file,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME);

	/* Method */
	tmp = nm_setting_ip4_config_get_method (s_ip4);
	ASSERT (strcmp (tmp, NM_SETTING_IP4_CONFIG_METHOD_MANUAL) == 0,
	        "wired-static-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        file,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_METHOD);

	/* Implicit may-fail */
	ASSERT (nm_setting_ip4_config_get_may_fail (s_ip4) == FALSE,
	        "wired-static-verify-ip6", "failed to verify %s: unexpected %s / %s key value",
	        file,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_MAY_FAIL);

	/* DNS Addresses */
	ASSERT (nm_setting_ip4_config_get_num_dns (s_ip4) == 2,
	        "wired-static-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        file,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS);

	ASSERT (inet_pton (AF_INET, expected_dns1, &addr) > 0,
	        "wired-static-verify-ip4", "failed to verify %s: couldn't convert DNS IP address #1",
	        file,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS);
	ASSERT (nm_setting_ip4_config_get_dns (s_ip4, 0) == addr.s_addr,
	        "wired-static-verify-ip4", "failed to verify %s: unexpected %s / %s key value #1",
	        file,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS);

	ASSERT (inet_pton (AF_INET, expected_dns2, &addr) > 0,
	        "wired-static-verify-ip4", "failed to verify %s: couldn't convert DNS IP address #2",
	        file,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS);
	ASSERT (nm_setting_ip4_config_get_dns (s_ip4, 1) == addr.s_addr,
	        "wired-static-verify-ip4", "failed to verify %s: unexpected %s / %s key value #2",
	        file,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS);

	ASSERT (nm_setting_ip4_config_get_num_addresses (s_ip4) == 1,
	        "wired-static-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        file,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS);

	/* Address #1 */
	ip4_addr = nm_setting_ip4_config_get_address (s_ip4, 0);
	ASSERT (ip4_addr,
	        "wired-static-verify-ip4", "failed to verify %s: missing IP4 address #1",
	        file,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_ADDRESSES);

	ASSERT (nm_ip4_address_get_prefix (ip4_addr) == 24,
	        "wired-static-verify-ip4", "failed to verify %s: unexpected IP4 address #1 prefix",
	        file,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_ADDRESSES);

	ASSERT (inet_pton (AF_INET, expected_address1, &addr) > 0,
	        "wired-static-verify-ip4", "failed to verify %s: couldn't convert IP address #1",
	        file,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS);
	ASSERT (nm_ip4_address_get_address (ip4_addr) == addr.s_addr,
	        "wired-static-verify-ip4", "failed to verify %s: unexpected IP4 address #1",
	        file,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_ADDRESSES);

	ASSERT (inet_pton (AF_INET, expected_address1_gw, &addr) > 0,
	        "wired-static-verify-ip4", "failed to verify %s: couldn't convert IP address #1 gateway",
	        file,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_ADDRESSES);
	ASSERT (nm_ip4_address_get_gateway (ip4_addr) == addr.s_addr,
	        "wired-static-verify-ip4", "failed to verify %s: unexpected IP4 address #1 gateway",
	        file,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_ADDRESSES);

	if (!strcmp (expected_id, "System test-wired-static")) {
		/* ===== IPv6 SETTING ===== */

		s_ip6 = NM_SETTING_IP6_CONFIG (nm_connection_get_setting (connection, NM_TYPE_SETTING_IP6_CONFIG));
		ASSERT (s_ip6 != NULL,
			"wired-static-verify-ip6", "failed to verify %s: missing %s setting",
			file,
			NM_SETTING_IP6_CONFIG_SETTING_NAME);

		/* Method */
		tmp = nm_setting_ip6_config_get_method (s_ip6);
		ASSERT (strcmp (tmp, NM_SETTING_IP6_CONFIG_METHOD_MANUAL) == 0,
			"wired-static-verify-ip6", "failed to verify %s: unexpected %s / %s key value",
			file,
			NM_SETTING_IP6_CONFIG_SETTING_NAME,
			NM_SETTING_IP6_CONFIG_METHOD);

		/* Implicit may-fail */
		ASSERT (nm_setting_ip6_config_get_may_fail (s_ip6) == TRUE,
		        "wired-static-verify-ip6", "failed to verify %s: unexpected %s / %s key value",
		        file,
		        NM_SETTING_IP6_CONFIG_SETTING_NAME,
		        NM_SETTING_IP6_CONFIG_MAY_FAIL);

		/* DNS Addresses */
		ASSERT (nm_setting_ip6_config_get_num_dns (s_ip6) == 2,
			"wired-static-verify-ip6", "failed to verify %s: unexpected %s / %s key value",
			file,
			NM_SETTING_IP6_CONFIG_SETTING_NAME,
			NM_SETTING_IP6_CONFIG_DNS);

		ASSERT (inet_pton (AF_INET6, expected6_dns1, &addr6) > 0,
			"wired-static-verify-ip6", "failed to verify %s: couldn't convert DNS IP address #1",
			file);
		ASSERT (IN6_ARE_ADDR_EQUAL (nm_setting_ip6_config_get_dns (s_ip6, 0), &addr6),
			"wired-static-verify-ip6", "failed to verify %s: unexpected %s / %s key value #1",
			file,
			NM_SETTING_IP6_CONFIG_SETTING_NAME,
			NM_SETTING_IP6_CONFIG_DNS);

		ASSERT (inet_pton (AF_INET6, expected6_dns2, &addr6) > 0,
			"wired-static-verify-ip6", "failed to verify %s: couldn't convert DNS IP address #2",
			file);
		ASSERT (IN6_ARE_ADDR_EQUAL (nm_setting_ip6_config_get_dns (s_ip6, 1), &addr6),
			"wired-static-verify-ip6", "failed to verify %s: unexpected %s / %s key value #2",
			file,
			NM_SETTING_IP6_CONFIG_SETTING_NAME,
			NM_SETTING_IP6_CONFIG_DNS);

		ASSERT (nm_setting_ip6_config_get_num_addresses (s_ip6) == 2,
			"wired-static-verify-ip6", "failed to verify %s: unexpected %s / %s key value",
			file,
			NM_SETTING_IP6_CONFIG_SETTING_NAME,
			NM_SETTING_IP6_CONFIG_ADDRESSES);

		/* Address #1 */
		ip6_addr = nm_setting_ip6_config_get_address (s_ip6, 0);
		ASSERT (ip6_addr,
			"wired-static-verify-ip6", "failed to verify %s: missing IP6 address #1",
			file);

		ASSERT (nm_ip6_address_get_prefix (ip6_addr) == 64,
			"wired-static-verify-ip6", "failed to verify %s: unexpected IP6 address #1 prefix",
			file);

		ASSERT (inet_pton (AF_INET6, expected6_address1, &addr6) > 0,
			"wired-static-verify-ip6", "failed to verify %s: couldn't convert IP address #1",
			file);
		ASSERT (IN6_ARE_ADDR_EQUAL (nm_ip6_address_get_address (ip6_addr), &addr6),
			"wired-static-verify-ip6", "failed to verify %s: unexpected IP6 address #1",
			file);

		/* Address #2 */
		ip6_addr = nm_setting_ip6_config_get_address (s_ip6, 1);
		ASSERT (ip6_addr,
			"wired-static-verify-ip6", "failed to verify %s: missing IP6 address #2",
			file);

		ASSERT (nm_ip6_address_get_prefix (ip6_addr) == 56,
			"wired-static-verify-ip6", "failed to verify %s: unexpected IP6 address #2 prefix",
			file);

		ASSERT (inet_pton (AF_INET6, expected6_address2, &addr6) > 0,
			"wired-static-verify-ip6", "failed to verify %s: couldn't convert IP address #2",
			file);
		ASSERT (IN6_ARE_ADDR_EQUAL (nm_ip6_address_get_address (ip6_addr), &addr6),
			"wired-static-verify-ip6", "failed to verify %s: unexpected IP6 address #2",
			file);
	}

	g_object_unref (connection);
}

#define TEST_IFCFG_STATIC_NO_PREFIX TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-static-no-prefix"

static void
test_read_wired_static_no_prefix (guint32 expected_prefix)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingIP4Config *s_ip4;
	char *unmanaged = FALSE;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;
	NMIP4Address *ip4_addr;
	char *file, *expected_id;
	const char *tmp;

	file = g_strdup_printf (TEST_IFCFG_STATIC_NO_PREFIX "-%u", expected_prefix);
	ASSERT (file != NULL,
	        "wired-static-no-prefix-read", "failed to create path to file");

	expected_id = g_strdup_printf ("System test-wired-static-no-prefix-%u", expected_prefix);
	ASSERT (expected_id != NULL,
	        "wired-static-no-prefix-read", "failed to expected connection ID");

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
	        "wired-static-no-prefix-read", "failed to read %s: %s", file, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "wired-static-no-prefix-verify", "failed to verify %s: %s", file, error->message);

	ASSERT (unmanaged == FALSE,
	        "wired-static-no-prefix-verify", "failed to verify %s: unexpected unmanaged value", file);

	/* ===== CONNECTION SETTING ===== */

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	ASSERT (s_con != NULL,
	        "wired-static-no-prefix-verify-connection", "failed to verify %s: missing %s setting",
	        file,
	        NM_SETTING_CONNECTION_SETTING_NAME);

	/* ID */
	tmp = nm_setting_connection_get_id (s_con);
	ASSERT (tmp != NULL,
	        "wired-static-no-prefix-verify-connection", "failed to verify %s: missing %s / %s key",
	        file,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);
	ASSERT (strcmp (tmp, expected_id) == 0,
	        "wired-static-no-prefix-verify-connection", "failed to verify %s: unexpected %s / %s key value",
	        file,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);
	g_free (expected_id);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = NM_SETTING_IP4_CONFIG (nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG));
	ASSERT (s_ip4 != NULL,
	        "wired-static-no-prefix-verify-ip4", "failed to verify %s: missing %s setting",
	        file,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME);

	/* Method */
	tmp = nm_setting_ip4_config_get_method (s_ip4);
	ASSERT (strcmp (tmp, NM_SETTING_IP4_CONFIG_METHOD_MANUAL) == 0,
	        "wired-static-no-prefix-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        file,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_METHOD);

	ASSERT (nm_setting_ip4_config_get_num_addresses (s_ip4) == 1,
	        "wired-static-no-prefix-verify-ip4", "failed to verify %s: unexpected %s / %s key value",
	        file,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS);

	/* Address #1 */
	ip4_addr = nm_setting_ip4_config_get_address (s_ip4, 0);
	ASSERT (ip4_addr,
	        "wired-static-no-prefix-verify-ip4", "failed to verify %s: missing IP4 address #1",
	        file,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_ADDRESSES);

	ASSERT (nm_ip4_address_get_prefix (ip4_addr) == expected_prefix,
	        "wired-static-no-prefix-verify-ip4", "failed to verify %s: unexpected IP4 address #1 prefix",
	        file,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_ADDRESSES);

	g_free (file);
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
	struct in_addr addr;
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
	struct in_addr addr;
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
	        "wired-global-gateway-verify-ip4", "failed to verify %s: unexpected IP4 address #1 prefix",
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

	/* ===== IPv6 SETTING ===== */

	s_ip6 = NM_SETTING_IP6_CONFIG (nm_connection_get_setting (connection, NM_TYPE_SETTING_IP6_CONFIG));
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

	ASSERT (unmanaged == FALSE,
	        "wired-defroute-no-verify", "failed to verify %s: unexpected unmanaged value", TEST_IFCFG_WIRED_DEFROUTE_NO);

	/* ===== CONNECTION SETTING ===== */

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
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

	s_wired = NM_SETTING_WIRED (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRED));
	ASSERT (s_wired != NULL,
	        "wired-defroute-no-verify-wired", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIRED_DEFROUTE_NO,
	        NM_SETTING_WIRED_SETTING_NAME);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = NM_SETTING_IP4_CONFIG (nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG));
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

	s_ip6 = NM_SETTING_IP6_CONFIG (nm_connection_get_setting (connection, NM_TYPE_SETTING_IP6_CONFIG));
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

	ASSERT (unmanaged == FALSE,
	        "wired-defroute-no-gatewaydev-yes-verify",
	        "failed to verify %s: unexpected unmanaged value",
	        TEST_IFCFG_WIRED_DEFROUTE_NO_GATEWAYDEV_YES);

	/* ===== CONNECTION SETTING ===== */

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
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

	s_wired = NM_SETTING_WIRED (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRED));
	ASSERT (s_wired != NULL,
	        "wired-defroute-no-gatewaydev-yes-verify-wired", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIRED_DEFROUTE_NO_GATEWAYDEV_YES,
	        NM_SETTING_WIRED_SETTING_NAME);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = NM_SETTING_IP4_CONFIG (nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG));
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

	s_ip6 = NM_SETTING_IP6_CONFIG (nm_connection_get_setting (connection, NM_TYPE_SETTING_IP6_CONFIG));
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
	struct in_addr addr;
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

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
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

	s_wired = NM_SETTING_WIRED (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRED));
	ASSERT (s_wired != NULL,
	        "wired-static-routes-verify-wired", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIRED_STATIC_ROUTES,
	        NM_SETTING_WIRED_SETTING_NAME);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = NM_SETTING_IP4_CONFIG (nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG));
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
	ASSERT (nm_ip4_route_get_dest (ip4_route) == addr.s_addr,
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
	ASSERT (nm_ip4_route_get_next_hop (ip4_route) == addr.s_addr,
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
	ASSERT (nm_ip4_route_get_dest (ip4_route) == addr.s_addr,
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
	ASSERT (nm_ip4_route_get_next_hop (ip4_route) == addr.s_addr,
	        "wired-static-routes-verify-ip4", "failed to verify %s: unexpected %s / %s key value #2",
	        TEST_IFCFG_WIRED_STATIC_ROUTES,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_ROUTES);
	ASSERT (nm_ip4_route_get_metric (ip4_route) == 3,
	        "wired-static-routes-verify-ip4", "failed to verify %s: unexpected route metric #2",
	        TEST_IFCFG_WIRED_STATIC_ROUTES);

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
	struct in_addr addr;
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

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
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

	s_wired = NM_SETTING_WIRED (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRED));
	ASSERT (s_wired != NULL,
	        "wired-static-routes-legacy-verify-wired", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIRED_STATIC_ROUTES_LEGACY,
	        NM_SETTING_WIRED_SETTING_NAME);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = NM_SETTING_IP4_CONFIG (nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG));
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
	ASSERT (nm_ip4_route_get_dest (ip4_route) == addr.s_addr,
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
	ASSERT (nm_ip4_route_get_next_hop (ip4_route) == addr.s_addr,
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
	ASSERT (nm_ip4_route_get_dest (ip4_route) == addr.s_addr,
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
	ASSERT (nm_ip4_route_get_next_hop (ip4_route) == addr.s_addr,
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
	ASSERT (nm_ip4_route_get_dest (ip4_route) == addr.s_addr,
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
	ASSERT (nm_ip4_route_get_next_hop (ip4_route) == addr.s_addr,
	        "wired-static-routes-legacy-verify-ip4", "failed to verify %s: unexpected %s / %s key value #3",
	        TEST_IFCFG_WIRED_STATIC_ROUTES_LEGACY,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_ROUTES);

	ASSERT (nm_ip4_route_get_metric (ip4_route) == 3,
	        "wired-static-routes-legacy-verify-ip4", "failed to verify %s: unexpected destination route #3 metric",
	        TEST_IFCFG_WIRED_STATIC_ROUTES_LEGACY);

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
	const char *expected_route1_dest = "9876::1234";
	guint32 expected_route1_prefix = 96;
	const char *expected_route1_nexthop = "9876::7777";
	guint32 expected_route1_metric = 2;
	const char *expected_dns1 = "1:2:3:4::a";
	const char *expected_dns2 = "1:2:3:4::b";
	NMIP6Address *ip6_addr;
	NMIP6Route *ip6_route;
	struct in6_addr addr;

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
	ASSERT (connection != NULL,
	        "wired-ipv6-manual-read", "failed to read %s: %s", TEST_IFCFG_WIRED_IPV6_MANUAL, error->message);

	ASSERT (nm_connection_verify (connection, &error),
	        "wired-ipv6-manual-verify", "failed to verify %s: %s", TEST_IFCFG_WIRED_IPV6_MANUAL, error->message);

	ASSERT (unmanaged == FALSE,
	        "wired-ipv6-manual-verify", "failed to verify %s: unexpected unmanaged value", TEST_IFCFG_WIRED_IPV6_MANUAL);

	/* ===== CONNECTION SETTING ===== */

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
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

	s_wired = NM_SETTING_WIRED (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRED));
	ASSERT (s_wired != NULL,
	        "wired-ipv6-manual-verify-wired", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIRED_IPV6_MANUAL,
	        NM_SETTING_WIRED_SETTING_NAME);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = NM_SETTING_IP4_CONFIG (nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG));
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

	s_ip6 = NM_SETTING_IP6_CONFIG (nm_connection_get_setting (connection, NM_TYPE_SETTING_IP6_CONFIG));
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
	ASSERT (nm_setting_ip6_config_get_num_routes (s_ip6) == 1,
		"wired-ipv6-manual-verify-ip6", "failed to verify %s: unexpected %s / %s key value",
		TEST_IFCFG_WIRED_IPV6_MANUAL,
		NM_SETTING_IP6_CONFIG_SETTING_NAME,
		NM_SETTING_IP6_CONFIG_ROUTES);

	/* Route #1 */
	ip6_route = nm_setting_ip6_config_get_route (s_ip6, 0);
	ASSERT (ip6_route,
		"wired-ipv6-manual-verify-ip6", "failed to verify %s: missing IP6 route #1",
		TEST_IFCFG_WIRED_IPV6_MANUAL);

	ASSERT (inet_pton (AF_INET6, expected_route1_dest, &addr) > 0,
		"wired-ipv6-manual-verify-ip6", "failed to verify %s: couldn't convert IP route dest #1",
		TEST_IFCFG_WIRED_IPV6_MANUAL);
	ASSERT (IN6_ARE_ADDR_EQUAL (nm_ip6_route_get_dest (ip6_route), &addr),
		"wired-ipv6-manual-verify-ip6", "failed to verify %s: unexpected IP6 route dest #1",
		TEST_IFCFG_WIRED_IPV6_MANUAL);

	ASSERT (nm_ip6_route_get_prefix (ip6_route) == expected_route1_prefix,
		"wired-ipv6-manual-verify-ip6", "failed to verify %s: unexpected IP6 route #1 prefix",
		TEST_IFCFG_WIRED_IPV6_MANUAL);

	ASSERT (inet_pton (AF_INET6, expected_route1_nexthop, &addr) > 0,
		"wired-ipv6-manual-verify-ip6", "failed to verify %s: couldn't convert IP route next_hop #1",
		TEST_IFCFG_WIRED_IPV6_MANUAL);
	ASSERT (IN6_ARE_ADDR_EQUAL (nm_ip6_route_get_next_hop (ip6_route), &addr),
		"wired-ipv6-manual-verify-ip6", "failed to verify %s: unexpected IP6 route next hop #1",
		TEST_IFCFG_WIRED_IPV6_MANUAL);

	ASSERT (nm_ip6_route_get_metric (ip6_route) == expected_route1_metric,
		"wired-ipv6-manual-verify-ip6", "failed to verify %s: unexpected IP6 route #1 metric",
		TEST_IFCFG_WIRED_IPV6_MANUAL);

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
	        NM_SETTING_IP6_CONFIG_DNS);

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

	ASSERT (unmanaged == FALSE,
	        "wired-ipv6-only-verify", "failed to verify %s: unexpected unmanaged value", TEST_IFCFG_WIRED_IPV6_MANUAL);

	/* ===== CONNECTION SETTING ===== */

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
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

	s_wired = NM_SETTING_WIRED (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRED));
	ASSERT (s_wired != NULL,
	        "wired-ipv6-only-verify-wired", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIRED_IPV6_MANUAL,
	        NM_SETTING_WIRED_SETTING_NAME);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = NM_SETTING_IP4_CONFIG (nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG));
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

	s_ip6 = NM_SETTING_IP6_CONFIG (nm_connection_get_setting (connection, NM_TYPE_SETTING_IP6_CONFIG));
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

	/* DNS domains - none as domains are stuffed to 'ipv4' setting */
	ASSERT (nm_setting_ip6_config_get_num_dns_searches (s_ip6) == 0,
	        "wired-ipv6-only-verify-ip6", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIRED_IPV6_MANUAL,
	        NM_SETTING_IP6_CONFIG_SETTING_NAME,
	        NM_SETTING_IP6_CONFIG_DNS);

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

	ASSERT (unmanaged == FALSE,
	        "wired-dhcp6-only-verify", "failed to verify %s: unexpected unmanaged value", TEST_IFCFG_WIRED_DHCP6_ONLY);

	/* ===== CONNECTION SETTING ===== */

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
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

	s_wired = NM_SETTING_WIRED (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRED));
	ASSERT (s_wired != NULL,
	        "wired-dhcp6-only-verify-wired", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIRED_DHCP6_ONLY,
	        NM_SETTING_WIRED_SETTING_NAME);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = NM_SETTING_IP4_CONFIG (nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG));
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

	s_ip6 = NM_SETTING_IP6_CONFIG (nm_connection_get_setting (connection, NM_TYPE_SETTING_IP6_CONFIG));
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
	        "onboot-no-verify-connection", "failed to verify %s: unexpected %s /%s key value",
	        TEST_IFCFG_ONBOOT_NO,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_AUTOCONNECT);

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
	        NM_SETTING_802_1X_SETTING_NAME);

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

#define TEST_IFCFG_WIFI_OPEN TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wifi-open"

static void
test_read_wifi_open (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
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

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
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

	s_wireless = NM_SETTING_WIRELESS (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRELESS));
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
	struct in_addr addr;
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

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	ASSERT (s_con != NULL,
	        "wifi-wep-passphrase-verify-connection", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_WEP_PASSPHRASE,
	        NM_SETTING_CONNECTION_SETTING_NAME);

	/* ===== WIRELESS SETTING ===== */

	s_wireless = NM_SETTING_WIRELESS (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRELESS));
	ASSERT (s_wireless != NULL,
	        "wifi-wep-passphrase-verify-wireless", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_WEP_PASSPHRASE,
	        NM_SETTING_WIRELESS_SETTING_NAME);

	/* Security */
	tmp = nm_setting_wireless_get_security (s_wireless);
	ASSERT (tmp != NULL,
	        "wifi-wep-passphrase-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WEP_PASSPHRASE,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_SEC);
	ASSERT (strcmp (tmp, NM_SETTING_WIRELESS_SECURITY_SETTING_NAME) == 0,
	        "wifi-wep-passphrase-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WEP_PASSPHRASE,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_SEC);


	/* ===== WIRELESS SECURITY SETTING ===== */

	s_wsec = NM_SETTING_WIRELESS_SECURITY (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRELESS_SECURITY));
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

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	ASSERT (s_con != NULL,
	        "wifi-wep-40-ascii-verify-connection", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_WEP_40_ASCII,
	        NM_SETTING_CONNECTION_SETTING_NAME);

	/* ===== WIRELESS SETTING ===== */

	s_wireless = NM_SETTING_WIRELESS (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRELESS));
	ASSERT (s_wireless != NULL,
	        "wifi-wep-40-ascii-verify-wireless", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_WEP_40_ASCII,
	        NM_SETTING_WIRELESS_SETTING_NAME);

	/* Security */
	tmp = nm_setting_wireless_get_security (s_wireless);
	ASSERT (tmp != NULL,
	        "wifi-wep-40-ascii-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WEP_40_ASCII,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_SEC);
	ASSERT (strcmp (tmp, NM_SETTING_WIRELESS_SECURITY_SETTING_NAME) == 0,
	        "wifi-wep-40-ascii-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WEP_40_ASCII,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_SEC);

	/* ===== WIRELESS SECURITY SETTING ===== */

	s_wsec = NM_SETTING_WIRELESS_SECURITY (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRELESS_SECURITY));
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

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	ASSERT (s_con != NULL,
	        "wifi-wep-104-ascii-verify-connection", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_WEP_104_ASCII,
	        NM_SETTING_CONNECTION_SETTING_NAME);

	/* ===== WIRELESS SETTING ===== */

	s_wireless = NM_SETTING_WIRELESS (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRELESS));
	ASSERT (s_wireless != NULL,
	        "wifi-wep-104-ascii-verify-wireless", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_WEP_104_ASCII,
	        NM_SETTING_WIRELESS_SETTING_NAME);

	/* Security */
	tmp = nm_setting_wireless_get_security (s_wireless);
	ASSERT (tmp != NULL,
	        "wifi-wep-104-ascii-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WEP_104_ASCII,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_SEC);
	ASSERT (strcmp (tmp, NM_SETTING_WIRELESS_SECURITY_SETTING_NAME) == 0,
	        "wifi-wep-104-ascii-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WEP_104_ASCII,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_SEC);

	/* ===== WIRELESS SECURITY SETTING ===== */

	s_wsec = NM_SETTING_WIRELESS_SECURITY (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRELESS_SECURITY));
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

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
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

	s_wireless = NM_SETTING_WIRELESS (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRELESS));
	ASSERT (s_wireless != NULL,
	        "wifi-wpa-psk-unquoted-verify-wireless", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_WIFI_WPA_PSK_UNQUOTED,
	        NM_SETTING_WIRELESS_SETTING_NAME);

	/* Security */
	tmp = nm_setting_wireless_get_security (s_wireless);
	ASSERT (tmp != NULL,
	        "wifi-wpa-psk-unquoted-verify-wireless", "failed to verify %s: missing %s / %s key",
	        TEST_IFCFG_WIFI_WPA_PSK_UNQUOTED,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_SEC);
	ASSERT (strcmp (tmp, NM_SETTING_WIRELESS_SECURITY_SETTING_NAME) == 0,
	        "wifi-wpa-psk-unquoted-verify-wireless", "failed to verify %s: unexpected %s / %s key value",
	        TEST_IFCFG_WIFI_WPA_PSK_UNQUOTED,
	        NM_SETTING_WIRELESS_SETTING_NAME,
	        NM_SETTING_WIRELESS_SEC);

	/* ===== WIRELESS SECURITY SETTING ===== */

	s_wsec = NM_SETTING_WIRELESS_SECURITY (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRELESS_SECURITY));
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
	verify_cert_or_key (CK_PRIV_KEY,
	                    s_8021x,
	                    TEST_IFCFG_WIFI_WPA_EAP_TLS_PRIVATE_KEY,
	                    expected_privkey_password,
	                    TEST_IFCFG_WIFI_WPA_EAP_TLS,
	                    "wifi-wpa-eap-tls-verify-8021x",
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
	verify_cert_or_key (CK_PRIV_KEY,
	                    s_8021x,
	                    TEST_IFCFG_WIFI_WPA_EAP_TLS_PRIVATE_KEY,
	                    expected_privkey_password,
	                    TEST_IFCFG_WIFI_WPA_EAP_TTLS_TLS,
	                    "wifi-wpa-eap-ttls-tls-verify-8021x",
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

	ASSERT (unmanaged == FALSE,
	        "wired-qeth-static-verify", "failed to verify %s: unexpected unmanaged value", TEST_IFCFG_WIRED_QETH_STATIC);

	/* ===== CONNECTION SETTING ===== */

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
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

	s_wired = NM_SETTING_WIRED (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRED));
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

	s_ip4 = NM_SETTING_IP4_CONFIG (nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG));
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
	guint64 timestamp = 0x12344433L;
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
	const guint32 route1_prefix = 64, route2_prefix = 0;
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
	              NM_SETTING_CONNECTION_ID, "Test Write Wired Static",
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
	ASSERT (s_ip6 != NULL,
	        "wired-static-write", "failed to allocate new %s setting",
	        NM_SETTING_IP6_CONFIG_SETTING_NAME);
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
	reread_s_ip4 = NM_SETTING_IP4_CONFIG (nm_connection_get_setting (reread, NM_TYPE_SETTING_IP4_CONFIG));
	reread_s_ip6 = NM_SETTING_IP6_CONFIG (nm_connection_get_setting (reread, NM_TYPE_SETTING_IP6_CONFIG));
	nm_setting_ip6_config_add_dns_search (reread_s_ip6, nm_setting_ip4_config_get_dns_search (reread_s_ip4, 2));
	nm_setting_ip6_config_add_dns_search (reread_s_ip6, nm_setting_ip4_config_get_dns_search (reread_s_ip4, 3));
	nm_setting_ip4_config_remove_dns_search (reread_s_ip4, 3);
	nm_setting_ip4_config_remove_dns_search (reread_s_ip4, 2);

	ASSERT (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "wired-static-write", "written and re-read connection weren't the same.");

	if (route6file)
		unlink (route6file);

	g_free (testfile);
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
	              NM_SETTING_CONNECTION_ID, "Test Write Wired DHCP",
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

	/* IP6 setting */
	s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();
	ASSERT (s_ip6 != NULL,
	        "wired-dhcp-write", "failed to allocate new %s setting",
	        NM_SETTING_IP6_CONFIG_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
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
	guint64 timestamp = 0x12344433L;
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
	ASSERT (connection != NULL,
	        "wired-static-ip6-only-write", "failed to allocate new connection");

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	ASSERT (s_con != NULL,
	        "wired-static-ip6-only-write", "failed to allocate new %s setting",
	        NM_SETTING_CONNECTION_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write Wired Static IP6 Only",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
	              NM_SETTING_CONNECTION_TIMESTAMP, timestamp,
	              NULL);
	g_free (uuid);

	/* Wired setting */
	s_wired = (NMSettingWired *) nm_setting_wired_new ();
	ASSERT (s_wired != NULL,
	        "wired-static-ip6-only-write", "failed to allocate new %s setting",
	        NM_SETTING_WIRED_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_wired));

	mac = g_byte_array_sized_new (sizeof (tmpmac));
	g_byte_array_append (mac, &tmpmac[0], sizeof (tmpmac));
	g_object_set (s_wired, NM_SETTING_WIRED_MAC_ADDRESS, mac, NULL);
	g_byte_array_free (mac, TRUE);

	/* IP4 setting */
	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	ASSERT (s_ip4 != NULL,
	        "wired-static-ip6-only-write", "failed to allocate new %s setting",
	        NM_SETTING_IP4_CONFIG_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4,
	              NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_DISABLED,
	              NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();
	ASSERT (s_ip6 != NULL,
	        "wired-static-ip6-only-write", "failed to allocate new %s setting",
	        NM_SETTING_IP6_CONFIG_SETTING_NAME);
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
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);
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

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
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

	s_wired = NM_SETTING_WIRED (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRED));
	ASSERT (s_wired != NULL,
	        "read-write-static-routes-legacy-verify-wired", "failed to verify %s: missing %s setting",
	        TEST_IFCFG_READ_WRITE_STATIC_ROUTES_LEGACY,
	        NM_SETTING_WIRED_SETTING_NAME);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = NM_SETTING_IP4_CONFIG (nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG));
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
	guint64 timestamp = 0x12344433L;
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
	ASSERT (connection != NULL,
	        "wired-static-routes-write", "failed to allocate new connection");

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	ASSERT (s_con != NULL,
	        "wired-static-routes-write", "failed to allocate new %s setting",
	        NM_SETTING_CONNECTION_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write Wired Static Routes",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
	              NM_SETTING_CONNECTION_TIMESTAMP, timestamp,
	              NULL);
	g_free (uuid);

	/* Wired setting */
	s_wired = (NMSettingWired *) nm_setting_wired_new ();
	ASSERT (s_wired != NULL,
	        "wired-static-routes-write", "failed to allocate new %s setting",
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
			"wired-static-routes-write", "failed to allocate new %s setting",
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
	ASSERT (s_ip6 != NULL,
	        "wired-dhcp-8021x-peap-mschapv2write", "failed to allocate new %s setting",
	        NM_SETTING_IP6_CONFIG_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6, NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE, NULL);

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
	ASSERT (connection != NULL,
	        "wired-dhcp-8021x-peap-mschapv2write", "failed to allocate new connection");

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	ASSERT (s_con != NULL,
	        "wired-dhcp-8021x-peap-mschapv2write", "failed to allocate new %s setting",
	        NM_SETTING_CONNECTION_SETTING_NAME);
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
	ASSERT (s_wired != NULL,
	        "wired-dhcp-8021x-peap-mschapv2write", "failed to allocate new %s setting",
	        NM_SETTING_WIRED_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_wired));

	/* IP4 setting */
	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	ASSERT (s_ip4 != NULL,
			"wired-dhcp-8021x-peap-mschapv2write", "failed to allocate new %s setting",
			NM_SETTING_IP4_CONFIG_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4, NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();
	ASSERT (s_ip6 != NULL,
	        "wired-dhcp-8021x-peap-mschapv2write", "failed to allocate new %s setting",
	        NM_SETTING_IP6_CONFIG_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6, NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE, NULL);

	/* 802.1x setting */
	s_8021x = (NMSetting8021x *) nm_setting_802_1x_new ();
	ASSERT (s_8021x != NULL,
			"wired-dhcp-8021x-peap-mschapv2write", "failed to allocate new %s setting",
			NM_SETTING_802_1X_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_8021x));

	g_object_set (s_8021x,
	              NM_SETTING_802_1X_IDENTITY, "Bob Saget",
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
	              NM_SETTING_CONNECTION_ID, "Test Write Wifi Open",
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

	/* IP6 setting */
	s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();
	ASSERT (s_ip6 != NULL,
	        "wifi-open-write", "failed to allocate new %s setting",
	        NM_SETTING_IP6_CONFIG_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6, NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE, NULL);

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

	/* Now make sure that the ESSID item isn't double-quoted (rh #606518) */
	ifcfg = svNewFile (testfile);
	ASSERT (ifcfg != NULL,
	        "wifi-open-write-reread", "failed to load %s as shvarfile", testfile);

	tmp = svGetValue (ifcfg, "ESSID", TRUE);
	ASSERT (tmp != NULL,
	        "wifi-open-write-reread", "failed to read ESSID key from %s", testfile);

	g_message ("%s", tmp);
	ASSERT (strncmp (tmp, "\"\"", 2) != 0,
	        "wifi-open-write-reread", "unexpected ESSID double-quote in %s", testfile);

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
	              NM_SETTING_CONNECTION_ID, "Test Write Wifi Open Hex SSID",
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

	/* IP6 setting */
	s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();
	ASSERT (s_ip6 != NULL,
	        "wifi-open-hex-ssid-write", "failed to allocate new %s setting",
	        NM_SETTING_IP6_CONFIG_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6, NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE, NULL);

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
	ASSERT (connection != NULL,
	        "wifi-wep-write", "failed to allocate new connection");

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	ASSERT (s_con != NULL,
	        "wifi-wep-write", "failed to allocate new %s setting",
	        NM_SETTING_CONNECTION_SETTING_NAME);
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
	ASSERT (s_wifi != NULL,
	        "wifi-wep-write", "failed to allocate new %s setting",
	        NM_SETTING_WIRELESS_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_wifi));

	ssid = g_byte_array_sized_new (sizeof (ssid_data));
	g_byte_array_append (ssid, ssid_data, sizeof (ssid_data));

	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_MODE, "infrastructure",
	              NM_SETTING_WIRELESS_SEC, NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	              NULL);

	g_byte_array_free (ssid, TRUE);

	/* Wireless security setting */
	s_wsec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
	ASSERT (s_wsec != NULL,
			"wifi-wep-write", "failed to allocate new %s setting",
			NM_SETTING_WIRELESS_SECURITY_SETTING_NAME);
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
	ASSERT (s_ip4 != NULL,
			"wifi-wep-write", "failed to allocate new %s setting",
			NM_SETTING_IP4_CONFIG_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4, NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();
	ASSERT (s_ip6 != NULL,
	        "wifi-wep-write", "failed to allocate new %s setting",
	        NM_SETTING_IP6_CONFIG_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6, NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE, NULL);

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
	ASSERT (connection != NULL,
	        "wifi-wep-adhoc-write", "failed to allocate new connection");

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	ASSERT (s_con != NULL,
	        "wifi-wep-adhoc-write", "failed to allocate new %s setting",
	        NM_SETTING_CONNECTION_SETTING_NAME);
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
	ASSERT (s_wifi != NULL,
	        "wifi-wep-adhoc-write", "failed to allocate new %s setting",
	        NM_SETTING_WIRELESS_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_wifi));

	ssid = g_byte_array_sized_new (sizeof (ssid_data));
	g_byte_array_append (ssid, ssid_data, sizeof (ssid_data));

	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_MODE, "adhoc",
	              NM_SETTING_WIRELESS_SEC, NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	              NULL);

	g_byte_array_free (ssid, TRUE);

	/* Wireless security setting */
	s_wsec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
	ASSERT (s_wsec != NULL,
			"wifi-wep-adhoc-write", "failed to allocate new %s setting",
			NM_SETTING_WIRELESS_SECURITY_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_wsec));

	g_object_set (s_wsec, NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "none", NULL);
	nm_setting_wireless_security_set_wep_key (s_wsec, 0, "0123456789abcdef0123456789");

	/* IP4 setting */
	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	ASSERT (s_ip4 != NULL,
			"wifi-wep-adhoc-write", "failed to allocate new %s setting",
			NM_SETTING_IP4_CONFIG_SETTING_NAME);
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
	ASSERT (s_ip6 != NULL,
	        "wifi-wep-adhoc-write", "failed to allocate new %s setting",
	        NM_SETTING_IP6_CONFIG_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6, NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE, NULL);

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
	ASSERT (connection != NULL,
	        "wifi-wep-passphrase-write", "failed to allocate new connection");

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	ASSERT (s_con != NULL,
	        "wifi-wep-passphrase-write", "failed to allocate new %s setting",
	        NM_SETTING_CONNECTION_SETTING_NAME);
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
	ASSERT (s_wifi != NULL,
	        "wifi-wep-passphrase-write", "failed to allocate new %s setting",
	        NM_SETTING_WIRELESS_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_wifi));

	ssid = g_byte_array_sized_new (sizeof (ssid_data));
	g_byte_array_append (ssid, ssid_data, sizeof (ssid_data));

	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_MODE, "infrastructure",
	              NM_SETTING_WIRELESS_SEC, NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	              NULL);

	g_byte_array_free (ssid, TRUE);

	/* Wireless security setting */
	s_wsec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
	ASSERT (s_wsec != NULL,
			"wifi-wep-passphrase-write", "failed to allocate new %s setting",
			NM_SETTING_WIRELESS_SECURITY_SETTING_NAME);
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
	ASSERT (s_ip4 != NULL,
			"wifi-wep-passphrase-write", "failed to allocate new %s setting",
			NM_SETTING_IP4_CONFIG_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4, NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();
	ASSERT (s_ip6 != NULL,
	        "wifi-wep-adhoc-write", "failed to allocate new %s setting",
	        NM_SETTING_IP6_CONFIG_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6, NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE, NULL);

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
	ASSERT (connection != NULL,
	        "wifi-wep-40-ascii-write", "failed to allocate new connection");

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	ASSERT (s_con != NULL,
	        "wifi-wep-40-ascii-write", "failed to allocate new %s setting",
	        NM_SETTING_CONNECTION_SETTING_NAME);
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
	ASSERT (s_wifi != NULL,
	        "wifi-wep-40-ascii-write", "failed to allocate new %s setting",
	        NM_SETTING_WIRELESS_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_wifi));

	ssid = g_byte_array_sized_new (sizeof (ssid_data));
	g_byte_array_append (ssid, ssid_data, sizeof (ssid_data));

	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_MODE, "infrastructure",
	              NM_SETTING_WIRELESS_SEC, NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	              NULL);

	g_byte_array_free (ssid, TRUE);

	/* Wireless security setting */
	s_wsec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
	ASSERT (s_wsec != NULL,
			"wifi-wep-40-ascii-write", "failed to allocate new %s setting",
			NM_SETTING_WIRELESS_SECURITY_SETTING_NAME);
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
	ASSERT (s_ip4 != NULL,
			"wifi-wep-40-ascii-write", "failed to allocate new %s setting",
			NM_SETTING_IP4_CONFIG_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4, NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();
	ASSERT (s_ip6 != NULL,
	        "wifi-wep-40-ascii-write", "failed to allocate new %s setting",
	        NM_SETTING_IP6_CONFIG_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6, NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE, NULL);

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
	ASSERT (connection != NULL,
	        "wifi-wep-104-ascii-write", "failed to allocate new connection");

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	ASSERT (s_con != NULL,
	        "wifi-wep-104-ascii-write", "failed to allocate new %s setting",
	        NM_SETTING_CONNECTION_SETTING_NAME);
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
	ASSERT (s_wifi != NULL,
	        "wifi-wep-104-ascii-write", "failed to allocate new %s setting",
	        NM_SETTING_WIRELESS_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_wifi));

	ssid = g_byte_array_sized_new (sizeof (ssid_data));
	g_byte_array_append (ssid, ssid_data, sizeof (ssid_data));

	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_MODE, "infrastructure",
	              NM_SETTING_WIRELESS_SEC, NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	              NULL);

	g_byte_array_free (ssid, TRUE);

	/* Wireless security setting */
	s_wsec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
	ASSERT (s_wsec != NULL,
			"wifi-wep-104-ascii-write", "failed to allocate new %s setting",
			NM_SETTING_WIRELESS_SECURITY_SETTING_NAME);
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
	ASSERT (s_ip4 != NULL,
			"wifi-wep-104-ascii-write", "failed to allocate new %s setting",
			NM_SETTING_IP4_CONFIG_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4, NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();
	ASSERT (s_ip6 != NULL,
	        "wifi-wep-104-ascii-write", "failed to allocate new %s setting",
	        NM_SETTING_IP6_CONFIG_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6, NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE, NULL);

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
	ASSERT (connection != NULL,
	        "wifi-leap-write", "failed to allocate new connection");

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	ASSERT (s_con != NULL,
	        "wifi-leap-write", "failed to allocate new %s setting",
	        NM_SETTING_CONNECTION_SETTING_NAME);
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
	ASSERT (s_wifi != NULL,
	        "wifi-leap-write", "failed to allocate new %s setting",
	        NM_SETTING_WIRELESS_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_wifi));

	ssid = g_byte_array_sized_new (sizeof (ssid_data));
	g_byte_array_append (ssid, ssid_data, sizeof (ssid_data));

	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_MODE, "infrastructure",
	              NM_SETTING_WIRELESS_SEC, NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	              NULL);

	g_byte_array_free (ssid, TRUE);

	/* Wireless security setting */
	s_wsec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
	ASSERT (s_wsec != NULL,
			"wifi-leap-write", "failed to allocate new %s setting",
			NM_SETTING_WIRELESS_SECURITY_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_wsec));

	g_object_set (s_wsec,
	              NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "ieee8021x",
	              NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "leap",
	              NM_SETTING_WIRELESS_SECURITY_LEAP_USERNAME, "Bill Smith",
	              NM_SETTING_WIRELESS_SECURITY_LEAP_PASSWORD, "foobar22",
	              NULL);

	/* IP4 setting */
	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	ASSERT (s_ip4 != NULL,
			"wifi-leap-write", "failed to allocate new %s setting",
			NM_SETTING_IP4_CONFIG_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4, NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();
	ASSERT (s_ip6 != NULL,
	        "wifi-leap-write", "failed to allocate new %s setting",
	        NM_SETTING_IP6_CONFIG_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6, NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE, NULL);

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
	ASSERT (connection != NULL,
	        test_name, "failed to allocate new connection");

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	ASSERT (s_con != NULL,
	        test_name, "failed to allocate new %s setting",
	        NM_SETTING_CONNECTION_SETTING_NAME);
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
	ASSERT (s_wifi != NULL,
	        test_name, "failed to allocate new %s setting",
	        NM_SETTING_WIRELESS_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_wifi));

	ssid = g_byte_array_sized_new (sizeof (ssid_data));
	g_byte_array_append (ssid, ssid_data, sizeof (ssid_data));

	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_MODE, "infrastructure",
	              NM_SETTING_WIRELESS_SEC, NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	              NULL);

	g_byte_array_free (ssid, TRUE);

	/* Wireless security setting */
	s_wsec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
	ASSERT (s_wsec != NULL,
			test_name, "failed to allocate new %s setting",
			NM_SETTING_WIRELESS_SECURITY_SETTING_NAME);
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
	ASSERT (s_ip4 != NULL,
			test_name, "failed to allocate new %s setting",
			NM_SETTING_IP4_CONFIG_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4, NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();
	ASSERT (s_ip6 != NULL,
	        test_name, "failed to allocate new %s setting",
	        NM_SETTING_IP6_CONFIG_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6, NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE, NULL);

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
	ASSERT (connection != NULL,
	        "wifi-wpa-psk-adhoc-write", "failed to allocate new connection");

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	ASSERT (s_con != NULL,
	        "wifi-wpa-psk-adhoc-write", "failed to allocate new %s setting",
	        NM_SETTING_CONNECTION_SETTING_NAME);
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
	ASSERT (s_wifi != NULL,
	        "wifi-wpa-psk-adhoc-write", "failed to allocate new %s setting",
	        NM_SETTING_WIRELESS_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_wifi));

	ssid = g_byte_array_sized_new (sizeof (ssid_data));
	g_byte_array_append (ssid, ssid_data, sizeof (ssid_data));

	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_MODE, "adhoc",
	              NM_SETTING_WIRELESS_SEC, NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	              NM_SETTING_WIRELESS_CHANNEL, 11,
	              NM_SETTING_WIRELESS_BAND, "bg",
	              NULL);

	g_byte_array_free (ssid, TRUE);

	/* Wireless security setting */
	s_wsec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
	ASSERT (s_wsec != NULL,
			"wifi-wpa-psk-adhoc-write", "failed to allocate new %s setting",
			NM_SETTING_WIRELESS_SECURITY_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_wsec));

	g_object_set (s_wsec,
	              NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "wpa-none",
	              NM_SETTING_WIRELESS_SECURITY_PSK, "7d308b11df1b4243b0f78e5f3fc68cdbb9a264ed0edf4c188edf329ff5b467f0",
	              NULL);

	nm_setting_wireless_security_add_proto (s_wsec, "wpa");
	nm_setting_wireless_security_add_group (s_wsec, "tkip");

	/* IP4 setting */
	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	ASSERT (s_ip4 != NULL,
			"wifi-wpa-psk-adhoc-write", "failed to allocate new %s setting",
			NM_SETTING_IP4_CONFIG_SETTING_NAME);
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
	ASSERT (s_ip6 != NULL,
	        "wifi-wpa-psk-adhoc-write", "failed to allocate new %s setting",
	        NM_SETTING_IP6_CONFIG_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6, NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE, NULL);

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
	ASSERT (connection != NULL,
	        "wifi-wpa-eap-tls-write", "failed to allocate new connection");

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	ASSERT (s_con != NULL,
	        "wifi-wpa-eap-tls-write", "failed to allocate new %s setting",
	        NM_SETTING_CONNECTION_SETTING_NAME);
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
	ASSERT (s_wifi != NULL,
	        "wifi-wpa-eap-tls-write", "failed to allocate new %s setting",
	        NM_SETTING_WIRELESS_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_wifi));

	ssid = g_byte_array_sized_new (strlen (ssid_data));
	g_byte_array_append (ssid, (const unsigned char *) ssid_data, strlen (ssid_data));

	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_MODE, "infrastructure",
	              NM_SETTING_WIRELESS_SEC, NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	              NULL);

	g_byte_array_free (ssid, TRUE);

	/* Wireless security setting */
	s_wsec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
	ASSERT (s_wsec != NULL,
	        "wifi-wpa-eap-tls-write", "failed to allocate new %s setting",
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_wsec));

	g_object_set (s_wsec, NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "wpa-eap", NULL);
	nm_setting_wireless_security_add_proto (s_wsec, "wpa");
	nm_setting_wireless_security_add_pairwise (s_wsec, "tkip");
	nm_setting_wireless_security_add_group (s_wsec, "tkip");

	/* Wireless security setting */
	s_8021x = (NMSetting8021x *) nm_setting_802_1x_new ();
	ASSERT (s_8021x != NULL,
	        "wifi-wpa-eap-tls-write", "failed to allocate new %s setting",
	        NM_SETTING_802_1X_SETTING_NAME);
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
	ASSERT (s_ip4 != NULL,
			"wifi-wpa-eap-tls-write", "failed to allocate new %s setting",
			NM_SETTING_IP4_CONFIG_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4, NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();
	ASSERT (s_ip6 != NULL,
	        "wifi-wpa-eap-tls-write", "failed to allocate new %s setting",
	        NM_SETTING_IP6_CONFIG_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6, NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE, NULL);

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
	ASSERT (connection != NULL,
	        "wifi-wpa-eap-ttls-tls-write", "failed to allocate new connection");

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	ASSERT (s_con != NULL,
	        "wifi-wpa-eap-ttls-tls-write", "failed to allocate new %s setting",
	        NM_SETTING_CONNECTION_SETTING_NAME);
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
	ASSERT (s_wifi != NULL,
	        "wifi-wpa-eap-ttls-tls-write", "failed to allocate new %s setting",
	        NM_SETTING_WIRELESS_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_wifi));

	ssid = g_byte_array_sized_new (strlen (ssid_data));
	g_byte_array_append (ssid, (const unsigned char *) ssid_data, strlen (ssid_data));

	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_MODE, "infrastructure",
	              NM_SETTING_WIRELESS_SEC, NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	              NULL);

	g_byte_array_free (ssid, TRUE);

	/* Wireless security setting */
	s_wsec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
	ASSERT (s_wsec != NULL,
	        "wifi-wpa-eap-ttls-tls-write", "failed to allocate new %s setting",
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_wsec));

	g_object_set (s_wsec, NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "wpa-eap", NULL);
	nm_setting_wireless_security_add_proto (s_wsec, "rsn");
	nm_setting_wireless_security_add_pairwise (s_wsec, "ccmp");
	nm_setting_wireless_security_add_group (s_wsec, "ccmp");

	/* Wireless security setting */
	s_8021x = (NMSetting8021x *) nm_setting_802_1x_new ();
	ASSERT (s_8021x != NULL,
	        "wifi-wpa-eap-ttls-tls-write", "failed to allocate new %s setting",
	        NM_SETTING_802_1X_SETTING_NAME);
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
	ASSERT (s_ip4 != NULL,
			"wifi-wpa-eap-ttls-tls-write", "failed to allocate new %s setting",
			NM_SETTING_IP4_CONFIG_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4, NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();
	ASSERT (s_ip6 != NULL,
	        "wifi-wpa-eap-ttls-tls-write", "failed to allocate new %s setting",
	        NM_SETTING_IP6_CONFIG_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6, NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE, NULL);

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
	ASSERT (connection != NULL,
	        "wifi-wpa-eap-ttls-mschapv2-write", "failed to allocate new connection");

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	ASSERT (s_con != NULL,
	        "wifi-wpa-eap-ttls-mschapv2-write", "failed to allocate new %s setting",
	        NM_SETTING_CONNECTION_SETTING_NAME);
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
	ASSERT (s_wifi != NULL,
	        "wifi-wpa-eap-ttls-mschapv2-write", "failed to allocate new %s setting",
	        NM_SETTING_WIRELESS_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_wifi));

	ssid = g_byte_array_sized_new (strlen (ssid_data));
	g_byte_array_append (ssid, (const unsigned char *) ssid_data, strlen (ssid_data));

	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_MODE, "infrastructure",
	              NM_SETTING_WIRELESS_SEC, NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	              NULL);

	g_byte_array_free (ssid, TRUE);

	/* Wireless security setting */
	s_wsec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
	ASSERT (s_wsec != NULL,
	        "wifi-wpa-eap-ttls-mschapv2-write", "failed to allocate new %s setting",
	        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME);
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
	ASSERT (s_8021x != NULL,
	        "wifi-wpa-eap-ttls-mschapv2-write", "failed to allocate new %s setting",
	        NM_SETTING_802_1X_SETTING_NAME);
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
	ASSERT (s_ip4 != NULL,
			"wifi-wpa-eap-ttls-mschapv2-write", "failed to allocate new %s setting",
			NM_SETTING_IP4_CONFIG_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4, NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();
	ASSERT (s_ip6 != NULL,
	        "wifi-wpa-eap-ttls-mschapv2-write", "failed to allocate new %s setting",
	        NM_SETTING_IP6_CONFIG_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6, NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE, NULL);

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

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
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

	s_wired = NM_SETTING_WIRED (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRED));
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

	s_ip4 = NM_SETTING_IP4_CONFIG (nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG));
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
	struct in_addr addr;
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

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
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

	s_wired = NM_SETTING_WIRED (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRED));
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

	s_ip4 = NM_SETTING_IP4_CONFIG (nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG));
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
	ASSERT (nm_setting_ip4_config_get_dns (s_ip4, 0) == addr.s_addr,
	        "ibft-static-verify-ip4", "failed to verify %s: unexpected %s / %s key value #1",
	        TEST_IFCFG_IBFT_STATIC,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS);

	ASSERT (inet_pton (AF_INET, expected_dns2, &addr) > 0,
	        "ibft-static-verify-ip4", "failed to verify %s: couldn't convert DNS IP address #2",
	        TEST_IFCFG_IBFT_STATIC,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS);
	ASSERT (nm_setting_ip4_config_get_dns (s_ip4, 1) == addr.s_addr,
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
	ASSERT (nm_ip4_address_get_address (ip4_addr) == addr.s_addr,
	        "ibft-static-verify-ip4", "failed to verify %s: unexpected IP4 address #1",
	        TEST_IFCFG_IBFT_STATIC,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_ADDRESSES);

	ASSERT (inet_pton (AF_INET, expected_address1_gw, &addr) > 0,
	        "ibft-static-verify-ip4", "failed to verify %s: couldn't convert IP address #1 gateway",
	        TEST_IFCFG_IBFT_STATIC,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_ADDRESSES);
	ASSERT (nm_ip4_address_get_gateway (ip4_addr) == addr.s_addr,
	        "ibft-static-verify-ip4", "failed to verify %s: unexpected IP4 address #1 gateway",
	        TEST_IFCFG_IBFT_STATIC,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_ADDRESSES);

	g_object_unref (connection);
}

static void
test_read_ibft_malformed (const char *name, const char *iscsiadm_path)
{
	NMConnection *connection;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;

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
	ASSERT (connection == NULL,
	        name, "unexpectedly able to read %s", TEST_IFCFG_IBFT_STATIC);
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
	ASSERT (connection != NULL,
	        "wired-qeth-dhcp-write", "failed to allocate new connection");

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	ASSERT (s_con != NULL,
	        "wired-qeth-dhcp-write", "failed to allocate new %s setting",
	        NM_SETTING_CONNECTION_SETTING_NAME);
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
	ASSERT (s_wired != NULL,
	        "wired-qeth-dhcp-write", "failed to allocate new %s setting",
	        NM_SETTING_WIRED_SETTING_NAME);
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
	ASSERT (s_ip4 != NULL,
			"wired-qeth-dhcp-write", "failed to allocate new %s setting",
			NM_SETTING_IP4_CONFIG_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4,
	              NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
	              NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();
	ASSERT (s_ip6 != NULL,
			"wired-qeth-dhcp-write", "failed to allocate new %s setting",
			NM_SETTING_IP6_CONFIG_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
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
	ASSERT (connection != NULL,
	        "wired-pppoe-write", "failed to allocate new connection");

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	ASSERT (s_con != NULL,
	        "wired-pppoe-write", "failed to allocate new %s setting",
	        NM_SETTING_CONNECTION_SETTING_NAME);
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
	ASSERT (s_wired != NULL,
	        "wired-pppoe-write", "failed to allocate new %s setting",
	        NM_SETTING_WIRED_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_wired));

	/* IP4 setting */
	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	ASSERT (s_ip4 != NULL,
			"wired-pppoe-write", "failed to allocate new %s setting",
			NM_SETTING_IP4_CONFIG_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4,
	              NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
	              NULL);

	/* PPPoE setting */
	s_pppoe = (NMSettingPPPOE *) nm_setting_pppoe_new ();
	ASSERT (s_pppoe != NULL,
			"wired-pppoe-write", "failed to allocate new %s setting",
			NM_SETTING_PPPOE_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_pppoe));

	g_object_set (G_OBJECT (s_pppoe),
	              NM_SETTING_PPPOE_SERVICE, "stupid-service",
	              NM_SETTING_PPPOE_USERNAME, "Bill Smith",
	              NM_SETTING_PPPOE_PASSWORD, "test1",
	              NULL);

	/* PPP setting */
	s_ppp = (NMSettingPPP *) nm_setting_ppp_new ();
	ASSERT (s_ppp != NULL,
			"wired-pppoe-write", "failed to allocate new %s setting",
			NM_SETTING_PPP_SETTING_NAME);
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
	ASSERT (connection != NULL,
	        "vpn-write", "failed to allocate new connection");

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	ASSERT (s_con != NULL,
	        "vpn-write", "failed to allocate new %s setting",
	        NM_SETTING_CONNECTION_SETTING_NAME);
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
	ASSERT (s_vpn != NULL,
	        "vpn-write", "failed to allocate new %s setting",
	        NM_SETTING_VPN_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_vpn));

	g_object_set (s_vpn,
	              NM_SETTING_VPN_SERVICE_TYPE, "awesomevpn",
	              NM_SETTING_VPN_USER_NAME, "Bill Smith",
	              NULL);

	nm_setting_vpn_add_data_item (s_vpn, "server", "vpn.somewhere.com");
	nm_setting_vpn_add_secret (s_vpn, "password", "sup3rs3cr3t");

	/* IP4 setting */
	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	ASSERT (s_ip4 != NULL,
			"vpn-write", "failed to allocate new %s setting",
			NM_SETTING_IP4_CONFIG_SETTING_NAME);
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
	ASSERT (connection != NULL,
	        "mobile-broadband-write", "failed to allocate new connection");

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	ASSERT (s_con != NULL,
	        "mobile-broadband-write", "failed to allocate new %s setting",
	        NM_SETTING_CONNECTION_SETTING_NAME);
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
		ASSERT (s_gsm != NULL,
		        "mobile-broadband-write", "failed to allocate new %s setting",
		        NM_SETTING_GSM_SETTING_NAME);
		nm_connection_add_setting (connection, NM_SETTING (s_gsm));

		g_object_set (s_gsm, NM_SETTING_GSM_NUMBER, "*99#", NULL);
	} else {
		/* CDMA setting */
		s_cdma = (NMSettingCdma *) nm_setting_cdma_new ();
		ASSERT (s_cdma != NULL,
		        "mobile-broadband-write", "failed to allocate new %s setting",
		        NM_SETTING_CDMA_SETTING_NAME);
		nm_connection_add_setting (connection, NM_SETTING (s_cdma));

		g_object_set (s_cdma, NM_SETTING_CDMA_NUMBER, "#777", NULL);
	}

	/* Serial setting */
	s_serial = (NMSettingSerial *) nm_setting_serial_new ();
	ASSERT (s_serial != NULL,
	        "mobile-broadband-write", "failed to allocate new %s setting",
	        NM_SETTING_SERIAL_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_serial));

	g_object_set (s_serial,
	              NM_SETTING_SERIAL_BAUD, 115200,
	              NM_SETTING_SERIAL_BITS, 8,
	              NM_SETTING_SERIAL_PARITY, 'n',
	              NM_SETTING_SERIAL_STOPBITS, 1,
	              NULL);

	/* IP4 setting */
	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	ASSERT (s_ip4 != NULL,
			"mobile-broadband-write", "failed to allocate new %s setting",
			NM_SETTING_IP4_CONFIG_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4,
	              NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
	              NULL);

	/* PPP setting */
	s_ppp = (NMSettingPPP *) nm_setting_ppp_new ();
	ASSERT (s_ppp != NULL,
			"mobile-broadband-write", "failed to allocate new %s setting",
			NM_SETTING_PPP_SETTING_NAME);
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
	ASSERT (connection == NULL,
	        "bridge-main-read", "unexpected success reading %s", TEST_IFCFG_BRIDGE_MAIN);
}

#define TEST_IFCFG_BRIDGE_COMPONENT TEST_IFCFG_DIR"/network-scripts/ifcfg-test-bridge-component"

static void
test_read_bridge_component (void)
{
	NMConnection *connection;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	gboolean ignore_error = FALSE;
	GError *error = NULL;

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
	ASSERT (connection != NULL,
	        "bridge-component-read", "unexpected failure reading %s", TEST_IFCFG_BRIDGE_COMPONENT);

	ASSERT (unmanaged != NULL,
	        "bridge-component-read", "missing unmanaged spec from %s", TEST_IFCFG_BRIDGE_COMPONENT);

	ASSERT (g_strcmp0 (unmanaged, "mac:00:22:15:59:62:97") == 0,
	        "bridge-component-read", "unexpected unmanaged spec from %s", TEST_IFCFG_BRIDGE_COMPONENT);

	g_object_unref (connection);
	g_free (unmanaged);
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
	ASSERT (connection == NULL,
	        "vlan-interface-read", "unexpected success reading %s", TEST_IFCFG_VLAN_INTERFACE);
}

#define TEST_IFCFG_WIFI_OPEN_SSID_BAD_HEX TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wifi-open-ssid-bad-hex"
#define TEST_IFCFG_WIFI_OPEN_SSID_LONG_QUOTED TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wifi-open-ssid-long-quoted"
#define TEST_IFCFG_WIFI_OPEN_SSID_LONG_HEX TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wifi-open-ssid-long-hex"


#define TEST_IFCFG_WIRED_STATIC           TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-static"
#define TEST_IFCFG_WIRED_STATIC_BOOTPROTO TEST_IFCFG_DIR"/network-scripts/ifcfg-test-wired-static-bootproto"

#define DEFAULT_HEX_PSK "7d308b11df1b4243b0f78e5f3fc68cdbb9a264ed0edf4c188edf329ff5b467f0"

int main (int argc, char **argv)
{
	GError *error = NULL;
	DBusGConnection *bus;
	char *base;

	g_type_init ();
	bus = dbus_g_bus_get (DBUS_BUS_SESSION, NULL);

	if (!nm_utils_init (&error))
		FAIL ("nm-utils-init", "failed to initialize libnm-util: %s", error->message);

	/* The tests */
	test_read_unmanaged ();
	test_read_minimal ();
	test_read_wired_static (TEST_IFCFG_WIRED_STATIC, "System test-wired-static");
	test_read_wired_static (TEST_IFCFG_WIRED_STATIC_BOOTPROTO, "System test-wired-static-bootproto");
	test_read_wired_static_no_prefix (8);
	test_read_wired_static_no_prefix (16);
	test_read_wired_static_no_prefix (24);
	test_read_wired_dhcp ();
	test_read_wired_global_gateway ();
	test_read_wired_never_default ();
	test_read_wired_defroute_no ();
	test_read_wired_defroute_no_gatewaydev_yes ();
	test_read_wired_static_routes ();
	test_read_wired_static_routes_legacy ();
	test_read_wired_ipv6_manual ();
	test_read_wired_ipv6_only ();
	test_read_wired_dhcp6_only ();
	test_read_onboot_no ();
	test_read_wired_8021x_peap_mschapv2 ();
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
	test_read_wifi_wpa_psk ();
	test_read_wifi_wpa_psk_unquoted ();
	test_read_wifi_wpa_psk_unquoted2 ();
	test_read_wifi_wpa_psk_adhoc ();
	test_read_wifi_wpa_psk_hex ();
	test_read_wifi_wpa_eap_tls ();
	test_read_wifi_wpa_eap_ttls_tls ();
	test_read_wifi_wep_eap_ttls_chap ();
	test_read_wired_qeth_static ();

	test_write_wired_static ();
	test_write_wired_static_ip6_only ();
	test_write_wired_static_routes ();
	test_read_write_static_routes_legacy ();
	test_write_wired_dhcp ();
	test_write_wired_dhcp_8021x_peap_mschapv2 ();
	test_write_wifi_open ();
	test_write_wifi_open_hex_ssid ();
	test_write_wifi_wep ();
	test_write_wifi_wep_adhoc ();
	test_write_wifi_wep_passphrase ();
	test_write_wifi_wep_40_ascii ();
	test_write_wifi_wep_104_ascii ();
	test_write_wifi_leap ();
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
	test_write_wifi_wpa_psk_adhoc ();
	test_write_wifi_wpa_eap_tls ();
	test_write_wifi_wpa_eap_ttls_tls ();
	test_write_wifi_wpa_eap_ttls_mschapv2 ();
	test_write_wired_qeth_dhcp ();

	/* iSCSI / ibft */
	test_read_ibft_dhcp ();
	test_read_ibft_static ();
	test_read_ibft_malformed ("ibft-bad-record-read", TEST_IFCFG_DIR "/iscsiadm-test-bad-record");
	test_read_ibft_malformed ("ibft-bad-entry-read", TEST_IFCFG_DIR "/iscsiadm-test-bad-entry");
	test_read_ibft_malformed ("ibft-bad-ipaddr-read", TEST_IFCFG_DIR "/iscsiadm-test-bad-ipaddr");
	test_read_ibft_malformed ("ibft-bad-gateway-read", TEST_IFCFG_DIR "/iscsiadm-test-bad-gateway");
	test_read_ibft_malformed ("ibft-bad-dns1-read", TEST_IFCFG_DIR "/iscsiadm-test-bad-dns1");
	test_read_ibft_malformed ("ibft-bad-dns2-read", TEST_IFCFG_DIR "/iscsiadm-test-bad-dns2");

	/* Stuff we expect to fail for now */
	test_write_wired_pppoe ();
	test_write_vpn ();
	test_write_mobile_broadband (TRUE);
	test_write_mobile_broadband (FALSE);
	test_read_bridge_main ();
	test_read_bridge_component ();
	test_read_vlan_interface ();

	base = g_path_get_basename (argv[0]);
	fprintf (stdout, "%s: SUCCESS\n", base);
	g_free (base);
	return 0;
}

