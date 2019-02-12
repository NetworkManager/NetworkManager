/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager
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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "nm-core-internal.h"

#include "supplicant/nm-supplicant-config.h"
#include "supplicant/nm-supplicant-settings-verify.h"

#include "nm-test-utils-core.h"

#define TEST_CERT_DIR                         NM_BUILD_SRCDIR"/src/supplicant/tests/certs"

/*****************************************************************************/

static gboolean
validate_opt (const char *detail,
              GVariant *config,
              const char *key,
              OptType val_type,
              gconstpointer expected)
{
	char *config_key;
	GVariant *config_value;
	gboolean found = FALSE;
	GVariantIter iter;

	g_assert (g_variant_is_of_type (config, G_VARIANT_TYPE_VARDICT));

	g_variant_iter_init (&iter, config);
	while (g_variant_iter_next (&iter, "{&sv}", (gpointer) &config_key, (gpointer) &config_value)) {
		if (!strcmp (key, config_key)) {
			found = TRUE;
			switch (val_type) {
			case TYPE_INT: {
				g_assert (g_variant_is_of_type (config_value, G_VARIANT_TYPE_INT32));
				g_assert_cmpint (g_variant_get_int32 (config_value), ==, GPOINTER_TO_INT (expected));
				break;
			}
			case TYPE_BYTES: {
				const guint8 *expected_bytes;
				gsize expected_len = 0;
				const guint8 *config_bytes;
				gsize config_len = 0;

				expected_bytes = g_bytes_get_data ((GBytes *) expected, &expected_len);
				g_assert (g_variant_is_of_type (config_value, G_VARIANT_TYPE_BYTESTRING));
				config_bytes = g_variant_get_fixed_array (config_value, &config_len, 1);
				g_assert_cmpmem (config_bytes, config_len, expected_bytes, expected_len);
				break;
			}
			case TYPE_KEYWORD:
			case TYPE_STRING: {
				const char *expected_str = expected;
				const char *config_str;

				g_assert (g_variant_is_of_type (config_value, G_VARIANT_TYPE_STRING));
				config_str = g_variant_get_string (config_value, NULL);
				g_assert_cmpstr (config_str, ==, expected_str);
				break;
			}
			default:
				g_assert_not_reached ();
				break;
			}
		}
		g_variant_unref (config_value);
	}

	return found;
}

static GVariant *
build_supplicant_config (NMConnection *connection,
                         guint mtu,
                         guint fixed_freq,
                         gboolean support_pmf,
                         gboolean support_fils)
{
	gs_unref_object NMSupplicantConfig *config = NULL;
	gs_free_error GError *error = NULL;
	NMSettingWireless *s_wifi;
	NMSettingWirelessSecurity *s_wsec;
	NMSetting8021x *s_8021x;
	gboolean success;

	config = nm_supplicant_config_new (support_pmf, support_fils);

	s_wifi = nm_connection_get_setting_wireless (connection);
	g_assert (s_wifi);
	success = nm_supplicant_config_add_setting_wireless (config,
	                                                     s_wifi,
	                                                     fixed_freq,
	                                                     &error);
	g_assert_no_error (error);
	g_assert (success);

	s_wsec = nm_connection_get_setting_wireless_security (connection);
	if (s_wsec) {
		NMSettingWirelessSecurityPmf pmf = nm_setting_wireless_security_get_pmf (s_wsec);
		NMSettingWirelessSecurityFils fils = nm_setting_wireless_security_get_fils (s_wsec);
		s_8021x = nm_connection_get_setting_802_1x (connection);
		success = nm_supplicant_config_add_setting_wireless_security (config,
			                                                          s_wsec,
			                                                          s_8021x,
			                                                          nm_connection_get_uuid (connection),
			                                                          mtu,
			                                                          pmf,
			                                                          fils,
			                                                          &error);
	} else {
		success = nm_supplicant_config_add_no_security (config, &error);
	}
	g_assert_no_error (error);
	g_assert (success);

	success = nm_supplicant_config_add_bgscan (config, connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	return nm_supplicant_config_to_variant (config);
}

static NMConnection *
new_basic_connection (const char *id,
                      GBytes *ssid,
                      const char *bssid_str)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wifi;
	NMSettingIPConfig *s_ip4;
	gs_free char *uuid = nm_utils_uuid_generate ();

	connection = nm_simple_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, id,
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRELESS_SETTING_NAME,
	              NULL);

	/* Wifi setting */
	s_wifi = (NMSettingWireless *) nm_setting_wireless_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wifi));
	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_BSSID, bssid_str,
	              NM_SETTING_WIRELESS_MODE, "infrastructure",
	              NM_SETTING_WIRELESS_BAND, "bg",
	              NULL);

	/* IP4 setting */
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));
	g_object_set (s_ip4, NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

	return connection;
}

static void
test_wifi_open (void)
{
	gs_unref_object NMConnection *connection = NULL;
	gs_unref_variant GVariant *config_dict = NULL;
	gboolean success;
	GError *error = NULL;
	const unsigned char ssid_data[] = { 0x54, 0x65, 0x73, 0x74, 0x20, 0x53, 0x53, 0x49, 0x44 };
	gs_unref_bytes GBytes *ssid = g_bytes_new (ssid_data, sizeof (ssid_data));
	const char *bssid_str = "11:22:33:44:55:66";

	connection = new_basic_connection ("Test Wifi Open", ssid, bssid_str);
	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	NMTST_EXPECT_NM_INFO ("Config: added 'ssid' value 'Test SSID'*");
	NMTST_EXPECT_NM_INFO ("Config: added 'scan_ssid' value '1'*");
	NMTST_EXPECT_NM_INFO ("Config: added 'bssid' value '11:22:33:44:55:66'*");
	NMTST_EXPECT_NM_INFO ("Config: added 'freq_list' value *");
	NMTST_EXPECT_NM_INFO ("Config: added 'key_mgmt' value 'NONE'");
	config_dict = build_supplicant_config (connection, 1500, 0, TRUE, TRUE);
	g_test_assert_expected_messages ();
	g_assert (config_dict);

	validate_opt ("wifi-open", config_dict, "scan_ssid", TYPE_INT, GINT_TO_POINTER (1));
	validate_opt ("wifi-open", config_dict, "ssid", TYPE_BYTES, ssid);
	validate_opt ("wifi-open", config_dict, "bssid", TYPE_KEYWORD, bssid_str);
	validate_opt ("wifi-open", config_dict, "key_mgmt", TYPE_KEYWORD, "NONE");
}

static void
test_wifi_wep_key (const char *detail,
                   gboolean test_bssid,
                   NMWepKeyType wep_type,
                   const char *key_data,
                   const unsigned char *expected,
                   size_t expected_size)
{
	gs_unref_object NMConnection *connection = NULL;
	gs_unref_variant GVariant *config_dict = NULL;
	NMSettingWirelessSecurity *s_wsec;
	gboolean success;
	GError *error = NULL;
	const unsigned char ssid_data[] = { 0x54, 0x65, 0x73, 0x74, 0x20, 0x53, 0x53, 0x49, 0x44 };
	gs_unref_bytes GBytes *ssid = g_bytes_new (ssid_data, sizeof (ssid_data));
	const char *bssid_str = "11:22:33:44:55:66";
	gs_unref_bytes GBytes *wep_key_bytes = g_bytes_new (expected, expected_size);
	const char *bgscan_data = "simple:30:-80:86400";
	gs_unref_bytes GBytes *bgscan = g_bytes_new (bgscan_data, strlen (bgscan_data));

	connection = new_basic_connection ("Test Wifi WEP Key", ssid, test_bssid ? bssid_str : NULL);

	/* Wifi Security setting */
	s_wsec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wsec));
	g_object_set (s_wsec,
	              NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "none",
	              NM_SETTING_WIRELESS_SECURITY_WEP_KEY_TYPE, wep_type,
	              NULL);
	nm_setting_wireless_security_set_wep_key (s_wsec, 0, key_data);

	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	NMTST_EXPECT_NM_INFO ("Config: added 'ssid' value 'Test SSID'*");
	NMTST_EXPECT_NM_INFO ("Config: added 'scan_ssid' value '1'*");
	if (test_bssid)
		NMTST_EXPECT_NM_INFO ("Config: added 'bssid' value '11:22:33:44:55:66'*");

	NMTST_EXPECT_NM_INFO ("Config: added 'freq_list' value *");
	NMTST_EXPECT_NM_INFO ("Config: added 'key_mgmt' value 'NONE'");
	NMTST_EXPECT_NM_INFO ("Config: added 'wep_key0' value *");
	NMTST_EXPECT_NM_INFO ("Config: added 'wep_tx_keyidx' value '0'");
	if (!test_bssid)
		NMTST_EXPECT_NM_INFO ("Config: added 'bgscan' value 'simple:30:-80:86400'*");

	config_dict = build_supplicant_config (connection, 1500, 0, TRUE, TRUE);
	g_test_assert_expected_messages ();
	g_assert (config_dict);

	validate_opt (detail, config_dict, "scan_ssid", TYPE_INT, GINT_TO_POINTER (1));
	validate_opt (detail, config_dict, "ssid", TYPE_BYTES, ssid);
	if (test_bssid)
		validate_opt (detail, config_dict, "bssid", TYPE_KEYWORD, bssid_str);
	else
		validate_opt (detail, config_dict, "bgscan", TYPE_BYTES, bgscan);

	validate_opt (detail, config_dict, "key_mgmt", TYPE_KEYWORD, "NONE");
	validate_opt (detail, config_dict, "wep_tx_keyidx", TYPE_INT, GINT_TO_POINTER (0));
	validate_opt (detail, config_dict, "wep_key0", TYPE_BYTES, wep_key_bytes);
}

static void
test_wifi_wep (void)
{
	const char *key1 = "12345";
	const unsigned char key1_expected[] = { 0x31, 0x32, 0x33, 0x34, 0x35 };
	const char *key2 = "ascii test$$$";
	const unsigned char key2_expected[] = { 0x61, 0x73, 0x63, 0x69, 0x69, 0x20, 0x74, 0x65, 0x73, 0x74, 0x24, 0x24, 0x24 };
	const char *key3 = "abcdef1234";
	const unsigned char key3_expected[] = { 0xab, 0xcd, 0xef, 0x12, 0x34 };
	const char *key4 = "96aec785c6392675f87f592972";
	const unsigned char key4_expected[] = { 0x96, 0xae, 0xc7, 0x85, 0xc6, 0x39, 0x26, 0x75, 0xf8, 0x7f, 0x59, 0x29, 0x72 };
	const char *key5 = "r34lly l33t w3p p4ssphr4s3 for t3st1ng";
	const unsigned char key5_expected[] = { 0xce, 0x68, 0x8b, 0x35, 0xf6, 0x0a, 0x2b, 0xbf, 0xc9, 0x8f, 0xed, 0x10, 0xda };

	test_wifi_wep_key ("wifi-wep-ascii-40", TRUE, NM_WEP_KEY_TYPE_KEY, key1, key1_expected, sizeof (key1_expected));
	test_wifi_wep_key ("wifi-wep-ascii-104", TRUE, NM_WEP_KEY_TYPE_KEY, key2, key2_expected, sizeof (key2_expected));
	test_wifi_wep_key ("wifi-wep-hex-40", TRUE, NM_WEP_KEY_TYPE_KEY, key3, key3_expected, sizeof (key3_expected));
	test_wifi_wep_key ("wifi-wep-hex-104", TRUE, NM_WEP_KEY_TYPE_KEY, key4, key4_expected, sizeof (key4_expected));
	test_wifi_wep_key ("wifi-wep-passphrase-104", TRUE, NM_WEP_KEY_TYPE_PASSPHRASE, key5, key5_expected, sizeof (key5_expected));

	test_wifi_wep_key ("wifi-wep-old-hex-104", TRUE, NM_WEP_KEY_TYPE_UNKNOWN, key4, key4_expected, sizeof (key4_expected));

	/* Unlocked BSSID to test bgscan */
	test_wifi_wep_key ("wifi-wep-hex-40", FALSE, NM_WEP_KEY_TYPE_KEY, key3, key3_expected, sizeof (key3_expected));
}

static void
test_wifi_wpa_psk (const char *detail,
                   OptType key_type,
                   const char *key_data,
                   const unsigned char *expected,
                   size_t expected_size,
                   NMSettingWirelessSecurityPmf pmf)
{
	gs_unref_object NMConnection *connection = NULL;
	gs_unref_variant GVariant *config_dict = NULL;
	NMSettingWirelessSecurity *s_wsec;
	gboolean success;
	GError *error = NULL;
	const unsigned char ssid_data[] = { 0x54, 0x65, 0x73, 0x74, 0x20, 0x53, 0x53, 0x49, 0x44 };
	gs_unref_bytes GBytes *ssid = g_bytes_new (ssid_data, sizeof (ssid_data));
	const char *bssid_str = "11:22:33:44:55:66";
	gs_unref_bytes GBytes *wpa_psk_bytes = g_bytes_new (expected, expected_size);

	connection = new_basic_connection ("Test Wifi WPA PSK", ssid, bssid_str);

	/* Wifi Security setting */
	s_wsec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wsec));
	g_object_set (s_wsec,
	              NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "wpa-psk",
	              NM_SETTING_WIRELESS_SECURITY_PSK, key_data,
	              NM_SETTING_WIRELESS_SECURITY_PMF, (int) pmf,
	              NULL);
	nm_setting_wireless_security_add_proto (s_wsec, "wpa");
	nm_setting_wireless_security_add_proto (s_wsec, "rsn");
	nm_setting_wireless_security_add_pairwise (s_wsec, "tkip");
	nm_setting_wireless_security_add_pairwise (s_wsec, "ccmp");
	nm_setting_wireless_security_add_group (s_wsec, "tkip");
	nm_setting_wireless_security_add_group (s_wsec, "ccmp");

	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	NMTST_EXPECT_NM_INFO ("Config: added 'ssid' value 'Test SSID'*");
	NMTST_EXPECT_NM_INFO ("Config: added 'scan_ssid' value '1'*");
	NMTST_EXPECT_NM_INFO ("Config: added 'bssid' value '11:22:33:44:55:66'*");
	NMTST_EXPECT_NM_INFO ("Config: added 'freq_list' value *");
	NMTST_EXPECT_NM_INFO ("Config: added 'key_mgmt' value 'WPA-PSK WPA-PSK-SHA256'");
	NMTST_EXPECT_NM_INFO ("Config: added 'psk' value *");
	NMTST_EXPECT_NM_INFO ("Config: added 'proto' value 'WPA RSN'");
	NMTST_EXPECT_NM_INFO ("Config: added 'pairwise' value 'TKIP CCMP'");
	NMTST_EXPECT_NM_INFO ("Config: added 'group' value 'TKIP CCMP'");
	switch (pmf) {
	case NM_SETTING_WIRELESS_SECURITY_PMF_DISABLE:
		NMTST_EXPECT_NM_INFO ("Config: added 'ieee80211w' value '0'");
		break;
	case NM_SETTING_WIRELESS_SECURITY_PMF_REQUIRED:
		NMTST_EXPECT_NM_INFO ("Config: added 'ieee80211w' value '2'");
		break;
	default:
		break;
	}
	config_dict = build_supplicant_config (connection, 1500, 0, TRUE, TRUE);

	g_test_assert_expected_messages ();
	g_assert (config_dict);

	validate_opt (detail, config_dict, "scan_ssid", TYPE_INT, GINT_TO_POINTER (1));
	validate_opt (detail, config_dict, "ssid", TYPE_BYTES, ssid);
	validate_opt (detail, config_dict, "bssid", TYPE_KEYWORD, bssid_str);
	validate_opt (detail, config_dict, "key_mgmt", TYPE_KEYWORD, "WPA-PSK WPA-PSK-SHA256");
	validate_opt (detail, config_dict, "proto", TYPE_KEYWORD, "WPA RSN");
	validate_opt (detail, config_dict, "pairwise", TYPE_KEYWORD, "TKIP CCMP");
	validate_opt (detail, config_dict, "group", TYPE_KEYWORD, "TKIP CCMP");
	if (key_type == TYPE_BYTES)
		validate_opt (detail, config_dict, "psk", key_type, wpa_psk_bytes);
	else if (key_type == TYPE_STRING)
		validate_opt (detail, config_dict, "psk", key_type, expected);
	else
		g_assert_not_reached ();
}

static void
test_wifi_sae_psk (const char *psk)
{
	gs_unref_object NMConnection *connection = NULL;
	gs_unref_variant GVariant *config_dict = NULL;
	NMSettingWirelessSecurity *s_wsec;
	gboolean success;
	GError *error = NULL;
	const unsigned char ssid_data[] = { 0x54, 0x65, 0x73, 0x74, 0x20, 0x53, 0x53, 0x49, 0x44 };
	gs_unref_bytes GBytes *ssid = g_bytes_new (ssid_data, sizeof (ssid_data));
	const char *bssid_str = "11:22:33:44:55:66";
	int short_psk = strlen (psk) < 8;

	connection = new_basic_connection ("Test Wifi SAE", ssid, bssid_str);

	/* Wifi Security setting */
	s_wsec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wsec));
	g_object_set (s_wsec,
	              NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "sae",
	              NM_SETTING_WIRELESS_SECURITY_PSK, psk,
	              NULL);
	nm_setting_wireless_security_add_proto (s_wsec, "rsn");
	nm_setting_wireless_security_add_pairwise (s_wsec, "tkip");
	nm_setting_wireless_security_add_pairwise (s_wsec, "ccmp");
	nm_setting_wireless_security_add_group (s_wsec, "tkip");
	nm_setting_wireless_security_add_group (s_wsec, "ccmp");

	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	NMTST_EXPECT_NM_INFO ("Config: added 'ssid' value 'Test SSID'*");
	NMTST_EXPECT_NM_INFO ("Config: added 'scan_ssid' value '1'*");
	NMTST_EXPECT_NM_INFO ("Config: added 'bssid' value '11:22:33:44:55:66'*");
	NMTST_EXPECT_NM_INFO ("Config: added 'freq_list' value *");
	NMTST_EXPECT_NM_INFO ("Config: added 'key_mgmt' value 'SAE'");
	if (short_psk)
		NMTST_EXPECT_NM_INFO ("Config: added 'sae_password' value *");
	else
		NMTST_EXPECT_NM_INFO ("Config: added 'psk' value *");
	NMTST_EXPECT_NM_INFO ("Config: added 'proto' value 'RSN'");
	NMTST_EXPECT_NM_INFO ("Config: added 'pairwise' value 'TKIP CCMP'");
	NMTST_EXPECT_NM_INFO ("Config: added 'group' value 'TKIP CCMP'");
	NMTST_EXPECT_NM_INFO ("Config: added 'ieee80211w' value '0'");
	config_dict = build_supplicant_config (connection, 1500, 0, TRUE, TRUE);

	g_test_assert_expected_messages ();
	g_assert (config_dict);

	validate_opt ("wifi-sae", config_dict, "scan_ssid", TYPE_INT, GINT_TO_POINTER (1));
	validate_opt ("wifi-sae", config_dict, "ssid", TYPE_BYTES, ssid);
	validate_opt ("wifi-sae", config_dict, "bssid", TYPE_KEYWORD, bssid_str);
	validate_opt ("wifi-sae", config_dict, "key_mgmt", TYPE_KEYWORD, "SAE");
	validate_opt ("wifi-sae", config_dict, "proto", TYPE_KEYWORD, "RSN");
	validate_opt ("wifi-sae", config_dict, "pairwise", TYPE_KEYWORD, "TKIP CCMP");
	validate_opt ("wifi-sae", config_dict, "group", TYPE_KEYWORD, "TKIP CCMP");
	if (short_psk)
		validate_opt ("wifi-sae", config_dict, "sae_password", TYPE_KEYWORD, psk);
	else
		validate_opt ("wifi-sae", config_dict, "psk", TYPE_KEYWORD, psk);
}

static void
test_wifi_sae (void)
{
	test_wifi_sae_psk ("Moo");
	test_wifi_sae_psk ("Hello World!");
}

static void
test_wifi_wpa_psk_types (void)
{
	const char *key1 = "d4721e911461d3cdef9793858e977fcda091779243abb7316c2f11605a160893";
	const unsigned char key1_expected[] = { 0xd4, 0x72, 0x1e, 0x91, 0x14, 0x61, 0xd3, 0xcd,
	                                        0xef, 0x97, 0x93, 0x85, 0x8e, 0x97, 0x7f, 0xcd,
	                                        0xa0, 0x91, 0x77, 0x92, 0x43, 0xab, 0xb7, 0x31,
	                                        0x6c, 0x2f, 0x11, 0x60, 0x5a, 0x16, 0x08, 0x93 };
	const char *key2 = "r34lly l33t wp4 p4ssphr4s3 for t3st1ng";

	test_wifi_wpa_psk ("wifi-wpa-psk-hex", TYPE_BYTES, key1, key1_expected,
	                   sizeof (key1_expected), NM_SETTING_WIRELESS_SECURITY_PMF_OPTIONAL);
	test_wifi_wpa_psk ("wifi-wep-psk-passphrase", TYPE_STRING, key2,
	                   (gconstpointer) key2, strlen (key2), NM_SETTING_WIRELESS_SECURITY_PMF_REQUIRED);
	test_wifi_wpa_psk ("pmf-disabled", TYPE_STRING, key2,
	                   (gconstpointer) key2, strlen (key2), NM_SETTING_WIRELESS_SECURITY_PMF_DISABLE);
}

static NMConnection *
generate_wifi_eap_connection (const char *id, GBytes *ssid, const char *bssid_str, NMSettingWirelessSecurityFils fils)
{
	NMConnection *connection = NULL;
	NMSettingWirelessSecurity *s_wsec;
	NMSetting8021x *s_8021x;
	gboolean success;
	GError *error = NULL;

	connection = new_basic_connection (id, ssid, bssid_str);

	/* Wifi Security setting */
	s_wsec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wsec));
	g_object_set (s_wsec,
	              NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "wpa-eap",
	              NM_SETTING_WIRELESS_SECURITY_FILS, (int) fils,
	              NULL);
	nm_setting_wireless_security_add_proto (s_wsec, "wpa");
	nm_setting_wireless_security_add_proto (s_wsec, "rsn");
	nm_setting_wireless_security_add_pairwise (s_wsec, "tkip");
	nm_setting_wireless_security_add_pairwise (s_wsec, "ccmp");
	nm_setting_wireless_security_add_group (s_wsec, "tkip");
	nm_setting_wireless_security_add_group (s_wsec, "ccmp");

	/* 802-1X setting */
	s_8021x = (NMSetting8021x *) nm_setting_802_1x_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_8021x));
	nm_setting_802_1x_add_eap_method (s_8021x, "tls");
	nm_setting_802_1x_set_client_cert (s_8021x, TEST_CERT_DIR "/test-cert.p12", NM_SETTING_802_1X_CK_SCHEME_PATH, NULL, NULL);
	g_assert (nm_setting_802_1x_set_ca_cert (s_8021x, TEST_CERT_DIR "/test-ca-cert.pem", NM_SETTING_802_1X_CK_SCHEME_PATH, NULL, NULL));
	nm_setting_802_1x_set_private_key (s_8021x, TEST_CERT_DIR "/test-cert.p12", NULL, NM_SETTING_802_1X_CK_SCHEME_PATH, NULL, NULL);

	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	return connection;
}

static void
test_wifi_eap_locked_bssid (void)
{
	gs_unref_object NMConnection *connection = NULL;
	gs_unref_variant GVariant *config_dict = NULL;
	const unsigned char ssid_data[] = { 0x54, 0x65, 0x73, 0x74, 0x20, 0x53, 0x53, 0x49, 0x44 };
	gs_unref_bytes GBytes *ssid = g_bytes_new (ssid_data, sizeof (ssid_data));
	const char *bssid_str = "11:22:33:44:55:66";
	guint32 mtu = 1100;

	connection = generate_wifi_eap_connection ("Test Wifi EAP-TLS Locked", ssid, bssid_str, NM_SETTING_WIRELESS_SECURITY_FILS_OPTIONAL);

	NMTST_EXPECT_NM_INFO ("Config: added 'ssid' value 'Test SSID'*");
	NMTST_EXPECT_NM_INFO ("Config: added 'scan_ssid' value '1'*");
	NMTST_EXPECT_NM_INFO ("Config: added 'bssid' value '11:22:33:44:55:66'*");
	NMTST_EXPECT_NM_INFO ("Config: added 'freq_list' value *");
	NMTST_EXPECT_NM_INFO ("Config: added 'key_mgmt' value 'WPA-EAP'");
	NMTST_EXPECT_NM_INFO ("Config: added 'proto' value 'WPA RSN'");
	NMTST_EXPECT_NM_INFO ("Config: added 'pairwise' value 'TKIP CCMP'");
	NMTST_EXPECT_NM_INFO ("Config: added 'group' value 'TKIP CCMP'");
	NMTST_EXPECT_NM_INFO ("Config: added 'eap' value 'TLS'");
	NMTST_EXPECT_NM_INFO ("Config: added 'fragment_size' value '1086'");
	NMTST_EXPECT_NM_INFO ("Config: added 'ca_cert' value '*/test-ca-cert.pem'");
	NMTST_EXPECT_NM_INFO ("Config: added 'private_key' value '*/test-cert.p12'");
	NMTST_EXPECT_NM_INFO ("Config: added 'proactive_key_caching' value '1'");
	config_dict = build_supplicant_config (connection, mtu, 0, FALSE, FALSE);
	g_test_assert_expected_messages ();
	g_assert (config_dict);

	validate_opt ("wifi-eap", config_dict, "scan_ssid", TYPE_INT, GINT_TO_POINTER (1));
	validate_opt ("wifi-eap", config_dict, "ssid", TYPE_BYTES, ssid);
	validate_opt ("wifi-eap", config_dict, "bssid", TYPE_KEYWORD, bssid_str);
	validate_opt ("wifi-eap", config_dict, "key_mgmt", TYPE_KEYWORD, "WPA-EAP");
	validate_opt ("wifi-eap", config_dict, "eap", TYPE_KEYWORD, "TLS");
	validate_opt ("wifi-eap", config_dict, "proto", TYPE_KEYWORD, "WPA RSN");
	validate_opt ("wifi-eap", config_dict, "pairwise", TYPE_KEYWORD, "TKIP CCMP");
	validate_opt ("wifi-eap", config_dict, "group", TYPE_KEYWORD, "TKIP CCMP");
	validate_opt ("wifi-eap", config_dict, "fragment_size", TYPE_INT, GINT_TO_POINTER(mtu-14));
}

static void
test_wifi_eap_unlocked_bssid (void)
{
	gs_unref_object NMConnection *connection = NULL;
	gs_unref_variant GVariant *config_dict = NULL;
	const unsigned char ssid_data[] = { 0x54, 0x65, 0x73, 0x74, 0x20, 0x53, 0x53, 0x49, 0x44 };
	gs_unref_bytes GBytes *ssid = g_bytes_new (ssid_data, sizeof (ssid_data));
	const char *bgscan_data = "simple:30:-65:300";
	gs_unref_bytes GBytes *bgscan = g_bytes_new (bgscan_data, strlen (bgscan_data));
	guint32 mtu = 1100;

	connection = generate_wifi_eap_connection ("Test Wifi EAP-TLS Unlocked", ssid, NULL, NM_SETTING_WIRELESS_SECURITY_FILS_REQUIRED);

	NMTST_EXPECT_NM_INFO ("Config: added 'ssid' value 'Test SSID'*");
	NMTST_EXPECT_NM_INFO ("Config: added 'scan_ssid' value '1'*");
	NMTST_EXPECT_NM_INFO ("Config: added 'freq_list' value *");
	NMTST_EXPECT_NM_INFO ("Config: added 'key_mgmt' value 'FILS-SHA256 FILS-SHA384'");
	NMTST_EXPECT_NM_INFO ("Config: added 'proto' value 'WPA RSN'");
	NMTST_EXPECT_NM_INFO ("Config: added 'pairwise' value 'TKIP CCMP'");
	NMTST_EXPECT_NM_INFO ("Config: added 'group' value 'TKIP CCMP'");
	NMTST_EXPECT_NM_INFO ("Config: added 'eap' value 'TLS'");
	NMTST_EXPECT_NM_INFO ("Config: added 'fragment_size' value '1086'");
	NMTST_EXPECT_NM_INFO ("Config: added 'ca_cert' value '*/test-ca-cert.pem'");
	NMTST_EXPECT_NM_INFO ("Config: added 'private_key' value '*/test-cert.p12'");
	NMTST_EXPECT_NM_INFO ("Config: added 'proactive_key_caching' value '1'");
	NMTST_EXPECT_NM_INFO ("Config: added 'bgscan' value 'simple:30:-65:300'");
	config_dict = build_supplicant_config (connection, mtu, 0, FALSE, TRUE);
	g_test_assert_expected_messages ();
	g_assert (config_dict);

	validate_opt ("wifi-eap", config_dict, "scan_ssid", TYPE_INT, GINT_TO_POINTER (1));
	validate_opt ("wifi-eap", config_dict, "ssid", TYPE_BYTES, ssid);
	validate_opt ("wifi-eap", config_dict, "key_mgmt", TYPE_KEYWORD, "FILS-SHA256 FILS-SHA384");
	validate_opt ("wifi-eap", config_dict, "eap", TYPE_KEYWORD, "TLS");
	validate_opt ("wifi-eap", config_dict, "proto", TYPE_KEYWORD, "WPA RSN");
	validate_opt ("wifi-eap", config_dict, "pairwise", TYPE_KEYWORD, "TKIP CCMP");
	validate_opt ("wifi-eap", config_dict, "group", TYPE_KEYWORD, "TKIP CCMP");
	validate_opt ("wifi-eap", config_dict, "fragment_size", TYPE_INT, GINT_TO_POINTER(mtu-14));
	validate_opt ("wifi-eap", config_dict, "bgscan", TYPE_BYTES, bgscan);
}

static void
test_wifi_eap_fils_disabled (void)
{
	gs_unref_object NMConnection *connection = NULL;
	gs_unref_variant GVariant *config_dict = NULL;
	const unsigned char ssid_data[] = { 0x54, 0x65, 0x73, 0x74, 0x20, 0x53, 0x53, 0x49, 0x44 };
	gs_unref_bytes GBytes *ssid = g_bytes_new (ssid_data, sizeof (ssid_data));
	const char *bgscan_data = "simple:30:-65:300";
	gs_unref_bytes GBytes *bgscan = g_bytes_new (bgscan_data, strlen (bgscan_data));
	guint32 mtu = 1100;

	connection = generate_wifi_eap_connection ("Test Wifi FILS disabled", ssid, NULL, NM_SETTING_WIRELESS_SECURITY_FILS_DISABLE);

	NMTST_EXPECT_NM_INFO ("Config: added 'ssid' value 'Test SSID'*");
	NMTST_EXPECT_NM_INFO ("Config: added 'scan_ssid' value '1'*");
	NMTST_EXPECT_NM_INFO ("Config: added 'freq_list' value *");
	NMTST_EXPECT_NM_INFO ("Config: added 'key_mgmt' value 'WPA-EAP WPA-EAP-SHA256'");
	NMTST_EXPECT_NM_INFO ("Config: added 'proto' value 'WPA RSN'");
	NMTST_EXPECT_NM_INFO ("Config: added 'pairwise' value 'TKIP CCMP'");
	NMTST_EXPECT_NM_INFO ("Config: added 'group' value 'TKIP CCMP'");
	NMTST_EXPECT_NM_INFO ("Config: added 'eap' value 'TLS'");
	NMTST_EXPECT_NM_INFO ("Config: added 'fragment_size' value '1086'");
	NMTST_EXPECT_NM_INFO ("Config: added 'ca_cert' value '*/test-ca-cert.pem'");
	NMTST_EXPECT_NM_INFO ("Config: added 'private_key' value '*/test-cert.p12'");
	NMTST_EXPECT_NM_INFO ("Config: added 'proactive_key_caching' value '1'");
	NMTST_EXPECT_NM_INFO ("Config: added 'bgscan' value 'simple:30:-65:300'");
	config_dict = build_supplicant_config (connection, mtu, 0, TRUE, TRUE);
	g_test_assert_expected_messages ();
	g_assert (config_dict);

	validate_opt ("wifi-eap", config_dict, "scan_ssid", TYPE_INT, GINT_TO_POINTER (1));
	validate_opt ("wifi-eap", config_dict, "ssid", TYPE_BYTES, ssid);
	validate_opt ("wifi-eap", config_dict, "key_mgmt", TYPE_KEYWORD, "WPA-EAP WPA-EAP-SHA256");
	validate_opt ("wifi-eap", config_dict, "eap", TYPE_KEYWORD, "TLS");
	validate_opt ("wifi-eap", config_dict, "proto", TYPE_KEYWORD, "WPA RSN");
	validate_opt ("wifi-eap", config_dict, "pairwise", TYPE_KEYWORD, "TKIP CCMP");
	validate_opt ("wifi-eap", config_dict, "group", TYPE_KEYWORD, "TKIP CCMP");
	validate_opt ("wifi-eap", config_dict, "fragment_size", TYPE_INT, GINT_TO_POINTER(mtu-14));
	validate_opt ("wifi-eap", config_dict, "bgscan", TYPE_BYTES, bgscan);
}

NMTST_DEFINE ();

int main (int argc, char **argv)
{
	nmtst_init_assert_logging (&argc, &argv, "INFO", "DEFAULT");

	g_test_add_func ("/supplicant-config/wifi-open", test_wifi_open);
	g_test_add_func ("/supplicant-config/wifi-wep", test_wifi_wep);
	g_test_add_func ("/supplicant-config/wifi-wpa-psk-types", test_wifi_wpa_psk_types);
	g_test_add_func ("/supplicant-config/wifi-eap/locked-bssid", test_wifi_eap_locked_bssid);
	g_test_add_func ("/supplicant-config/wifi-eap/unlocked-bssid", test_wifi_eap_unlocked_bssid);
	g_test_add_func ("/supplicant-config/wifi-eap/fils-disabled", test_wifi_eap_fils_disabled);
	g_test_add_func ("/supplicant-config/wifi-sae", test_wifi_sae);

	return g_test_run ();
}
