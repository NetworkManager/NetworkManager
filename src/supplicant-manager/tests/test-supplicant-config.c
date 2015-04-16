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

#include "nm-core-internal.h"

#include "nm-supplicant-config.h"
#include "nm-supplicant-settings-verify.h"
#include "nm-default.h"

#include "nm-test-utils.h"

static gboolean
validate_opt (const char *detail,
              GVariant *config,
              const char *key,
              OptType val_type,
              gconstpointer expected,
              size_t expected_len)
{
	char *config_key;
	GVariant *config_value;
	gboolean found = FALSE;
	const guint8 *bytes;
	gsize len;
	const char *s;
	const unsigned char *expected_array = expected;
	GVariantIter iter;

	g_assert (g_variant_is_of_type (config, G_VARIANT_TYPE_VARDICT));

	g_variant_iter_init (&iter, config);
	while (g_variant_iter_next (&iter, "{&sv}", (gpointer) &config_key, (gpointer) &config_value)) {
		if (!strcmp (key, config_key)) {
			found = TRUE;
			switch (val_type) {
			case TYPE_INT:
				g_assert (g_variant_is_of_type (config_value, G_VARIANT_TYPE_INT32));
				g_assert_cmpint (g_variant_get_int32 (config_value), ==, GPOINTER_TO_INT (expected));
				break;
			case TYPE_BYTES:
				g_assert (g_variant_is_of_type (config_value, G_VARIANT_TYPE_BYTESTRING));
				bytes = g_variant_get_fixed_array (config_value, &len, 1);
				g_assert_cmpint (len, ==, expected_len);
				g_assert (memcmp (bytes, expected_array, expected_len) == 0);
				break;
			case TYPE_KEYWORD:
			case TYPE_STRING:
				g_assert (g_variant_is_of_type (config_value, G_VARIANT_TYPE_STRING));
				if (expected_len == -1)
					expected_len = strlen ((const char *) expected);
				s = g_variant_get_string (config_value, NULL);
				g_assert_cmpint (strlen (s), ==, expected_len);
				g_assert_cmpstr (s, ==, expected);
				break;
			default:
				g_assert_not_reached ();
				break;
			}
		}
		g_variant_unref (config_value);
	}

	return found;
}

static void
test_wifi_open (void)
{
	gs_unref_object NMConnection *connection = NULL;
	gs_unref_object NMSupplicantConfig *config = NULL;
	gs_unref_variant GVariant *config_dict = NULL;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wifi;
	NMSettingIPConfig *s_ip4;
	char *uuid;
	gboolean success;
	GError *error = NULL;
	GBytes *ssid;
	const unsigned char ssid_data[] = { 0x54, 0x65, 0x73, 0x74, 0x20, 0x53, 0x53, 0x49, 0x44 };
	const char *bssid_str = "11:22:33:44:55:66";

	connection = nm_simple_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Wifi Open",
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
	              NM_SETTING_WIRELESS_BSSID, bssid_str,
	              NM_SETTING_WIRELESS_MODE, "infrastructure",
	              NM_SETTING_WIRELESS_BAND, "bg",
	              NULL);

	g_bytes_unref (ssid);

	/* IP4 setting */
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4, NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	config = nm_supplicant_config_new ();

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*added 'ssid' value 'Test SSID'*");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*added 'scan_ssid' value '1'*");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*added 'bssid' value '11:22:33:44:55:66'*");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*added 'freq_list' value *");
	g_assert (nm_supplicant_config_add_setting_wireless (config, s_wifi, 0));
	g_test_assert_expected_messages ();

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*added 'key_mgmt' value 'NONE'");
	g_assert (nm_supplicant_config_add_no_security (config));
	g_test_assert_expected_messages ();

	config_dict = nm_supplicant_config_to_variant (config);
	g_assert (config_dict);

	validate_opt ("wifi-open", config_dict, "scan_ssid", TYPE_INT, GINT_TO_POINTER (1), -1);
	validate_opt ("wifi-open", config_dict, "ssid", TYPE_BYTES, ssid_data, sizeof (ssid_data));
	validate_opt ("wifi-open", config_dict, "bssid", TYPE_KEYWORD, bssid_str, -1);
	validate_opt ("wifi-open", config_dict, "key_mgmt", TYPE_KEYWORD, "NONE", -1);
}

static void
test_wifi_wep_key (const char *detail,
                   NMWepKeyType wep_type,
                   const char *key_data,
                   const unsigned char *expected,
                   size_t expected_size)
{
	gs_unref_object NMConnection *connection = NULL;
	gs_unref_object NMSupplicantConfig *config = NULL;
	gs_unref_variant GVariant *config_dict = NULL;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wifi;
	NMSettingWirelessSecurity *s_wsec;
	NMSettingIPConfig *s_ip4;
	char *uuid;
	gboolean success;
	GError *error = NULL;
	GBytes *ssid;
	const unsigned char ssid_data[] = { 0x54, 0x65, 0x73, 0x74, 0x20, 0x53, 0x53, 0x49, 0x44 };
	const char *bssid_str = "11:22:33:44:55:66";

	connection = nm_simple_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Wifi WEP Key",
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
	              NM_SETTING_WIRELESS_BSSID, bssid_str,
	              NM_SETTING_WIRELESS_MODE, "infrastructure",
	              NM_SETTING_WIRELESS_BAND, "bg",
	              NULL);

	g_bytes_unref (ssid);

	/* Wifi Security setting */
	s_wsec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wsec));

	g_object_set (s_wsec,
	              NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "none",
	              NM_SETTING_WIRELESS_SECURITY_WEP_KEY_TYPE, wep_type,
	              NULL);
	nm_setting_wireless_security_set_wep_key (s_wsec, 0, key_data);	

	/* IP4 setting */
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4, NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	config = nm_supplicant_config_new ();

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*added 'ssid' value 'Test SSID'*");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*added 'scan_ssid' value '1'*");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*added 'bssid' value '11:22:33:44:55:66'*");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*added 'freq_list' value *");
	g_assert (nm_supplicant_config_add_setting_wireless (config, s_wifi, 0));
	g_test_assert_expected_messages ();

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*added 'key_mgmt' value 'NONE'");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*added 'wep_key0' value *");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*added 'wep_tx_keyidx' value '0'");
	g_assert (nm_supplicant_config_add_setting_wireless_security (config,
	                                                              s_wsec,
	                                                              NULL,
	                                                              "376aced7-b28c-46be-9a62-fcdf072571da"));
	g_test_assert_expected_messages ();

	config_dict = nm_supplicant_config_to_variant (config);
	g_assert (config_dict);

	validate_opt (detail, config_dict, "scan_ssid", TYPE_INT, GINT_TO_POINTER (1), -1);
	validate_opt (detail, config_dict, "ssid", TYPE_BYTES, ssid_data, sizeof (ssid_data));
	validate_opt (detail, config_dict, "bssid", TYPE_KEYWORD, bssid_str, -1);
	validate_opt (detail, config_dict, "key_mgmt", TYPE_KEYWORD, "NONE", -1);
	validate_opt (detail, config_dict, "wep_tx_keyidx", TYPE_INT, GINT_TO_POINTER (0), -1);
	validate_opt (detail, config_dict, "wep_key0", TYPE_BYTES, expected, expected_size);
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

	test_wifi_wep_key ("wifi-wep-ascii-40", NM_WEP_KEY_TYPE_KEY, key1, key1_expected, sizeof (key1_expected));
	test_wifi_wep_key ("wifi-wep-ascii-104", NM_WEP_KEY_TYPE_KEY, key2, key2_expected, sizeof (key2_expected));
	test_wifi_wep_key ("wifi-wep-hex-40", NM_WEP_KEY_TYPE_KEY, key3, key3_expected, sizeof (key3_expected));
	test_wifi_wep_key ("wifi-wep-hex-104", NM_WEP_KEY_TYPE_KEY, key4, key4_expected, sizeof (key4_expected));
	test_wifi_wep_key ("wifi-wep-passphrase-104", NM_WEP_KEY_TYPE_PASSPHRASE, key5, key5_expected, sizeof (key5_expected));

	test_wifi_wep_key ("wifi-wep-old-hex-104", NM_WEP_KEY_TYPE_UNKNOWN, key4, key4_expected, sizeof (key4_expected));
}

static void
test_wifi_wpa_psk (const char *detail,
                   OptType key_type,
                   const char *key_data,
                   const unsigned char *expected,
                   size_t expected_size)
{
	gs_unref_object NMConnection *connection = NULL;
	gs_unref_object NMSupplicantConfig *config = NULL;
	gs_unref_variant GVariant *config_dict = NULL;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wifi;
	NMSettingWirelessSecurity *s_wsec;
	NMSettingIPConfig *s_ip4;
	char *uuid;
	gboolean success;
	GError *error = NULL;
	GBytes *ssid;
	const unsigned char ssid_data[] = { 0x54, 0x65, 0x73, 0x74, 0x20, 0x53, 0x53, 0x49, 0x44 };
	const char *bssid_str = "11:22:33:44:55:66";

	connection = nm_simple_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Wifi WEP Key",
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
	              NM_SETTING_WIRELESS_BSSID, bssid_str,
	              NM_SETTING_WIRELESS_MODE, "infrastructure",
	              NM_SETTING_WIRELESS_BAND, "bg",
	              NULL);

	g_bytes_unref (ssid);

	/* Wifi Security setting */
	s_wsec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wsec));

	g_object_set (s_wsec,
	              NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "wpa-psk",
	              NM_SETTING_WIRELESS_SECURITY_PSK, key_data,
	              NULL);

	nm_setting_wireless_security_add_proto (s_wsec, "wpa");
	nm_setting_wireless_security_add_proto (s_wsec, "rsn");
	nm_setting_wireless_security_add_pairwise (s_wsec, "tkip");
	nm_setting_wireless_security_add_pairwise (s_wsec, "ccmp");
	nm_setting_wireless_security_add_group (s_wsec, "tkip");
	nm_setting_wireless_security_add_group (s_wsec, "ccmp");

	/* IP4 setting */
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4, NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);

	config = nm_supplicant_config_new ();

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*added 'ssid' value 'Test SSID'*");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*added 'scan_ssid' value '1'*");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*added 'bssid' value '11:22:33:44:55:66'*");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*added 'freq_list' value *");
	g_assert (nm_supplicant_config_add_setting_wireless (config, s_wifi, 0));
	g_test_assert_expected_messages ();

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*added 'key_mgmt' value 'WPA-PSK'");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*added 'psk' value *");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*added 'proto' value 'WPA RSN'");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*added 'pairwise' value 'TKIP CCMP'");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE,
	                       "*added 'group' value 'TKIP CCMP'");
	g_assert (nm_supplicant_config_add_setting_wireless_security (config,
	                                                              s_wsec,
	                                                              NULL,
	                                                              "376aced7-b28c-46be-9a62-fcdf072571da"));
	g_test_assert_expected_messages ();

	config_dict = nm_supplicant_config_to_variant (config);
	g_assert (config_dict);

	validate_opt (detail, config_dict, "scan_ssid", TYPE_INT, GINT_TO_POINTER (1), -1);
	validate_opt (detail, config_dict, "ssid", TYPE_BYTES, ssid_data, sizeof (ssid_data));
	validate_opt (detail, config_dict, "bssid", TYPE_KEYWORD, bssid_str, -1);
	validate_opt (detail, config_dict, "key_mgmt", TYPE_KEYWORD, "WPA-PSK", -1);
	validate_opt (detail, config_dict, "proto", TYPE_KEYWORD, "WPA RSN", -1);
	validate_opt (detail, config_dict, "pairwise", TYPE_KEYWORD, "TKIP CCMP", -1);
	validate_opt (detail, config_dict, "group", TYPE_KEYWORD, "TKIP CCMP", -1);
	validate_opt (detail, config_dict, "psk", key_type, expected, expected_size);
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

	test_wifi_wpa_psk ("wifi-wpa-psk-hex", TYPE_BYTES, key1, key1_expected, sizeof (key1_expected));
	test_wifi_wpa_psk ("wifi-wep-psk-passphrase", TYPE_STRING, key2, (gconstpointer) key2, strlen (key2));
}

NMTST_DEFINE ();

int main (int argc, char **argv)
{
	nmtst_init_assert_logging (&argc, &argv, "INFO", "DEFAULT");

	g_test_add_func ("/supplicant-config/wifi-open", test_wifi_open);
	g_test_add_func ("/supplicant-config/wifi-wep", test_wifi_wep);
	g_test_add_func ("/supplicant-config/wifi-wpa-psk-types", test_wifi_wpa_psk_types);

	return g_test_run ();
}

