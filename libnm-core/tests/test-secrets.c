/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
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
 * Copyright 2008 - 2011 Red Hat, Inc.
 *
 */

#include "nm-default.h"

#include <string.h>

#include "nm-setting-8021x.h"
#include "nm-setting-cdma.h"
#include "nm-setting-connection.h"
#include "nm-setting-gsm.h"
#include "nm-setting-ip4-config.h"
#include "nm-setting-ppp.h"
#include "nm-setting-pppoe.h"
#include "nm-setting-vpn.h"
#include "nm-setting-wired.h"
#include "nm-setting-wireless-security.h"
#include "nm-setting-wireless.h"
#include "nm-simple-connection.h"
#include "nm-utils.h"
#include "nm-core-internal.h"

#include "nm-utils/nm-test-utils.h"

#define TEST_NEED_SECRETS_EAP_TLS_CA_CERT TEST_CERT_DIR "/test_ca_cert.pem"
#define TEST_NEED_SECRETS_EAP_TLS_CLIENT_CERT TEST_CERT_DIR "/test_key_and_cert.pem"
#define TEST_NEED_SECRETS_EAP_TLS_PRIVATE_KEY TEST_CERT_DIR "/test_key_and_cert.pem"

static void
_assert_hints_has (GPtrArray *hints, const char *item)
{
	guint i;
	guint found = 0;

	g_assert (hints);
	g_assert (item);
	for (i = 0; i < hints->len; i++) {
		g_assert (hints->pdata[i]);
		if (strcmp (hints->pdata[i], item) == 0)
			found++;
	}
	g_assert_cmpint (found, ==, 1);
}

static NMConnection *
make_tls_connection (const char *detail, NMSetting8021xCKScheme scheme)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSetting8021x *s_8021x;
	NMSettingWired *s_wired;
	NMSettingIP4Config *s_ip4;
	char *uuid;
	gboolean success;
	GError *error = NULL;

	connection = nm_simple_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Need TLS Secrets",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* Wired setting */
	s_wired = (NMSettingWired *) nm_setting_wired_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wired));

	/* Wireless security setting */
	s_8021x = (NMSetting8021x *) nm_setting_802_1x_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_8021x));

	g_object_set (s_8021x, NM_SETTING_802_1X_IDENTITY, "Bill Smith", NULL);

	nm_setting_802_1x_add_eap_method (s_8021x, "tls");

	success = nm_setting_802_1x_set_ca_cert (s_8021x,
	                                         TEST_NEED_SECRETS_EAP_TLS_CA_CERT,
	                                         scheme,
	                                         NULL,
	                                         &error);
	nmtst_assert_success (success, error);

	success = nm_setting_802_1x_set_client_cert (s_8021x,
	                                             TEST_NEED_SECRETS_EAP_TLS_CLIENT_CERT,
	                                             scheme,
	                                             NULL,
	                                             &error);
	nmtst_assert_success (success, error);

	success = nm_setting_802_1x_set_private_key (s_8021x,
	                                             TEST_NEED_SECRETS_EAP_TLS_PRIVATE_KEY,
	                                             "test",
	                                             scheme,
	                                             NULL,
	                                             &error);
	nmtst_assert_success (success, error);

	success = nm_setting_set_secret_flags (NM_SETTING (s_8021x),
	                                       NM_SETTING_802_1X_PRIVATE_KEY_PASSWORD,
	                                       NM_SETTING_SECRET_FLAG_AGENT_OWNED,
	                                       &error);
	nmtst_assert_success (success, error);

	/* IP4 setting */
	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4, NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

	nmtst_assert_connection_verifies_and_normalizable (connection);

	return connection;
}

static void
test_need_tls_secrets_path (void)
{
	NMConnection *connection;
	const char *setting_name;
	GPtrArray *hints = NULL;

	connection = make_tls_connection ("need-tls-secrets-path-key", NM_SETTING_802_1X_CK_SCHEME_PATH);

	/* Ensure we don't need any secrets since we just set up the connection */
	setting_name = nm_connection_need_secrets (connection, &hints);
	g_assert (!setting_name);
	g_assert (!hints);

	/* Connection is good; clear secrets and ensure private key password is then required */
	nm_connection_clear_secrets (connection);

	hints = NULL;
	setting_name = nm_connection_need_secrets (connection, &hints);
	g_assert_cmpstr (setting_name, ==, NM_SETTING_802_1X_SETTING_NAME);
	_assert_hints_has (hints, NM_SETTING_802_1X_PRIVATE_KEY_PASSWORD);

	g_ptr_array_free (hints, TRUE);
	g_object_unref (connection);
}

static void
test_need_tls_secrets_blob (void)
{
	NMConnection *connection;
	const char *setting_name;
	GPtrArray *hints = NULL;

	connection = make_tls_connection ("need-tls-secrets-blob-key", NM_SETTING_802_1X_CK_SCHEME_BLOB);

	/* Ensure we don't need any secrets since we just set up the connection */
	setting_name = nm_connection_need_secrets (connection, &hints);
	g_assert (!setting_name);
	g_assert (!hints);

	/* Clear secrets and ensure password is again required */
	nm_connection_clear_secrets (connection);

	hints = NULL;
	setting_name = nm_connection_need_secrets (connection, &hints);
	g_assert_cmpstr (setting_name, ==, NM_SETTING_802_1X_SETTING_NAME);
	_assert_hints_has (hints, NM_SETTING_802_1X_PRIVATE_KEY_PASSWORD);

	g_ptr_array_free (hints, TRUE);
	g_object_unref (connection);
}

static NMConnection *
make_tls_phase2_connection (const char *detail, NMSetting8021xCKScheme scheme)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSetting8021x *s_8021x;
	NMSettingWired *s_wired;
	NMSettingIP4Config *s_ip4;
	char *uuid;
	gboolean success;
	GError *error = NULL;

	connection = nm_simple_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Need TLS Secrets",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
	              NULL);
	g_free (uuid);

	/* Wired setting */
	s_wired = (NMSettingWired *) nm_setting_wired_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wired));

	/* Wireless security setting */
	s_8021x = (NMSetting8021x *) nm_setting_802_1x_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_8021x));

	g_object_set (s_8021x, NM_SETTING_802_1X_ANONYMOUS_IDENTITY, "blahblah", NULL);
	g_object_set (s_8021x, NM_SETTING_802_1X_IDENTITY, "Bill Smith", NULL);

	nm_setting_802_1x_add_eap_method (s_8021x, "ttls");
	g_object_set (s_8021x, NM_SETTING_802_1X_PHASE2_AUTH, "tls", NULL);

	success = nm_setting_802_1x_set_phase2_ca_cert (s_8021x,
	                                                TEST_NEED_SECRETS_EAP_TLS_CA_CERT,
	                                                scheme,
	                                                NULL,
	                                                &error);
	nmtst_assert_success (success, error);

	success = nm_setting_802_1x_set_phase2_client_cert (s_8021x,
	                                                    TEST_NEED_SECRETS_EAP_TLS_CLIENT_CERT,
	                                                    scheme,
	                                                    NULL,
	                                                    &error);
	nmtst_assert_success (success, error);

	success = nm_setting_802_1x_set_phase2_private_key (s_8021x,
	                                                    TEST_NEED_SECRETS_EAP_TLS_PRIVATE_KEY,
	                                                    "test",
	                                                    scheme,
	                                                    NULL,
	                                                    &error);
	nmtst_assert_success (success, error);

	success = nm_setting_set_secret_flags (NM_SETTING (s_8021x),
	                                       NM_SETTING_802_1X_PHASE2_PRIVATE_KEY_PASSWORD,
	                                       NM_SETTING_SECRET_FLAG_AGENT_OWNED,
	                                       &error);
	nmtst_assert_success (success, error);


	/* IP4 setting */
	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4, NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

	nmtst_assert_connection_verifies_and_normalizable (connection);
	return connection;
}

static void
test_need_tls_phase2_secrets_path (void)
{
	NMConnection *connection;
	const char *setting_name;
	GPtrArray *hints = NULL;

	connection = make_tls_phase2_connection ("need-tls-phase2-secrets-path-key",
	                                         NM_SETTING_802_1X_CK_SCHEME_PATH);

	/* Ensure we don't need any secrets since we just set up the connection */
	setting_name = nm_connection_need_secrets (connection, &hints);
	g_assert (!setting_name);
	g_assert (!hints);

	/* Connection is good; clear secrets and ensure private key password is then required */
	nm_connection_clear_secrets (connection);

	hints = NULL;
	setting_name = nm_connection_need_secrets (connection, &hints);
	g_assert_cmpstr (setting_name, ==, NM_SETTING_802_1X_SETTING_NAME);
	_assert_hints_has (hints, NM_SETTING_802_1X_PHASE2_PRIVATE_KEY_PASSWORD);

	g_ptr_array_free (hints, TRUE);
	g_object_unref (connection);
}

static void
test_need_tls_phase2_secrets_blob (void)
{
	NMConnection *connection;
	const char *setting_name;
	GPtrArray *hints = NULL;

	connection = make_tls_phase2_connection ("need-tls-phase2-secrets-blob-key",
	                                         NM_SETTING_802_1X_CK_SCHEME_BLOB);

	/* Ensure we don't need any secrets since we just set up the connection */
	setting_name = nm_connection_need_secrets (connection, &hints);
	g_assert (!setting_name);
	g_assert (!hints);

	/* Connection is good; clear secrets and ensure private key password is then required */
	nm_connection_clear_secrets (connection);

	hints = NULL;
	setting_name = nm_connection_need_secrets (connection, &hints);
	g_assert_cmpstr (setting_name, ==, NM_SETTING_802_1X_SETTING_NAME);
	_assert_hints_has (hints, NM_SETTING_802_1X_PHASE2_PRIVATE_KEY_PASSWORD);

	g_ptr_array_free (hints, TRUE);
	g_object_unref (connection);
}

static NMConnection *
wifi_connection_new (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wifi;
	NMSettingWirelessSecurity *s_wsec;
	unsigned char tmpssid[] = { 0x31, 0x33, 0x33, 0x37 };
	char *uuid;
	GBytes *ssid;

	connection = nm_simple_connection_new ();
	g_assert (connection);

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	g_assert (s_con);

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Wireless",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, FALSE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRELESS_SETTING_NAME,
	              NULL);
	g_free (uuid);
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	/* Wireless setting */
	s_wifi = (NMSettingWireless *) nm_setting_wireless_new ();
	g_assert (s_wifi);

	ssid = g_bytes_new (tmpssid, sizeof (tmpssid));
	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NULL);
	g_bytes_unref (ssid);
	nm_connection_add_setting (connection, NM_SETTING (s_wifi));

	/* Wifi security */
	s_wsec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
	g_assert (s_wsec);

	g_object_set (G_OBJECT (s_wsec),
	              NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "none",
	              NULL);
	nm_connection_add_setting (connection, NM_SETTING (s_wsec));

	return connection;
}

static GVariant *
build_wep_secrets (const char *wepkey)
{
	GVariantBuilder builder;

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{sv}"));
	g_variant_builder_add (&builder, "{sv}",
	                       NM_SETTING_WIRELESS_SECURITY_WEP_KEY0,
	                       g_variant_new_string (wepkey));
	g_variant_builder_add (&builder, "{sv}",
	                       NM_SETTING_WIRELESS_SECURITY_WEP_KEY_TYPE,
	                       g_variant_new_uint32 (NM_WEP_KEY_TYPE_KEY));

	return g_variant_builder_end (&builder);
}

static void
test_update_secrets_wifi_single_setting (void)
{
	NMConnection *connection;
	NMSettingWirelessSecurity *s_wsec;
	GVariant *secrets;
	GError *error = NULL;
	gboolean success;
	const char *wepkey = "11111111111111111111111111";
	const char *tmp;

	/* Test update with a hashed setting of 802-11-wireless secrets */

	connection = wifi_connection_new ();

	secrets = build_wep_secrets (wepkey);
	success = nm_connection_update_secrets (connection,
	                                        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	                                        secrets,
	                                        &error);
	g_assert_no_error (error);
	g_assert (success);

	g_variant_unref (secrets);

	/* Make sure the secret is now in the connection */
	s_wsec = nm_connection_get_setting_wireless_security (connection);
	g_assert (s_wsec);
	tmp = nm_setting_wireless_security_get_wep_key (s_wsec, 0);
	g_assert_cmpstr (tmp, ==, wepkey);

	g_object_unref (connection);
}

static void
test_update_secrets_wifi_full_hash (void)
{
	NMConnection *connection;
	NMSettingWirelessSecurity *s_wsec;
	GVariantBuilder builder;
	GVariant *all;
	GError *error = NULL;
	gboolean success;
	const char *wepkey = "11111111111111111111111111";
	const char *tmp;

	/* Test update with a hashed connection containing only 802-11-wireless
	 * setting and secrets.
	 */

	connection = wifi_connection_new ();

	g_variant_builder_init (&builder, NM_VARIANT_TYPE_CONNECTION);
	g_variant_builder_add (&builder, "{s@a{sv}}",
	                       NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	                       build_wep_secrets (wepkey));
	all = g_variant_builder_end (&builder);

	success = nm_connection_update_secrets (connection,
	                                        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	                                        all,
	                                        &error);
	g_assert_no_error (error);
	g_assert (success);

	g_variant_unref (all);

	/* Make sure the secret is now in the connection */
	s_wsec = nm_connection_get_setting_wireless_security (connection);
	g_assert (s_wsec);
	tmp = nm_setting_wireless_security_get_wep_key (s_wsec, 0);
	g_assert_cmpstr (tmp, ==, wepkey);

	g_object_unref (connection);
}

static void
test_update_secrets_wifi_bad_setting_name (void)
{
	NMConnection *connection;
	GVariant *secrets;
	GError *error = NULL;
	gboolean success;
	const char *wepkey = "11111111111111111111111111";

	/* Test that passing an invalid setting name to
	 * nm_connection_update_secrets() fails with the correct error.
	 */

	connection = wifi_connection_new ();

	secrets = build_wep_secrets (wepkey);

	success = nm_connection_update_secrets (connection,
	                                        "asdfasdfasdfasf",
	                                        secrets,
	                                        &error);
	g_assert_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_SETTING_NOT_FOUND);
	g_assert (success == FALSE);

	g_clear_error (&error);
	g_variant_unref (secrets);
	g_object_unref (connection);
}

static void
test_update_secrets_whole_connection (void)
{
	NMConnection *connection;
	NMSettingWirelessSecurity *s_wsec;
	GVariant *secrets;
	GError *error = NULL;
	gboolean success;
	const char *wepkey = "11111111111111111111111111";

	/* Test calling nm_connection_update_secrets() with an entire hashed
	 * connection including non-secrets.
	 */

	connection = wifi_connection_new ();

	/* Build up the secrets dictionary */
	secrets = nm_connection_to_dbus (connection, NM_CONNECTION_SERIALIZE_ALL);
	NMTST_VARIANT_EDITOR (secrets,
	                      NMTST_VARIANT_ADD_PROPERTY (NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	                                                  NM_SETTING_WIRELESS_SECURITY_WEP_KEY0,
	                                                  "s",
	                                                  wepkey);
	                      );

	success = nm_connection_update_secrets (connection, NULL, secrets, &error);
	g_assert_no_error (error);
	g_assert (success == TRUE);

	g_variant_unref (secrets);

	s_wsec = nm_connection_get_setting_wireless_security (connection);
	g_assert (s_wsec);
	g_assert_cmpstr (nm_setting_wireless_security_get_wep_key (s_wsec, 0), ==, wepkey);

	g_object_unref (connection);
}

static void
test_update_secrets_whole_connection_empty_hash (void)
{
	NMConnection *connection;
	GVariant *secrets;
	GError *error = NULL;
	gboolean success;

	/* Test that updating secrets with an empty connection hash returns success */

	connection = wifi_connection_new ();
	secrets = g_variant_new_array (G_VARIANT_TYPE ("{sa{sv}}"), NULL, 0);
	success = nm_connection_update_secrets (connection, NULL, secrets, &error);
	g_assert_no_error (error);
	g_assert (success == TRUE);
	g_variant_unref (secrets);
	g_object_unref (connection);
}

static void
test_update_secrets_whole_connection_bad_setting (void)
{
	NMConnection *connection;
	NMSettingWirelessSecurity *s_wsec;
	GVariant *secrets, *copy, *setting_hash;
	const char *setting_name;
	GVariantBuilder conn_builder;
	GVariantIter conn_iter;
	GError *error = NULL;
	gboolean success;
	const char *wepkey = "11111111111111111111111111";

	/* Test that sending a hashed connection containing an invalid setting
	 * name fails with the right error.
	 */

	connection = wifi_connection_new ();
	s_wsec = nm_connection_get_setting_wireless_security (connection);
	g_assert (s_wsec != NULL);
	g_object_set (G_OBJECT (s_wsec),
	              NM_SETTING_WIRELESS_SECURITY_WEP_KEY0, wepkey,
	              NULL);

	/* Build up the secrets hash */
	secrets = nm_connection_to_dbus (connection, NM_CONNECTION_SERIALIZE_ALL);

	/* Copy the dict, renaming the wireless-security setting in the process
	 * (so we ensure libnm is returning the right error when it finds an entry
	 * in the connection hash that doesn't match any setting in the connection).
	 */
	g_variant_builder_init (&conn_builder, NM_VARIANT_TYPE_CONNECTION);
	g_variant_iter_init (&conn_iter, secrets);
	while (g_variant_iter_next (&conn_iter, "{&s@a{sv}}", &setting_name, &setting_hash)) {
		if (strcmp (setting_name, NM_SETTING_WIRELESS_SECURITY_SETTING_NAME) == 0)
			setting_name = "asdfasdfasdfasdf";

		g_variant_builder_add (&conn_builder, "{s@a{sv}}", setting_name, setting_hash);
		g_variant_unref (setting_hash);
	}
	copy = g_variant_builder_end (&conn_builder);
	g_variant_unref (secrets);

	success = nm_connection_update_secrets (connection, NULL, copy, &error);
	g_assert_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_SETTING_NOT_FOUND);
	g_assert (success == FALSE);

	g_clear_error (&error);
	g_variant_unref (copy);
	g_object_unref (connection);
}

static void
test_update_secrets_whole_connection_empty_base_setting (void)
{
	NMConnection *connection;
	GVariant *secrets, *setting;
	GError *error = NULL;
	gboolean success;

	/* Test that a hashed connection which does not have any hashed secrets
	 * for the requested setting returns success.
	 */

	connection = wifi_connection_new ();
	secrets = nm_connection_to_dbus (connection, NM_CONNECTION_SERIALIZE_ONLY_SECRETS);
	g_assert_cmpint (g_variant_n_children (secrets), ==, 3);

	setting = g_variant_lookup_value (secrets, NM_SETTING_WIRELESS_SETTING_NAME, NULL);
	g_assert (setting != NULL);
	g_variant_unref (setting);

	success = nm_connection_update_secrets (connection,
	                                        NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	                                        secrets,
	                                        &error);
	g_assert_no_error (error);
	g_assert (success);

	g_variant_unref (secrets);
	g_object_unref (connection);
}

static void
test_update_secrets_null_setting_name_with_setting_hash (void)
{
	NMConnection *connection;
	GVariant *secrets;
	GError *error = NULL;
	gboolean success;
	const char *wepkey = "11111111111111111111111111";

	/* Ensure that a NULL setting name and only a hashed setting fails */

	connection = wifi_connection_new ();

	secrets = build_wep_secrets (wepkey);

	g_test_expect_message ("libnm", G_LOG_LEVEL_CRITICAL,
	                       NMTST_G_RETURN_MSG (setting_name != NULL || full_connection));
	success = nm_connection_update_secrets (connection, NULL, secrets, &error);
	g_test_assert_expected_messages ();
	g_assert_no_error (error);
	g_assert (!success);

	g_variant_unref (secrets);
	g_object_unref (connection);
}

NMTST_DEFINE ();

int
main (int argc, char **argv)
{
	nmtst_init (&argc, &argv, TRUE);

	/* The tests */
	g_test_add_func ("/libnm/need_tls_secrets_path", test_need_tls_secrets_path);
	g_test_add_func ("/libnm/need_tls_secrets_blob", test_need_tls_secrets_blob);
	g_test_add_func ("/libnm/need_tls_phase2_secrets_path", test_need_tls_phase2_secrets_path);
	g_test_add_func ("/libnm/need_tls_phase2_secrets_blob", test_need_tls_phase2_secrets_blob);

	g_test_add_func ("/libnm/update_secrets_wifi_single_setting", test_update_secrets_wifi_single_setting);
	g_test_add_func ("/libnm/update_secrets_wifi_full_hash", test_update_secrets_wifi_full_hash);
	g_test_add_func ("/libnm/update_secrets_wifi_bad_setting_name", test_update_secrets_wifi_bad_setting_name);

	g_test_add_func ("/libnm/update_secrets_whole_connection", test_update_secrets_whole_connection);
	g_test_add_func ("/libnm/update_secrets_whole_connection_empty_hash", test_update_secrets_whole_connection_empty_hash);
	g_test_add_func ("/libnm/update_secrets_whole_connection_bad_setting", test_update_secrets_whole_connection_bad_setting);
	g_test_add_func ("/libnm/update_secrets_whole_connection_empty_base_setting", test_update_secrets_whole_connection_empty_base_setting);
	g_test_add_func ("/libnm/update_secrets_null_setting_name_with_setting_hash", test_update_secrets_null_setting_name_with_setting_hash);

	return g_test_run ();
}
