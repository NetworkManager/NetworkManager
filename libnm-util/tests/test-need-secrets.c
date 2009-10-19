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
 * Copyright (C) 2008 - 2009 Red Hat, Inc.
 *
 */

#include <glib.h>
#include <dbus/dbus-glib.h>
#include <string.h>

#include "nm-test-helpers.h"
#include <nm-utils.h>

#include "nm-setting-connection.h"
#include "nm-setting-wired.h"
#include "nm-setting-8021x.h"
#include "nm-setting-ip4-config.h"
#include "nm-setting-wireless-security.h"
#include "nm-setting-cdma.h"
#include "nm-setting-gsm.h"
#include "nm-setting-ppp.h"
#include "nm-setting-pppoe.h"
#include "nm-setting-vpn.h"


#define TEST_NEED_SECRETS_EAP_TLS_CA_CERT TEST_CERT_DIR "/test_ca_cert.pem"
#define TEST_NEED_SECRETS_EAP_TLS_CLIENT_CERT TEST_CERT_DIR "/test_key_and_cert.pem"
#define TEST_NEED_SECRETS_EAP_TLS_PRIVATE_KEY TEST_CERT_DIR "/test_key_and_cert.pem"

static gboolean
find_hints_item (GPtrArray *hints, const char *item)
{
	int i;

	for (i = 0; i < hints->len; i++) {
		if (!strcmp (item, (const char *) g_ptr_array_index (hints, i)))
			return TRUE;
	}
	return FALSE;
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

	connection = nm_connection_new ();
	ASSERT (connection != NULL,
	        detail, "failed to allocate new connection");

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	ASSERT (s_con != NULL,
	        detail, "failed to allocate new %s setting",
	        NM_SETTING_CONNECTION_SETTING_NAME);
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
	ASSERT (s_wired != NULL,
	        detail, "failed to allocate new %s setting",
	        NM_SETTING_WIRED_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_wired));

	/* Wireless security setting */
	s_8021x = (NMSetting8021x *) nm_setting_802_1x_new ();
	ASSERT (s_8021x != NULL,
	        detail, "failed to allocate new %s setting",
	        NM_SETTING_802_1X_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_8021x));

	g_object_set (s_8021x, NM_SETTING_802_1X_IDENTITY, "Bill Smith", NULL);

	nm_setting_802_1x_add_eap_method (s_8021x, "tls");

	success = nm_setting_802_1x_set_ca_cert (s_8021x,
	                                         TEST_NEED_SECRETS_EAP_TLS_CA_CERT,
	                                         scheme,
	                                         NULL,
	                                         &error);
	ASSERT (success == TRUE,
	        detail, "failed to set CA certificate '%s': %s",
	        TEST_NEED_SECRETS_EAP_TLS_CA_CERT, error->message);

	success = nm_setting_802_1x_set_client_cert (s_8021x,
	                                             TEST_NEED_SECRETS_EAP_TLS_CLIENT_CERT,
	                                             scheme,
	                                             NULL,
	                                             &error);
	ASSERT (success == TRUE,
	        detail, "failed to set client certificate '%s': %s",
	        TEST_NEED_SECRETS_EAP_TLS_CLIENT_CERT, error->message);

	success = nm_setting_802_1x_set_private_key (s_8021x,
	                                             TEST_NEED_SECRETS_EAP_TLS_PRIVATE_KEY,
	                                             "test",
	                                             scheme,
	                                             NULL,
	                                             &error);
	ASSERT (success == TRUE,
	        detail, "failed to set private key '%s': %s",
	        TEST_NEED_SECRETS_EAP_TLS_PRIVATE_KEY, error->message);

	/* IP4 setting */
	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	ASSERT (s_ip4 != NULL,
			detail, "failed to allocate new %s setting",
			NM_SETTING_IP4_CONFIG_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4, NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

	ASSERT (nm_connection_verify (connection, &error) == TRUE,
	        detail, "failed to verify connection: %s",
	        (error && error->message) ? error->message : "(unknown)");

	return connection;
}

static void
test_need_tls_secrets_path (void)
{
	NMConnection *connection;
	const char *setting_name;
	GPtrArray *hints = NULL;
	NMSetting8021x *s_8021x;

	connection = make_tls_connection ("need-tls-secrets-path-key", NM_SETTING_802_1X_CK_SCHEME_PATH);
	ASSERT (connection != NULL,
	        "need-tls-secrets-path-key",
	        "error creating test connection");

	/* Ensure we don't need any secrets since we just set up the connection */
	setting_name = nm_connection_need_secrets (connection, &hints);
	ASSERT (setting_name == NULL,
	        "need-tls-secrets-path-key",
	        "secrets are unexpectedly required");
	ASSERT (hints == NULL,
	        "need-tls-secrets-path-key",
	        "hints should be NULL since no secrets were required");

	/* Connection is good; clear secrets and ensure private key is then required */
	nm_connection_clear_secrets (connection);

	hints = NULL;
	setting_name = nm_connection_need_secrets (connection, &hints);
	ASSERT (setting_name != NULL,
	        "need-tls-secrets-path-key",
	        "unexpected secrets success");
	ASSERT (strcmp (setting_name, NM_SETTING_802_1X_SETTING_NAME) == 0,
			"need-tls-secrets-path-key",
			"unexpected setting secrets required");

	ASSERT (hints != NULL,
	        "need-tls-secrets-path-key",
	        "expected returned secrets hints");
	ASSERT (find_hints_item (hints, NM_SETTING_802_1X_PRIVATE_KEY),
			"need-tls-secrets-path-key",
			"expected to require private key, but it wasn't");

	g_object_unref (connection);

	/*** Just clear the private key this time ***/

	connection = make_tls_connection ("need-tls-secrets-path-key-password", NM_SETTING_802_1X_CK_SCHEME_PATH);
	ASSERT (connection != NULL,
	        "need-tls-secrets-path-key-password",
	        "error creating test connection");

	s_8021x = (NMSetting8021x *) nm_connection_get_setting (connection, NM_TYPE_SETTING_802_1X);
	ASSERT (s_8021x != NULL,
	        "need-tls-secrets-path-key-password",
	        "error getting test 802.1x setting");

	g_object_set (G_OBJECT (s_8021x), NM_SETTING_802_1X_PRIVATE_KEY_PASSWORD, NULL, NULL);

	hints = NULL;
	setting_name = nm_connection_need_secrets (connection, &hints);
	ASSERT (setting_name != NULL,
	        "need-tls-secrets-path-key-password",
	        "unexpected secrets success");
	ASSERT (strcmp (setting_name, NM_SETTING_802_1X_SETTING_NAME) == 0,
			"need-tls-secrets-path-key-password",
			"unexpected setting secrets required");

	ASSERT (hints != NULL,
	        "need-tls-secrets-path-key-password",
	        "expected returned secrets hints");
	ASSERT (find_hints_item (hints, NM_SETTING_802_1X_PRIVATE_KEY_PASSWORD),
			"need-tls-secrets-path-key-password",
			"expected to require private key password, but it wasn't");

	g_object_unref (connection);
}

static void
test_need_tls_secrets_blob (void)
{
	NMConnection *connection;
	const char *setting_name;
	GPtrArray *hints = NULL;
	NMSetting8021x *s_8021x;

	connection = make_tls_connection ("need-tls-secrets-blob-key", NM_SETTING_802_1X_CK_SCHEME_BLOB);
	ASSERT (connection != NULL,
	        "need-tls-secrets-blob-key",
	        "error creating test connection");

	/* Ensure we don't need any secrets since we just set up the connection */
	setting_name = nm_connection_need_secrets (connection, &hints);
	ASSERT (setting_name == NULL,
	        "need-tls-secrets-blob-key",
	        "secrets are unexpectedly required");
	ASSERT (hints == NULL,
	        "need-tls-secrets-blob-key",
	        "hints should be NULL since no secrets were required");

	/* Connection is good; clear secrets and ensure private key is then required */
	nm_connection_clear_secrets (connection);

	hints = NULL;
	setting_name = nm_connection_need_secrets (connection, &hints);
	ASSERT (setting_name != NULL,
	        "need-tls-secrets-blob-key",
	        "unexpected secrets success");
	ASSERT (strcmp (setting_name, NM_SETTING_802_1X_SETTING_NAME) == 0,
			"need-tls-secrets-blob-key",
			"unexpected setting secrets required");

	ASSERT (hints != NULL,
	        "need-tls-secrets-blob-key",
	        "expected returned secrets hints");
	ASSERT (find_hints_item (hints, NM_SETTING_802_1X_PRIVATE_KEY),
			"need-tls-secrets-blob-key",
			"expected to require private key, but it wasn't");

	g_object_unref (connection);

	/*** Just clear the private key this time ***/

	connection = make_tls_connection ("need-tls-secrets-blob-key-password", NM_SETTING_802_1X_CK_SCHEME_BLOB);
	ASSERT (connection != NULL,
	        "need-tls-secrets-blob-key-password",
	        "error creating test connection");

	s_8021x = (NMSetting8021x *) nm_connection_get_setting (connection, NM_TYPE_SETTING_802_1X);
	ASSERT (s_8021x != NULL,
	        "need-tls-secrets-blob-key-password",
	        "error getting test 802.1x setting");

	g_object_set (G_OBJECT (s_8021x), NM_SETTING_802_1X_PRIVATE_KEY_PASSWORD, NULL, NULL);

	/* Blobs are already decrypted and don't need a password */
	hints = NULL;
	setting_name = nm_connection_need_secrets (connection, &hints);
	ASSERT (setting_name == NULL,
	        "need-tls-secrets-blob-key-password",
	        "unexpected secrets failure");
	ASSERT (hints == NULL,
	        "need-tls-secrets-blob-key-password",
	        "hints should be NULL since no secrets were required");

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

	connection = nm_connection_new ();
	ASSERT (connection != NULL,
	        detail, "failed to allocate new connection");

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	ASSERT (s_con != NULL,
	        detail, "failed to allocate new %s setting",
	        NM_SETTING_CONNECTION_SETTING_NAME);
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
	ASSERT (s_wired != NULL,
	        detail, "failed to allocate new %s setting",
	        NM_SETTING_WIRED_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_wired));

	/* Wireless security setting */
	s_8021x = (NMSetting8021x *) nm_setting_802_1x_new ();
	ASSERT (s_8021x != NULL,
	        detail, "failed to allocate new %s setting",
	        NM_SETTING_802_1X_SETTING_NAME);
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
	ASSERT (success == TRUE,
	        detail, "failed to set phase2 CA certificate '%s': %s",
	        TEST_NEED_SECRETS_EAP_TLS_CA_CERT, error->message);

	success = nm_setting_802_1x_set_phase2_client_cert (s_8021x,
	                                                    TEST_NEED_SECRETS_EAP_TLS_CLIENT_CERT,
	                                                    scheme,
	                                                    NULL,
	                                                    &error);
	ASSERT (success == TRUE,
	        detail, "failed to set phase2 client certificate '%s': %s",
	        TEST_NEED_SECRETS_EAP_TLS_CLIENT_CERT, error->message);

	success = nm_setting_802_1x_set_phase2_private_key (s_8021x,
	                                                    TEST_NEED_SECRETS_EAP_TLS_PRIVATE_KEY,
	                                                    "test",
	                                                    scheme,
	                                                    NULL,
	                                                    &error);
	ASSERT (success == TRUE,
	        detail, "failed to set phase2 private key '%s': %s",
	        TEST_NEED_SECRETS_EAP_TLS_PRIVATE_KEY, error->message);

	/* IP4 setting */
	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	ASSERT (s_ip4 != NULL,
			detail, "failed to allocate new %s setting",
			NM_SETTING_IP4_CONFIG_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4, NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

	ASSERT (nm_connection_verify (connection, &error) == TRUE,
	        detail, "failed to verify connection: %s",
	        (error && error->message) ? error->message : "(unknown)");

	return connection;
}

static void
test_need_tls_phase2_secrets_path (void)
{
	NMConnection *connection;
	const char *setting_name;
	GPtrArray *hints = NULL;
	NMSetting8021x *s_8021x;

	connection = make_tls_phase2_connection ("need-tls-phase2-secrets-path-key",
	                                         NM_SETTING_802_1X_CK_SCHEME_PATH);
	ASSERT (connection != NULL,
	        "need-tls-phase2-secrets-path-key",
	        "error creating test connection");

	/* Ensure we don't need any secrets since we just set up the connection */
	setting_name = nm_connection_need_secrets (connection, &hints);
	ASSERT (setting_name == NULL,
	        "need-tls-phase2-secrets-path-key",
	        "secrets are unexpectedly required");
	ASSERT (hints == NULL,
	        "need-tls-phase2-secrets-path-key",
	        "hints should be NULL since no secrets were required");

	/* Connection is good; clear secrets and ensure private key is then required */
	nm_connection_clear_secrets (connection);

	hints = NULL;
	setting_name = nm_connection_need_secrets (connection, &hints);
	ASSERT (setting_name != NULL,
	        "need-tls-phase2-secrets-path-key",
	        "unexpected secrets success");
	ASSERT (strcmp (setting_name, NM_SETTING_802_1X_SETTING_NAME) == 0,
			"need-tls-phase2-secrets-path-key",
			"unexpected setting secrets required");

	ASSERT (hints != NULL,
	        "need-tls-phase2-secrets-path-key",
	        "expected returned secrets hints");
	ASSERT (find_hints_item (hints, NM_SETTING_802_1X_PHASE2_PRIVATE_KEY),
			"need-tls-phase2-secrets-path-key",
			"expected to require private key, but it wasn't");

	g_object_unref (connection);

	/*** Just clear the private key this time ***/

	connection = make_tls_phase2_connection ("need-tls-phase2-secrets-path-key-password",
	                                         NM_SETTING_802_1X_CK_SCHEME_PATH);
	ASSERT (connection != NULL,
	        "need-tls-phase2-secrets-path-key-password",
	        "error creating test connection");

	s_8021x = (NMSetting8021x *) nm_connection_get_setting (connection, NM_TYPE_SETTING_802_1X);
	ASSERT (s_8021x != NULL,
	        "need-tls-phase2-secrets-path-key-password",
	        "error getting test 802.1x setting");

	g_object_set (G_OBJECT (s_8021x), NM_SETTING_802_1X_PHASE2_PRIVATE_KEY_PASSWORD, NULL, NULL);

	hints = NULL;
	setting_name = nm_connection_need_secrets (connection, &hints);
	ASSERT (setting_name != NULL,
	        "need-tls-phase2-secrets-path-key-password",
	        "unexpected secrets success");
	ASSERT (strcmp (setting_name, NM_SETTING_802_1X_SETTING_NAME) == 0,
			"need-tls-phase2-secrets-path-key-password",
			"unexpected setting secrets required");

	ASSERT (hints != NULL,
	        "need-tls-phase2-secrets-path-key-password",
	        "expected returned secrets hints");
	ASSERT (find_hints_item (hints, NM_SETTING_802_1X_PHASE2_PRIVATE_KEY_PASSWORD),
			"need-tls-phase2-secrets-path-key-password",
			"expected to require private key password, but it wasn't");

	g_object_unref (connection);
}

static void
test_need_tls_phase2_secrets_blob (void)
{
	NMConnection *connection;
	const char *setting_name;
	GPtrArray *hints = NULL;
	NMSetting8021x *s_8021x;

	connection = make_tls_phase2_connection ("need-tls-phase2-secrets-blob-key",
	                                         NM_SETTING_802_1X_CK_SCHEME_BLOB);
	ASSERT (connection != NULL,
	        "need-tls-phase2-secrets-blob-key",
	        "error creating test connection");

	/* Ensure we don't need any secrets since we just set up the connection */
	setting_name = nm_connection_need_secrets (connection, &hints);
	ASSERT (setting_name == NULL,
	        "need-tls-phase2-secrets-blob-key",
	        "secrets are unexpectedly required");
	ASSERT (hints == NULL,
	        "need-tls-phase2-secrets-blob-key",
	        "hints should be NULL since no secrets were required");

	/* Connection is good; clear secrets and ensure private key is then required */
	nm_connection_clear_secrets (connection);

	hints = NULL;
	setting_name = nm_connection_need_secrets (connection, &hints);
	ASSERT (setting_name != NULL,
	        "need-tls-phase2-secrets-blob-key",
	        "unexpected secrets success");
	ASSERT (strcmp (setting_name, NM_SETTING_802_1X_SETTING_NAME) == 0,
			"need-tls-phase2-secrets-blob-key",
			"unexpected setting secrets required");

	ASSERT (hints != NULL,
	        "need-tls-phase2-secrets-blob-key",
	        "expected returned secrets hints");
	ASSERT (find_hints_item (hints, NM_SETTING_802_1X_PHASE2_PRIVATE_KEY),
			"need-tls-phase2-secrets-blob-key",
			"expected to require private key, but it wasn't");

	g_object_unref (connection);

	/*** Just clear the private key this time ***/

	connection = make_tls_phase2_connection ("need-tls-phase2-secrets-blob-key-password",
	                                         NM_SETTING_802_1X_CK_SCHEME_BLOB);
	ASSERT (connection != NULL,
	        "need-tls-phase2-secrets-blob-key-password",
	        "error creating test connection");

	s_8021x = (NMSetting8021x *) nm_connection_get_setting (connection, NM_TYPE_SETTING_802_1X);
	ASSERT (s_8021x != NULL,
	        "need-tls-phase2-secrets-blob-key-password",
	        "error getting test 802.1x setting");

	g_object_set (G_OBJECT (s_8021x), NM_SETTING_802_1X_PHASE2_PRIVATE_KEY_PASSWORD, NULL, NULL);

	/* Blobs are already decrypted and don't need a password */
	hints = NULL;
	setting_name = nm_connection_need_secrets (connection, &hints);
	ASSERT (setting_name == NULL,
	        "need-tls-phase2-secrets-blob-key-password",
	        "unexpected secrets failure");
	ASSERT (hints == NULL,
	        "need-tls-phase2-secrets-blob-key-password",
	        "hints should be NULL since no secrets were required");

	g_object_unref (connection);
}

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
	test_need_tls_secrets_path ();
	test_need_tls_secrets_blob ();
	test_need_tls_phase2_secrets_path ();
	test_need_tls_phase2_secrets_blob ();

	base = g_path_get_basename (argv[0]);
	fprintf (stdout, "%s: SUCCESS\n", base);
	g_free (base);
	return 0;
}

