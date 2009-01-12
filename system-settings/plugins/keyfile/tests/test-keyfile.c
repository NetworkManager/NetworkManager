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
 * Copyright (C) 2008 Red Hat, Inc.
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
#include <nm-setting-ip4-config.h>

#include "reader.h"
#include "writer.h"

#define TEST_WIRED_FILE TEST_KEYFILES_DIR"/Test_Wired_Connection"

static void
FAIL(const char *test_name, const char *fmt, ...)
{
    va_list args;
    char buf[500];

	snprintf (buf, 500, "FAIL: (%s) %s\n", test_name, fmt);

    va_start (args, fmt);
	vfprintf (stderr, buf, args);
    va_end (args);
	_exit (1);
}

#define ASSERT(x, test_name, fmt, ...) \
	if (!(x)) { \
		FAIL (test_name, fmt, ## __VA_ARGS__); \
	}

static void
test_read_valid_wired_connection (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIP4Config *s_ip4;
	GError *error = NULL;
	const GByteArray *array;
	char expected_mac_address[ETH_ALEN] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
	const char *tmp;
	const char *expected_id = "Test Wired Connection";
	const char *expected_uuid = "4e80a56d-c99f-4aad-a6dd-b449bc398c57";
	const guint64 expected_timestamp = 6654332;
	guint64 timestamp;
	const char *expected_dns1 = "4.2.2.1";
	const char *expected_dns2 = "4.2.2.2";
	struct in_addr addr;
	const char *expected_address1 = "192.168.0.5";
	const char *expected_address2 = "1.2.3.4";
	const char *expected_address1_gw = "192.168.0.1";
	const char *expected_address2_gw = "1.2.1.1";
	NMIP4Address *ip4_addr;

	connection = connection_from_file (TEST_WIRED_FILE, TRUE);
	ASSERT (connection != NULL,
			"connection-read", "failed to read %s", TEST_WIRED_FILE);

	ASSERT (nm_connection_verify (connection, &error),
	        "connection-verify", "failed to verify %s: %s", TEST_WIRED_FILE, error->message);

	/* ===== CONNECTION SETTING ===== */

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	ASSERT (s_con != NULL,
	        "connection-verify-connection", "failed to verify %s: missing %s setting",
	        TEST_WIRED_FILE,
	        NM_SETTING_CONNECTION_SETTING_NAME);

	/* ID */
	tmp = nm_setting_connection_get_id (s_con);
	ASSERT (tmp != NULL,
	        "connection-verify-connection", "failed to verify %s: missing %s / %s key",
	        TEST_WIRED_FILE,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);
	ASSERT (strcmp (tmp, expected_id) == 0,
	        "connection-verify-connection", "failed to verify %s: unexpected %s / %s key value",
	        TEST_WIRED_FILE,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_ID);

	/* UUID */
	tmp = nm_setting_connection_get_uuid (s_con);
	ASSERT (tmp != NULL,
	        "connection-verify-connection", "failed to verify %s: missing %s / %s key",
	        TEST_WIRED_FILE,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_UUID);
	ASSERT (strcmp (tmp, expected_uuid) == 0,
	        "connection-verify-connection", "failed to verify %s: unexpected %s / %s key value",
	        TEST_WIRED_FILE,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_UUID);

	/* Timestamp */
	timestamp = nm_setting_connection_get_timestamp (s_con);
	ASSERT (timestamp == expected_timestamp,
	        "connection-verify-connection", "failed to verify %s: unexpected %s /%s key value",
	        TEST_WIRED_FILE,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_TIMESTAMP);

	/* Autoconnect */
	ASSERT (nm_setting_connection_get_autoconnect (s_con) == TRUE,
	        "connection-verify-connection", "failed to verify %s: unexpected %s /%s key value",
	        TEST_WIRED_FILE,
	        NM_SETTING_CONNECTION_SETTING_NAME,
	        NM_SETTING_CONNECTION_AUTOCONNECT);

	/* ===== WIRED SETTING ===== */

	s_wired = NM_SETTING_WIRED (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRED));
	ASSERT (s_wired != NULL,
	        "connection-verify-wired", "failed to verify %s: missing %s setting",
	        TEST_WIRED_FILE,
	        NM_SETTING_WIRED_SETTING_NAME);

	/* MAC address */
	array = nm_setting_wired_get_mac_address (s_wired);
	ASSERT (array != NULL,
	        "connection-verify-wired", "failed to verify %s: missing %s / %s key",
	        TEST_WIRED_FILE,
	        NM_SETTING_WIRED_SETTING_NAME,
	        NM_SETTING_WIRED_MAC_ADDRESS);
	ASSERT (array->len == ETH_ALEN,
	        "connection-verify-wired", "failed to verify %s: unexpected %s / %s key value length",
	        TEST_WIRED_FILE,
	        NM_SETTING_WIRED_SETTING_NAME,
	        NM_SETTING_WIRED_MAC_ADDRESS);
	ASSERT (memcmp (array->data, &expected_mac_address[0], sizeof (expected_mac_address)) == 0,
	        "connection-verify-wired", "failed to verify %s: unexpected %s / %s key value",
	        TEST_WIRED_FILE,
	        NM_SETTING_WIRED_SETTING_NAME,
	        NM_SETTING_WIRED_MAC_ADDRESS);

	ASSERT (nm_setting_wired_get_mtu (s_wired) == 1400,
	        "connection-verify-wired", "failed to verify %s: unexpected %s / %s key value",
	        TEST_WIRED_FILE,
	        NM_SETTING_WIRED_SETTING_NAME,
	        NM_SETTING_WIRED_MTU);

	/* ===== IPv4 SETTING ===== */

	s_ip4 = NM_SETTING_IP4_CONFIG (nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG));
	ASSERT (s_ip4 != NULL,
	        "connection-verify-ip4", "failed to verify %s: missing %s setting",
	        TEST_WIRED_FILE,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME);

	/* Method */
	tmp = nm_setting_ip4_config_get_method (s_ip4);
	ASSERT (strcmp (tmp, NM_SETTING_IP4_CONFIG_METHOD_MANUAL) == 0,
	        "connection-verify-wired", "failed to verify %s: unexpected %s / %s key value",
	        TEST_WIRED_FILE,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_METHOD);

	/* DNS Addresses */
	ASSERT (nm_setting_ip4_config_get_num_dns (s_ip4) == 2,
	        "connection-verify-wired", "failed to verify %s: unexpected %s / %s key value",
	        TEST_WIRED_FILE,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS);

	ASSERT (inet_pton (AF_INET, expected_dns1, &addr) > 0,
	        "connection-verify-wired", "failed to verify %s: couldn't convert DNS IP address #1",
	        TEST_WIRED_FILE,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS);
	ASSERT (nm_setting_ip4_config_get_dns (s_ip4, 0) == addr.s_addr,
	        "connection-verify-wired", "failed to verify %s: unexpected %s / %s key value #1",
	        TEST_WIRED_FILE,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS);

	ASSERT (inet_pton (AF_INET, expected_dns2, &addr) > 0,
	        "connection-verify-wired", "failed to verify %s: couldn't convert DNS IP address #2",
	        TEST_WIRED_FILE,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS);
	ASSERT (nm_setting_ip4_config_get_dns (s_ip4, 1) == addr.s_addr,
	        "connection-verify-wired", "failed to verify %s: unexpected %s / %s key value #2",
	        TEST_WIRED_FILE,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS);

	ASSERT (nm_setting_ip4_config_get_num_addresses (s_ip4) == 2,
	        "connection-verify-wired", "failed to verify %s: unexpected %s / %s key value",
	        TEST_WIRED_FILE,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS);

	/* Address #1 */
	ip4_addr = nm_setting_ip4_config_get_address (s_ip4, 0);
	ASSERT (ip4_addr,
	        "connection-verify-wired", "failed to verify %s: missing IP4 address #1",
	        TEST_WIRED_FILE,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_ADDRESSES);

	ASSERT (nm_ip4_address_get_prefix (ip4_addr) == 24,
	        "connection-verify-wired", "failed to verify %s: unexpected IP4 address #1 gateway",
	        TEST_WIRED_FILE,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_ADDRESSES);

	ASSERT (inet_pton (AF_INET, expected_address1, &addr) > 0,
	        "connection-verify-wired", "failed to verify %s: couldn't convert IP address #1",
	        TEST_WIRED_FILE,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS);
	ASSERT (nm_ip4_address_get_address (ip4_addr) == addr.s_addr,
	        "connection-verify-wired", "failed to verify %s: unexpected IP4 address #1",
	        TEST_WIRED_FILE,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_ADDRESSES);

	ASSERT (inet_pton (AF_INET, expected_address1_gw, &addr) > 0,
	        "connection-verify-wired", "failed to verify %s: couldn't convert IP address #1 gateway",
	        TEST_WIRED_FILE,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_ADDRESSES);
	ASSERT (nm_ip4_address_get_gateway (ip4_addr) == addr.s_addr,
	        "connection-verify-wired", "failed to verify %s: unexpected IP4 address #1 gateway",
	        TEST_WIRED_FILE,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_ADDRESSES);
	
	/* Address #2 */
	ip4_addr = nm_setting_ip4_config_get_address (s_ip4, 1);
	ASSERT (ip4_addr,
	        "connection-verify-wired", "failed to verify %s: missing IP4 address #2",
	        TEST_WIRED_FILE,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_ADDRESSES);

	ASSERT (nm_ip4_address_get_prefix (ip4_addr) == 16,
	        "connection-verify-wired", "failed to verify %s: unexpected IP4 address #2 gateway",
	        TEST_WIRED_FILE,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_ADDRESSES);

	ASSERT (inet_pton (AF_INET, expected_address2, &addr) > 0,
	        "connection-verify-wired", "failed to verify %s: couldn't convert IP address #2",
	        TEST_WIRED_FILE,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_DNS);
	ASSERT (nm_ip4_address_get_address (ip4_addr) == addr.s_addr,
	        "connection-verify-wired", "failed to verify %s: unexpected IP4 address #2",
	        TEST_WIRED_FILE,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_ADDRESSES);

	ASSERT (inet_pton (AF_INET, expected_address2_gw, &addr) > 0,
	        "connection-verify-wired", "failed to verify %s: couldn't convert IP address #2 gateway",
	        TEST_WIRED_FILE,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_ADDRESSES);
	ASSERT (nm_ip4_address_get_gateway (ip4_addr) == addr.s_addr,
	        "connection-verify-wired", "failed to verify %s: unexpected IP4 address #2 gateway",
	        TEST_WIRED_FILE,
	        NM_SETTING_IP4_CONFIG_SETTING_NAME,
	        NM_SETTING_IP4_CONFIG_ADDRESSES);

	g_object_unref (connection);
}

static void
test_write_wired_connection (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIP4Config *s_ip4;
	char *uuid;
	GByteArray *mac;
	unsigned char tmpmac[] = { 0x99, 0x88, 0x77, 0x66, 0x55, 0x44 };
	gboolean success;
	NMConnection *reread;
	char *testfile = NULL;
	GError *error = NULL;
	pid_t owner_grp;
	uid_t owner_uid;

	connection = nm_connection_new ();
	ASSERT (connection != NULL,
			"connection-write", "failed to allocate new connection");

	s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());
	ASSERT (s_con != NULL,
			"connection-write", "failed to allocate new %s setting",
			NM_SETTING_CONNECTION_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Work Wireless",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, FALSE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
	              NM_SETTING_CONNECTION_TIMESTAMP, 0x12345678L,
	              NULL);
	g_free (uuid);

	s_wired = NM_SETTING_WIRED (nm_setting_wired_new ());
	ASSERT (s_wired != NULL,
			"connection-write", "failed to allocate new %s setting",
			NM_SETTING_WIRED_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_wired));

	mac = g_byte_array_sized_new (ETH_ALEN);
	g_byte_array_append (mac, &tmpmac[0], sizeof (tmpmac));
	g_object_set (s_wired,
	              NM_SETTING_WIRED_MAC_ADDRESS, mac,
	              NM_SETTING_WIRED_MTU, 900,
	              NULL);
	g_byte_array_free (mac, TRUE);

	s_ip4 = NM_SETTING_IP4_CONFIG (nm_setting_ip4_config_new ());
	ASSERT (s_ip4 != NULL,
			"connection-write", "failed to allocate new %s setting",
			NM_SETTING_WIRED_SETTING_NAME);
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	/* Write out the connection */
	owner_uid = geteuid ();
	owner_grp = getegid ();
	success = write_connection (connection, TEST_SCRATCH_DIR, owner_uid, owner_grp, &testfile, &error);
	ASSERT (success == TRUE,
			"connection-write", "failed to allocate write keyfile: %s",
			error ? error->message : "(none)");

	ASSERT (testfile != NULL,
			"connection-write", "didn't get keyfile name back after writing connection");

	/* Read the connection back in and compare it to the one we just wrote out */
	reread = connection_from_file (testfile, TRUE);
	ASSERT (reread != NULL, "connection-write", "failed to re-read test connection");

	ASSERT (nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
			"connection-write", "written and re-read connection weren't the same");

	g_clear_error (&error);
	unlink (testfile);
	g_free (testfile);

	g_object_unref (reread);
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
	test_read_valid_wired_connection ();
	test_write_wired_connection ();

	basename = g_path_get_basename (argv[0]);
	fprintf (stdout, "%s: SUCCESS\n", basename);
	g_free (basename);
	return 0;
}

