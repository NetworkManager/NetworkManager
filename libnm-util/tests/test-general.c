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

#include "config.h"

#include <glib.h>
#include <dbus/dbus-glib.h>
#include <string.h>
#include <netinet/ether.h>
#include <linux/if_infiniband.h>
#include <sys/wait.h>
#include <sys/resource.h>

#include <nm-utils.h>
#include "gsystem-local-alloc.h"

#include "nm-setting-private.h"
#include "nm-setting-connection.h"
#include "nm-setting-vpn.h"
#include "nm-setting-gsm.h"
#include "nm-setting-cdma.h"
#include "nm-setting-wired.h"
#include "nm-setting-wireless-security.h"
#include "nm-setting-ip6-config.h"
#include "nm-setting-ip4-config.h"
#include "nm-setting-pppoe.h"
#include "nm-setting-serial.h"
#include "nm-setting-vlan.h"
#include "nm-setting-bond.h"
#include "nm-utils.h"
#include "nm-dbus-glib-types.h"

#include "nm-test-utils.h"

static void
vpn_check_func (const char *key, const char *value, gpointer user_data)
{
	const char *test = user_data;

	if (!strcmp (key, "foobar1")) {
		ASSERT (strcmp (value, "blahblah1") == 0,
				test, "unexpected vpn item '%s' / '%s'", key, value);
		return;
	}

	if (!strcmp (key, "foobar2")) {
		ASSERT (strcmp (value, "blahblah2") == 0,
				test, "unexpected vpn item '%s' / '%s'", key, value);
		return;
	}

	if (!strcmp (key, "foobar3")) {
		ASSERT (strcmp (value, "blahblah3") == 0,
				test, "unexpected vpn item '%s' / '%s'", key, value);
		return;
	}

	if (!strcmp (key, "foobar4")) {
		ASSERT (strcmp (value, "blahblah4") == 0,
				test, "unexpected vpn item '%s' / '%s'", key, value);
		return;
	}

	ASSERT (FALSE, test, "unexpected vpn item '%s'", key);
}

static void
vpn_check_empty_func (const char *key, const char *value, gpointer user_data)
{
	const char *test = user_data;

	/* We don't expect any values */
	ASSERT (FALSE, test, "unexpected vpn item '%s'", key);
}

static void
test_setting_vpn_items (void)
{
	NMSettingVPN *s_vpn;

	s_vpn = (NMSettingVPN *) nm_setting_vpn_new ();
	ASSERT (s_vpn != NULL,
	        "vpn-items",
	        "error creating vpn setting");

	nm_setting_vpn_add_data_item (s_vpn, "foobar1", "blahblah1");
	nm_setting_vpn_add_data_item (s_vpn, "foobar2", "blahblah2");
	nm_setting_vpn_add_data_item (s_vpn, "foobar3", "blahblah3");
	nm_setting_vpn_add_data_item (s_vpn, "foobar4", "blahblah4");

	/* Ensure that added values are all present */
	nm_setting_vpn_foreach_data_item (s_vpn, vpn_check_func, "vpn-data");
	nm_setting_vpn_remove_data_item (s_vpn, "foobar1");
	nm_setting_vpn_remove_data_item (s_vpn, "foobar2");
	nm_setting_vpn_remove_data_item (s_vpn, "foobar3");
	nm_setting_vpn_remove_data_item (s_vpn, "foobar4");

	nm_setting_vpn_add_secret (s_vpn, "foobar1", "blahblah1");
	nm_setting_vpn_add_secret (s_vpn, "foobar2", "blahblah2");
	nm_setting_vpn_add_secret (s_vpn, "foobar3", "blahblah3");
	nm_setting_vpn_add_secret (s_vpn, "foobar4", "blahblah4");

	/* Ensure that added values are all present */
	nm_setting_vpn_foreach_secret (s_vpn, vpn_check_func, "vpn-secrets");
	nm_setting_vpn_remove_secret (s_vpn, "foobar1");
	nm_setting_vpn_remove_secret (s_vpn, "foobar2");
	nm_setting_vpn_remove_secret (s_vpn, "foobar3");
	nm_setting_vpn_remove_secret (s_vpn, "foobar4");

	/* Try to add some blank values and make sure they are rejected */
	g_test_expect_message ("libnm-util", G_LOG_LEVEL_CRITICAL, "*key != NULL*");
	nm_setting_vpn_add_data_item (s_vpn, NULL, NULL);
	g_test_assert_expected_messages ();

	g_test_expect_message ("libnm-util", G_LOG_LEVEL_CRITICAL, "*strlen (key) > 0*");
	nm_setting_vpn_add_data_item (s_vpn, "", "");
	g_test_assert_expected_messages ();

	g_test_expect_message ("libnm-util", G_LOG_LEVEL_CRITICAL, "*item != NULL*");
	nm_setting_vpn_add_data_item (s_vpn, "foobar1", NULL);
	g_test_assert_expected_messages ();

	g_test_expect_message ("libnm-util", G_LOG_LEVEL_CRITICAL, "*strlen (item) > 0*");
	nm_setting_vpn_add_data_item (s_vpn, "foobar1", "");
	g_test_assert_expected_messages ();

	g_test_expect_message ("libnm-util", G_LOG_LEVEL_CRITICAL, "*key != NULL*");
	nm_setting_vpn_add_data_item (s_vpn, NULL, "blahblah1");
	g_test_assert_expected_messages ();

	g_test_expect_message ("libnm-util", G_LOG_LEVEL_CRITICAL, "*strlen (key) > 0*");
	nm_setting_vpn_add_data_item (s_vpn, "", "blahblah1");
	g_test_assert_expected_messages ();

	nm_setting_vpn_foreach_data_item (s_vpn, vpn_check_empty_func, "vpn-data-empty");

	/* Try to add some blank secrets and make sure they are rejected */
	g_test_expect_message ("libnm-util", G_LOG_LEVEL_CRITICAL, "*key != NULL*");
	nm_setting_vpn_add_secret (s_vpn, NULL, NULL);
	g_test_assert_expected_messages ();

	g_test_expect_message ("libnm-util", G_LOG_LEVEL_CRITICAL, "*strlen (key) > 0*");
	nm_setting_vpn_add_secret (s_vpn, "", "");
	g_test_assert_expected_messages ();

	g_test_expect_message ("libnm-util", G_LOG_LEVEL_CRITICAL, "*secret != NULL*");
	nm_setting_vpn_add_secret (s_vpn, "foobar1", NULL);
	g_test_assert_expected_messages ();

	g_test_expect_message ("libnm-util", G_LOG_LEVEL_CRITICAL, "*strlen (secret) > 0*");
	nm_setting_vpn_add_secret (s_vpn, "foobar1", "");
	g_test_assert_expected_messages ();

	g_test_expect_message ("libnm-util", G_LOG_LEVEL_CRITICAL, "*key != NULL*");
	nm_setting_vpn_add_secret (s_vpn, NULL, "blahblah1");
	g_test_assert_expected_messages ();

	g_test_expect_message ("libnm-util", G_LOG_LEVEL_CRITICAL, "*strlen (key) > 0*");
	nm_setting_vpn_add_secret (s_vpn, "", "blahblah1");
	g_test_assert_expected_messages ();

	nm_setting_vpn_foreach_secret (s_vpn, vpn_check_empty_func, "vpn-secrets-empty");

	g_object_unref (s_vpn);
}

static void
test_setting_vpn_update_secrets (void)
{
	NMConnection *connection;
	NMSettingVPN *s_vpn;
	GHashTable *settings, *vpn, *secrets;
	GValue val = G_VALUE_INIT;
	gboolean success;
	GError *error = NULL;
	const char *tmp;
	const char *key1 = "foobar";
	const char *key2 = "blahblah";
	const char *val1 = "value1";
	const char *val2 = "value2";

	connection = nm_connection_new ();
	ASSERT (connection != NULL,
	        "vpn-update-secrets",
	        "error creating connection");

	s_vpn = (NMSettingVPN *) nm_setting_vpn_new ();
	ASSERT (s_vpn != NULL,
	        "vpn-update-secrets",
	        "error creating vpn setting");
	nm_connection_add_setting (connection, NM_SETTING (s_vpn));

	settings = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, (GDestroyNotify) g_hash_table_destroy);
	vpn = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, (GDestroyNotify) g_value_unset);
	g_hash_table_insert (settings, NM_SETTING_VPN_SETTING_NAME, vpn);

	secrets = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, NULL);
	g_value_init (&val, DBUS_TYPE_G_MAP_OF_STRING);
	g_value_take_boxed (&val, secrets);
	g_hash_table_insert (vpn, NM_SETTING_VPN_SECRETS, &val);

	/* Add some secrets */
	g_hash_table_insert (secrets, (char *) key1, (char *) val1);
	g_hash_table_insert (secrets, (char *) key2, (char *) val2);

	success = nm_connection_update_secrets (connection, NM_SETTING_VPN_SETTING_NAME, settings, &error);
	ASSERT (success == TRUE,
	        "vpn-update-secrets", "failed to update VPN secrets: %s", error->message);

	/* Read the secrets back out */
	tmp = nm_setting_vpn_get_secret (s_vpn, key1);
	ASSERT (tmp != NULL,
	        "vpn-update-secrets", "unexpected failure getting key #1");
	ASSERT (strcmp (tmp, val1) == 0,
	        "vpn-update-secrets", "unexpected key #1 value");

	tmp = nm_setting_vpn_get_secret (s_vpn, key2);
	ASSERT (tmp != NULL,
	        "vpn-update-secrets", "unexpected failure getting key #2");
	ASSERT (strcmp (tmp, val2) == 0,
	        "vpn-update-secrets", "unexpected key #2 value");

	g_hash_table_destroy (settings);
	g_object_unref (connection);
}

#define TO_DEL_NUM 50
typedef struct {
	NMSettingVPN *s_vpn;
	char *to_del[TO_DEL_NUM];
	guint called;
} IterInfo;

static void
del_iter_func (const char *key, const char *value, gpointer user_data)
{
	IterInfo *info = user_data;
	int i;

	/* Record how many times this function gets called; it should get called
	 * exactly as many times as there are keys in the hash table, regardless
	 * of what keys we delete from the table.
	 */
	info->called++;

	/* During the iteration, remove a bunch of stuff from the table */
	if (info->called == 1) {
		for (i = 0; i < TO_DEL_NUM; i++)
			nm_setting_vpn_remove_data_item (info->s_vpn, info->to_del[i]);
	}
}

static void
test_setting_vpn_modify_during_foreach (void)
{
	NMSettingVPN *s_vpn;
	IterInfo info;
	char *key, *val;
	int i, u = 0;

	s_vpn = (NMSettingVPN *) nm_setting_vpn_new ();
	g_assert (s_vpn);

	for (i = 0; i < TO_DEL_NUM * 2; i++) {
		key = g_strdup_printf ("adsfasdfadf%d", i);
		val = g_strdup_printf ("42263236236awt%d", i);
		nm_setting_vpn_add_data_item (s_vpn, key, val);

		/* Cache some keys to delete */
		if (i % 2)
			info.to_del[u++] = g_strdup (key);

		g_free (key);
		g_free (val);
	}

	/* Iterate over current table keys */
	info.s_vpn = s_vpn;
	info.called = 0;
	nm_setting_vpn_foreach_data_item (s_vpn, del_iter_func, &info);

	/* Make sure all the things we removed during iteration are really gone */
	for (i = 0; i < TO_DEL_NUM; i++) {
		g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, info.to_del[i]), ==, NULL);
		g_free (info.to_del[i]);
	}

	/* And make sure the foreach callback was called the same number of times
	 * as there were keys in the table at the beginning of the foreach.
	 */
	g_assert_cmpint (info.called, ==, TO_DEL_NUM * 2);

	g_object_unref (s_vpn);
}

static void
_g_value_array_free (void *ptr)
{
	if (ptr)
		g_value_array_free ((GValueArray *) ptr);
}

#define OLD_DBUS_TYPE_G_IP6_ADDRESS (dbus_g_type_get_struct ("GValueArray", DBUS_TYPE_G_UCHAR_ARRAY, G_TYPE_UINT, G_TYPE_INVALID))
#define OLD_DBUS_TYPE_G_ARRAY_OF_IP6_ADDRESS (dbus_g_type_get_collection ("GPtrArray", OLD_DBUS_TYPE_G_IP6_ADDRESS))

/* Test that setting the IPv6 setting's 'addresses' property using the old
 * IPv6 address format still works, i.e. that the GValue transformation function
 * from old->new is working correctly.
 */
static void
test_setting_ip6_config_old_address_array (void)
{
	NMSettingIP6Config *s_ip6;
	GPtrArray *addresses, *read_addresses;
	GValueArray *array, *read_array;
	GValue element = G_VALUE_INIT, written_value = G_VALUE_INIT, read_value = G_VALUE_INIT;
	GByteArray *ba;
	const guint8 addr[16] = { 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
	                          0x11, 0x22, 0x33, 0x44, 0x66, 0x77, 0x88, 0x99 };
	const guint8 gw[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	guint32 prefix = 56;
	GValue *read_addr, *read_prefix, *read_gw;

	s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();
	ASSERT (s_ip6 != NULL,
	        "ip6-old-addr", "error creating IP6 setting");

	g_value_init (&written_value, OLD_DBUS_TYPE_G_ARRAY_OF_IP6_ADDRESS);

	addresses = g_ptr_array_new_full (0, _g_value_array_free);
	array = g_value_array_new (3);

	/* IP address */
	g_value_init (&element, DBUS_TYPE_G_UCHAR_ARRAY);
	ba = g_byte_array_new ();
	g_byte_array_append (ba, &addr[0], sizeof (addr));
	g_value_take_boxed (&element, ba);
	g_value_array_append (array, &element);
	g_value_unset (&element);

	/* Prefix */
	g_value_init (&element, G_TYPE_UINT);
	g_value_set_uint (&element, prefix);
	g_value_array_append (array, &element);
	g_value_unset (&element);

	g_ptr_array_add (addresses, array);
	g_value_set_boxed (&written_value, addresses);

	/* Set the address array on the object */
	g_object_set_property (G_OBJECT (s_ip6), NM_SETTING_IP6_CONFIG_ADDRESSES, &written_value);

	/* Get it back so we can compare it */
	g_value_init (&read_value, DBUS_TYPE_G_ARRAY_OF_IP6_ADDRESS);
	g_object_get_property (G_OBJECT (s_ip6), NM_SETTING_IP6_CONFIG_ADDRESSES, &read_value);

	ASSERT (G_VALUE_HOLDS (&read_value, DBUS_TYPE_G_ARRAY_OF_IP6_ADDRESS),
	        "ip6-old-addr", "wrong addresses property value type '%s'",
	        G_VALUE_TYPE_NAME (&read_value));

	read_addresses = (GPtrArray *) g_value_get_boxed (&read_value);
	ASSERT (read_addresses != NULL,
	        "ip6-old-addr", "missing addresses on readback");
	ASSERT (read_addresses->len == 1,
	        "ip6-old-addr", "expected one address on readback");

	read_array = (GValueArray *) g_ptr_array_index (read_addresses, 0);

	read_addr = g_value_array_get_nth (read_array, 0);
	ba = g_value_get_boxed (read_addr);
	ASSERT (ba->len == sizeof (addr),
	        "ip6-old-addr", "unexpected address item length %d", ba->len);
	ASSERT (memcmp (ba->data, &addr[0], sizeof (addr)) == 0,
	        "ip6-old-addr", "unexpected failure comparing addresses");

	read_prefix = g_value_array_get_nth (read_array, 1);
	ASSERT (g_value_get_uint (read_prefix) == prefix,
	        "ip6-old-addr", "unexpected failure comparing prefix");

	/* Ensure the gateway is all zeros, which is how the 2-item to 3-item
	 * conversion happens.
	 */
	read_gw = g_value_array_get_nth (read_array, 2);
	ba = g_value_get_boxed (read_gw);
	ASSERT (ba->len == sizeof (gw),
	        "ip6-old-addr", "unexpected gateway item length %d", ba->len);
	ASSERT (memcmp (ba->data, &gw[0], sizeof (gw)) == 0,
	        "ip6-old-addr", "unexpected failure comparing gateways");

	g_ptr_array_unref (addresses);
	g_value_unset (&written_value);
	g_value_unset (&read_value);
	g_object_unref (s_ip6);
}

static void
test_setting_gsm_apn_spaces (void)
{
	gs_unref_object NMSettingGsm *s_gsm = NULL;
	const char *tmp;

	s_gsm = (NMSettingGsm *) nm_setting_gsm_new ();
	ASSERT (s_gsm != NULL,
	        "gsm-apn-spaces",
	        "error creating GSM setting");

	/* Trailing space */
	g_object_set (s_gsm, NM_SETTING_GSM_APN, "foobar ", NULL);
	tmp = nm_setting_gsm_get_apn (s_gsm);
	ASSERT (tmp != NULL,
	        "gsm-apn-spaces", "empty APN");
	ASSERT (strcmp (tmp, "foobar") == 0,
	        "gsm-apn-spaces", "unexpected APN");

	/* Leading space */
	g_object_set (s_gsm, NM_SETTING_GSM_APN, " foobar", NULL);
	tmp = nm_setting_gsm_get_apn (s_gsm);
	ASSERT (tmp != NULL,
	        "gsm-apn-spaces", "empty APN");
	ASSERT (strcmp (tmp, "foobar") == 0,
	        "gsm-apn-spaces", "unexpected APN");
}

static void
test_setting_gsm_apn_bad_chars (void)
{
	gs_unref_object NMSettingGsm *s_gsm = NULL;

	s_gsm = (NMSettingGsm *) nm_setting_gsm_new ();
	ASSERT (s_gsm != NULL,
	        "gsm-apn-bad-chars",
	        "error creating GSM setting");

	g_object_set (s_gsm, NM_SETTING_GSM_NUMBER, "*99#", NULL);

	/* Make sure a valid APN works */
	g_object_set (s_gsm, NM_SETTING_GSM_APN, "foobar123.-baz", NULL);
	ASSERT (nm_setting_verify (NM_SETTING (s_gsm), NULL, NULL) == TRUE,
	        "gsm-apn-bad-chars", "unexpectedly invalid GSM setting");

	/* Random invalid chars */
	g_object_set (s_gsm, NM_SETTING_GSM_APN, "@#%$@#%@#%", NULL);
	ASSERT (nm_setting_verify (NM_SETTING (s_gsm), NULL, NULL) == FALSE,
	        "gsm-apn-bad-chars", "unexpectedly valid GSM setting");

	/* Spaces */
	g_object_set (s_gsm, NM_SETTING_GSM_APN, "foobar baz", NULL);
	ASSERT (nm_setting_verify (NM_SETTING (s_gsm), NULL, NULL) == FALSE,
	        "gsm-apn-bad-chars", "unexpectedly valid GSM setting");

	/* 0 characters long */
	g_object_set (s_gsm, NM_SETTING_GSM_APN, "", NULL);
	ASSERT (nm_setting_verify (NM_SETTING (s_gsm), NULL, NULL) == FALSE,
	        "gsm-apn-bad-chars", "unexpectedly valid GSM setting");

	/* 65-character long */
	g_object_set (s_gsm, NM_SETTING_GSM_APN, "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl1", NULL);
	ASSERT (nm_setting_verify (NM_SETTING (s_gsm), NULL, NULL) == FALSE,
	        "gsm-apn-bad-chars", "unexpectedly valid GSM setting");
}

static void
test_setting_gsm_apn_underscore (void)
{
	gs_unref_object NMSettingGsm *s_gsm = NULL;
	GError *error = NULL;
	gboolean success;

	s_gsm = (NMSettingGsm *) nm_setting_gsm_new ();
	g_assert (s_gsm);

	g_object_set (s_gsm, NM_SETTING_GSM_NUMBER, "*99#", NULL);

	/* 65-character long */
	g_object_set (s_gsm, NM_SETTING_GSM_APN, "foobar_baz", NULL);
	success = nm_setting_verify (NM_SETTING (s_gsm), NULL, &error);
	g_assert_no_error (error);
	g_assert (success == TRUE);
}

static void
test_setting_gsm_without_number (void)
{
	gs_unref_object NMSettingGsm *s_gsm = NULL;
	GError *error = NULL;
	gboolean success;

	s_gsm = (NMSettingGsm *) nm_setting_gsm_new ();
	g_assert (s_gsm);

	g_object_set (s_gsm, NM_SETTING_GSM_NUMBER, NULL, NULL);
	success = nm_setting_verify (NM_SETTING (s_gsm), NULL, &error);
	g_assert_no_error (error);
	g_assert (success == TRUE);

	g_object_set (s_gsm, NM_SETTING_GSM_NUMBER, "", NULL);
	success = nm_setting_verify (NM_SETTING (s_gsm), NULL, &error);
	g_assert_error (error, NM_SETTING_GSM_ERROR, NM_SETTING_GSM_ERROR_INVALID_PROPERTY);
	g_error_free (error);
}

static NMSettingWirelessSecurity *
make_test_wsec_setting (const char *detail)
{
	NMSettingWirelessSecurity *s_wsec;

	s_wsec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
	ASSERT (s_wsec != NULL, detail, "error creating setting");

	g_object_set (s_wsec,
	              NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "wpa-psk",
	              NM_SETTING_WIRELESS_SECURITY_LEAP_USERNAME, "foobarbaz",
	              NM_SETTING_WIRELESS_SECURITY_PSK, "random psk",
	              NM_SETTING_WIRELESS_SECURITY_WEP_KEY0, "aaaaaaaaaa",
	              NULL);

	return s_wsec;
}

static void
test_setting_to_hash_all (void)
{
	NMSettingWirelessSecurity *s_wsec;
	GHashTable *hash;

	s_wsec = make_test_wsec_setting ("setting-to-hash-all");

	hash = nm_setting_to_hash (NM_SETTING (s_wsec), NM_SETTING_HASH_FLAG_ALL);

	/* Make sure all keys are there */
	ASSERT (g_hash_table_lookup (hash, NM_SETTING_WIRELESS_SECURITY_KEY_MGMT),
	        "setting-to-hash-all", "unexpectedly missing " NM_SETTING_WIRELESS_SECURITY_KEY_MGMT);
	ASSERT (g_hash_table_lookup (hash, NM_SETTING_WIRELESS_SECURITY_LEAP_USERNAME),
	        "setting-to-hash-all", "unexpectedly missing " NM_SETTING_WIRELESS_SECURITY_LEAP_USERNAME);
	ASSERT (g_hash_table_lookup (hash, NM_SETTING_WIRELESS_SECURITY_PSK),
	        "setting-to-hash-all", "unexpectedly missing " NM_SETTING_WIRELESS_SECURITY_PSK);
	ASSERT (g_hash_table_lookup (hash, NM_SETTING_WIRELESS_SECURITY_WEP_KEY0),
	        "setting-to-hash-all", "unexpectedly missing " NM_SETTING_WIRELESS_SECURITY_WEP_KEY0);

	g_hash_table_destroy (hash);
	g_object_unref (s_wsec);
}

static void
test_setting_to_hash_no_secrets (void)
{
	NMSettingWirelessSecurity *s_wsec;
	GHashTable *hash;

	s_wsec = make_test_wsec_setting ("setting-to-hash-no-secrets");

	hash = nm_setting_to_hash (NM_SETTING (s_wsec), NM_SETTING_HASH_FLAG_NO_SECRETS);

	/* Make sure non-secret keys are there */
	ASSERT (g_hash_table_lookup (hash, NM_SETTING_WIRELESS_SECURITY_KEY_MGMT),
	        "setting-to-hash-no-secrets", "unexpectedly missing " NM_SETTING_WIRELESS_SECURITY_KEY_MGMT);
	ASSERT (g_hash_table_lookup (hash, NM_SETTING_WIRELESS_SECURITY_LEAP_USERNAME),
	        "setting-to-hash-no-secrets", "unexpectedly missing " NM_SETTING_WIRELESS_SECURITY_LEAP_USERNAME);

	/* Make sure secrets are not there */
	ASSERT (g_hash_table_lookup (hash, NM_SETTING_WIRELESS_SECURITY_PSK) == NULL,
	        "setting-to-hash-no-secrets", "unexpectedly present " NM_SETTING_WIRELESS_SECURITY_PSK);
	ASSERT (g_hash_table_lookup (hash, NM_SETTING_WIRELESS_SECURITY_WEP_KEY0) == NULL,
	        "setting-to-hash-no-secrets", "unexpectedly present " NM_SETTING_WIRELESS_SECURITY_WEP_KEY0);

	g_hash_table_destroy (hash);
	g_object_unref (s_wsec);
}

static void
test_setting_to_hash_only_secrets (void)
{
	NMSettingWirelessSecurity *s_wsec;
	GHashTable *hash;

	s_wsec = make_test_wsec_setting ("setting-to-hash-only-secrets");

	hash = nm_setting_to_hash (NM_SETTING (s_wsec), NM_SETTING_HASH_FLAG_ONLY_SECRETS);

	/* Make sure non-secret keys are there */
	ASSERT (g_hash_table_lookup (hash, NM_SETTING_WIRELESS_SECURITY_KEY_MGMT) == NULL,
	        "setting-to-hash-only-secrets", "unexpectedly present " NM_SETTING_WIRELESS_SECURITY_KEY_MGMT);
	ASSERT (g_hash_table_lookup (hash, NM_SETTING_WIRELESS_SECURITY_LEAP_USERNAME) == NULL,
	        "setting-to-hash-only-secrets", "unexpectedly present " NM_SETTING_WIRELESS_SECURITY_LEAP_USERNAME);

	/* Make sure secrets are not there */
	ASSERT (g_hash_table_lookup (hash, NM_SETTING_WIRELESS_SECURITY_PSK),
	        "setting-to-hash-only-secrets", "unexpectedly missing " NM_SETTING_WIRELESS_SECURITY_PSK);
	ASSERT (g_hash_table_lookup (hash, NM_SETTING_WIRELESS_SECURITY_WEP_KEY0),
	        "setting-to-hash-only-secrets", "unexpectedly missing " NM_SETTING_WIRELESS_SECURITY_WEP_KEY0);

	g_hash_table_destroy (hash);
	g_object_unref (s_wsec);
}

static void
test_connection_to_hash_setting_name (void)
{
	NMConnection *connection;
	NMSettingWirelessSecurity *s_wsec;
	GHashTable *hash;

	connection = nm_connection_new ();
	s_wsec = make_test_wsec_setting ("connection-to-hash-setting-name");
	nm_connection_add_setting (connection, NM_SETTING (s_wsec));

	hash = nm_connection_to_hash (connection, NM_SETTING_HASH_FLAG_ALL);

	/* Make sure the keys of the first level hash are setting names, not
	 * the GType name of the setting objects.
	 */
	ASSERT (g_hash_table_lookup (hash, NM_SETTING_WIRELESS_SECURITY_SETTING_NAME) != NULL,
	        "connection-to-hash-setting-name", "unexpectedly missing " NM_SETTING_WIRELESS_SECURITY_SETTING_NAME);

	g_hash_table_destroy (hash);
	g_object_unref (connection);
}

static void
test_setting_new_from_hash (void)
{
	NMSettingWirelessSecurity *s_wsec;
	GHashTable *hash;

	s_wsec = make_test_wsec_setting ("setting-to-hash-all");
	hash = nm_setting_to_hash (NM_SETTING (s_wsec), NM_SETTING_HASH_FLAG_ALL);
	g_object_unref (s_wsec);

	s_wsec = (NMSettingWirelessSecurity *) nm_setting_new_from_hash (NM_TYPE_SETTING_WIRELESS_SECURITY, hash);
	g_hash_table_destroy (hash);

	g_assert (s_wsec);
	g_assert_cmpstr (nm_setting_wireless_security_get_key_mgmt (s_wsec), ==, "wpa-psk");
	g_assert_cmpstr (nm_setting_wireless_security_get_leap_username (s_wsec), ==, "foobarbaz");
	g_assert_cmpstr (nm_setting_wireless_security_get_psk (s_wsec), ==, "random psk");
	g_object_unref (s_wsec);
}

static NMConnection *
new_test_connection (void)
{
	NMConnection *connection;
	NMSetting *setting;
	char *uuid;
	guint64 timestamp = time (NULL);

	connection = nm_connection_new ();

	setting = nm_setting_connection_new ();
	uuid = nm_utils_uuid_generate ();
	g_object_set (G_OBJECT (setting),
	              NM_SETTING_CONNECTION_ID, "foobar",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
	              NM_SETTING_CONNECTION_TIMESTAMP, timestamp,
	              NULL);
	g_free (uuid);
	nm_connection_add_setting (connection, setting);

	setting = nm_setting_wired_new ();
	g_object_set (G_OBJECT (setting),
	              NM_SETTING_WIRED_MTU, 1592,
	              NULL);
	nm_connection_add_setting (connection, setting);

	setting = nm_setting_ip4_config_new ();
	g_object_set (G_OBJECT (setting),
	              NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
	              NM_SETTING_IP4_CONFIG_DHCP_HOSTNAME, "eyeofthetiger",
	              NULL);
	nm_connection_add_setting (connection, setting);

	return connection;
}

static GValue *
string_to_gvalue (const char *str)
{
	GValue *val;

	val = g_slice_new0 (GValue);
	g_value_init (val, G_TYPE_STRING);
	g_value_set_string (val, str);
	return val;
}

static void
destroy_gvalue (gpointer data)
{
	g_value_unset ((GValue *) data);
	g_slice_free (GValue, data);
}

static GHashTable *
new_connection_hash (char **out_uuid,
                     const char **out_expected_id,
                     const char **out_expected_ip6_method)
{
	GHashTable *hash;
	GHashTable *setting;

	hash = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, (GDestroyNotify) g_hash_table_destroy);

	*out_uuid = nm_utils_uuid_generate ();
	*out_expected_id = "My happy connection";
	*out_expected_ip6_method = NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL;

	/* Connection setting */
	setting = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, destroy_gvalue);
	g_hash_table_insert (setting,
	                     g_strdup (NM_SETTING_NAME),
	                     string_to_gvalue (NM_SETTING_CONNECTION_SETTING_NAME));
	g_hash_table_insert (setting,
	                     g_strdup (NM_SETTING_CONNECTION_ID),
	                     string_to_gvalue (*out_expected_id));
	g_hash_table_insert (setting,
	                     g_strdup (NM_SETTING_CONNECTION_UUID),
	                     string_to_gvalue (*out_uuid));
	g_hash_table_insert (setting,
	                     g_strdup (NM_SETTING_CONNECTION_TYPE),
	                     string_to_gvalue (NM_SETTING_WIRED_SETTING_NAME));
	g_hash_table_insert (hash, g_strdup (NM_SETTING_CONNECTION_SETTING_NAME), setting);

	/* Wired setting */
	setting = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, destroy_gvalue);
	g_hash_table_insert (hash, g_strdup (NM_SETTING_WIRED_SETTING_NAME), setting);

	/* IP6 */
	setting = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, destroy_gvalue);
	g_hash_table_insert (setting,
	                     g_strdup (NM_SETTING_IP6_CONFIG_METHOD),
	                     string_to_gvalue (*out_expected_ip6_method));
	g_hash_table_insert (hash, g_strdup (NM_SETTING_IP6_CONFIG_SETTING_NAME), setting);

	return hash;
}

static void
test_connection_replace_settings (void)
{
	NMConnection *connection;
	GHashTable *new_settings;
	GError *error = NULL;
	gboolean success;
	NMSettingConnection *s_con;
	NMSettingIP6Config *s_ip6;
	char *uuid = NULL;
	const char *expected_id = NULL, *expected_method = NULL;

	connection = new_test_connection ();

	new_settings = new_connection_hash (&uuid, &expected_id, &expected_method);
	g_assert (new_settings);

	/* Replace settings and test */
	success = nm_connection_replace_settings (connection, new_settings, &error);
	g_assert_no_error (error);
	g_assert (success);

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, expected_id);
	g_assert_cmpstr (nm_setting_connection_get_uuid (s_con), ==, uuid);

	g_assert (nm_connection_get_setting_wired (connection));
	g_assert (!nm_connection_get_setting_ip4_config (connection));

	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	g_assert (s_ip6);
	g_assert_cmpstr (nm_setting_ip6_config_get_method (s_ip6), ==, expected_method);

	g_free (uuid);
	g_hash_table_destroy (new_settings);
	g_object_unref (connection);
}

static void
test_connection_replace_settings_from_connection (void)
{
	NMConnection *connection, *replacement;
	GError *error = NULL;
	gboolean success;
	NMSettingConnection *s_con;
	NMSetting *setting;
	GByteArray *ssid;
	char *uuid = NULL;
	const char *expected_id = "Awesome connection";

	connection = new_test_connection ();
	g_assert (connection);

	replacement = nm_connection_new ();
	g_assert (replacement);

	/* New connection setting */
	setting = nm_setting_connection_new ();
	g_assert (setting);

	uuid = nm_utils_uuid_generate ();
	g_object_set (setting,
	              NM_SETTING_CONNECTION_ID, expected_id,
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRELESS_SETTING_NAME,
	              NULL);
	nm_connection_add_setting (replacement, setting);

	/* New wifi setting */
	setting = nm_setting_wireless_new ();
	g_assert (setting);

	ssid = g_byte_array_new ();
	g_byte_array_append (ssid, (const guint8 *) "1234567", 7);
	g_object_set (setting,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_MODE, "infrastructure",
	              NULL);
	g_byte_array_free (ssid, TRUE);
	nm_connection_add_setting (replacement, setting);

	/* Replace settings and test */
	success = nm_connection_replace_settings_from_connection (connection, replacement, &error);
	g_assert_no_error (error);
	g_assert (success);

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, expected_id);
	g_assert_cmpstr (nm_setting_connection_get_uuid (s_con), ==, uuid);

	g_assert (!nm_connection_get_setting_wired (connection));
	g_assert (!nm_connection_get_setting_ip6_config (connection));
	g_assert (nm_connection_get_setting_wireless (connection));

	g_free (uuid);
	g_object_unref (replacement);
	g_object_unref (connection);
}

static void
test_connection_new_from_hash (void)
{
	NMConnection *connection;
	GHashTable *new_settings;
	GError *error = NULL;
	NMSettingConnection *s_con;
	NMSettingIP6Config *s_ip6;
	char *uuid = NULL;
	const char *expected_id = NULL, *expected_method = NULL;

	new_settings = new_connection_hash (&uuid, &expected_id, &expected_method);
	g_assert (new_settings);

	/* Replace settings and test */
	connection = nm_connection_new_from_hash (new_settings, &error);
	g_assert_no_error (error);
	g_assert (connection);

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, expected_id);
	g_assert_cmpstr (nm_setting_connection_get_uuid (s_con), ==, uuid);

	g_assert (nm_connection_get_setting_wired (connection));
	g_assert (!nm_connection_get_setting_ip4_config (connection));

	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	g_assert (s_ip6);
	g_assert_cmpstr (nm_setting_ip6_config_get_method (s_ip6), ==, expected_method);

	g_free (uuid);
	g_hash_table_destroy (new_settings);
	g_object_unref (connection);
}

static void
check_permission (NMSettingConnection *s_con,
                  guint32 idx,
                  const char *expected_uname,
                  const char *tag)
{
	gboolean success;
	const char *ptype = NULL, *pitem = NULL, *detail = NULL;

	success = nm_setting_connection_get_permission (s_con, 0, &ptype, &pitem, &detail);
	ASSERT (success == TRUE, tag, "unexpected failure getting added permission");

	/* Permission type */
	ASSERT (ptype != NULL, tag, "unexpected failure getting permission type");
	ASSERT (strcmp (ptype, "user") == 0, tag, "retrieved unexpected permission type");

	/* Permission item */
	ASSERT (pitem != NULL, tag, "unexpected failure getting permission item");
	ASSERT (strcmp (pitem, expected_uname) == 0, tag, "retrieved unexpected permission item");

	ASSERT (detail == NULL, tag, "unexpected success getting permission detail");
}

#define TEST_UNAME "asdfasfasdf"

static void
test_setting_connection_permissions_helpers (void)
{
	NMSettingConnection *s_con;
	gboolean success;
	char buf[9] = { 0x61, 0x62, 0x63, 0xff, 0xfe, 0xfd, 0x23, 0x01, 0x00 };
	GSList *list = NULL;
	const char *expected_perm = "user:" TEST_UNAME ":";

	s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());

	/* Ensure a bad [type] is rejected */
	g_test_expect_message ("libnm-util", G_LOG_LEVEL_CRITICAL, "*strcmp (ptype, \"user\") == 0*");
	success = nm_setting_connection_add_permission (s_con, "foobar", "blah", NULL);
	g_test_assert_expected_messages ();
	ASSERT (success == FALSE,
	        "setting-connection-permissions-helpers", "unexpected success adding bad permission type #1");

	/* Ensure a bad [type] is rejected */
	g_test_expect_message ("libnm-util", G_LOG_LEVEL_CRITICAL, "*ptype*");
	success = nm_setting_connection_add_permission (s_con, NULL, "blah", NULL);
	g_test_assert_expected_messages ();
	ASSERT (success == FALSE,
	        "setting-connection-permissions-helpers", "unexpected success adding bad permission type #2");

	/* Ensure a bad [item] is rejected */
	g_test_expect_message ("libnm-util", G_LOG_LEVEL_CRITICAL, "*uname*");
	g_test_expect_message ("libnm-util", G_LOG_LEVEL_CRITICAL, "*p != NULL*");
	success = nm_setting_connection_add_permission (s_con, "user", NULL, NULL);
	g_test_assert_expected_messages ();
	ASSERT (success == FALSE,
	        "setting-connection-permissions-helpers", "unexpected success adding bad permission item #1");

	/* Ensure a bad [item] is rejected */
	g_test_expect_message ("libnm-util", G_LOG_LEVEL_CRITICAL, "*uname[0] != '\\0'*");
	g_test_expect_message ("libnm-util", G_LOG_LEVEL_CRITICAL, "*p != NULL*");
	success = nm_setting_connection_add_permission (s_con, "user", "", NULL);
	g_test_assert_expected_messages ();
	ASSERT (success == FALSE,
	        "setting-connection-permissions-helpers", "unexpected success adding bad permission item #2");

	/* Ensure an [item] with ':' is rejected */
	g_test_expect_message ("libnm-util", G_LOG_LEVEL_CRITICAL, "*strchr (uname, ':')*");
	g_test_expect_message ("libnm-util", G_LOG_LEVEL_CRITICAL, "*p != NULL*");
	success = nm_setting_connection_add_permission (s_con, "user", "ad:asdf", NULL);
	g_test_assert_expected_messages ();
	ASSERT (success == FALSE,
	        "setting-connection-permissions-helpers", "unexpected success adding bad permission item #3");

	/* Ensure a non-UTF-8 [item] is rejected */
	g_test_expect_message ("libnm-util", G_LOG_LEVEL_CRITICAL, "*g_utf8_validate (uname, -1, NULL)*");
	g_test_expect_message ("libnm-util", G_LOG_LEVEL_CRITICAL, "*p != NULL*");
	success = nm_setting_connection_add_permission (s_con, "user", buf, NULL);
	g_test_assert_expected_messages ();
	ASSERT (success == FALSE,
	        "setting-connection-permissions-helpers", "unexpected success adding bad permission item #4");

	/* Ensure a non-NULL [detail] is rejected */
	g_test_expect_message ("libnm-util", G_LOG_LEVEL_CRITICAL, "*detail == NULL*");
	success = nm_setting_connection_add_permission (s_con, "user", "dafasdf", "asdf");
	g_test_assert_expected_messages ();
	ASSERT (success == FALSE,
	        "setting-connection-permissions-helpers", "unexpected success adding bad detail");

	/* Ensure a valid call results in success */
	success = nm_setting_connection_add_permission (s_con, "user", TEST_UNAME, NULL);
	ASSERT (success == TRUE,
	        "setting-connection-permissions-helpers", "unexpected failure adding valid user permisson");

	ASSERT (nm_setting_connection_get_num_permissions (s_con) == 1,
	        "setting-connection-permissions-helpers", "unexpected failure getting number of permissions");

	check_permission (s_con, 0, TEST_UNAME, "setting-connection-permissions-helpers");

	/* Check the actual GObject property just to be paranoid */
	g_object_get (G_OBJECT (s_con), NM_SETTING_CONNECTION_PERMISSIONS, &list, NULL);
	ASSERT (list != NULL,
	        "setting-connection-permissions-helpers", "unexpected failure getting permissions list");
	ASSERT (g_slist_length (list) == 1,
	        "setting-connection-permissions-helpers", "unexpected failure getting number of permissions in list");
	ASSERT (strcmp (list->data, expected_perm) == 0,
	        "setting-connection-permissions-helpers", "unexpected permission property data");
	g_slist_free_full (list, g_free);

	/* Now remove that permission and ensure we have 0 permissions */
	nm_setting_connection_remove_permission (s_con, 0);
	ASSERT (nm_setting_connection_get_num_permissions (s_con) == 0,
	        "setting-connection-permissions-helpers", "unexpected failure removing permission");

	g_object_unref (s_con);
}

static void
add_permission_property (NMSettingConnection *s_con,
                         const char *ptype,
                         const char *pitem,
                         int pitem_len,
                         const char *detail)
{
	GString *str;
	GSList *list = NULL;

	str = g_string_sized_new (50);
	if (ptype)
		g_string_append (str, ptype);
	g_string_append_c (str, ':');

	if (pitem) {
		if (pitem_len >= 0)
			g_string_append_len (str, pitem, pitem_len);
		else
			g_string_append (str, pitem);
	}

	g_string_append_c (str, ':');

	if (detail)
		g_string_append (str, detail);

	list = g_slist_append (list, str->str);
	g_object_set (G_OBJECT (s_con), NM_SETTING_CONNECTION_PERMISSIONS, list, NULL);

	g_string_free (str, TRUE);
	g_slist_free (list);
}

static void
test_setting_connection_permissions_property (void)
{
	NMSettingConnection *s_con;
	gboolean success;
	char buf[9] = { 0x61, 0x62, 0x63, 0xff, 0xfe, 0xfd, 0x23, 0x01, 0x00 };

	s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());

	/* Ensure a bad [type] is rejected */
	g_test_expect_message ("libnm-util", G_LOG_LEVEL_CRITICAL, "*strncmp (str, PERM_USER_PREFIX, strlen (PERM_USER_PREFIX)) == 0*");
	add_permission_property (s_con, "foobar", "blah", -1, NULL);
	g_test_assert_expected_messages ();
	ASSERT (nm_setting_connection_get_num_permissions (s_con) == 0,
	        "setting-connection-permissions-property", "unexpected success adding bad permission type #1");

	/* Ensure a bad [type] is rejected */
	g_test_expect_message ("libnm-util", G_LOG_LEVEL_CRITICAL, "*strncmp (str, PERM_USER_PREFIX, strlen (PERM_USER_PREFIX)) == 0*");
	add_permission_property (s_con, NULL, "blah", -1, NULL);
	g_test_assert_expected_messages ();
	ASSERT (nm_setting_connection_get_num_permissions (s_con) == 0,
	        "setting-connection-permissions-property", "unexpected success adding bad permission type #2");

	/* Ensure a bad [item] is rejected */
	g_test_expect_message ("libnm-util", G_LOG_LEVEL_CRITICAL, "*last_colon > str*");
	add_permission_property (s_con, "user", NULL, -1, NULL);
	g_test_assert_expected_messages ();
	ASSERT (nm_setting_connection_get_num_permissions (s_con) == 0,
	        "setting-connection-permissions-property", "unexpected success adding bad permission item #1");

	/* Ensure a bad [item] is rejected */
	g_test_expect_message ("libnm-util", G_LOG_LEVEL_CRITICAL, "*last_colon > str*");
	add_permission_property (s_con, "user", "", -1, NULL);
	g_test_assert_expected_messages ();
	ASSERT (nm_setting_connection_get_num_permissions (s_con) == 0,
	        "setting-connection-permissions-property", "unexpected success adding bad permission item #2");

	/* Ensure an [item] with ':' in the middle is rejected */
	g_test_expect_message ("libnm-util", G_LOG_LEVEL_CRITICAL, "*str[i] != ':'*");
	add_permission_property (s_con, "user", "ad:asdf", -1, NULL);
	g_test_assert_expected_messages ();
	ASSERT (nm_setting_connection_get_num_permissions (s_con) == 0,
	        "setting-connection-permissions-property", "unexpected success adding bad permission item #3");

	/* Ensure an [item] with ':' at the end is rejected */
	g_test_expect_message ("libnm-util", G_LOG_LEVEL_CRITICAL, "*str[i] != ':'*");
	add_permission_property (s_con, "user", "adasdfaf:", -1, NULL);
	g_test_assert_expected_messages ();
	ASSERT (nm_setting_connection_get_num_permissions (s_con) == 0,
	        "setting-connection-permissions-property", "unexpected success adding bad permission item #4");

	/* Ensure a non-UTF-8 [item] is rejected */
	g_test_expect_message ("libnm-util", G_LOG_LEVEL_CRITICAL, "*g_utf8_validate (str, -1, NULL)*");
	add_permission_property (s_con, "user", buf, (int) sizeof (buf), NULL);
	g_test_assert_expected_messages ();
	ASSERT (nm_setting_connection_get_num_permissions (s_con) == 0,
	        "setting-connection-permissions-property", "unexpected success adding bad permission item #5");

	/* Ensure a non-NULL [detail] is rejected */
	g_test_expect_message ("libnm-util", G_LOG_LEVEL_CRITICAL, "*(last_colon + 1) == '\\0'*");
	add_permission_property (s_con, "user", "dafasdf", -1, "asdf");
	g_test_assert_expected_messages ();
	ASSERT (nm_setting_connection_get_num_permissions (s_con) == 0,
	        "setting-connection-permissions-property", "unexpected success adding bad detail");

	/* Ensure a valid call results in success */
	success = nm_setting_connection_add_permission (s_con, "user", TEST_UNAME, NULL);
	ASSERT (nm_setting_connection_get_num_permissions (s_con) == 1,
	        "setting-connection-permissions-property", "unexpected failure adding valid user permisson");

	check_permission (s_con, 0, TEST_UNAME, "setting-connection-permissions-property");

	/* Now remove that permission and ensure we have 0 permissions */
	nm_setting_connection_remove_permission (s_con, 0);
	ASSERT (nm_setting_connection_get_num_permissions (s_con) == 0,
	        "setting-connection-permissions-property", "unexpected failure removing permission");

	g_object_unref (s_con);
}

static void
test_connection_compare_same (void)
{
	NMConnection *a, *b;

	a = new_test_connection ();
	b = nm_connection_duplicate (a);
	g_assert (nm_connection_compare (a, b, NM_SETTING_COMPARE_FLAG_EXACT));
	g_object_unref (a);
	g_object_unref (b);
}

static void
test_connection_compare_key_only_in_a (void)
{
	NMConnection *a, *b;
	NMSettingConnection *s_con;

	a = new_test_connection ();
	b = nm_connection_duplicate (a);
	s_con = (NMSettingConnection *) nm_connection_get_setting (b, NM_TYPE_SETTING_CONNECTION);
	g_assert (s_con);
	g_object_set (s_con, NM_SETTING_CONNECTION_TIMESTAMP, (guint64) 0, NULL);

	g_assert (!nm_connection_compare (a, b, NM_SETTING_COMPARE_FLAG_EXACT));
	g_object_unref (a);
	g_object_unref (b);
}

static void
test_connection_compare_setting_only_in_a (void)
{
	NMConnection *a, *b;

	a = new_test_connection ();
	b = nm_connection_duplicate (a);
	nm_connection_remove_setting (b, NM_TYPE_SETTING_IP4_CONFIG);
	g_assert (!nm_connection_compare (a, b, NM_SETTING_COMPARE_FLAG_EXACT));
	g_object_unref (a);
	g_object_unref (b);
}

static void
test_connection_compare_key_only_in_b (void)
{
	NMConnection *a, *b;
	NMSettingConnection *s_con;

	a = new_test_connection ();
	b = nm_connection_duplicate (a);
	s_con = (NMSettingConnection *) nm_connection_get_setting (b, NM_TYPE_SETTING_CONNECTION);
	g_assert (s_con);
	g_object_set (s_con, NM_SETTING_CONNECTION_TIMESTAMP, (guint64) 0, NULL);

	g_assert (!nm_connection_compare (a, b, NM_SETTING_COMPARE_FLAG_EXACT));
	g_object_unref (a);
	g_object_unref (b);
}

static void
test_connection_compare_setting_only_in_b (void)
{
	NMConnection *a, *b;

	a = new_test_connection ();
	b = nm_connection_duplicate (a);
	nm_connection_remove_setting (a, NM_TYPE_SETTING_IP4_CONFIG);
	g_assert (!nm_connection_compare (a, b, NM_SETTING_COMPARE_FLAG_EXACT));
	g_object_unref (a);
	g_object_unref (b);
}

typedef struct {
	const char *key_name;
	guint32 result;
} DiffKey;

typedef struct {
	const char *name;
	DiffKey keys[30];
} DiffSetting;

#define ARRAY_LEN(a)  (sizeof (a) / sizeof (a[0]))

static void
ensure_diffs (GHashTable *diffs, const DiffSetting *check, gsize n_check)
{
	guint i;

	g_assert (g_hash_table_size (diffs) == n_check);

	/* Loop through the settings */
	for (i = 0; i < n_check; i++) {
		GHashTable *setting_hash;
		guint z = 0;

		setting_hash = g_hash_table_lookup (diffs, check[i].name);
		g_assert (setting_hash);

		/* Get the number of keys to check */
		while (check[i].keys[z].key_name)
			z++;
		g_assert (g_hash_table_size (setting_hash) == z);

		/* Now compare the actual keys */
		for (z = 0; check[i].keys[z].key_name; z++) {
			NMSettingDiffResult result;

			result = GPOINTER_TO_UINT (g_hash_table_lookup (setting_hash, check[i].keys[z].key_name));
			g_assert (result == check[i].keys[z].result);
		}
	}
}

static void
test_connection_diff_a_only (void)
{
	NMConnection *connection;
	GHashTable *out_diffs = NULL;
	gboolean same;
	const DiffSetting settings[] = {
		{ NM_SETTING_CONNECTION_SETTING_NAME, {
			{ NM_SETTING_CONNECTION_ID,                   NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_CONNECTION_UUID,                 NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_CONNECTION_INTERFACE_NAME,       NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_CONNECTION_TYPE,                 NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_CONNECTION_TIMESTAMP,            NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_CONNECTION_AUTOCONNECT,          NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_CONNECTION_READ_ONLY,            NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_CONNECTION_PERMISSIONS,          NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_CONNECTION_ZONE,                 NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_CONNECTION_MASTER,               NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_CONNECTION_SLAVE_TYPE,           NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_CONNECTION_SECONDARIES,          NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_CONNECTION_GATEWAY_PING_TIMEOUT, NM_SETTING_DIFF_RESULT_IN_A },
			{ NULL, NM_SETTING_DIFF_RESULT_UNKNOWN }
		} },
		{ NM_SETTING_WIRED_SETTING_NAME, {
			{ NM_SETTING_WIRED_PORT,                  NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_WIRED_SPEED,                 NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_WIRED_DUPLEX,                NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_WIRED_AUTO_NEGOTIATE,        NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_WIRED_MAC_ADDRESS,           NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_WIRED_CLONED_MAC_ADDRESS,    NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_WIRED_MAC_ADDRESS_BLACKLIST, NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_WIRED_MTU,                   NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_WIRED_S390_SUBCHANNELS,      NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_WIRED_S390_NETTYPE,          NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_WIRED_S390_OPTIONS,          NM_SETTING_DIFF_RESULT_IN_A },
			{ NULL, NM_SETTING_DIFF_RESULT_UNKNOWN },
		} },
		{ NM_SETTING_IP4_CONFIG_SETTING_NAME, {
			{ NM_SETTING_IP4_CONFIG_METHOD,             NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_IP4_CONFIG_DNS,                NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_IP4_CONFIG_DNS_SEARCH,         NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_IP4_CONFIG_ADDRESSES,          NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_IP4_CONFIG_ROUTES,             NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_IP4_CONFIG_ROUTE_METRIC,       NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_IP4_CONFIG_IGNORE_AUTO_ROUTES, NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_IP4_CONFIG_IGNORE_AUTO_DNS,    NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_IP4_CONFIG_DHCP_CLIENT_ID,     NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_IP4_CONFIG_DHCP_SEND_HOSTNAME, NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_IP4_CONFIG_DHCP_HOSTNAME,      NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_IP4_CONFIG_NEVER_DEFAULT,      NM_SETTING_DIFF_RESULT_IN_A },
			{ NM_SETTING_IP4_CONFIG_MAY_FAIL,           NM_SETTING_DIFF_RESULT_IN_A },
			{ NULL, NM_SETTING_DIFF_RESULT_UNKNOWN },
		} },
	};

	connection = new_test_connection ();

	same = nm_connection_diff (connection, NULL, NM_SETTING_COMPARE_FLAG_EXACT, &out_diffs);
	g_assert (same == FALSE);
	g_assert (out_diffs != NULL);
	g_assert (g_hash_table_size (out_diffs) > 0);

	ensure_diffs (out_diffs, settings, ARRAY_LEN (settings));

	g_hash_table_destroy (out_diffs);
	g_object_unref (connection);
}

static void
test_connection_diff_same (void)
{
	NMConnection *a, *b;
	GHashTable *out_diffs = NULL;
	gboolean same;

	a = new_test_connection ();
	b = nm_connection_duplicate (a);

	same = nm_connection_diff (a, b, NM_SETTING_COMPARE_FLAG_EXACT, &out_diffs);
	g_assert (same == TRUE);
	g_assert (out_diffs == NULL);
	g_object_unref (a);
	g_object_unref (b);
}

static void
test_connection_diff_different (void)
{
	NMConnection *a, *b;
	GHashTable *out_diffs = NULL;
	NMSettingIP4Config *s_ip4;
	gboolean same;
	const DiffSetting settings[] = {
		{ NM_SETTING_IP4_CONFIG_SETTING_NAME, {
			{ NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_DIFF_RESULT_IN_A | NM_SETTING_DIFF_RESULT_IN_B },
			{ NULL, NM_SETTING_DIFF_RESULT_UNKNOWN },
		} },
	};

	a = new_test_connection ();
	b = nm_connection_duplicate (a);
	s_ip4 = nm_connection_get_setting_ip4_config (a);
	g_assert (s_ip4);
	g_object_set (G_OBJECT (s_ip4),
	              NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_MANUAL,
	              NULL);

	same = nm_connection_diff (a, b, NM_SETTING_COMPARE_FLAG_EXACT, &out_diffs);
	g_assert (same == FALSE);
	g_assert (out_diffs != NULL);
	g_assert (g_hash_table_size (out_diffs) > 0);

	ensure_diffs (out_diffs, settings, ARRAY_LEN (settings));

	g_hash_table_destroy (out_diffs);
	g_object_unref (a);
	g_object_unref (b);
}

static void
test_connection_diff_no_secrets (void)
{
	NMConnection *a, *b;
	GHashTable *out_diffs = NULL;
	NMSetting *s_pppoe;
	gboolean same;
	const DiffSetting settings[] = {
		{ NM_SETTING_PPPOE_SETTING_NAME, {
			{ NM_SETTING_PPPOE_PASSWORD, NM_SETTING_DIFF_RESULT_IN_B },
			{ NULL, NM_SETTING_DIFF_RESULT_UNKNOWN },
		} },
	};

	a = new_test_connection ();
	s_pppoe = nm_setting_pppoe_new ();
	g_object_set (G_OBJECT (s_pppoe),
	              NM_SETTING_PPPOE_USERNAME, "thomas",
	              NULL);
	nm_connection_add_setting (a, s_pppoe);

	b = nm_connection_duplicate (a);

	/* Add a secret to B */
	s_pppoe = NM_SETTING (nm_connection_get_setting_pppoe (b));
	g_assert (s_pppoe);
	g_object_set (G_OBJECT (s_pppoe),
	              NM_SETTING_PPPOE_PASSWORD, "secretpassword",
	              NULL);

	/* Make sure the diff returns no results as secrets are ignored */
	same = nm_connection_diff (a, b, NM_SETTING_COMPARE_FLAG_IGNORE_SECRETS, &out_diffs);
	g_assert (same == TRUE);
	g_assert (out_diffs == NULL);

	/* Now make sure the diff returns results if secrets are not ignored */
	same = nm_connection_diff (a, b, NM_SETTING_COMPARE_FLAG_EXACT, &out_diffs);
	g_assert (same == FALSE);
	g_assert (out_diffs != NULL);
	g_assert (g_hash_table_size (out_diffs) > 0);

	ensure_diffs (out_diffs, settings, ARRAY_LEN (settings));

	g_hash_table_destroy (out_diffs);
	g_object_unref (a);
	g_object_unref (b);
}

static void
test_connection_diff_inferrable (void)
{
	NMConnection *a, *b;
	GHashTable *out_diffs = NULL;
	gboolean same;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIP4Config *s_ip4;
	char *uuid;
	const DiffSetting settings[] = {
		{ NM_SETTING_CONNECTION_SETTING_NAME, {
			{ NM_SETTING_CONNECTION_INTERFACE_NAME, NM_SETTING_DIFF_RESULT_IN_A },
			{ NULL, NM_SETTING_DIFF_RESULT_UNKNOWN },
		} },
	};

	a = new_test_connection ();
	b = nm_connection_duplicate (a);

	/* Change the UUID, wired MTU, and set ignore-auto-dns */
	s_con = nm_connection_get_setting_connection (a);
	g_assert (s_con);
	uuid = nm_utils_uuid_generate ();
	g_object_set (G_OBJECT (s_con),
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_ID, "really neat connection",
	              NULL);
	g_free (uuid);

	s_wired = nm_connection_get_setting_wired (a);
	g_assert (s_wired);
	g_object_set (G_OBJECT (s_wired), NM_SETTING_WIRED_MTU, 300, NULL);

	s_ip4 = nm_connection_get_setting_ip4_config (a);
	g_assert (s_ip4);
	g_object_set (G_OBJECT (s_ip4), NM_SETTING_IP4_CONFIG_IGNORE_AUTO_DNS, TRUE, NULL);

	/* Make sure the diff returns no results as secrets are ignored */
	same = nm_connection_diff (a, b, NM_SETTING_COMPARE_FLAG_INFERRABLE, &out_diffs);
	g_assert (same == TRUE);
	g_assert (out_diffs == NULL);

	/* And change a INFERRABLE property to ensure that it shows up in the diff results */
	g_object_set (G_OBJECT (s_con), NM_SETTING_CONNECTION_INTERFACE_NAME, "usb0", NULL);

	/* Make sure the diff returns no results as secrets are ignored */
	same = nm_connection_diff (a, b, NM_SETTING_COMPARE_FLAG_INFERRABLE, &out_diffs);
	g_assert (same == FALSE);
	g_assert (out_diffs != NULL);
	g_assert (g_hash_table_size (out_diffs) > 0);

	ensure_diffs (out_diffs, settings, ARRAY_LEN (settings));

	g_hash_table_destroy (out_diffs);
	g_object_unref (a);
	g_object_unref (b);
}

static void
add_generic_settings (NMConnection *connection, const char *ctype)
{
	NMSetting *setting;
	char *uuid;

	uuid = nm_utils_uuid_generate ();

	setting = nm_setting_connection_new ();
	g_object_set (setting,
	              NM_SETTING_CONNECTION_ID, "asdfasdfadf",
	              NM_SETTING_CONNECTION_TYPE, ctype,
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NULL);
	nm_connection_add_setting (connection, setting);

	g_free (uuid);

	setting = nm_setting_ip4_config_new ();
	g_object_set (setting, NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);
	nm_connection_add_setting (connection, setting);

	setting = nm_setting_ip6_config_new ();
	g_object_set (setting, NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_AUTO, NULL);
	nm_connection_add_setting (connection, setting);
}

static void
test_connection_good_base_types (void)
{
	NMConnection *connection;
	NMSetting *setting;
	gboolean success;
	GError *error = NULL;
	GByteArray *array;
	const guint8 bdaddr[] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };

	/* Try a basic wired connection */
	connection = nm_connection_new ();
	add_generic_settings (connection, NM_SETTING_WIRED_SETTING_NAME);
	setting = nm_setting_wired_new ();
	nm_connection_add_setting (connection, setting);

	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);
	g_object_unref (connection);

	/* Try a wired PPPoE connection */
	connection = nm_connection_new ();
	add_generic_settings (connection, NM_SETTING_PPPOE_SETTING_NAME);
	setting = nm_setting_pppoe_new ();
	g_object_set (setting, NM_SETTING_PPPOE_USERNAME, "bob smith", NULL);
	nm_connection_add_setting (connection, setting);

	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);
	g_object_unref (connection);

	/* Wifi connection */
	connection = nm_connection_new ();
	add_generic_settings (connection, NM_SETTING_WIRELESS_SETTING_NAME);

	setting = nm_setting_wireless_new ();
	array = g_byte_array_new ();
	g_byte_array_append (array, (const guint8 *) "1234567", 7);
	g_object_set (setting,
	              NM_SETTING_WIRELESS_SSID, array,
	              NM_SETTING_WIRELESS_MODE, "infrastructure",
	              NULL);
	g_byte_array_free (array, TRUE);
	nm_connection_add_setting (connection, setting);

	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);
	g_object_unref (connection);

	/* Bluetooth connection */
	connection = nm_connection_new ();
	add_generic_settings (connection, NM_SETTING_BLUETOOTH_SETTING_NAME);

	setting = nm_setting_bluetooth_new ();
	array = g_byte_array_new ();
	g_byte_array_append (array, bdaddr, sizeof (bdaddr));
	g_object_set (setting,
	              NM_SETTING_BLUETOOTH_BDADDR, array,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_BLUETOOTH_TYPE_PANU,
	              NULL);
	g_byte_array_free (array, TRUE);
	nm_connection_add_setting (connection, setting);

	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);
	g_object_unref (connection);

	/* WiMAX connection */
	connection = nm_connection_new ();
	add_generic_settings (connection, NM_SETTING_WIMAX_SETTING_NAME);
	setting = nm_setting_wimax_new ();
	g_object_set (setting, NM_SETTING_WIMAX_NETWORK_NAME, "CLEAR", NULL);
	nm_connection_add_setting (connection, setting);

	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);
	g_object_unref (connection);

	/* GSM connection */
	connection = nm_connection_new ();
	add_generic_settings (connection, NM_SETTING_GSM_SETTING_NAME);

	setting = nm_setting_gsm_new ();
	g_object_set (setting,
	              NM_SETTING_GSM_NUMBER, "*99#",
	              NM_SETTING_GSM_APN, "metered.billing.sucks",
	              NULL);
	nm_connection_add_setting (connection, setting);
	g_clear_object (&connection);

	/* CDMA connection */
	connection = nm_connection_new ();
	add_generic_settings (connection, NM_SETTING_CDMA_SETTING_NAME);

	setting = nm_setting_cdma_new ();
	g_object_set (setting,
	              NM_SETTING_CDMA_NUMBER, "#777",
	              NM_SETTING_CDMA_USERNAME, "foobar@vzw.com",
	              NULL);
	nm_connection_add_setting (connection, setting);

	success = nm_connection_verify (connection, &error);
	g_assert_no_error (error);
	g_assert (success);
	g_object_unref (connection);
}

static void
test_connection_bad_base_types (void)
{
	NMConnection *connection;
	NMSetting *setting;
	gboolean success;
	GError *error = NULL;

	/* Test various non-base connection types to make sure they are rejected;
	 * using a fake 'wired' connection so the rest of it verifies
	 */

	/* Connection setting */
	connection = nm_connection_new ();
	add_generic_settings (connection, NM_SETTING_CONNECTION_SETTING_NAME);
	setting = nm_setting_wired_new ();
	nm_connection_add_setting (connection, setting);

	success = nm_connection_verify (connection, &error);
	g_assert_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_CONNECTION_TYPE_INVALID);
	g_assert (success == FALSE);
	g_object_unref (connection);
	g_clear_error (&error);

	/* PPP setting */
	connection = nm_connection_new ();
	add_generic_settings (connection, NM_SETTING_PPP_SETTING_NAME);
	setting = nm_setting_wired_new ();
	nm_connection_add_setting (connection, setting);
	setting = nm_setting_ppp_new ();
	nm_connection_add_setting (connection, setting);

	success = nm_connection_verify (connection, &error);
	g_assert_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_CONNECTION_TYPE_INVALID);
	g_assert (success == FALSE);
	g_object_unref (connection);
	g_clear_error (&error);

	/* Serial setting */
	connection = nm_connection_new ();
	add_generic_settings (connection, NM_SETTING_SERIAL_SETTING_NAME);
	setting = nm_setting_wired_new ();
	nm_connection_add_setting (connection, setting);
	setting = nm_setting_serial_new ();
	nm_connection_add_setting (connection, setting);

	success = nm_connection_verify (connection, &error);
	g_assert_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_CONNECTION_TYPE_INVALID);
	g_assert (success == FALSE);
	g_object_unref (connection);
	g_clear_error (&error);

	/* IP4 setting */
	connection = nm_connection_new ();
	add_generic_settings (connection, NM_SETTING_IP4_CONFIG_SETTING_NAME);
	setting = nm_setting_wired_new ();
	nm_connection_add_setting (connection, setting);

	success = nm_connection_verify (connection, &error);
	g_assert_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_CONNECTION_TYPE_INVALID);
	g_assert (success == FALSE);
	g_object_unref (connection);
	g_clear_error (&error);

	/* IP6 setting */
	connection = nm_connection_new ();
	add_generic_settings (connection, NM_SETTING_IP6_CONFIG_SETTING_NAME);
	setting = nm_setting_wired_new ();
	nm_connection_add_setting (connection, setting);

	success = nm_connection_verify (connection, &error);
	g_assert_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_CONNECTION_TYPE_INVALID);
	g_assert (success == FALSE);
	g_object_unref (connection);
	g_clear_error (&error);
}

static void
test_setting_compare_id (void)
{
	gs_unref_object NMSetting *old = NULL, *new = NULL;
	gboolean success;

	old = nm_setting_connection_new ();
	g_object_set (old,
	              NM_SETTING_CONNECTION_ID, "really awesome cool connection",
	              NM_SETTING_CONNECTION_UUID, "fbbd59d5-acab-4e30-8f86-258d272617e7",
	              NM_SETTING_CONNECTION_AUTOCONNECT, FALSE,
	              NULL);

	new = nm_setting_duplicate (old);
	g_object_set (new, NM_SETTING_CONNECTION_ID, "some different connection id", NULL);

	/* First make sure they are different */
	success = nm_setting_compare (old, new, NM_SETTING_COMPARE_FLAG_EXACT);
	g_assert (success == FALSE);

	success = nm_setting_compare (old, new, NM_SETTING_COMPARE_FLAG_IGNORE_ID);
	g_assert (success);
}

static void
_compare_secrets (NMSettingSecretFlags secret_flags,
                  NMSettingCompareFlags comp_flags,
                  gboolean remove_secret)
{
	gs_unref_object NMSetting *old = NULL, *new = NULL;
	gboolean success;

	/* Make sure that a connection with transient/unsaved secrets compares
	 * successfully to the same connection without those secrets.
	 */

	old = nm_setting_wireless_security_new ();
	g_object_set (old,
	              NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "wpa-psk",
	              NM_SETTING_WIRELESS_SECURITY_PSK, "really cool psk",
	              NULL);
	nm_setting_set_secret_flags (old, NM_SETTING_WIRELESS_SECURITY_PSK, secret_flags, NULL);

	/* Clear the PSK from the duplicated setting */
	new = nm_setting_duplicate (old);
	if (remove_secret) {
		g_object_set (new, NM_SETTING_WIRELESS_SECURITY_PSK, NULL, NULL);

		success = nm_setting_compare (old, new, NM_SETTING_COMPARE_FLAG_EXACT);
		g_assert (success == FALSE);
	}

	success = nm_setting_compare (old, new, comp_flags);
	g_assert (success);
}

static void
test_setting_compare_secrets (void)
{
	_compare_secrets (NM_SETTING_SECRET_FLAG_AGENT_OWNED, NM_SETTING_COMPARE_FLAG_IGNORE_AGENT_OWNED_SECRETS, TRUE);
	_compare_secrets (NM_SETTING_SECRET_FLAG_NOT_SAVED, NM_SETTING_COMPARE_FLAG_IGNORE_NOT_SAVED_SECRETS, TRUE);
	_compare_secrets (NM_SETTING_SECRET_FLAG_NONE, NM_SETTING_COMPARE_FLAG_IGNORE_SECRETS, TRUE);
	_compare_secrets (NM_SETTING_SECRET_FLAG_NONE, NM_SETTING_COMPARE_FLAG_EXACT, FALSE);
}

static void
_compare_vpn_secrets (NMSettingSecretFlags secret_flags,
                      NMSettingCompareFlags comp_flags,
                      gboolean remove_secret)
{
	gs_unref_object NMSetting *old = NULL, *new = NULL;
	gboolean success;

	/* Make sure that a connection with transient/unsaved secrets compares
	 * successfully to the same connection without those secrets.
	 */

	old = nm_setting_vpn_new ();
	nm_setting_vpn_add_secret (NM_SETTING_VPN (old), "foobarbaz", "really secret password");
	nm_setting_vpn_add_secret (NM_SETTING_VPN (old), "asdfasdfasdf", "really adfasdfasdfasdf");
	nm_setting_vpn_add_secret (NM_SETTING_VPN (old), "0123456778", "abcdefghijklmnpqrstuvqxyz");
	nm_setting_vpn_add_secret (NM_SETTING_VPN (old), "borkbork", "yet another really secret password");
	nm_setting_set_secret_flags (old, "borkbork", secret_flags, NULL);

	/* Clear "borkbork" from the duplicated setting */
	new = nm_setting_duplicate (old);
	if (remove_secret) {
		nm_setting_vpn_remove_secret (NM_SETTING_VPN (new), "borkbork");

		/* First make sure they are different */
		success = nm_setting_compare (old, new, NM_SETTING_COMPARE_FLAG_EXACT);
		g_assert (success == FALSE);
	}

	success = nm_setting_compare (old, new, comp_flags);
	g_assert (success);
}

static void
test_setting_compare_vpn_secrets (void)
{
	_compare_vpn_secrets (NM_SETTING_SECRET_FLAG_AGENT_OWNED, NM_SETTING_COMPARE_FLAG_IGNORE_AGENT_OWNED_SECRETS, TRUE);
	_compare_vpn_secrets (NM_SETTING_SECRET_FLAG_NOT_SAVED, NM_SETTING_COMPARE_FLAG_IGNORE_NOT_SAVED_SECRETS, TRUE);
	_compare_vpn_secrets (NM_SETTING_SECRET_FLAG_NONE, NM_SETTING_COMPARE_FLAG_IGNORE_SECRETS, TRUE);
	_compare_vpn_secrets (NM_SETTING_SECRET_FLAG_NONE, NM_SETTING_COMPARE_FLAG_EXACT, FALSE);
}

static void
test_hwaddr_aton_ether_normal (void)
{
	guint8 buf[100];
	guint8 expected[ETH_ALEN] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };

	g_assert (nm_utils_hwaddr_aton ("00:11:22:33:44:55", ARPHRD_ETHER, buf) != NULL);
	g_assert (memcmp (buf, expected, sizeof (expected)) == 0);
}

static void
test_hwaddr_aton_ib_normal (void)
{
	guint8 buf[100];
	const char *source = "00:11:22:33:44:55:66:77:88:99:01:12:23:34:45:56:67:78:89:90";
	guint8 expected[INFINIBAND_ALEN] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
		0x77, 0x88, 0x99, 0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89,
		0x90 };

	g_assert (nm_utils_hwaddr_aton (source, ARPHRD_INFINIBAND, buf) != NULL);
	g_assert (memcmp (buf, expected, sizeof (expected)) == 0);
}

static void
test_hwaddr_aton_no_leading_zeros (void)
{
	guint8 buf[100];
	guint8 expected[ETH_ALEN] = { 0x00, 0x1A, 0x2B, 0x03, 0x44, 0x05 };

	g_assert (nm_utils_hwaddr_aton ("0:1a:2B:3:44:5", ARPHRD_ETHER, buf) != NULL);
	g_assert (memcmp (buf, expected, sizeof (expected)) == 0);
}

static void
test_hwaddr_aton_malformed (void)
{
	guint8 buf[100];

	g_assert (nm_utils_hwaddr_aton ("0:1a:2B:3:a@%%", ARPHRD_ETHER, buf) == NULL);
}

static void
test_connection_changed_cb (NMConnection *connection, gboolean *data)
{
	*data = TRUE;
}

static void
test_ip4_prefix_to_netmask (void)
{
	int i;

	for (i = 0; i<=32; i++) {
		guint32 netmask = nm_utils_ip4_prefix_to_netmask (i);
		int plen = nm_utils_ip4_netmask_to_prefix (netmask);

		g_assert_cmpint (i, ==, plen);
		{
			guint32 msk = 0x80000000;
			guint32 netmask2 = 0;
			guint32 prefix = i;
			while (prefix > 0) {
				netmask2 |= msk;
				msk >>= 1;
				prefix--;
			}
			g_assert_cmpint (netmask, ==, (guint32) htonl (netmask2));
		}
	}
}

static void
test_ip4_netmask_to_prefix (void)
{
	int i, j;

	GRand *r = g_rand_new ();

	g_rand_set_seed (r, 1);

	for (i = 2; i<=32; i++) {
		guint32 netmask = nm_utils_ip4_prefix_to_netmask (i);
		guint32 netmask_lowest_bit = netmask & ~nm_utils_ip4_prefix_to_netmask (i-1);

		g_assert_cmpint (i, ==, nm_utils_ip4_netmask_to_prefix (netmask));

		for (j = 0; j < 2*i; j++) {
			guint32 n = g_rand_int (r);
			guint32 netmask_holey;
			guint32 prefix_holey;

			netmask_holey = (netmask & n) | netmask_lowest_bit;

			if (netmask_holey == netmask)
				continue;

			/* create an invalid netmask with holes and check that the function
			 * returns the longest prefix. */
			prefix_holey = nm_utils_ip4_netmask_to_prefix (netmask_holey);

			g_assert_cmpint (i, ==, prefix_holey);
		}
	}

	g_rand_free (r);
}

#define ASSERT_CHANGED(statement) \
{ \
	changed = FALSE; \
	statement; \
	g_assert (changed); \
}

#define ASSERT_UNCHANGED(statement) \
{ \
	changed = FALSE; \
	statement; \
	g_assert (!changed); \
}

static void
test_connection_changed_signal (void)
{
	NMConnection *connection;
	gboolean changed = FALSE;

	connection = new_test_connection ();
	g_signal_connect (connection,
	                  NM_CONNECTION_CHANGED,
	                  (GCallback) test_connection_changed_cb,
	                  &changed);

	/* Add new setting */
	ASSERT_CHANGED (nm_connection_add_setting (connection, nm_setting_vlan_new ()));

	/* Remove existing setting */
	ASSERT_CHANGED (nm_connection_remove_setting (connection, NM_TYPE_SETTING_VLAN));

	/* Remove non-existing setting */
	ASSERT_UNCHANGED (nm_connection_remove_setting (connection, NM_TYPE_SETTING_VLAN));

	g_object_unref (connection);
}

static void
test_setting_connection_changed_signal (void)
{
	NMConnection *connection;
	gboolean changed = FALSE;
	NMSettingConnection *s_con;
	gs_free char *uuid = NULL;

	connection = nm_connection_new ();
	g_signal_connect (connection,
	                  NM_CONNECTION_CHANGED,
	                  (GCallback) test_connection_changed_cb,
	                  &changed);

	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	ASSERT_CHANGED (g_object_set (s_con, NM_SETTING_CONNECTION_ID, "adfadfasdfaf", NULL));

	ASSERT_CHANGED (nm_setting_connection_add_permission (s_con, "user", "billsmith", NULL));
	ASSERT_CHANGED (nm_setting_connection_remove_permission (s_con, 0));

	g_test_expect_message ("libnm-util", G_LOG_LEVEL_CRITICAL, "*iter != NULL*");
	ASSERT_UNCHANGED (nm_setting_connection_remove_permission (s_con, 1));
	g_test_assert_expected_messages ();

	uuid = nm_utils_uuid_generate ();
	ASSERT_CHANGED (nm_setting_connection_add_secondary (s_con, uuid));
	ASSERT_CHANGED (nm_setting_connection_remove_secondary (s_con, 0));

	g_test_expect_message ("libnm-util", G_LOG_LEVEL_CRITICAL, "*elt != NULL*");
	ASSERT_UNCHANGED (nm_setting_connection_remove_secondary (s_con, 1));
	g_test_assert_expected_messages ();

	g_object_unref (connection);
}

static void
test_setting_bond_changed_signal (void)
{
	NMConnection *connection;
	gboolean changed = FALSE;
	NMSettingBond *s_bond;

	connection = nm_connection_new ();
	g_signal_connect (connection,
	                  NM_CONNECTION_CHANGED,
	                  (GCallback) test_connection_changed_cb,
	                  &changed);

	s_bond = (NMSettingBond *) nm_setting_bond_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_bond));

	ASSERT_CHANGED (nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_DOWNDELAY, "10"));
	ASSERT_CHANGED (nm_setting_bond_remove_option (s_bond, NM_SETTING_BOND_OPTION_DOWNDELAY));
	ASSERT_UNCHANGED (nm_setting_bond_remove_option (s_bond, NM_SETTING_BOND_OPTION_UPDELAY));

	g_object_unref (connection);
}

static void
test_setting_ip4_changed_signal (void)
{
	NMConnection *connection;
	gboolean changed = FALSE;
	NMSettingIP4Config *s_ip4;
	NMIP4Address *addr;
	NMIP4Route *route;

	connection = nm_connection_new ();
	g_signal_connect (connection,
	                  NM_CONNECTION_CHANGED,
	                  (GCallback) test_connection_changed_cb,
	                  &changed);

	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	ASSERT_CHANGED (nm_setting_ip4_config_add_dns (s_ip4, 0x1122));
	ASSERT_CHANGED (nm_setting_ip4_config_remove_dns (s_ip4, 0));

	g_test_expect_message ("libnm-util", G_LOG_LEVEL_CRITICAL, "*i <= priv->dns->len*");
	ASSERT_UNCHANGED (nm_setting_ip4_config_remove_dns (s_ip4, 1));
	g_test_assert_expected_messages ();

	nm_setting_ip4_config_add_dns (s_ip4, 0x3344);
	ASSERT_CHANGED (nm_setting_ip4_config_clear_dns (s_ip4));

	ASSERT_CHANGED (nm_setting_ip4_config_add_dns_search (s_ip4, "foobar.com"));
	ASSERT_CHANGED (nm_setting_ip4_config_remove_dns_search (s_ip4, 0));

	g_test_expect_message ("libnm-util", G_LOG_LEVEL_CRITICAL, "*elt != NULL*");
	ASSERT_UNCHANGED (nm_setting_ip4_config_remove_dns_search (s_ip4, 1));
	g_test_assert_expected_messages ();

	ASSERT_CHANGED (nm_setting_ip4_config_add_dns_search (s_ip4, "foobar.com"));
	ASSERT_CHANGED (nm_setting_ip4_config_clear_dns_searches (s_ip4));

	addr = nm_ip4_address_new ();
	nm_ip4_address_set_address (addr, 0x2233);
	nm_ip4_address_set_prefix (addr, 24);
	ASSERT_CHANGED (nm_setting_ip4_config_add_address (s_ip4, addr));
	ASSERT_CHANGED (nm_setting_ip4_config_remove_address (s_ip4, 0));

	g_test_expect_message ("libnm-util", G_LOG_LEVEL_CRITICAL, "*elt != NULL*");
	ASSERT_UNCHANGED (nm_setting_ip4_config_remove_address (s_ip4, 1));
	g_test_assert_expected_messages ();

	nm_setting_ip4_config_add_address (s_ip4, addr);
	ASSERT_CHANGED (nm_setting_ip4_config_clear_addresses (s_ip4));

	route = nm_ip4_route_new ();
	nm_ip4_route_set_dest (route, 0x2233);
	nm_ip4_route_set_prefix (route, 24);

	ASSERT_CHANGED (nm_setting_ip4_config_add_route (s_ip4, route));
	ASSERT_CHANGED (nm_setting_ip4_config_remove_route (s_ip4, 0));

	g_test_expect_message ("libnm-util", G_LOG_LEVEL_CRITICAL, "*elt != NULL*");
	ASSERT_UNCHANGED (nm_setting_ip4_config_remove_route (s_ip4, 1));
	g_test_assert_expected_messages ();

	nm_setting_ip4_config_add_route (s_ip4, route);
	ASSERT_CHANGED (nm_setting_ip4_config_clear_routes (s_ip4));

	nm_ip4_address_unref (addr);
	nm_ip4_route_unref (route);
	g_object_unref (connection);
}

static void
test_setting_ip6_changed_signal (void)
{
	NMConnection *connection;
	gboolean changed = FALSE;
	NMSettingIP6Config *s_ip6;
	NMIP6Address *addr;
	NMIP6Route *route;
	const struct in6_addr t = { { { 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 } } };

	connection = nm_connection_new ();
	g_signal_connect (connection,
	                  NM_CONNECTION_CHANGED,
	                  (GCallback) test_connection_changed_cb,
	                  &changed);

	s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	ASSERT_CHANGED (nm_setting_ip6_config_add_dns (s_ip6, &t));
	ASSERT_CHANGED (nm_setting_ip6_config_remove_dns (s_ip6, 0));

	g_test_expect_message ("libnm-util", G_LOG_LEVEL_CRITICAL, "*elt != NULL*");
	ASSERT_UNCHANGED (nm_setting_ip6_config_remove_dns (s_ip6, 1));
	g_test_assert_expected_messages ();

	nm_setting_ip6_config_add_dns (s_ip6, &t);
	ASSERT_CHANGED (nm_setting_ip6_config_clear_dns (s_ip6));

	ASSERT_CHANGED (nm_setting_ip6_config_add_dns_search (s_ip6, "foobar.com"));
	ASSERT_CHANGED (nm_setting_ip6_config_remove_dns_search (s_ip6, 0));

	g_test_expect_message ("libnm-util", G_LOG_LEVEL_CRITICAL, "*elt != NULL*");
	ASSERT_UNCHANGED (nm_setting_ip6_config_remove_dns_search (s_ip6, 1));
	g_test_assert_expected_messages ();

	nm_setting_ip6_config_add_dns_search (s_ip6, "foobar.com");
	ASSERT_CHANGED (nm_setting_ip6_config_clear_dns_searches (s_ip6));

	addr = nm_ip6_address_new ();
	nm_ip6_address_set_address (addr, &t);
	nm_ip6_address_set_prefix (addr, 64);

	ASSERT_CHANGED (nm_setting_ip6_config_add_address (s_ip6, addr));
	ASSERT_CHANGED (nm_setting_ip6_config_remove_address (s_ip6, 0));

	g_test_expect_message ("libnm-util", G_LOG_LEVEL_CRITICAL, "*elt != NULL*");
	ASSERT_UNCHANGED (nm_setting_ip6_config_remove_address (s_ip6, 1));
	g_test_assert_expected_messages ();

	nm_setting_ip6_config_add_address (s_ip6, addr);
	ASSERT_CHANGED (nm_setting_ip6_config_clear_addresses (s_ip6));

	route = nm_ip6_route_new ();
	nm_ip6_route_set_dest (route, &t);
	nm_ip6_route_set_prefix (route, 128);

	ASSERT_CHANGED (nm_setting_ip6_config_add_route (s_ip6, route));
	ASSERT_CHANGED (nm_setting_ip6_config_remove_route (s_ip6, 0));

	g_test_expect_message ("libnm-util", G_LOG_LEVEL_CRITICAL, "*elt != NULL*");
	ASSERT_UNCHANGED (nm_setting_ip6_config_remove_route (s_ip6, 1));
	g_test_assert_expected_messages ();

	nm_setting_ip6_config_add_route (s_ip6, route);
	ASSERT_CHANGED (nm_setting_ip6_config_clear_routes (s_ip6));

	nm_ip6_address_unref (addr);
	nm_ip6_route_unref (route);
	g_object_unref (connection);
}

static void
test_setting_vlan_changed_signal (void)
{
	NMConnection *connection;
	gboolean changed = FALSE;
	NMSettingVlan *s_vlan;

	connection = nm_connection_new ();
	g_signal_connect (connection,
	                  NM_CONNECTION_CHANGED,
	                  (GCallback) test_connection_changed_cb,
	                  &changed);

	s_vlan = (NMSettingVlan *) nm_setting_vlan_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_vlan));

	ASSERT_CHANGED (nm_setting_vlan_add_priority (s_vlan, NM_VLAN_INGRESS_MAP, 1, 3));
	ASSERT_CHANGED (nm_setting_vlan_remove_priority (s_vlan, NM_VLAN_INGRESS_MAP, 0));
	g_test_expect_message ("libnm-util", G_LOG_LEVEL_CRITICAL, "*idx < g_slist_length (list)*");
	ASSERT_UNCHANGED (nm_setting_vlan_remove_priority (s_vlan, NM_VLAN_INGRESS_MAP, 1));
	g_test_assert_expected_messages ();
	ASSERT_CHANGED (nm_setting_vlan_add_priority_str (s_vlan, NM_VLAN_INGRESS_MAP, "1:3"));
	ASSERT_CHANGED (nm_setting_vlan_clear_priorities (s_vlan, NM_VLAN_INGRESS_MAP));

	ASSERT_CHANGED (nm_setting_vlan_add_priority (s_vlan, NM_VLAN_EGRESS_MAP, 1, 3));
	ASSERT_CHANGED (nm_setting_vlan_remove_priority (s_vlan, NM_VLAN_EGRESS_MAP, 0));
	g_test_expect_message ("libnm-util", G_LOG_LEVEL_CRITICAL, "*idx < g_slist_length (list)*");
	ASSERT_UNCHANGED (nm_setting_vlan_remove_priority (s_vlan, NM_VLAN_EGRESS_MAP, 1));
	g_test_assert_expected_messages ();
	ASSERT_CHANGED (nm_setting_vlan_add_priority_str (s_vlan, NM_VLAN_EGRESS_MAP, "1:3"));
	ASSERT_CHANGED (nm_setting_vlan_clear_priorities (s_vlan, NM_VLAN_EGRESS_MAP));

	g_object_unref (connection);
}

static void
test_setting_vpn_changed_signal (void)
{
	NMConnection *connection;
	gboolean changed = FALSE;
	NMSettingVPN *s_vpn;

	connection = nm_connection_new ();
	g_signal_connect (connection,
	                  NM_CONNECTION_CHANGED,
	                  (GCallback) test_connection_changed_cb,
	                  &changed);

	s_vpn = (NMSettingVPN *) nm_setting_vpn_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_vpn));

	ASSERT_CHANGED (nm_setting_vpn_add_data_item (s_vpn, "foobar", "baz"));
	ASSERT_CHANGED (nm_setting_vpn_remove_data_item (s_vpn, "foobar"));
	ASSERT_UNCHANGED (nm_setting_vpn_remove_data_item (s_vpn, "not added"));

	ASSERT_CHANGED (nm_setting_vpn_add_secret (s_vpn, "foobar", "baz"));
	ASSERT_CHANGED (nm_setting_vpn_remove_secret (s_vpn, "foobar"));
	ASSERT_UNCHANGED (nm_setting_vpn_remove_secret (s_vpn, "not added"));

	g_object_unref (connection);
}

static void
test_setting_wired_changed_signal (void)
{
	NMConnection *connection;
	gboolean changed = FALSE;
	NMSettingWired *s_wired;

	connection = nm_connection_new ();
	g_signal_connect (connection,
	                  NM_CONNECTION_CHANGED,
	                  (GCallback) test_connection_changed_cb,
	                  &changed);

	s_wired = (NMSettingWired *) nm_setting_wired_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wired));

	ASSERT_CHANGED (nm_setting_wired_add_s390_option (s_wired, "portno", "1"));
	ASSERT_CHANGED (nm_setting_wired_remove_s390_option (s_wired, "portno"));
	ASSERT_UNCHANGED (nm_setting_wired_remove_s390_option (s_wired, "layer2"));

	g_object_unref (connection);
}

static void
test_setting_wireless_changed_signal (void)
{
	NMConnection *connection;
	gboolean changed = FALSE;
	NMSettingWireless *s_wifi;

	connection = nm_connection_new ();
	g_signal_connect (connection,
	                  NM_CONNECTION_CHANGED,
	                  (GCallback) test_connection_changed_cb,
	                  &changed);

	s_wifi = (NMSettingWireless *) nm_setting_wireless_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wifi));

	ASSERT_CHANGED (nm_setting_wireless_add_seen_bssid (s_wifi, "00:11:22:33:44:55"));

	g_object_unref (connection);
}

static void
test_setting_wireless_security_changed_signal (void)
{
	NMConnection *connection;
	gboolean changed = FALSE;
	NMSettingWirelessSecurity *s_wsec;

	connection = nm_connection_new ();
	g_signal_connect (connection,
	                  NM_CONNECTION_CHANGED,
	                  (GCallback) test_connection_changed_cb,
	                  &changed);

	s_wsec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wsec));

	/* Protos */
	ASSERT_CHANGED (nm_setting_wireless_security_add_proto (s_wsec, "wpa"));
	ASSERT_CHANGED (nm_setting_wireless_security_remove_proto (s_wsec, 0));
	g_test_expect_message ("libnm-util", G_LOG_LEVEL_CRITICAL, "*elt != NULL*");
	ASSERT_UNCHANGED (nm_setting_wireless_security_remove_proto (s_wsec, 1));
	g_test_assert_expected_messages ();

	nm_setting_wireless_security_add_proto (s_wsec, "wep");
	ASSERT_CHANGED (nm_setting_wireless_security_clear_protos (s_wsec));

	/* Pairwise ciphers */
	ASSERT_CHANGED (nm_setting_wireless_security_add_pairwise (s_wsec, "tkip"));
	ASSERT_CHANGED (nm_setting_wireless_security_remove_pairwise (s_wsec, 0));
	g_test_expect_message ("libnm-util", G_LOG_LEVEL_CRITICAL, "*elt != NULL*");
	ASSERT_UNCHANGED (nm_setting_wireless_security_remove_pairwise (s_wsec, 1));
	g_test_assert_expected_messages ();

	nm_setting_wireless_security_add_pairwise (s_wsec, "tkip");
	ASSERT_CHANGED (nm_setting_wireless_security_clear_pairwise (s_wsec));

	/* Group ciphers */
	ASSERT_CHANGED (nm_setting_wireless_security_add_group (s_wsec, "ccmp"));
	ASSERT_CHANGED (nm_setting_wireless_security_remove_group (s_wsec, 0));
	g_test_expect_message ("libnm-util", G_LOG_LEVEL_CRITICAL, "*elt != NULL*");
	ASSERT_UNCHANGED (nm_setting_wireless_security_remove_group (s_wsec, 1));
	g_test_assert_expected_messages ();

	nm_setting_wireless_security_add_group (s_wsec, "tkip");
	ASSERT_CHANGED (nm_setting_wireless_security_clear_groups (s_wsec));

	/* WEP key secret flags */
	ASSERT_CHANGED (g_assert (nm_setting_set_secret_flags (NM_SETTING (s_wsec), "wep-key0", NM_SETTING_SECRET_FLAG_AGENT_OWNED, NULL)));
	ASSERT_CHANGED (g_assert (nm_setting_set_secret_flags (NM_SETTING (s_wsec), "wep-key1", NM_SETTING_SECRET_FLAG_AGENT_OWNED, NULL)));
	ASSERT_CHANGED (g_assert (nm_setting_set_secret_flags (NM_SETTING (s_wsec), "wep-key2", NM_SETTING_SECRET_FLAG_AGENT_OWNED, NULL)));
	ASSERT_CHANGED (g_assert (nm_setting_set_secret_flags (NM_SETTING (s_wsec), "wep-key3", NM_SETTING_SECRET_FLAG_AGENT_OWNED, NULL)));

	g_object_unref (connection);
}

static void
test_setting_802_1x_changed_signal (void)
{
	NMConnection *connection;
	gboolean changed = FALSE;
	NMSetting8021x *s_8021x;

	connection = nm_connection_new ();
	g_signal_connect (connection,
	                  NM_CONNECTION_CHANGED,
	                  (GCallback) test_connection_changed_cb,
	                  &changed);

	s_8021x = (NMSetting8021x *) nm_setting_802_1x_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_8021x));

	/* EAP methods */
	ASSERT_CHANGED (nm_setting_802_1x_add_eap_method (s_8021x, "tls"));
	ASSERT_CHANGED (nm_setting_802_1x_remove_eap_method (s_8021x, 0));
	g_test_expect_message ("libnm-util", G_LOG_LEVEL_CRITICAL, "*elt != NULL*");
	ASSERT_UNCHANGED (nm_setting_802_1x_remove_eap_method (s_8021x, 1));
	g_test_assert_expected_messages ();

	nm_setting_802_1x_add_eap_method (s_8021x, "ttls");
	ASSERT_CHANGED (nm_setting_802_1x_clear_eap_methods (s_8021x));

	/* alternate subject matches */
	ASSERT_CHANGED (nm_setting_802_1x_add_altsubject_match (s_8021x, "EMAIL:server@example.com"));
	ASSERT_CHANGED (nm_setting_802_1x_remove_altsubject_match (s_8021x, 0));
	g_test_expect_message ("libnm-util", G_LOG_LEVEL_CRITICAL, "*elt != NULL*");
	ASSERT_UNCHANGED (nm_setting_802_1x_remove_altsubject_match (s_8021x, 1));
	g_test_assert_expected_messages ();

	nm_setting_802_1x_add_altsubject_match (s_8021x, "EMAIL:server@example.com");
	ASSERT_CHANGED (nm_setting_802_1x_clear_altsubject_matches (s_8021x));

	/* phase2 alternate subject matches */
	ASSERT_CHANGED (nm_setting_802_1x_add_phase2_altsubject_match (s_8021x, "EMAIL:server@example.com"));
	ASSERT_CHANGED (nm_setting_802_1x_remove_phase2_altsubject_match (s_8021x, 0));
	g_test_expect_message ("libnm-util", G_LOG_LEVEL_CRITICAL, "*elt != NULL*");
	ASSERT_UNCHANGED (nm_setting_802_1x_remove_phase2_altsubject_match (s_8021x, 1));
	g_test_assert_expected_messages ();

	nm_setting_802_1x_add_phase2_altsubject_match (s_8021x, "EMAIL:server@example.com");
	ASSERT_CHANGED (nm_setting_802_1x_clear_phase2_altsubject_matches (s_8021x));

	g_object_unref (connection);
}

static void
test_setting_old_uuid (void)
{
	GError *error = NULL;
	gs_unref_object NMSetting *setting = NULL;
	gboolean success;

	/* NetworkManager-0.9.4.0 generated 40-character UUIDs with no dashes,
	 * like this one. Test that we maintain compatibility. */
	const char *uuid = "f43bec2cdd60e5da381ebb1eb1fa39f3cc52660c";

	setting = nm_setting_connection_new ();
	g_object_set (G_OBJECT (setting),
	              NM_SETTING_CONNECTION_ID, "uuidtest",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
	              NULL);

	success = nm_setting_verify (NM_SETTING (setting), NULL, &error);
	g_assert_no_error (error);
	g_assert (success == TRUE);
}

/*
 * nm_connection_verify() modifies the connection by setting
 * the interface-name property to the virtual_iface_name of
 * the type specific settings.
 *
 * It would be preferable of verify() not to touch the connection,
 * but as it is now, stick with it and test it.
 **/
static void
test_connection_verify_sets_interface_name (void)
{
	NMConnection *con;
	NMSettingConnection *s_con;
	NMSettingBond *s_bond;
	GError *error = NULL;
	gboolean success;

	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	g_object_set (G_OBJECT (s_con),
	              NM_SETTING_CONNECTION_ID, "test1",
	              NM_SETTING_CONNECTION_UUID, "22001632-bbb4-4616-b277-363dce3dfb5b",
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_BOND_SETTING_NAME,
	              NULL);
	s_bond = (NMSettingBond *) nm_setting_bond_new ();
	g_object_set (G_OBJECT (s_bond),
	              NM_SETTING_BOND_INTERFACE_NAME, "bond-x",
	              NULL);

	con = nm_connection_new ();
	nm_connection_add_setting (con, NM_SETTING (s_con));
	nm_connection_add_setting (con, NM_SETTING (s_bond));

	g_assert_cmpstr (nm_connection_get_interface_name (con), ==, NULL);

	/* for backward compatiblity, normalizes the interface name */
	success = nm_connection_verify (con, &error);
	g_assert (success && !error);

	g_assert_cmpstr (nm_connection_get_interface_name (con), ==, "bond-x");

	g_object_unref (con);
}

/*
 * Test normalization of interface-name
 **/
static void
test_connection_normalize_virtual_iface_name (void)
{
	NMConnection *con;
	NMSettingConnection *s_con;
	NMSettingVlan *s_vlan;
	NMSetting *setting;
	GError *error = NULL;
	gboolean success;
	const char *IFACE_NAME = "iface";
	const char *IFACE_VIRT = "iface-X";
	gboolean modified = FALSE;

	con = nm_connection_new ();

	setting = nm_setting_ip4_config_new ();
	g_object_set (setting,
	              NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
	              NULL);
	nm_connection_add_setting (con, setting);

	setting = nm_setting_ip6_config_new ();
	g_object_set (setting,
	              NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_AUTO,
	              NM_SETTING_IP6_CONFIG_MAY_FAIL, TRUE,
	              NULL);
	nm_connection_add_setting (con, setting);

	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	g_object_set (G_OBJECT (s_con),
	              NM_SETTING_CONNECTION_ID, "test1",
	              NM_SETTING_CONNECTION_UUID, "22001632-bbb4-4616-b277-363dce3dfb5b",
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_VLAN_SETTING_NAME,
	              NM_SETTING_CONNECTION_INTERFACE_NAME, IFACE_NAME,
	              NULL);
	s_vlan = (NMSettingVlan *) nm_setting_vlan_new ();
	g_object_set (G_OBJECT (s_vlan),
	              NM_SETTING_VLAN_INTERFACE_NAME, IFACE_VIRT,
	              NM_SETTING_VLAN_PARENT, "eth0",
	              NULL);

	nm_connection_add_setting (con, NM_SETTING (s_con));
	nm_connection_add_setting (con, NM_SETTING (s_vlan));

	g_assert_cmpstr (nm_connection_get_interface_name (con), ==, IFACE_NAME);
	g_assert_cmpstr (nm_setting_vlan_get_interface_name (s_vlan), ==, IFACE_VIRT);

	/* for backward compatiblity, normalizes the interface name */
	success = nm_connection_verify (con, &error);
	g_assert (success && !error);

	g_assert_cmpstr (nm_connection_get_interface_name (con), ==, IFACE_NAME);
	g_assert_cmpstr (nm_setting_vlan_get_interface_name (s_vlan), ==, IFACE_VIRT);

	success = nm_connection_normalize (con, NULL, &modified, &error);
	g_assert (success && !error);
	g_assert (modified);

	g_assert_cmpstr (nm_connection_get_interface_name (con), ==, IFACE_NAME);
	g_assert_cmpstr (nm_setting_vlan_get_interface_name (s_vlan), ==, IFACE_NAME);

	success = nm_connection_verify (con, &error);
	g_assert (success && !error);

	g_object_unref (con);
}

static void
_test_libnm_linking_setup_child_process (gpointer user_data)
{
	int val;
	struct rlimit limit;

	/* the child process is supposed to crash. We don't want it
	 * to write a core dump. */

	val = getrlimit (RLIMIT_CORE, &limit);
	if (val == 0) {
		limit.rlim_cur = 0;
		val = setrlimit (RLIMIT_CORE, &limit);
		if (val == 0)
			return;
	}
	/* on error, do not crash or fail assertion. Instead just exit */
	exit (1);
}

static void
test_libnm_linking (void)
{
	char *argv[] = { "./test-libnm-linking", NULL };
	char *out, *err;
	int status;
	GError *error = NULL;

	g_spawn_sync (BUILD_DIR, argv, NULL, 0 /*G_SPAWN_DEFAULT*/,
	              _test_libnm_linking_setup_child_process, NULL,
	              &out, &err, &status, &error);
	g_assert_no_error (error);

	g_assert (WIFSIGNALED (status));

	g_assert (strstr (err, "Mixing libnm") != NULL);
	g_free (out);
	g_free (err);
}

/******************************************************************************/

static void
_test_uuid (const char *expected_uuid, const char *str)
{
	gs_free char *uuid_test = NULL;

	g_assert (str);

	uuid_test = nm_utils_uuid_generate_from_string (str);

	g_assert (uuid_test);
	g_assert (nm_utils_is_uuid (uuid_test));

	if (strcmp (uuid_test, expected_uuid)) {
		g_error ("UUID test failed: text=%s, uuid=%s, expected=%s",
		         str, uuid_test, expected_uuid);
	}
}

static void
test_nm_utils_uuid_generate_from_string (void)
{
	gs_free char *uuid_test = NULL;

	_test_uuid ("0cc175b9-c0f1-b6a8-31c3-99e269772661", "a");
	_test_uuid ("098f6bcd-4621-d373-cade-4e832627b4f6", "test");
	_test_uuid ("59c0547b-7fe2-1c15-2cce-e328e8bf6742", "/etc/NetworkManager/system-connections/em1");

	g_test_expect_message ("libnm-util", G_LOG_LEVEL_CRITICAL, "*nm_utils_uuid_generate_from_string*: *s && *s*");
	uuid_test = nm_utils_uuid_generate_from_string ("");
	g_assert (uuid_test == NULL);
	g_test_assert_expected_messages ();

	g_test_expect_message ("libnm-util", G_LOG_LEVEL_CRITICAL, "*nm_utils_uuid_generate_from_string*: *s && *s*");
	uuid_test = nm_utils_uuid_generate_from_string (NULL);
	g_assert (uuid_test == NULL);
	g_test_assert_expected_messages ();
}

/******************************************************************************/

NMTST_DEFINE ();

int main (int argc, char **argv)
{
	nmtst_init (&argc, &argv, TRUE);

	/* The tests */
	g_test_add_func ("/libnm/setting_vpn_items", test_setting_vpn_items);
	g_test_add_func ("/libnm/setting_vpn_update_secrets", test_setting_vpn_update_secrets);
	g_test_add_func ("/libnm/setting_vpn_modify_during_foreach", test_setting_vpn_modify_during_foreach);
	g_test_add_func ("/libnm/setting_ip6_config_old_address_array", test_setting_ip6_config_old_address_array);
	g_test_add_func ("/libnm/setting_gsm_apn_spaces", test_setting_gsm_apn_spaces);
	g_test_add_func ("/libnm/setting_gsm_apn_bad_chars", test_setting_gsm_apn_bad_chars);
	g_test_add_func ("/libnm/setting_gsm_apn_underscore", test_setting_gsm_apn_underscore);
	g_test_add_func ("/libnm/setting_gsm_without_number", test_setting_gsm_without_number);
	g_test_add_func ("/libnm/setting_to_hash_all", test_setting_to_hash_all);
	g_test_add_func ("/libnm/setting_to_hash_no_secrets", test_setting_to_hash_no_secrets);
	g_test_add_func ("/libnm/setting_to_hash_only_secrets", test_setting_to_hash_only_secrets);
	g_test_add_func ("/libnm/setting_compare_id", test_setting_compare_id);
	g_test_add_func ("/libnm/setting_compare_secrets", test_setting_compare_secrets);
	g_test_add_func ("/libnm/setting_compare_vpn_secrets", test_setting_compare_vpn_secrets);
	g_test_add_func ("/libnm/setting_old_uuid", test_setting_old_uuid);

	g_test_add_func ("/libnm/connection_to_hash_setting_name", test_connection_to_hash_setting_name);
	g_test_add_func ("/libnm/setting_new_from_hash", test_setting_new_from_hash);
	g_test_add_func ("/libnm/connection_replace_settings", test_connection_replace_settings);
	g_test_add_func ("/libnm/connection_replace_settings_from_connection", test_connection_replace_settings_from_connection);
	g_test_add_func ("/libnm/connection_new_from_hash", test_connection_new_from_hash);
	g_test_add_func ("/libnm/connection_verify_sets_interface_name", test_connection_verify_sets_interface_name);
	g_test_add_func ("/libnm/connection_normalize_virtual_iface_name", test_connection_normalize_virtual_iface_name);

	g_test_add_func ("/libnm/setting_connection_permissions_helpers", test_setting_connection_permissions_helpers);
	g_test_add_func ("/libnm/setting_connection_permissions_property", test_setting_connection_permissions_property);

	g_test_add_func ("/libnm/connection_compare_same", test_connection_compare_same);
	g_test_add_func ("/libnm/connection_compare_key_only_in_a", test_connection_compare_key_only_in_a);
	g_test_add_func ("/libnm/connection_compare_setting_only_in_a", test_connection_compare_setting_only_in_a);
	g_test_add_func ("/libnm/connection_compare_key_only_in_b", test_connection_compare_key_only_in_b);
	g_test_add_func ("/libnm/connection_compare_setting_only_in_b", test_connection_compare_setting_only_in_b);

	g_test_add_func ("/libnm/connection_diff_a_only", test_connection_diff_a_only);
	g_test_add_func ("/libnm/connection_diff_same", test_connection_diff_same);
	g_test_add_func ("/libnm/connection_diff_different", test_connection_diff_different);
	g_test_add_func ("/libnm/connection_diff_no_secrets", test_connection_diff_no_secrets);
	g_test_add_func ("/libnm/connection_diff_inferrable", test_connection_diff_inferrable);
	g_test_add_func ("/libnm/connection_good_base_types", test_connection_good_base_types);
	g_test_add_func ("/libnm/connection_bad_base_types", test_connection_bad_base_types);

	g_test_add_func ("/libnm/hwaddr_aton_ether_normal", test_hwaddr_aton_ether_normal);
	g_test_add_func ("/libnm/hwaddr_aton_ib_normal", test_hwaddr_aton_ib_normal);
	g_test_add_func ("/libnm/hwaddr_aton_no_leading_zeros", test_hwaddr_aton_no_leading_zeros);
	g_test_add_func ("/libnm/hwaddr_aton_malformed", test_hwaddr_aton_malformed);
	g_test_add_func ("/libnm/ip4_prefix_to_netmask", test_ip4_prefix_to_netmask);
	g_test_add_func ("/libnm/ip4_netmask_to_prefix", test_ip4_netmask_to_prefix);

	g_test_add_func ("/libnm/connection_changed_signal", test_connection_changed_signal);
	g_test_add_func ("/libnm/setting_connection_changed_signal", test_setting_connection_changed_signal);
	g_test_add_func ("/libnm/setting_bond_changed_signal", test_setting_bond_changed_signal);
	g_test_add_func ("/libnm/setting_ip4_changed_signal", test_setting_ip4_changed_signal);
	g_test_add_func ("/libnm/setting_ip6_changed_signal", test_setting_ip6_changed_signal);
	g_test_add_func ("/libnm/setting_vlan_changed_signal", test_setting_vlan_changed_signal);
	g_test_add_func ("/libnm/setting_vpn_changed_signal", test_setting_vpn_changed_signal);
	g_test_add_func ("/libnm/setting_wired_changed_signal", test_setting_wired_changed_signal);
	g_test_add_func ("/libnm/setting_wireless_changed_signal", test_setting_wireless_changed_signal);
	g_test_add_func ("/libnm/setting_wireless_security_changed_signal", test_setting_wireless_security_changed_signal);
	g_test_add_func ("/libnm/setting_802_1x_changed_signal", test_setting_802_1x_changed_signal);

	g_test_add_func ("/libnm/libnm_linking", test_libnm_linking);

	g_test_add_func ("/libnm/nm_utils_uuid_generate_from_string", test_nm_utils_uuid_generate_from_string);

	return g_test_run ();
}

