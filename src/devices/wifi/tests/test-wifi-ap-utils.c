/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
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
 * Copyright (C) 2011 Red Hat, Inc.
 *
 */

#include "nm-default.h"

#include <string.h>

#include "nm-wifi-ap-utils.h"

#include "nm-core-internal.h"

#include "nm-test-utils.h"

#define DEBUG 1

/*******************************************/

#define COMPARE(src, expected, success, error, edomain, ecode) \
{ \
	if (expected) { \
		if (!success) { \
			g_assert (error != NULL); \
			g_warning ("Failed to complete connection: %s", error->message); \
		} \
		g_assert (success == TRUE); \
		g_assert (error == NULL); \
\
		success = nm_connection_compare (src, expected, NM_SETTING_COMPARE_FLAG_EXACT); \
		if (success == FALSE && DEBUG) { \
			g_message ("\n- COMPLETED ---------------------------------\n"); \
			nm_connection_dump (src); \
			g_message ("+ EXPECTED ++++++++++++++++++++++++++++++++++++\n"); \
			nm_connection_dump (expected); \
			g_message ("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n"); \
		} \
		g_assert (success == TRUE); \
	} else { \
		if (success) { \
			g_message ("\n- COMPLETED ---------------------------------\n"); \
			nm_connection_dump (src); \
		} \
		g_assert (success == FALSE); \
		g_assert_error (error, edomain, ecode); \
	} \
 \
	g_clear_error (&error); \
}

static gboolean
complete_connection (const char *ssid,
                     const char *bssid,
                     NM80211Mode mode,
                     guint32 flags,
                     guint32 wpa_flags,
                     guint32 rsn_flags,
                     gboolean lock_bssid,
                     NMConnection *src,
                     GError **error)
{
	GByteArray *tmp;
	gboolean success;
	NMSettingWireless *s_wifi;

	/* Add a wifi setting if one doesn't exist */
	s_wifi = nm_connection_get_setting_wireless (src);
	if (!s_wifi) {
		s_wifi = (NMSettingWireless *) nm_setting_wireless_new ();
		nm_connection_add_setting (src, NM_SETTING (s_wifi));
	}

	tmp = g_byte_array_sized_new (strlen (ssid));
	g_byte_array_append (tmp, (const guint8 *) ssid, strlen (ssid));

	success = nm_ap_utils_complete_connection (tmp,
	                                           bssid,
	                                           mode,
	                                           flags,
	                                           wpa_flags,
	                                           rsn_flags,
	                                           src,
	                                           lock_bssid,
	                                           error);
	g_byte_array_free (tmp, TRUE);
	return success;
}

typedef struct {
	const char *key;
	const char *str;
	guint32     uint;
} KeyData;

static void
set_items (NMSetting *setting, const KeyData *items)
{
	const KeyData *item;
	GParamSpec *pspec;
	GBytes *tmp;

	for (item = items; item && item->key; item++) {
		g_assert (item->key);
		pspec = g_object_class_find_property (G_OBJECT_GET_CLASS (setting), item->key);
		g_assert (pspec);

		if (pspec->value_type == G_TYPE_STRING) {
			g_assert (item->uint == 0);
			if (item->str)
				g_object_set (G_OBJECT (setting), item->key, item->str, NULL);
		} else if (pspec->value_type == G_TYPE_UINT) {
			g_assert (item->str == NULL);
			g_object_set (G_OBJECT (setting), item->key, item->uint, NULL);
		} else if (pspec->value_type == G_TYPE_INT) {
			gint foo = (gint) item->uint;

			g_assert (item->str == NULL);
			g_object_set (G_OBJECT (setting), item->key, foo, NULL);
		} else if (pspec->value_type == G_TYPE_BOOLEAN) {
			gboolean foo = !! (item->uint);

			g_assert (item->str == NULL);
			g_object_set (G_OBJECT (setting), item->key, foo, NULL);
		} else if (pspec->value_type == G_TYPE_BYTES) {
			g_assert (item->str);
			tmp = g_bytes_new (item->str, strlen (item->str));
			g_object_set (G_OBJECT (setting), item->key, tmp, NULL);
			g_bytes_unref (tmp);
		} else {
			/* Special types, check based on property name */
			if (!strcmp (item->key, NM_SETTING_WIRELESS_SECURITY_PROTO))
				nm_setting_wireless_security_add_proto (NM_SETTING_WIRELESS_SECURITY (setting), item->str);
			else if (!strcmp (item->key, NM_SETTING_WIRELESS_SECURITY_PAIRWISE))
				nm_setting_wireless_security_add_pairwise (NM_SETTING_WIRELESS_SECURITY (setting), item->str);
			else if (!strcmp (item->key, NM_SETTING_WIRELESS_SECURITY_GROUP))
				nm_setting_wireless_security_add_group (NM_SETTING_WIRELESS_SECURITY (setting), item->str);
			else if (!strcmp (item->key, NM_SETTING_802_1X_EAP))
				nm_setting_802_1x_add_eap_method (NM_SETTING_802_1X (setting), item->str);
		}
	}
}

static NMSettingWireless *
fill_wifi_empty (NMConnection *connection)
{
	NMSettingWireless *s_wifi;

	s_wifi = nm_connection_get_setting_wireless (connection);
	if (!s_wifi) {
		s_wifi = (NMSettingWireless *) nm_setting_wireless_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_wifi));
	}
	return s_wifi;
}

static NMSettingWireless *
fill_wifi (NMConnection *connection, const KeyData items[])
{
	NMSettingWireless *s_wifi;

	s_wifi = nm_connection_get_setting_wireless (connection);
	if (!s_wifi) {
		s_wifi = (NMSettingWireless *) nm_setting_wireless_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_wifi));
	}

	set_items (NM_SETTING (s_wifi), items);
	return s_wifi;
}

static NMSettingWirelessSecurity *
fill_wsec (NMConnection *connection, const KeyData items[])
{
	NMSettingWirelessSecurity *s_wsec;

	s_wsec = nm_connection_get_setting_wireless_security (connection);
	if (!s_wsec) {
		s_wsec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_wsec));
	}

	set_items (NM_SETTING (s_wsec), items);
	return s_wsec;
}

static NMSetting8021x *
fill_8021x (NMConnection *connection, const KeyData items[])
{
	NMSetting8021x *s_8021x;

	s_8021x = nm_connection_get_setting_802_1x (connection);
	if (!s_8021x) {
		s_8021x = (NMSetting8021x *) nm_setting_802_1x_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_8021x));
	}

	set_items (NM_SETTING (s_8021x), items);
	return s_8021x;
}

static NMConnection *
create_basic (const char *ssid,
              const char *bssid,
              NM80211Mode mode)
{
	NMConnection *connection;
	NMSettingWireless *s_wifi = NULL;
	GBytes *tmp;

	connection = nm_simple_connection_new ();

	s_wifi = (NMSettingWireless *) nm_setting_wireless_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wifi));

	/* SSID */
	tmp = g_bytes_new (ssid, strlen (ssid));
	g_object_set (G_OBJECT (s_wifi), NM_SETTING_WIRELESS_SSID, tmp, NULL);
	g_bytes_unref (tmp);

	/* BSSID */
	if (bssid)
		g_object_set (G_OBJECT (s_wifi), NM_SETTING_WIRELESS_BSSID, bssid, NULL);

	if (mode == NM_802_11_MODE_INFRA)
		g_object_set (G_OBJECT (s_wifi), NM_SETTING_WIRELESS_MODE, "infrastructure", NULL);
	else if (mode == NM_802_11_MODE_ADHOC)
		g_object_set (G_OBJECT (s_wifi), NM_SETTING_WIRELESS_MODE, "adhoc", NULL);
	else
		g_assert_not_reached ();

	return connection;
}

/*******************************************/

static void
test_lock_bssid (void)
{
	NMConnection *src, *expected;
	const char *bssid = "01:02:03:04:05:06";
	const char *ssid = "blahblah";
	gboolean success;
	GError *error = NULL;

	src = nm_simple_connection_new ();
	success = complete_connection (ssid, bssid,
	                               NM_802_11_MODE_INFRA, NM_802_11_AP_FLAGS_NONE,
	                               NM_802_11_AP_SEC_NONE, NM_802_11_AP_SEC_NONE,
	                               TRUE,
	                               src, &error);
	expected = create_basic (ssid, bssid, NM_802_11_MODE_INFRA);
	COMPARE (src, expected, success, error, 0, 0);

	g_object_unref (src);
	g_object_unref (expected);
}

/*******************************************/

static void
test_open_ap_empty_connection (void)
{
	NMConnection *src, *expected;
	const char *bssid = "01:02:03:04:05:06";
	const char *ssid = "blahblah";
	gboolean success;
	GError *error = NULL;

	/* Test that an empty source connection is correctly filled with the
	 * SSID and Infra modes of the given AP details.
	 */

	src = nm_simple_connection_new ();
	success = complete_connection (ssid, bssid,
	                               NM_802_11_MODE_INFRA, NM_802_11_AP_FLAGS_NONE,
	                               NM_802_11_AP_SEC_NONE, NM_802_11_AP_SEC_NONE,
	                               FALSE,
	                               src, &error);
	expected = create_basic (ssid, NULL, NM_802_11_MODE_INFRA);
	COMPARE (src, expected, success, error, 0, 0);

	g_object_unref (src);
	g_object_unref (expected);
}

/*******************************************/

static void
test_open_ap_leap_connection_1 (gconstpointer add_wifi)
{
	NMConnection *src;
	const char *bssid = "01:02:03:04:05:06";
	const KeyData src_wsec[] = { { NM_SETTING_WIRELESS_SECURITY_LEAP_USERNAME, "Bill Smith", 0 }, { NULL } };
	gboolean success;
	GError *error = NULL;

	/* Test that a basic connection filled with a LEAP username is
	 * rejected when completion is attempted with an open AP.  LEAP requires
	 * the AP to have the Privacy bit set.
	 */

	src = nm_simple_connection_new ();
	if (add_wifi)
		fill_wifi_empty (src);
	fill_wsec (src, src_wsec);

	success = complete_connection ("blahblah", bssid,
	                               NM_802_11_MODE_INFRA, NM_802_11_AP_FLAGS_NONE,
	                               NM_802_11_AP_SEC_NONE, NM_802_11_AP_SEC_NONE,
	                               FALSE,
	                               src, &error);
	/* We expect failure */
	COMPARE (src, NULL, success, error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_SETTING);

	g_object_unref (src);
}

/*******************************************/

static void
test_open_ap_leap_connection_2 (void)
{
	NMConnection *src;
	const char *bssid = "01:02:03:04:05:06";
	const KeyData src_wsec[] = { { NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "ieee8021x", 0 }, { NULL } };
	gboolean success;
	GError *error = NULL;

	/* Test that a basic connection specifying IEEE8021x security (ie, Dynamic
	 * WEP or LEAP) is rejected when completion is attempted with an open AP.
	 */

	src = nm_simple_connection_new ();
	fill_wifi_empty (src);
	fill_wsec (src, src_wsec);

	success = complete_connection ("blahblah", bssid,
	                               NM_802_11_MODE_INFRA, NM_802_11_AP_FLAGS_NONE,
	                               NM_802_11_AP_SEC_NONE, NM_802_11_AP_SEC_NONE,
	                               FALSE,
	                               src, &error);
	/* We expect failure */
	COMPARE (src, NULL, success, error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_SETTING);

	g_object_unref (src);
}

/*******************************************/

static void
test_open_ap_wep_connection (gconstpointer add_wifi)
{
	NMConnection *src;
	const char *bssid = "01:02:03:04:05:06";
	const KeyData src_wsec[] = {
	    { NM_SETTING_WIRELESS_SECURITY_WEP_KEY0, "11111111111111111111111111", 0 },
	    { NM_SETTING_WIRELESS_SECURITY_WEP_TX_KEYIDX, NULL, 0 },
	    { NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "open", 0 },
	    { NULL } };
	gboolean success;
	GError *error = NULL;

	/* Test that a static WEP connection is rejected when completion is
	 * attempted with an open AP.
	 */

	src = nm_simple_connection_new ();
	if (add_wifi)
		fill_wifi_empty (src);
	fill_wsec (src, src_wsec);
	success = complete_connection ("blahblah", bssid,
	                               NM_802_11_MODE_INFRA, NM_802_11_AP_FLAGS_NONE,
	                               NM_802_11_AP_SEC_NONE, NM_802_11_AP_SEC_NONE,
	                               FALSE,
	                               src, &error);
	/* We expect failure */
	COMPARE (src, NULL, success, error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_SETTING);

	g_object_unref (src);
}

/*******************************************/

static void
test_ap_wpa_psk_connection_base (const char *key_mgmt,
                                 const char *auth_alg,
                                 guint32 flags,
                                 guint32 wpa_flags,
                                 guint32 rsn_flags,
                                 gboolean add_wifi,
                                 guint error_code,
                                 NMConnection *expected)
{
	NMConnection *src;
	const char *ssid = "blahblah";
	const char *bssid = "01:02:03:04:05:06";
	const KeyData exp_wifi[] = {
		{ NM_SETTING_WIRELESS_SSID, ssid, 0 },
		{ NM_SETTING_WIRELESS_MODE, "infrastructure", 0 },
		{ NULL } };
	const KeyData both_wsec[] = {
	    { NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, key_mgmt, 0 },
	    { NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, auth_alg, 0 },
	    { NM_SETTING_WIRELESS_SECURITY_PSK, "asdfasdfasdfasdfasdfafs", 0 },
	    { NULL } };
	gboolean success;
	GError *error = NULL;

	src = nm_simple_connection_new ();
	if (add_wifi)
		fill_wifi_empty (src);
	fill_wsec (src, both_wsec);
	success = complete_connection (ssid, bssid, NM_802_11_MODE_INFRA,
	                               flags, wpa_flags, rsn_flags,
	                               FALSE, src, &error);
	if (expected) {
		fill_wifi (expected, exp_wifi);
		fill_wsec (expected, both_wsec);
	}
	COMPARE (src, expected, success, error, NM_CONNECTION_ERROR, error_code);

	g_object_unref (src);
}

static void
test_open_ap_wpa_psk_connection_1 (void)
{
	/* Test that a WPA-PSK connection filling only the PSK itself and *not*
	 * filling the wifi setting is rejected when completion is attempted with
	 * an open AP.
	 */
	test_ap_wpa_psk_connection_base (NULL, NULL,
	                                 NM_802_11_AP_FLAGS_NONE,
	                                 NM_802_11_AP_SEC_NONE,
	                                 NM_802_11_AP_SEC_NONE,
	                                 FALSE,
	                                 NM_CONNECTION_ERROR_INVALID_SETTING,
	                                 NULL);
}

static void
test_open_ap_wpa_psk_connection_2 (void)
{
	/* Test that a WPA-PSK connection filling only the PSK itself and also
	 * filling the wifi setting is rejected when completion is attempted with
	 * an open AP.
	 */
	test_ap_wpa_psk_connection_base (NULL, NULL,
	                                 NM_802_11_AP_FLAGS_NONE,
	                                 NM_802_11_AP_SEC_NONE,
	                                 NM_802_11_AP_SEC_NONE,
	                                 TRUE,
	                                 NM_CONNECTION_ERROR_INVALID_SETTING,
	                                 NULL);
}

static void
test_open_ap_wpa_psk_connection_3 (void)
{
	/* Test that a WPA-PSK connection filling the PSK and setting the auth alg
	 * to 'open' is rejected when completion is attempted with an open AP.
	 */
	test_ap_wpa_psk_connection_base (NULL, "open",
	                                 NM_802_11_AP_FLAGS_NONE,
	                                 NM_802_11_AP_SEC_NONE,
	                                 NM_802_11_AP_SEC_NONE,
	                                 FALSE,
	                                 NM_CONNECTION_ERROR_INVALID_SETTING,
	                                 NULL);
}

static void
test_open_ap_wpa_psk_connection_4 (void)
{
	/* Test that a WPA-PSK connection filling the PSK and setting the auth alg
	 * to 'shared' is rejected when completion is attempted with an open AP.
	 * Shared auth cannot be used with WPA.
	 */
	test_ap_wpa_psk_connection_base (NULL, "shared",
	                                 NM_802_11_AP_FLAGS_NONE,
	                                 NM_802_11_AP_SEC_NONE,
	                                 NM_802_11_AP_SEC_NONE,
	                                 FALSE,
	                                 NM_CONNECTION_ERROR_INVALID_SETTING,
	                                 NULL);
}

static void
test_open_ap_wpa_psk_connection_5 (void)
{
	/* Test that a WPA-PSK connection filling the PSK, the auth algorithm, and
	 * key management is rejected when completion is attempted with an open AP.
	 */
	test_ap_wpa_psk_connection_base ("wpa-psk", "open",
	                                 NM_802_11_AP_FLAGS_NONE,
	                                 NM_802_11_AP_SEC_NONE,
	                                 NM_802_11_AP_SEC_NONE,
	                                 FALSE,
	                                 NM_CONNECTION_ERROR_INVALID_SETTING,
	                                 NULL);
}

/*******************************************/

static void
test_ap_wpa_eap_connection_base (const char *key_mgmt,
                                 const char *auth_alg,
                                 guint32 flags,
                                 guint32 wpa_flags,
                                 guint32 rsn_flags,
                                 gboolean add_wifi,
                                 guint error_code)
{
	NMConnection *src;
	const char *bssid = "01:02:03:04:05:06";
	const KeyData src_empty[] = { { NULL } };
	const KeyData src_wsec[] = {
	    { NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, key_mgmt, 0 },
	    { NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, auth_alg, 0 },
	    { NULL } };
	gboolean success;
	GError *error = NULL;

	src = nm_simple_connection_new ();
	if (add_wifi)
		fill_wifi_empty (src);
	fill_wsec (src, src_wsec);
	fill_8021x (src, src_empty);
	success = complete_connection ("blahblah", bssid, NM_802_11_MODE_INFRA,
	                               flags, wpa_flags, rsn_flags,
	                               FALSE, src, &error);
	/* Failure expected */
	COMPARE (src, NULL, success, error, NM_CONNECTION_ERROR, error_code);

	g_object_unref (src);
}

enum {
	IDX_NONE = 0,
	IDX_OPEN,
	IDX_PRIV,
	IDX_WPA_PSK_PTKIP_GTKIP,
	IDX_WPA_PSK_PTKIP_PCCMP_GTKIP,
	IDX_WPA_RSN_PSK_PTKIP_PCCMP_GTKIP,
	IDX_WPA_RSN_PSK_PCCMP_GCCMP,
	IDX_RSN_PSK_PCCMP_GCCMP,
	IDX_RSN_PSK_PTKIP_PCCMP_GTKIP,
	IDX_WPA_8021X,
	IDX_RSN_8021X,
};

static guint32
flags_for_idx (guint32 idx)
{
	if (idx == IDX_OPEN)
		return NM_802_11_AP_FLAGS_NONE;
	else if (   idx == IDX_PRIV
	         || idx == IDX_WPA_PSK_PTKIP_GTKIP
	         || idx == IDX_WPA_PSK_PTKIP_PCCMP_GTKIP
	         || idx == IDX_RSN_PSK_PCCMP_GCCMP
	         || idx == IDX_RSN_PSK_PTKIP_PCCMP_GTKIP
	         || idx == IDX_WPA_RSN_PSK_PTKIP_PCCMP_GTKIP
	         || idx == IDX_WPA_RSN_PSK_PCCMP_GCCMP
	         || idx == IDX_WPA_8021X
	         || idx == IDX_RSN_8021X)
		return NM_802_11_AP_FLAGS_PRIVACY;
	else
		g_assert_not_reached ();
}

static guint32
wpa_flags_for_idx (guint32 idx)
{
	if (idx == IDX_OPEN || idx == IDX_PRIV ||  idx == IDX_RSN_8021X
	    || idx == IDX_RSN_PSK_PCCMP_GCCMP || idx == IDX_RSN_PSK_PTKIP_PCCMP_GTKIP)
		return NM_802_11_AP_SEC_NONE;
	else if (idx == IDX_WPA_PSK_PTKIP_GTKIP)
		return NM_802_11_AP_SEC_PAIR_TKIP | NM_802_11_AP_SEC_GROUP_TKIP | NM_802_11_AP_SEC_KEY_MGMT_PSK;
	else if (idx == IDX_WPA_RSN_PSK_PTKIP_PCCMP_GTKIP)
		return NM_802_11_AP_SEC_PAIR_TKIP | NM_802_11_AP_SEC_PAIR_CCMP | NM_802_11_AP_SEC_GROUP_TKIP | NM_802_11_AP_SEC_KEY_MGMT_PSK;
	else if (NM_IN_SET (idx, IDX_WPA_PSK_PTKIP_PCCMP_GTKIP, IDX_WPA_RSN_PSK_PCCMP_GCCMP))
		return NM_802_11_AP_SEC_PAIR_CCMP | NM_802_11_AP_SEC_GROUP_CCMP | NM_802_11_AP_SEC_KEY_MGMT_PSK;
	else if (idx == IDX_WPA_8021X)
		return NM_802_11_AP_SEC_PAIR_TKIP | NM_802_11_AP_SEC_GROUP_TKIP | NM_802_11_AP_SEC_KEY_MGMT_802_1X;
	else
		g_assert_not_reached ();
}

static guint32
rsn_flags_for_idx (guint32 idx)
{
	if (idx == IDX_OPEN || idx == IDX_PRIV || idx == IDX_WPA_8021X
	    || idx == IDX_WPA_PSK_PTKIP_GTKIP || idx == IDX_WPA_PSK_PTKIP_PCCMP_GTKIP)
		return NM_802_11_AP_SEC_NONE;
	else if (idx == IDX_RSN_PSK_PCCMP_GCCMP)
		return NM_802_11_AP_SEC_PAIR_CCMP | NM_802_11_AP_SEC_GROUP_CCMP | NM_802_11_AP_SEC_KEY_MGMT_PSK;
	else if (idx == IDX_RSN_PSK_PTKIP_PCCMP_GTKIP)
		return NM_802_11_AP_SEC_PAIR_TKIP | NM_802_11_AP_SEC_PAIR_CCMP | NM_802_11_AP_SEC_GROUP_TKIP | NM_802_11_AP_SEC_KEY_MGMT_PSK;
	else if (idx == IDX_WPA_RSN_PSK_PTKIP_PCCMP_GTKIP)
		return NM_802_11_AP_SEC_PAIR_TKIP | NM_802_11_AP_SEC_PAIR_CCMP | NM_802_11_AP_SEC_GROUP_TKIP | NM_802_11_AP_SEC_KEY_MGMT_PSK;
	else if (idx == IDX_WPA_RSN_PSK_PCCMP_GCCMP)
		return NM_802_11_AP_SEC_PAIR_CCMP | NM_802_11_AP_SEC_GROUP_CCMP | NM_802_11_AP_SEC_KEY_MGMT_PSK;
	else if (idx == IDX_RSN_8021X)
		return NM_802_11_AP_SEC_PAIR_CCMP | NM_802_11_AP_SEC_GROUP_CCMP | NM_802_11_AP_SEC_KEY_MGMT_802_1X;
	else
		g_assert_not_reached ();
}

static guint32
error_code_for_idx (guint32 idx, guint num)
{
	if (idx == IDX_OPEN)
		return NM_CONNECTION_ERROR_INVALID_SETTING;
	else if (idx == IDX_PRIV) {
		if (num <= 3)
			return NM_CONNECTION_ERROR_MISSING_PROPERTY;
		else
			return NM_CONNECTION_ERROR_INVALID_PROPERTY;
	} else if (   idx == IDX_WPA_PSK_PTKIP_GTKIP || idx == IDX_WPA_PSK_PTKIP_PCCMP_GTKIP
	           || idx == IDX_WPA_RSN_PSK_PCCMP_GCCMP || idx == IDX_WPA_RSN_PSK_PTKIP_PCCMP_GTKIP
	           || idx == IDX_RSN_PSK_PTKIP_PCCMP_GTKIP || idx == IDX_RSN_PSK_PCCMP_GCCMP)
		if (num == 4)
			return NM_CONNECTION_ERROR_INVALID_PROPERTY;
		else
			return NM_CONNECTION_ERROR_INVALID_SETTING;
	else
		g_assert_not_reached ();
}

static void
test_ap_wpa_eap_connection_1 (gconstpointer data)
{
	guint idx = GPOINTER_TO_UINT (data);

	test_ap_wpa_eap_connection_base (NULL, NULL,
	                                 flags_for_idx (idx),
	                                 wpa_flags_for_idx (idx),
	                                 rsn_flags_for_idx (idx),
	                                 FALSE,
	                                 error_code_for_idx (idx, 1));
}

static void
test_ap_wpa_eap_connection_2 (gconstpointer data)
{
	guint idx = GPOINTER_TO_UINT (data);

	test_ap_wpa_eap_connection_base (NULL, NULL,
	                                 flags_for_idx (idx),
	                                 wpa_flags_for_idx (idx),
	                                 rsn_flags_for_idx (idx),
	                                 TRUE,
	                                 error_code_for_idx (idx, 2));
}

static void
test_ap_wpa_eap_connection_3 (gconstpointer data)
{
	guint idx = GPOINTER_TO_UINT (data);

	test_ap_wpa_eap_connection_base (NULL, "open",
	                                 flags_for_idx (idx),
	                                 wpa_flags_for_idx (idx),
	                                 rsn_flags_for_idx (idx),
	                                 FALSE,
	                                 error_code_for_idx (idx, 3));
}

static void
test_ap_wpa_eap_connection_4 (gconstpointer data)
{
	guint idx = GPOINTER_TO_UINT (data);

	test_ap_wpa_eap_connection_base (NULL, "shared",
	                                 flags_for_idx (idx),
	                                 wpa_flags_for_idx (idx),
	                                 rsn_flags_for_idx (idx),
	                                 FALSE,
	                                 error_code_for_idx (idx, 4));
}

static void
test_ap_wpa_eap_connection_5 (gconstpointer data)
{
	guint idx = GPOINTER_TO_UINT (data);

	test_ap_wpa_eap_connection_base ("wpa-eap", "open",
	                                 flags_for_idx (idx),
	                                 wpa_flags_for_idx (idx),
	                                 rsn_flags_for_idx (idx),
	                                 FALSE,
	                                 error_code_for_idx (idx, 5));
}

/*******************************************/

static void
test_priv_ap_empty_connection (void)
{
	NMConnection *src, *expected;
	const char *bssid = "01:02:03:04:05:06";
	const char *ssid = "blahblah";
	const KeyData exp_wsec[] = {
	    { NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "none", 0 },
	    { NULL } };
	gboolean success;
	GError *error = NULL;

	/* Test that an empty connection is completed to a valid Static WEP
	 * connection when completed with an AP with the Privacy bit set.
	 */

	src = nm_simple_connection_new ();
	success = complete_connection (ssid, bssid,
	                               NM_802_11_MODE_INFRA, NM_802_11_AP_FLAGS_PRIVACY,
	                               NM_802_11_AP_SEC_NONE, NM_802_11_AP_SEC_NONE,
	                               FALSE,
	                               src, &error);

	/* Static WEP connection expected */
	expected = create_basic (ssid, NULL, NM_802_11_MODE_INFRA);
	fill_wsec (expected, exp_wsec);
	COMPARE (src, expected, success, error, 0, 0);

	g_object_unref (src);
	g_object_unref (expected);
}

/*******************************************/

static void
test_priv_ap_leap_connection_1 (gconstpointer add_wifi)
{
	NMConnection *src, *expected;
	const char *ssid = "blahblah";
	const char *bssid = "01:02:03:04:05:06";
	const char *leap_username = "Bill Smith";
	const KeyData src_wsec[] = {
	    { NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "ieee8021x", 0 },
	    { NM_SETTING_WIRELESS_SECURITY_LEAP_USERNAME, leap_username, 0 },
	    { NULL } };
	const KeyData exp_wsec[] = {
	    { NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "ieee8021x", 0 },
	    { NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "leap", 0 },
	    { NM_SETTING_WIRELESS_SECURITY_LEAP_USERNAME, leap_username, 0 },
	    { NULL } };
	gboolean success;
	GError *error = NULL;

	/* Test that an minimal LEAP connection specifying only key management and
	 * the LEAP username is completed to a full LEAP connection when completed
	 * with an AP with the Privacy bit set.
	 */

	src = nm_simple_connection_new ();
	if (add_wifi)
		fill_wifi_empty (src);
	fill_wsec (src, src_wsec);
	success = complete_connection (ssid, bssid,
	                               NM_802_11_MODE_INFRA, NM_802_11_AP_FLAGS_PRIVACY,
	                               NM_802_11_AP_SEC_NONE, NM_802_11_AP_SEC_NONE,
	                               FALSE,
	                               src, &error);
	/* We expect success here; since LEAP APs just set the 'privacy' flag
	 * there's no way to determine from the AP's beacon whether it's static WEP,
	 * dynamic WEP, or LEAP.
	 */
	expected = create_basic (ssid, NULL, NM_802_11_MODE_INFRA);
	fill_wsec (expected, exp_wsec);
	COMPARE (src, expected, success, error, 0, 0);

	g_object_unref (src);
	g_object_unref (expected);
}

/*******************************************/

static void
test_priv_ap_leap_connection_2 (void)
{
	NMConnection *src;
	const char *bssid = "01:02:03:04:05:06";
	const KeyData src_wsec[] = {
	    { NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "ieee8021x", 0 },
	    { NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "leap", 0 },
	    { NULL } };
	gboolean success;
	GError *error = NULL;

	/* Test that an minimal LEAP connection specifying only key management and
	 * the LEAP auth alg is completed to a full LEAP connection when completed
	 * with an AP with the Privacy bit set.
	 */

	src = nm_simple_connection_new ();
	fill_wifi_empty (src);
	fill_wsec (src, src_wsec);
	success = complete_connection ("blahblah", bssid,
	                               NM_802_11_MODE_INFRA, NM_802_11_AP_FLAGS_PRIVACY,
	                               NM_802_11_AP_SEC_NONE, NM_802_11_AP_SEC_NONE,
	                               FALSE,
	                               src, &error);
	/* We expect failure here, we need a LEAP username */
	COMPARE (src, NULL, success, error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_MISSING_PROPERTY);

	g_object_unref (src);
}

/*******************************************/

static void
test_priv_ap_dynamic_wep_1 (void)
{
	NMConnection *src, *expected;
	const char *ssid = "blahblah";
	const char *bssid = "01:02:03:04:05:06";
	const KeyData src_wsec[] = {
	    { NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "ieee8021x", 0 },
	    { NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "open", 0 },
	    { NULL } };
	const KeyData both_8021x[] = {
	    { NM_SETTING_802_1X_EAP, "peap", 0 },
	    { NM_SETTING_802_1X_IDENTITY, "Bill Smith", 0 },
	    { NM_SETTING_802_1X_PHASE2_AUTH, "mschapv2", 0 },
	    { NULL } };
	const KeyData exp_wsec[] = {
	    { NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "ieee8021x", 0 },
	    { NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "open", 0 },
	    { NULL } };
	gboolean success;
	GError *error = NULL;

	/* Test that an minimal Dynamic WEP connection specifying key management,
	 * the auth algorithm, and valid 802.1x setting is completed to a valid
	 * Dynamic WEP connection when completed with an AP with the Privacy bit set.
	 */

	src = nm_simple_connection_new ();
	fill_wifi_empty (src);
	fill_wsec (src, src_wsec);
	fill_8021x (src, both_8021x);
	success = complete_connection (ssid, bssid,
	                               NM_802_11_MODE_INFRA, NM_802_11_AP_FLAGS_PRIVACY,
	                               NM_802_11_AP_SEC_NONE, NM_802_11_AP_SEC_NONE,
	                               FALSE,
	                               src, &error);

	/* We expect a completed Dynamic WEP connection */
	expected = create_basic (ssid, NULL, NM_802_11_MODE_INFRA);
	fill_wsec (expected, exp_wsec);
	fill_8021x (expected, both_8021x);
	COMPARE (src, expected, success, error, 0, 0);

	g_object_unref (src);
	g_object_unref (expected);
}

/*******************************************/

static void
test_priv_ap_dynamic_wep_2 (void)
{
	NMConnection *src, *expected;
	const char *ssid = "blahblah";
	const char *bssid = "01:02:03:04:05:06";
	const KeyData src_wsec[] = {
	    { NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "open", 0 },
	    { NULL } };
	const KeyData both_8021x[] = {
	    { NM_SETTING_802_1X_EAP, "peap", 0 },
	    { NM_SETTING_802_1X_IDENTITY, "Bill Smith", 0 },
	    { NM_SETTING_802_1X_PHASE2_AUTH, "mschapv2", 0 },
	    { NULL } };
	const KeyData exp_wsec[] = {
	    { NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "ieee8021x", 0 },
	    { NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "open", 0 },
	    { NULL } };
	gboolean success;
	GError *error = NULL;

	/* Test that an minimal Dynamic WEP connection specifying only the auth
	 * algorithm and a valid 802.1x setting is completed to a valid Dynamic
	 * WEP connection when completed with an AP with the Privacy bit set.
	 */

	src = nm_simple_connection_new ();
	fill_wifi_empty (src);
	fill_wsec (src, src_wsec);
	fill_8021x (src, both_8021x);
	success = complete_connection (ssid, bssid,
	                               NM_802_11_MODE_INFRA, NM_802_11_AP_FLAGS_PRIVACY,
	                               NM_802_11_AP_SEC_NONE, NM_802_11_AP_SEC_NONE,
	                               FALSE,
	                               src, &error);

	/* We expect a completed Dynamic WEP connection */
	expected = create_basic (ssid, NULL, NM_802_11_MODE_INFRA);
	fill_wsec (expected, exp_wsec);
	fill_8021x (expected, both_8021x);
	COMPARE (src, expected, success, error, 0, 0);

	g_object_unref (src);
	g_object_unref (expected);
}

/*******************************************/

static void
test_priv_ap_dynamic_wep_3 (void)
{
	NMConnection *src;
	const char *bssid = "01:02:03:04:05:06";
	const KeyData src_wsec[] = {
	    { NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "shared", 0 },
	    { NULL } };
	const KeyData src_8021x[] = {
	    { NM_SETTING_802_1X_EAP, "peap", 0 },
	    { NM_SETTING_802_1X_IDENTITY, "Bill Smith", 0 },
	    { NM_SETTING_802_1X_PHASE2_AUTH, "mschapv2", 0 },
	    { NULL } };
	gboolean success;
	GError *error = NULL;

	/* Ensure that a basic connection specifying 'shared' auth and an 802.1x
	 * setting is rejected, as 802.1x is incompatible with 'shared' auth.
	 */

	src = nm_simple_connection_new ();
	fill_wifi_empty (src);
	fill_wsec (src, src_wsec);
	fill_8021x (src, src_8021x);
	success = complete_connection ("blahblah", bssid,
	                               NM_802_11_MODE_INFRA, NM_802_11_AP_FLAGS_PRIVACY,
	                               NM_802_11_AP_SEC_NONE, NM_802_11_AP_SEC_NONE,
	                               FALSE,
	                               src, &error);
	/* Expect failure; shared is not compatible with dynamic WEP */
	COMPARE (src, NULL, success, error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY);

	g_object_unref (src);
}

/*******************************************/

static void
test_priv_ap_wpa_psk_connection_1 (void)
{
	/* Test that a basic WPA-PSK connection is rejected when completion is
	 * attempted with an AP with just the Privacy bit set.  Lack of WPA/RSN
	 * flags means the AP provides Static/Dynamic WEP or LEAP, not WPA.
	 */
	test_ap_wpa_psk_connection_base (NULL, NULL,
	                                 NM_802_11_AP_FLAGS_PRIVACY,
	                                 NM_802_11_AP_SEC_NONE,
	                                 NM_802_11_AP_SEC_NONE,
	                                 FALSE,
	                                 NM_CONNECTION_ERROR_INVALID_PROPERTY,
	                                 NULL);
}

static void
test_priv_ap_wpa_psk_connection_2 (void)
{
	/* Test that a basic WPA-PSK connection is rejected when completion is
	 * attempted with an AP with just the Privacy bit set.  Lack of WPA/RSN
	 * flags means the AP provides Static/Dynamic WEP or LEAP, not WPA.
	 */
	test_ap_wpa_psk_connection_base (NULL, NULL,
	                                 NM_802_11_AP_FLAGS_PRIVACY,
	                                 NM_802_11_AP_SEC_NONE,
	                                 NM_802_11_AP_SEC_NONE,
	                                 TRUE,
	                                 NM_CONNECTION_ERROR_INVALID_PROPERTY,
	                                 NULL);
}

static void
test_priv_ap_wpa_psk_connection_3 (void)
{
	/* Test that a basic WPA-PSK connection specifying only the auth algorithm
	 * is rejected when completion is attempted with an AP with just the Privacy
	 * bit set.  Lack of WPA/RSN flags means the AP provides Static/Dynamic WEP
	 * or LEAP, not WPA.
	 */
	test_ap_wpa_psk_connection_base (NULL, "open",
	                                 NM_802_11_AP_FLAGS_PRIVACY,
	                                 NM_802_11_AP_SEC_NONE,
	                                 NM_802_11_AP_SEC_NONE,
	                                 FALSE,
	                                 NM_CONNECTION_ERROR_INVALID_PROPERTY,
	                                 NULL);
}

static void
test_priv_ap_wpa_psk_connection_4 (void)
{
	/* Test that a basic WPA-PSK connection specifying only the auth algorithm
	 * is rejected when completion is attempted with an AP with just the Privacy
	 * bit set.  Lack of WPA/RSN flags means the AP provides Static/Dynamic WEP
	 * or LEAP, not WPA.  Second, 'shared' auth is incompatible with WPA.
	 */
	test_ap_wpa_psk_connection_base (NULL, "shared",
	                                 NM_802_11_AP_FLAGS_PRIVACY,
	                                 NM_802_11_AP_SEC_NONE,
	                                 NM_802_11_AP_SEC_NONE,
	                                 FALSE,
	                                 NM_CONNECTION_ERROR_INVALID_PROPERTY,
	                                 NULL);
}

static void
test_priv_ap_wpa_psk_connection_5 (void)
{
	/* Test that a WPA-PSK connection specifying both the key management and
	 * auth algorithm is rejected when completion is attempted with an AP with
	 * just the Privacy bit set.  Lack of WPA/RSN flags means the AP provides
	 * Static/Dynamic WEP or LEAP, not WPA.
	 */
	test_ap_wpa_psk_connection_base ("wpa-psk", "open",
	                                 NM_802_11_AP_FLAGS_PRIVACY,
	                                 NM_802_11_AP_SEC_NONE,
	                                 NM_802_11_AP_SEC_NONE,
	                                 FALSE,
	                                 NM_CONNECTION_ERROR_INVALID_PROPERTY,
	                                 NULL);
}

/*******************************************/

static void
test_wpa_ap_empty_connection (gconstpointer data)
{
	guint idx = GPOINTER_TO_UINT (data);
	NMConnection *src, *expected;
	const char *bssid = "01:02:03:04:05:06";
	const char *ssid = "blahblah";
	const KeyData exp_wsec[] = {
	    { NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "wpa-psk", 0 },
	    { NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "open", 0 },
	    { NULL } };
	gboolean success;
	GError *error = NULL;

	/* Test that a basic WPA-PSK connection specifying just key management and
	 * the auth algorithm is completed successfully when given an AP with WPA
	 * or RSN flags.
	 */

	src = nm_simple_connection_new ();
	success = complete_connection (ssid, bssid,
	                               NM_802_11_MODE_INFRA, NM_802_11_AP_FLAGS_PRIVACY,
	                               wpa_flags_for_idx (idx),
	                               rsn_flags_for_idx (idx),
	                               FALSE, src, &error);

	/* WPA connection expected */
	expected = create_basic (ssid, NULL, NM_802_11_MODE_INFRA);
	fill_wsec (expected, exp_wsec);
	COMPARE (src, expected, success, error, 0, 0);

	g_object_unref (src);
	g_object_unref (expected);
}

/*******************************************/

static void
test_wpa_ap_leap_connection_1 (gconstpointer data)
{
	guint idx = GPOINTER_TO_UINT (data);
	NMConnection *src;
	const char *ssid = "blahblah";
	const char *bssid = "01:02:03:04:05:06";
	const char *leap_username = "Bill Smith";
	const KeyData src_wsec[] = {
	    { NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "ieee8021x", 0 },
	    { NM_SETTING_WIRELESS_SECURITY_LEAP_USERNAME, leap_username, 0 },
	    { NULL } };
	gboolean success;
	GError *error = NULL;

	/* Test that completion of a LEAP connection with a WPA-enabled AP is
	 * rejected since WPA APs (usually) do not support LEAP.
	 */

	src = nm_simple_connection_new ();
	fill_wifi_empty (src);
	fill_wsec (src, src_wsec);
	success = complete_connection (ssid, bssid,
	                               NM_802_11_MODE_INFRA, NM_802_11_AP_FLAGS_PRIVACY,
	                               wpa_flags_for_idx (idx),
	                               rsn_flags_for_idx (idx),
	                               FALSE,
	                               src, &error);
	/* Expect failure here; WPA APs don't support old-school LEAP */
	COMPARE (src, NULL, success, error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY);

	g_object_unref (src);
}

/*******************************************/

static void
test_wpa_ap_leap_connection_2 (gconstpointer data)
{
	guint idx = GPOINTER_TO_UINT (data);
	NMConnection *src;
	const char *bssid = "01:02:03:04:05:06";
	const KeyData src_wsec[] = {
	    { NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "ieee8021x", 0 },
	    { NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "leap", 0 },
	    { NULL } };
	gboolean success;
	GError *error = NULL;

	/* Test that completion of a LEAP connection with a WPA-enabled AP is
	 * rejected since WPA APs (usually) do not support LEAP.
	 */

	src = nm_simple_connection_new ();
	fill_wifi_empty (src);
	fill_wsec (src, src_wsec);
	success = complete_connection ("blahblah", bssid,
	                               NM_802_11_MODE_INFRA, NM_802_11_AP_FLAGS_PRIVACY,
	                               wpa_flags_for_idx (idx),
	                               rsn_flags_for_idx (idx),
	                               FALSE,
	                               src, &error);
	/* We expect failure here, we need a LEAP username */
	COMPARE (src, NULL, success, error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY);

	g_object_unref (src);
}

/*******************************************/

static void
test_wpa_ap_dynamic_wep_connection (gconstpointer data)
{
	guint idx = GPOINTER_TO_UINT (data);
	NMConnection *src;
	const char *bssid = "01:02:03:04:05:06";
	const KeyData src_wsec[] = {
	    { NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "ieee8021x", 0 },
	    { NULL } };
	gboolean success;
	GError *error = NULL;

	/* Test that completion of a Dynamic WEP connection with a WPA-enabled AP is
	 * rejected since WPA APs (usually) do not support Dynamic WEP.
	 */

	src = nm_simple_connection_new ();
	fill_wifi_empty (src);
	fill_wsec (src, src_wsec);
	success = complete_connection ("blahblah", bssid,
	                               NM_802_11_MODE_INFRA, NM_802_11_AP_FLAGS_PRIVACY,
	                               wpa_flags_for_idx (idx),
	                               rsn_flags_for_idx (idx),
	                               FALSE,
	                               src, &error);
	/* We expect failure here since Dynamic WEP is incompatible with WPA */
	COMPARE (src, NULL, success, error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY);

	g_object_unref (src);
}

/*******************************************/

static void
test_wpa_ap_wpa_psk_connection_1 (gconstpointer data)
{
	guint idx = GPOINTER_TO_UINT (data);
	NMConnection *expected;
	const KeyData exp_wsec[] = {
	    { NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "wpa-psk", 0 },
	    { NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "open", 0 },
	    { NULL } };

	expected = nm_simple_connection_new ();
	fill_wsec (expected, exp_wsec);
	test_ap_wpa_psk_connection_base (NULL, NULL,
	                                 NM_802_11_AP_FLAGS_PRIVACY,
	                                 wpa_flags_for_idx (idx),
	                                 rsn_flags_for_idx (idx),
	                                 FALSE,
	                                 NM_CONNECTION_ERROR_INVALID_PROPERTY,
	                                 expected);
	g_object_unref (expected);
}

static void
test_wpa_ap_wpa_psk_connection_2 (gconstpointer data)
{
	guint idx = GPOINTER_TO_UINT (data);
	NMConnection *expected;
	const KeyData exp_wsec[] = {
	    { NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "wpa-psk", 0 },
	    { NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "open", 0 },
	    { NULL } };

	expected = nm_simple_connection_new ();
	fill_wsec (expected, exp_wsec);
	test_ap_wpa_psk_connection_base (NULL, NULL,
	                                 NM_802_11_AP_FLAGS_PRIVACY,
	                                 wpa_flags_for_idx (idx),
	                                 rsn_flags_for_idx (idx),
	                                 TRUE,
	                                 NM_CONNECTION_ERROR_INVALID_PROPERTY,
	                                 expected);
	g_object_unref (expected);
}

static void
test_wpa_ap_wpa_psk_connection_3 (gconstpointer data)
{
	guint idx = GPOINTER_TO_UINT (data);
	NMConnection *expected;
	const KeyData exp_wsec[] = {
	    { NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "wpa-psk", 0 },
	    { NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "open", 0 },
	    { NULL } };

	expected = nm_simple_connection_new ();
	fill_wsec (expected, exp_wsec);
	test_ap_wpa_psk_connection_base (NULL, "open",
	                                 NM_802_11_AP_FLAGS_PRIVACY,
	                                 wpa_flags_for_idx (idx),
	                                 rsn_flags_for_idx (idx),
	                                 FALSE,
	                                 NM_CONNECTION_ERROR_INVALID_PROPERTY,
	                                 expected);
	g_object_unref (expected);
}

static void
test_wpa_ap_wpa_psk_connection_4 (gconstpointer data)
{
	guint idx = GPOINTER_TO_UINT (data);
	test_ap_wpa_psk_connection_base (NULL, "shared",
	                                 NM_802_11_AP_FLAGS_PRIVACY,
	                                 wpa_flags_for_idx (idx),
	                                 rsn_flags_for_idx (idx),
	                                 FALSE,
	                                 NM_CONNECTION_ERROR_INVALID_PROPERTY,
	                                 NULL);
}

static void
test_wpa_ap_wpa_psk_connection_5 (gconstpointer data)
{
	guint idx = GPOINTER_TO_UINT (data);
	NMConnection *expected;
	const KeyData exp_wsec[] = {
	    { NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "wpa-psk", 0 },
	    { NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "open", 0 },
	    { NULL } };

	expected = nm_simple_connection_new ();
	fill_wsec (expected, exp_wsec);
	test_ap_wpa_psk_connection_base ("wpa-psk", "open",
	                                 NM_802_11_AP_FLAGS_PRIVACY,
	                                 wpa_flags_for_idx (idx),
	                                 rsn_flags_for_idx (idx),
	                                 FALSE,
	                                 NM_CONNECTION_ERROR_INVALID_PROPERTY,
	                                 expected);
	g_object_unref (expected);
}

/*******************************************/

static void
test_strength_dbm (void)
{
	/* boundary conditions first */
	g_assert_cmpint (nm_ap_utils_level_to_quality (-1), ==, 100);
	g_assert_cmpint (nm_ap_utils_level_to_quality (-40), ==, 100);
	g_assert_cmpint (nm_ap_utils_level_to_quality (-30), ==, 100);
	g_assert_cmpint (nm_ap_utils_level_to_quality (-100), ==, 0);
	g_assert_cmpint (nm_ap_utils_level_to_quality (-200), ==, 0);

	g_assert_cmpint (nm_ap_utils_level_to_quality (-81), ==, 32);
	g_assert_cmpint (nm_ap_utils_level_to_quality (-92), ==, 14);
	g_assert_cmpint (nm_ap_utils_level_to_quality (-74), ==, 44);
	g_assert_cmpint (nm_ap_utils_level_to_quality (-81), ==, 32);
	g_assert_cmpint (nm_ap_utils_level_to_quality (-66), ==, 57);
}

static void
test_strength_percent (void)
{
	int i;

	/* boundary conditions first */
	g_assert_cmpint (nm_ap_utils_level_to_quality (0), ==, 0);
	g_assert_cmpint (nm_ap_utils_level_to_quality (100), ==, 100);
	g_assert_cmpint (nm_ap_utils_level_to_quality (110), ==, 100);

	for (i = 0; i <= 100; i++)
		g_assert_cmpint (nm_ap_utils_level_to_quality (i), ==, i);
}

static void
test_strength_wext (void)
{
	/* boundary conditions that we assume aren't WEXT first */
	g_assert_cmpint (nm_ap_utils_level_to_quality (256), ==, 100);
	g_assert_cmpint (nm_ap_utils_level_to_quality (110), ==, 100);

	/* boundary conditions that we assume are WEXT */
	g_assert_cmpint (nm_ap_utils_level_to_quality (111), ==, 0);
	g_assert_cmpint (nm_ap_utils_level_to_quality (150), ==, 0);
	g_assert_cmpint (nm_ap_utils_level_to_quality (225), ==, 100);
	g_assert_cmpint (nm_ap_utils_level_to_quality (255), ==, 100);

	g_assert_cmpint (nm_ap_utils_level_to_quality (157), ==, 2);
	g_assert_cmpint (nm_ap_utils_level_to_quality (200), ==, 74);
	g_assert_cmpint (nm_ap_utils_level_to_quality (215), ==, 99);
}

/*******************************************/

NMTST_DEFINE ();

int
main (int argc, char **argv)
{
	gsize i;

	nmtst_init_assert_logging (&argc, &argv, "INFO", "DEFAULT");

	g_test_add_func ("/wifi/lock_bssid",
	                 test_lock_bssid);

	/* Open AP tests; make sure that connections to be completed that have
	 * various security-related settings already set cause the completion
	 * to fail.
	 */
	g_test_add_func ("/wifi/open_ap/empty_connection",
	                 test_open_ap_empty_connection);
	g_test_add_data_func ("/wifi/open_ap/leap_connection/1",
	                      (gconstpointer) TRUE,
	                      test_open_ap_leap_connection_1);
	g_test_add_data_func ("/wifi/open_ap/leap_connection/1_no_add_wifi",
	                      (gconstpointer) FALSE,
	                      test_open_ap_leap_connection_1);
	g_test_add_func ("/wifi/open_ap/leap_connection/2",
	                 test_open_ap_leap_connection_2);
	g_test_add_data_func ("/wifi/open_ap/wep_connection_true",
	                      (gconstpointer) TRUE,
	                      test_open_ap_wep_connection);
	g_test_add_data_func ("/wifi/open_ap/wep_connection_false",
	                      (gconstpointer) FALSE,
	                      test_open_ap_wep_connection);

	g_test_add_func ("/wifi/open_ap/wpa_psk_connection/1",
	                 test_open_ap_wpa_psk_connection_1);
	g_test_add_func ("/wifi/open_ap/wpa_psk_connection/2",
	                 test_open_ap_wpa_psk_connection_2);
	g_test_add_func ("/wifi/open_ap/wpa_psk_connection/3",
	                 test_open_ap_wpa_psk_connection_3);
	g_test_add_func ("/wifi/open_ap/wpa_psk_connection/4",
	                 test_open_ap_wpa_psk_connection_4);
	g_test_add_func ("/wifi/open_ap/wpa_psk_connection/5",
	                 test_open_ap_wpa_psk_connection_5);

	g_test_add_data_func ("/wifi/open_ap/wpa_eap_connection/1",
	                      (gconstpointer) IDX_OPEN,
	                      test_ap_wpa_eap_connection_1);
	g_test_add_data_func ("/wifi/open_ap/wpa_eap_connection/2",
	                      (gconstpointer) IDX_OPEN,
	                      test_ap_wpa_eap_connection_2);
	g_test_add_data_func ("/wifi/open_ap/wpa_eap_connection/3",
	                      (gconstpointer) IDX_OPEN,
	                      test_ap_wpa_eap_connection_3);
	g_test_add_data_func ("/wifi/open_ap/wpa_eap_connection/4",
	                      (gconstpointer) IDX_OPEN,
	                      test_ap_wpa_eap_connection_4);
	g_test_add_data_func ("/wifi/open_ap/wpa_eap_connection/5",
	                      (gconstpointer) IDX_OPEN,
	                      test_ap_wpa_eap_connection_5);

	/* WEP AP tests */
	g_test_add_func ("/wifi/priv_ap/empty_connection",
	                 test_priv_ap_empty_connection);
	g_test_add_data_func ("/wifi/priv_ap/leap_connection/1",
	                      (gconstpointer) FALSE,
	                      test_priv_ap_leap_connection_1);
	g_test_add_func ("/wifi/priv_ap/leap_connection/2",
	                 test_priv_ap_leap_connection_2);

	g_test_add_func ("/wifi/priv_ap/dynamic_wep/1",
	                 test_priv_ap_dynamic_wep_1);
	g_test_add_func ("/wifi/priv_ap/dynamic_wep/2",
	                 test_priv_ap_dynamic_wep_2);
	g_test_add_func ("/wifi/priv_ap/dynamic_wep/3",
	                 test_priv_ap_dynamic_wep_3);

	g_test_add_func ("/wifi/priv_ap/wpa_psk_connection/1",
	                 test_priv_ap_wpa_psk_connection_1);
	g_test_add_func ("/wifi/priv_ap/wpa_psk_connection/2",
	                 test_priv_ap_wpa_psk_connection_2);
	g_test_add_func ("/wifi/priv_ap/wpa_psk_connection/3",
	                 test_priv_ap_wpa_psk_connection_3);
	g_test_add_func ("/wifi/priv_ap/wpa_psk_connection/4",
	                 test_priv_ap_wpa_psk_connection_4);
	g_test_add_func ("/wifi/priv_ap/wpa_psk_connection/5",
	                 test_priv_ap_wpa_psk_connection_5);

	g_test_add_data_func ("/wifi/priv_ap/wpa_eap_connection/1",
	                      (gconstpointer) IDX_PRIV,
	                      test_ap_wpa_eap_connection_1);
	g_test_add_data_func ("/wifi/priv_ap/wpa_eap_connection/2",
	                      (gconstpointer) IDX_PRIV,
	                      test_ap_wpa_eap_connection_2);
	g_test_add_data_func ("/wifi/priv_ap/wpa_eap_connection/3",
	                      (gconstpointer) IDX_PRIV,
	                      test_ap_wpa_eap_connection_3);
	g_test_add_data_func ("/wifi/priv_ap/wpa_eap_connection/4",
	                      (gconstpointer) IDX_PRIV,
	                      test_ap_wpa_eap_connection_4);
	g_test_add_data_func ("/wifi/priv_ap/wpa_eap_connection/5",
	                      (gconstpointer) IDX_PRIV,
	                      test_ap_wpa_eap_connection_5);

#define ADD_FUNC(func) do { \
		gchar *name_idx = g_strdup_printf ("/wifi/wpa_psk/" G_STRINGIFY (func) "/%zd", i); \
		g_test_add_data_func (name_idx, (gconstpointer) i, func); \
		g_free (name_idx); \
	} while (0)

	/* WPA-PSK tests */
	for (i = IDX_WPA_PSK_PTKIP_GTKIP; i <= IDX_WPA_RSN_PSK_PCCMP_GCCMP; i++) {
		ADD_FUNC(test_wpa_ap_empty_connection);
		ADD_FUNC(test_wpa_ap_leap_connection_1);
		ADD_FUNC(test_wpa_ap_leap_connection_2);
		ADD_FUNC(test_wpa_ap_dynamic_wep_connection);
		ADD_FUNC(test_wpa_ap_wpa_psk_connection_1);
		ADD_FUNC(test_wpa_ap_wpa_psk_connection_2);
		ADD_FUNC(test_wpa_ap_wpa_psk_connection_3);
		ADD_FUNC(test_wpa_ap_wpa_psk_connection_4);
		ADD_FUNC(test_wpa_ap_wpa_psk_connection_5);
		ADD_FUNC(test_ap_wpa_eap_connection_1);
		ADD_FUNC(test_ap_wpa_eap_connection_2);
		ADD_FUNC(test_ap_wpa_eap_connection_3);
		ADD_FUNC(test_ap_wpa_eap_connection_4);
		ADD_FUNC(test_ap_wpa_eap_connection_5);
	}

#undef ADD_FUNC
#define ADD_FUNC(func) do { \
		gchar *name_idx = g_strdup_printf ("/wifi/rsn_psk/" G_STRINGIFY (func) "/%zd", i); \
		g_test_add_data_func (name_idx, (gconstpointer) i, func); \
		g_free (name_idx); \
	} while (0)

	/* RSN-PSK tests */
	for (i = IDX_WPA_RSN_PSK_PTKIP_PCCMP_GTKIP; i <= IDX_RSN_PSK_PTKIP_PCCMP_GTKIP; i++) {
		ADD_FUNC(test_wpa_ap_empty_connection);
		ADD_FUNC(test_wpa_ap_leap_connection_1);
		ADD_FUNC(test_wpa_ap_leap_connection_2);
		ADD_FUNC(test_wpa_ap_dynamic_wep_connection);
		ADD_FUNC(test_wpa_ap_wpa_psk_connection_1);
		ADD_FUNC(test_wpa_ap_wpa_psk_connection_2);
		ADD_FUNC(test_wpa_ap_wpa_psk_connection_3);
		ADD_FUNC(test_wpa_ap_wpa_psk_connection_4);
		ADD_FUNC(test_wpa_ap_wpa_psk_connection_5);
		ADD_FUNC(test_ap_wpa_eap_connection_1);
		ADD_FUNC(test_ap_wpa_eap_connection_2);
		ADD_FUNC(test_ap_wpa_eap_connection_3);
		ADD_FUNC(test_ap_wpa_eap_connection_4);
		ADD_FUNC(test_ap_wpa_eap_connection_5);
	}

#undef ADD_FUNC

	/* Scanned signal strength conversion tests */
	g_test_add_func ("/wifi/strength/dbm",
	                 test_strength_dbm);
	g_test_add_func ("/wifi/strength/percent",
	                 test_strength_percent);
	g_test_add_func ("/wifi/strength/wext",
	                 test_strength_wext);

	return g_test_run ();
}
