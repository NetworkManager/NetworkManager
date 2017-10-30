/*-*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2011 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-wifi-utils.h"

#include <string.h>
#include <stdlib.h>

#include "nm-utils.h"

static gboolean
verify_no_wep (NMSettingWirelessSecurity *s_wsec, const char *tag, GError **error)
{
	if (   nm_setting_wireless_security_get_wep_key (s_wsec, 0)
	    || nm_setting_wireless_security_get_wep_key (s_wsec, 1)
	    || nm_setting_wireless_security_get_wep_key (s_wsec, 2)
	    || nm_setting_wireless_security_get_wep_key (s_wsec, 3)
	    || nm_setting_wireless_security_get_wep_tx_keyidx (s_wsec)
	    || nm_setting_wireless_security_get_wep_key_type (s_wsec)) {
		/* Dynamic WEP cannot have any WEP keys set */
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_SETTING,
		             _("%s is incompatible with static WEP keys"), tag);
		g_prefix_error (error, "%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME);
		return FALSE;
	}

	return TRUE;
}

static gboolean
verify_leap (NMSettingWirelessSecurity *s_wsec,
             NMSetting8021x *s_8021x,
             gboolean adhoc,
             GError **error)
{
	const char *key_mgmt, *auth_alg, *leap_username;

	key_mgmt = nm_setting_wireless_security_get_key_mgmt (s_wsec);
	auth_alg = nm_setting_wireless_security_get_auth_alg (s_wsec);
	leap_username = nm_setting_wireless_security_get_leap_username (s_wsec);

	/* One (or both) of two things indicates we want LEAP:
	 * 1) auth_alg == 'leap'
	 * 2) valid leap_username
     *
     * LEAP always requires a LEAP username.
	 */

	if (auth_alg) {
		if (!strcmp (auth_alg, "leap")) {
			/* LEAP authentication requires at least a LEAP username */
			if (!leap_username) {
				g_set_error_literal (error,
				                     NM_CONNECTION_ERROR,
				                     NM_CONNECTION_ERROR_MISSING_PROPERTY,
				                     _("LEAP authentication requires a LEAP username"));
				g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
				                NM_SETTING_WIRELESS_SECURITY_LEAP_USERNAME);
				return FALSE;
			}
		} else if (leap_username) {
			/* Leap username requires 'leap' auth */
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     _("LEAP username requires 'leap' authentication"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
			                NM_SETTING_WIRELESS_SECURITY_LEAP_USERNAME);
			return FALSE;
		}
	}

	if (leap_username) {
		if (key_mgmt && strcmp (key_mgmt, "ieee8021x")) {
			/* LEAP requires ieee8021x key management */
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     _("LEAP authentication requires IEEE 802.1x key management"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
			                NM_SETTING_WIRELESS_SECURITY_KEY_MGMT);
			return FALSE;
		}
	}

	/* At this point if auth_alg is set it must be 'leap', and if key_mgmt
	 * is set it must be 'ieee8021x'.
	 */
	if (leap_username) {
		if (auth_alg)
			g_assert (strcmp (auth_alg, "leap") == 0);
		if (key_mgmt)
			g_assert (strcmp (key_mgmt, "ieee8021x") == 0);

		if (adhoc) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_SETTING,
			                     _("LEAP authentication is incompatible with Ad-Hoc mode"));
			g_prefix_error (error, "%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME);
			return FALSE;
		}

		if (!verify_no_wep (s_wsec, "LEAP", error))
			return FALSE;

		if (s_8021x) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_SETTING,
			                     _("LEAP authentication is incompatible with 802.1x setting"));
			g_prefix_error (error, "%s: ", NM_SETTING_802_1X_SETTING_NAME);
			return FALSE;
		}
	}

	return TRUE;
}

static gboolean
verify_no_wpa (NMSettingWirelessSecurity *s_wsec,
               const char *tag,
               GError **error)
{
	const char *key_mgmt;
	int n, i;

	key_mgmt = nm_setting_wireless_security_get_key_mgmt (s_wsec);
	if (key_mgmt && !strncmp (key_mgmt, "wpa", 3)) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("a connection using '%s' authentication cannot use WPA key management"),
		             tag);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
		                NM_SETTING_WIRELESS_SECURITY_KEY_MGMT);
		return FALSE;
	}

	if (nm_setting_wireless_security_get_num_protos (s_wsec)) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("a connection using '%s' authentication cannot specify WPA protocols"),
		             tag);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
		                NM_SETTING_WIRELESS_SECURITY_PROTO);
		return FALSE;
	}

	n = nm_setting_wireless_security_get_num_pairwise (s_wsec);
	for (i = 0; i < n; i++) {
		const char *pw;

		pw = nm_setting_wireless_security_get_pairwise (s_wsec, i);
		if (!strcmp (pw, "tkip") || !strcmp (pw, "ccmp")) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("a connection using '%s' authentication cannot specify WPA ciphers"),
			             tag);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
			                NM_SETTING_WIRELESS_SECURITY_PAIRWISE);
			return FALSE;
		}
	}

	n = nm_setting_wireless_security_get_num_groups (s_wsec);
	for (i = 0; i < n; i++) {
		const char *gr;

		gr = nm_setting_wireless_security_get_group (s_wsec, i);
		if (strcmp (gr, "wep40") && strcmp (gr, "wep104")) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("a connection using '%s' authentication cannot specify WPA ciphers"),
			             tag);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
			                NM_SETTING_WIRELESS_SECURITY_GROUP);
			return FALSE;
		}
	}

	if (nm_setting_wireless_security_get_psk (s_wsec)) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("a connection using '%s' authentication cannot specify a WPA password"),
		             tag);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
		                NM_SETTING_WIRELESS_SECURITY_PSK);
		return FALSE;
	}

	return TRUE;
}

static gboolean
verify_dynamic_wep (NMSettingWirelessSecurity *s_wsec,
                    NMSetting8021x *s_8021x,
                    gboolean adhoc,
                    GError **error)
{
	const char *key_mgmt, *auth_alg, *leap_username;

	key_mgmt = nm_setting_wireless_security_get_key_mgmt (s_wsec);
	auth_alg = nm_setting_wireless_security_get_auth_alg (s_wsec);
	leap_username = nm_setting_wireless_security_get_leap_username (s_wsec);

	g_return_val_if_fail (leap_username == NULL, TRUE);

	if (key_mgmt) {
		if (!strcmp (key_mgmt, "ieee8021x")) {
			if (!s_8021x) {
				/* 802.1x key management requires an 802.1x setting */
				g_set_error_literal (error,
				                     NM_CONNECTION_ERROR,
				                     NM_CONNECTION_ERROR_MISSING_SETTING,
				                     _("Dynamic WEP requires an 802.1x setting"));
				g_prefix_error (error, "%s: ", NM_SETTING_802_1X_SETTING_NAME);
				return FALSE;
			}

			if (auth_alg && strcmp (auth_alg, "open")) {
				/* 802.1x key management must use "open" authentication */
				g_set_error_literal (error,
				                     NM_CONNECTION_ERROR,
				                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
				                     _("Dynamic WEP requires 'open' authentication"));
				g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
				                NM_SETTING_WIRELESS_SECURITY_AUTH_ALG);
				return FALSE;
			}

			/* Dynamic WEP incompatible with anything static WEP related */
			if (!verify_no_wep (s_wsec, "Dynamic WEP", error))
				return FALSE;
		} else if (!strcmp (key_mgmt, "none")) {
			if (s_8021x) {
				/* 802.1x setting requires 802.1x key management */
				g_set_error_literal (error,
				                     NM_CONNECTION_ERROR,
				                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
				                     _("Dynamic WEP requires 'ieee8021x' key management"));
				g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
				                NM_SETTING_WIRELESS_SECURITY_KEY_MGMT);
				return FALSE;
			}
		}
	} else if (s_8021x) {
		/* 802.1x setting incompatible with anything but 'open' auth */
		if (auth_alg && strcmp (auth_alg, "open")) {
			/* 802.1x key management must use "open" authentication */
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     _("Dynamic WEP requires 'open' authentication"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
			                NM_SETTING_WIRELESS_SECURITY_AUTH_ALG);
			return FALSE;
		}

		/* Dynamic WEP incompatible with anything static WEP related */
		if (!verify_no_wep (s_wsec, "Dynamic WEP", error))
			return FALSE;
	}

	return TRUE;
}

static gboolean
verify_wpa_psk (NMSettingWirelessSecurity *s_wsec,
                NMSetting8021x *s_8021x,
                gboolean adhoc,
                guint32 wpa_flags,
                guint32 rsn_flags,
                GError **error)
{
	const char *key_mgmt, *auth_alg, *tmp;
	int n;

	key_mgmt = nm_setting_wireless_security_get_key_mgmt (s_wsec);
	auth_alg = nm_setting_wireless_security_get_auth_alg (s_wsec);

	if (key_mgmt) {
		if (!strcmp (key_mgmt, "wpa-psk") || !strcmp (key_mgmt, "wpa-none")) {
			if (s_8021x) {
				g_set_error_literal (error,
				                     NM_CONNECTION_ERROR,
				                     NM_CONNECTION_ERROR_INVALID_SETTING,
				                     _("WPA-PSK authentication is incompatible with 802.1x"));
				g_prefix_error (error, "%s: ", NM_SETTING_802_1X_SETTING_NAME);
				return FALSE;
			}

			if (auth_alg && strcmp (auth_alg, "open")) {
				/* WPA must use "open" authentication */
				g_set_error_literal (error,
				                     NM_CONNECTION_ERROR,
				                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
				                     _("WPA-PSK requires 'open' authentication"));
				g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
				                NM_SETTING_WIRELESS_SECURITY_AUTH_ALG);
				return FALSE;
			}
		}

		if (!strcmp (key_mgmt, "wpa-none")) {
			if (!adhoc) {
				g_set_error_literal (error,
				                     NM_CONNECTION_ERROR,
				                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
				                     _("WPA Ad-Hoc authentication requires an Ad-Hoc mode AP"));
				g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SETTING_NAME,
				                NM_SETTING_WIRELESS_MODE);
				return FALSE;
			}

			/* Ad-Hoc WPA requires 'wpa' proto, 'none' pairwise, and 'tkip' group */
			n = nm_setting_wireless_security_get_num_protos (s_wsec);
			tmp = (n > 0) ? nm_setting_wireless_security_get_proto (s_wsec, 0) : NULL;
			if (n > 1 || !tmp || strcmp (tmp, "wpa")) {
				g_set_error_literal (error,
				                     NM_CONNECTION_ERROR,
				                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
				                     _("WPA Ad-Hoc authentication requires 'wpa' protocol"));
				g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
				                NM_SETTING_WIRELESS_SECURITY_PROTO);
				return FALSE;
			}

			n = nm_setting_wireless_security_get_num_pairwise (s_wsec);
			tmp = (n > 0) ? nm_setting_wireless_security_get_pairwise (s_wsec, 0) : NULL;
			if (n > 1 || g_strcmp0 (tmp, "none")) {
				g_set_error_literal (error,
				                     NM_CONNECTION_ERROR,
				                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
				                     _("WPA Ad-Hoc authentication requires 'none' pairwise cipher"));
				g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
				                NM_SETTING_WIRELESS_SECURITY_PAIRWISE);
				return FALSE;
			}

			n = nm_setting_wireless_security_get_num_groups (s_wsec);
			tmp = (n > 0) ? nm_setting_wireless_security_get_group (s_wsec, 0) : NULL;
			if (n > 1 || !tmp || strcmp (tmp, "tkip")) {
				g_set_error_literal (error,
				                     NM_CONNECTION_ERROR,
				                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
				                     _("WPA Ad-Hoc requires 'tkip' group cipher"));
				g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
				                NM_SETTING_WIRELESS_SECURITY_GROUP);
				return FALSE;
			}
		}

		if (!strcmp (key_mgmt, "wpa-psk")) {
			/* Make sure the AP's capabilities support WPA-PSK */
			if (   !(wpa_flags & NM_802_11_AP_SEC_KEY_MGMT_PSK)
			    && !(rsn_flags & NM_802_11_AP_SEC_KEY_MGMT_PSK)) {
				g_set_error_literal (error,
				                     NM_CONNECTION_ERROR,
				                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
				                     _("Access point does not support PSK but setting requires it"));
				g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
				                NM_SETTING_WIRELESS_SECURITY_KEY_MGMT);
				return FALSE;
			}
		}
	}

	return TRUE;
}

static gboolean
verify_wpa_eap (NMSettingWirelessSecurity *s_wsec,
                NMSetting8021x *s_8021x,
                guint32 wpa_flags,
                guint32 rsn_flags,
                GError **error)
{
	const char *key_mgmt, *auth_alg;
	gboolean is_wpa_eap = FALSE;

	key_mgmt = nm_setting_wireless_security_get_key_mgmt (s_wsec);
	auth_alg = nm_setting_wireless_security_get_auth_alg (s_wsec);

	if (key_mgmt) {
		if (!strcmp (key_mgmt, "wpa-eap")) {
			if (!s_8021x) {
				g_set_error_literal (error,
				                     NM_CONNECTION_ERROR,
				                     NM_CONNECTION_ERROR_MISSING_SETTING,
				                     _("WPA-EAP authentication requires an 802.1x setting"));
				g_prefix_error (error, "%s: ", NM_SETTING_802_1X_SETTING_NAME);
				return FALSE;
			}

			if (auth_alg && strcmp (auth_alg, "open")) {
				/* WPA must use "open" authentication */
				g_set_error_literal (error,
				                     NM_CONNECTION_ERROR,
				                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
				                     _("WPA-EAP requires 'open' authentication"));
				g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
				                NM_SETTING_WIRELESS_SECURITY_AUTH_ALG);
				return FALSE;
			}

			is_wpa_eap = TRUE;
		} else if (s_8021x) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_SETTING,
			                     _("802.1x setting requires 'wpa-eap' key management"));
			g_prefix_error (error, "%s: ", NM_SETTING_802_1X_SETTING_NAME);
			return FALSE;
		}
	}

	if (is_wpa_eap || s_8021x) {
		/* Make sure the AP's capabilities support WPA-EAP */
		if (   !(wpa_flags & NM_802_11_AP_SEC_KEY_MGMT_802_1X)
		    && !(rsn_flags & NM_802_11_AP_SEC_KEY_MGMT_802_1X)) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_SETTING,
			                     _("Access point does not support 802.1x but setting requires it"));
			g_prefix_error (error, "%s: ", NM_SETTING_802_1X_SETTING_NAME);
			return FALSE;
		}
	}

	return TRUE;
}

static gboolean
verify_adhoc (NMSettingWirelessSecurity *s_wsec,
              NMSetting8021x *s_8021x,
              gboolean adhoc,
              GError **error)
{
	const char *key_mgmt = NULL, *leap_username = NULL, *auth_alg = NULL;

	if (s_wsec) {
		key_mgmt = nm_setting_wireless_security_get_key_mgmt (s_wsec);
		auth_alg = nm_setting_wireless_security_get_auth_alg (s_wsec);
		leap_username = nm_setting_wireless_security_get_leap_username (s_wsec);
	}

	if (adhoc) {
		if (key_mgmt && strcmp (key_mgmt, "wpa-none") && strcmp (key_mgmt, "none")) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     _("Access point mode is Ad-Hoc but setting requires Infrastructure security"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
			                NM_SETTING_WIRELESS_SECURITY_KEY_MGMT);
			return FALSE;
		}

		if (s_8021x) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_SETTING,
			                     _("Ad-Hoc mode is incompatible with 802.1x security"));
			g_prefix_error (error, "%s: ", NM_SETTING_802_1X_SETTING_NAME);
			return FALSE;
		}

		if (leap_username) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     _("Ad-Hoc mode is incompatible with LEAP security"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
			                NM_SETTING_WIRELESS_SECURITY_AUTH_ALG);
			return FALSE;
		}

		if (auth_alg && strcmp (auth_alg, "open")) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     _("Ad-Hoc mode requires 'open' authentication"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
			                NM_SETTING_WIRELESS_SECURITY_AUTH_ALG);
			return FALSE;
		}
	} else {
		if (key_mgmt && !strcmp (key_mgmt, "wpa-none")) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     _("Access point mode is Infrastructure but setting requires Ad-Hoc security"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
			                NM_SETTING_WIRELESS_SECURITY_KEY_MGMT);
			return FALSE;
		}
	}

	return TRUE;
}

gboolean
nm_wifi_utils_complete_connection (const GByteArray *ap_ssid,
                                   const char *bssid,
                                   NM80211Mode ap_mode,
                                   guint32 ap_flags,
                                   guint32 ap_wpa_flags,
                                   guint32 ap_rsn_flags,
                                   NMConnection *connection,
                                   gboolean lock_bssid,
                                   GError **error)
{
	NMSettingWireless *s_wifi;
	NMSettingWirelessSecurity *s_wsec;
	NMSetting8021x *s_8021x;
	GBytes *ssid, *ap_ssid_bytes;
	const char *mode, *key_mgmt, *auth_alg, *leap_username;
	gboolean adhoc = FALSE;

	s_wifi = nm_connection_get_setting_wireless (connection);
	g_assert (s_wifi);
	s_wsec = nm_connection_get_setting_wireless_security (connection);
	s_8021x = nm_connection_get_setting_802_1x (connection);

	/* Fill in missing SSID */
	ap_ssid_bytes = ap_ssid ? g_bytes_new (ap_ssid->data, ap_ssid->len) : NULL;
	ssid = nm_setting_wireless_get_ssid (s_wifi);
	if (!ssid)
		g_object_set (G_OBJECT (s_wifi), NM_SETTING_WIRELESS_SSID, ap_ssid_bytes, NULL);
	else if (!ap_ssid_bytes || !g_bytes_equal (ssid, ap_ssid_bytes)) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("connection does not match access point"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SETTING_NAME, NM_SETTING_WIRELESS_SSID);
		g_bytes_unref (ap_ssid_bytes);
		return FALSE;
	}
	g_bytes_unref (ap_ssid_bytes);

	if (lock_bssid && !nm_setting_wireless_get_bssid (s_wifi))
		g_object_set (G_OBJECT (s_wifi), NM_SETTING_WIRELESS_BSSID, bssid, NULL);

	/* And mode */
	mode = nm_setting_wireless_get_mode (s_wifi);
	if (mode) {
		gboolean valid = FALSE;

		/* Make sure the supplied mode matches the AP's */
		if (   !strcmp (mode, NM_SETTING_WIRELESS_MODE_INFRA)
		    || !strcmp (mode, NM_SETTING_WIRELESS_MODE_AP)) {
			if (ap_mode == NM_802_11_MODE_INFRA)
				valid = TRUE;
		} else if (!strcmp (mode, NM_SETTING_WIRELESS_MODE_ADHOC)) {
			if (ap_mode == NM_802_11_MODE_ADHOC)
				valid = TRUE;
			adhoc = TRUE;
		}

		if (valid == FALSE) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("connection does not match access point"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SETTING_NAME, NM_SETTING_WIRELESS_MODE);
			return FALSE;
		}
	} else {
		mode = NM_SETTING_WIRELESS_MODE_INFRA;
		if (ap_mode == NM_802_11_MODE_ADHOC) {
			mode = NM_SETTING_WIRELESS_MODE_ADHOC;
			adhoc = TRUE;
		}
		g_object_set (G_OBJECT (s_wifi), NM_SETTING_WIRELESS_MODE, mode, NULL);
	}

	/* Security */

	/* Open */
	if (   !(ap_flags & NM_802_11_AP_FLAGS_PRIVACY)
	    && (ap_wpa_flags == NM_802_11_AP_SEC_NONE)
	    && (ap_rsn_flags == NM_802_11_AP_SEC_NONE)) {
		/* Make sure the connection doesn't specify security */
		if (s_wsec || s_8021x) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_SETTING,
			                     _("Access point is unencrypted but setting specifies security"));
			if (s_wsec)
				g_prefix_error (error, "%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME);
			else
				g_prefix_error (error, "%s: ", NM_SETTING_802_1X_SETTING_NAME);
			return FALSE;
		}
		return TRUE;
	}

	/* Everything else requires security */
	if (!s_wsec) {
		s_wsec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_wsec));
	}

	key_mgmt = nm_setting_wireless_security_get_key_mgmt (s_wsec);
	auth_alg = nm_setting_wireless_security_get_auth_alg (s_wsec);
	leap_username = nm_setting_wireless_security_get_leap_username (s_wsec);

	/* Ad-Hoc checks */
	if (!verify_adhoc (s_wsec, s_8021x, adhoc, error))
		return FALSE;

	/* Static WEP, Dynamic WEP, or LEAP */
	if (   (ap_flags & NM_802_11_AP_FLAGS_PRIVACY)
	    && (ap_wpa_flags == NM_802_11_AP_SEC_NONE)
	    && (ap_rsn_flags == NM_802_11_AP_SEC_NONE)) {
		const char *tag = "WEP";
		gboolean is_dynamic_wep = FALSE;

		if (!verify_leap (s_wsec, s_8021x, adhoc, error))
			return FALSE;

		if (leap_username) {
			tag = "LEAP";
		} else {
			/* Static or Dynamic WEP */
			if (!verify_dynamic_wep (s_wsec, s_8021x, adhoc, error))
				return FALSE;

			if (s_8021x || (key_mgmt && !strcmp (key_mgmt, "ieee8021x"))) {
				is_dynamic_wep = TRUE;
				tag = "Dynamic WEP";
			}
		}

		/* Nothing WPA-related can be set */
		if (!verify_no_wpa (s_wsec, tag, error))
			return FALSE;

		if (leap_username) {
			/* LEAP */
			g_object_set (s_wsec,
			              NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "ieee8021x",
			              NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "leap",
			              NULL);
		} else if (is_dynamic_wep) {
			/* Dynamic WEP */
			g_object_set (s_wsec,
			              NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "ieee8021x",
			              NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "open",
			              NULL);

			if (s_8021x) {
				/* Dynamic WEP requires a valid 802.1x setting since we can't
				 * autocomplete 802.1x.
				 */
				if (!nm_setting_verify (NM_SETTING (s_8021x), NULL, error))
					return FALSE;
			}
		} else {
			/* Static WEP */
			g_object_set (s_wsec,
			              NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "none",
			              NULL);
		}

		return TRUE;
	}

	/* WPA/RSN */
	g_assert (ap_wpa_flags || ap_rsn_flags);

	/* Ensure key management is valid for WPA */
	if ((key_mgmt && !strcmp (key_mgmt, "ieee8021x")) || leap_username) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("WPA authentication is incompatible with non-EAP (original) LEAP or Dynamic WEP"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME, NM_SETTING_WIRELESS_SECURITY_KEY_MGMT);
		return FALSE;
	}

	/* 'shared' auth incompatible with any type of WPA */
	if (auth_alg && strcmp (auth_alg, "open")) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("WPA authentication is incompatible with Shared Key authentication"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME, NM_SETTING_WIRELESS_SECURITY_AUTH_ALG);
		return FALSE;
	}

	if (!verify_no_wep (s_wsec, "WPA", error))
		return FALSE;

	if (!verify_wpa_psk (s_wsec, s_8021x, adhoc, ap_wpa_flags, ap_rsn_flags, error))
		return FALSE;

	if (!adhoc && !verify_wpa_eap (s_wsec, s_8021x, ap_wpa_flags, ap_rsn_flags, error))
		return FALSE;

	if (adhoc) {
		g_object_set (s_wsec, NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "wpa-none", NULL);
		/* Ad-Hoc does not support RSN/WPA2 */
		nm_setting_wireless_security_add_proto (s_wsec, "wpa");
		nm_setting_wireless_security_add_pairwise (s_wsec, "none");
		nm_setting_wireless_security_add_group (s_wsec, "tkip");
	} else if (s_8021x) {
		g_object_set (s_wsec,
		              NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "wpa-eap",
		              NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "open",
		              NULL);
		/* Leave proto/pairwise/group as client set them; if they are unset the
		 * supplicant will figure out the best combination at connect time.
		 */

		/* 802.1x also requires the client to completely fill in the 8021x
		 * setting.  Since there's so much configuration required for it, there's
		 * no way it can be automatically completed.
		 */
	} else if (   (key_mgmt && !strcmp (key_mgmt, "wpa-psk"))
	           || (ap_wpa_flags & NM_802_11_AP_SEC_KEY_MGMT_PSK)
	           || (ap_rsn_flags & NM_802_11_AP_SEC_KEY_MGMT_PSK)) {
		g_object_set (s_wsec,
		              NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "wpa-psk",
		              NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "open",
		              NULL);
		/* Leave proto/pairwise/group as client set them; if they are unset the
		 * supplicant will figure out the best combination at connect time.
		 */
	} else {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_FAILED,
		                     _("Failed to determine AP security information"));
		return FALSE;
	}

	return TRUE;
}

guint32
nm_wifi_utils_level_to_quality (gint val)
{
	if (val < 0) {
		/* Assume dBm already; rough conversion: best = -40, worst = -100 */
		val = abs (CLAMP (val, -100, -40) + 40);  /* normalize to 0 */
		val = 100 - (int) ((100.0 * (double) val) / 60.0);
	} else if (val > 110 && val < 256) {
		/* assume old-style WEXT 8-bit unsigned signal level */
		val -= 256;  /* subtract 256 to convert to dBm */
		val = abs (CLAMP (val, -100, -40) + 40);  /* normalize to 0 */
		val = 100 - (int) ((100.0 * (double) val) / 60.0);
	} else {
		/* Assume signal is a "quality" percentage */
	}

	return CLAMP (val, 0, 100);
}

