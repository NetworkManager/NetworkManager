/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

/*
 * Dan Williams <dcbw@redhat.com>
 * Tambet Ingo <tambet@gmail.com>
 *
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
 * (C) Copyright 2007 - 2008 Red Hat, Inc.
 * (C) Copyright 2007 - 2008 Novell, Inc.
 */

#include <string.h>
#include <netinet/ether.h>
#include <dbus/dbus-glib.h>

#include "wireless-helper.h"

#include "NetworkManager.h"
#include "nm-setting-wireless.h"
#include "nm-param-spec-specialized.h"
#include "nm-utils.h"
#include "nm-dbus-glib-types.h"

GQuark
nm_setting_wireless_error_quark (void)
{
	static GQuark quark;

	if (G_UNLIKELY (!quark))
		quark = g_quark_from_static_string ("nm-setting-wireless-error-quark");
	return quark;
}

/* This should really be standard. */
#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

GType
nm_setting_wireless_error_get_type (void)
{
	static GType etype = 0;

	if (etype == 0) {
		static const GEnumValue values[] = {
			/* Unknown error. */
			ENUM_ENTRY (NM_SETTING_WIRELESS_ERROR_UNKNOWN, "UnknownError"),
			/* The specified property was invalid. */
			ENUM_ENTRY (NM_SETTING_WIRELESS_ERROR_INVALID_PROPERTY, "InvalidProperty"),
			/* The specified property was missing and is required. */
			ENUM_ENTRY (NM_SETTING_WIRELESS_ERROR_MISSING_PROPERTY, "MissingProperty"),
			/* The required security setting is missing */
			ENUM_ENTRY (NM_SETTING_WIRELESS_ERROR_MISSING_SECURITY_SETTING, "MissingSecuritySetting"),
			/* The 'channel' property requires a valid 'band' */
			ENUM_ENTRY (NM_SETTING_WIRELESS_ERROR_CHANNEL_REQUIRES_BAND, "ChannelRequiresBand"),
			{ 0, 0, 0 }
		};
		etype = g_enum_register_static ("NMSettingWirelessError", values);
	}
	return etype;
}


G_DEFINE_TYPE (NMSettingWireless, nm_setting_wireless, NM_TYPE_SETTING)

enum {
	PROP_0,
	PROP_SSID,
	PROP_MODE,
	PROP_BAND,
	PROP_CHANNEL,
	PROP_BSSID,
	PROP_RATE,
	PROP_TX_POWER,
	PROP_MAC_ADDRESS,
	PROP_MTU,
	PROP_SEEN_BSSIDS,
	PROP_SEC,

	LAST_PROP
};

static gboolean
match_cipher (const char *cipher,
              const char *expected,
              guint32 wpa_flags,
              guint32 rsn_flags,
              guint32 flag)
{
	if (strcmp (cipher, expected) != 0)
		return FALSE;

	if (!(wpa_flags & flag) && !(rsn_flags & flag))
		return FALSE;

	return TRUE;
}

gboolean
nm_setting_wireless_ap_security_compatible (NMSettingWireless *s_wireless,
								    NMSettingWirelessSecurity *s_wireless_sec,
								    guint32 ap_flags,
								    guint32 ap_wpa,
								    guint32 ap_rsn,
								    guint32 ap_mode)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRELESS (s_wireless), FALSE);

	if (!s_wireless->security) {
		if (   (ap_flags & NM_802_11_AP_FLAGS_PRIVACY)
		    || (ap_wpa != NM_802_11_AP_SEC_NONE)
		    || (ap_rsn != NM_802_11_AP_SEC_NONE))
			return FALSE;
		return TRUE;
	}

	if (strcmp (s_wireless->security, NM_SETTING_WIRELESS_SECURITY_SETTING_NAME) != 0)
		return FALSE;

	if (s_wireless_sec == NULL || !s_wireless_sec->key_mgmt)
		return FALSE;

	/* Static WEP */
	if (!strcmp (s_wireless_sec->key_mgmt, "none")) {
		if (   !(ap_flags & NM_802_11_AP_FLAGS_PRIVACY)
		    || (ap_wpa != NM_802_11_AP_SEC_NONE)
		    || (ap_rsn != NM_802_11_AP_SEC_NONE))
			return FALSE;
		return TRUE;
	}

	/* Adhoc WPA */
	if (!strcmp (s_wireless_sec->key_mgmt, "wpa-none")) {
		if (ap_mode != NM_802_11_MODE_ADHOC)
			return FALSE;
		// FIXME: validate ciphers if the BSSID actually puts WPA/RSN IE in
		// it's beacon
		return TRUE;
	}

	/* Stuff after this point requires infrastructure */
	if (ap_mode != NM_802_11_MODE_INFRA)
		return FALSE;

	/* Dynamic WEP or LEAP */
	if (!strcmp (s_wireless_sec->key_mgmt, "ieee8021x")) {
		if (!(ap_flags & NM_802_11_AP_FLAGS_PRIVACY))
			return FALSE;

		/* If the AP is advertising a WPA IE, make sure it supports WEP ciphers */
		if (ap_wpa != NM_802_11_AP_SEC_NONE) {
			gboolean found = FALSE;
			GSList *iter;

			if (!(ap_wpa & NM_802_11_AP_SEC_KEY_MGMT_802_1X))
				return FALSE;

			/* quick check; can't use AP if it doesn't support at least one
			 * WEP cipher in both pairwise and group suites.
			 */
			if (   !(ap_wpa & (NM_802_11_AP_SEC_PAIR_WEP40 | NM_802_11_AP_SEC_PAIR_WEP104))
			    || !(ap_wpa & (NM_802_11_AP_SEC_GROUP_WEP40 | NM_802_11_AP_SEC_GROUP_WEP104)))
				return FALSE;

			/* Match at least one pairwise cipher with AP's capability */
			for (iter = s_wireless_sec->pairwise; iter; iter = g_slist_next (iter)) {
				if ((found = match_cipher (iter->data, "wep40", ap_wpa, ap_wpa, NM_802_11_AP_SEC_PAIR_WEP40)))
					break;
				if ((found = match_cipher (iter->data, "wep104", ap_wpa, ap_wpa, NM_802_11_AP_SEC_PAIR_WEP104)))
					break;
			}
			if (!found)
				return FALSE;

			/* Match at least one group cipher with AP's capability */
			for (iter = s_wireless_sec->group; iter; iter = g_slist_next (iter)) {
				if ((found = match_cipher (iter->data, "wep40", ap_wpa, ap_wpa, NM_802_11_AP_SEC_GROUP_WEP40)))
					break;
				if ((found = match_cipher (iter->data, "wep104", ap_wpa, ap_wpa, NM_802_11_AP_SEC_GROUP_WEP104)))
					break;
			}
			if (!found)
				return FALSE;
		}
		return TRUE;
	}

	/* WPA[2]-PSK and WPA[2] Enterprise */
	if (   !strcmp (s_wireless_sec->key_mgmt, "wpa-psk")
	    || !strcmp (s_wireless_sec->key_mgmt, "wpa-eap")) {
		GSList * elt;
		gboolean found = FALSE;

		if (!(ap_flags & NM_802_11_AP_FLAGS_PRIVACY))
			return FALSE;

		if (!s_wireless_sec->pairwise || !s_wireless_sec->group)
			return FALSE;

		if (!strcmp (s_wireless_sec->key_mgmt, "wpa-psk")) {
			if (   !(ap_wpa & NM_802_11_AP_SEC_KEY_MGMT_PSK)
			    && !(ap_rsn & NM_802_11_AP_SEC_KEY_MGMT_PSK))
				return FALSE;
		} else if (!strcmp (s_wireless_sec->key_mgmt, "wpa-eap")) {
			if (   !(ap_wpa & NM_802_11_AP_SEC_KEY_MGMT_802_1X)
			    && !(ap_rsn & NM_802_11_AP_SEC_KEY_MGMT_802_1X))
				return FALSE;
		}

		// FIXME: should handle WPA and RSN separately here to ensure that
		// if the Connection only uses WPA we don't match a cipher against
		// the AP's RSN IE instead

		/* Match at least one pairwise cipher with AP's capability */
		for (elt = s_wireless_sec->pairwise; elt; elt = g_slist_next (elt)) {
			if ((found = match_cipher (elt->data, "tkip", ap_wpa, ap_rsn, NM_802_11_AP_SEC_PAIR_TKIP)))
				break;
			if ((found = match_cipher (elt->data, "ccmp", ap_wpa, ap_rsn, NM_802_11_AP_SEC_PAIR_CCMP)))
				break;
		}
		if (!found)
			return FALSE;

		/* Match at least one group cipher with AP's capability */
		for (elt = s_wireless_sec->group; elt; elt = g_slist_next (elt)) {
			if ((found = match_cipher (elt->data, "wep40", ap_wpa, ap_rsn, NM_802_11_AP_SEC_GROUP_WEP40)))
				break;
			if ((found = match_cipher (elt->data, "wep104", ap_wpa, ap_rsn, NM_802_11_AP_SEC_GROUP_WEP104)))
				break;
			if ((found = match_cipher (elt->data, "tkip", ap_wpa, ap_rsn, NM_802_11_AP_SEC_GROUP_TKIP)))
				break;
			if ((found = match_cipher (elt->data, "ccmp", ap_wpa, ap_rsn, NM_802_11_AP_SEC_GROUP_CCMP)))
				break;
		}
		if (!found)
			return FALSE;

		return TRUE;
	}

	return FALSE;
}

NMSetting *
nm_setting_wireless_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_WIRELESS, NULL);
}

static gint
find_setting_by_name (gconstpointer a, gconstpointer b)
{
	NMSetting *setting = NM_SETTING (a);
	const char *str = (const char *) b;

	return strcmp (nm_setting_get_name (setting), str);
}

static gboolean
verify (NMSetting *setting, GSList *all_settings, GError **error)
{
	NMSettingWireless *self = NM_SETTING_WIRELESS (setting);
	const char *valid_modes[] = { "infrastructure", "adhoc", NULL };
	const char *valid_bands[] = { "a", "bg", NULL };
	GSList *iter;

	if (!self->ssid) {
		g_set_error (error,
		             NM_SETTING_WIRELESS_ERROR,
		             NM_SETTING_WIRELESS_ERROR_MISSING_PROPERTY,
		             NM_SETTING_WIRELESS_SSID);
		return FALSE;
	}

	if (!self->ssid->len || self->ssid->len > 32) {
		g_set_error (error,
		             NM_SETTING_WIRELESS_ERROR,
		             NM_SETTING_WIRELESS_ERROR_INVALID_PROPERTY,
		             NM_SETTING_WIRELESS_SSID);
		return FALSE;
	}

	if (self->mode && !nm_utils_string_in_list (self->mode, valid_modes)) {
		g_set_error (error,
		             NM_SETTING_WIRELESS_ERROR,
		             NM_SETTING_WIRELESS_ERROR_INVALID_PROPERTY,
		             NM_SETTING_WIRELESS_MODE);
		return FALSE;
	}

	if (self->band && !nm_utils_string_in_list (self->band, valid_bands)) {
		g_set_error (error,
		             NM_SETTING_WIRELESS_ERROR,
		             NM_SETTING_WIRELESS_ERROR_INVALID_PROPERTY,
		             NM_SETTING_WIRELESS_BAND);
		return FALSE;
	}

	if (self->channel && !self->band) {
		g_set_error (error,
		             NM_SETTING_WIRELESS_ERROR,
		             NM_SETTING_WIRELESS_ERROR_CHANNEL_REQUIRES_BAND,
		             NM_SETTING_WIRELESS_BAND);
		return FALSE;
	}

	if (self->channel) {
		if (!strcmp (self->band, "a")) {
			int i;
			int valid_channels[] = { 7, 8, 9, 11, 12, 16, 34, 36, 40, 44, 48,
			                         52, 56, 60, 64, 100, 104, 108, 112, 116,
			                         120, 124, 128, 132, 136, 140, 149, 153,
			                         157, 161, 165, 183, 184, 185, 187, 188,
			                         192, 196, 0 };

			for (i = 0; valid_channels[i]; i++) {
				if (self->channel == valid_channels[i])
					break;
			}

			if (valid_channels[i] == 0) {
				g_set_error (error,
				             NM_SETTING_WIRELESS_ERROR,
				             NM_SETTING_WIRELESS_ERROR_INVALID_PROPERTY,
				             NM_SETTING_WIRELESS_CHANNEL);
				return FALSE;
			}
		} else if (!strcmp (self->band, "bg") && self->channel > 14) {
				g_set_error (error,
				             NM_SETTING_WIRELESS_ERROR,
				             NM_SETTING_WIRELESS_ERROR_INVALID_PROPERTY,
				             NM_SETTING_WIRELESS_CHANNEL);
			return FALSE;
		}
	}

	if (self->bssid && self->bssid->len != ETH_ALEN) {
		g_set_error (error,
		             NM_SETTING_WIRELESS_ERROR,
		             NM_SETTING_WIRELESS_ERROR_INVALID_PROPERTY,
		             NM_SETTING_WIRELESS_BSSID);
		return FALSE;
	}

	if (self->mac_address && self->mac_address->len != ETH_ALEN) {
		g_set_error (error,
		             NM_SETTING_WIRELESS_ERROR,
		             NM_SETTING_WIRELESS_ERROR_INVALID_PROPERTY,
		             NM_SETTING_WIRELESS_MAC_ADDRESS);
		return FALSE;
	}

	for (iter = self->seen_bssids; iter; iter = iter->next) {
		struct ether_addr addr;

		if (!ether_aton_r (iter->data, &addr)) {
			g_set_error (error,
			             NM_SETTING_WIRELESS_ERROR,
			             NM_SETTING_WIRELESS_ERROR_INVALID_PROPERTY,
			             NM_SETTING_WIRELESS_SEEN_BSSIDS);
			return FALSE;
		}
	}

	if (   self->security
	    && !g_slist_find_custom (all_settings, self->security, find_setting_by_name)) {
		g_set_error (error,
		             NM_SETTING_WIRELESS_ERROR,
		             NM_SETTING_WIRELESS_ERROR_MISSING_SECURITY_SETTING,
		             NULL);
		return FALSE;
	}

	return TRUE;
}

static void
nm_setting_wireless_init (NMSettingWireless *setting)
{
	((NMSetting *) setting)->name = g_strdup (NM_SETTING_WIRELESS_SETTING_NAME);
}

static void
finalize (GObject *object)
{
	NMSettingWireless *self = NM_SETTING_WIRELESS (object);

	g_free (self->mode);
	g_free (self->band);
	g_free (self->security);

	if (self->ssid)
		g_byte_array_free (self->ssid, TRUE);
	if (self->bssid)
		g_byte_array_free (self->bssid, TRUE);
	if (self->mac_address)
		g_byte_array_free (self->mac_address, TRUE);

	nm_utils_slist_free (self->seen_bssids, g_free);

	G_OBJECT_CLASS (nm_setting_wireless_parent_class)->finalize (object);
}

static void
set_property (GObject *object, guint prop_id,
		    const GValue *value, GParamSpec *pspec)
{
	NMSettingWireless *setting = NM_SETTING_WIRELESS (object);

	switch (prop_id) {
	case PROP_SSID:
		if (setting->ssid)
			g_byte_array_free (setting->ssid, TRUE);
		setting->ssid = g_value_dup_boxed (value);
		break;
	case PROP_MODE:
		g_free (setting->mode);
		setting->mode = g_value_dup_string (value);
		break;
	case PROP_BAND:
		g_free (setting->band);
		setting->band = g_value_dup_string (value);
		break;
	case PROP_CHANNEL:
		setting->channel = g_value_get_uint (value);
		break;
	case PROP_BSSID:
		if (setting->bssid)
			g_byte_array_free (setting->bssid, TRUE);
		setting->bssid = g_value_dup_boxed (value);
		break;
	case PROP_RATE:
		setting->rate = g_value_get_uint (value);
		break;
	case PROP_TX_POWER:
		setting->tx_power = g_value_get_uint (value);
		break;
	case PROP_MAC_ADDRESS:
		if (setting->mac_address)
			g_byte_array_free (setting->mac_address, TRUE);
		setting->mac_address = g_value_dup_boxed (value);
		break;
	case PROP_MTU:
		setting->mtu = g_value_get_uint (value);
		break;
	case PROP_SEEN_BSSIDS:
		nm_utils_slist_free (setting->seen_bssids, g_free);
		setting->seen_bssids = g_value_dup_boxed (value);
		break;
	case PROP_SEC:
		g_free (setting->security);
		setting->security = g_value_dup_string (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
get_property (GObject *object, guint prop_id,
		    GValue *value, GParamSpec *pspec)
{
	NMSettingWireless *setting = NM_SETTING_WIRELESS (object);

	switch (prop_id) {
	case PROP_SSID:
		g_value_set_boxed (value, setting->ssid);
		break;
	case PROP_MODE:
		g_value_set_string (value, setting->mode);
		break;
	case PROP_BAND:
		g_value_set_string (value, setting->band);
		break;
	case PROP_CHANNEL:
		g_value_set_uint (value, setting->channel);
		break;
	case PROP_BSSID:
		g_value_set_boxed (value, setting->bssid);
		break;
	case PROP_RATE:
		g_value_set_uint (value, setting->rate);
		break;
	case PROP_TX_POWER:
		g_value_set_uint (value, setting->tx_power);
		break;
	case PROP_MAC_ADDRESS:
		g_value_set_boxed (value, setting->mac_address);
		break;
	case PROP_MTU:
		g_value_set_uint (value, setting->mtu);
		break;
	case PROP_SEEN_BSSIDS:
		g_value_set_boxed (value, setting->seen_bssids);
		break;
	case PROP_SEC:
		g_value_set_string (value, setting->security);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_setting_wireless_class_init (NMSettingWirelessClass *setting_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (setting_class);
	NMSettingClass *parent_class = NM_SETTING_CLASS (setting_class);

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize     = finalize;
	parent_class->verify       = verify;

	/* Properties */
	g_object_class_install_property
		(object_class, PROP_SSID,
		 nm_param_spec_specialized (NM_SETTING_WIRELESS_SSID,
							   "SSID",
							   "SSID",
							   DBUS_TYPE_G_UCHAR_ARRAY,
							   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	g_object_class_install_property
		(object_class, PROP_MODE,
		 g_param_spec_string (NM_SETTING_WIRELESS_MODE,
						  "Mode",
						  "Mode",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	g_object_class_install_property
		(object_class, PROP_BAND,
		 g_param_spec_string (NM_SETTING_WIRELESS_BAND,
						  "Band",
						  "Band",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	g_object_class_install_property
		(object_class, PROP_CHANNEL,
		 g_param_spec_uint (NM_SETTING_WIRELESS_CHANNEL,
						"Channel",
						"Channel",
						0, G_MAXUINT32, 0,
						G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	g_object_class_install_property
		(object_class, PROP_BSSID,
		 nm_param_spec_specialized (NM_SETTING_WIRELESS_BSSID,
							   "BSSID",
							   "BSSID",
							   DBUS_TYPE_G_UCHAR_ARRAY,
							   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	g_object_class_install_property
		(object_class, PROP_RATE,
		 g_param_spec_uint (NM_SETTING_WIRELESS_RATE,
						"Rate",
						"Rate",
						0, G_MAXUINT32, 0,
						G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE | NM_SETTING_PARAM_FUZZY_IGNORE));

	g_object_class_install_property
		(object_class, PROP_TX_POWER,
		 g_param_spec_uint (NM_SETTING_WIRELESS_TX_POWER,
						"TX Power",
						"TX Power",
						0, G_MAXUINT32, 0,
						G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE | NM_SETTING_PARAM_FUZZY_IGNORE));

	g_object_class_install_property
		(object_class, PROP_MAC_ADDRESS,
		 nm_param_spec_specialized (NM_SETTING_WIRELESS_MAC_ADDRESS,
							   "MAC Address",
							   "Harware address",
							   DBUS_TYPE_G_UCHAR_ARRAY,
							   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	g_object_class_install_property
		(object_class, PROP_SEEN_BSSIDS,
		 nm_param_spec_specialized (NM_SETTING_WIRELESS_SEEN_BSSIDS,
							   "Seen BSSIDS",
							   "Seen BSSIDs",
							   DBUS_TYPE_G_LIST_OF_STRING,
							   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE | NM_SETTING_PARAM_FUZZY_IGNORE));

	g_object_class_install_property
		(object_class, PROP_MTU,
		 g_param_spec_uint (NM_SETTING_WIRELESS_MTU,
						"MTU",
						"MTU",
						0, G_MAXUINT32, 0,
						G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE | NM_SETTING_PARAM_FUZZY_IGNORE));

	g_object_class_install_property
		(object_class, PROP_SEC,
		 g_param_spec_string (NM_SETTING_WIRELESS_SEC,
						  "Security",
						  "Security",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));
}
