/* NetworkManager -- Network link manager
 *
 * Ray Strode <rstrode@redhat.com>
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * (C) Copyright 2005 Red Hat, Inc.
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <iwlib.h>
#include <wireless.h>

#include <glib.h>
#include <glib-object.h>
#include <dbus/dbus.h>
#include "nm-utils.h"
#include "NetworkManager.h"

struct EncodingTriplet
{
	const char *encoding1;
	const char *encoding2;
	const char *encoding3;
};

struct IsoLangToEncodings
{
	const char *	lang;
	struct EncodingTriplet encodings;
};

/* 5-letter language codes */
static const struct IsoLangToEncodings isoLangEntries5[] =
{
	/* Simplified Chinese */
	{ "zh_cn",	{"euc-cn",	"gb2312",			"gb18030"} },	/* PRC */
	{ "zh_sg",	{"euc-cn",	"gb2312",			"gb18030"} },	/* Singapore */

	/* Traditional Chinese */
	{ "zh_tw",	{"big5",		"euc-tw",			NULL} },		/* Taiwan */
	{ "zh_hk",	{"big5",		"euc-tw",			"big5-hkcs"} },/* Hong Kong */
	{ "zh_mo",	{"big5",		"euc-tw",			NULL} },		/* Macau */

	/* Table end */
	{ NULL, {NULL, NULL, NULL} }
};

/* 2-letter language codes; we don't care about the other 3 in this table */
static const struct IsoLangToEncodings isoLangEntries2[] =
{
	/* Japanese */
	{ "ja",		{"euc-jp",	"shift_jis",		"iso-2022-jp"} },

	/* Korean */
	{ "ko",		{"euc-kr",	"iso-2022-kr",		"johab"} },

	/* Thai */
	{ "th",		{"iso-8859-11","windows-874",		NULL} },

	/* Central European */
	{ "hu",		{"iso-8859-2",	"windows-1250",	NULL} },	/* Hungarian */
	{ "cs",		{"iso-8859-2",	"windows-1250",	NULL} },	/* Czech */
	{ "hr",		{"iso-8859-2",	"windows-1250",	NULL} },	/* Croatian */
	{ "pl",		{"iso-8859-2",	"windows-1250",	NULL} },	/* Polish */
	{ "ro",		{"iso-8859-2",	"windows-1250",	NULL} },	/* Romanian */
	{ "sk",		{"iso-8859-2",	"windows-1250",	NULL} },	/* Slovakian */
	{ "sl",		{"iso-8859-2",	"windows-1250",	NULL} },	/* Slovenian */
	{ "sh",		{"iso-8859-2",	"windows-1250",	NULL} },	/* Serbo-Croatian */

	/* Cyrillic */
	{ "ru",		{"koi8-r",	"windows-1251",	"iso-8859-5"} },	/* Russian */
	{ "be",		{"koi8-r",	"windows-1251",	"iso-8859-5"} },	/* Belorussian */
	{ "bg",		{"windows-1251","koi8-r",		"iso-8859-5"} },	/* Bulgarian */
	{ "mk",		{"koi8-r",	"windows-1251",	"iso-8859-5"} },	/* Macedonian */
	{ "sr",		{"koi8-r",	"windows-1251",	"iso-8859-5"} },	/* Serbian */
	{ "uk",		{"koi8-u",	"koi8-r",			"windows-1251"} },	/* Ukranian */

	/* Arabic */
	{ "ar",		{"iso-8859-6",	"windows-1256",	NULL} },

	/* Balitc */
	{ "et",		{"iso-8859-4",	"windows-1257",	NULL} },	/* Estonian */
	{ "lt",		{"iso-8859-4",	"windows-1257",	NULL} },	/* Lithuanian */
	{ "lv",		{"iso-8859-4",	"windows-1257",	NULL} },	/* Latvian */

	/* Greek */
	{ "el",		{"iso-8859-7",	"windows-1253",	NULL} },

	/* Hebrew */
	{ "he",		{"iso-8859-8",	"windows-1255",	NULL} },
	{ "iw",		{"iso-8859-8",	"windows-1255",	NULL} },

	/* Turkish */
	{ "tr",		{"iso-8859-9",	"windows-1254",	NULL} },

	/* Table end */
	{ NULL, {NULL, NULL, NULL} }
};


static GHashTable * langToEncodings5 = NULL;
static GHashTable * langToEncodings2 = NULL;

static void
init_lang_to_encodings_hash (void)
{
	static GStaticMutex mutex = G_STATIC_MUTEX_INIT;

	g_static_mutex_lock (&mutex);
	if (G_UNLIKELY (!langToEncodings5 || !langToEncodings2))
	{
		const struct IsoLangToEncodings *	enc = &isoLangEntries5[0];

		/* Five-letter codes */
		langToEncodings5 = g_hash_table_new (g_str_hash, g_str_equal);
		while (enc->lang)
		{
			g_hash_table_insert (langToEncodings5, (gpointer) enc->lang,
					(gpointer) &enc->encodings);
			enc++;
		}

		/* Two-letter codes */
		enc = &isoLangEntries2[0];
		langToEncodings2 = g_hash_table_new (g_str_hash, g_str_equal);
		while (enc->lang)
		{
			g_hash_table_insert (langToEncodings2, (gpointer) enc->lang,
					(gpointer) &enc->encodings);
			enc++;
		}
	}
	g_static_mutex_unlock (&mutex);
}


static gboolean
get_encodings_for_lang (const char *lang,
                        char **encoding1,
                        char **encoding2,
                        char **encoding3)
{
	struct EncodingTriplet *	encodings;
	gboolean				success = FALSE;
	char *				tmp_lang;

	g_return_val_if_fail (lang != NULL, FALSE);
	g_return_val_if_fail (encoding1 != NULL, FALSE);
	g_return_val_if_fail (encoding2 != NULL, FALSE);
	g_return_val_if_fail (encoding3 != NULL, FALSE);

	*encoding1 = "iso-8859-1";
	*encoding2 = "windows-1251";
	*encoding3 = NULL;

	init_lang_to_encodings_hash ();

	tmp_lang = g_strdup (lang);
	if ((encodings = g_hash_table_lookup (langToEncodings5, tmp_lang)))
	{
		*encoding1 = (char *) encodings->encoding1;
		*encoding2 = (char *) encodings->encoding2;
		*encoding3 = (char *) encodings->encoding3;
		success = TRUE;
	}

	/* Truncate tmp_lang to length of 2 */
	if (strlen (tmp_lang) > 2)
		tmp_lang[2] = '\0';
	if (!success && (encodings = g_hash_table_lookup (langToEncodings2, tmp_lang)))
	{
		*encoding1 = (char *) encodings->encoding1;
		*encoding2 = (char *) encodings->encoding2;
		*encoding3 = (char *) encodings->encoding3;
		success = TRUE;
	}

	g_free (tmp_lang);
	return success;
}


char *
nm_utils_ssid_to_utf8 (const char *ssid, guint32 len)
{
	char * new_ssid = NULL;
	char buf[IW_ESSID_MAX_SIZE + 1];
	guint32 buf_len = MIN (sizeof (buf) - 1, len);
	char * lang;
	char *e1 = NULL, *e2 = NULL, *e3 = NULL;

	g_return_val_if_fail (ssid != NULL, NULL);

	memset (buf, 0, sizeof (buf));
	memcpy (buf, ssid, buf_len);

	if (g_utf8_validate (buf, buf_len, NULL)) {
		new_ssid = g_strdup (buf);
		goto out;
	}

	/* Even if the local encoding is UTF-8, LANG may give
	 * us a clue as to what encoding SSIDs are more likely to be in.
	 */
	g_get_charset ((const char **)(&e1));
	if ((lang = getenv ("LANG"))) {
		char * dot;

		lang = g_ascii_strdown (lang, -1);
		if ((dot = strchr (lang, '.')))
			*dot = '\0';

		get_encodings_for_lang (lang, &e1, &e2, &e3);
		g_free (lang);
	}

	new_ssid = g_convert (buf, buf_len, "UTF-8", e1, NULL, NULL, NULL);
	if (!new_ssid && e2) {
		new_ssid = g_convert (buf, buf_len, "UTF-8", e2, NULL, NULL, NULL);
	}
	if (!new_ssid && e3) {
		new_ssid = g_convert (buf, buf_len, "UTF-8", e3, NULL, NULL, NULL);
	}
	if (!new_ssid) {
		new_ssid = g_convert_with_fallback (buf, buf_len, "UTF-8", e1,
	                "?", NULL, NULL, NULL);
	}

out:
	return new_ssid;
}

/* Shamelessly ripped from the Linux kernel ieee80211 stack */
gboolean
nm_utils_is_empty_ssid (const guint8 * ssid, int len)
{
        /* Single white space is for Linksys APs */
        if (len == 1 && ssid[0] == ' ')
                return TRUE;

        /* Otherwise, if the entire ssid is 0, we assume it is hidden */
        while (len--) {
                if (ssid[len] != '\0')
                        return FALSE;
        }
        return TRUE;
}

const char *
nm_utils_escape_ssid (const guint8 * ssid, guint32 len)
{
	static char escaped[IW_ESSID_MAX_SIZE * 2 + 1];
	const guint8 *s = ssid;
	char *d = escaped;

	if (nm_utils_is_empty_ssid (ssid, len)) {
		memcpy (escaped, "<hidden>", sizeof ("<hidden>"));
		return escaped;
	}

	len = MIN (len, (guint32) IW_ESSID_MAX_SIZE);
	while (len--) {
		if (*s == '\0') {
			*d++ = '\\';
			*d++ = '0';
			s++;
		} else {
			*d++ = *s++;
		}
	}
	*d = '\0';
	return escaped;
}

gboolean
nm_utils_same_ssid (const GByteArray * ssid1,
                    const GByteArray * ssid2,
                    gboolean ignore_trailing_null)
{
	guint32 ssid1_len, ssid2_len;

	if (ssid1 == ssid2)
		return TRUE;
	if ((ssid1 && !ssid2) || (!ssid1 && ssid2))
		return FALSE;

	ssid1_len = ssid1->len;
	ssid2_len = ssid2->len;
	if (ssid1_len && ssid2_len && ignore_trailing_null) {
		if (ssid1->data[ssid1_len - 1] == '\0')
			ssid1_len--;
		if (ssid2->data[ssid2_len - 1] == '\0')
			ssid2_len--;
	}

	if (ssid1_len != ssid2_len)
		return FALSE;

	return memcmp (ssid1->data, ssid2->data, ssid1_len) == 0 ? TRUE : FALSE;
}

static void
value_destroy (gpointer data)
{
	GValue *value = (GValue *) data;

	g_value_unset (value);
	g_slice_free (GValue, value);
}

static void
value_dup (gpointer key, gpointer val, gpointer user_data)
{
	GHashTable *dup = (GHashTable *) user_data;
	GValue *value = (GValue *) val;
	GValue *dup_value;

	dup_value = g_slice_new0 (GValue);
	g_value_init (dup_value, G_VALUE_TYPE (val));
	g_value_copy (value, dup_value);

	g_hash_table_insert (dup, g_strdup ((char *) key), dup_value);
}

GHashTable *
nm_utils_gvalue_hash_dup (GHashTable *hash)
{
	GHashTable *dup;

	g_return_val_if_fail (hash != NULL, NULL);

	dup = g_hash_table_new_full (g_str_hash, g_str_equal,
						    (GDestroyNotify) g_free,
						    value_destroy);

	g_hash_table_foreach (hash, value_dup, dup);

	return dup;
}

char *
nm_utils_garray_to_string (GArray *array)
{
	GString *str;
	int i;
	char c;

	g_return_val_if_fail (array != NULL, NULL);

	str = g_string_sized_new (array->len);
	for (i = 0; i < array->len; i++) {
		c = array->data[i];

		/* Convert NULLs to spaces to increase the readability. */
		if (c == '\0')
			c = ' ';
		str = g_string_append_c (str, c);
	}
	str = g_string_append_c (str, '\0');

	return g_string_free (str, FALSE);
}

static gboolean
device_supports_ap_ciphers (guint32 dev_caps,
                            guint32 ap_flags,
                            gboolean static_wep)
{
	gboolean have_pair = FALSE;
	gboolean have_group = FALSE;
	/* Device needs to support at least one pairwise and one group cipher */

	/* Pairwise */
	if (static_wep) {
		/* Static WEP only uses group ciphers */
		have_pair = TRUE;
	} else {
		if (dev_caps & NM_802_11_DEVICE_CAP_CIPHER_WEP40)
			if (ap_flags & NM_802_11_AP_SEC_PAIR_WEP40)
				have_pair = TRUE;
		if (dev_caps & NM_802_11_DEVICE_CAP_CIPHER_WEP104)
			if (ap_flags & NM_802_11_AP_SEC_PAIR_WEP104)
				have_pair = TRUE;
		if (dev_caps & NM_802_11_DEVICE_CAP_CIPHER_TKIP)
			if (ap_flags & NM_802_11_AP_SEC_PAIR_TKIP)
				have_pair = TRUE;
		if (dev_caps & NM_802_11_DEVICE_CAP_CIPHER_CCMP)
			if (ap_flags & NM_802_11_AP_SEC_PAIR_CCMP)
				have_pair = TRUE;
	}

	/* Group */
	if (dev_caps & NM_802_11_DEVICE_CAP_CIPHER_WEP40)
		if (ap_flags & NM_802_11_AP_SEC_GROUP_WEP40)
			have_group = TRUE;
	if (dev_caps & NM_802_11_DEVICE_CAP_CIPHER_WEP104)
		if (ap_flags & NM_802_11_AP_SEC_GROUP_WEP104)
			have_group = TRUE;
	if (!static_wep) {
		if (dev_caps & NM_802_11_DEVICE_CAP_CIPHER_TKIP)
			if (ap_flags & NM_802_11_AP_SEC_GROUP_TKIP)
				have_group = TRUE;
		if (dev_caps & NM_802_11_DEVICE_CAP_CIPHER_CCMP)
			if (ap_flags & NM_802_11_AP_SEC_GROUP_CCMP)
				have_group = TRUE;
	}

	return (have_pair && have_group);
}

gboolean
nm_utils_security_valid (NMUtilsSecurityType type,
                         guint32 dev_caps,
                         gboolean have_ap,
                         guint32 ap_flags,
                         guint32 ap_wpa,
                         guint32 ap_rsn)
{
	gboolean good = TRUE;

	if (!have_ap) {
		if (type == NMU_SEC_NONE)
			return TRUE;
		if (   (type == NMU_SEC_STATIC_WEP)
		    || (type == NMU_SEC_DYNAMIC_WEP)
		    || (type == NMU_SEC_LEAP)) {
			if (dev_caps & (NM_802_11_DEVICE_CAP_CIPHER_WEP40 | NM_802_11_DEVICE_CAP_CIPHER_WEP104))
				return TRUE;
		}
	}

	switch (type) {
	case NMU_SEC_NONE:
		g_assert (have_ap);
		if (ap_flags & NM_802_11_AP_FLAGS_PRIVACY)
			return FALSE;
		if (ap_wpa || ap_rsn)
			return FALSE;
		break;
	case NMU_SEC_LEAP: /* require PRIVACY bit for LEAP? */
	case NMU_SEC_STATIC_WEP:
		g_assert (have_ap);
		if (!(ap_flags & NM_802_11_AP_FLAGS_PRIVACY))
			return FALSE;
		if (ap_wpa || ap_rsn) {
			if (!device_supports_ap_ciphers (dev_caps, ap_wpa, TRUE))
				if (!device_supports_ap_ciphers (dev_caps, ap_rsn, TRUE))
					return FALSE;
		}
		break;
	case NMU_SEC_DYNAMIC_WEP:
		g_assert (have_ap);
		if (ap_rsn || !(ap_flags & NM_802_11_AP_FLAGS_PRIVACY))
			return FALSE;
		/* Some APs broadcast minimal WPA-enabled beacons that must be handled */
		if (ap_wpa) {
			if (!(ap_wpa & NM_802_11_AP_SEC_KEY_MGMT_802_1X))
				return FALSE;
			if (!device_supports_ap_ciphers (dev_caps, ap_wpa, FALSE))
				return FALSE;
		}
		break;
	case NMU_SEC_WPA_PSK:
		if (!(dev_caps & NM_802_11_DEVICE_CAP_WPA))
			return FALSE;
		if (have_ap) {
			if (!(ap_flags & NM_802_11_AP_FLAGS_PRIVACY))
				return FALSE;

			if (ap_wpa & NM_802_11_AP_SEC_KEY_MGMT_PSK) {
				if (   (ap_wpa & NM_802_11_AP_SEC_PAIR_TKIP)
				    && (dev_caps & NM_802_11_DEVICE_CAP_CIPHER_TKIP))
					return TRUE;
				if (   (ap_wpa & NM_802_11_AP_SEC_PAIR_CCMP)
				    && (dev_caps & NM_802_11_DEVICE_CAP_CIPHER_CCMP))
					return TRUE;
			}
			return FALSE;
		}
		break;
	case NMU_SEC_WPA2_PSK:
		if (!(dev_caps & NM_802_11_DEVICE_CAP_RSN))
			return FALSE;
		if (have_ap) {
			if (!(ap_flags & NM_802_11_AP_FLAGS_PRIVACY))
				return FALSE;

			if (ap_rsn & NM_802_11_AP_SEC_KEY_MGMT_PSK) {
				if (   (ap_rsn & NM_802_11_AP_SEC_PAIR_TKIP)
				    && (dev_caps & NM_802_11_DEVICE_CAP_CIPHER_TKIP))
					return TRUE;
				if (   (ap_rsn & NM_802_11_AP_SEC_PAIR_CCMP)
				    && (dev_caps & NM_802_11_DEVICE_CAP_CIPHER_CCMP))
					return TRUE;
			}
			return FALSE;
		}
		break;
	case NMU_SEC_WPA_ENTERPRISE:
		if (!(dev_caps & NM_802_11_DEVICE_CAP_WPA))
			return FALSE;
		if (have_ap) {
			if (!(ap_flags & NM_802_11_AP_FLAGS_PRIVACY))
				return FALSE;
			if (!(ap_wpa & NM_802_11_AP_SEC_KEY_MGMT_802_1X))
				return FALSE;
			/* Ensure at least one WPA cipher is supported */
			if (!device_supports_ap_ciphers (dev_caps, ap_wpa, FALSE))
				return FALSE;
		}
		break;
	case NMU_SEC_WPA2_ENTERPRISE:
		if (!(dev_caps & NM_802_11_DEVICE_CAP_RSN))
			return FALSE;
		if (have_ap) {
			if (!(ap_flags & NM_802_11_AP_FLAGS_PRIVACY))
				return FALSE;
			if (!(ap_rsn & NM_802_11_AP_SEC_KEY_MGMT_802_1X))
				return FALSE;
			/* Ensure at least one WPA cipher is supported */
			if (!device_supports_ap_ciphers (dev_caps, ap_rsn, FALSE))
				return FALSE;
		}
		break;
	default:
		good = FALSE;
		break;
	}

	return good;
}


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
nm_utils_ap_security_compatible (NMConnection *connection,
                                 guint32 ap_flags,
                                 guint32 ap_wpa,
                                 guint32 ap_rsn,
                                 guint32 ap_mode)
{
	NMSettingWireless *s_wireless;
	NMSettingWirelessSecurity *s_wireless_sec;

	g_return_val_if_fail (connection != NULL, FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);

	s_wireless = (NMSettingWireless *) nm_connection_get_setting (connection, NM_SETTING_WIRELESS);
	if (!s_wireless)
		return FALSE;

	if (!s_wireless->security) {
		if (   (ap_flags & NM_802_11_AP_FLAGS_PRIVACY)
		    || (ap_wpa != NM_802_11_AP_SEC_NONE)
		    || (ap_rsn != NM_802_11_AP_SEC_NONE))
			return FALSE;
		return TRUE;
	}

	if (strcmp (s_wireless->security, NM_SETTING_WIRELESS_SECURITY) != 0)
		return FALSE;

	s_wireless_sec = (NMSettingWirelessSecurity *) nm_connection_get_setting (connection, NM_SETTING_WIRELESS_SECURITY);
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
		if (ap_mode != IW_MODE_ADHOC)
			return FALSE;
		// FIXME: validate ciphers if the BSSID actually puts WPA/RSN IE in
		// it's beacon
		return TRUE;
	}

	/* Stuff after this point requires infrastructure */
	if (ap_mode != IW_MODE_INFRA)
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

