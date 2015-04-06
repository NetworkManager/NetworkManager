/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

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
 * Copyright 2005 - 2013 Red Hat, Inc.
 */

#include "config.h"

#include <string.h>
#include <stdlib.h>
#include <netinet/ether.h>
#include <linux/if_infiniband.h>
#include <uuid/uuid.h>
#include <libintl.h>
#include <gmodule.h>
#include <glib/gi18n-lib.h>

#include "nm-glib.h"
#include "nm-utils.h"
#include "nm-utils-private.h"
#include "nm-dbus-glib-types.h"
#include "nm-setting-private.h"
#include "crypto.h"
#include "nm-macros-internal.h"

/* Embed the commit id in the build binary */
static const char *const __nm_git_sha = STRLEN (NM_GIT_SHA) > 0 ? "NM_GIT_SHA:"NM_GIT_SHA : "";

/**
 * SECTION:nm-utils
 * @short_description: Utility functions
 * @include: nm-utils.h
 *
 * A collection of utility functions for working with SSIDs, IP addresses, Wi-Fi
 * access points and devices, among other things.
 */

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

	/* Baltic */
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
	struct IsoLangToEncodings *enc;

	if (G_UNLIKELY (langToEncodings5 == NULL)) {
		/* Five-letter codes */
		enc = (struct IsoLangToEncodings *) &isoLangEntries5[0];
		langToEncodings5 = g_hash_table_new (g_str_hash, g_str_equal);
		while (enc->lang) {
			g_hash_table_insert (langToEncodings5, (gpointer) enc->lang,
			                     (gpointer) &enc->encodings);
			enc++;
		}
	}

	if (G_UNLIKELY (langToEncodings2 == NULL)) {
		/* Two-letter codes */
		enc = (struct IsoLangToEncodings *) &isoLangEntries2[0];
		langToEncodings2 = g_hash_table_new (g_str_hash, g_str_equal);
		while (enc->lang) {
			g_hash_table_insert (langToEncodings2, (gpointer) enc->lang,
			                     (gpointer) &enc->encodings);
			enc++;
		}
	}
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
	if ((encodings = g_hash_table_lookup (langToEncodings5, tmp_lang))) {
		*encoding1 = (char *) encodings->encoding1;
		*encoding2 = (char *) encodings->encoding2;
		*encoding3 = (char *) encodings->encoding3;
		success = TRUE;
	}

	/* Truncate tmp_lang to length of 2 */
	if (strlen (tmp_lang) > 2)
		tmp_lang[2] = '\0';
	if (!success && (encodings = g_hash_table_lookup (langToEncodings2, tmp_lang))) {
		*encoding1 = (char *) encodings->encoding1;
		*encoding2 = (char *) encodings->encoding2;
		*encoding3 = (char *) encodings->encoding3;
		success = TRUE;
	}

	g_free (tmp_lang);
	return success;
}

/* init, deinit for libnm_util */

static void __attribute__((constructor))
_check_symbols (void)
{
	GModule *self;
	gpointer func;

	self = g_module_open (NULL, 0);
	if (g_module_symbol (self, "nm_device_state_get_type", &func))
		g_error ("libnm symbols detected; Mixing libnm with libnm-util/libnm-glib is not supported");
	g_module_close (self);
}

static gboolean initialized = FALSE;

/**
 * nm_utils_init:
 * @error: location to store error, or %NULL
 *
 * Initializes libnm-util; should be called when starting any program that
 * uses libnm-util.  This function can be called more than once.
 *
 * Returns: %TRUE if the initialization was successful, %FALSE on failure.
 **/
gboolean
nm_utils_init (GError **error)
{
	(void) __nm_git_sha;

	if (!initialized) {
		initialized = TRUE;

		bindtextdomain (GETTEXT_PACKAGE, LOCALEDIR);
		bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");

		if (!crypto_init (error))
			return FALSE;

		_nm_value_transforms_register ();
	}
	return TRUE;
}

/**
 * nm_utils_deinit:
 *
 * No-op. Although this function still exists for ABI compatibility reasons, it
 * does not have any effect, and does not ever need to be called.
 **/
void
nm_utils_deinit (void)
{
}

/* ssid helpers */

/**
 * nm_utils_ssid_to_utf8:
 * @ssid: a byte array containing the SSID data
 *
 * Wi-Fi SSIDs are byte arrays, they are _not_ strings.  Thus, an SSID may
 * contain embedded NULLs and other unprintable characters.  Often it is
 * useful to print the SSID out for debugging purposes, but that should be the
 * _only_ use of this function.  Do not use this function for any persistent
 * storage of the SSID, since the printable SSID returned from this function
 * cannot be converted back into the real SSID of the access point.
 *
 * This function does almost everything humanly possible to convert the input
 * into a printable UTF-8 string, using roughly the following procedure:
 *
 * 1) if the input data is already UTF-8 safe, no conversion is performed
 * 2) attempts to get the current system language from the LANG environment
 *    variable, and depending on the language, uses a table of alternative
 *    encodings to try.  For example, if LANG=hu_HU, the table may first try
 *    the ISO-8859-2 encoding, and if that fails, try the Windows-1250 encoding.
 *    If all fallback encodings fail, replaces non-UTF-8 characters with '?'.
 * 3) If the system language was unable to be determined, falls back to the
 *    ISO-8859-1 encoding, then to the Windows-1251 encoding.
 * 4) If step 3 fails, replaces non-UTF-8 characters with '?'.
 *
 * Again, this function should be used for debugging and display purposes
 * _only_.
 *
 * Returns: (transfer full): an allocated string containing a UTF-8
 * representation of the SSID, which must be freed by the caller using g_free().
 * Returns %NULL on errors.
 **/
char *
nm_utils_ssid_to_utf8 (const GByteArray *ssid)
{
	char *converted = NULL;
	char *lang, *e1 = NULL, *e2 = NULL, *e3 = NULL;

	g_return_val_if_fail (ssid != NULL, NULL);

	if (g_utf8_validate ((const gchar *) ssid->data, ssid->len, NULL))
		return g_strndup ((const gchar *) ssid->data, ssid->len);

	/* LANG may be a good encoding hint */
	g_get_charset ((const char **)(&e1));
	if ((lang = getenv ("LANG"))) {
		char * dot;

		lang = g_ascii_strdown (lang, -1);
		if ((dot = strchr (lang, '.')))
			*dot = '\0';

		get_encodings_for_lang (lang, &e1, &e2, &e3);
		g_free (lang);
	}

	converted = g_convert ((const gchar *) ssid->data, ssid->len, "UTF-8", e1, NULL, NULL, NULL);
	if (!converted && e2)
		converted = g_convert ((const gchar *) ssid->data, ssid->len, "UTF-8", e2, NULL, NULL, NULL);

	if (!converted && e3)
		converted = g_convert ((const gchar *) ssid->data, ssid->len, "UTF-8", e3, NULL, NULL, NULL);

	if (!converted) {
		converted = g_convert_with_fallback ((const gchar *) ssid->data, ssid->len,
		                                     "UTF-8", e1, "?", NULL, NULL, NULL);
	}

	if (!converted) {
		/* If there is still no converted string, the SSID probably
		 * contains characters not valid in the current locale. Convert
		 * the string to ASCII instead.
		 */

		/* Use the printable range of 0x20-0x7E */
		gchar *valid_chars = " !\"#$%&'()*+,-./0123456789:;<=>?@"
		                     "ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`"
		                     "abcdefghijklmnopqrstuvwxyz{|}~";

		converted = g_strndup ((const gchar *)ssid->data, ssid->len);
		g_strcanon (converted, valid_chars, '?');
	}

	return converted;
}

/* Shamelessly ripped from the Linux kernel ieee80211 stack */
/**
 * nm_utils_is_empty_ssid:
 * @ssid: pointer to a buffer containing the SSID data
 * @len: length of the SSID data in @ssid
 *
 * Different manufacturers use different mechanisms for not broadcasting the
 * AP's SSID.  This function attempts to detect blank/empty SSIDs using a
 * number of known SSID-cloaking methods.
 *
 * Returns: %TRUE if the SSID is "empty", %FALSE if it is not
 **/
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

#define ESSID_MAX_SIZE 32

/**
 * nm_utils_escape_ssid:
 * @ssid: pointer to a buffer containing the SSID data
 * @len: length of the SSID data in @ssid
 *
 * This function does a quick printable character conversion of the SSID, simply
 * replacing embedded NULLs and non-printable characters with the hexadecimal
 * representation of that character.  Intended for debugging only, should not
 * be used for display of SSIDs.
 *
 * Returns: pointer to the escaped SSID, which uses an internal static buffer
 * and will be overwritten by subsequent calls to this function
 **/
const char *
nm_utils_escape_ssid (const guint8 * ssid, guint32 len)
{
	static char escaped[ESSID_MAX_SIZE * 2 + 1];
	const guint8 *s = ssid;
	char *d = escaped;

	if (nm_utils_is_empty_ssid (ssid, len)) {
		memcpy (escaped, "<hidden>", sizeof ("<hidden>"));
		return escaped;
	}

	len = MIN (len, (guint32) ESSID_MAX_SIZE);
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

/**
 * nm_utils_same_ssid:
 * @ssid1: first SSID data to compare
 * @ssid2: second SSID data to compare
 * @ignore_trailing_null: %TRUE to ignore one trailing NULL byte
 *
 * Earlier versions of the Linux kernel added a NULL byte to the end of the
 * SSID to enable easy printing of the SSID on the console or in a terminal,
 * but this behavior was problematic (SSIDs are simply byte arrays, not strings)
 * and thus was changed.  This function compensates for that behavior at the
 * cost of some compatibility with odd SSIDs that may legitimately have trailing
 * NULLs, even though that is functionally pointless.
 *
 * Returns: %TRUE if the SSIDs are the same, %FALSE if they are not
 **/
gboolean
nm_utils_same_ssid (const GByteArray * ssid1,
                    const GByteArray * ssid2,
                    gboolean ignore_trailing_null)
{
	guint32 ssid1_len, ssid2_len;

	if (ssid1 == ssid2)
		return TRUE;
	if (!ssid1 || !ssid2)
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
	GHashTable *table = (GHashTable *) user_data;
	GValue *value = (GValue *) val;
	GValue *dup_value;

	dup_value = g_slice_new0 (GValue);
	g_value_init (dup_value, G_VALUE_TYPE (val));
	g_value_copy (value, dup_value);

	g_hash_table_insert (table, g_strdup ((char *) key), dup_value);
}

/**
 * nm_utils_gvalue_hash_dup:
 * @hash: a #GHashTable mapping string:GValue
 *
 * Utility function to duplicate a hash table of #GValues.
 *
 * Returns: (transfer container) (element-type utf8 GObject.Value): a newly allocated duplicated #GHashTable, caller must free the
 * returned hash with g_hash_table_unref() or g_hash_table_destroy()
 **/
GHashTable *
nm_utils_gvalue_hash_dup (GHashTable *hash)
{
	GHashTable *table;

	g_return_val_if_fail (hash != NULL, NULL);

	table = g_hash_table_new_full (g_str_hash, g_str_equal,
	                               (GDestroyNotify) g_free,
	                               value_destroy);

	g_hash_table_foreach (hash, value_dup, table);

	return table;
}

/**
 * nm_utils_slist_free: (skip)
 * @list: a #GSList
 * @elem_destroy_fn: user function called for each element in @list
 *
 * Utility function to free a #GSList.
 *
 * Deprecated: use g_slist_free_full().
 **/
void
nm_utils_slist_free (GSList *list, GDestroyNotify elem_destroy_fn)
{
	g_slist_free_full (list, elem_destroy_fn);
}

gboolean
_nm_utils_string_in_list (const char *str, const char **valid_strings)
{
	int i;

	for (i = 0; valid_strings[i]; i++)
		if (strcmp (str, valid_strings[i]) == 0)
			break;

	return valid_strings[i] != NULL;
}

gboolean
_nm_utils_string_slist_validate (GSList *list, const char **valid_values)
{
	GSList *iter;

	for (iter = list; iter; iter = iter->next) {
		if (!_nm_utils_string_in_list ((char *) iter->data, valid_values))
			return FALSE;
	}

	return TRUE;
}

gboolean
_nm_utils_gvalue_array_validate (GValueArray *elements, guint n_expected, ...)
{
	va_list args;
	GValue *tmp;
	int i;
	gboolean valid = FALSE;

	if (n_expected != elements->n_values)
		return FALSE;

	va_start (args, n_expected);
	for (i = 0; i < n_expected; i++) {
		tmp = g_value_array_get_nth (elements, i);
		if (G_VALUE_TYPE (tmp) != va_arg (args, GType))
			goto done;
	}
	valid = TRUE;

done:
	va_end (args);
	return valid;
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
		if (dev_caps & NM_WIFI_DEVICE_CAP_CIPHER_WEP40)
			if (ap_flags & NM_802_11_AP_SEC_PAIR_WEP40)
				have_pair = TRUE;
		if (dev_caps & NM_WIFI_DEVICE_CAP_CIPHER_WEP104)
			if (ap_flags & NM_802_11_AP_SEC_PAIR_WEP104)
				have_pair = TRUE;
		if (dev_caps & NM_WIFI_DEVICE_CAP_CIPHER_TKIP)
			if (ap_flags & NM_802_11_AP_SEC_PAIR_TKIP)
				have_pair = TRUE;
		if (dev_caps & NM_WIFI_DEVICE_CAP_CIPHER_CCMP)
			if (ap_flags & NM_802_11_AP_SEC_PAIR_CCMP)
				have_pair = TRUE;
	}

	/* Group */
	if (dev_caps & NM_WIFI_DEVICE_CAP_CIPHER_WEP40)
		if (ap_flags & NM_802_11_AP_SEC_GROUP_WEP40)
			have_group = TRUE;
	if (dev_caps & NM_WIFI_DEVICE_CAP_CIPHER_WEP104)
		if (ap_flags & NM_802_11_AP_SEC_GROUP_WEP104)
			have_group = TRUE;
	if (!static_wep) {
		if (dev_caps & NM_WIFI_DEVICE_CAP_CIPHER_TKIP)
			if (ap_flags & NM_802_11_AP_SEC_GROUP_TKIP)
				have_group = TRUE;
		if (dev_caps & NM_WIFI_DEVICE_CAP_CIPHER_CCMP)
			if (ap_flags & NM_802_11_AP_SEC_GROUP_CCMP)
				have_group = TRUE;
	}

	return (have_pair && have_group);
}

/**
 * nm_utils_ap_mode_security_valid:
 * @type: the security type to check device capabilties against,
 * e.g. #NMU_SEC_STATIC_WEP
 * @wifi_caps: bitfield of the capabilities of the specific Wi-Fi device, e.g.
 * #NM_WIFI_DEVICE_CAP_CIPHER_WEP40
 *
 * Given a set of device capabilities, and a desired security type to check
 * against, determines whether the combination of device capabilities and
 * desired security type are valid for AP/Hotspot connections.
 *
 * Returns: %TRUE if the device capabilities are compatible with the desired
 * @type, %FALSE if they are not.
 *
 * Since: 0.9.8
 **/
gboolean
nm_utils_ap_mode_security_valid (NMUtilsSecurityType type,
                                 NMDeviceWifiCapabilities wifi_caps)
{
	if (!(wifi_caps & NM_WIFI_DEVICE_CAP_AP))
		return FALSE;

	/* Return TRUE for any security that wpa_supplicant's lightweight AP
	 * mode can handle: which is open, WEP, and WPA/WPA2 PSK.
	 */
	switch (type) {
	case NMU_SEC_NONE:
	case NMU_SEC_STATIC_WEP:
	case NMU_SEC_WPA_PSK:
	case NMU_SEC_WPA2_PSK:
		return TRUE;
	default:
		break;
	}
	return FALSE;
}

/**
 * nm_utils_security_valid:
 * @type: the security type to check AP flags and device capabilties against,
 * e.g. #NMU_SEC_STATIC_WEP
 * @wifi_caps: bitfield of the capabilities of the specific Wi-Fi device, e.g.
 * #NM_WIFI_DEVICE_CAP_CIPHER_WEP40
 * @have_ap: whether the @ap_flags, @ap_wpa, and @ap_rsn arguments are valid
 * @adhoc: whether the capabilities being tested are from an Ad-Hoc AP (IBSS)
 * @ap_flags: bitfield of AP capabilities, e.g. #NM_802_11_AP_FLAGS_PRIVACY
 * @ap_wpa: bitfield of AP capabilties derived from the AP's WPA beacon,
 * e.g. (#NM_802_11_AP_SEC_PAIR_TKIP | #NM_802_11_AP_SEC_KEY_MGMT_PSK)
 * @ap_rsn: bitfield of AP capabilties derived from the AP's RSN/WPA2 beacon,
 * e.g. (#NM_802_11_AP_SEC_PAIR_CCMP | #NM_802_11_AP_SEC_PAIR_TKIP)
 *
 * Given a set of device capabilities, and a desired security type to check
 * against, determines whether the combination of device, desired security
 * type, and AP capabilities intersect.
 *
 * NOTE: this function cannot handle checking security for AP/Hotspot mode;
 * use nm_utils_ap_mode_security_valid() instead.
 *
 * Returns: %TRUE if the device capabilities and AP capabilties intersect and are
 * compatible with the desired @type, %FALSE if they are not
 **/
gboolean
nm_utils_security_valid (NMUtilsSecurityType type,
                         NMDeviceWifiCapabilities wifi_caps,
                         gboolean have_ap,
                         gboolean adhoc,
                         NM80211ApFlags ap_flags,
                         NM80211ApSecurityFlags ap_wpa,
                         NM80211ApSecurityFlags ap_rsn)
{
	gboolean good = TRUE;

	if (!have_ap) {
		if (type == NMU_SEC_NONE)
			return TRUE;
		if (   (type == NMU_SEC_STATIC_WEP)
		    || ((type == NMU_SEC_DYNAMIC_WEP) && !adhoc)
		    || ((type == NMU_SEC_LEAP) && !adhoc)) {
			if (wifi_caps & (NM_WIFI_DEVICE_CAP_CIPHER_WEP40 | NM_WIFI_DEVICE_CAP_CIPHER_WEP104))
				return TRUE;
			else
				return FALSE;
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
		if (adhoc)
			return FALSE;
		/* Fall through */
	case NMU_SEC_STATIC_WEP:
		g_assert (have_ap);
		if (!(ap_flags & NM_802_11_AP_FLAGS_PRIVACY))
			return FALSE;
		if (ap_wpa || ap_rsn) {
			if (!device_supports_ap_ciphers (wifi_caps, ap_wpa, TRUE))
				if (!device_supports_ap_ciphers (wifi_caps, ap_rsn, TRUE))
					return FALSE;
		}
		break;
	case NMU_SEC_DYNAMIC_WEP:
		if (adhoc)
			return FALSE;
		g_assert (have_ap);
		if (ap_rsn || !(ap_flags & NM_802_11_AP_FLAGS_PRIVACY))
			return FALSE;
		/* Some APs broadcast minimal WPA-enabled beacons that must be handled */
		if (ap_wpa) {
			if (!(ap_wpa & NM_802_11_AP_SEC_KEY_MGMT_802_1X))
				return FALSE;
			if (!device_supports_ap_ciphers (wifi_caps, ap_wpa, FALSE))
				return FALSE;
		}
		break;
	case NMU_SEC_WPA_PSK:
		if (adhoc)
			return FALSE;  /* FIXME: Kernel WPA Ad-Hoc support is buggy */
		if (!(wifi_caps & NM_WIFI_DEVICE_CAP_WPA))
			return FALSE;
		if (have_ap) {
			/* Ad-Hoc WPA APs won't necessarily have the PSK flag set, and
			 * they don't have any pairwise ciphers. */
			if (adhoc) {
				/* coverity[dead_error_line] */
				if (   (ap_wpa & NM_802_11_AP_SEC_GROUP_TKIP)
				    && (wifi_caps & NM_WIFI_DEVICE_CAP_CIPHER_TKIP))
					return TRUE;
				if (   (ap_wpa & NM_802_11_AP_SEC_GROUP_CCMP)
				    && (wifi_caps & NM_WIFI_DEVICE_CAP_CIPHER_CCMP))
					return TRUE;
			} else {
				if (ap_wpa & NM_802_11_AP_SEC_KEY_MGMT_PSK) {
					if (   (ap_wpa & NM_802_11_AP_SEC_PAIR_TKIP)
					    && (wifi_caps & NM_WIFI_DEVICE_CAP_CIPHER_TKIP))
						return TRUE;
					if (   (ap_wpa & NM_802_11_AP_SEC_PAIR_CCMP)
					    && (wifi_caps & NM_WIFI_DEVICE_CAP_CIPHER_CCMP))
						return TRUE;
				}
			}
			return FALSE;
		}
		break;
	case NMU_SEC_WPA2_PSK:
		if (adhoc)
			return FALSE;  /* FIXME: Kernel WPA Ad-Hoc support is buggy */
		if (!(wifi_caps & NM_WIFI_DEVICE_CAP_RSN))
			return FALSE;
		if (have_ap) {
			/* Ad-Hoc WPA APs won't necessarily have the PSK flag set, and
			 * they don't have any pairwise ciphers, nor any RSA flags yet. */
			if (adhoc) {
				/* coverity[dead_error_line] */
				if (wifi_caps & NM_WIFI_DEVICE_CAP_CIPHER_TKIP)
					return TRUE;
				if (wifi_caps & NM_WIFI_DEVICE_CAP_CIPHER_CCMP)
					return TRUE;
			} else {
				if (ap_rsn & NM_802_11_AP_SEC_KEY_MGMT_PSK) {
					if (   (ap_rsn & NM_802_11_AP_SEC_PAIR_TKIP)
					    && (wifi_caps & NM_WIFI_DEVICE_CAP_CIPHER_TKIP))
						return TRUE;
					if (   (ap_rsn & NM_802_11_AP_SEC_PAIR_CCMP)
					    && (wifi_caps & NM_WIFI_DEVICE_CAP_CIPHER_CCMP))
						return TRUE;
				}
			}
			return FALSE;
		}
		break;
	case NMU_SEC_WPA_ENTERPRISE:
		if (adhoc)
			return FALSE;
		if (!(wifi_caps & NM_WIFI_DEVICE_CAP_WPA))
			return FALSE;
		if (have_ap) {
			if (!(ap_wpa & NM_802_11_AP_SEC_KEY_MGMT_802_1X))
				return FALSE;
			/* Ensure at least one WPA cipher is supported */
			if (!device_supports_ap_ciphers (wifi_caps, ap_wpa, FALSE))
				return FALSE;
		}
		break;
	case NMU_SEC_WPA2_ENTERPRISE:
		if (adhoc)
			return FALSE;
		if (!(wifi_caps & NM_WIFI_DEVICE_CAP_RSN))
			return FALSE;
		if (have_ap) {
			if (!(ap_rsn & NM_802_11_AP_SEC_KEY_MGMT_802_1X))
				return FALSE;
			/* Ensure at least one WPA cipher is supported */
			if (!device_supports_ap_ciphers (wifi_caps, ap_rsn, FALSE))
				return FALSE;
		}
		break;
	default:
		good = FALSE;
		break;
	}

	return good;
}

/**
 * nm_utils_wep_key_valid:
 * @key: a string that might be a WEP key
 * @wep_type: the #NMWepKeyType type of the WEP key
 *
 * Checks if @key is a valid WEP key
 *
 * Returns: %TRUE if @key is a WEP key, %FALSE if not
 *
 * Since: 0.9.8
 */
gboolean
nm_utils_wep_key_valid (const char *key, NMWepKeyType wep_type)
{
	int keylen, i;

	if (!key)
		return FALSE;

	keylen = strlen (key);
	if (   wep_type == NM_WEP_KEY_TYPE_KEY
	    || wep_type == NM_WEP_KEY_TYPE_UNKNOWN) {
		if (keylen == 10 || keylen == 26) {
			/* Hex key */
			for (i = 0; i < keylen; i++) {
				if (!g_ascii_isxdigit (key[i]))
					return FALSE;
			}
		} else if (keylen == 5 || keylen == 13) {
			/* ASCII key */
			for (i = 0; i < keylen; i++) {
				if (!g_ascii_isprint (key[i]))
					return FALSE;
			}
		} else
			return FALSE;

	} else if (wep_type == NM_WEP_KEY_TYPE_PASSPHRASE) {
		if (!keylen || keylen > 64)
			return FALSE;
	}

	return TRUE;
}

/**
 * nm_utils_wpa_psk_valid:
 * @psk: a string that might be a WPA PSK
 *
 * Checks if @psk is a valid WPA PSK
 *
 * Returns: %TRUE if @psk is a WPA PSK, %FALSE if not
 *
 * Since: 0.9.8
 */
gboolean
nm_utils_wpa_psk_valid (const char *psk)
{
	int psklen, i;

	if (!psk)
		return FALSE;

	psklen = strlen (psk);
	if (psklen < 8 || psklen > 64)
		return FALSE;

	if (psklen == 64) {
		/* Hex PSK */
		for (i = 0; i < psklen; i++) {
			if (!g_ascii_isxdigit (psk[i]))
				return FALSE;
		}
	}

	return TRUE;
}

/**
 * nm_utils_ip4_addresses_from_gvalue:
 * @value: #GValue containing a #GPtrArray of #GArrays of #guint32s
 *
 * Utility function to convert a #GPtrArray of #GArrays of #guint32s representing
 * a list of NetworkManager IPv4 addresses (which is a tuple of address, gateway,
 * and prefix) into a #GSList of #NMIP4Address objects.  The specific format of
 * this serialization is not guaranteed to be stable and the #GArray may be
 * extended in the future.
 *
 * Returns: (transfer full) (element-type NMIP4Address): a newly allocated #GSList of #NMIP4Address objects
 **/
GSList *
nm_utils_ip4_addresses_from_gvalue (const GValue *value)
{
	GPtrArray *addresses;
	int i;
	GSList *list = NULL;

	addresses = (GPtrArray *) g_value_get_boxed (value);
	for (i = 0; addresses && (i < addresses->len); i++) {
		GArray *array = (GArray *) g_ptr_array_index (addresses, i);
		NMIP4Address *addr;

		if (array->len < 3) {
			g_warning ("Ignoring invalid IP4 address");
			continue;
		}

		addr = nm_ip4_address_new ();
		nm_ip4_address_set_address (addr, g_array_index (array, guint32, 0));
		nm_ip4_address_set_prefix (addr, g_array_index (array, guint32, 1));
		nm_ip4_address_set_gateway (addr, g_array_index (array, guint32, 2));
		list = g_slist_prepend (list, addr);
	}

	return g_slist_reverse (list);
}

/**
 * nm_utils_ip4_addresses_to_gvalue:
 * @list: (element-type NMIP4Address): a list of #NMIP4Address objects
 * @value: a pointer to a #GValue into which to place the converted addresses,
 * which should be unset by the caller (when no longer needed) with
 * g_value_unset().
 *
 * Utility function to convert a #GSList of #NMIP4Address objects into a
 * #GPtrArray of #GArrays of #guint32s representing a list of NetworkManager IPv4
 * addresses (which is a tuple of address, gateway, and prefix).   The specific
 * format of this serialization is not guaranteed to be stable and may be
 * extended in the future.
 **/
void
nm_utils_ip4_addresses_to_gvalue (GSList *list, GValue *value)
{
	GPtrArray *addresses;
	GSList *iter;

	addresses = g_ptr_array_new ();

	for (iter = list; iter; iter = iter->next) {
		NMIP4Address *addr = (NMIP4Address *) iter->data;
		GArray *array;
		guint32 tmp;

		array = g_array_sized_new (FALSE, TRUE, sizeof (guint32), 3);

		tmp = nm_ip4_address_get_address (addr);
		g_array_append_val (array, tmp);

		tmp = nm_ip4_address_get_prefix (addr);
		g_array_append_val (array, tmp);

		tmp = nm_ip4_address_get_gateway (addr);
		g_array_append_val (array, tmp);

		g_ptr_array_add (addresses, array);
	}

	g_value_take_boxed (value, addresses);
}

/**
 * nm_utils_ip4_routes_from_gvalue:
 * @value: #GValue containing a #GPtrArray of #GArrays of #guint32s
 *
 * Utility function to convert a #GPtrArray of #GArrays of #guint32s representing
 * a list of NetworkManager IPv4 routes (which is a tuple of route, next hop,
 * prefix, and metric) into a #GSList of #NMIP4Route objects.  The specific
 * format of this serialization is not guaranteed to be stable and may be
 * extended in the future.
 *
 * Returns: (transfer full) (element-type NMIP4Route): a newly allocated #GSList of #NMIP4Route objects
 **/
GSList *
nm_utils_ip4_routes_from_gvalue (const GValue *value)
{
	GPtrArray *routes;
	int i;
	GSList *list = NULL;

	routes = (GPtrArray *) g_value_get_boxed (value);
	for (i = 0; routes && (i < routes->len); i++) {
		GArray *array = (GArray *) g_ptr_array_index (routes, i);
		NMIP4Route *route;

		if (array->len < 4) {
			g_warning ("Ignoring invalid IP4 route");
			continue;
		}

		route = nm_ip4_route_new ();
		nm_ip4_route_set_dest (route, g_array_index (array, guint32, 0));
		nm_ip4_route_set_prefix (route, g_array_index (array, guint32, 1));
		nm_ip4_route_set_next_hop (route, g_array_index (array, guint32, 2));
		nm_ip4_route_set_metric (route, g_array_index (array, guint32, 3));
		list = g_slist_prepend (list, route);
	}

	return g_slist_reverse (list);
}

/**
 * nm_utils_ip4_routes_to_gvalue:
 * @list: (element-type NMIP4Route): a list of #NMIP4Route objects
 * @value: a pointer to a #GValue into which to place the converted routes,
 * which should be unset by the caller (when no longer needed) with
 * g_value_unset().
 *
 * Utility function to convert a #GSList of #NMIP4Route objects into a
 * #GPtrArray of #GArrays of #guint32s representing a list of NetworkManager IPv4
 * routes (which is a tuple of route, next hop, prefix, and metric).   The
 * specific format of this serialization is not guaranteed to be stable and may
 * be extended in the future.
 **/
void
nm_utils_ip4_routes_to_gvalue (GSList *list, GValue *value)
{
	GPtrArray *routes;
	GSList *iter;

	routes = g_ptr_array_new ();

	for (iter = list; iter; iter = iter->next) {
		NMIP4Route *route = (NMIP4Route *) iter->data;
		GArray *array;
		guint32 tmp;

		array = g_array_sized_new (FALSE, TRUE, sizeof (guint32), 3);

		tmp = nm_ip4_route_get_dest (route);
		g_array_append_val (array, tmp);

		tmp = nm_ip4_route_get_prefix (route);
		g_array_append_val (array, tmp);

		tmp = nm_ip4_route_get_next_hop (route);
		g_array_append_val (array, tmp);

		tmp = nm_ip4_route_get_metric (route);
		g_array_append_val (array, tmp);

		g_ptr_array_add (routes, array);
	}

	g_value_take_boxed (value, routes);
}

/**
 * nm_utils_ip4_netmask_to_prefix:
 * @netmask: an IPv4 netmask in network byte order
 *
 * Returns: the CIDR prefix represented by the netmask
 **/
guint32
nm_utils_ip4_netmask_to_prefix (guint32 netmask)
{
	guint32 prefix;
	guint8 v;
	const guint8 *p = (guint8 *) &netmask;

	if (p[3]) {
		prefix = 24;
		v = p[3];
	} else if (p[2]) {
		prefix = 16;
		v = p[2];
	} else if (p[1]) {
		prefix = 8;
		v = p[1];
	} else {
		prefix = 0;
		v = p[0];
	}

	while (v) {
		prefix++;
		v <<= 1;
	}

	return prefix;
}

/**
 * nm_utils_ip4_prefix_to_netmask:
 * @prefix: a CIDR prefix
 *
 * Returns: the netmask represented by the prefix, in network byte order
 **/
guint32
nm_utils_ip4_prefix_to_netmask (guint32 prefix)
{
	return prefix < 32 ? ~htonl(0xFFFFFFFF >> prefix) : 0xFFFFFFFF;
}


/**
 * nm_utils_ip4_get_default_prefix:
 * @ip: an IPv4 address (in network byte order)
 *
 * When the Internet was originally set up, various ranges of IP addresses were
 * segmented into three network classes: A, B, and C.  This function will return
 * a prefix that is associated with the IP address specified defining where it
 * falls in the predefined classes.
 *
 * Returns: the default class prefix for the given IP
 **/
/* The function is originally from ipcalc.c of Red Hat's initscripts. */
guint32
nm_utils_ip4_get_default_prefix (guint32 ip)
{
	if (((ntohl (ip) & 0xFF000000) >> 24) <= 127)
		return 8;  /* Class A - 255.0.0.0 */
	else if (((ntohl (ip) & 0xFF000000) >> 24) <= 191)
		return 16;  /* Class B - 255.255.0.0 */

	return 24;  /* Class C - 255.255.255.0 */
}

/**
 * nm_utils_ip6_addresses_from_gvalue:
 * @value: gvalue containing a GPtrArray of GValueArrays of (GArray of guchars) and #guint32
 *
 * Utility function to convert a #GPtrArray of #GValueArrays of (#GArray of guchars) and #guint32
 * representing a list of NetworkManager IPv6 addresses (which is a tuple of address,
 * prefix, and gateway), into a #GSList of #NMIP6Address objects.  The specific format of
 * this serialization is not guaranteed to be stable and the #GValueArray may be
 * extended in the future.
 *
 * Returns: (transfer full) (element-type NMIP6Address): a newly allocated #GSList of #NMIP6Address objects
 **/
GSList *
nm_utils_ip6_addresses_from_gvalue (const GValue *value)
{
	GPtrArray *addresses;
	int i;
	GSList *list = NULL;

	addresses = (GPtrArray *) g_value_get_boxed (value);

	for (i = 0; addresses && (i < addresses->len); i++) {
		GValueArray *elements = (GValueArray *) g_ptr_array_index (addresses, i);
		GValue *tmp;
		GByteArray *ba_addr;
		GByteArray *ba_gw = NULL;
		NMIP6Address *addr;
		guint32 prefix;

		if (elements->n_values < 2 || elements->n_values > 3) {
			g_warning ("%s: ignoring invalid IP6 address structure", __func__);
			continue;
		}

		/* Third element (gateway) is optional */
		if (   !_nm_utils_gvalue_array_validate (elements, 2, DBUS_TYPE_G_UCHAR_ARRAY, G_TYPE_UINT)
		    && !_nm_utils_gvalue_array_validate (elements, 3, DBUS_TYPE_G_UCHAR_ARRAY, G_TYPE_UINT, DBUS_TYPE_G_UCHAR_ARRAY)) {
			g_warning ("%s: ignoring invalid IP6 address structure", __func__);
			continue;
		}

		tmp = g_value_array_get_nth (elements, 0);
		ba_addr = g_value_get_boxed (tmp);
		if (ba_addr->len != 16) {
			g_warning ("%s: ignoring invalid IP6 address of length %d",
			           __func__, ba_addr->len);
			continue;
		}

		tmp = g_value_array_get_nth (elements, 1);
		prefix = g_value_get_uint (tmp);
		if (prefix > 128) {
			g_warning ("%s: ignoring invalid IP6 prefix %d",
			           __func__, prefix);
			continue;
		}

		if (elements->n_values == 3) {
			tmp = g_value_array_get_nth (elements, 2);
			ba_gw = g_value_get_boxed (tmp);
			if (ba_gw->len != 16) {
				g_warning ("%s: ignoring invalid IP6 gateway address of length %d",
				           __func__, ba_gw->len);
				continue;
			}
		}

		addr = nm_ip6_address_new ();
		nm_ip6_address_set_prefix (addr, prefix);
		nm_ip6_address_set_address (addr, (const struct in6_addr *) ba_addr->data);
		if (ba_gw)
			nm_ip6_address_set_gateway (addr, (const struct in6_addr *) ba_gw->data);

		list = g_slist_prepend (list, addr);
	}

	return g_slist_reverse (list);
}

/**
 * nm_utils_ip6_addresses_to_gvalue:
 * @list: (element-type NMIP6Address): a list of #NMIP6Address objects
 * @value: a pointer to a #GValue into which to place the converted addresses,
 * which should be unset by the caller (when no longer needed) with
 * g_value_unset().
 *
 * Utility function to convert a #GSList of #NMIP6Address objects into a
 * #GPtrArray of #GValueArrays representing a list of NetworkManager IPv6 addresses
 * (which is a tuple of address, prefix, and gateway). The specific format of
 * this serialization is not guaranteed to be stable and may be extended in the
 * future.
 **/
void
nm_utils_ip6_addresses_to_gvalue (GSList *list, GValue *value)
{
	GPtrArray *addresses;
	GSList *iter;

	addresses = g_ptr_array_new ();

	for (iter = list; iter; iter = iter->next) {
		NMIP6Address *addr = (NMIP6Address *) iter->data;
		GValueArray *array;
		GValue element = G_VALUE_INIT;
		GByteArray *ba;

		array = g_value_array_new (3);

		/* IP address */
		g_value_init (&element, DBUS_TYPE_G_UCHAR_ARRAY);
		ba = g_byte_array_new ();
		g_byte_array_append (ba, (guint8 *) nm_ip6_address_get_address (addr), 16);
		g_value_take_boxed (&element, ba);
		g_value_array_append (array, &element);
		g_value_unset (&element);

		/* Prefix */
		g_value_init (&element, G_TYPE_UINT);
		g_value_set_uint (&element, nm_ip6_address_get_prefix (addr));
		g_value_array_append (array, &element);
		g_value_unset (&element);

		/* Gateway */
		g_value_init (&element, DBUS_TYPE_G_UCHAR_ARRAY);
		ba = g_byte_array_new ();
		g_byte_array_append (ba, (guint8 *) nm_ip6_address_get_gateway (addr), 16);
		g_value_take_boxed (&element, ba);
		g_value_array_append (array, &element);
		g_value_unset (&element);

		g_ptr_array_add (addresses, array);
	}

	g_value_take_boxed (value, addresses);
}

/**
 * nm_utils_ip6_routes_from_gvalue:
 * @value: #GValue containing a #GPtrArray of #GValueArrays of (#GArray of #guchars), #guint32,
 * (#GArray of #guchars), and #guint32
 *
 * Utility function #GPtrArray of #GValueArrays of (#GArray of #guchars), #guint32,
 * (#GArray of #guchars), and #guint32 representing a list of NetworkManager IPv6
 * routes (which is a tuple of destination, prefix, next hop, and metric)
 * into a #GSList of #NMIP6Route objects.  The specific format of this serialization
 * is not guaranteed to be stable and may be extended in the future.
 *
 * Returns: (transfer full) (element-type NMIP6Route): a newly allocated #GSList of #NMIP6Route objects
 **/
GSList *
nm_utils_ip6_routes_from_gvalue (const GValue *value)
{
	GPtrArray *routes;
	int i;
	GSList *list = NULL;

	routes = (GPtrArray *) g_value_get_boxed (value);
	for (i = 0; routes && (i < routes->len); i++) {
		GValueArray *route_values = (GValueArray *) g_ptr_array_index (routes, i);
		GByteArray *dest, *next_hop;
		guint prefix, metric;
		NMIP6Route *route;

		if (!_nm_utils_gvalue_array_validate (route_values, 4,
		                                      DBUS_TYPE_G_UCHAR_ARRAY,
		                                      G_TYPE_UINT,
		                                      DBUS_TYPE_G_UCHAR_ARRAY,
		                                      G_TYPE_UINT)) {
			g_warning ("Ignoring invalid IP6 route");
			continue;
		}

		dest = g_value_get_boxed (g_value_array_get_nth (route_values, 0));
		if (dest->len != 16) {
			g_warning ("%s: ignoring invalid IP6 dest address of length %d",
			           __func__, dest->len);
			continue;
		}

		prefix = g_value_get_uint (g_value_array_get_nth (route_values, 1));

		next_hop = g_value_get_boxed (g_value_array_get_nth (route_values, 2));
		if (next_hop->len != 16) {
			g_warning ("%s: ignoring invalid IP6 next_hop address of length %d",
			           __func__, next_hop->len);
			continue;
		}

		metric = g_value_get_uint (g_value_array_get_nth (route_values, 3));

		route = nm_ip6_route_new ();
		nm_ip6_route_set_dest (route, (struct in6_addr *)dest->data);
		nm_ip6_route_set_prefix (route, prefix);
		nm_ip6_route_set_next_hop (route, (struct in6_addr *)next_hop->data);
		nm_ip6_route_set_metric (route, metric);
		list = g_slist_prepend (list, route);
	}

	return g_slist_reverse (list);
}

/**
 * nm_utils_ip6_routes_to_gvalue:
 * @list: (element-type NMIP6Route): a list of #NMIP6Route objects
 * @value: a pointer to a #GValue into which to place the converted routes,
 * which should be unset by the caller (when no longer needed) with
 * g_value_unset().
 *
 * Utility function to convert a #GSList of #NMIP6Route objects into a #GPtrArray of
 * #GValueArrays of (#GArray of #guchars), #guint32, (#GArray of #guchars), and #guint32
 * representing a list of NetworkManager IPv6 routes (which is a tuple of destination,
 * prefix, next hop, and metric).  The specific format of this serialization is not
 * guaranteed to be stable and may be extended in the future.
 **/
void
nm_utils_ip6_routes_to_gvalue (GSList *list, GValue *value)
{
	GPtrArray *routes;
	GSList *iter;

	routes = g_ptr_array_new ();

	for (iter = list; iter; iter = iter->next) {
		NMIP6Route *route = (NMIP6Route *) iter->data;
		GValueArray *array;
		const struct in6_addr *addr;
		GByteArray *ba;
		GValue element = G_VALUE_INIT;

		array = g_value_array_new (4);

		g_value_init (&element, DBUS_TYPE_G_UCHAR_ARRAY);
		addr = nm_ip6_route_get_dest (route);
		ba = g_byte_array_new ();
		g_byte_array_append (ba, (guchar *)addr, sizeof (*addr));
		g_value_take_boxed (&element, ba);
		g_value_array_append (array, &element);
		g_value_unset (&element);

		g_value_init (&element, G_TYPE_UINT);
		g_value_set_uint (&element, nm_ip6_route_get_prefix (route));
		g_value_array_append (array, &element);
		g_value_unset (&element);

		g_value_init (&element, DBUS_TYPE_G_UCHAR_ARRAY);
		addr = nm_ip6_route_get_next_hop (route);
		ba = g_byte_array_new ();
		g_byte_array_append (ba, (guchar *)addr, sizeof (*addr));
		g_value_take_boxed (&element, ba);
		g_value_array_append (array, &element);
		g_value_unset (&element);

		g_value_init (&element, G_TYPE_UINT);
		g_value_set_uint (&element, nm_ip6_route_get_metric (route));
		g_value_array_append (array, &element);
		g_value_unset (&element);

		g_ptr_array_add (routes, array);
	}

	g_value_take_boxed (value, routes);
}

/**
 * nm_utils_ip6_dns_from_gvalue: (skip)
 * @value: a #GValue
 *
 * Converts a #GValue containing a #GPtrArray of IP6 DNS, represented as
 * #GByteArrays into a #GSList of <literal><type>struct in6_addr</type></literal>s.
 *
 * Returns: a #GSList of IP6 addresses.
 */
GSList *
nm_utils_ip6_dns_from_gvalue (const GValue *value)
{
	GPtrArray *dns;
	int i;
	GSList *list = NULL;

	dns = (GPtrArray *) g_value_get_boxed (value);
	for (i = 0; dns && (i < dns->len); i++) {
		GByteArray *bytearray = (GByteArray *) g_ptr_array_index (dns, i);
		struct in6_addr *addr;

		if (bytearray->len != 16) {
			g_warning ("%s: ignoring invalid IP6 address of length %d",
			           __func__, bytearray->len);
			continue;
		}

		addr = g_malloc0 (sizeof (struct in6_addr));
		memcpy (addr->s6_addr, bytearray->data, bytearray->len);
		list = g_slist_prepend (list, addr);
	}

	return g_slist_reverse (list);
}

/**
 * nm_utils_ip6_dns_to_gvalue: (skip)
 * @list: a list of #NMIP6Route objects
 * @value: a pointer to a #GValue into which to place the converted DNS server
 * addresses, which should be unset by the caller (when no longer needed) with
 * g_value_unset().
 *
 * Utility function to convert a #GSList of <literal><type>struct
 * in6_addr</type></literal> structs into a #GPtrArray of #GByteArrays
 * representing each server's IPv6 addresses in network byte order.
 * The specific format of this serialization is not guaranteed to be
 * stable and may be extended in the future.
 */
void
nm_utils_ip6_dns_to_gvalue (GSList *list, GValue *value)
{
	GPtrArray *dns;
	GSList *iter;

	dns = g_ptr_array_new ();

	for (iter = list; iter; iter = iter->next) {
		struct in6_addr *addr = (struct in6_addr *) iter->data;
		GByteArray *bytearray;

		bytearray = g_byte_array_sized_new (16);
		g_byte_array_append (bytearray, (guint8 *) addr->s6_addr, 16);
		g_ptr_array_add (dns, bytearray);
	}

	g_value_take_boxed (value, dns);
}

/**
 * nm_utils_uuid_generate:
 *
 * Returns: a newly allocated UUID suitable for use as the #NMSettingConnection
 * object's #NMSettingConnection:id: property.  Should be freed with g_free()
 **/
char *
nm_utils_uuid_generate (void)
{
	uuid_t uuid;
	char *buf;

	buf = g_malloc0 (37);
	uuid_generate_random (uuid);
	uuid_unparse_lower (uuid, &buf[0]);
	return buf;
}

/**
 * nm_utils_uuid_generate_from_string:
 * @s: a string to use as the seed for the UUID
 *
 * For a given @s, this function will always return the same UUID.
 *
 * Returns: a newly allocated UUID suitable for use as the #NMSettingConnection
 * object's #NMSettingConnection:id: property
 **/
char *
nm_utils_uuid_generate_from_string (const char *s)
{
	GError *error = NULL;
	uuid_t uuid;
	char *buf = NULL;

	g_return_val_if_fail (s && *s, NULL);

	if (!nm_utils_init (&error)) {
		g_warning ("error initializing crypto: (%d) %s",
		           error ? error->code : 0,
		           error ? error->message : "unknown");
		if (error)
			g_error_free (error);
		return NULL;
	}

	if (!crypto_md5_hash (NULL, 0, s, strlen (s), (char *) uuid, sizeof (uuid), &error)) {
		g_warning ("error generating UUID: (%d) %s",
		           error ? error->code : 0,
		           error ? error->message : "unknown");
		if (error)
			g_error_free (error);
		return NULL;
	}

	buf = g_malloc0 (37);
	uuid_unparse_lower (uuid, &buf[0]);

	return buf;
}

static char *
make_key (const char *cipher,
          const char *salt,
          const gsize salt_len,
          const char *password,
          gsize *out_len,
          GError **error)
{
	char *key;
	guint32 digest_len = 24; /* DES-EDE3-CBC */

	g_return_val_if_fail (salt != NULL, NULL);
	g_return_val_if_fail (salt_len >= 8, NULL);
	g_return_val_if_fail (password != NULL, NULL);
	g_return_val_if_fail (out_len != NULL, NULL);

	if (!strcmp (cipher, "DES-EDE3-CBC"))
		digest_len = 24;
	else if (!strcmp (cipher, "AES-128-CBC"))
		digest_len = 16;

	key = g_malloc0 (digest_len + 1);

	if (!crypto_md5_hash (salt, salt_len, password, strlen (password), key, digest_len, error)) {
		*out_len = 0;
		memset (key, 0, digest_len);
		g_free (key);
		key = NULL;
	} else
		*out_len = digest_len;

	return key;
}

/**
 * nm_utils_rsa_key_encrypt_helper:
 * @cipher: cipher to use for encryption ("DES-EDE3-CBC" or "AES-128-CBC")
 * @data: RSA private key data to be encrypted
 * @in_password: (allow-none): existing password to use, if any
 * @out_password: (out) (allow-none): if @in_password was %NULL, a random password will be generated
 *  and returned in this argument
 * @error: detailed error information on return, if an error occurred
 *
 * Encrypts the given RSA private key data with the given password (or generates
 * a password if no password was given) and converts the data to PEM format
 * suitable for writing to a file.
 *
 * Returns: (transfer full): on success, PEM-formatted data suitable for writing to a PEM-formatted
 * certificate/private key file.
 **/
static GByteArray *
nm_utils_rsa_key_encrypt_helper (const char *cipher,
                                 const GByteArray *data,
                                 const char *in_password,
                                 char **out_password,
                                 GError **error)
{
	char salt[16];
	int salt_len;
	char *key = NULL, *enc = NULL, *pw_buf[32];
	gsize key_len = 0, enc_len = 0;
	GString *pem = NULL;
	char *tmp, *tmp_password = NULL;
	int left;
	const char *p;
	GByteArray *ret = NULL;

	g_return_val_if_fail (!g_strcmp0 (cipher, CIPHER_DES_EDE3_CBC) || !g_strcmp0 (cipher, CIPHER_AES_CBC), NULL);
	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (data->len > 0, NULL);
	if (out_password)
		g_return_val_if_fail (*out_password == NULL, NULL);

	/* Make the password if needed */
	if (!in_password) {
		if (!crypto_randomize (pw_buf, sizeof (pw_buf), error))
			return NULL;
		in_password = tmp_password = nm_utils_bin2hexstr ((const char *) pw_buf, sizeof (pw_buf), -1);
	}

	if (g_strcmp0 (cipher, CIPHER_AES_CBC) == 0)
		salt_len = 16;
	else
		salt_len = 8;

	if (!crypto_randomize (salt, salt_len, error))
		goto out;

	key = make_key (cipher, &salt[0], salt_len, in_password, &key_len, error);
	if (!key)
		goto out;

	enc = crypto_encrypt (cipher, data, salt, salt_len, key, key_len, &enc_len, error);
	if (!enc)
		goto out;

	pem = g_string_sized_new (enc_len * 2 + 100);
	g_string_append (pem, "-----BEGIN RSA PRIVATE KEY-----\n");
	g_string_append (pem, "Proc-Type: 4,ENCRYPTED\n");

	/* Convert the salt to a hex string */
	tmp = nm_utils_bin2hexstr ((const char *) salt, salt_len, salt_len * 2);
	g_string_append_printf (pem, "DEK-Info: %s,%s\n\n", cipher, tmp);
	g_free (tmp);

	/* Convert the encrypted key to a base64 string */
	p = tmp = g_base64_encode ((const guchar *) enc, enc_len);
	left = strlen (tmp);
	while (left > 0) {
		g_string_append_len (pem, p, (left < 64) ? left : 64);
		g_string_append_c (pem, '\n');
		left -= 64;
		p += 64;
	}
	g_free (tmp);

	g_string_append (pem, "-----END RSA PRIVATE KEY-----\n");

	ret = g_byte_array_sized_new (pem->len);
	g_byte_array_append (ret, (const unsigned char *) pem->str, pem->len);
	if (tmp_password && out_password)
		*out_password = g_strdup (tmp_password);

out:
	if (key) {
		memset (key, 0, key_len);
		g_free (key);
	}
	if (enc) {
		memset (enc, 0, enc_len);
		g_free (enc);
	}
	if (pem)
		g_string_free (pem, TRUE);

	if (tmp_password) {
		memset (tmp_password, 0, strlen (tmp_password));
		g_free (tmp_password);
	}

	return ret;
}

/**
 * nm_utils_rsa_key_encrypt:
 * @data: RSA private key data to be encrypted
 * @in_password: (allow-none): existing password to use, if any
 * @out_password: (out) (allow-none): if @in_password was %NULL, a random password will be generated
 *  and returned in this argument
 * @error: detailed error information on return, if an error occurred
 *
 * Encrypts the given RSA private key data with the given password (or generates
 * a password if no password was given) and converts the data to PEM format
 * suitable for writing to a file. It uses Triple DES cipher for the encryption.
 *
 * Returns: (transfer full): on success, PEM-formatted data suitable for writing to a PEM-formatted
 * certificate/private key file.
 **/
GByteArray *
nm_utils_rsa_key_encrypt (const GByteArray *data,
                          const char *in_password,
                          char **out_password,
                          GError **error)
{


	return nm_utils_rsa_key_encrypt_helper (CIPHER_DES_EDE3_CBC,
	                                        data,
	                                        in_password,
	                                        out_password,
	                                        error);
}

/**
 * nm_utils_rsa_key_encrypt_aes:
 * @data: RSA private key data to be encrypted
 * @in_password: (allow-none): existing password to use, if any
 * @out_password: (out) (allow-none): if @in_password was %NULL, a random password will be generated
 *  and returned in this argument
 * @error: detailed error information on return, if an error occurred
 *
 * Encrypts the given RSA private key data with the given password (or generates
 * a password if no password was given) and converts the data to PEM format
 * suitable for writing to a file.  It uses AES cipher for the encryption.
 *
 * Returns: (transfer full): on success, PEM-formatted data suitable for writing to a PEM-formatted
 * certificate/private key file.
 **/
GByteArray *
nm_utils_rsa_key_encrypt_aes (const GByteArray *data,
                              const char *in_password,
                              char **out_password,
                              GError **error)
{

	return nm_utils_rsa_key_encrypt_helper (CIPHER_AES_CBC,
	                                        data,
	                                        in_password,
	                                        out_password,
	                                        error);
}

/**
 * nm_utils_file_is_pkcs12:
 * @filename: name of the file to test
 *
 * Utility function to find out if the @filename is in PKCS#<!-- -->12 format.
 *
 * Returns: %TRUE if the file is PKCS#<!-- -->12, %FALSE if it is not
 **/
gboolean
nm_utils_file_is_pkcs12 (const char *filename)
{
	return crypto_is_pkcs12_file (filename, NULL);
}

/**********************************************************************************************/

/**
 * nm_utils_file_search_in_paths:
 * @progname: the helper program name, like "iptables"
 *   Must be a non-empty string, without path separator (/).
 * @try_first: (allow-none): a custom path to try first before searching.
 *   It is silently ignored if it is empty or not an absolute path.
 * @paths: (allow-none): a %NULL terminated list of search paths.
 *   Can be empty or %NULL, in which case only @try_first is checked.
 * @file_test_flags: the flags passed to g_file_test() when searching
 *   for @progname. Set it to 0 to skip the g_file_test().
 * @predicate: (scope call): if given, pass the file name to this function
 *   for additional checks. This check is performed after the check for
 *   @file_test_flags. You cannot omit both @file_test_flags and @predicate.
 * @user_data: (closure): (allow-none): user data for @predicate function.
 * @error: (allow-none): on failure, set a "not found" error %G_IO_ERROR %G_IO_ERROR_NOT_FOUND.
 *
 * Searches for a @progname file in a list of search @paths.
 *
 * Returns: (transfer none): the full path to the helper, if found, or %NULL if not found.
 *   The returned string is not owned by the caller, but later
 *   invocations of the function might overwrite it.
 */
const char *
nm_utils_file_search_in_paths (const char *progname,
                               const char *try_first,
                               const char *const *paths,
                               GFileTest file_test_flags,
                               NMUtilsFileSearchInPathsPredicate predicate,
                               gpointer user_data,
                               GError **error)
{
	GString *tmp;
	const char *ret;

	g_return_val_if_fail (!error || !*error, NULL);
	g_return_val_if_fail (progname && progname[0] && !strchr (progname, '/'), NULL);
	g_return_val_if_fail (file_test_flags || predicate, NULL);

	/* Only consider @try_first if it is a valid, absolute path. This makes
	 * it simpler to pass in a path from configure checks. */
	if (   try_first
	    && try_first[0] == '/'
	    && (file_test_flags == 0 || g_file_test (try_first, file_test_flags))
	    && (!predicate || predicate (try_first, user_data)))
		return g_intern_string (try_first);

	if (!paths || !*paths)
		goto NOT_FOUND;

	tmp = g_string_sized_new (50);
	for (; *paths; paths++) {
		if (!*paths)
			continue;
		g_string_append (tmp, *paths);
		if (tmp->str[tmp->len - 1] != '/')
			g_string_append_c (tmp, '/');
		g_string_append (tmp, progname);
		if (   (file_test_flags == 0 || g_file_test (tmp->str, file_test_flags))
		    && (!predicate || predicate (tmp->str, user_data))) {
			ret = g_intern_string (tmp->str);
			g_string_free (tmp, TRUE);
			return ret;
		}
		g_string_set_size (tmp, 0);
	}
	g_string_free (tmp, TRUE);

NOT_FOUND:
	g_set_error (error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND, _("Could not find \"%s\" binary"), progname);
	return NULL;
}

/**********************************************************************************************/

/* Band, channel/frequency stuff for wireless */
struct cf_pair {
	guint32 chan;
	guint32 freq;
};

static struct cf_pair a_table[] = {
	/* A band */
	{  7, 5035 },
	{  8, 5040 },
	{  9, 5045 },
	{ 11, 5055 },
	{ 12, 5060 },
	{ 16, 5080 },
	{ 34, 5170 },
	{ 36, 5180 },
	{ 38, 5190 },
	{ 40, 5200 },
	{ 42, 5210 },
	{ 44, 5220 },
	{ 46, 5230 },
	{ 48, 5240 },
	{ 50, 5250 },
	{ 52, 5260 },
	{ 56, 5280 },
	{ 58, 5290 },
	{ 60, 5300 },
	{ 64, 5320 },
	{ 100, 5500 },
	{ 104, 5520 },
	{ 108, 5540 },
	{ 112, 5560 },
	{ 116, 5580 },
	{ 120, 5600 },
	{ 124, 5620 },
	{ 128, 5640 },
	{ 132, 5660 },
	{ 136, 5680 },
	{ 140, 5700 },
	{ 149, 5745 },
	{ 152, 5760 },
	{ 153, 5765 },
	{ 157, 5785 },
	{ 160, 5800 },
	{ 161, 5805 },
	{ 165, 5825 },
	{ 183, 4915 },
	{ 184, 4920 },
	{ 185, 4925 },
	{ 187, 4935 },
	{ 188, 4945 },
	{ 192, 4960 },
	{ 196, 4980 },
	{ 0, -1 }
};

static struct cf_pair bg_table[] = {
	/* B/G band */
	{ 1, 2412 },
	{ 2, 2417 },
	{ 3, 2422 },
	{ 4, 2427 },
	{ 5, 2432 },
	{ 6, 2437 },
	{ 7, 2442 },
	{ 8, 2447 },
	{ 9, 2452 },
	{ 10, 2457 },
	{ 11, 2462 },
	{ 12, 2467 },
	{ 13, 2472 },
	{ 14, 2484 },
	{ 0, -1 }
};

/**
 * nm_utils_wifi_freq_to_channel:
 * @freq: frequency
 *
 * Utility function to translate a Wi-Fi frequency to its corresponding channel.
 *
 * Returns: the channel represented by the frequency or 0
 **/
guint32
nm_utils_wifi_freq_to_channel (guint32 freq)
{
	int i = 0;

	if (freq > 4900) {
		while (a_table[i].chan && (a_table[i].freq != freq))
			i++;
		return a_table[i].chan;
	} else {
		while (bg_table[i].chan && (bg_table[i].freq != freq))
			i++;
		return bg_table[i].chan;
	}

	return 0;
}

/**
 * nm_utils_wifi_channel_to_freq:
 * @channel: channel
 * @band: frequency band for wireless ("a" or "bg")
 *
 * Utility function to translate a Wi-Fi channel to its corresponding frequency.
 *
 * Returns: the frequency represented by the channel of the band,
 *          or -1 when the freq is invalid, or 0 when the band
 *          is invalid
 **/
guint32
nm_utils_wifi_channel_to_freq (guint32 channel, const char *band)
{
	int i = 0;

	if (!strcmp (band, "a")) {
		while (a_table[i].chan && (a_table[i].chan != channel))
			i++;
		return a_table[i].freq;
	} else if (!strcmp (band, "bg")) {
		while (bg_table[i].chan && (bg_table[i].chan != channel))
			i++;
		return bg_table[i].freq;
	}

	return 0;
}

/**
 * nm_utils_wifi_find_next_channel:
 * @channel: current channel
 * @direction: whether going downward (0 or less) or upward (1 or more)
 * @band: frequency band for wireless ("a" or "bg")
 *
 * Utility function to find out next/previous Wi-Fi channel for a channel.
 *
 * Returns: the next channel in the specified direction or 0
 **/
guint32
nm_utils_wifi_find_next_channel (guint32 channel, int direction, char *band)
{
	size_t a_size = sizeof (a_table) / sizeof (struct cf_pair);
	size_t bg_size = sizeof (bg_table) / sizeof (struct cf_pair);
	struct cf_pair *pair = NULL;

	if (!strcmp (band, "a")) {
		if (channel < a_table[0].chan)
			return a_table[0].chan;
		if (channel > a_table[a_size - 2].chan)
			return a_table[a_size - 2].chan;
		pair = &a_table[0];
	} else if (!strcmp (band, "bg")) {
		if (channel < bg_table[0].chan)
			return bg_table[0].chan;
		if (channel > bg_table[bg_size - 2].chan)
			return bg_table[bg_size - 2].chan;
		pair = &bg_table[0];
	} else {
		g_assert_not_reached ();
		return 0;
	}

	while (pair->chan) {
		if (channel == pair->chan)
			return channel;
		if ((channel < (pair+1)->chan) && (channel > pair->chan)) {
			if (direction > 0)
				return (pair+1)->chan;
			else
				return pair->chan;
		}
		pair++;
	}
	return 0;
}

/**
 * nm_utils_wifi_is_channel_valid:
 * @channel: channel
 * @band: frequency band for wireless ("a" or "bg")
 *
 * Utility function to verify Wi-Fi channel validity.
 *
 * Returns: %TRUE or %FALSE
 **/
gboolean
nm_utils_wifi_is_channel_valid (guint32 channel, const char *band)
{
	struct cf_pair *table = NULL;
	int i = 0;

	if (!strcmp (band, "a"))
		table = a_table;
	else if (!strcmp (band, "bg"))
		table = bg_table;
	else
		return FALSE;

	while (table[i].chan && (table[i].chan != channel))
		i++;

	if (table[i].chan != 0)
		return TRUE;
	else
		return FALSE;
}

/**
 * nm_utils_hwaddr_len:
 * @type: the type of address; either <literal>ARPHRD_ETHER</literal> or
 *   <literal>ARPHRD_INFINIBAND</literal>
 *
 * Returns the length in octets of a hardware address of type @type.
 *
 * Return value: the positive length, or -1 if the type is unknown/unsupported.
 */
int
nm_utils_hwaddr_len (int type)
{
	if (type == ARPHRD_ETHER)
		return ETH_ALEN;
	else if (type == ARPHRD_INFINIBAND)
		return INFINIBAND_ALEN;
	else
		return -1;
}

/**
 * nm_utils_hwaddr_type:
 * @len: the length of hardware address in bytes
 *
 * Returns the type (either <literal>ARPHRD_ETHER</literal> or
 * <literal>ARPHRD_INFINIBAND</literal>) of the raw address given its length.
 *
 * Return value: the type, either <literal>ARPHRD_ETHER</literal> or
 * <literal>ARPHRD_INFINIBAND</literal>.  If the length is unexpected, return -1
 * (unsupported type/length).
 *
 * Deprecated: This could not be extended to cover other types, since
 * there is not a one-to-one mapping between types and lengths. This
 * was mostly only used to get a type to pass to
 * nm_utils_hwaddr_ntoa() or nm_utils_hwaddr_aton() when you only had
 * a length; but you can just use nm_utils_hwaddr_ntoa_len() or
 * nm_utils_hwaddr_aton_len() now instead.
 */
int
nm_utils_hwaddr_type (int len)
{
	if (len == ETH_ALEN)
		return ARPHRD_ETHER;
	else if (len == INFINIBAND_ALEN)
		return ARPHRD_INFINIBAND;
	else
		return -1;
}

#define HEXVAL(c) ((c) <= '9' ? (c) - '0' : ((c) & 0x4F) - 'A' + 10)

/**
 * nm_utils_hwaddr_aton:
 * @asc: the ASCII representation of a hardware address
 * @type: the type of address; either <literal>ARPHRD_ETHER</literal> or
 *   <literal>ARPHRD_INFINIBAND</literal>
 * @buffer: buffer to store the result into
 *
 * Parses @asc and converts it to binary form in @buffer. See
 * nm_utils_hwaddr_atoba() if you'd rather have the result in a
 * #GByteArray.
 *
 * See also nm_utils_hwaddr_aton_len(), which takes an output length
 * instead of a type.
 *
 * Return value: @buffer, or %NULL if @asc couldn't be parsed
 */
guint8 *
nm_utils_hwaddr_aton (const char *asc, int type, gpointer buffer)
{
	int len = nm_utils_hwaddr_len (type);

	if (len <= 0) {
		g_return_val_if_reached (NULL);
		return NULL;
	}
	return nm_utils_hwaddr_aton_len (asc, buffer, len);
}

/**
 * nm_utils_hwaddr_atoba:
 * @asc: the ASCII representation of a hardware address
 * @type: the type of address; either <literal>ARPHRD_ETHER</literal> or
 *   <literal>ARPHRD_INFINIBAND</literal>
 *
 * Parses @asc and converts it to binary form in a #GByteArray. See
 * nm_utils_hwaddr_aton() if you don't want a #GByteArray.
 *
 * Return value: (transfer full): a new #GByteArray, or %NULL if @asc couldn't
 * be parsed
 */
GByteArray *
nm_utils_hwaddr_atoba (const char *asc, int type)
{
	GByteArray *ba;
	int len = nm_utils_hwaddr_len (type);

	if (len <= 0) {
		g_return_val_if_reached (NULL);
		return NULL;
	}

	ba = g_byte_array_sized_new (len);
	g_byte_array_set_size (ba, len);
	if (!nm_utils_hwaddr_aton_len (asc, ba->data, len)) {
		g_byte_array_unref (ba);
		return NULL;
	}

	return ba;
}

/**
 * nm_utils_hwaddr_ntoa:
 * @addr: a binary hardware address
 * @type: the type of address; either <literal>ARPHRD_ETHER</literal> or
 *   <literal>ARPHRD_INFINIBAND</literal>
 *
 * Converts @addr to textual form.
 *
 * See also nm_utils_hwaddr_ntoa_len(), which takes a length instead of
 * a type.
 *
 * Return value: (transfer full): the textual form of @addr
 */
char *
nm_utils_hwaddr_ntoa (gconstpointer addr, int type)
{
	int len = nm_utils_hwaddr_len (type);

	if (len <= 0) {
		g_return_val_if_reached (NULL);
		return NULL;
	}

	return nm_utils_hwaddr_ntoa_len (addr, len);
}

/**
 * nm_utils_hwaddr_aton_len:
 * @asc: the ASCII representation of a hardware address
 * @buffer: buffer to store the result into
 * @length: the expected length in bytes of the result and
 * the size of the buffer in bytes.
 *
 * Parses @asc and converts it to binary form in @buffer.
 * Bytes in @asc can be sepatared by colons (:), or hyphens (-), but not mixed.
 *
 * Return value: @buffer, or %NULL if @asc couldn't be parsed
 *   or would be shorter or longer than @length.
 *
 * Since: 0.9.10
 */
guint8 *
nm_utils_hwaddr_aton_len (const char *asc, gpointer buffer, gsize length)
{
	const char *in = asc;
	guint8 *out = (guint8 *)buffer;
	char delimiter = '\0';

	if (!asc) {
		g_return_val_if_reached (NULL);
		return NULL;
	}
	g_return_val_if_fail (buffer, NULL);
	g_return_val_if_fail (length, NULL);

	while (length && *in) {
		guint8 d1 = in[0], d2 = in[1];

		if (!g_ascii_isxdigit (d1))
			return NULL;

		/* If there's no leading zero (ie "aa:b:cc") then fake it */
		if (d2 && g_ascii_isxdigit (d2)) {
			*out++ = (HEXVAL (d1) << 4) + HEXVAL (d2);
			in += 2;
		} else {
			/* Fake leading zero */
			*out++ = (HEXVAL ('0') << 4) + HEXVAL (d1);
			in += 1;
		}

		length--;
		if (*in) {
			if (delimiter == '\0') {
				if (*in == ':' || *in == '-')
					delimiter = *in;
				else
					return NULL;
			} else {
				if (*in != delimiter)
					return NULL;
			}
			in++;
		}
	}

	if (length == 0 && !*in)
		return buffer;
	else
		return NULL;
}

/**
 * nm_utils_hwaddr_ntoa_len:
 * @addr: a binary hardware address
 * @length: the length of @addr
 *
 * Converts @addr to textual form.
 *
 * Return value: (transfer full): the textual form of @addr
 *
 * Since: 0.9.10
 */
char *
nm_utils_hwaddr_ntoa_len (gconstpointer addr, gsize length)
{
	const guint8 *in = addr;
	char *out, *result;
	const char *LOOKUP = "0123456789ABCDEF";

	g_return_val_if_fail (addr != NULL, g_strdup (""));
	g_return_val_if_fail (length != 0, g_strdup (""));

	result = out = g_malloc (length * 3);
	for (;;) {
		guint8 v = *in++;

		*out++ = LOOKUP[v >> 4];
		*out++ = LOOKUP[v & 0x0F];
		if (--length == 0) {
			*out = 0;
			return result;
		}
		*out++ = ':';
	}
}

/**
 * nm_utils_hwaddr_valid:
 * @asc: the ASCII representation of a hardware address
 *
 * Parses @asc to see if it is a valid hardware address of some type.
 *
 * Return value: %TRUE if @asc appears to be a valid hardware address
 *   of some type, %FALSE if not.
 *
 * Since: 0.9.10
 */
gboolean
nm_utils_hwaddr_valid (const char *asc)
{
	guint8 buf[NM_UTILS_HWADDR_LEN_MAX];
	gsize in_len, out_len;

	if (!asc || !*asc)
		return FALSE;
	in_len = strlen (asc);
	if ((in_len + 1) % 3 != 0)
		return FALSE;
	out_len = (in_len + 1) / 3;
	if (out_len > NM_UTILS_HWADDR_LEN_MAX)
		return FALSE;
	return nm_utils_hwaddr_aton_len (asc, buf, out_len) != NULL;
}

/**
 * nm_utils_bin2hexstr:
 * @bytes: an array of bytes
 * @len: the length of the @bytes array
 * @final_len: an index where to cut off the returned string, or -1
 *
 * Converts a byte-array @bytes into a hexadecimal string.
 * If @final_len is greater than -1, the returned string is terminated at
 * that index (returned_string[final_len] == '\0'),
 *
 * Return value: (transfer full): the textual form of @bytes
 *
 * Since: 0.9.10
 */
/*
 * Code originally by Alex Larsson <alexl@redhat.com> and
 *  copyright Red Hat, Inc. under terms of the LGPL.
 */
char *
nm_utils_bin2hexstr (const char *bytes, int len, int final_len)
{
	static char hex_digits[] = "0123456789abcdef";
	char *result;
	int i;
	gsize buflen = (len * 2) + 1;

	g_return_val_if_fail (bytes != NULL, NULL);
	g_return_val_if_fail (len > 0, NULL);
	g_return_val_if_fail (len < 4096, NULL);   /* Arbitrary limit */
	if (final_len > -1)
		g_return_val_if_fail (final_len < buflen, NULL);

	result = g_malloc0 (buflen);
	for (i = 0; i < len; i++) {
		result[2*i] = hex_digits[(bytes[i] >> 4) & 0xf];
		result[2*i+1] = hex_digits[bytes[i] & 0xf];
	}
	/* Cut converted key off at the correct length for this cipher type */
	if (final_len > -1)
		result[final_len] = '\0';
	else
		result[buflen - 1] = '\0';

	return result;
}

/* From hostap, Copyright (c) 2002-2005, Jouni Malinen <jkmaline@cc.hut.fi> */
/**
 * nm_utils_hex2byte:
 * @hex: a string representing a hex byte
 *
 * Converts a hex string (2 characters) into its byte representation.
 *
 * Return value: a byte, or -1 if @hex doesn't represent a hex byte
 *
 * Since: 0.9.10
 */
int
nm_utils_hex2byte (const char *hex)
{
	int a, b;
	a = g_ascii_xdigit_value (*hex++);
	if (a < 0)
		return -1;
	b = g_ascii_xdigit_value (*hex++);
	if (b < 0)
		return -1;
	return (a << 4) | b;
}

/**
 * nm_utils_hexstr2bin:
 * @hex: an hex string
 * @len: the length of the @hex string (it has to be even)
 *
 * Converts a hexadecimal string @hex into a byte-array. The returned array
 * length is @len/2.
 *
 * Return value: (transfer full): a array of bytes, or %NULL on error
 *
 * Since: 0.9.10
 */
char *
nm_utils_hexstr2bin (const char *hex, size_t len)
{
	size_t       i;
	int          a;
	const char * ipos = hex;
	char *       buf = NULL;
	char *       opos;

	/* Length must be a multiple of 2 */
	if ((len % 2) != 0)
		return NULL;

	opos = buf = g_malloc0 ((len / 2) + 1);
	for (i = 0; i < len; i += 2) {
		a = nm_utils_hex2byte (ipos);
		if (a < 0) {
			g_free (buf);
			return NULL;
		}
		*opos++ = a;
		ipos += 2;
	}
	return buf;
}
/* End from hostap */

/**
 * nm_utils_iface_valid_name:
 * @name: Name of interface
 *
 * This function is a 1:1 copy of the kernel's interface validation
 * function in net/core/dev.c.
 *
 * Returns: %TRUE if interface name is valid, otherwise %FALSE is returned.
 *
 * Since: 0.9.8
 */
gboolean
nm_utils_iface_valid_name (const char *name)
{
	g_return_val_if_fail (name != NULL, FALSE);

	if (*name == '\0')
		return FALSE;

	if (strlen (name) >= 16)
		return FALSE;

	if (!strcmp (name, ".") || !strcmp (name, ".."))
		return FALSE;

	while (*name) {
		if (*name == '/' || g_ascii_isspace (*name))
			return FALSE;
		name++;
	}

	return TRUE;
}

/**
 * nm_utils_is_uuid:
 * @str: a string that might be a UUID
 *
 * Checks if @str is a UUID
 *
 * Returns: %TRUE if @str is a UUID, %FALSE if not
 *
 * Since: 0.9.8
 */
gboolean
nm_utils_is_uuid (const char *str)
{
	const char *p = str;
	int num_dashes = 0;

	while (*p) {
		if (*p == '-')
			num_dashes++;
		else if (!g_ascii_isxdigit (*p))
			return FALSE;
		p++;
	}

	if ((num_dashes == 4) && (p - str == 36))
		return TRUE;

	/* Backwards compat for older configurations */
	if ((num_dashes == 0) && (p - str == 40))
		return TRUE;

	return FALSE;
}

static char _nm_utils_inet_ntop_buffer[NM_UTILS_INET_ADDRSTRLEN];

/**
 * nm_utils_inet4_ntop: (skip)
 * @inaddr: the address that should be converted to string.
 * @dst: the destination buffer, it must contain at least
 *  <literal>INET_ADDRSTRLEN</literal> or %NM_UTILS_INET_ADDRSTRLEN
 *  characters. If set to %NULL, it will return a pointer to an internal, static
 *  buffer (shared with nm_utils_inet6_ntop()).  Beware, that the internal
 *  buffer will be overwritten with ever new call of nm_utils_inet4_ntop() or
 *  nm_utils_inet6_ntop() that does not provied it's own @dst buffer. Also,
 *  using the internal buffer is not thread safe. When in doubt, pass your own
 *  @dst buffer to avoid these issues.
 *
 * Wrapper for inet_ntop.
 *
 * Returns: the input buffer @dst, or a pointer to an
 *  internal, static buffer. This function cannot fail.
 *
 * Since: 0.9.10
 **/
const char *
nm_utils_inet4_ntop (in_addr_t inaddr, char *dst)
{
	return inet_ntop (AF_INET, &inaddr, dst ? dst : _nm_utils_inet_ntop_buffer,
	                  INET_ADDRSTRLEN);
}

/**
 * nm_utils_inet6_ntop: (skip)
 * @in6addr: the address that should be converted to string.
 * @dst: the destination buffer, it must contain at least
 *  <literal>INET6_ADDRSTRLEN</literal> or %NM_UTILS_INET_ADDRSTRLEN
 *  characters. If set to %NULL, it will return a pointer to an internal, static
 *  buffer (shared with nm_utils_inet4_ntop()).  Beware, that the internal
 *  buffer will be overwritten with ever new call of nm_utils_inet4_ntop() or
 *  nm_utils_inet6_ntop() that does not provied it's own @dst buffer. Also,
 *  using the internal buffer is not thread safe. When in doubt, pass your own
 *  @dst buffer to avoid these issues.
 *
 * Wrapper for inet_ntop.
 *
 * Returns: the input buffer @dst, or a pointer to an
 *  internal, static buffer. %NULL is not allowed as @in6addr,
 *  otherwise, this function cannot fail.
 *
 * Since: 0.9.10
 **/
const char *
nm_utils_inet6_ntop (const struct in6_addr *in6addr, char *dst)
{
	g_return_val_if_fail (in6addr, NULL);
	return inet_ntop (AF_INET6, in6addr, dst ? dst : _nm_utils_inet_ntop_buffer,
	                  INET6_ADDRSTRLEN);
}

/**
 * nm_utils_check_virtual_device_compatibility:
 * @virtual_type: a virtual connection type
 * @other_type: a connection type to test against @virtual_type
 *
 * Determines if a connection of type @virtual_type can (in the
 * general case) work with connections of type @other_type.
 *
 * If @virtual_type is %NM_TYPE_SETTING_VLAN, then this checks if
 * @other_type is a valid type for the parent of a VLAN.
 *
 * If @virtual_type is a "master" type (eg, %NM_TYPE_SETTING_BRIDGE),
 * then this checks if @other_type is a valid type for a slave of that
 * master.
 *
 * Note that even if this returns %TRUE it is not guaranteed that
 * <emphasis>every</emphasis> connection of type @other_type is
 * compatible with @virtual_type; it may depend on the exact
 * configuration of the two connections, or on the capabilities of an
 * underlying device driver.
 *
 * Returns: %TRUE or %FALSE
 *
 * Since: 0.9.10
 */
gboolean
nm_utils_check_virtual_device_compatibility (GType virtual_type, GType other_type)
{
	g_return_val_if_fail (_nm_setting_type_is_base_type (virtual_type), FALSE);
	g_return_val_if_fail (_nm_setting_type_is_base_type (other_type), FALSE);

	if (virtual_type == NM_TYPE_SETTING_BOND) {
		return (   other_type == NM_TYPE_SETTING_INFINIBAND
		        || other_type == NM_TYPE_SETTING_WIRED
		        || other_type == NM_TYPE_SETTING_BRIDGE
		        || other_type == NM_TYPE_SETTING_BOND
		        || other_type == NM_TYPE_SETTING_TEAM
		        || other_type == NM_TYPE_SETTING_VLAN);
	} else if (virtual_type == NM_TYPE_SETTING_BRIDGE) {
		return (   other_type == NM_TYPE_SETTING_WIRED
		        || other_type == NM_TYPE_SETTING_BOND
		        || other_type == NM_TYPE_SETTING_TEAM
		        || other_type == NM_TYPE_SETTING_VLAN);
	} else if (virtual_type == NM_TYPE_SETTING_TEAM) {
		return (   other_type == NM_TYPE_SETTING_WIRED
		        || other_type == NM_TYPE_SETTING_BRIDGE
		        || other_type == NM_TYPE_SETTING_BOND
		        || other_type == NM_TYPE_SETTING_TEAM
		        || other_type == NM_TYPE_SETTING_VLAN);
	} else if (virtual_type == NM_TYPE_SETTING_VLAN) {
		return (   other_type == NM_TYPE_SETTING_WIRED
		        || other_type == NM_TYPE_SETTING_WIRELESS
		        || other_type == NM_TYPE_SETTING_BRIDGE
		        || other_type == NM_TYPE_SETTING_BOND
		        || other_type == NM_TYPE_SETTING_TEAM
		        || other_type == NM_TYPE_SETTING_VLAN);
	} else {
		g_warn_if_reached ();
		return FALSE;
	}
}

/***********************************************************/

/* Unused prototypes to make the compiler happy */
gconstpointer nm_utils_get_private (void);
gconstpointer nm_util_get_private (void);


/**
 * nm_utils_get_private:
 *
 * Entry point for NetworkManager-internal API.  You should not use this
 * function for any reason.
 *
 * Returns: Who knows? It's a mystery.
 *
 * Since: 0.9.10
 */
gconstpointer
nm_utils_get_private (void)
{
	/* We told you not to use it! */
	g_assert_not_reached ();
}

/**
 * nm_util_get_private:
 *
 * You should not use this function for any reason.
 *
 * Returns: Who knows? It's a mystery.
 *
 * Since: 0.9.10
 */
gconstpointer
nm_util_get_private (void)
{
	/* We told you not to use it! */
	g_assert_not_reached ();
}
