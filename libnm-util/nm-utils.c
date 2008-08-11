/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

/* NetworkManager -- Network link manager
 *
 * Ray Strode <rstrode@redhat.com>
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
 * (C) Copyright 2005 - 2008 Red Hat, Inc.
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>

#include "wireless-helper.h"

#include <glib.h>
#include <glib-object.h>
#include <dbus/dbus-glib.h>
#include "nm-utils.h"
#include "NetworkManager.h"
#include "nm-dbus-glib-types.h"
#include "nm-setting-ip4-config.h"
#include "nm-setting-ip6-config.h"

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

static char *
string_to_utf8 (const char *str, gsize len)
{
	char *converted = NULL;
	char *lang, *e1 = NULL, *e2 = NULL, *e3 = NULL;

	g_return_val_if_fail (str != NULL, NULL);

	if (g_utf8_validate (str, len, NULL))
		return g_strdup (str);

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

	converted = g_convert (str, len, "UTF-8", e1, NULL, NULL, NULL);
	if (!converted && e2)
		converted = g_convert (str, len, "UTF-8", e2, NULL, NULL, NULL);

	if (!converted && e3)
		converted = g_convert (str, len, "UTF-8", e3, NULL, NULL, NULL);

	if (!converted) {
		converted = g_convert_with_fallback (str, len, "UTF-8", e1,
	                "?", NULL, NULL, NULL);
	}

	return converted;
}

char *
nm_utils_ssid_to_utf8 (const char *ssid, guint32 len)
{
	char *converted = NULL, *buf;
	gsize buflen = MIN (IW_ESSID_MAX_SIZE, (gsize) len);

	g_return_val_if_fail (ssid != NULL, NULL);

	/* New buffer to ensure NULL-termination of SSID */
	buf = g_malloc0 (IW_ESSID_MAX_SIZE + 1);
	memcpy (buf, ssid, buflen);
	converted = string_to_utf8 (buf, buflen);
	g_free (buf);
	return converted;
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
	GHashTable *table = (GHashTable *) user_data;
	GValue *value = (GValue *) val;
	GValue *dup_value;

	dup_value = g_slice_new0 (GValue);
	g_value_init (dup_value, G_VALUE_TYPE (val));
	g_value_copy (value, dup_value);

	g_hash_table_insert (table, g_strdup ((char *) key), dup_value);
}

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

/* Converts a GArray into a UTF-8 string */
char *
nm_utils_garray_to_string (GArray *array)
{
	GString *str;
	int i;
	char c;
	char *converted = NULL;

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

	converted = string_to_utf8 (str->str, (gsize) str->len);
	g_string_free (str, FALSE);
	return converted;
}

void
nm_utils_slist_free (GSList *list, GDestroyNotify elem_destroy_fn)
{
	if (!list)
		return;

	if (elem_destroy_fn)
		g_slist_foreach (list, (GFunc) elem_destroy_fn, NULL);

	g_slist_free (list);
}

gboolean
nm_utils_string_in_list (const char *str, const char **valid_strings)
{
	int i;

	for (i = 0; valid_strings[i]; i++)
		if (strcmp (str, valid_strings[i]) == 0)
			break;

	return valid_strings[i] != NULL;
}

gboolean
nm_utils_string_list_contains (GSList *list, const char *string)
{
	GSList *iter;

	g_return_val_if_fail (string != NULL, FALSE);

	for (iter = list; iter; iter = g_slist_next (iter))
		if (!strcmp (iter->data, string))
			return TRUE;
	return FALSE;
}

gboolean
nm_utils_string_slist_validate (GSList *list, const char **valid_values)
{
	GSList *iter;

	for (iter = list; iter; iter = iter->next) {
		if (!nm_utils_string_in_list ((char *) iter->data, valid_values))
			return FALSE;
	}

	return TRUE;
}

static void
nm_utils_convert_strv_to_slist (const GValue *src_value, GValue *dest_value)
{
	char **str;
	GSList *list = NULL;
	guint i = 0;

	g_return_if_fail (g_type_is_a (G_VALUE_TYPE (src_value), G_TYPE_STRV));

	str = (char **) g_value_get_boxed (src_value);

	while (str[i])
		list = g_slist_prepend (list, g_strdup (str[i++]));

	g_value_take_boxed (dest_value, g_slist_reverse (list));
}

static void
nm_utils_convert_strv_to_string (const GValue *src_value, GValue *dest_value)
{
	GSList *strings;
	GString *printable;
	GSList *iter;

	g_return_if_fail (g_type_is_a (G_VALUE_TYPE (src_value), DBUS_TYPE_G_LIST_OF_STRING));

	strings = (GSList *) g_value_get_boxed (src_value);

	printable = g_string_new ("[");
	for (iter = strings; iter; iter = g_slist_next (iter)) {
		if (iter != strings)
			g_string_append (printable, ", '");
		else
			g_string_append_c (printable, '\'');
		g_string_append (printable, iter->data);
		g_string_append_c (printable, '\'');
	}
	g_string_append_c (printable, ']');

	g_value_take_string (dest_value, printable->str);
	g_string_free (printable, FALSE);
}

static void
nm_utils_convert_uint_array_to_string (const GValue *src_value, GValue *dest_value)
{
	GArray *array;
	GString *printable;
	guint i = 0;

	g_return_if_fail (g_type_is_a (G_VALUE_TYPE (src_value), DBUS_TYPE_G_UINT_ARRAY));

	array = (GArray *) g_value_get_boxed (src_value);

	printable = g_string_new ("[");
	while (array && (i < array->len)) {
		char buf[INET_ADDRSTRLEN + 1];
		struct in_addr addr;

		if (i > 0)
			g_string_append (printable, ", ");

		memset (buf, 0, sizeof (buf));
		addr.s_addr = g_array_index (array, guint32, i++);
		if (!inet_ntop (AF_INET, &addr, buf, INET_ADDRSTRLEN))
			nm_warning ("%s: error converting IP4 address 0x%X",
			            __func__, ntohl (addr.s_addr));
		g_string_append_printf (printable, "%u (%s)", addr.s_addr, buf);
	}
	g_string_append_c (printable, ']');

	g_value_take_string (dest_value, printable->str);
	g_string_free (printable, FALSE);
}

static void
nm_utils_convert_ip4_addr_struct_array_to_string (const GValue *src_value, GValue *dest_value)
{
	GPtrArray *ptr_array;
	GString *printable;
	guint i = 0;

	g_return_if_fail (g_type_is_a (G_VALUE_TYPE (src_value), DBUS_TYPE_G_ARRAY_OF_ARRAY_OF_UINT));

	ptr_array = (GPtrArray *) g_value_get_boxed (src_value);

	printable = g_string_new ("[");
	while (i < ptr_array->len) {
		GArray *array;
		char buf[INET_ADDRSTRLEN + 1];
		struct in_addr addr;

		if (i > 0)
			g_string_append (printable, ", ");

		g_string_append (printable, "{ ");
		array = (GArray *) g_ptr_array_index (ptr_array, i++);
		if (array->len < 2) {
			g_string_append (printable, "invalid");
			continue;
		}

		memset (buf, 0, sizeof (buf));
		addr.s_addr = g_array_index (array, guint32, 0);
		if (!inet_ntop (AF_INET, &addr, buf, INET_ADDRSTRLEN))
			nm_warning ("%s: error converting IP4 address 0x%X",
			            __func__, ntohl (addr.s_addr));
		g_string_append_printf (printable, "ip = %s", buf);
		g_string_append (printable, ", ");

		memset (buf, 0, sizeof (buf));
		addr.s_addr = g_array_index (array, guint32, 1);
		if (!inet_ntop (AF_INET, &addr, buf, INET_ADDRSTRLEN))
			nm_warning ("%s: error converting IP4 address 0x%X",
			            __func__, ntohl (addr.s_addr));
		g_string_append_printf (printable, "mask = %s", buf);

		if (array->len > 2) {
			g_string_append (printable, ", ");

			memset (buf, 0, sizeof (buf));
			addr.s_addr = g_array_index (array, guint32, 2);
			if (!inet_ntop (AF_INET, &addr, buf, INET_ADDRSTRLEN))
				nm_warning ("%s: error converting IP4 address 0x%X",
				            __func__, ntohl (addr.s_addr));
			g_string_append_printf (printable, "gw = %s", buf);
		}

		g_string_append (printable, " }");
	}
	g_string_append_c (printable, ']');

	g_value_take_string (dest_value, printable->str);
	g_string_free (printable, FALSE);
}

static void
convert_one_gvalue_hash_entry (gpointer key, gpointer value, gpointer user_data)
{
	GString *printable = (GString *) user_data;
	char *value_as_string;

	value_as_string = g_strdup_value_contents ((GValue *) value);
	g_string_append_printf (printable, " { '%s': %s },", (const char *) key, value_as_string);
	g_free (value_as_string);
}

static void
nm_utils_convert_gvalue_hash_to_string (const GValue *src_value, GValue *dest_value)
{
	GHashTable *hash;
	GString *printable;

	g_return_if_fail (g_type_is_a (G_VALUE_TYPE (src_value), DBUS_TYPE_G_MAP_OF_VARIANT));

	hash = (GHashTable *) g_value_get_boxed (src_value);

	printable = g_string_new ("[");
	g_hash_table_foreach (hash, convert_one_gvalue_hash_entry, printable);
	g_string_append (printable, " ]");

	g_value_take_string (dest_value, printable->str);
	g_string_free (printable, FALSE);
}

static void
convert_one_string_hash_entry (gpointer key, gpointer value, gpointer user_data)
{
	GString *printable = (GString *) user_data;

	g_string_append_printf (printable, " { '%s': %s },", (const char *) key, (const char *) value);
}

static void
nm_utils_convert_string_hash_to_string (const GValue *src_value, GValue *dest_value)
{
	GHashTable *hash;
	GString *printable;

	g_return_if_fail (g_type_is_a (G_VALUE_TYPE (src_value), DBUS_TYPE_G_MAP_OF_STRING));

	hash = (GHashTable *) g_value_get_boxed (src_value);

	printable = g_string_new ("[");
	g_hash_table_foreach (hash, convert_one_string_hash_entry, printable);
	g_string_append (printable, " ]");

	g_value_take_string (dest_value, printable->str);
	g_string_free (printable, FALSE);
}

void
nm_utils_register_value_transformations (void)
{
	static gboolean registered = FALSE;

	if (G_UNLIKELY (!registered)) {
		g_value_register_transform_func (G_TYPE_STRV, 
		                                 DBUS_TYPE_G_LIST_OF_STRING,
		                                 nm_utils_convert_strv_to_slist);
		g_value_register_transform_func (DBUS_TYPE_G_LIST_OF_STRING,
		                                 G_TYPE_STRING, 
		                                 nm_utils_convert_strv_to_string);
		g_value_register_transform_func (DBUS_TYPE_G_UINT_ARRAY,
		                                 G_TYPE_STRING, 
		                                 nm_utils_convert_uint_array_to_string);
		g_value_register_transform_func (DBUS_TYPE_G_ARRAY_OF_ARRAY_OF_UINT,
		                                 G_TYPE_STRING, 
		                                 nm_utils_convert_ip4_addr_struct_array_to_string);
		g_value_register_transform_func (DBUS_TYPE_G_MAP_OF_VARIANT,
		                                 G_TYPE_STRING, 
		                                 nm_utils_convert_gvalue_hash_to_string);
		g_value_register_transform_func (DBUS_TYPE_G_MAP_OF_STRING,
		                                 G_TYPE_STRING, 
		                                 nm_utils_convert_string_hash_to_string);
		registered = TRUE;
	}
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

gboolean
nm_utils_security_valid (NMUtilsSecurityType type,
                         guint32 dev_caps,
                         gboolean have_ap,
                         gboolean adhoc,
                         guint32 ap_flags,
                         guint32 ap_wpa,
                         guint32 ap_rsn)
{
	gboolean good = TRUE;

	if (!have_ap) {
		if (type == NMU_SEC_NONE)
			return TRUE;
		if (   (type == NMU_SEC_STATIC_WEP)
		    || ((type == NMU_SEC_DYNAMIC_WEP) && !adhoc)
		    || ((type == NMU_SEC_LEAP) && !adhoc)) {
			if (dev_caps & (NM_WIFI_DEVICE_CAP_CIPHER_WEP40 | NM_WIFI_DEVICE_CAP_CIPHER_WEP104))
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
		if (adhoc)
			return FALSE;
		/* Fall through */
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
		if (adhoc)
			return FALSE;
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
		if (!(dev_caps & NM_WIFI_DEVICE_CAP_WPA))
			return FALSE;
		if (have_ap) {
			if (!(ap_flags & NM_802_11_AP_FLAGS_PRIVACY))
				return FALSE;

			if (ap_wpa & NM_802_11_AP_SEC_KEY_MGMT_PSK) {
				if (   (ap_wpa & NM_802_11_AP_SEC_PAIR_TKIP)
				    && (dev_caps & NM_WIFI_DEVICE_CAP_CIPHER_TKIP))
					return TRUE;
				if (   (ap_wpa & NM_802_11_AP_SEC_PAIR_CCMP)
				    && (dev_caps & NM_WIFI_DEVICE_CAP_CIPHER_CCMP))
					return TRUE;
			}
			return FALSE;
		}
		break;
	case NMU_SEC_WPA2_PSK:
		if (!(dev_caps & NM_WIFI_DEVICE_CAP_RSN))
			return FALSE;
		if (have_ap) {
			if (!(ap_flags & NM_802_11_AP_FLAGS_PRIVACY))
				return FALSE;

			if (ap_rsn & NM_802_11_AP_SEC_KEY_MGMT_PSK) {
				if (   (ap_rsn & NM_802_11_AP_SEC_PAIR_TKIP)
				    && (dev_caps & NM_WIFI_DEVICE_CAP_CIPHER_TKIP))
					return TRUE;
				if (   (ap_rsn & NM_802_11_AP_SEC_PAIR_CCMP)
				    && (dev_caps & NM_WIFI_DEVICE_CAP_CIPHER_CCMP))
					return TRUE;
			}
			return FALSE;
		}
		break;
	case NMU_SEC_WPA_ENTERPRISE:
		if (adhoc)
			return FALSE;
		if (!(dev_caps & NM_WIFI_DEVICE_CAP_WPA))
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
		if (adhoc)
			return FALSE;
		if (!(dev_caps & NM_WIFI_DEVICE_CAP_RSN))
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

GSList *
nm_utils_ip4_addresses_from_gvalue (const GValue *value)
{
	GPtrArray *addresses;
	int i;
	GSList *list = NULL;

	addresses = (GPtrArray *) g_value_get_boxed (value);
	for (i = 0; addresses && (i < addresses->len); i++) {
		GArray *array = (GArray *) g_ptr_array_index (addresses, i);
		NMSettingIP4Address *addr;

		if (array->len != 3) {
			nm_warning ("Ignoring invalid IP4 address");
			continue;
		}
		
		addr = g_malloc0 (sizeof (NMSettingIP4Address));
		addr->address = g_array_index (array, guint32, 0);
		addr->prefix = g_array_index (array, guint32, 1);
		addr->gateway = g_array_index (array, guint32, 2);
		list = g_slist_prepend (list, addr);
	}

	return g_slist_reverse (list);
}

void
nm_utils_ip4_addresses_to_gvalue (GSList *list, GValue *value)
{
	GPtrArray *addresses;
	GSList *iter;

	addresses = g_ptr_array_new ();

	for (iter = list; iter; iter = iter->next) {
		NMSettingIP4Address *addr = (NMSettingIP4Address *) iter->data;
		GArray *array;

		array = g_array_sized_new (FALSE, TRUE, sizeof (guint32), 3);

		g_array_append_val (array, addr->address);
		g_array_append_val (array, addr->prefix);
		g_array_append_val (array, addr->gateway);
		g_ptr_array_add (addresses, array);
	}

	g_value_take_boxed (value, addresses);
}

GSList *
nm_utils_ip4_routes_from_gvalue (const GValue *value)
{
	GPtrArray *routes;
	int i;
	GSList *list = NULL;

	routes = (GPtrArray *) g_value_get_boxed (value);
	for (i = 0; routes && (i < routes->len); i++) {
		GArray *array = (GArray *) g_ptr_array_index (routes, i);
		NMSettingIP4Route *route;

		if (array->len != 4) {
			nm_warning ("Ignoring invalid IP4 route");
			continue;
		}
		
		route = g_malloc0 (sizeof (NMSettingIP4Route));
		route->address = g_array_index (array, guint32, 0);
		route->prefix = g_array_index (array, guint32, 1);
		route->next_hop = g_array_index (array, guint32, 2);
		route->metric = g_array_index (array, guint32, 3);
		list = g_slist_prepend (list, route);
	}

	return g_slist_reverse (list);
}

void
nm_utils_ip4_routes_to_gvalue (GSList *list, GValue *value)
{
	GPtrArray *routes;
	GSList *iter;

	routes = g_ptr_array_new ();

	for (iter = list; iter; iter = iter->next) {
		NMSettingIP4Route *route = (NMSettingIP4Route *) iter->data;
		GArray *array;

		array = g_array_sized_new (FALSE, TRUE, sizeof (guint32), 3);

		g_array_append_val (array, route->address);
		g_array_append_val (array, route->prefix);
		g_array_append_val (array, route->next_hop);
		g_array_append_val (array, route->metric);
		g_ptr_array_add (routes, array);
	}

	g_value_take_boxed (value, routes);
}

/*
 * nm_utils_ip4_netmask_to_prefix
 *
 * Figure out the network prefix from a netmask.  Netmask
 * MUST be in network byte order.
 *
 */
guint32
nm_utils_ip4_netmask_to_prefix (guint32 netmask)
{
	guchar *p, *end;
	guint32 prefix = 0;

	p = (guchar *) &netmask;
	end = p + sizeof (guint32);

	while ((*p == 0xFF) && p < end) {
		prefix += 8;
		p++;
	}

	if (p < end) {
		guchar v = *p;

		while (v) {
			prefix++;
			v <<= 1;
		}
	}

	return prefix;
}

/*
 * nm_utils_ip4_prefix_to_netmask
 *
 * Figure out the netmask from a prefix.
 *
 */
guint32
nm_utils_ip4_prefix_to_netmask (guint32 prefix)
{
	guint32 msk = 0x80000000;
	guint32 netmask = 0;

	while (prefix > 0) {
		netmask |= msk;
		msk >>= 1;
		prefix--;
	}

	return (guint32) htonl (netmask);
}

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
		GByteArray *ba_addr, *ba_gw;
		NMSettingIP6Address *addr;
		guint32 prefix;

		if (   (elements->n_values != 3)
		    || (G_VALUE_TYPE (g_value_array_get_nth (elements, 0)) != DBUS_TYPE_G_UCHAR_ARRAY)
		    || (G_VALUE_TYPE (g_value_array_get_nth (elements, 1)) != G_TYPE_UINT)
		    || (G_VALUE_TYPE (g_value_array_get_nth (elements, 2)) != DBUS_TYPE_G_UCHAR_ARRAY)) {
			nm_warning ("%s: ignoring invalid IP6 address structure", __func__);
			continue;
		}

		tmp = g_value_array_get_nth (elements, 0);
		ba_addr = g_value_get_boxed (tmp);
		if (ba_addr->len != 16) {
			nm_warning ("%s: ignoring invalid IP6 address of length %d",
			            __func__, ba_addr->len);
			continue;
		}

		tmp = g_value_array_get_nth (elements, 1);
		prefix = g_value_get_uint (tmp);
		if (prefix > 32) {
			nm_warning ("%s: ignoring invalid IP6 prefix %d",
			            __func__, prefix);
			continue;
		}

		tmp = g_value_array_get_nth (elements, 2);
		ba_gw = g_value_get_boxed (tmp);
		if (ba_gw->len != 16) {
			nm_warning ("%s: ignoring invalid IP6 gateway of length %d",
			            __func__, ba_gw->len);
			continue;
		}
		
		addr = g_malloc0 (sizeof (NMSettingIP6Address));
		addr->prefix = prefix;
		memcpy (addr->address.s6_addr, ba_addr->data, 16);
		memcpy (addr->gateway.s6_addr, ba_gw->data, 16);
		list = g_slist_prepend (list, addr);
	}

	return g_slist_reverse (list);
}

void
nm_utils_ip6_addresses_to_gvalue (GSList *list, GValue *value)
{
	GPtrArray *addresses;
	GSList *iter;

	addresses = g_ptr_array_new ();

	for (iter = list; iter; iter = iter->next) {
		NMSettingIP6Address *addr = (NMSettingIP6Address *) iter->data;
		GValue element = { 0, };
		GByteArray *ba_addr, *ba_gw;

		g_value_init (&element, DBUS_TYPE_G_IP6_ADDRESS);
		g_value_take_boxed (&element, dbus_g_type_specialized_construct (DBUS_TYPE_G_IP6_ADDRESS));

		ba_addr = g_byte_array_sized_new (16);
		g_byte_array_append (ba_addr, (guint8 *) addr->address.s6_addr, 16);

		ba_gw = g_byte_array_sized_new (16);
		g_byte_array_append (ba_gw, (guint8 *) addr->gateway.s6_addr, 16);

		dbus_g_type_struct_set (&element,
		                        0, ba_addr,
		                        1, addr->prefix,
		                        2, ba_gw,
		                        G_MAXUINT);

		g_ptr_array_add (addresses, g_value_get_boxed (&element));
		g_value_unset (&element);
	}

	g_value_take_boxed (value, addresses);
}

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
			nm_warning ("%s: ignoring invalid IP6 address of length %d",
			            __func__, bytearray->len);
			continue;
		}

		addr = g_malloc0 (sizeof (struct in6_addr));
		memcpy (addr->s6_addr, bytearray->data, bytearray->len);
		list = g_slist_prepend (list, addr);
	}

	return g_slist_reverse (list);
}

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
