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
 * (C) Copyright 2005 - 2010 Red Hat, Inc.
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>

#include "wireless-helper.h"

#include <glib.h>
#include <glib-object.h>
#include <glib/gi18n.h>
#include <dbus/dbus-glib.h>
#include <uuid/uuid.h>

#include "nm-utils.h"
#include "nm-utils-private.h"
#include "NetworkManager.h"
#include "nm-dbus-glib-types.h"
#include "nm-setting-ip4-config.h"
#include "nm-setting-ip6-config.h"
#include "crypto.h"

/**
 * SECTION:nm-utils
 * @short_description: Utility functions
 * @include: nm-utils.h
 *
 * A collection of utility functions for working SSIDs, IP addresses, WiFi
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

/* init, deinit for libnm_util */

static gboolean initialized = FALSE;

/**
 * nm_utils_init:
 * @error: location to store error, or %NULL
 *
 * Initializes libnm-util; should be called when starting and program that
 * uses libnm-util.  Sets up an atexit() handler to ensure de-initialization
 * is performed, but calling nm_utils_deinit() to explicitly deinitialize
 * libnm-util can also be done.  This function can be called more than once.
 * 
 * Returns: TRUE if the initialization was successful, FALSE on failure.
 **/
gboolean
nm_utils_init (GError **error)
{
	if (!initialized) {
		if (!crypto_init (error))
			return FALSE;

		_nm_utils_register_value_transformations ();

		atexit (nm_utils_deinit);
		initialized = TRUE;
	}
	return TRUE;
}

/**
 * nm_utils_deinit:
 *
 * Frees all resources used internally by libnm-util.  This function is called
 * from an atexit() handler, set up by nm_utils_init(), but is safe to be called
 * more than once.  Subsequent calls have no effect until nm_utils_init() is
 * called again.
 **/
void
nm_utils_deinit (void)
{
	if (initialized) {
		crypto_deinit ();
		initialized = FALSE;
	}
}

/* ssid helpers */

/**
 * nm_utils_ssid_to_utf8:
 * @ssid: pointer to a buffer containing the SSID data
 * @len: length of the SSID data in @ssid
 *
 * WiFi SSIDs are byte arrays, they are _not_ strings.  Thus, an SSID may
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
 * Returns: an allocated string containing a UTF-8 representation of the
 * SSID, which must be freed by the caller using g_free().  Returns NULL
 * on errors.
 **/
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
/**
 * nm_utils_is_empty_ssid:
 * @ssid: pointer to a buffer containing the SSID data
 * @len: length of the SSID data in @ssid
 *
 * Different manufacturers use different mechanisms for not broadcasting the
 * AP's SSID.  This function attempts to detect blank/empty SSIDs using a
 * number of known SSID-cloaking methods.
 *
 * Returns: TRUE if the SSID is "empty", FALSE if it is not
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

/**
 * nm_utils_same_ssid:
 * @ssid1: first SSID data to compare
 * @ssid2: second SSID data to compare
 * @ignore_trailing_null: TRUE to ignore one trailing NULL byte
 *
 * Earlier versions of the Linux kernel added a NULL byte to the end of the
 * SSID to enable easy printing of the SSID on the console or in a terminal,
 * but this behavior was problematic (SSIDs are simply byte arrays, not strings)
 * and thus was changed.  This function compensates for that behavior at the
 * cost of some compatibility with odd SSIDs that may legitimately have trailing
 * NULLs, even though that is functionally pointless.
 *
 * Returns: TRUE if the SSIDs are the same, FALSE if they are not
 **/
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

/**
 * nm_utils_gvalue_hash_dup:
 * @hash: a #GHashTable mapping string:GValue
 *
 * Utility function to duplicate a hash table of GValues.
 *
 * Returns: a newly allocated duplicated #GHashTable, caller must free the
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
 * nm_utils_slist_free:
 * @list: a #GSList
 * @elem_destroy_fn: user function called for each element in @list
 *
 * Utility function to free a #GSList.
 **/
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

static void
nm_utils_convert_strv_to_slist (const GValue *src_value, GValue *dest_value)
{
	char **str;
	GSList *list = NULL;
	guint i = 0;

	g_return_if_fail (g_type_is_a (G_VALUE_TYPE (src_value), G_TYPE_STRV));

	str = (char **) g_value_get_boxed (src_value);

	while (str && str[i])
		list = g_slist_prepend (list, g_strdup (str[i++]));

	g_value_take_boxed (dest_value, g_slist_reverse (list));
}

static void
nm_utils_convert_strv_to_ptrarray (const GValue *src_value, GValue *dest_value)
{
	char **str;
	GPtrArray *array = NULL;
	guint i = 0;

	g_return_if_fail (g_type_is_a (G_VALUE_TYPE (src_value), G_TYPE_STRV));

	str = (char **) g_value_get_boxed (src_value);

	array = g_ptr_array_sized_new (3);
	while (str && str[i])
		g_ptr_array_add (array, g_strdup (str[i++]));

	g_value_take_boxed (dest_value, array);
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
nm_utils_convert_string_array_to_string (const GValue *src_value, GValue *dest_value)
{
	GPtrArray *strings;
	GString *printable;
	int i;

	g_return_if_fail (g_type_is_a (G_VALUE_TYPE (src_value), DBUS_TYPE_G_ARRAY_OF_STRING));

	strings = (GPtrArray *) g_value_get_boxed (src_value);

	printable = g_string_new ("[");
	for (i = 0; strings && i < strings->len; i++) {
		if (i > 0)
			g_string_append (printable, ", '");
		else
			g_string_append_c (printable, '\'');
		g_string_append (printable, g_ptr_array_index (strings, i));
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
nm_utils_convert_ip4_addr_route_struct_array_to_string (const GValue *src_value, GValue *dest_value)
{
	GPtrArray *ptr_array;
	GString *printable;
	guint i = 0;

	g_return_if_fail (g_type_is_a (G_VALUE_TYPE (src_value), DBUS_TYPE_G_ARRAY_OF_ARRAY_OF_UINT));

	ptr_array = (GPtrArray *) g_value_get_boxed (src_value);

	printable = g_string_new ("[");
	while (ptr_array && (i < ptr_array->len)) {
		GArray *array;
		char buf[INET_ADDRSTRLEN + 1];
		struct in_addr addr;
		gboolean is_addr; /* array contains address x route */

		if (i > 0)
			g_string_append (printable, ", ");

		g_string_append (printable, "{ ");
		array = (GArray *) g_ptr_array_index (ptr_array, i++);
		if (array->len < 2) {
			g_string_append (printable, "invalid");
			continue;
		}
		is_addr = (array->len < 4);

		memset (buf, 0, sizeof (buf));
		addr.s_addr = g_array_index (array, guint32, 0);
		if (!inet_ntop (AF_INET, &addr, buf, INET_ADDRSTRLEN))
			nm_warning ("%s: error converting IP4 address 0x%X",
			            __func__, ntohl (addr.s_addr));
		if (is_addr)
			g_string_append_printf (printable, "ip = %s", buf);
		else
			g_string_append_printf (printable, "dst = %s", buf);
		g_string_append (printable, ", ");

		memset (buf, 0, sizeof (buf));
		g_string_append_printf (printable, "px = %u",
		                        g_array_index (array, guint32, 1));

		if (array->len > 2) {
			g_string_append (printable, ", ");

			memset (buf, 0, sizeof (buf));
			addr.s_addr = g_array_index (array, guint32, 2);
			if (!inet_ntop (AF_INET, &addr, buf, INET_ADDRSTRLEN))
				nm_warning ("%s: error converting IP4 address 0x%X",
				            __func__, ntohl (addr.s_addr));
			if (is_addr)
				g_string_append_printf (printable, "gw = %s", buf);
			else
				g_string_append_printf (printable, "nh = %s", buf);
		}

		if (array->len > 3) {
			g_string_append (printable, ", ");

			memset (buf, 0, sizeof (buf));
			g_string_append_printf (printable, "mt = %u",
			                        g_array_index (array, guint32, 3));
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
	if (hash)
		g_hash_table_foreach (hash, convert_one_string_hash_entry, printable);
	g_string_append (printable, " ]");

	g_value_take_string (dest_value, printable->str);
	g_string_free (printable, FALSE);
}

static void
nm_utils_convert_byte_array_to_string (const GValue *src_value, GValue *dest_value)
{
	GArray *array;
	GString *printable;
	guint i = 0;

	g_return_if_fail (g_type_is_a (G_VALUE_TYPE (src_value), DBUS_TYPE_G_UCHAR_ARRAY));

	array = (GArray *) g_value_get_boxed (src_value);

	printable = g_string_new ("[");
	if (array) {
		while (i < MIN (array->len, 35)) {
			if (i > 0)
				g_string_append_c (printable, ' ');
			g_string_append_printf (printable, "0x%02X",
			                        g_array_index (array, unsigned char, i++));
		}
		if (i < array->len)
			g_string_append (printable, " ... ");
	}
	g_string_append_c (printable, ']');

	g_value_take_string (dest_value, printable->str);
	g_string_free (printable, FALSE);
}

static gboolean
nm_utils_inet6_ntop (struct in6_addr *addr, char *buf)
{
	if (!inet_ntop (AF_INET6, addr, buf, INET6_ADDRSTRLEN)) {
		int i;
		GString *ip6_str = g_string_new (NULL);
		g_string_append_printf (ip6_str, "%02X", addr->s6_addr[0]);
		for (i = 1; i < 16; i++)
			g_string_append_printf (ip6_str, " %02X", addr->s6_addr[i]);
		nm_warning ("%s: error converting IP6 address %s",
		            __func__, ip6_str->str);
		g_string_free (ip6_str, TRUE);
		return FALSE;
	}
	return TRUE;
}

static void
nm_utils_convert_ip6_dns_array_to_string (const GValue *src_value, GValue *dest_value)
{
	GPtrArray *ptr_array;
	GString *printable;
	guint i = 0;

	g_return_if_fail (g_type_is_a (G_VALUE_TYPE (src_value), DBUS_TYPE_G_ARRAY_OF_ARRAY_OF_UCHAR));

	ptr_array = (GPtrArray *) g_value_get_boxed (src_value);

	printable = g_string_new ("[");
	while (ptr_array && (i < ptr_array->len)) {
		GByteArray *bytearray;
		char buf[INET6_ADDRSTRLEN];
		struct in6_addr *addr;

		if (i > 0)
			g_string_append (printable, ", ");

		bytearray = (GByteArray *) g_ptr_array_index (ptr_array, i++);
		if (bytearray->len != 16) {
			g_string_append (printable, "invalid");
			continue;
		}
		addr = (struct in6_addr *) bytearray->data;
		memset (buf, 0, sizeof (buf));
		nm_utils_inet6_ntop (addr, buf);
		g_string_append_printf (printable, "%s", buf);
	}
	g_string_append_c (printable, ']');

	g_value_take_string (dest_value, printable->str);
	g_string_free (printable, FALSE);
}

static void
nm_utils_convert_ip6_addr_struct_array_to_string (const GValue *src_value, GValue *dest_value)
{
	GPtrArray *ptr_array;
	GString *printable;
	guint i = 0;

	g_return_if_fail (g_type_is_a (G_VALUE_TYPE (src_value), DBUS_TYPE_G_ARRAY_OF_IP6_ADDRESS));

	ptr_array = (GPtrArray *) g_value_get_boxed (src_value);

	printable = g_string_new ("[");
	while (ptr_array && (i < ptr_array->len)) {
		GValueArray *elements;
		GValue *tmp;
		GByteArray *ba_addr;
		char buf[INET6_ADDRSTRLEN];
		struct in6_addr *addr;
		guint32 prefix;

		if (i > 0)
			g_string_append (printable, ", ");

		g_string_append (printable, "{ ");
		elements = (GValueArray *) g_ptr_array_index (ptr_array, i++);
		if (   (elements->n_values != 3)
		    || (G_VALUE_TYPE (g_value_array_get_nth (elements, 0)) != DBUS_TYPE_G_UCHAR_ARRAY)
		    || (G_VALUE_TYPE (g_value_array_get_nth (elements, 1)) != G_TYPE_UINT)
		    || (G_VALUE_TYPE (g_value_array_get_nth (elements, 2)) != DBUS_TYPE_G_UCHAR_ARRAY)) {
			g_string_append (printable, "invalid }");
			continue;
		}

		/* IPv6 address */
		tmp = g_value_array_get_nth (elements, 0);
		ba_addr = g_value_get_boxed (tmp);
		if (ba_addr->len != 16) {
			g_string_append (printable, "invalid }");
			continue;
		}
		addr = (struct in6_addr *) ba_addr->data;
		memset (buf, 0, sizeof (buf));
		nm_utils_inet6_ntop (addr, buf);
		g_string_append_printf (printable, "ip = %s", buf);
		g_string_append (printable, ", ");

		/* Prefix */
		tmp = g_value_array_get_nth (elements, 1);
		prefix = g_value_get_uint (tmp);
		if (prefix > 128) {
			g_string_append (printable, "invalid }");
			continue;
		}
		g_string_append_printf (printable, "px = %u", prefix);
		g_string_append (printable, ", ");

		/* IPv6 Gateway */
		tmp = g_value_array_get_nth (elements, 2);
		ba_addr = g_value_get_boxed (tmp);
		if (ba_addr->len != 16) {
			g_string_append (printable, "invalid }");
			continue;
		}
		addr = (struct in6_addr *) ba_addr->data;
		memset (buf, 0, sizeof (buf));
		nm_utils_inet6_ntop (addr, buf);
		g_string_append_printf (printable, "gw = %s", buf);
		g_string_append (printable, " }");
	}
	g_string_append_c (printable, ']');

	g_value_take_string (dest_value, printable->str);
	g_string_free (printable, FALSE);
}

static void
nm_utils_convert_ip6_route_struct_array_to_string (const GValue *src_value, GValue *dest_value)
{
	GPtrArray *ptr_array;
	GString *printable;
	guint i = 0;

	g_return_if_fail (g_type_is_a (G_VALUE_TYPE (src_value), DBUS_TYPE_G_ARRAY_OF_IP6_ROUTE));

	ptr_array = (GPtrArray *) g_value_get_boxed (src_value);

	printable = g_string_new ("[");
	while (ptr_array && (i < ptr_array->len)) {
		GValueArray *elements;
		GValue *tmp;
		GByteArray *ba_addr;
		char buf[INET6_ADDRSTRLEN];
		struct in6_addr *addr;
		guint32 prefix, metric;

		if (i > 0)
			g_string_append (printable, ", ");

		g_string_append (printable, "{ ");
		elements = (GValueArray *) g_ptr_array_index (ptr_array, i++);
		if (   (elements->n_values != 4)
		    || (G_VALUE_TYPE (g_value_array_get_nth (elements, 0)) != DBUS_TYPE_G_UCHAR_ARRAY)
		    || (G_VALUE_TYPE (g_value_array_get_nth (elements, 1)) != G_TYPE_UINT)
		    || (G_VALUE_TYPE (g_value_array_get_nth (elements, 2)) != DBUS_TYPE_G_UCHAR_ARRAY)
		    || (G_VALUE_TYPE (g_value_array_get_nth (elements, 3)) != G_TYPE_UINT)) {
			g_string_append (printable, "invalid");
			continue;
		}

		/* Destination address */
		tmp = g_value_array_get_nth (elements, 0);
		ba_addr = g_value_get_boxed (tmp);
		if (ba_addr->len != 16) {
			g_string_append (printable, "invalid");
			continue;
		}
		addr = (struct in6_addr *) ba_addr->data;
		memset (buf, 0, sizeof (buf));
		nm_utils_inet6_ntop (addr, buf);
		g_string_append_printf (printable, "dst = %s", buf);
		g_string_append (printable, ", ");

		/* Prefix */
		tmp = g_value_array_get_nth (elements, 1);
		prefix = g_value_get_uint (tmp);
		if (prefix > 128) {
			g_string_append (printable, "invalid");
			continue;
		}
		g_string_append_printf (printable, "px = %u", prefix);
		g_string_append (printable, ", ");

		/* Next hop addresses */
		tmp = g_value_array_get_nth (elements, 2);
		ba_addr = g_value_get_boxed (tmp);
		if (ba_addr->len != 16) {
			g_string_append (printable, "invalid");
			continue;
		}
		addr = (struct in6_addr *) ba_addr->data;
		memset (buf, 0, sizeof (buf));
		nm_utils_inet6_ntop (addr, buf);
		g_string_append_printf (printable, "nh = %s", buf);
		g_string_append (printable, ", ");

		/* Metric */
		tmp = g_value_array_get_nth (elements, 3);
		metric = g_value_get_uint (tmp);
		g_string_append_printf (printable, "mt = %u", metric);

		g_string_append (printable, " }");
	}
	g_string_append_c (printable, ']');

	g_value_take_string (dest_value, printable->str);
	g_string_free (printable, FALSE);
}

#define OLD_DBUS_TYPE_G_IP6_ADDRESS (dbus_g_type_get_struct ("GValueArray", DBUS_TYPE_G_UCHAR_ARRAY, G_TYPE_UINT, G_TYPE_INVALID))
#define OLD_DBUS_TYPE_G_ARRAY_OF_IP6_ADDRESS (dbus_g_type_get_collection ("GPtrArray", OLD_DBUS_TYPE_G_IP6_ADDRESS))

static void
nm_utils_convert_old_ip6_addr_array (const GValue *src_value, GValue *dst_value)
{
	GPtrArray *src_outer_array;
	GPtrArray *dst_outer_array;
	guint i;

	g_return_if_fail (g_type_is_a (G_VALUE_TYPE (src_value), OLD_DBUS_TYPE_G_ARRAY_OF_IP6_ADDRESS));

	src_outer_array = (GPtrArray *) g_value_get_boxed (src_value);
	dst_outer_array = g_ptr_array_new ();

	for (i = 0; src_outer_array && (i < src_outer_array->len); i++) {
		GValueArray *src_addr_array;
		GValueArray *dst_addr_array;
		GValue element = {0, };
		GValue *src_addr, *src_prefix;
		GByteArray *ba;

		src_addr_array = (GValueArray *) g_ptr_array_index (src_outer_array, i);

		if (   (src_addr_array->n_values != 2)
		    || (G_VALUE_TYPE (g_value_array_get_nth (src_addr_array, 0)) != DBUS_TYPE_G_UCHAR_ARRAY)
		    || (G_VALUE_TYPE (g_value_array_get_nth (src_addr_array, 1)) != G_TYPE_UINT)) {
			g_warning ("%s: invalid old IPv6 address type", __func__);
			return;
		}

		dst_addr_array = g_value_array_new (3);

		src_addr = g_value_array_get_nth (src_addr_array, 0);
		g_value_array_append (dst_addr_array, src_addr);
		src_prefix = g_value_array_get_nth (src_addr_array, 1);
		g_value_array_append (dst_addr_array, src_prefix);

		/* Blank Gateway */
		g_value_init (&element, DBUS_TYPE_G_UCHAR_ARRAY);
		ba = g_byte_array_new ();
		g_byte_array_append (ba, (guint8 *) "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16);
		g_value_take_boxed (&element, ba);
		g_value_array_append (dst_addr_array, &element);
		g_value_unset (&element);

		g_ptr_array_add (dst_outer_array, dst_addr_array);
	}

	g_value_take_boxed (dst_value, dst_outer_array);
}

void
_nm_utils_register_value_transformations (void)
{
	static gboolean registered = FALSE;

	if (G_UNLIKELY (!registered)) {
		g_value_register_transform_func (G_TYPE_STRV, 
		                                 DBUS_TYPE_G_LIST_OF_STRING,
		                                 nm_utils_convert_strv_to_slist);
		g_value_register_transform_func (G_TYPE_STRV,
		                                 DBUS_TYPE_G_ARRAY_OF_STRING,
		                                 nm_utils_convert_strv_to_ptrarray);
		g_value_register_transform_func (DBUS_TYPE_G_LIST_OF_STRING,
		                                 G_TYPE_STRING, 
		                                 nm_utils_convert_strv_to_string);
		g_value_register_transform_func (DBUS_TYPE_G_ARRAY_OF_STRING,
		                                 G_TYPE_STRING,
		                                 nm_utils_convert_string_array_to_string);
		g_value_register_transform_func (DBUS_TYPE_G_UINT_ARRAY,
		                                 G_TYPE_STRING, 
		                                 nm_utils_convert_uint_array_to_string);
		g_value_register_transform_func (DBUS_TYPE_G_ARRAY_OF_ARRAY_OF_UINT,
		                                 G_TYPE_STRING, 
		                                 nm_utils_convert_ip4_addr_route_struct_array_to_string);
		g_value_register_transform_func (DBUS_TYPE_G_MAP_OF_VARIANT,
		                                 G_TYPE_STRING, 
		                                 nm_utils_convert_gvalue_hash_to_string);
		g_value_register_transform_func (DBUS_TYPE_G_MAP_OF_STRING,
		                                 G_TYPE_STRING, 
		                                 nm_utils_convert_string_hash_to_string);
		g_value_register_transform_func (DBUS_TYPE_G_UCHAR_ARRAY,
		                                 G_TYPE_STRING,
		                                 nm_utils_convert_byte_array_to_string);
		g_value_register_transform_func (DBUS_TYPE_G_ARRAY_OF_ARRAY_OF_UCHAR,
		                                 G_TYPE_STRING, 
		                                 nm_utils_convert_ip6_dns_array_to_string);
		g_value_register_transform_func (DBUS_TYPE_G_ARRAY_OF_IP6_ADDRESS,
		                                 G_TYPE_STRING, 
		                                 nm_utils_convert_ip6_addr_struct_array_to_string);
		g_value_register_transform_func (DBUS_TYPE_G_ARRAY_OF_IP6_ROUTE,
		                                 G_TYPE_STRING, 
		                                 nm_utils_convert_ip6_route_struct_array_to_string);
		g_value_register_transform_func (OLD_DBUS_TYPE_G_ARRAY_OF_IP6_ADDRESS,
		                                 DBUS_TYPE_G_ARRAY_OF_IP6_ADDRESS,
		                                 nm_utils_convert_old_ip6_addr_array);
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

/**
 * nm_utils_security_valid:
 * @type: the security type to check AP flags and device capabilties against,
 * e.g. #NMU_SEC_STATIC_WEP
 * @wifi_caps: bitfield of the capabilities of the specific WiFi device, e.g.
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
 * Returns: TRUE if the device capabilities and AP capabilties intersect and are
 * compatible with the desired @type, FALSE if they are not
 **/
gboolean
nm_utils_security_valid (NMUtilsSecurityType type,
                         guint32 wifi_caps,
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
			if (wifi_caps & (NM_WIFI_DEVICE_CAP_CIPHER_WEP40 | NM_WIFI_DEVICE_CAP_CIPHER_WEP104))
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
		if (!(wifi_caps & NM_WIFI_DEVICE_CAP_WPA))
			return FALSE;
		if (have_ap) {
			/* Ad-Hoc WPA APs won't necessarily have the PSK flag set */
			if ((ap_wpa & NM_802_11_AP_SEC_KEY_MGMT_PSK) || adhoc) {
				if (   (ap_wpa & NM_802_11_AP_SEC_PAIR_TKIP)
				    && (wifi_caps & NM_WIFI_DEVICE_CAP_CIPHER_TKIP))
					return TRUE;
				if (   (ap_wpa & NM_802_11_AP_SEC_PAIR_CCMP)
				    && (wifi_caps & NM_WIFI_DEVICE_CAP_CIPHER_CCMP))
					return TRUE;
			}
			return FALSE;
		}
		break;
	case NMU_SEC_WPA2_PSK:
		if (!(wifi_caps & NM_WIFI_DEVICE_CAP_RSN))
			return FALSE;
		if (have_ap) {
			/* Ad-Hoc WPA APs won't necessarily have the PSK flag set */
			if ((ap_rsn & NM_802_11_AP_SEC_KEY_MGMT_PSK) || adhoc) {
				if (   (ap_rsn & NM_802_11_AP_SEC_PAIR_TKIP)
				    && (wifi_caps & NM_WIFI_DEVICE_CAP_CIPHER_TKIP))
					return TRUE;
				if (   (ap_rsn & NM_802_11_AP_SEC_PAIR_CCMP)
				    && (wifi_caps & NM_WIFI_DEVICE_CAP_CIPHER_CCMP))
					return TRUE;
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
 * nm_utils_ip4_addresses_from_gvalue:
 * @value: gvalue containing a GPtrArray of GArrays of guint32s
 *
 * Utility function to convert a #GPtrArray of #GArrays of guint32s representing
 * a list of NetworkManager IPv4 addresses (which is a tuple of address, gateway,
 * and prefix) into a GSList of #NMIP4Address objects.  The specific format of
 * this serialization is not guaranteed to be stable and the #GArray may be
 * extended in the future.
 *
 * Returns: a newly allocated #GSList of #NMIP4Address objects
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
			nm_warning ("Ignoring invalid IP4 address");
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
 * @list: a list of #NMIP4Address objects
 * @value: a pointer to a #GValue into which to place the converted addresses,
 * which should be unset by the caller (when no longer needed) with
 * g_value_unset().
 *
 * Utility function to convert a #GSList of #NMIP4Address objects into a
 * GPtrArray of GArrays of guint32s representing a list of NetworkManager IPv4
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
 * @value: gvalue containing a GPtrArray of GArrays of guint32s
 *
 * Utility function to convert a GPtrArray of GArrays of guint32s representing
 * a list of NetworkManager IPv4 routes (which is a tuple of route, next hop,
 * prefix, and metric) into a GSList of #NMIP4Route objects.  The specific
 * format of this serialization is not guaranteed to be stable and may be
 * extended in the future.
 *
 * Returns: a newly allocated #GSList of #NMIP4Route objects
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
			nm_warning ("Ignoring invalid IP4 route");
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
 * @list: a list of #NMIP4Route objects
 * @value: a pointer to a #GValue into which to place the converted routes,
 * which should be unset by the caller (when no longer needed) with
 * g_value_unset().
 *
 * Utility function to convert a #GSList of #NMIP4Route objects into a
 * GPtrArray of GArrays of guint32s representing a list of NetworkManager IPv4
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

/**
 * nm_utils_ip4_prefix_to_netmask:
 * @prefix: a CIDR prefix
 *
 * Returns: the netmask represented by the prefix
 **/
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
 * @value: gvalue containing a GPtrArray of GValueArrays of (GArray of guchars) and guint32
 *
 * Utility function to convert a #GPtrArray of #GValueArrays of (#GArray of guchars) and guint32
 * representing a list of NetworkManager IPv6 addresses (which is a tuple of address,
 * prefix, and gateway), into a GSList of #NMIP6Address objects.  The specific format of
 * this serialization is not guaranteed to be stable and the #GValueArray may be
 * extended in the future.
 *
 * Returns: a newly allocated #GSList of #NMIP6Address objects
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
			nm_warning ("%s: ignoring invalid IP6 address structure", __func__);
			continue;
		}

		if (   (G_VALUE_TYPE (g_value_array_get_nth (elements, 0)) != DBUS_TYPE_G_UCHAR_ARRAY)
		    || (G_VALUE_TYPE (g_value_array_get_nth (elements, 1)) != G_TYPE_UINT)) {
			nm_warning ("%s: ignoring invalid IP6 address structure", __func__);
			continue;
		}

		/* Check optional 3rd element (gateway) */
		if (   elements->n_values == 3
		    && (G_VALUE_TYPE (g_value_array_get_nth (elements, 2)) != DBUS_TYPE_G_UCHAR_ARRAY)) {
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
		if (prefix > 128) {
			nm_warning ("%s: ignoring invalid IP6 prefix %d",
			            __func__, prefix);
			continue;
		}

		if (elements->n_values == 3) {
			tmp = g_value_array_get_nth (elements, 2);
			ba_gw = g_value_get_boxed (tmp);
			if (ba_gw->len != 16) {
				nm_warning ("%s: ignoring invalid IP6 gateway address of length %d",
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
 * @list: a list of #NMIP6Address objects
 * @value: a pointer to a #GValue into which to place the converted addresses,
 * which should be unset by the caller (when no longer needed) with
 * g_value_unset().
 *
 * Utility function to convert a #GSList of #NMIP6Address objects into a
 * GPtrArray of GValueArrays representing a list of NetworkManager IPv6 addresses
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
		GValue element = {0, };
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
 * @value: gvalue containing a GPtrArray of GValueArrays of (GArray or guchars), guint32,
 * (GArray of guchars), and guint32
 *
 * Utility function GPtrArray of GValueArrays of (GArray or guchars), guint32,
 * (GArray of guchars), and guint32 representing a list of NetworkManager IPv6
 * routes (which is a tuple of destination, prefix, next hop, and metric)
 * into a GSList of #NMIP6Route objects.  The specific format of this serialization
 * is not guaranteed to be stable and may be extended in the future.
 *
 * Returns: a newly allocated #GSList of #NMIP6Route objects
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

		if (   (route_values->n_values != 4)
		    || (G_VALUE_TYPE (g_value_array_get_nth (route_values, 0)) != DBUS_TYPE_G_UCHAR_ARRAY)
			|| (G_VALUE_TYPE (g_value_array_get_nth (route_values, 1)) != G_TYPE_UINT)
		    || (G_VALUE_TYPE (g_value_array_get_nth (route_values, 2)) != DBUS_TYPE_G_UCHAR_ARRAY)
			|| (G_VALUE_TYPE (g_value_array_get_nth (route_values, 3)) != G_TYPE_UINT)) {
			nm_warning ("Ignoring invalid IP6 route");
			continue;
		}

		dest = g_value_get_boxed (g_value_array_get_nth (route_values, 0));
		if (dest->len != 16) {
			nm_warning ("%s: ignoring invalid IP6 dest address of length %d",
			            __func__, dest->len);
			continue;
		}

		prefix = g_value_get_uint (g_value_array_get_nth (route_values, 1));

		next_hop = g_value_get_boxed (g_value_array_get_nth (route_values, 2));
		if (next_hop->len != 16) {
			nm_warning ("%s: ignoring invalid IP6 next_hop address of length %d",
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
 * @list: a list of #NMIP6Route objects
 * @value: a pointer to a #GValue into which to place the converted routes,
 * which should be unset by the caller (when no longer needed) with
 * g_value_unset().
 *
 * Utility function to convert a #GSList of #NMIP6Route objects into a GPtrArray of
 * GValueArrays of (GArray or guchars), guint32, (GArray of guchars), and guint32
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
		GValue element = {0, };

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
	uuid_t *uuid;
	char *buf = NULL;

	if (!nm_utils_init (&error)) {
		nm_warning ("error initializing crypto: (%d) %s",
		            error ? error->code : 0,
		            error ? error->message : "unknown");
		if (error)
			g_error_free (error);
		return NULL;
	}

	uuid = g_malloc0 (sizeof (*uuid));
	if (!crypto_md5_hash (NULL, 0, s, strlen (s), (char *) uuid, sizeof (*uuid), &error)) {
		nm_warning ("error generating UUID: (%d) %s",
		            error ? error->code : 0,
		            error ? error->message : "unknown");
		if (error)
			g_error_free (error);
		goto out;
	}

	buf = g_malloc0 (37);
	uuid_unparse_lower (*uuid, &buf[0]);

out:
	g_free (uuid);
	return buf;
}

static char *
make_key (const char *salt,
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

	key = g_malloc0 (digest_len + 1);
	if (!key) {
		g_set_error (error,
		             NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_OUT_OF_MEMORY,
		             _("Not enough memory to make encryption key."));
		return NULL;
	}

	if (!crypto_md5_hash (salt, salt_len, password, strlen (password), key, digest_len, error)) {
		*out_len = 0;
		memset (key, 0, digest_len);
		g_free (key);
		key = NULL;
	} else
		*out_len = digest_len;

	return key;
}

/*
 * utils_bin2hexstr
 *
 * Convert a byte-array into a hexadecimal string.
 *
 * Code originally by Alex Larsson <alexl@redhat.com> and
 *  copyright Red Hat, Inc. under terms of the LGPL.
 *
 */
static char *
utils_bin2hexstr (const char *bytes, int len, int final_len)
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
	for (i = 0; i < len; i++)
	{
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

/**
 * nm_utils_rsa_key_encrypt:
 * @data: RSA private key data to be encrypted
 * @in_password: existing password to use, if any
 * @out_password: if @in_password was NULL, a random password will be generated
 *  and returned in this argument
 * @error: detailed error information on return, if an error occurred
 *
 * Encrypts the given RSA private key data with the given password (or generates
 * a password if no password was given) and converts the data to PEM format
 * suitable for writing to a file.
 *
 * Returns: on success, PEM-formatted data suitable for writing to a PEM-formatted
 * certificate/private key file.
 **/
GByteArray *
nm_utils_rsa_key_encrypt (const GByteArray *data,
                          const char *in_password,
                          char **out_password,
                          GError **error)
{
	char salt[8];
	char *key = NULL, *enc = NULL, *pw_buf[32];
	gsize key_len = 0, enc_len = 0;
	GString *pem = NULL;
	char *tmp, *tmp_password = NULL;
	int left;
	const char *p;
	GByteArray *ret = NULL;

	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (data->len > 0, NULL);
	if (out_password)
		g_return_val_if_fail (*out_password == NULL, NULL);

	/* Make the password if needed */
	if (!in_password) {
		if (!crypto_randomize (pw_buf, sizeof (pw_buf), error))
			return NULL;
		in_password = tmp_password = utils_bin2hexstr ((const char *) pw_buf, sizeof (pw_buf), -1);
	}

	if (!crypto_randomize (salt, sizeof (salt), error))
		goto out;

	key = make_key (&salt[0], sizeof (salt), in_password, &key_len, error);
	if (!key)
		goto out;

	enc = crypto_encrypt (CIPHER_DES_EDE3_CBC, data, salt, sizeof (salt), key, key_len, &enc_len, error);
	if (!enc)
		goto out;

	pem = g_string_sized_new (enc_len * 2 + 100);
	if (!pem) {
		g_set_error_literal (error, NM_CRYPTO_ERROR,
		                     NM_CRYPTO_ERR_OUT_OF_MEMORY,
		                     _("Could not allocate memory for PEM file creation."));
		goto out;
	}

	g_string_append (pem, "-----BEGIN RSA PRIVATE KEY-----\n");
	g_string_append (pem, "Proc-Type: 4,ENCRYPTED\n");

	/* Convert the salt to a hex string */
	tmp = utils_bin2hexstr ((const char *) salt, sizeof (salt), 16);
	if (!tmp) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_OUT_OF_MEMORY,
		             _("Could not allocate memory for writing IV to PEM file."));
		goto out;
	}

	g_string_append_printf (pem, "DEK-Info: DES-EDE3-CBC,%s\n\n", tmp);
	g_free (tmp);

	/* Convert the encrypted key to a base64 string */
	p = tmp = g_base64_encode ((const guchar *) enc, enc_len);
	if (!tmp) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_OUT_OF_MEMORY,
		             _("Could not allocate memory for writing encrypted key to PEM file."));
		goto out;
	}

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
	if (!ret) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_OUT_OF_MEMORY,
		             _("Could not allocate memory for PEM file data."));
		goto out;
	}
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
 * Utility function to translate a WiFi frequency to its corresponding channel.
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
 * Utility function to translate a WiFi channel to its corresponding frequency.
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
 * Utility function to find out next/previous WiFi channel for a channel.
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
 * Utility function to verify WiFi channel validity.
 *
 * Returns: TRUE or FALSE
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

