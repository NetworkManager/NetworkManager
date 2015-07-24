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
 * Copyright 2005 - 2014 Red Hat, Inc.
 */

#include "config.h"

#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <uuid/uuid.h>
#include <libintl.h>
#include <gmodule.h>
#include <glib/gi18n-lib.h>

#include "nm-utils.h"
#include "nm-utils-private.h"
#include "nm-glib-compat.h"
#include "nm-setting-private.h"
#include "crypto.h"
#include "gsystem-local-alloc.h"
#include "nm-macros-internal.h"

#include "nm-setting-bond.h"
#include "nm-setting-bridge.h"
#include "nm-setting-infiniband.h"
#include "nm-setting-ip6-config.h"
#include "nm-setting-team.h"
#include "nm-setting-vlan.h"
#include "nm-setting-wired.h"
#include "nm-setting-wireless.h"

/* Embed the commit id in the build binary */
static const char *const __nm_git_sha = STRLEN (NM_GIT_SHA) > 0 ? "NM_GIT_SHA:"NM_GIT_SHA : "";

/**
 * SECTION:nm-utils
 * @short_description: Utility functions
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

/* init libnm */

static gboolean initialized = FALSE;

static void __attribute__((constructor))
_nm_utils_init (void)
{
	GModule *self;
	gpointer func;

	(void) __nm_git_sha;

	if (initialized)
		return;
	initialized = TRUE;

	self = g_module_open (NULL, 0);
	if (g_module_symbol (self, "nm_util_get_private", &func))
		g_error ("libnm-util symbols detected; Mixing libnm with libnm-util/libnm-glib is not supported");
	g_module_close (self);

	bindtextdomain (GETTEXT_PACKAGE, LOCALEDIR);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");

	nm_g_type_init ();

	_nm_dbus_errors_init ();
}

gboolean _nm_utils_is_manager_process;

/* ssid helpers */

/**
 * nm_utils_ssid_to_utf8:
 * @ssid: (array length=len): pointer to a buffer containing the SSID data
 * @len: length of the SSID data in @ssid
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
nm_utils_ssid_to_utf8 (const guint8 *ssid, gsize len)
{
	char *converted = NULL;
	char *lang, *e1 = NULL, *e2 = NULL, *e3 = NULL;

	g_return_val_if_fail (ssid != NULL, NULL);

	if (g_utf8_validate ((const gchar *) ssid, len, NULL))
		return g_strndup ((const gchar *) ssid, len);

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

	converted = g_convert ((const gchar *) ssid, len, "UTF-8", e1, NULL, NULL, NULL);
	if (!converted && e2)
		converted = g_convert ((const gchar *) ssid, len, "UTF-8", e2, NULL, NULL, NULL);

	if (!converted && e3)
		converted = g_convert ((const gchar *) ssid, len, "UTF-8", e3, NULL, NULL, NULL);

	if (!converted) {
		converted = g_convert_with_fallback ((const gchar *) ssid, len,
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

		converted = g_strndup ((const gchar *)ssid, len);
		g_strcanon (converted, valid_chars, '?');
	}

	return converted;
}

/* Shamelessly ripped from the Linux kernel ieee80211 stack */
/**
 * nm_utils_is_empty_ssid:
 * @ssid: (array length=len): pointer to a buffer containing the SSID data
 * @len: length of the SSID data in @ssid
 *
 * Different manufacturers use different mechanisms for not broadcasting the
 * AP's SSID.  This function attempts to detect blank/empty SSIDs using a
 * number of known SSID-cloaking methods.
 *
 * Returns: %TRUE if the SSID is "empty", %FALSE if it is not
 **/
gboolean
nm_utils_is_empty_ssid (const guint8 *ssid, gsize len)
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
 * @ssid: (array length=len): pointer to a buffer containing the SSID data
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
nm_utils_escape_ssid (const guint8 *ssid, gsize len)
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
 * @ssid1: (array length=len1): the first SSID to compare
 * @len1: length of the SSID data in @ssid1
 * @ssid2: (array length=len2): the second SSID to compare
 * @len2: length of the SSID data in @ssid2
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
nm_utils_same_ssid (const guint8 *ssid1, gsize len1,
                    const guint8 *ssid2, gsize len2,
                    gboolean ignore_trailing_null)
{
	g_return_val_if_fail (ssid1 != NULL || len1 == 0, FALSE);
	g_return_val_if_fail (ssid2 != NULL || len2 == 0, FALSE);

	if (ssid1 == ssid2 && len1 == len2)
		return TRUE;
	if (!ssid1 || !ssid2)
		return FALSE;

	if (ignore_trailing_null) {
		if (len1 && ssid1[len1 - 1] == '\0')
			len1--;
		if (len2 && ssid2[len2 - 1] == '\0')
			len2--;
	}

	if (len1 != len2)
		return FALSE;

	return memcmp (ssid1, ssid2, len1) == 0 ? TRUE : FALSE;
}

gboolean
_nm_utils_string_in_list (const char *str, const char **valid_strings)
{
	return _nm_utils_strv_find_first ((char **) valid_strings, -1, str) >= 0;
}

/**
 * _nm_utils_strv_find_first:
 * @list: the strv list to search
 * @len: the length of the list, or a negative value if @list is %NULL terminated.
 * @needle: the value to search for. The search is done using strcmp().
 *
 * Searches @list for @needle and returns the index of the first match (based
 * on strcmp()).
 *
 * For convenience, @list has type 'char**' instead of 'const char **'.
 *
 * Returns: index of first occurrence or -1 if @needle is not found in @list.
 */
gssize
_nm_utils_strv_find_first (char **list, gssize len, const char *needle)
{
	gssize i;

	if (len > 0) {
		g_return_val_if_fail (list, -1);

		if (!needle) {
			/* if we search a list with known length, %NULL is a valid @needle. */
			for (i = 0; i < len; i++) {
				if (!list[i])
					return i;
			}
		} else {
			for (i = 0; i < len; i++) {
				if (list[i] && !strcmp (needle, list[i]))
					return i;
			}
		}
	} else if (len < 0) {
		g_return_val_if_fail (needle, -1);

		if (list) {
			for (i = 0; list[i]; i++) {
				if (strcmp (needle, list[i]) == 0)
					return i;
			}
		}
	}
	return -1;
}

char **
_nm_utils_strv_cleanup (char **strv,
                        gboolean strip_whitespace,
                        gboolean skip_empty,
                        gboolean skip_repeated)
{
	guint i, j;

	if (!strv || !*strv)
		return strv;

	if (strip_whitespace) {
		for (i = 0; strv[i]; i++)
			g_strstrip (strv[i]);
	}
	if (!skip_empty && !skip_repeated)
		return strv;
	j = 0;
	for (i = 0; strv[i]; i++) {
		if (   (skip_empty && !*strv[i])
		    || (skip_repeated && _nm_utils_strv_find_first (strv, j, strv[i]) >= 0))
			g_free (strv[i]);
		else
			strv[j++] = strv[i];
	}
	strv[j] = NULL;
	return strv;
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

/**
 * _nm_utils_hash_values_to_slist:
 * @hash: a #GHashTable
 *
 * Utility function to iterate over a hash table and return
 * it's values as a #GSList.
 *
 * Returns: (element-type gpointer) (transfer container): a newly allocated #GSList
 * containing the values of the hash table. The caller must free the
 * returned list with g_slist_free(). The hash values are not owned
 * by the returned list.
 **/
GSList *
_nm_utils_hash_values_to_slist (GHashTable *hash)
{
	GSList *list = NULL;
	GHashTableIter iter;
	void *value;

	g_return_val_if_fail (hash, NULL);

	g_hash_table_iter_init (&iter, hash);
	while (g_hash_table_iter_next (&iter, NULL, &value))
		 list = g_slist_prepend (list, value);

	return list;
}

GVariant *
_nm_utils_strdict_to_dbus (const GValue *prop_value)
{
	GHashTable *hash;
	GHashTableIter iter;
	gpointer key, value;
	GVariantBuilder builder;

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{ss}"));
	hash = g_value_get_boxed (prop_value);
	if (hash) {
		g_hash_table_iter_init (&iter, hash);
		while (g_hash_table_iter_next (&iter, &key, &value))
			g_variant_builder_add (&builder, "{ss}", key, value);
	}

	return g_variant_builder_end (&builder);
}

void
_nm_utils_strdict_from_dbus (GVariant *dbus_value,
                             GValue *prop_value)
{
	GVariantIter iter;
	const char *key, *value;
	GHashTable *hash;

	hash = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
	g_variant_iter_init (&iter, dbus_value);
	while (g_variant_iter_next (&iter, "{&s&s}", &key, &value))
		g_hash_table_insert (hash, g_strdup (key), g_strdup (value));

	g_value_take_boxed (prop_value, hash);
}

GHashTable *
_nm_utils_copy_strdict (GHashTable *strdict)
{
	GHashTable *copy;
	GHashTableIter iter;
	gpointer key, value;

	copy = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
	if (strdict) {
		g_hash_table_iter_init (&iter, strdict);
		while (g_hash_table_iter_next (&iter, &key, &value))
			g_hash_table_insert (copy, g_strdup (key), g_strdup (value));
	}
	return copy;
}

GPtrArray *
_nm_utils_copy_slist_to_array (const GSList *list,
                               NMUtilsCopyFunc copy_func,
                               GDestroyNotify unref_func)
{
	const GSList *iter;
	GPtrArray *array;

	array = g_ptr_array_new_with_free_func (unref_func);
	for (iter = list; iter; iter = iter->next)
		g_ptr_array_add (array, copy_func ? copy_func (iter->data) : iter->data);
	return array;
}

GSList *
_nm_utils_copy_array_to_slist (const GPtrArray *array,
                               NMUtilsCopyFunc copy_func)
{
	GSList *slist = NULL;
	gpointer item;
	int i;

	if (!array)
		return NULL;

	for (i = 0; i < array->len; i++) {
		item = array->pdata[i];
		slist = g_slist_prepend (slist, copy_func (item));
	}

	return g_slist_reverse (slist);
}

GPtrArray *
_nm_utils_copy_array (const GPtrArray *array,
                      NMUtilsCopyFunc copy_func,
                      GDestroyNotify free_func)
{
	GPtrArray *copy;
	int i;

	if (!array)
		return g_ptr_array_new_with_free_func (free_func);

	copy = g_ptr_array_new_full (array->len, free_func);
	for (i = 0; i < array->len; i++)
		g_ptr_array_add (copy, copy_func (array->pdata[i]));
	return copy;
}

GPtrArray *
_nm_utils_copy_object_array (const GPtrArray *array)
{
	return _nm_utils_copy_array (array, g_object_ref, g_object_unref);
}

/* have @list of type 'gpointer *' instead of 'gconstpointer *' to
 * reduce the necessity for annoying const-casts. */
gssize
_nm_utils_ptrarray_find_first (gpointer *list, gssize len, gconstpointer needle)
{
	gssize i;

	if (len == 0)
		return -1;

	if (len > 0) {
		g_return_val_if_fail (list, -1);
		for (i = 0; i < len; i++) {
			if (list[i] == needle)
				return i;
		}
	} else {
		g_return_val_if_fail (needle, -1);
		for (i = 0; list && list[i]; i++) {
			if (list[i] == needle)
				return i;
		}
	}
	return -1;
}

gssize
_nm_utils_ptrarray_find_binary_search (gpointer *list, gsize len, gpointer needle, GCompareDataFunc cmpfcn, gpointer user_data)
{
	gssize imin, imax, imid;
	int cmp;

	g_return_val_if_fail (list || !len, ~((gssize) 0));
	g_return_val_if_fail (cmpfcn, ~((gssize) 0));

	imin = 0;
	if (len == 0)
		return ~imin;

	imax = len - 1;

	while (imin <= imax) {
		imid = imin + (imax - imin) / 2;

		cmp = cmpfcn (list[imid], needle, user_data);
		if (cmp == 0)
			return imid;

		if (cmp < 0)
			imin = imid + 1;
		else
			imax = imid - 1;
	}

	/* return the inverse of @imin. This is a negative number, but
	 * also is ~imin the position where the value should be inserted. */
	return ~imin;
}

GVariant *
_nm_utils_bytes_to_dbus (const GValue *prop_value)
{
	GBytes *bytes = g_value_get_boxed (prop_value);

	if (bytes) {
		return g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
		                                  g_bytes_get_data (bytes, NULL),
		                                  g_bytes_get_size (bytes),
		                                  1);
	} else {
		return g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
		                                  NULL, 0,
		                                  1);
	}
}

void
_nm_utils_bytes_from_dbus (GVariant *dbus_value,
                           GValue *prop_value)
{
	GBytes *bytes;

	if (g_variant_n_children (dbus_value)) {
		gconstpointer data;
		gsize length;

		data = g_variant_get_fixed_array (dbus_value, &length, 1);
		bytes = g_bytes_new (data, length);
	} else
		bytes = NULL;
	g_value_take_boxed (prop_value, bytes);
}

GSList *
_nm_utils_strv_to_slist (char **strv, gboolean deep_copy)
{
	int i;
	GSList *list = NULL;

	if (strv) {
		if (deep_copy) {
			for (i = 0; strv[i]; i++)
				list = g_slist_prepend (list, g_strdup (strv[i]));
		} else {
			for (i = 0; strv[i]; i++)
				list = g_slist_prepend (list, strv[i]);
		}
	}

	return g_slist_reverse (list);
}

char **
_nm_utils_slist_to_strv (GSList *slist, gboolean deep_copy)
{
	GSList *iter;
	char **strv;
	int len, i;

	len = g_slist_length (slist);
	strv = g_new (char *, len + 1);

	if (deep_copy) {
		for (i = 0, iter = slist; iter; iter = iter->next, i++)
			strv[i] = g_strdup (iter->data);
	} else {
		for (i = 0, iter = slist; iter; iter = iter->next, i++)
			strv[i] = iter->data;
	}
	strv[i] = NULL;

	return strv;
}

GPtrArray *
_nm_utils_strv_to_ptrarray (char **strv)
{
	GPtrArray *ptrarray;
	int i;

	ptrarray = g_ptr_array_new_with_free_func (g_free);

	if (strv) {
		for (i = 0; strv[i]; i++)
			g_ptr_array_add (ptrarray, g_strdup (strv[i]));
	}

	return ptrarray;
}

char **
_nm_utils_ptrarray_to_strv (GPtrArray *ptrarray)
{
	char **strv;
	int i;

	if (!ptrarray)
		return g_new0 (char *, 1);

	strv = g_new (char *, ptrarray->len + 1);

	for (i = 0; i < ptrarray->len; i++)
		strv[i] = g_strdup (ptrarray->pdata[i]);
	strv[i] = NULL;

	return strv;
}

/**
 * _nm_utils_strsplit_set:
 * @str: string to split
 * @delimiters: string of delimiter characters
 * @max_tokens: the maximum number of tokens to split string into. When it is
 * less than 1, the @str is split completely.
 *
 * Utility function for splitting string into a string array. It is a wrapper
 * for g_strsplit_set(), but it also removes empty strings from the vector as
 * they are not useful in most cases.
 *
 * Returns: (transfer full): a newly allocated NULL-terminated array of strings.
 * The caller must free the returned array with g_strfreev().
 **/
char **
_nm_utils_strsplit_set (const char *str, const char *delimiters, int max_tokens)
{
	char **result;
	uint i;
	uint j;

	result = g_strsplit_set (str, delimiters, max_tokens);

	/* remove empty strings */
	for (i = 0; result && result[i]; i++) {
		if (*result[i] == '\0') {
			g_free (result[i]);
			for (j = i; result[j]; j++)
				result[j] = result[j + 1];
			i--;
		}
	}
	return result;
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
 */
gboolean
nm_utils_wep_key_valid (const char *key, NMWepKeyType wep_type)
{
	int keylen, i;

	if (!key)
		return FALSE;

	if (wep_type == NM_WEP_KEY_TYPE_UNKNOWN) {
		return nm_utils_wep_key_valid (key, NM_WEP_KEY_TYPE_KEY) ||
		       nm_utils_wep_key_valid (key, NM_WEP_KEY_TYPE_PASSPHRASE);
	}

	keylen = strlen (key);
	if (wep_type == NM_WEP_KEY_TYPE_KEY) {
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
 * nm_utils_ip4_dns_to_variant:
 * @dns: (type utf8): an array of IP address strings
 *
 * Utility function to convert an array of IP address strings int a #GVariant of
 * type 'au' representing an array of IPv4 addresses.
 *
 * Returns: (transfer none): a new floating #GVariant representing @dns.
 **/
GVariant *
nm_utils_ip4_dns_to_variant (char **dns)
{
	GVariantBuilder builder;
	int i;

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("au"));

	if (dns) {
		for (i = 0; dns[i]; i++) {
			guint32 ip = 0;

			inet_pton (AF_INET, dns[i], &ip);
			g_variant_builder_add (&builder, "u", ip);
		}
	}

	return g_variant_builder_end (&builder);
}

/**
 * nm_utils_ip4_dns_from_variant:
 * @value: a #GVariant of type 'au'
 *
 * Utility function to convert a #GVariant of type 'au' representing a list of
 * IPv4 addresses into an array of IP address strings.
 *
 * Returns: (transfer full) (type utf8): a %NULL-terminated array of IP address strings.
 **/
char **
nm_utils_ip4_dns_from_variant (GVariant *value)
{
	const guint32 *array;
	gsize length;
	char **dns;
	int i;

	g_return_val_if_fail (g_variant_is_of_type (value, G_VARIANT_TYPE ("au")), NULL);

	array = g_variant_get_fixed_array (value, &length, sizeof (guint32));
	dns = g_new (char *, length + 1);

	for (i = 0; i < length; i++)
		dns[i] = g_strdup (nm_utils_inet4_ntop (array[i], NULL));
	dns[i] = NULL;

	return dns;
}

/**
 * nm_utils_ip4_addresses_to_variant:
 * @addresses: (element-type NMIPAddress): an array of #NMIPAddress objects
 * @gateway: (allow-none): the gateway IP address
 *
 * Utility function to convert a #GPtrArray of #NMIPAddress objects representing
 * IPv4 addresses into a #GVariant of type 'aau' representing an array of
 * NetworkManager IPv4 addresses (which are tuples of address, prefix, and
 * gateway). The "gateway" field of the first address will get the value of
 * @gateway (if non-%NULL). In all of the other addresses, that field will be 0.
 *
 * Returns: (transfer none): a new floating #GVariant representing @addresses.
 **/
GVariant *
nm_utils_ip4_addresses_to_variant (GPtrArray *addresses, const char *gateway)
{
	GVariantBuilder builder;
	int i;

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("aau"));

	if (addresses) {
		for (i = 0; i < addresses->len; i++) {
			NMIPAddress *addr = addresses->pdata[i];
			guint32 array[3];

			if (nm_ip_address_get_family (addr) != AF_INET)
				continue;

			nm_ip_address_get_address_binary (addr, &array[0]);
			array[1] = nm_ip_address_get_prefix (addr);
			if (i == 0 && gateway)
				inet_pton (AF_INET, gateway, &array[2]);
			else
				array[2] = 0;

			g_variant_builder_add (&builder, "@au",
			                       g_variant_new_fixed_array (G_VARIANT_TYPE_UINT32,
			                                                  array, 3, sizeof (guint32)));
		}
	}

	return g_variant_builder_end (&builder);
}

/**
 * nm_utils_ip4_addresses_from_variant:
 * @value: a #GVariant of type 'aau'
 * @out_gateway: (out) (allow-none) (transfer full): on return, will contain the IP gateway
 *
 * Utility function to convert a #GVariant of type 'aau' representing a list of
 * NetworkManager IPv4 addresses (which are tuples of address, prefix, and
 * gateway) into a #GPtrArray of #NMIPAddress objects. The "gateway" field of
 * the first address (if set) will be returned in @out_gateway; the "gateway" fields
 * of the other addresses are ignored.
 *
 * Returns: (transfer full) (element-type NMIPAddress): a newly allocated
 *   #GPtrArray of #NMIPAddress objects
 **/
GPtrArray *
nm_utils_ip4_addresses_from_variant (GVariant *value, char **out_gateway)
{
	GPtrArray *addresses;
	GVariantIter iter;
	GVariant *addr_var;

	g_return_val_if_fail (g_variant_is_of_type (value, G_VARIANT_TYPE ("aau")), NULL);

	if (out_gateway)
		*out_gateway = NULL;

	g_variant_iter_init (&iter, value);
	addresses = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_ip_address_unref);

	while (g_variant_iter_next (&iter, "@au", &addr_var)) {
		const guint32 *addr_array;
		gsize length;
		NMIPAddress *addr;
		GError *error = NULL;

		addr_array = g_variant_get_fixed_array (addr_var, &length, sizeof (guint32));
		if (length < 3) {
			g_warning ("Ignoring invalid IP4 address");
			g_variant_unref (addr_var);
			continue;
		}

		addr = nm_ip_address_new_binary (AF_INET, &addr_array[0], addr_array[1], &error);
		if (addr) {
			g_ptr_array_add (addresses, addr);

			if (addr_array[2] && out_gateway && !*out_gateway)
				*out_gateway = g_strdup (nm_utils_inet4_ntop (addr_array[2], NULL));
		} else {
			g_warning ("Ignoring invalid IP4 address: %s", error->message);
			g_clear_error (&error);
		}

		g_variant_unref (addr_var);
	}

	return addresses;
}

/**
 * nm_utils_ip4_routes_to_variant:
 * @routes: (element-type NMIPRoute): an array of #NMIP4Route objects
 *
 * Utility function to convert a #GPtrArray of #NMIPRoute objects representing
 * IPv4 routes into a #GVariant of type 'aau' representing an array of
 * NetworkManager IPv4 routes (which are tuples of route, prefix, next hop, and
 * metric).
 *
 * Returns: (transfer none): a new floating #GVariant representing @routes.
 **/
GVariant *
nm_utils_ip4_routes_to_variant (GPtrArray *routes)
{
	GVariantBuilder builder;
	int i;

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("aau"));

	if (routes) {
		for (i = 0; i < routes->len; i++) {
			NMIPRoute *route = routes->pdata[i];
			guint32 array[4];

			if (nm_ip_route_get_family (route) != AF_INET)
				continue;

			nm_ip_route_get_dest_binary (route, &array[0]);
			array[1] = nm_ip_route_get_prefix (route);
			nm_ip_route_get_next_hop_binary (route, &array[2]);
			/* The old routes format uses "0" for default, not "-1" */
			array[3] = MAX (0, nm_ip_route_get_metric (route));

			g_variant_builder_add (&builder, "@au",
			                       g_variant_new_fixed_array (G_VARIANT_TYPE_UINT32,
			                                                  array, 4, sizeof (guint32)));
		}
	}

	return g_variant_builder_end (&builder);
}

/**
 * nm_utils_ip4_routes_from_variant:
 * @value: #GVariant of type 'aau'
 *
 * Utility function to convert a #GVariant of type 'aau' representing an array
 * of NetworkManager IPv4 routes (which are tuples of route, prefix, next hop,
 * and metric) into a #GPtrArray of #NMIPRoute objects.
 *
 * Returns: (transfer full) (element-type NMIPRoute): a newly allocated
 *   #GPtrArray of #NMIPRoute objects
 **/
GPtrArray *
nm_utils_ip4_routes_from_variant (GVariant *value)
{
	GVariantIter iter;
	GVariant *route_var;
	GPtrArray *routes;

	g_return_val_if_fail (g_variant_is_of_type (value, G_VARIANT_TYPE ("aau")), NULL);

	g_variant_iter_init (&iter, value);
	routes = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_ip_route_unref);

	while (g_variant_iter_next (&iter, "@au", &route_var)) {
		const guint32 *route_array;
		gsize length;
		NMIPRoute *route;
		GError *error = NULL;

		route_array = g_variant_get_fixed_array (route_var, &length, sizeof (guint32));
		if (length < 4) {
			g_warning ("Ignoring invalid IP4 route");
			g_variant_unref (route_var);
			continue;
		}

		route = nm_ip_route_new_binary (AF_INET,
		                                &route_array[0],
		                                route_array[1],
		                                &route_array[2],
		                                /* The old routes format uses "0" for default, not "-1" */
		                                route_array[3] ? (gint64) route_array[3] : -1,
		                                &error);
		if (route)
			g_ptr_array_add (routes, route);
		else {
			g_warning ("Ignoring invalid IP4 route: %s", error->message);
			g_clear_error (&error);
		}
		g_variant_unref (route_var);
	}

	return routes;
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
 * nm_utils_ip6_dns_to_variant:
 * @dns: (type utf8): an array of IP address strings
 *
 * Utility function to convert an array of IP address strings int a #GVariant of
 * type 'aay' representing an array of IPv6 addresses.
 *
 * Returns: (transfer none): a new floating #GVariant representing @dns.
 **/
GVariant *
nm_utils_ip6_dns_to_variant (char **dns)
{
	GVariantBuilder builder;
	int i;

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("aay"));

	if (dns) {
		for (i = 0; dns[i]; i++) {
			struct in6_addr ip;

			inet_pton (AF_INET6, dns[i], &ip);
			g_variant_builder_add (&builder, "@ay",
			                       g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
			                                                  &ip, sizeof (ip), 1));
		}
	}

	return g_variant_builder_end (&builder);
}

/**
 * nm_utils_ip6_dns_from_variant:
 * @value: a #GVariant of type 'aay'
 *
 * Utility function to convert a #GVariant of type 'aay' representing a list of
 * IPv6 addresses into an array of IP address strings.
 *
 * Returns: (transfer full) (type utf8): a %NULL-terminated array of IP address strings.
 **/
char **
nm_utils_ip6_dns_from_variant (GVariant *value)
{
	GVariantIter iter;
	GVariant *ip_var;
	char **dns;
	int i;

	g_return_val_if_fail (g_variant_is_of_type (value, G_VARIANT_TYPE ("aay")), NULL);

	dns = g_new (char *, g_variant_n_children (value) + 1);

	g_variant_iter_init (&iter, value);
	i = 0;
	while (g_variant_iter_next (&iter, "@ay", &ip_var)) {
		gsize length;
		const struct in6_addr *ip = g_variant_get_fixed_array (ip_var, &length, 1);

		if (length != sizeof (struct in6_addr)) {
			g_warning ("%s: ignoring invalid IP6 address of length %d",
			           __func__, (int) length);
			g_variant_unref (ip_var);
			continue;
		}

		dns[i++] = g_strdup (nm_utils_inet6_ntop (ip, NULL));
		g_variant_unref (ip_var);
	}
	dns[i] = NULL;

	return dns;
}

/**
 * nm_utils_ip6_addresses_to_variant:
 * @addresses: (element-type NMIPAddress): an array of #NMIPAddress objects
 * @gateway: (allow-none): the gateway IP address
 *
 * Utility function to convert a #GPtrArray of #NMIPAddress objects representing
 * IPv6 addresses into a #GVariant of type 'a(ayuay)' representing an array of
 * NetworkManager IPv6 addresses (which are tuples of address, prefix, and
 * gateway).  The "gateway" field of the first address will get the value of
 * @gateway (if non-%NULL). In all of the other addresses, that field will be
 * all 0s.
 *
 * Returns: (transfer none): a new floating #GVariant representing @addresses.
 **/
GVariant *
nm_utils_ip6_addresses_to_variant (GPtrArray *addresses, const char *gateway)
{
	GVariantBuilder builder;
	int i;

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("a(ayuay)"));

	if (addresses) {
		for (i = 0; i < addresses->len; i++) {
			NMIPAddress *addr = addresses->pdata[i];
			struct in6_addr ip_bytes, gateway_bytes;
			GVariant *ip_var, *gateway_var;
			guint32 prefix;

			if (nm_ip_address_get_family (addr) != AF_INET6)
				continue;

			nm_ip_address_get_address_binary (addr, &ip_bytes);
			ip_var = g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, &ip_bytes, 16, 1);

			prefix = nm_ip_address_get_prefix (addr);

			if (i == 0 && gateway)
				inet_pton (AF_INET6, gateway, &gateway_bytes);
			else
				memset (&gateway_bytes, 0, sizeof (gateway_bytes));
			gateway_var = g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, &gateway_bytes, 16, 1);

			g_variant_builder_add (&builder, "(@ayu@ay)", ip_var, prefix, gateway_var);
		}
	}

	return g_variant_builder_end (&builder);
}

/**
 * nm_utils_ip6_addresses_from_variant:
 * @value: a #GVariant of type 'a(ayuay)'
 * @out_gateway: (out) (allow-none) (transfer full): on return, will contain the IP gateway
 *
 * Utility function to convert a #GVariant of type 'a(ayuay)' representing a
 * list of NetworkManager IPv6 addresses (which are tuples of address, prefix,
 * and gateway) into a #GPtrArray of #NMIPAddress objects. The "gateway" field
 * of the first address (if set) will be returned in @out_gateway; the "gateway"
 * fields of the other addresses are ignored.
 *
 * Returns: (transfer full) (element-type NMIPAddress): a newly allocated
 *   #GPtrArray of #NMIPAddress objects
 **/
GPtrArray *
nm_utils_ip6_addresses_from_variant (GVariant *value, char **out_gateway)
{
	GVariantIter iter;
	GVariant *addr_var, *gateway_var;
	guint32 prefix;
	GPtrArray *addresses;

	g_return_val_if_fail (g_variant_is_of_type (value, G_VARIANT_TYPE ("a(ayuay)")), NULL);

	if (out_gateway)
		*out_gateway = NULL;

	g_variant_iter_init (&iter, value);
	addresses = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_ip_address_unref);

	while (g_variant_iter_next (&iter, "(@ayu@ay)", &addr_var, &prefix, &gateway_var)) {
		NMIPAddress *addr;
		const struct in6_addr *addr_bytes, *gateway_bytes;
		gsize addr_len, gateway_len;
		GError *error = NULL;

		if (   !g_variant_is_of_type (addr_var, G_VARIANT_TYPE_BYTESTRING)
		    || !g_variant_is_of_type (gateway_var, G_VARIANT_TYPE_BYTESTRING)) {
			g_warning ("%s: ignoring invalid IP6 address structure", __func__);
			goto next;
		}

		addr_bytes = g_variant_get_fixed_array (addr_var, &addr_len, 1);
		if (addr_len != 16) {
			g_warning ("%s: ignoring invalid IP6 address of length %d",
			           __func__, (int) addr_len);
			goto next;
		}

		addr = nm_ip_address_new_binary (AF_INET6, addr_bytes, prefix, &error);
		if (addr) {
			g_ptr_array_add (addresses, addr);

			if (out_gateway && !*out_gateway) {
				gateway_bytes = g_variant_get_fixed_array (gateway_var, &gateway_len, 1);
				if (gateway_len != 16) {
					g_warning ("%s: ignoring invalid IP6 address of length %d",
					           __func__, (int) gateway_len);
					goto next;
				}
				if (!IN6_IS_ADDR_UNSPECIFIED (gateway_bytes))
					*out_gateway = g_strdup (nm_utils_inet6_ntop (gateway_bytes, NULL));
			}
		} else {
			g_warning ("Ignoring invalid IP6 address: %s", error->message);
			g_clear_error (&error);
		}

	next:
		g_variant_unref (addr_var);
		g_variant_unref (gateway_var);
	}

	return addresses;
}

/**
 * nm_utils_ip6_routes_to_variant:
 * @routes: (element-type NMIPRoute): an array of #NMIPRoute objects
 *
 * Utility function to convert a #GPtrArray of #NMIPRoute objects representing
 * IPv6 routes into a #GVariant of type 'a(ayuayu)' representing an array of
 * NetworkManager IPv6 routes (which are tuples of route, prefix, next hop, and
 * metric).
 *
 * Returns: (transfer none): a new floating #GVariant representing @routes.
 **/
GVariant *
nm_utils_ip6_routes_to_variant (GPtrArray *routes)
{
	GVariantBuilder builder;
	int i;

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("a(ayuayu)"));

	if (routes) {
		for (i = 0; i < routes->len; i++) {
			NMIPRoute *route = routes->pdata[i];
			struct in6_addr dest_bytes, next_hop_bytes;
			GVariant *dest, *next_hop;
			guint32 prefix, metric;

			if (nm_ip_route_get_family (route) != AF_INET6)
				continue;

			nm_ip_route_get_dest_binary (route, &dest_bytes);
			dest = g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, &dest_bytes, 16, 1);
			prefix = nm_ip_route_get_prefix (route);
			nm_ip_route_get_next_hop_binary (route, &next_hop_bytes);
			next_hop = g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, &next_hop_bytes, 16, 1);
			/* The old routes format uses "0" for default, not "-1" */
			metric = MAX (0, nm_ip_route_get_metric (route));

			g_variant_builder_add (&builder, "(@ayu@ayu)", dest, prefix, next_hop, metric);
		}
	}

	return g_variant_builder_end (&builder);
}

/**
 * nm_utils_ip6_routes_from_variant:
 * @value: #GVariant of type 'a(ayuayu)'
 *
 * Utility function to convert a #GVariant of type 'a(ayuayu)' representing an
 * array of NetworkManager IPv6 routes (which are tuples of route, prefix, next
 * hop, and metric) into a #GPtrArray of #NMIPRoute objects.
 *
 * Returns: (transfer full) (element-type NMIPRoute): a newly allocated
 *   #GPtrArray of #NMIPRoute objects
 **/
GPtrArray *
nm_utils_ip6_routes_from_variant (GVariant *value)
{
	GPtrArray *routes;
	GVariantIter iter;
	GVariant *dest_var, *next_hop_var;
	const struct in6_addr *dest, *next_hop;
	gsize dest_len, next_hop_len;
	guint32 prefix, metric;

	g_return_val_if_fail (g_variant_is_of_type (value, G_VARIANT_TYPE ("a(ayuayu)")), NULL);

	routes = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_ip_route_unref);

	g_variant_iter_init (&iter, value);
	while (g_variant_iter_next (&iter, "(@ayu@ayu)", &dest_var, &prefix, &next_hop_var, &metric)) {
		NMIPRoute *route;
		GError *error = NULL;

		if (   !g_variant_is_of_type (dest_var, G_VARIANT_TYPE_BYTESTRING)
		    || !g_variant_is_of_type (next_hop_var, G_VARIANT_TYPE_BYTESTRING)) {
			g_warning ("%s: ignoring invalid IP6 address structure", __func__);
			goto next;
		}

		dest = g_variant_get_fixed_array (dest_var, &dest_len, 1);
		if (dest_len != 16) {
			g_warning ("%s: ignoring invalid IP6 address of length %d",
			           __func__, (int) dest_len);
			goto next;
		}

		next_hop = g_variant_get_fixed_array (next_hop_var, &next_hop_len, 1);
		if (next_hop_len != 16) {
			g_warning ("%s: ignoring invalid IP6 address of length %d",
			           __func__, (int) next_hop_len);
			goto next;
		}

		route = nm_ip_route_new_binary (AF_INET6, dest, prefix, next_hop,
		                                metric ? (gint64) metric : -1,
		                                &error);
		if (route)
			g_ptr_array_add (routes, route);
		else {
			g_warning ("Ignoring invalid IP6 route: %s", error->message);
			g_clear_error (&error);
		}

	next:
		g_variant_unref (dest_var);
		g_variant_unref (next_hop_var);
	}

	return routes;
}

/**
 * nm_utils_ip_addresses_to_variant:
 * @addresses: (element-type NMIPAddress): an array of #NMIPAddress objects
 *
 * Utility function to convert a #GPtrArray of #NMIPAddress objects representing
 * IPv4 or IPv6 addresses into a #GVariant of type 'aa{sv}' representing an
 * array of new-style NetworkManager IP addresses. All addresses will include
 * "address" (an IP address string), and "prefix" (a uint). Some addresses may
 * include additional attributes.
 *
 * Returns: (transfer none): a new floating #GVariant representing @addresses.
 **/
GVariant *
nm_utils_ip_addresses_to_variant (GPtrArray *addresses)
{
	GVariantBuilder builder;
	int i;

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("aa{sv}"));

	if (addresses) {
		for (i = 0; i < addresses->len; i++) {
			NMIPAddress *addr = addresses->pdata[i];
			GVariantBuilder addr_builder;
			char **names;
			int n;

			g_variant_builder_init (&addr_builder, G_VARIANT_TYPE ("a{sv}"));
			g_variant_builder_add (&addr_builder, "{sv}",
			                       "address",
			                       g_variant_new_string (nm_ip_address_get_address (addr)));
			g_variant_builder_add (&addr_builder, "{sv}",
			                       "prefix",
			                       g_variant_new_uint32 (nm_ip_address_get_prefix (addr)));

			names = nm_ip_address_get_attribute_names (addr);
			for (n = 0; names[n]; n++) {
				g_variant_builder_add (&addr_builder, "{sv}",
				                       names[n],
				                       nm_ip_address_get_attribute (addr, names[n]));
			}
			g_strfreev (names);

			g_variant_builder_add (&builder, "a{sv}", &addr_builder);
		}
	}

	return g_variant_builder_end (&builder);
}

/**
 * nm_utils_ip_addresses_from_variant:
 * @value: a #GVariant of type 'aa{sv}'
 * @family: an IP address family
 *
 * Utility function to convert a #GVariant representing a list of new-style
 * NetworkManager IPv4 or IPv6 addresses (as described in the documentation for
 * nm_utils_ip_addresses_to_variant()) into a #GPtrArray of #NMIPAddress
 * objects.
 *
 * Returns: (transfer full) (element-type NMIPAddress): a newly allocated
 *   #GPtrArray of #NMIPAddress objects
 **/
GPtrArray *
nm_utils_ip_addresses_from_variant (GVariant *value,
                                    int family)
{
	GPtrArray *addresses;
	GVariantIter iter, attrs_iter;
	GVariant *addr_var;
	const char *ip;
	guint32 prefix;
	const char *attr_name;
	GVariant *attr_val;
	NMIPAddress *addr;
	GError *error = NULL;

	g_return_val_if_fail (g_variant_is_of_type (value, G_VARIANT_TYPE ("aa{sv}")), NULL);

	g_variant_iter_init (&iter, value);
	addresses = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_ip_address_unref);

	while (g_variant_iter_next (&iter, "@a{sv}", &addr_var)) {
		if (   !g_variant_lookup (addr_var, "address", "&s", &ip)
		    || !g_variant_lookup (addr_var, "prefix", "u", &prefix)) {
			g_warning ("Ignoring invalid address");
			g_variant_unref (addr_var);
			continue;
		}

		addr = nm_ip_address_new (family, ip, prefix, &error);
		if (!addr) {
			g_warning ("Ignoring invalid address: %s", error->message);
			g_clear_error (&error);
			g_variant_unref (addr_var);
			continue;
		}

		g_variant_iter_init (&attrs_iter, addr_var);
		while (g_variant_iter_next (&attrs_iter, "{&sv}", &attr_name, &attr_val)) {
			if (   strcmp (attr_name, "address") != 0
			    && strcmp (attr_name, "prefix") != 0)
				nm_ip_address_set_attribute (addr, attr_name, attr_val);
			g_variant_unref (attr_val);
		}

		g_variant_unref (addr_var);
		g_ptr_array_add (addresses, addr);
	}

	return addresses;
}

/**
 * nm_utils_ip_routes_to_variant:
 * @routes: (element-type NMIPRoute): an array of #NMIPRoute objects
 *
 * Utility function to convert a #GPtrArray of #NMIPRoute objects representing
 * IPv4 or IPv6 routes into a #GVariant of type 'aa{sv}' representing an array
 * of new-style NetworkManager IP routes (which are tuples of destination,
 * prefix, next hop, metric, and additional attributes).
 *
 * Returns: (transfer none): a new floating #GVariant representing @routes.
 **/
GVariant *
nm_utils_ip_routes_to_variant (GPtrArray *routes)
{
	GVariantBuilder builder;
	int i;

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("aa{sv}"));

	if (routes) {
		for (i = 0; i < routes->len; i++) {
			NMIPRoute *route = routes->pdata[i];
			GVariantBuilder route_builder;
			char **names;
			int n;

			g_variant_builder_init (&route_builder, G_VARIANT_TYPE ("a{sv}"));
			g_variant_builder_add (&route_builder, "{sv}",
			                       "dest",
			                       g_variant_new_string (nm_ip_route_get_dest (route)));
			g_variant_builder_add (&route_builder, "{sv}",
			                       "prefix",
			                       g_variant_new_uint32 (nm_ip_route_get_prefix (route)));
			if (nm_ip_route_get_next_hop (route)) {
				g_variant_builder_add (&route_builder, "{sv}",
				                       "next-hop",
				                       g_variant_new_string (nm_ip_route_get_next_hop (route)));
			}
			if (nm_ip_route_get_metric (route) != -1) {
				g_variant_builder_add (&route_builder, "{sv}",
				                       "metric",
				                       g_variant_new_uint32 ((guint32) nm_ip_route_get_metric (route)));
			}

			names = nm_ip_route_get_attribute_names (route);
			for (n = 0; names[n]; n++) {
				g_variant_builder_add (&route_builder, "{sv}",
				                       names[n],
				                       nm_ip_route_get_attribute (route, names[n]));
			}
			g_strfreev (names);

			g_variant_builder_add (&builder, "a{sv}", &route_builder);
		}
	}

	return g_variant_builder_end (&builder);
}

/**
 * nm_utils_ip_routes_from_variant:
 * @value: a #GVariant of type 'aa{sv}'
 * @family: an IP address family
 *
 * Utility function to convert a #GVariant representing a list of new-style
 * NetworkManager IPv4 or IPv6 addresses (which are tuples of destination,
 * prefix, next hop, metric, and additional attributes) into a #GPtrArray of
 * #NMIPRoute objects.
 *
 * Returns: (transfer full) (element-type NMIPRoute): a newly allocated
 *   #GPtrArray of #NMIPRoute objects
 **/
GPtrArray *
nm_utils_ip_routes_from_variant (GVariant *value,
                                 int family)
{
	GPtrArray *routes;
	GVariantIter iter, attrs_iter;
	GVariant *route_var;
	const char *dest, *next_hop;
	guint32 prefix, metric32;
	gint64 metric;
	const char *attr_name;
	GVariant *attr_val;
	NMIPRoute *route;
	GError *error = NULL;

	g_return_val_if_fail (g_variant_is_of_type (value, G_VARIANT_TYPE ("aa{sv}")), NULL);

	g_variant_iter_init (&iter, value);
	routes = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_ip_route_unref);

	while (g_variant_iter_next (&iter, "@a{sv}", &route_var)) {
		if (   !g_variant_lookup (route_var, "dest", "&s", &dest)
		    || !g_variant_lookup (route_var, "prefix", "u", &prefix)) {
			g_warning ("Ignoring invalid address");
			g_variant_unref (route_var);
			continue;
		}
		if (!g_variant_lookup (route_var, "next-hop", "&s", &next_hop))
			next_hop = NULL;
		if (g_variant_lookup (route_var, "metric", "u", &metric32))
			metric = metric32;
		else
			metric = -1;

		route = nm_ip_route_new (family, dest, prefix, next_hop, metric, &error);
		if (!route) {
			g_warning ("Ignoring invalid route: %s", error->message);
			g_clear_error (&error);
			g_variant_unref (route_var);
			continue;
		}

		g_variant_iter_init (&attrs_iter, route_var);
		while (g_variant_iter_next (&attrs_iter, "{&sv}", &attr_name, &attr_val)) {
			if (   strcmp (attr_name, "dest") != 0
			    && strcmp (attr_name, "prefix") != 0
			    && strcmp (attr_name, "next-hop") != 0
			    && strcmp (attr_name, "metric") != 0)
				nm_ip_route_set_attribute (route, attr_name, attr_val);
			g_variant_unref (attr_val);
		}

		g_ptr_array_add (routes, route);
	}

	return routes;
}

/**********************************************************************************************/

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
 * @slen: if negative, treat @s as zero terminated C string.
 *   Otherwise, assume the length as given (and allow @s to be
 *   non-null terminated or contain '\0').
 * @uuid_type: a type identifier which UUID format to generate.
 * @type_args: additional arguments, depending on the uuid_type
 *
 * For a given @s, this function will always return the same UUID.
 *
 * Returns: a newly allocated UUID suitable for use as the #NMSettingConnection
 * object's #NMSettingConnection:id: property
 **/
char *
nm_utils_uuid_generate_from_string (const char *s, gssize slen, int uuid_type, gpointer type_args)
{
	uuid_t uuid;
	char *buf;

	g_return_val_if_fail (slen == 0 || s, FALSE);

	g_return_val_if_fail (uuid_type == NM_UTILS_UUID_TYPE_LEGACY || uuid_type == NM_UTILS_UUID_TYPE_VARIANT3, NULL);
	g_return_val_if_fail (!type_args || uuid_type == NM_UTILS_UUID_TYPE_VARIANT3, NULL);

	switch (uuid_type) {
	case NM_UTILS_UUID_TYPE_LEGACY:
		crypto_md5_hash (NULL, 0, s, slen, (char *) uuid, sizeof (uuid));
		break;
	case NM_UTILS_UUID_TYPE_VARIANT3: {
		uuid_t ns_uuid = { 0 };

		if (type_args) {
			/* type_args can be a name space UUID. Interpret it as (char *) */
			if (uuid_parse ((char *) type_args, ns_uuid) != 0)
				g_return_val_if_reached (NULL);
		}

		crypto_md5_hash (s, slen, (char *) ns_uuid, sizeof (ns_uuid), (char *) uuid, sizeof (uuid));

		uuid[6] = (uuid[6] & 0x0F) | 0x30;
		uuid[8] = (uuid[8] & 0x3F) | 0x80;
		break;
	}
	default:
		g_return_val_if_reached (NULL);
	}

	buf = g_malloc0 (37);
	uuid_unparse_lower (uuid, &buf[0]);

	return buf;
}

/**
 * _nm_utils_uuid_generate_from_strings:
 * @string1: a variadic list of strings. Must be NULL terminated.
 *
 * Returns a variant3 UUID based on the concatenated C strings.
 * It does not simply concatenate them, but also includes the
 * terminating '\0' character. For example "a", "b", gives
 * "a\0b\0".
 *
 * This has the advantage, that the following invocations
 * all give different UUIDs: (NULL), (""), ("",""), ("","a"), ("a",""),
 * ("aa"), ("aa", ""), ("", "aa"), ...
 */
char *
_nm_utils_uuid_generate_from_strings (const char *string1, ...)
{
	GString *str;
	va_list args;
	const char *s;
	char *uuid;

	if (!string1)
		return nm_utils_uuid_generate_from_string (NULL, 0, NM_UTILS_UUID_TYPE_VARIANT3, NM_UTILS_UUID_NS);

	str = g_string_sized_new (120); /* effectively allocates power of 2 (128)*/

	g_string_append_len (str, string1, strlen (string1) + 1);

	va_start (args, string1);
	s = va_arg (args, const char *);
	while (s) {
		g_string_append_len (str, s, strlen (s) + 1);
		s = va_arg (args, const char *);
	}
	va_end (args);

	uuid = nm_utils_uuid_generate_from_string (str->str, str->len, NM_UTILS_UUID_TYPE_VARIANT3, NM_UTILS_UUID_NS);

	g_string_free (str, TRUE);
	return uuid;
}

/**********************************************************************************************/

/**
 * nm_utils_rsa_key_encrypt:
 * @data: (array length=len): RSA private key data to be encrypted
 * @len: length of @data
 * @in_password: (allow-none): existing password to use, if any
 * @out_password: (out) (allow-none): if @in_password was %NULL, a random
 *  password will be generated and returned in this argument
 * @error: detailed error information on return, if an error occurred
 *
 * Encrypts the given RSA private key data with the given password (or generates
 * a password if no password was given) and converts the data to PEM format
 * suitable for writing to a file. It uses Triple DES cipher for the encryption.
 *
 * Returns: (transfer full): on success, PEM-formatted data suitable for writing
 * to a PEM-formatted certificate/private key file.
 **/
GByteArray *
nm_utils_rsa_key_encrypt (const guint8 *data,
                          gsize len,
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

	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (len > 0, NULL);
	if (out_password)
		g_return_val_if_fail (*out_password == NULL, NULL);

	/* Make the password if needed */
	if (!in_password) {
		if (!crypto_randomize (pw_buf, sizeof (pw_buf), error))
			return NULL;
		in_password = tmp_password = nm_utils_bin2hexstr (pw_buf, sizeof (pw_buf), -1);
	}

	salt_len = 8;
	if (!crypto_randomize (salt, salt_len, error))
		goto out;

	key = crypto_make_des_aes_key (CIPHER_DES_EDE3_CBC, &salt[0], salt_len, in_password, &key_len, NULL);
	if (!key)
		g_return_val_if_reached (NULL);

	enc = crypto_encrypt (CIPHER_DES_EDE3_CBC, data, len, salt, salt_len, key, key_len, &enc_len, error);
	if (!enc)
		goto out;

	pem = g_string_sized_new (enc_len * 2 + 100);
	g_string_append (pem, "-----BEGIN RSA PRIVATE KEY-----\n");
	g_string_append (pem, "Proc-Type: 4,ENCRYPTED\n");

	/* Convert the salt to a hex string */
	tmp = nm_utils_bin2hexstr (salt, salt_len, salt_len * 2);
	g_string_append_printf (pem, "DEK-Info: %s,%s\n\n", CIPHER_DES_EDE3_CBC, tmp);
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

static gboolean
file_has_extension (const char *filename, const char *extensions[])
{
	const char *ext;
	int i;

	ext = strrchr (filename, '.');
	if (!ext)
		return FALSE;

	for (i = 0; extensions[i]; i++) {
		if (!g_ascii_strcasecmp (ext, extensions[i]))
			return TRUE;
	}

	return FALSE;
}

/**
 * nm_utils_file_is_certificate:
 * @filename: name of the file to test
 *
 * Tests if @filename has a valid extension for an X.509 certificate file
 * (".cer", ".crt", ".der", or ".pem"), and contains a certificate in a format
 * recognized by NetworkManager.
 *
 * Returns: %TRUE if the file is a certificate, %FALSE if it is not
 **/
gboolean
nm_utils_file_is_certificate (const char *filename)
{
	const char *extensions[] = { ".der", ".pem", ".crt", ".cer", NULL };
	NMCryptoFileFormat file_format = NM_CRYPTO_FILE_FORMAT_UNKNOWN;
	GByteArray *cert;

	g_return_val_if_fail (filename != NULL, FALSE);

	if (!file_has_extension (filename, extensions))
		return FALSE;

	cert = crypto_load_and_verify_certificate (filename, &file_format, NULL);
	if (cert)
		g_byte_array_unref (cert);

	return file_format = NM_CRYPTO_FILE_FORMAT_X509;
}

/**
 * nm_utils_file_is_private_key:
 * @filename: name of the file to test
 * @out_encrypted: (out): on return, whether the file is encrypted
 *
 * Tests if @filename has a valid extension for an X.509 private key file
 * (".der", ".key", ".pem", or ".p12"), and contains a private key in a format
 * recognized by NetworkManager.
 *
 * Returns: %TRUE if the file is a private key, %FALSE if it is not
 **/
gboolean
nm_utils_file_is_private_key (const char *filename, gboolean *out_encrypted)
{
	const char *extensions[] = { ".der", ".pem", ".p12", ".key", NULL };

	g_return_val_if_fail (filename != NULL, FALSE);
	g_return_val_if_fail (out_encrypted == NULL || *out_encrypted == FALSE, FALSE);

	if (!file_has_extension (filename, extensions))
		return FALSE;

	return crypto_verify_private_key (filename, NULL, out_encrypted, NULL) != NM_CRYPTO_FILE_FORMAT_UNKNOWN;
}

/**
 * nm_utils_file_is_pkcs12:
 * @filename: name of the file to test
 *
 * Tests if @filename is a PKCS#<!-- -->12 file.
 *
 * Returns: %TRUE if the file is PKCS#<!-- -->12, %FALSE if it is not
 **/
gboolean
nm_utils_file_is_pkcs12 (const char *filename)
{
	g_return_val_if_fail (filename != NULL, FALSE);

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
 * nm_utils_wifi_strength_bars:
 * @strength: the access point strength, from 0 to 100
 *
 * Converts @strength into a 4-character-wide graphical representation of
 * strength suitable for printing to stdout. If the current locale and terminal
 * support it, this will use unicode graphics characters to represent
 * "bars". Otherwise it will use 0 to 4 asterisks.
 *
 * Returns: the graphical representation of the access point strength
 */
const char *
nm_utils_wifi_strength_bars (guint8 strength)
{
	static const char *strength_full, *strength_high, *strength_med, *strength_low, *strength_none;

	if (G_UNLIKELY (strength_full == NULL)) {
		gboolean can_show_graphics = TRUE;
		char *locale_str;

		if (!g_get_charset (NULL)) {
			/* Non-UTF-8 locale */
			locale_str = g_locale_from_utf8 ("\342\226\202\342\226\204\342\226\206\342\226\210", -1, NULL, NULL, NULL);
			if (locale_str)
				g_free (locale_str);
			else
				can_show_graphics = FALSE;
		}

		/* The linux console font doesn't have these characters */
		if (g_strcmp0 (g_getenv ("TERM"), "linux") == 0)
			can_show_graphics = FALSE;

		if (can_show_graphics) {
			strength_full = /* ▂▄▆█ */ "\342\226\202\342\226\204\342\226\206\342\226\210";
			strength_high = /* ▂▄▆_ */ "\342\226\202\342\226\204\342\226\206_";
			strength_med  = /* ▂▄__ */ "\342\226\202\342\226\204__";
			strength_low  = /* ▂___ */ "\342\226\202___";
			strength_none = /* ____ */ "____";
		} else {
			strength_full = "****";
			strength_high = "*** ";
			strength_med  = "**  ";
			strength_low  = "*   ";
			strength_none = "    ";
		}
	}

	if (strength > 80)
		return strength_full;
	else if (strength > 55)
		return strength_high;
	else if (strength > 30)
		return strength_med;
	else if (strength > 5)
		return strength_low;
	else
		return strength_none;
}

/**
 * nm_utils_hwaddr_len:
 * @type: the type of address; either <literal>ARPHRD_ETHER</literal> or
 * <literal>ARPHRD_INFINIBAND</literal>
 *
 * Returns the length in octets of a hardware address of type @type.
 *
 * It is an error to call this function with any value other than
 * <literal>ARPHRD_ETHER</literal> or <literal>ARPHRD_INFINIBAND</literal>.
 *
 * Return value: the length.
 */
gsize
nm_utils_hwaddr_len (int type)
{
	g_return_val_if_fail (type == ARPHRD_ETHER || type == ARPHRD_INFINIBAND, 0);

	if (type == ARPHRD_ETHER)
		return ETH_ALEN;
	else if (type == ARPHRD_INFINIBAND)
		return INFINIBAND_ALEN;

	g_assert_not_reached ();
}

#define HEXVAL(c) ((c) <= '9' ? (c) - '0' : ((c) & 0x4F) - 'A' + 10)

/**
 * nm_utils_hwaddr_atoba:
 * @asc: the ASCII representation of a hardware address
 * @length: the expected length in bytes of the result
 *
 * Parses @asc and converts it to binary form in a #GByteArray. See
 * nm_utils_hwaddr_aton() if you don't want a #GByteArray.
 *
 * Return value: (transfer full): a new #GByteArray, or %NULL if @asc couldn't
 * be parsed
 */
GByteArray *
nm_utils_hwaddr_atoba (const char *asc, gsize length)
{
	GByteArray *ba;

	g_return_val_if_fail (asc != NULL, NULL);
	g_return_val_if_fail (length > 0 && length <= NM_UTILS_HWADDR_LEN_MAX, NULL);

	ba = g_byte_array_sized_new (length);
	g_byte_array_set_size (ba, length);
	if (!nm_utils_hwaddr_aton (asc, ba->data, length)) {
		g_byte_array_unref (ba);
		return NULL;
	}

	return ba;
}

/**
 * nm_utils_hwaddr_aton:
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
 */
guint8 *
nm_utils_hwaddr_aton (const char *asc, gpointer buffer, gsize length)
{
	const char *in = asc;
	guint8 *out = (guint8 *)buffer;
	char delimiter = '\0';

	g_return_val_if_fail (asc != NULL, NULL);
	g_return_val_if_fail (buffer != NULL, NULL);
	g_return_val_if_fail (length > 0 && length <= NM_UTILS_HWADDR_LEN_MAX, NULL);

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
 * nm_utils_hwaddr_ntoa:
 * @addr: (type guint8) (array length=length): a binary hardware address
 * @length: the length of @addr
 *
 * Converts @addr to textual form.
 *
 * Return value: (transfer full): the textual form of @addr
 */
char *
nm_utils_hwaddr_ntoa (gconstpointer addr, gsize length)
{
	const guint8 *in = addr;
	char *out, *result;
	const char *LOOKUP = "0123456789ABCDEF";

	g_return_val_if_fail (addr != NULL, g_strdup (""));
	g_return_val_if_fail (length > 0 && length <= NM_UTILS_HWADDR_LEN_MAX, g_strdup (""));

	result = out = g_malloc (length * 3);
	while (length--) {
		guint8 v = *in++;

		*out++ = LOOKUP[v >> 4];
		*out++ = LOOKUP[v & 0x0F];
		if (length)
			*out++ = ':';
	}

	*out = 0;
	return result;
}

static int
hwaddr_binary_len (const char *asc)
{
	int octets = 1;

	if (!*asc)
		return 0;

	for (; *asc; asc++) {
		if (*asc == ':' || *asc == '-')
			octets++;
	}
	return octets;
}

/**
 * nm_utils_hwaddr_valid:
 * @asc: the ASCII representation of a hardware address
 * @length: the length of address that @asc is expected to convert to
 *   (or -1 to accept any length up to %NM_UTILS_HWADDR_LEN_MAX)
 *
 * Parses @asc to see if it is a valid hardware address of the given
 * length.
 *
 * Return value: %TRUE if @asc appears to be a valid hardware address
 *   of the indicated length, %FALSE if not.
 */
gboolean
nm_utils_hwaddr_valid (const char *asc, gssize length)
{
	guint8 buf[NM_UTILS_HWADDR_LEN_MAX];

	g_return_val_if_fail (asc != NULL, FALSE);
	g_return_val_if_fail (length == -1 || (length > 0 && length <= NM_UTILS_HWADDR_LEN_MAX), FALSE);

	if (length == -1) {
		length = hwaddr_binary_len (asc);
		if (length == 0 || length > NM_UTILS_HWADDR_LEN_MAX)
			return FALSE;
	}

	return nm_utils_hwaddr_aton (asc, buf, length) != NULL;
}

/**
 * nm_utils_hwaddr_canonical:
 * @asc: the ASCII representation of a hardware address
 * @length: the length of address that @asc is expected to convert to
 *   (or -1 to accept any length up to %NM_UTILS_HWADDR_LEN_MAX)
 *
 * Parses @asc to see if it is a valid hardware address of the given
 * length, and if so, returns it in canonical form (uppercase, with
 * leading 0s as needed, and with colons rather than hyphens).
 *
 * Return value: (transfer full): the canonicalized address if @asc appears to
 *   be a valid hardware address of the indicated length, %NULL if not.
 */
char *
nm_utils_hwaddr_canonical (const char *asc, gssize length)
{
	guint8 buf[NM_UTILS_HWADDR_LEN_MAX];

	g_return_val_if_fail (asc != NULL, NULL);
	g_return_val_if_fail (length == -1 || (length > 0 && length <= NM_UTILS_HWADDR_LEN_MAX), NULL);

	if (length == -1) {
		length = hwaddr_binary_len (asc);
		if (length == 0 || length > NM_UTILS_HWADDR_LEN_MAX)
			return NULL;
	}

	if (nm_utils_hwaddr_aton (asc, buf, length) == NULL)
		return NULL;

	return nm_utils_hwaddr_ntoa (buf, length);
}

/* This is used to possibly canonicalize values passed to MAC address property
 * setters. Unlike nm_utils_hwaddr_canonical(), it accepts %NULL, and if you
 * pass it an invalid MAC address, it just returns that string rather than
 * returning %NULL (so that we can return a proper error from verify() later).
 */
char *
_nm_utils_hwaddr_canonical_or_invalid (const char *mac, gssize length)
{
	char *canonical;

	if (!mac)
		return NULL;

	canonical = nm_utils_hwaddr_canonical (mac, length);
	if (canonical)
		return canonical;
	else
		return g_strdup (mac);
}

/**
 * nm_utils_hwaddr_matches:
 * @hwaddr1: pointer to a binary or ASCII hardware address, or %NULL
 * @hwaddr1_len: size of @hwaddr1, or -1 if @hwaddr1 is ASCII
 * @hwaddr2: pointer to a binary or ASCII hardware address, or %NULL
 * @hwaddr2_len: size of @hwaddr2, or -1 if @hwaddr2 is ASCII
 *
 * Generalized hardware address comparison function. Tests if @hwaddr1 and
 * @hwaddr2 "equal" (or more precisely, "equivalent"), with several advantages
 * over a simple memcmp():
 *
 *   1. If @hwaddr1_len or @hwaddr2_len is -1, then the corresponding address is
 *      assumed to be ASCII rather than binary, and will be converted to binary
 *      before being compared.
 *
 *   2. If @hwaddr1 or @hwaddr2 is %NULL, it is treated instead as though it was
 *      a zero-filled buffer @hwaddr1_len or @hwaddr2_len bytes long.
 *
 *   3. If @hwaddr1 and @hwaddr2 are InfiniBand hardware addresses (that is, if
 *      they are <literal>INFINIBAND_ALEN</literal> bytes long in binary form)
 *      then only the last 8 bytes are compared, since those are the only bytes
 *      that actually identify the hardware. (The other 12 bytes will change
 *      depending on the configuration of the InfiniBand fabric that the device
 *      is connected to.)
 *
 * If a passed-in ASCII hardware address cannot be parsed, or would parse to an
 * address larger than %NM_UTILS_HWADDR_LEN_MAX, then it will silently fail to
 * match. (This means that externally-provided address strings do not need to be
 * sanity-checked before comparing them against known good addresses; they are
 * guaranteed to not match if they are invalid.)
 *
 * Return value: %TRUE if @hwaddr1 and @hwaddr2 are equivalent, %FALSE if they are
 *   different (or either of them is invalid).
 */
gboolean
nm_utils_hwaddr_matches (gconstpointer hwaddr1,
                         gssize        hwaddr1_len,
                         gconstpointer hwaddr2,
                         gssize        hwaddr2_len)
{
	guint8 buf1[NM_UTILS_HWADDR_LEN_MAX], buf2[NM_UTILS_HWADDR_LEN_MAX];

	if (hwaddr1_len == -1) {
		g_return_val_if_fail (hwaddr1 != NULL, FALSE);

		hwaddr1_len = hwaddr_binary_len (hwaddr1);
		if (hwaddr1_len == 0 || hwaddr1_len > NM_UTILS_HWADDR_LEN_MAX)
			return FALSE;
		if (!nm_utils_hwaddr_aton (hwaddr1, buf1, hwaddr1_len))
			return FALSE;

		hwaddr1 = buf1;
	} else {
		g_return_val_if_fail (hwaddr1_len > 0 && hwaddr1_len <= NM_UTILS_HWADDR_LEN_MAX, FALSE);

		if (!hwaddr1) {
			memset (buf1, 0, hwaddr1_len);
			hwaddr1 = buf1;
		}
	}

	if (hwaddr2_len == -1) {
		g_return_val_if_fail (hwaddr2 != NULL, FALSE);

		if (!nm_utils_hwaddr_aton (hwaddr2, buf2, hwaddr1_len))
			return FALSE;

		hwaddr2 = buf2;
		hwaddr2_len = hwaddr1_len;
	} else {
		g_return_val_if_fail (hwaddr2_len > 0 && hwaddr2_len <= NM_UTILS_HWADDR_LEN_MAX, FALSE);

		if (!hwaddr2) {
			memset (buf2, 0, hwaddr2_len);
			hwaddr2 = buf2;
		}
	}

	if (hwaddr1_len != hwaddr2_len)
		return FALSE;

	if (hwaddr1_len == INFINIBAND_ALEN) {
		hwaddr1 = (guint8 *)hwaddr1 + INFINIBAND_ALEN - 8;
		hwaddr2 = (guint8 *)hwaddr2 + INFINIBAND_ALEN - 8;
		hwaddr1_len = hwaddr2_len = 8;
	}

	return !memcmp (hwaddr1, hwaddr2, hwaddr1_len);
}

GVariant *
_nm_utils_hwaddr_to_dbus (const GValue *prop_value)
{
	const char *str = g_value_get_string (prop_value);
	guint8 buf[NM_UTILS_HWADDR_LEN_MAX];
	int len;

	if (str) {
		len = hwaddr_binary_len (str);
		g_return_val_if_fail (len > 0 && len <= NM_UTILS_HWADDR_LEN_MAX, NULL);
		if (!nm_utils_hwaddr_aton (str, buf, len))
			len = 0;
	} else
		len = 0;

	return g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, buf, len, 1);
}

void
_nm_utils_hwaddr_from_dbus (GVariant *dbus_value,
                            GValue *prop_value)
{
	gsize length = 0;
	const guint8 *array = g_variant_get_fixed_array (dbus_value, &length, 1);
	char *str;

	str = length ? nm_utils_hwaddr_ntoa (array, length) : NULL;
	g_value_take_string (prop_value, str);
}

/**
 * nm_utils_bin2hexstr:
 * @src: (type guint8) (array length=len): an array of bytes
 * @len: the length of the @src array
 * @final_len: an index where to cut off the returned string, or -1
 *
 * Converts the byte array @src into a hexadecimal string. If @final_len is
 * greater than -1, the returned string is terminated at that index
 * (returned_string[final_len] == '\0'),
 *
 * Return value: (transfer full): the textual form of @bytes
 */
/*
 * Code originally by Alex Larsson <alexl@redhat.com> and
 *  copyright Red Hat, Inc. under terms of the LGPL.
 */
char *
nm_utils_bin2hexstr (gconstpointer src, gsize len, int final_len)
{
	static char hex_digits[] = "0123456789abcdef";
	const guint8 *bytes = src;
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

/**
 * nm_utils_hexstr2bin:
 * @hex: a string of hexadecimal characters with optional ':' separators
 *
 * Converts a hexadecimal string @hex into an array of bytes.  The optional
 * separator ':' may be used between single or pairs of hexadecimal characters,
 * eg "00:11" or "0:1".  Any "0x" at the beginning of @hex is ignored.  @hex
 * may not start or end with ':'.
 *
 * Return value: (transfer full): the converted bytes, or %NULL on error
 */
GBytes *
nm_utils_hexstr2bin (const char *hex)
{
	guint i = 0, x = 0;
	gs_free guint8 *c = NULL;
	int a, b;
	gboolean found_colon = FALSE;

	g_return_val_if_fail (hex != NULL, NULL);

	if (strncasecmp (hex, "0x", 2) == 0)
		hex += 2;
	found_colon = !!strchr (hex, ':');

	c = g_malloc (strlen (hex) / 2 + 1);
	for (;;) {
		a = g_ascii_xdigit_value (hex[i++]);
		if (a < 0)
			return NULL;

		if (hex[i] && hex[i] != ':') {
			b = g_ascii_xdigit_value (hex[i++]);
			if (b < 0)
				return NULL;
			c[x++] = ((guint) a << 4) | ((guint) b);
		} else
			c[x++] = (guint) a;

		if (!hex[i])
			break;
		if (hex[i] == ':') {
			if (!hex[i + 1]) {
				/* trailing ':' is invalid */
				return NULL;
			}
			i++;
		} else if (found_colon) {
			/* If colons exist, they must delimit 1 or 2 hex chars */
			return NULL;
		}
	}

	return g_bytes_new (c, x);
}

/**
 * nm_utils_iface_valid_name:
 * @name: Name of interface
 *
 * This function is a 1:1 copy of the kernel's interface validation
 * function in net/core/dev.c.
 *
 * Returns: %TRUE if interface name is valid, otherwise %FALSE is returned.
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
 **/
const char *
nm_utils_inet6_ntop (const struct in6_addr *in6addr, char *dst)
{
	g_return_val_if_fail (in6addr, NULL);
	return inet_ntop (AF_INET6, in6addr, dst ? dst : _nm_utils_inet_ntop_buffer,
	                  INET6_ADDRSTRLEN);
}

/**
 * nm_utils_ipaddr_valid:
 * @family: <literal>AF_INET</literal> or <literal>AF_INET6</literal>, or
 *   <literal>AF_UNSPEC</literal> to accept either
 * @ip: an IP address
 *
 * Checks if @ip contains a valid IP address of the given family.
 *
 * Return value: %TRUE or %FALSE
 */
gboolean
nm_utils_ipaddr_valid (int family, const char *ip)
{
	guint8 buf[sizeof (struct in6_addr)];

	g_return_val_if_fail (family == AF_INET || family == AF_INET6 || family == AF_UNSPEC, FALSE);

	if (!ip)
		return FALSE;

	if (family == AF_UNSPEC)
		family = strchr (ip, ':') ? AF_INET6 : AF_INET;

	return inet_pton (family, ip, buf) == 1;
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

typedef struct {
	const char *str;
	const char *num;
} BondMode;

static BondMode bond_mode_table[] = {
	[0] = { "balance-rr",    "0" },
	[1] = { "active-backup", "1" },
	[2] = { "balance-xor",   "2" },
	[3] = { "broadcast",     "3" },
	[4] = { "802.3ad",       "4" },
	[5] = { "balance-tlb",   "5" },
	[6] = { "balance-alb",   "6" },
};

/**
 * nm_utils_bond_mode_int_to_string:
 * @mode: bonding mode as a numeric value
 *
 * Convert bonding mode from integer value to descriptive name.
 * See https://www.kernel.org/doc/Documentation/networking/bonding.txt for
 * available modes.
 *
 * Returns: bonding mode string, or NULL on error
 *
 * Since: 1.2
 */
const char *
nm_utils_bond_mode_int_to_string (int mode)
{
	if (mode >= 0 && mode < G_N_ELEMENTS (bond_mode_table))
		return bond_mode_table[mode].str;
	return NULL;
}

/**
 * nm_utils_bond_mode_string_to_int:
 * @mode: bonding mode as string
 *
 * Convert bonding mode from string representation to numeric value.
 * See https://www.kernel.org/doc/Documentation/networking/bonding.txt for
 * available modes.
 * The @mode string can be either a descriptive name or a number (as string).
 *
 * Returns: numeric bond mode, or -1 on error
 *
 * Since: 1.2
 */
int
nm_utils_bond_mode_string_to_int (const char *mode)
{
	int i;

	if (!mode || !*mode)
		return -1;

	for (i = 0; i < G_N_ELEMENTS (bond_mode_table); i++) {
		if (   strcmp (mode, bond_mode_table[i].str) == 0
		    || strcmp (mode, bond_mode_table[i].num) == 0)
			return i;
	}
	return -1;
}

/**********************************************************************************************/

/* _nm_utils_ascii_str_to_int64:
 *
 * A wrapper for g_ascii_strtoll, that checks whether the whole string
 * can be successfully converted to a number and is within a given
 * range. On any error, @fallback will be returned and %errno will be set
 * to a non-zero value. On success, %errno will be set to zero, check %errno
 * for errors. Any trailing or leading (ascii) white space is ignored and the
 * functions is locale independent.
 *
 * The function is guaranteed to return a value between @min and @max
 * (inclusive) or @fallback. Also, the parsing is rather strict, it does
 * not allow for any unrecognized characters, except leading and trailing
 * white space.
 **/
gint64
_nm_utils_ascii_str_to_int64 (const char *str, guint base, gint64 min, gint64 max, gint64 fallback)
{
	gint64 v;
	size_t len;
	char buf[64], *s, *str_free = NULL;

	if (str) {
		while (g_ascii_isspace (str[0]))
			str++;
	}
	if (!str || !str[0]) {
		errno = EINVAL;
		return fallback;
	}

	len = strlen (str);
	if (g_ascii_isspace (str[--len])) {
		/* backward search the first non-ws character.
		 * We already know that str[0] is non-ws. */
		while (g_ascii_isspace (str[--len]))
			;

		/* str[len] is now the last non-ws character... */
		len++;

		if (len >= sizeof (buf))
			s = str_free = g_malloc (len + 1);
		else
			s = buf;

		memcpy (s, str, len);
		s[len] = 0;

		nm_assert (len > 0 && len < strlen (str) && len == strlen (s));
		nm_assert (!g_ascii_isspace (str[len-1]) && g_ascii_isspace (str[len]));
		nm_assert (strncmp (str, s, len) == 0);

		str = s;
	}

	errno = 0;
	v = g_ascii_strtoll (str, &s, base);

	if (errno != 0)
		v = fallback;
	else if (s[0] != 0) {
		errno = EINVAL;
		v = fallback;
	} else if (v > max || v < min) {
		errno = ERANGE;
		v = fallback;
	}

	if (G_UNLIKELY (str_free))
		g_free (str_free);
	return v;
}

static gboolean
validate_dns_option (const char *name, gboolean numeric, gboolean ipv6,
                     const NMUtilsDNSOptionDesc *option_descs)
{
	const NMUtilsDNSOptionDesc *desc;

	if (!option_descs)
		return !!*name;

	for (desc = option_descs; desc->name; desc++) {
		if (!strcmp (name, desc->name) &&
		    numeric == desc->numeric &&
		    (!desc->ipv6_only || ipv6))
			return TRUE;
	}

	return FALSE;
}

/**
 * _nm_utils_dns_option_validate
 * @option: option string
 * @out_name: (out) (allow-none): the option name
 * @out_value: (out) (allow-none): the option value
 * @ipv6: whether the option refers to a IPv6 configuration
 * @option_descs: (allow-none): an array of NMUtilsDNSOptionDesc which describes the
 * valid options
 *
 * Parses a DNS option in the form "name" or "name:number" and, if
 * @option_descs is not NULL, checks that the option conforms to one
 * of the provided descriptors. If @option_descs is NULL @ipv6 is
 * not considered.
 *
 * Returns: %TRUE when the parsing was successful and the option is valid,
 * %FALSE otherwise
 */
gboolean
_nm_utils_dns_option_validate (const char *option, char **out_name,
                               long *out_value, gboolean ipv6,
                               const NMUtilsDNSOptionDesc *option_descs)
{
	char **tokens, *ptr;
	gboolean ret = FALSE;

	g_return_val_if_fail (option != NULL, FALSE);

	if (out_name)
		*out_name = NULL;
	if (out_value)
		*out_value = -1;

	if (!option[0])
		return FALSE;

	tokens = g_strsplit (option, ":", 2);

	if (g_strv_length (tokens) == 1) {
		ret = validate_dns_option (tokens[0], FALSE, ipv6, option_descs);
		if (ret && out_name)
			*out_name = g_strdup (tokens[0]);
		goto out;
	}

	if (!tokens[1][0]) {
		ret = FALSE;
		goto out;
	}

	for (ptr = tokens[1]; *ptr; ptr++) {
		if (!g_ascii_isdigit (*ptr)) {
			ret = FALSE;
			goto out;
		}
	}

	ret = FALSE;
	if (validate_dns_option (tokens[0], TRUE, ipv6, option_descs)) {
		int value = _nm_utils_ascii_str_to_int64 (tokens[1], 10, 0, G_MAXINT32, -1);
		if (value >= 0) {
			if (out_name)
				*out_name = g_strdup (tokens[0]);
			if (out_value)
				*out_value = value;
			ret = TRUE;
		}
	}
out:
	g_strfreev (tokens);
	return ret;
}

/**
 * _nm_utils_dns_option_find_idx
 * @array: an array of strings
 * @option: a dns option string
 *
 * Searches for an option in an array of strings. The match is
 * performed only the option name; the option value is ignored.
 *
 * Returns: the index of the option in the array or -1 if was not
 * found.
 */
int _nm_utils_dns_option_find_idx (GPtrArray *array, const char *option)
{
	gboolean ret;
	char *option_name, *tmp_name;
	int i;

	if (!_nm_utils_dns_option_validate (option, &option_name, NULL, FALSE, NULL))
		return -1;

	for (i = 0; i < array->len; i++) {
		if (_nm_utils_dns_option_validate (array->pdata[i], &tmp_name, NULL, FALSE, NULL)) {
			ret = strcmp (tmp_name, option_name);
			g_free (tmp_name);
			if (!ret) {
				g_free (option_name);
				return i;
			}
		}

	}

	g_free (option_name);
	return -1;
}

/**
 * nm_utils_enum_to_str
 * @type: the %GType of the enum
 * @value: the value to be translated
 *
 * Converts an enum value to its string representation. If the enum is a
 * %G_TYPE_FLAGS the function returns a comma-separated list of matching values.
 * If the enum is a %G_TYPE_ENUM and the given value is not valid the
 * function returns %NULL.
 *
 * Returns: a newly allocated string or %NULL
 *
 * Since: 1.2
 */
char *nm_utils_enum_to_str (GType type, int value)
{
	GTypeClass *class;
	char *ret;

	class = g_type_class_ref (type);

	if (G_IS_ENUM_CLASS (class)) {
		GEnumValue *enum_value;

		enum_value = g_enum_get_value (G_ENUM_CLASS (class), value);
		ret = enum_value ? strdup (enum_value->value_nick) : NULL;
	} else if (G_IS_FLAGS_CLASS (class)) {
		GFlagsValue *flags_value;
		GString *str = g_string_new ("");
		gboolean first = TRUE;

		while (value) {
			flags_value = g_flags_get_first_value (G_FLAGS_CLASS (class), value);
			if (!flags_value)
				break;

			if (!first)
				g_string_append_c (str, ',');
			g_string_append (str, flags_value->value_nick);

			value &= ~flags_value->value;
			first = FALSE;
		}
		ret = g_string_free (str, FALSE);
	} else
		g_return_val_if_reached (NULL);

	g_type_class_unref (class);
	return ret;
}

/**
 * nm_utils_enum_from_str
 * @type: the %GType of the enum
 * @str: the input string
 * @out_value: (out) (allow-none) the output value
 * @err_token: (out) (allow-none) location to store the first unrecognized token
 *
 * Converts a string to the matching enum value.
 *
 * If the enum is a %G_TYPE_FLAGS the function returns the logical OR of values
 * matching the comma-separated tokens in the string; if an unknown token is found
 * the function returns %FALSE and stores a pointer to a newly allocated string
 * containing the unrecognized token in @err_token.
 *
 * Returns: %TRUE if the conversion was successful, %FALSE otherwise
 *
 * Since: 1.2
 */
gboolean nm_utils_enum_from_str (GType type, const char *str,
                                 int *out_value, char **err_token)
{
	GTypeClass *class;
	gboolean ret = FALSE;
	int value = 0;

	g_return_val_if_fail (str, FALSE);
	class = g_type_class_ref (type);

	if (G_IS_ENUM_CLASS (class)) {
		GEnumValue *enum_value;

		enum_value = g_enum_get_value_by_nick (G_ENUM_CLASS (class), str);
		if (enum_value) {
			value = enum_value->value;
			ret = TRUE;
		}
	} else if (G_IS_FLAGS_CLASS (class)) {
		GFlagsValue *flags_value;
		gs_strfreev char **strv = NULL;
		int i;

		strv = g_strsplit (str, ",", 0);
		for (i = 0; strv[i]; i++) {
			if (!strv[i][0])
				continue;

			flags_value = g_flags_get_value_by_nick (G_FLAGS_CLASS (class), strv[i]);
			if (!flags_value)
				break;

			value |= flags_value->value;
		}

		if (strv[i]) {
			if (err_token)
				*err_token = strdup (strv[i]);
			value = 0;
		} else
			ret = TRUE;
	} else
		g_return_val_if_reached (FALSE);

	if (out_value)
		*out_value = value;

	g_type_class_unref (class);
	return ret;
}

