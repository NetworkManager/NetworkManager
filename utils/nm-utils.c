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

#include <glib.h>
#include "nm-utils.h"

gchar *nm_dbus_escape_object_path (const gchar *utf8_string)
{
	const gchar *p;
	gchar *object_path;
	GString *string;

	g_return_val_if_fail (utf8_string != NULL, NULL);	
	g_return_val_if_fail (g_utf8_validate (utf8_string, -1, NULL), NULL);

	string = g_string_sized_new ((strlen (utf8_string) + 1) * 6);

	for (p = utf8_string; *p != '\0'; p = g_utf8_next_char (p))
	{
		gunichar character;

		character = g_utf8_get_char (p);

		if (((character >= ((gunichar) 'a')) && 
		     (character <= ((gunichar) 'z'))) ||
		    ((character >= ((gunichar) 'A')) && 
		     (character <= ((gunichar) 'Z'))) ||
		    ((character >= ((gunichar) '0')) && 
		     (character <= ((gunichar) '9'))) ||
		     (character == ((gunichar) '/')))
		{
			g_string_append_c (string, (gchar) character);
			continue;
		}

		g_string_append_printf (string, "_%x_", character);
	}

	object_path = string->str;

	g_string_free (string, FALSE);

	return object_path;
}

gchar *nm_dbus_unescape_object_path (const gchar *object_path)
{
	const gchar *p;
	gchar *utf8_string;
	GString *string;

	g_return_val_if_fail (object_path != NULL, NULL);	

	string = g_string_sized_new (strlen (object_path) + 1);

	for (p = object_path; *p != '\0'; p++)
	{
		const gchar *q;
		gchar *hex_digits, *end, utf8_character[6] = { '\0' };
		gint utf8_character_size;
		gunichar character;
		gulong hex_value;

		if (*p != '_')
		{
		    g_string_append_c (string, *p);
		    continue;
		}

		q = strchr (p + 1, '_'); 

		if ((q == NULL) || (q == p + 1))
		{
		    g_string_free (string, TRUE);
		    return NULL;
		}

		hex_digits = g_strndup (p + 1, (q - 1) - p);

		hex_value = strtoul (hex_digits, &end, 16);

		character = (gunichar) hex_value;

		if (((hex_value == G_MAXLONG) && (errno == ERANGE)) ||
		    (hex_value > G_MAXUINT32) ||
		    (*end != '\0') ||
		    (!g_unichar_validate (character)))
		{
		    g_free (hex_digits);
		    g_string_free (string, TRUE);
		    return NULL;
		}

		utf8_character_size = 
			g_unichar_to_utf8 (character, utf8_character);

		g_assert (utf8_character_size > 0);

		g_string_append_len (string, utf8_character,
				     utf8_character_size);

		p = q;
	}

	utf8_string = string->str;

	g_string_free (string, FALSE);

	return utf8_string;
}

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
nm_utils_essid_to_utf8 (const char *orig_essid)
{
	char *new_essid = NULL;

	g_return_val_if_fail (orig_essid != NULL, NULL);

	if (g_utf8_validate (orig_essid, -1, NULL)) 
		new_essid = g_strdup (orig_essid);
	else
	{
		char * lang;
		char *e1 = NULL, *e2 = NULL, *e3 = NULL;

		/* Even if the local encoding is UTF-8, LANG may give
		 * us a clue as to what encoding ESSIDs are more likely to be in.
		 */
		g_get_charset ((const char **)(&e1));
		if ((lang = getenv ("LANG")))
		{
			char * dot;

			lang = g_ascii_strdown (lang, -1);
			if ((dot = strchr (lang, '.')))
				*dot = '\0';

			get_encodings_for_lang (lang, &e1, &e2, &e3);
			g_free (lang);
		}

		new_essid = g_convert (orig_essid, -1, "UTF-8", e1, NULL, NULL, NULL);
		if (!new_essid && e2)
		{
			new_essid = g_convert (orig_essid, -1, "UTF-8", e2,
		                NULL, NULL, NULL);
		}
		if (!new_essid && e3)
		{
			new_essid = g_convert (orig_essid, -1, "UTF-8", e3,
		                NULL, NULL, NULL);
		}

		if (!new_essid)
		{
			new_essid = g_convert_with_fallback (orig_essid, -1, "UTF-8", e1,
		                "?", NULL, NULL, NULL);
		}
	}

	return new_essid;
}
