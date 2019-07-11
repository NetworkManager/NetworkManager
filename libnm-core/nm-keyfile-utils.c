/* NetworkManager system settings service
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2010 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-keyfile-utils.h"

#include <stdlib.h>

#include "nm-keyfile-internal.h"
#include "nm-setting-wired.h"
#include "nm-setting-wireless.h"
#include "nm-setting-wireless-security.h"

/*****************************************************************************/

/**
 * nm_key_file_get_boolean:
 * @kf: the #GKeyFile
 * @group: the group
 * @key: the key
 * @default_value: the default value if the value is set or not parsable as a boolean.
 *
 * Replacement for g_key_file_get_boolean() (which uses g_key_file_parse_value_as_boolean()).
 * g_key_file_get_boolean() seems odd to me, because it accepts trailing ASCII whitespace,
 * but not leading.
 * This uses _nm_utils_ascii_str_to_bool(), which accepts trailing and leading whitespace,
 * case-insensitive words, and also strings like "on" and "off".
 * _nm_utils_ascii_str_to_bool() is our way to parse booleans from string, and we should
 * use that one consistently.
 *
 * Also, it doesn't have g_key_file_get_boolean()'s odd API to require an error argument
 * to detect parsing failures.
 *
 * Returns: either %TRUE or %FALSE if the key exists and is parsable as a boolean.
 *   Otherwise, @default_value.
 */
int
nm_key_file_get_boolean (GKeyFile *kf, const char *group, const char *key, int default_value)
{
	gs_free char *value = NULL;

	value = g_key_file_get_value (kf, group, key, NULL);

	if (!value)
		return default_value;
	return _nm_utils_ascii_str_to_bool (value, default_value);
}

/*****************************************************************************/

typedef struct {
	const char *setting;
	const char *alias;
} SettingAlias;

static const SettingAlias alias_list[] = {
	{ NM_SETTING_WIRED_SETTING_NAME, "ethernet" },
	{ NM_SETTING_WIRELESS_SETTING_NAME, "wifi" },
	{ NM_SETTING_WIRELESS_SECURITY_SETTING_NAME, "wifi-security" },
};

const char *
nm_keyfile_plugin_get_alias_for_setting_name (const char *setting_name)
{
	guint i;

	g_return_val_if_fail (setting_name != NULL, NULL);

	for (i = 0; i < G_N_ELEMENTS (alias_list); i++) {
		if (nm_streq (setting_name, alias_list[i].setting))
			return alias_list[i].alias;
	}
	return NULL;
}

const char *
nm_keyfile_plugin_get_setting_name_for_alias (const char *alias)
{
	guint i;

	g_return_val_if_fail (alias != NULL, NULL);

	for (i = 0; i < G_N_ELEMENTS (alias_list); i++) {
		if (nm_streq (alias, alias_list[i].alias))
			return alias_list[i].setting;
	}
	return NULL;
}

/*****************************************************************************/

/* List helpers */
#define DEFINE_KF_LIST_WRAPPER(stype, get_ctype, set_ctype) \
get_ctype \
nm_keyfile_plugin_kf_get_##stype##_list (GKeyFile *kf, \
                                         const char *group, \
                                         const char *key, \
                                         gsize *out_length, \
                                         GError **error) \
{ \
	get_ctype list; \
	const char *alias; \
	GError *local = NULL; \
	gsize l; \
 \
	list = g_key_file_get_##stype##_list (kf, group, key, &l, &local); \
	if (g_error_matches (local, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_GROUP_NOT_FOUND)) { \
		alias = nm_keyfile_plugin_get_alias_for_setting_name (group); \
		if (alias) { \
			g_clear_error (&local); \
			list = g_key_file_get_##stype##_list (kf, alias, key, &l, &local); \
		} \
	} \
	nm_assert ((!local) != (!list)); \
	if (local) \
		g_propagate_error (error, local); \
	if (!list) \
		l = 0; \
	NM_SET_OUT (out_length, l); \
	return list; \
} \
 \
void \
nm_keyfile_plugin_kf_set_##stype##_list (GKeyFile *kf, \
                                         const char *group, \
                                         const char *key, \
                                         set_ctype list[], \
                                         gsize length) \
{ \
	const char *alias; \
 \
	alias = nm_keyfile_plugin_get_alias_for_setting_name (group); \
	g_key_file_set_##stype##_list (kf, alias ?: group, key, list, length); \
}

DEFINE_KF_LIST_WRAPPER(integer, int*, int);
DEFINE_KF_LIST_WRAPPER(string, char **, const char* const);

void
nm_keyfile_plugin_kf_set_integer_list_uint8 (GKeyFile *kf,
                                             const char *group,
                                             const char *key,
                                             const guint8 *data,
                                             gsize length)
{
	gsize i;
	gsize l = length * 4 + 2;
	gs_free char *value = g_malloc (l);
	char *s = value;

	g_return_if_fail (kf);
	g_return_if_fail (!length || data);
	g_return_if_fail (group && group[0]);
	g_return_if_fail (key && key[0]);

	value[0] = '\0';
	for (i = 0; i < length; i++)
		nm_utils_strbuf_append (&s, &l, "%d;", (int) data[i]);
	nm_assert (l > 0);
	nm_keyfile_plugin_kf_set_value (kf, group, key, value);
}

/* Single value helpers */
#define DEFINE_KF_WRAPPER(stype, get_ctype, set_ctype) \
get_ctype \
nm_keyfile_plugin_kf_get_##stype (GKeyFile *kf, \
                                  const char *group, \
                                  const char *key, \
                                  GError **error) \
{ \
	get_ctype val; \
	const char *alias; \
	GError *local = NULL; \
 \
	val = g_key_file_get_##stype (kf, group, key, &local); \
	if (g_error_matches (local, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_GROUP_NOT_FOUND)) { \
		alias = nm_keyfile_plugin_get_alias_for_setting_name (group); \
		if (alias) { \
			g_clear_error (&local); \
			val = g_key_file_get_##stype (kf, alias, key, &local); \
		} \
	} \
	if (local) \
		g_propagate_error (error, local); \
	return val; \
} \
 \
void \
nm_keyfile_plugin_kf_set_##stype (GKeyFile *kf, \
                                  const char *group, \
                                  const char *key, \
                                  set_ctype value) \
{ \
	const char *alias; \
 \
	alias = nm_keyfile_plugin_get_alias_for_setting_name (group); \
	g_key_file_set_##stype (kf, alias ?: group, key, value); \
}

DEFINE_KF_WRAPPER(string, char*, const char*);
DEFINE_KF_WRAPPER(boolean, gboolean, gboolean);
DEFINE_KF_WRAPPER(value, char*, const char*);

gint64
nm_keyfile_plugin_kf_get_int64 (GKeyFile *kf,
                                const char *group,
                                const char *key,
                                guint base,
                                gint64 min,
                                gint64 max,
                                gint64 fallback,
                                GError **error)
{
	gs_free char *s = NULL;
	int errsv;
	gint64 v;

	s = nm_keyfile_plugin_kf_get_value (kf, group, key, error);
	if (!s) {
		errno = ENODATA;
		return fallback;
	}

	v = _nm_utils_ascii_str_to_int64 (s, base, min, max, fallback);
	errsv = errno;
	if (   errsv != 0
	    && error) {
		g_set_error (error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_INVALID_VALUE,
		             _("value is not an integer in range [%lld, %lld]"),
		             (long long) min, (long long) max);
		errno = errsv;
	}
	return v;
}

char **
nm_keyfile_plugin_kf_get_keys (GKeyFile *kf,
                               const char *group,
                               gsize *out_length,
                               GError **error)
{
	char **keys;
	const char *alias;
	GError *local = NULL;
	gsize l;

	keys = g_key_file_get_keys (kf, group, &l, &local);
	if (g_error_matches (local, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_GROUP_NOT_FOUND)) {
		alias = nm_keyfile_plugin_get_alias_for_setting_name (group);
		if (alias) {
			g_clear_error (&local);
			keys = g_key_file_get_keys (kf, alias, &l, error ? &local : NULL);
		}
	}
	nm_assert ((!local) != (!keys));
	if (!keys)
		l = 0;
	nm_assert (l == NM_PTRARRAY_LEN (keys));
	NM_SET_OUT (out_length, l);
	if (local)
		g_propagate_error (error, local);
	return keys;
}

gboolean
nm_keyfile_plugin_kf_has_key (GKeyFile *kf,
                              const char *group,
                              const char *key,
                              GError **error)
{
	gboolean has;
	const char *alias;
	GError *local = NULL;

	has = g_key_file_has_key (kf, group, key, &local);
	if (g_error_matches (local, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_GROUP_NOT_FOUND)) {
		alias = nm_keyfile_plugin_get_alias_for_setting_name (group);
		if (alias) {
			g_clear_error (&local);
			has = g_key_file_has_key (kf, alias, key, &local);
		}
	}
	if (local)
		g_propagate_error (error, local);
	return has;
}

/*****************************************************************************/

void
_nm_keyfile_copy (GKeyFile *dst, GKeyFile *src)
{
	gs_strfreev char **groups = NULL;
	guint g, k;

	groups = g_key_file_get_groups (src, NULL);
	for (g = 0; groups && groups[g]; g++) {
		const char *group = groups[g];
		gs_strfreev char **keys = NULL;

		keys = g_key_file_get_keys (src, group, NULL, NULL);
		if (!keys)
			continue;

		for (k = 0; keys[k]; k++) {
			const char *key = keys[k];
			gs_free char *value = NULL;

			value = g_key_file_get_value (src, group, key, NULL);
			if (value)
				g_key_file_set_value (dst, group, key, value);
			else
				g_key_file_remove_key (dst, group, key, NULL);
		}
	}
}

/*****************************************************************************/

gboolean
_nm_keyfile_a_contains_all_in_b (GKeyFile *kf_a, GKeyFile *kf_b)
{
	gs_strfreev char **groups = NULL;
	guint i, j;

	if (kf_a == kf_b)
		return TRUE;
	if (!kf_a || !kf_b)
		return FALSE;

	groups = g_key_file_get_groups (kf_a, NULL);
	for (i = 0; groups && groups[i]; i++) {
		gs_strfreev char **keys = NULL;

		keys = g_key_file_get_keys (kf_a, groups[i], NULL, NULL);
		if (!keys)
			continue;

		for (j = 0; keys[j]; j++) {
			gs_free char *key_a = g_key_file_get_value (kf_a, groups[i], keys[j], NULL);
			gs_free char *key_b = g_key_file_get_value (kf_b, groups[i], keys[j], NULL);

			if (g_strcmp0 (key_a, key_b) != 0)
				return FALSE;
		}
	}
	return TRUE;
}

static gboolean
_nm_keyfile_equals_ordered (GKeyFile *kf_a, GKeyFile *kf_b)
{
	gs_strfreev char **groups = NULL;
	gs_strfreev char **groups_b = NULL;
	guint i, j;

	if (kf_a == kf_b)
		return TRUE;
	if (!kf_a || !kf_b)
		return FALSE;

	groups = g_key_file_get_groups (kf_a, NULL);
	groups_b = g_key_file_get_groups (kf_b, NULL);
	if (!groups && !groups_b)
		return TRUE;
	if (!groups || !groups_b)
		return FALSE;
	for (i = 0; groups[i] && groups_b[i] && !strcmp (groups[i], groups_b[i]); i++)
		;
	if (groups[i] || groups_b[i])
		return FALSE;

	for (i = 0; groups[i]; i++) {
		gs_strfreev char **keys = NULL;
		gs_strfreev char **keys_b = NULL;

		keys = g_key_file_get_keys (kf_a, groups[i], NULL, NULL);
		keys_b = g_key_file_get_keys (kf_b, groups[i], NULL, NULL);

		if ((!keys) != (!keys_b))
			return FALSE;
		if (!keys)
			continue;

		for (j = 0; keys[j] && keys_b[j] && !strcmp (keys[j], keys_b[j]); j++)
			;
		if (keys[j] || keys_b[j])
			return FALSE;

		for (j = 0; keys[j]; j++) {
			gs_free char *key_a = g_key_file_get_value (kf_a, groups[i], keys[j], NULL);
			gs_free char *key_b = g_key_file_get_value (kf_b, groups[i], keys[j], NULL);

			if (g_strcmp0 (key_a, key_b) != 0)
				return FALSE;
		}
	}
	return TRUE;
}

gboolean
_nm_keyfile_equals (GKeyFile *kf_a, GKeyFile *kf_b, gboolean consider_order)
{
	if (!consider_order) {
		return    _nm_keyfile_a_contains_all_in_b (kf_a, kf_b)
		       && _nm_keyfile_a_contains_all_in_b (kf_b, kf_a);
	} else {
		return _nm_keyfile_equals_ordered (kf_a, kf_b);
	}
}

gboolean
_nm_keyfile_has_values (GKeyFile *keyfile)
{
	gs_strfreev char **groups = NULL;

	g_return_val_if_fail (keyfile, FALSE);

	groups = g_key_file_get_groups (keyfile, NULL);
	return groups && groups[0];
}

/*****************************************************************************/

static const char *
_keyfile_key_encode (const char *name,
                     char **out_to_free)
{
	gsize len, i;
	GString *str;

	nm_assert (name);
	nm_assert (out_to_free && !*out_to_free);

	/* See g_key_file_is_key_name().
	 *
	 * GKeyFile allows all UTF-8 characters (even non-well formed sequences),
	 * except:
	 *  - no empty keys
	 *  - no leading/trailing ' '
	 *  - no '=', '[', ']'
	 *
	 * We do something more strict here. All non-ASCII characters, all non-printable
	 * characters, and all invalid characters are escaped with "\\XX".
	 *
	 * We don't escape \\, unless it is followed by two hex digits.
	 */

	if (!name[0]) {
		/* empty keys are are backslash encoded. Note that usually
		 * \\00 is not a valid encode, the only exception is the empty
		 * word. */
		return "\\00";
	}

	/* find the first character that needs escaping. */
	i = 0;
	if (name[0] != ' ') {
		for (;; i++) {
			const guchar ch = (guchar) name[i];

			if (ch == '\0')
				return name;

			if (   ch < 0x20
			    || ch >= 127
			    || NM_IN_SET (ch, '=', '[', ']')
			    || (   ch == '\\'
			        && g_ascii_isxdigit (name[i + 1])
			        && g_ascii_isxdigit (name[i + 2]))
			    || (   ch == ' '
			        && name[i + 1] == '\0'))
				break;
		}
	} else if (name[1] == '\0')
		return "\\20";

	len = i + strlen (&name[i]);
	nm_assert (len == strlen (name));
	str = g_string_sized_new (len + 15);

	if (name[0] == ' ') {
		nm_assert (i == 0);
		g_string_append (str, "\\20");
		i = 1;
	} else
		g_string_append_len (str, name, i);

	for (;; i++) {
		const guchar ch = (guchar) name[i];

		if (ch == '\0')
			break;

		if (   ch < 0x20
		    || ch >= 127
		    || NM_IN_SET (ch, '=', '[', ']')
		    || (   ch == '\\'
		        && g_ascii_isxdigit (name[i + 1])
		        && g_ascii_isxdigit (name[i + 2]))
		    || (   ch == ' '
		        && name[i + 1] == '\0'))
			g_string_append_printf (str, "\\%02X", ch);
		else
			g_string_append_c (str, (char) ch);
	}

	return (*out_to_free = g_string_free (str, FALSE));
}

static const char *
_keyfile_key_decode (const char *key,
                     char **out_to_free)
{
	gsize i, len;
	GString *str;

	nm_assert (key);
	nm_assert (out_to_free && !*out_to_free);

	if (!key[0])
		return "";

	for (i = 0; TRUE; i++) {
		const char ch = key[i];

		if (ch == '\0')
			return key;
		if (   ch == '\\'
		    && g_ascii_isxdigit (key[i + 1])
		    && g_ascii_isxdigit (key[i + 2]))
			break;
	}

	len = i + strlen (&key[i]);

	if (   len == 3
	    && nm_streq (key, "\\00"))
		return "";

	nm_assert (len == strlen (key));
	str = g_string_sized_new (len + 3);

	g_string_append_len (str, key, i);
	for (;;) {
		const char ch = key[i];
		char ch1, ch2;
		unsigned v;

		if (ch == '\0')
			break;

		if (   ch == '\\'
		    && g_ascii_isxdigit ((ch1 = key[i + 1]))
		    && g_ascii_isxdigit ((ch2 = key[i + 2]))) {
			v = (g_ascii_xdigit_value (ch1) << 4) + g_ascii_xdigit_value (ch2);
			if (v != 0) {
				g_string_append_c (str, (char) v);
				i += 3;
				continue;
			}
		}
		g_string_append_c (str, ch);
		i++;
	}

	return (*out_to_free = g_string_free (str, FALSE));
}

/*****************************************************************************/

const char *
nm_keyfile_key_encode (const char *name,
                       char **out_to_free)
{
	const char *key;

	key = _keyfile_key_encode (name, out_to_free);
#if NM_MORE_ASSERTS > 5
	nm_assert (key);
	nm_assert (!*out_to_free || key == *out_to_free);
	nm_assert (!*out_to_free || !nm_streq0 (name, key));
	{
		gs_free char *to_free2 = NULL;
		const char *name2;

		name2 = _keyfile_key_decode (key, &to_free2);
		/* name2, the result of encode()+decode() is identical to name.
		 * That is because
		 *   - encode() is a injective function.
		 *   - decode() is a surjective function, however for output
		 *     values of encode() is behaves injective too. */
		nm_assert (nm_streq0 (name2, name));
	}
#endif
	return key;
}

const char *
nm_keyfile_key_decode (const char *key,
                       char **out_to_free)
{
	const char *name;

	name = _keyfile_key_decode (key, out_to_free);
#if NM_MORE_ASSERTS > 5
	nm_assert (name);
	nm_assert (!*out_to_free || name == *out_to_free);
	{
		gs_free char *to_free2 = NULL;
		const char *key2;

		key2 = _keyfile_key_encode (name, &to_free2);
		/* key2, the result of decode+encode may not be idential
		 * to the original key. That is, decode() is a surjective
		 * function mapping different keys to the same name.
		 * However, decode() behaves injective for input that
		 * are valid output of encode(). */
		nm_assert (key2);
	}
#endif
	return name;
}
