/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
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

#include "config.h"

#include <glib.h>
#include <stdlib.h>
#include <string.h>
#include "gsystem-local-alloc.h"
#include "utils.h"
#include <nm-setting-wired.h>
#include <nm-setting-wireless.h>
#include <nm-setting-wireless-security.h>


static const char temp_letters[] =
"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/*
 * Check '.[a-zA-Z0-9]{6}' file suffix used for temporary files by g_file_set_contents() (mkstemp()).
 */
static gboolean
check_mkstemp_suffix (const char *path)
{
	const char *ptr;

	g_return_val_if_fail (path != NULL, FALSE);

	/* Matches *.[a-zA-Z0-9]{6} suffix of mkstemp()'s temporary files */
	ptr = strrchr (path, '.');
	if (ptr && (strspn (ptr + 1, temp_letters) == 6) && (! ptr[7]))
		return TRUE;
	return FALSE;
}

static gboolean
check_prefix (const char *base, const char *tag)
{
	int len, tag_len;

	g_return_val_if_fail (base != NULL, TRUE);
	g_return_val_if_fail (tag != NULL, TRUE);

	len = strlen (base);
	tag_len = strlen (tag);
	if ((len > tag_len) && !g_ascii_strncasecmp (base, tag, tag_len))
		return TRUE;
	return FALSE;
}

static gboolean
check_suffix (const char *base, const char *tag)
{
	int len, tag_len;

	g_return_val_if_fail (base != NULL, TRUE);
	g_return_val_if_fail (tag != NULL, TRUE);

	len = strlen (base);
	tag_len = strlen (tag);
	if ((len > tag_len) && !g_ascii_strcasecmp (base + len - tag_len, tag))
		return TRUE;
	return FALSE;
}

#define SWP_TAG ".swp"
#define SWPX_TAG ".swpx"
#define PEM_TAG ".pem"
#define DER_TAG ".der"

gboolean
nm_keyfile_plugin_utils_should_ignore_file (const char *filename)
{
	gs_free char *base = NULL;

	g_return_val_if_fail (filename != NULL, TRUE);

	base = g_path_get_basename (filename);
	g_return_val_if_fail (base != NULL, TRUE);

	/* Ignore hidden and backup files */
	/* should_ignore_file() must mirror escape_filename() */
	if (check_prefix (base, ".") || check_suffix (base, "~"))
		return TRUE;
	/* Ignore temporary files */
	if (check_mkstemp_suffix (base))
		return TRUE;
	/* Ignore 802.1x certificates and keys */
	if (check_suffix (base, PEM_TAG) || check_suffix (base, DER_TAG))
		return TRUE;

	return FALSE;
}

char *
nm_keyfile_plugin_utils_escape_filename (const char *filename)
{
	GString *str;
	const char *f = filename;
	const char ESCAPE_CHAR = '*';

	/* keyfile used to escape with '*', do not change that behavior.
	 * But for newly added escapings, use '_' instead. */
	const char ESCAPE_CHAR2 = '_';

	g_return_val_if_fail (filename && filename[0], NULL);

	str = g_string_sized_new (60);

	/* Convert '/' to ESCAPE_CHAR */
	for (f = filename; f[0]; f++) {
		if (f[0] == '/')
			g_string_append_c (str, ESCAPE_CHAR);
		else
			g_string_append_c (str, f[0]);
	}

	/* escape_filename() must avoid anything that should_ignore_file() would reject.
	 * We can escape here more aggressivly then what we would read back. */
	if (check_prefix (str->str, "."))
		str->str[0] = ESCAPE_CHAR2;
	if (check_suffix (str->str, "~"))
		str->str[str->len - 1] = ESCAPE_CHAR2;
	if (   check_mkstemp_suffix (str->str)
	    || check_suffix (str->str, PEM_TAG)
	    || check_suffix (str->str, DER_TAG))
		g_string_append_c (str, ESCAPE_CHAR2);

	return g_string_free (str, FALSE);;
}


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
		if (strcmp (setting_name, alias_list[i].setting) == 0)
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
		if (strcmp (alias, alias_list[i].alias) == 0)
			return alias_list[i].setting;
	}
	return NULL;
}

/**********************************************************************/

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
 \
	list = g_key_file_get_##stype##_list (kf, group, key, out_length, &local); \
	if (g_error_matches (local, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_GROUP_NOT_FOUND)) { \
		alias = nm_keyfile_plugin_get_alias_for_setting_name (group); \
		if (alias) { \
			g_clear_error (&local); \
			list = g_key_file_get_##stype##_list (kf, alias, key, out_length, &local); \
		} \
	} \
	if (local) \
		g_propagate_error (error, local); \
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
	g_key_file_set_##stype##_list (kf, alias ? alias : group, key, list, length); \
}

DEFINE_KF_LIST_WRAPPER(integer, gint*, gint);
DEFINE_KF_LIST_WRAPPER(string, gchar **, const gchar* const);

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
	g_key_file_set_##stype (kf, alias ? alias : group, key, value); \
}

DEFINE_KF_WRAPPER(string, gchar*, const gchar*);
DEFINE_KF_WRAPPER(integer, gint, gint);
DEFINE_KF_WRAPPER(uint64, guint64, guint64);
DEFINE_KF_WRAPPER(boolean, gboolean, gboolean);
DEFINE_KF_WRAPPER(value, gchar*, const gchar*);


gchar **
nm_keyfile_plugin_kf_get_keys (GKeyFile *kf,
                               const char *group,
                               gsize *out_length,
                               GError **error)
{
	gchar **keys;
	const char *alias;
	GError *local = NULL;

	keys = g_key_file_get_keys (kf, group, out_length, &local);
	if (g_error_matches (local, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_GROUP_NOT_FOUND)) {
		alias = nm_keyfile_plugin_get_alias_for_setting_name (group);
		if (alias) {
			g_clear_error (&local);
			keys = g_key_file_get_keys (kf, alias, out_length, &local);
		}
	}
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


