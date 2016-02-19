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

#include "nm-default.h"

#include <stdlib.h>
#include <string.h>

#include "nm-keyfile-utils.h"
#include "nm-keyfile-internal.h"
#include "nm-setting-wired.h"
#include "nm-setting-wireless.h"
#include "nm-setting-wireless-security.h"

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

/************************************************************************/

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

/************************************************************************/

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
