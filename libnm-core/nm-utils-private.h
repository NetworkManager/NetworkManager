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
 * Copyright 2005 - 2017 Red Hat, Inc.
 */

#ifndef __NM_UTILS_PRIVATE_H__
#define __NM_UTILS_PRIVATE_H__

#if !((NETWORKMANAGER_COMPILATION) & NM_NETWORKMANAGER_COMPILATION_WITH_LIBNM_CORE_PRIVATE)
#error Cannot use this header.
#endif

#include "nm-setting-private.h"
#include "nm-setting-ip-config.h"

struct _NMVariantAttributeSpec {
	char *name;
	const GVariantType *type;
	bool v4:1;
	bool v6:1;
	bool no_value:1;
	bool consumes_rest:1;
	char str_type;
};

gboolean    _nm_utils_string_slist_validate (GSList *list,
                                             const char **valid_values);

gboolean _nm_utils_secret_flags_validate (NMSettingSecretFlags secret_flags,
                                          const char *setting_name,
                                          const char *property_name,
                                          NMSettingSecretFlags disallowed_flags,
                                          GError **error);

gboolean _nm_utils_wps_method_validate (NMSettingWirelessSecurityWpsMethod wps_method,
                                        const char *setting_name,
                                        const char *property_name,
                                        gboolean wps_required,
                                        GError **error);

/* D-Bus transform funcs */

GVariant   *_nm_utils_hwaddr_cloned_get (NMSetting     *setting,
                                         const char    *property);
gboolean    _nm_utils_hwaddr_cloned_set (NMSetting     *setting,
                                         GVariant      *connection_dict,
                                         const char    *property,
                                         GVariant      *value,
                                         NMSettingParseFlags parse_flags,
                                         GError       **error);
gboolean    _nm_utils_hwaddr_cloned_not_set (NMSetting *setting,
                                             GVariant      *connection_dict,
                                             const char    *property,
                                             NMSettingParseFlags parse_flags,
                                             GError       **error);
GVariant *  _nm_utils_hwaddr_cloned_data_synth (const NMSettInfoSetting *sett_info,
                                                guint property_idx,
                                                NMConnection *connection,
                                                NMSetting *setting,
                                                NMConnectionSerializationFlags flags);
gboolean    _nm_utils_hwaddr_cloned_data_set (NMSetting *setting,
                                              GVariant *connection_dict,
                                              const char *property,
                                              GVariant *value,
                                              NMSettingParseFlags parse_flags,
                                              GError **error);

GVariant *  _nm_utils_hwaddr_to_dbus   (const GValue *prop_value);
void        _nm_utils_hwaddr_from_dbus (GVariant *dbus_value,
                                        GValue *prop_value);

GVariant *  _nm_utils_strdict_to_dbus   (const GValue *prop_value);
void        _nm_utils_strdict_from_dbus (GVariant *dbus_value,
                                         GValue *prop_value);

void        _nm_utils_bytes_from_dbus   (GVariant *dbus_value,
                                         GValue *prop_value);

char *      _nm_utils_hwaddr_canonical_or_invalid (const char *mac, gssize length);

GPtrArray * _nm_utils_team_link_watchers_from_variant (GVariant *value);
GVariant *  _nm_utils_team_link_watchers_to_variant (GPtrArray *link_watchers);

void        _nm_utils_format_variant_attributes_full (GString *str,
                                                      const NMUtilsNamedValue *values,
                                                      guint num_values,
                                                      char attr_separator,
                                                      char key_value_separator);
gboolean    _nm_sriov_vf_parse_vlans (NMSriovVF *vf, const char *str, GError **error);

GVariant *  _nm_utils_bridge_vlans_to_dbus (NMSetting *setting, const char *property);
gboolean    _nm_utils_bridge_vlans_from_dbus (NMSetting *setting,
                                              GVariant *connection_dict,
                                              const char *property,
                                              GVariant *value,
                                              NMSettingParseFlags parse_flags,
                                              GError **error);
gboolean    _nm_utils_bridge_vlan_verify_list (GPtrArray *vlans,
                                               gboolean check_normalizable,
                                               GError **error,
                                               const char *setting,
                                               const char *property);

/* JSON to GValue conversion macros */

static inline void
_nm_auto_unset_and_free_gvalue (GValue **ptr)
{
	if (*ptr) {
		g_value_unset (*ptr);
		g_free (*ptr);
	}
}
#define nm_auto_unset_and_free_gvalue nm_auto(_nm_auto_unset_and_free_gvalue)

typedef struct {
	const char *key1;
	const char *key2;
	const char *key3;
	union {
		int default_int;
		gboolean default_bool;
		const char *default_str;
	};
} _NMUtilsTeamPropertyKeys;

static inline int
_nm_utils_json_extract_int (char *conf,
                            _NMUtilsTeamPropertyKeys key,
                            gboolean is_port)
{
	nm_auto_unset_and_free_gvalue GValue *t_value = NULL;

	t_value = _nm_utils_team_config_get (conf, key.key1, key.key2, key.key3, is_port);
	if (   !t_value
	    || !G_VALUE_HOLDS_INT (t_value))
		return key.default_int;
	return g_value_get_int (t_value);
}

static inline gboolean
_nm_utils_json_extract_boolean (char *conf,
                                _NMUtilsTeamPropertyKeys key,
                                gboolean is_port)
{
	nm_auto_unset_and_free_gvalue GValue *t_value = NULL;

	t_value = _nm_utils_team_config_get (conf, key.key1, key.key2, key.key3, is_port);
	if (   !t_value
	    || !G_VALUE_HOLDS_BOOLEAN (t_value))
		return key.default_bool;
	return g_value_get_boolean (t_value);
}

static inline char *
_nm_utils_json_extract_string (char *conf,
                               _NMUtilsTeamPropertyKeys key,
                               gboolean is_port)
{
	nm_auto_unset_and_free_gvalue GValue *t_value = NULL;

	t_value = _nm_utils_team_config_get (conf, key.key1, key.key2, key.key3, is_port);
	if (   !t_value
	    || !G_VALUE_HOLDS_STRING (t_value))
		return g_strdup (key.default_str);
	return g_value_dup_string (t_value);
}

static inline char **
_nm_utils_json_extract_strv (char *conf,
                             _NMUtilsTeamPropertyKeys key,
                             gboolean is_port)
{
	nm_auto_unset_and_free_gvalue GValue *t_value = NULL;

	t_value = _nm_utils_team_config_get (conf, key.key1, key.key2, key.key3, is_port);
	if (   !t_value
	    || !G_TYPE_CHECK_VALUE_TYPE (t_value, G_TYPE_STRV))
		return NULL;
	return    g_strdupv (g_value_get_boxed (t_value))
	       ?: g_new0 (char *, 1);
}

static inline GPtrArray *
_nm_utils_json_extract_ptr_array (char *conf,
                                  _NMUtilsTeamPropertyKeys key,
                                  gboolean is_port)
{
	nm_auto_unset_and_free_gvalue GValue *t_value = NULL;
	GPtrArray *data, *ret;
	guint i;

	ret = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_team_link_watcher_unref);

	t_value = _nm_utils_team_config_get (conf, key.key1, key.key2, key.key3, is_port);
	if (   !t_value
	    || !G_TYPE_CHECK_VALUE_TYPE (t_value, G_TYPE_PTR_ARRAY))
		return ret;

	data = g_value_get_boxed (t_value);
	if (!data)
		return ret;
	for (i = 0; i < data->len; i++)
		g_ptr_array_add (ret, nm_team_link_watcher_dup (data->pdata[i]));
	return ret;
}

static inline void
_nm_utils_json_append_gvalue (char **conf,
                              _NMUtilsTeamPropertyKeys key,
                              const GValue *val)
{
	_nm_utils_team_config_set (conf, key.key1, key.key2, key.key3, val);
}

#endif
