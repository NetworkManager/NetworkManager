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

#define NM_VARIANT_ATTRIBUTE_SPEC_DEFINE(_name, _type, ...) \
	(&((const NMVariantAttributeSpec) { \
		.name          = _name, \
		.type          = _type, \
		__VA_ARGS__ \
	}))

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

GVariant *_nm_utils_hwaddr_cloned_get (const NMSettInfoSetting *sett_info,
                                       guint property_idx,
                                       NMConnection *connection,
                                       NMSetting *setting,
                                       NMConnectionSerializationFlags flags,
                                       const NMConnectionSerializationOptions *options);
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
                                                NMConnectionSerializationFlags flags,
                                                const NMConnectionSerializationOptions *options);
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

void        _nm_utils_format_variant_attributes_full (GString *str,
                                                      const NMUtilsNamedValue *values,
                                                      guint num_values,
                                                      char attr_separator,
                                                      char key_value_separator);
gboolean    _nm_sriov_vf_parse_vlans (NMSriovVF *vf, const char *str, GError **error);

GVariant *  _nm_utils_bridge_vlans_to_dbus (const NMSettInfoSetting *sett_info,
                                            guint property_idx,
                                            NMConnection *connection,
                                            NMSetting *setting,
                                            NMConnectionSerializationFlags flags,
                                            const NMConnectionSerializationOptions *options);

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

#endif
