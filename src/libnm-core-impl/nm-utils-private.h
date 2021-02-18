/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2005 - 2017 Red Hat, Inc.
 */

#ifndef __NM_UTILS_PRIVATE_H__
#define __NM_UTILS_PRIVATE_H__

#if !((NETWORKMANAGER_COMPILATION) &NM_NETWORKMANAGER_COMPILATION_WITH_LIBNM_CORE_PRIVATE)
    #error Cannot use this header.
#endif

#include "nm-setting-private.h"
#include "nm-setting-ip-config.h"

#define NM_VARIANT_ATTRIBUTE_SPEC_DEFINE(_name, _type, ...) \
    (&((const NMVariantAttributeSpec){.name = _name, .type = _type, __VA_ARGS__}))

gboolean _nm_utils_string_slist_validate(GSList *list, const char **valid_values);

gboolean _nm_utils_secret_flags_validate(NMSettingSecretFlags secret_flags,
                                         const char *         setting_name,
                                         const char *         property_name,
                                         NMSettingSecretFlags disallowed_flags,
                                         GError **            error);

gboolean _nm_utils_wps_method_validate(NMSettingWirelessSecurityWpsMethod wps_method,
                                       const char *                       setting_name,
                                       const char *                       property_name,
                                       gboolean                           wps_required,
                                       GError **                          error);

/* D-Bus transform funcs */

extern const NMSettInfoPropertType nm_sett_info_propert_type_strdict;

extern const NMSettInfoPropertType nm_sett_info_propert_type_mac_address;

extern const NMSettInfoPropertType nm_sett_info_propert_type_cloned_mac_address;

extern const NMSettInfoPropertType nm_sett_info_propert_type_assigned_mac_address;

extern const NMSettInfoPropertType nm_sett_info_propert_type_bridge_vlans;

void _nm_utils_strdict_from_dbus(GVariant *dbus_value, GValue *prop_value);

void _nm_utils_bytes_from_dbus(GVariant *dbus_value, GValue *prop_value);

char *_nm_utils_hwaddr_canonical_or_invalid(const char *mac, gssize length);

gboolean _nm_utils_hwaddr_link_local_valid(const char *mac);

gboolean _nm_sriov_vf_parse_vlans(NMSriovVF *vf, const char *str, GError **error);

gboolean _nm_utils_bridge_vlan_verify_list(GPtrArray * vlans,
                                           gboolean    check_normalizable,
                                           GError **   error,
                                           const char *setting,
                                           const char *property);

#endif
