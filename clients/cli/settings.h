// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2010 - 2014 Red Hat, Inc.
 */

#ifndef NMC_SETTINGS_H
#define NMC_SETTINGS_H

#include "nm-meta-setting.h"
#include "nm-meta-setting-desc.h"

#include "nmcli.h"

/*****************************************************************************/

void nmc_setting_ip4_connect_handlers (NMSettingIPConfig *setting);
void nmc_setting_ip6_connect_handlers (NMSettingIPConfig *setting);
void nmc_setting_proxy_connect_handlers (NMSettingProxy *setting);
void nmc_setting_wireless_connect_handlers (NMSettingWireless *setting);
void nmc_setting_connection_connect_handlers (NMSettingConnection *setting, NMConnection *connection);

char      **nmc_setting_get_valid_properties (NMSetting *setting);
char       *nmc_setting_get_property_desc (NMSetting *setting, const char *prop);
const char *const*nmc_setting_get_property_allowed_values (NMSetting *setting, const char *prop, char ***out_to_free);
char       *nmc_setting_get_property (NMSetting *setting,
                                      const char *prop,
                                      GError **error);
char       *nmc_setting_get_property_parsable (NMSetting *setting,
                                               const char *prop,
                                               GError **error);
gboolean    nmc_setting_set_property (NMClient *client,
                                      NMSetting *setting,
                                      const char *prop,
                                      NMMetaAccessorModifier modifier,
                                      const char *val,
                                      GError **error);

gboolean setting_details (const NmcConfig *nmc_config, NMSetting *setting, const char *one_prop);

#endif /* NMC_SETTINGS_H */
