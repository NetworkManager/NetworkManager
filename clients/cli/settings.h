/* nmcli - command-line tool to control NetworkManager
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
 * Copyright 2010 - 2014 Red Hat, Inc.
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
                                      const char *val,
                                      GError **error);
gboolean    nmc_setting_reset_property (NMSetting *setting,
                                        const char *prop,
                                        GError **error);
gboolean    nmc_setting_remove_property_option (NMSetting *setting,
                                                const char *prop,
                                                const char *option,
                                                guint32 idx,
                                                GError **error);
void nmc_property_set_default_value (NMSetting *setting, const char *prop);

gboolean nmc_property_get_gvalue (NMSetting *setting, const char *prop, GValue *value);
gboolean nmc_property_set_gvalue (NMSetting *setting, const char *prop, GValue *value);

gboolean setting_details (const NmcConfig *nmc_config, NMSetting *setting, const char *one_prop);

#endif /* NMC_SETTINGS_H */
