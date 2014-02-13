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
 * (C) Copyright 2010 - 2013 Red Hat, Inc.
 */

#ifndef NMC_SETTINGS_H
#define NMC_SETTINGS_H

#include <nm-setting-connection.h>
#include <nm-setting-wired.h>
#include <nm-setting-adsl.h>
#include <nm-setting-8021x.h>
#include <nm-setting-wireless.h>
#include <nm-setting-wireless-security.h>
#include <nm-setting-ip4-config.h>
#include <nm-setting-ip6-config.h>
#include <nm-setting-serial.h>
#include <nm-setting-ppp.h>
#include <nm-setting-pppoe.h>
#include <nm-setting-gsm.h>
#include <nm-setting-cdma.h>
#include <nm-setting-bluetooth.h>
#include <nm-setting-olpc-mesh.h>
#include <nm-setting-vpn.h>
#include <nm-setting-wimax.h>
#include <nm-setting-infiniband.h>
#include <nm-setting-bond.h>
#include <nm-setting-bridge.h>
#include <nm-setting-bridge-port.h>
#include <nm-setting-vlan.h>
#include <nm-setting-dcb.h>

#include "nmcli.h"
#include "utils.h"

/* --- Functions --- */

void nmc_properties_init (void);
void nmc_properties_cleanup (void);

NMSetting *nmc_setting_new_for_name (const char *name);
void nmc_setting_custom_init (NMSetting *setting);
void nmc_setting_ip4_connect_handlers (NMSettingIP4Config *setting);
void nmc_setting_ip6_connect_handlers (NMSettingIP6Config *setting);
void nmc_setting_wireless_connect_handlers (NMSettingWireless *setting);

char      **nmc_setting_get_valid_properties (NMSetting *setting);
char       *nmc_setting_get_property_desc (NMSetting *setting, const char *prop);
const char *nmc_setting_get_property_allowed_values (NMSetting *setting, const char *prop);
char       *nmc_setting_get_property (NMSetting *setting,
                                      const char *prop,
                                      GError **error);
char       *nmc_setting_get_property_out2in (NMSetting *setting,
                                             const char *prop,
                                             GError **error);
gboolean    nmc_setting_set_property (NMSetting *setting,
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

gboolean setting_details (NMSetting *ssetting, NmCli *nmc, const char *one_prop);

#endif /* NMC_SETTINGS_H */
