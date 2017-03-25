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

#include "nm-setting-metadata.h"

#include "nmcli.h"
#include "utils.h"

/*****************************************************************************/

typedef enum {
	NMC_PROPERTY_GET_PRETTY,
	NMC_PROPERTY_GET_PARSABLE,
} NmcPropertyGetType;

typedef struct _NmcSettingInfo NmcSettingInfo;
typedef struct _NmcPropertyInfo NmcPropertyInfo;

struct _NmcPropertyInfo {
	const char *property_name;

	/* the property list for now must contain as first field the
	 * "name", which isn't a regular property. This is required by
	 * NmcOutputField and this first field is ignored for the
	 * group_list/setting_info. */
	bool is_name:1;

	char *(*get_fcn) (const NmcSettingInfo *setting_info,
	                  const NmcPropertyInfo *property_info,
	                  NMSetting *setting,
	                  NmcPropertyGetType get_type);
	union {
		const char *(*get_direct) (NMSetting *setting);
		char *(*get_nmc) (NMSetting *setting, NmcPropertyGetType get_type);
	} get_data;

	gboolean (*set_fcn) (const NmcSettingInfo *setting_info,
	                     const NmcPropertyInfo *property_info,
	                     NMSetting *setting,
	                     const char *value,
	                     GError **error);
	union {
		gboolean (*set_nmc) (NMSetting *setting, const char *property_name, const char *value, GError **error);
	} set_data;

	gboolean (*remove_fcn) (const NmcSettingInfo *setting_info,
	                        const NmcPropertyInfo *property_info,
	                        NMSetting *setting,
	                        const char *option,
	                        guint32 idx,
	                        GError **error);
	union {
		gboolean (*remove_nmc) (NMSetting *setting, const char *property_name, const char *option, guint32 idx, GError **error);
	} remove_data;
};

struct _NmcSettingInfo {
	const NMMetaSettingInfo *general;
	gboolean (*get_setting_details) (const NmcSettingInfo *setting_info,
	                                 NMSetting *setting,
	                                 NmCli *nmc,
	                                 const char *one_prop,
	                                 gboolean secrets);
	const NmcPropertyInfo *properties;
	guint properties_num;
	const char *all_properties;
};

extern const NmcSettingInfo nmc_setting_infos[_NM_META_SETTING_TYPE_NUM];

/*****************************************************************************/

void nmc_properties_init (void);
void nmc_properties_cleanup (void);

NMSetting *nmc_setting_new_for_name (const char *name);
void nmc_setting_custom_init (NMSetting *setting);
void nmc_setting_ip4_connect_handlers (NMSettingIPConfig *setting);
void nmc_setting_ip6_connect_handlers (NMSettingIPConfig *setting);
void nmc_setting_proxy_connect_handlers (NMSettingProxy *setting);
void nmc_setting_wireless_connect_handlers (NMSettingWireless *setting);
void nmc_setting_connection_connect_handlers (NMSettingConnection *setting, NMConnection *connection);

char      **nmc_setting_get_valid_properties (NMSetting *setting);
char       *nmc_setting_get_property_desc (NMSetting *setting, const char *prop);
const char **nmc_setting_get_property_allowed_values (NMSetting *setting, const char *prop);
char       *nmc_setting_get_property (NMSetting *setting,
                                      const char *prop,
                                      GError **error);
char       *nmc_setting_get_property_parsable (NMSetting *setting,
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

gboolean setting_details (NMSetting *setting, NmCli *nmc, const char *one_prop, gboolean secrets);

extern NmcOutputField nmc_fields_setting_wired[];
extern NmcOutputField nmc_fields_setting_8021X[];
extern NmcOutputField nmc_fields_setting_wireless[];
extern NmcOutputField nmc_fields_setting_wireless_security[];
extern NmcOutputField nmc_fields_setting_ip4_config[];
extern NmcOutputField nmc_fields_setting_ip6_config[];
extern NmcOutputField nmc_fields_setting_serial[];
extern NmcOutputField nmc_fields_setting_ppp[];
extern NmcOutputField nmc_fields_setting_pppoe[];
extern NmcOutputField nmc_fields_setting_adsl[];
extern NmcOutputField nmc_fields_setting_gsm[];
extern NmcOutputField nmc_fields_setting_cdma[];
extern NmcOutputField nmc_fields_setting_bluetooth[];
extern NmcOutputField nmc_fields_setting_olpc_mesh[];
extern NmcOutputField nmc_fields_setting_vpn[];
extern NmcOutputField nmc_fields_setting_wimax[];
extern NmcOutputField nmc_fields_setting_infiniband[];
extern NmcOutputField nmc_fields_setting_bond[];
extern NmcOutputField nmc_fields_setting_vlan[];
extern NmcOutputField nmc_fields_setting_bridge[];
extern NmcOutputField nmc_fields_setting_bridge_port[];
extern NmcOutputField nmc_fields_setting_team[];
extern NmcOutputField nmc_fields_setting_team_port[];
extern NmcOutputField nmc_fields_setting_dcb[];
extern NmcOutputField nmc_fields_setting_tun[];
extern NmcOutputField nmc_fields_setting_ip_tunnel[];
extern NmcOutputField nmc_fields_setting_macvlan[];
extern NmcOutputField nmc_fields_setting_macsec[];
extern NmcOutputField nmc_fields_setting_vxlan[];
extern NmcOutputField nmc_fields_setting_proxy[];
extern NmcOutputField nmc_fields_setting_dummy[];

#endif /* NMC_SETTINGS_H */
