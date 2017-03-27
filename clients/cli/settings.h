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

typedef enum {
	NMC_PROPERTY_TYPE_MAC_MODE_DEFAULT,
	NMC_PROPERTY_TYPE_MAC_MODE_CLONED,
	NMC_PROPERTY_TYPE_MAC_MODE_INFINIBAND,
} NmcPropertyTypeMacMode;

typedef struct _NmcSettingInfo     NmcSettingInfo;
typedef struct _NmcPropertyInfo    NmcPropertyInfo;
typedef struct _NmcPropertyType    NmcPropertyType;
typedef struct _NmcPropertyTypData NmcPropertyTypData;

struct _NmcPropertyType {

	/* FIXME: the function should return an allocated string. */
	const char *(*describe_fcn) (const NmcSettingInfo *setting_info,
	                             const NmcPropertyInfo *property_info);

	char *(*get_fcn) (const NmcSettingInfo *setting_info,
	                  const NmcPropertyInfo *property_info,
	                  NMSetting *setting,
	                  NmcPropertyGetType get_type,
	                  gboolean show_secrets);
	gboolean (*set_fcn) (const NmcSettingInfo *setting_info,
	                     const NmcPropertyInfo *property_info,
	                     NMSetting *setting,
	                     const char *value,
	                     GError **error);
	gboolean (*remove_fcn) (const NmcSettingInfo *setting_info,
	                        const NmcPropertyInfo *property_info,
	                        NMSetting *setting,
	                        const char *option,
	                        guint32 idx,
	                        GError **error);

	/* FIXME: the function should return an allocated string. */
	const char *const*(*values_fcn) (const NmcSettingInfo *setting_info,
	                                 const NmcPropertyInfo *property_info);
};

struct _NmcPropertyTypData {
	union {
		struct {
			union {
				char *(*get_fcn) (NMSetting *setting, NmcPropertyGetType get_type);
				gboolean (*get_fcn_with_default) (NMSetting *setting);
			};
			gboolean (*set_fcn) (NMSetting *setting, const char *property_name, const char *value, GError **error);
			gboolean (*remove_fcn) (NMSetting *setting, const char *property_name, const char *option, guint32 idx, GError **error);
			union {
				union {
					struct {
						GType (*get_gtype) (void);
						bool has_minmax:1;
						int min;
						int max;
					} gobject_enum;
				} values_data;
				const char *const* (*values_fcn) (NMSetting *setting, const char *prop);
			};
		} nmc;
		struct {
			guint32 (*get_fcn) (NMSetting *setting);
		} mtu;
		struct {
			NmcPropertyTypeMacMode mode;
		} mac;
	};
	const char *const*values_static;
};

struct _NmcPropertyInfo {
	const char *property_name;

	/* the property list for now must contain as first field the
	 * "name", which isn't a regular property. This is required by
	 * NmcOutputField and this first field is ignored for the
	 * group_list/setting_info. */
	bool is_name:1;

	bool is_secret:1;

	const char *describe_message;

	const NmcPropertyType    *property_type;
	const NmcPropertyTypData *property_typ_data;
};

struct _NmcSettingInfo {
	const NMMetaSettingInfo *general;
	/* the order of the properties matter. The first *must* be the
	 * "name", and then the order is as they are listed by default. */
	const NmcPropertyInfo *properties;
	guint properties_num;
};

extern const NmcSettingInfo nmc_setting_infos[_NM_META_SETTING_TYPE_NUM];

/*****************************************************************************/

NMSetting *nmc_setting_new_for_name (const char *name);
void nmc_setting_custom_init (NMSetting *setting);
void nmc_setting_ip4_connect_handlers (NMSettingIPConfig *setting);
void nmc_setting_ip6_connect_handlers (NMSettingIPConfig *setting);
void nmc_setting_proxy_connect_handlers (NMSettingProxy *setting);
void nmc_setting_wireless_connect_handlers (NMSettingWireless *setting);
void nmc_setting_connection_connect_handlers (NMSettingConnection *setting, NMConnection *connection);

char      **nmc_setting_get_valid_properties (NMSetting *setting);
char       *nmc_setting_get_property_desc (NMSetting *setting, const char *prop);
const char *const*nmc_setting_get_property_allowed_values (NMSetting *setting, const char *prop);
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

#endif /* NMC_SETTINGS_H */
