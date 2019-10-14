// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2011 Red Hat, Inc.
 */

#ifndef __NM_SETTING_PRIVATE_H__
#define __NM_SETTING_PRIVATE_H__

#if !((NETWORKMANAGER_COMPILATION) & NM_NETWORKMANAGER_COMPILATION_WITH_LIBNM_CORE_PRIVATE)
#error Cannot use this header.
#endif

#include "nm-setting.h"
#include "nm-setting-bridge.h"
#include "nm-connection.h"
#include "nm-core-enum-types.h"

#include "nm-core-internal.h"

/*****************************************************************************/

NMSettingPriority _nm_setting_get_base_type_priority (NMSetting *setting);
NMSettingPriority _nm_setting_type_get_base_type_priority (GType type);
int _nm_setting_compare_priority (gconstpointer a, gconstpointer b);

/*****************************************************************************/

void _nm_setting_emit_property_changed (NMSetting *setting);

typedef enum NMSettingUpdateSecretResult {
	NM_SETTING_UPDATE_SECRET_ERROR              = FALSE,
	NM_SETTING_UPDATE_SECRET_SUCCESS_MODIFIED   = TRUE,
	NM_SETTING_UPDATE_SECRET_SUCCESS_UNCHANGED  = 2,
} NMSettingUpdateSecretResult;

NMSettingUpdateSecretResult _nm_setting_update_secrets (NMSetting *setting,
                                                        GVariant *secrets,
                                                        GError **error);
gboolean _nm_setting_clear_secrets (NMSetting *setting,
                                    NMSettingClearSecretsWithFlagsFn func,
                                    gpointer user_data);

/* The property of the #NMSetting should be considered during comparisons that
 * use the %NM_SETTING_COMPARE_FLAG_INFERRABLE flag. Properties that don't have
 * this flag, are ignored when doing an infrerrable comparison.  This flag should
 * be set on all properties that are read from the kernel or the system when a
 * connection is generated.  eg, IP addresses/routes can be read from the
 * kernel, but the 'autoconnect' property cannot, so
 * %NM_SETTING_IP4_CONFIG_ADDRESSES gets the INFERRABLE flag, but
 * %NM_SETTING_CONNECTION_AUTOCONNECT would not.
 *
 * This flag should not be used with properties where the default cannot be
 * read separately from the current value, like MTU or wired duplex mode.
 */
#define NM_SETTING_PARAM_INFERRABLE (1 << (4 + G_PARAM_USER_SHIFT))

/* This is a legacy property, which clients should not send to the daemon. */
#define NM_SETTING_PARAM_LEGACY (1 << (5 + G_PARAM_USER_SHIFT))

/* When a connection is active and gets modified, usually the change
 * to the settings-connection does not propagate automatically to the
 * applied-connection of the device. For certain properties like the
 * firewall zone and the metered property, this is different.
 *
 * Such fields can be ignored during nm_connection_compare() with the
 * NMSettingCompareFlag NM_SETTING_COMPARE_FLAG_IGNORE_REAPPLY_IMMEDIATELY.
 */
#define NM_SETTING_PARAM_REAPPLY_IMMEDIATELY (1 << (6 + G_PARAM_USER_SHIFT))

/* property_to_dbus() should ignore the property flags, and instead always calls to_dbus_fcn()
 */
#define NM_SETTING_PARAM_TO_DBUS_IGNORE_FLAGS (1 << (7 + G_PARAM_USER_SHIFT))

extern const NMSettInfoPropertType nm_sett_info_propert_type_deprecated_interface_name;
extern const NMSettInfoPropertType nm_sett_info_propert_type_deprecated_ignore_i;
extern const NMSettInfoPropertType nm_sett_info_propert_type_deprecated_ignore_u;

extern const NMSettInfoPropertType nm_sett_info_propert_type_plain_i;
extern const NMSettInfoPropertType nm_sett_info_propert_type_plain_u;

NMSettingVerifyResult _nm_setting_verify (NMSetting *setting,
                                          NMConnection *connection,
                                          GError **error);

gboolean _nm_setting_verify_secret_string (const char *str,
                                           const char *setting_name,
                                           const char *property,
                                           GError **error);

gboolean _nm_setting_aggregate (NMSetting *setting,
                                NMConnectionAggregateType type,
                                gpointer arg);

gboolean _nm_setting_slave_type_is_valid (const char *slave_type, const char **out_port_type);

GVariant   *_nm_setting_to_dbus       (NMSetting *setting,
                                       NMConnection *connection,
                                       NMConnectionSerializationFlags flags,
                                       const NMConnectionSerializationOptions *options);

NMSetting  *_nm_setting_new_from_dbus (GType setting_type,
                                       GVariant *setting_dict,
                                       GVariant *connection_dict,
                                       NMSettingParseFlags parse_flags,
                                       GError **error);

gboolean _nm_setting_property_is_regular_secret (NMSetting *setting,
                                                 const char *secret_name);
gboolean _nm_setting_property_is_regular_secret_flags (NMSetting *setting,
                                                       const char *secret_flags_name);

/*****************************************************************************/

static inline GArray *
_nm_sett_info_property_override_create_array (void)
{
	return g_array_new (FALSE, FALSE, sizeof (NMSettInfoProperty));
}

GArray *_nm_sett_info_property_override_create_array_ip_config (void);

void _nm_setting_class_commit_full (NMSettingClass *setting_class,
                                    NMMetaSettingType meta_type,
                                    const NMSettInfoSettDetail *detail,
                                    GArray *properties_override);

static inline void
_nm_setting_class_commit (NMSettingClass *setting_class,
                          NMMetaSettingType meta_type)
{
	_nm_setting_class_commit_full (setting_class, meta_type, NULL, NULL);
}

#define NM_SETT_INFO_SETT_GENDATA(...) \
	({ \
		static const NMSettInfoSettGendata _g = { \
			__VA_ARGS__ \
		}; \
		\
		&_g; \
	})

#define NM_SETT_INFO_SETT_DETAIL(...) \
	(&((const NMSettInfoSettDetail) { \
		__VA_ARGS__ \
	}))

#define NM_SETT_INFO_PROPERT_TYPE(...) \
	({ \
		static const NMSettInfoPropertType _g = { \
			__VA_ARGS__ \
		}; \
		\
		&_g; \
	})

#define NM_SETT_INFO_PROPERTY(...) \
	(&((const NMSettInfoProperty) { \
		__VA_ARGS__ \
	}))

gboolean _nm_properties_override_assert (const NMSettInfoProperty *prop_info);

static inline void
_nm_properties_override (GArray *properties_override,
                         const NMSettInfoProperty *prop_info)
{
	nm_assert (properties_override);
	nm_assert (_nm_properties_override_assert (prop_info));
	g_array_append_vals (properties_override, prop_info, 1);
}

#define _nm_properties_override_gobj(properties_override, p_param_spec, p_property_type) \
	_nm_properties_override ((properties_override), \
	                         NM_SETT_INFO_PROPERTY ( \
	                             .param_spec = (p_param_spec), \
	                             .property_type = (p_property_type), \
	                         ))

#define _nm_properties_override_dbus(properties_override, p_name, p_property_type) \
	_nm_properties_override ((properties_override), \
	                         NM_SETT_INFO_PROPERTY ( \
	                             .name = (""p_name""), \
	                             .property_type = (p_property_type), \
	                         ))

/*****************************************************************************/

gboolean _nm_setting_use_legacy_property (NMSetting *setting,
                                          GVariant *connection_dict,
                                          const char *legacy_property,
                                          const char *new_property);

GPtrArray  *_nm_setting_need_secrets (NMSetting *setting);

gboolean _nm_setting_should_compare_secret_property (NMSetting *setting,
                                                     NMSetting *other,
                                                     const char *secret_name,
                                                     NMSettingCompareFlags flags);

NMBridgeVlan *_nm_bridge_vlan_dup (const NMBridgeVlan *vlan);
NMBridgeVlan *_nm_bridge_vlan_dup_and_seal (const NMBridgeVlan *vlan);

/*****************************************************************************/

#endif  /* NM_SETTING_PRIVATE_H */
