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
 * Copyright 2011 Red Hat, Inc.
 */

#ifndef __NM_SETTING_PRIVATE_H__
#define __NM_SETTING_PRIVATE_H__

#include "nm-setting.h"
#include "nm-connection.h"
#include "nm-core-enum-types.h"

#include "nm-core-internal.h"

void _nm_register_setting_impl (const char *name,
                                GType type,
                                NMSettingPriority priority);

#define _nm_register_setting(name, priority) \
	G_STMT_START { \
		_nm_register_setting_impl ("" NM_SETTING_ ## name ## _SETTING_NAME "", g_define_type_id, priority); \
	} G_STMT_END

NMSettingPriority _nm_setting_get_base_type_priority (NMSetting *setting);
NMSettingPriority _nm_setting_type_get_base_type_priority (GType type);
gint _nm_setting_compare_priority (gconstpointer a, gconstpointer b);

typedef enum NMSettingUpdateSecretResult {
	NM_SETTING_UPDATE_SECRET_ERROR              = FALSE,
	NM_SETTING_UPDATE_SECRET_SUCCESS_MODIFIED   = TRUE,
	NM_SETTING_UPDATE_SECRET_SUCCESS_UNCHANGED  = 2,
} NMSettingUpdateSecretResult;

NMSettingUpdateSecretResult _nm_setting_update_secrets (NMSetting *setting,
                                                        GVariant *secrets,
                                                        GError **error);
gboolean _nm_setting_clear_secrets (NMSetting *setting);
gboolean _nm_setting_clear_secrets_with_flags (NMSetting *setting,
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

/* Ensure the setting's GType is registered at library load time */
#define NM_SETTING_REGISTER_TYPE(x) \
static void __attribute__((constructor)) register_setting (void) \
{ nm_g_type_init (); g_type_ensure (x); }

GVariant *_nm_setting_get_deprecated_virtual_interface_name (NMSetting *setting,
                                                             NMConnection *connection,
                                                             const char *property);

NMSettingVerifyResult _nm_setting_verify (NMSetting *setting,
                                          NMConnection *connection,
                                          GError **error);

gboolean _nm_setting_verify_secret_string (const char *str,
                                           const char *setting_name,
                                           const char *property,
                                           GError **error);

gboolean _nm_setting_slave_type_is_valid (const char *slave_type, const char **out_port_type);

GVariant   *_nm_setting_to_dbus       (NMSetting *setting,
                                       NMConnection *connection,
                                       NMConnectionSerializationFlags flags);

NMSetting  *_nm_setting_new_from_dbus (GType setting_type,
                                       GVariant *setting_dict,
                                       GVariant *connection_dict,
                                       NMSettingParseFlags parse_flags,
                                       GError **error);

typedef GVariant * (*NMSettingPropertyGetFunc)    (NMSetting     *setting,
                                                   const char    *property);
typedef GVariant * (*NMSettingPropertySynthFunc)  (NMSetting     *setting,
                                                   NMConnection  *connection,
                                                   const char    *property);
typedef gboolean   (*NMSettingPropertySetFunc)    (NMSetting     *setting,
                                                   GVariant      *connection_dict,
                                                   const char    *property,
                                                   GVariant      *value,
                                                   NMSettingParseFlags parse_flags,
                                                   GError       **error);
typedef gboolean   (*NMSettingPropertyNotSetFunc) (NMSetting     *setting,
                                                   GVariant      *connection_dict,
                                                   const char    *property,
                                                   NMSettingParseFlags parse_flags,
                                                   GError       **error);

void _nm_setting_class_add_dbus_only_property (NMSettingClass *setting_class,
                                               const char *property_name,
                                               const GVariantType *dbus_type,
                                               NMSettingPropertySynthFunc synth_func,
                                               NMSettingPropertySetFunc set_func);

void _nm_setting_class_override_property (NMSettingClass *setting_class,
                                          const char *property_name,
                                          const GVariantType *dbus_type,
                                          NMSettingPropertyGetFunc get_func,
                                          NMSettingPropertySetFunc set_func,
                                          NMSettingPropertyNotSetFunc not_set_func);

typedef GVariant * (*NMSettingPropertyTransformToFunc) (const GValue *from);
typedef void (*NMSettingPropertyTransformFromFunc) (GVariant *from, GValue *to);

void _nm_setting_class_transform_property (NMSettingClass *setting_class,
                                           const char *property_name,
                                           const GVariantType *dbus_type,
                                           NMSettingPropertyTransformToFunc to_dbus,
                                           NMSettingPropertyTransformFromFunc from_dbus);

gboolean _nm_setting_use_legacy_property (NMSetting *setting,
                                          GVariant *connection_dict,
                                          const char *legacy_property,
                                          const char *new_property);

GPtrArray  *_nm_setting_need_secrets (NMSetting *setting);

#endif  /* NM_SETTING_PRIVATE_H */
