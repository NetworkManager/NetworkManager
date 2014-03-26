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
 * (C) Copyright 2011 Red Hat, Inc.
 */

#ifndef NM_SETTING_PRIVATE_H
#define NM_SETTING_PRIVATE_H

#include "nm-setting.h"
#include "nm-glib-compat.h"

#define NM_SETTING_SECRET_FLAGS_ALL \
	(NM_SETTING_SECRET_FLAG_NONE | \
	 NM_SETTING_SECRET_FLAG_AGENT_OWNED | \
	 NM_SETTING_SECRET_FLAG_NOT_SAVED | \
	 NM_SETTING_SECRET_FLAG_NOT_REQUIRED)

void _nm_register_setting (const char *name,
                           const GType type,
                           const guint32 priority,
                           const GQuark error_quark);

/* Ensure, that name is a compile time constant string. Put the function name in parenthesis to suppress expansion. */
#define _nm_register_setting(name, type, priority, error_quark)    _nm_register_setting ((name ""), type, priority, error_quark)

gboolean _nm_setting_is_base_type (NMSetting *setting);
gboolean _nm_setting_type_is_base_type (GType type);
GType _nm_setting_lookup_setting_type (const char *name);
GType _nm_setting_lookup_setting_type_by_quark (GQuark error_quark);
gint _nm_setting_compare_priority (gconstpointer a, gconstpointer b);

typedef enum NMSettingUpdateSecretResult {
	NM_SETTING_UPDATE_SECRET_ERROR              = FALSE,
	NM_SETTING_UPDATE_SECRET_SUCCESS_MODIFIED   = TRUE,
	NM_SETTING_UPDATE_SECRET_SUCCESS_UNCHANGED  = 2,
} NMSettingUpdateSecretResult;

NMSettingUpdateSecretResult _nm_setting_update_secrets (NMSetting *setting,
                                                        GHashTable *secrets,
                                                        GError **error);
gboolean _nm_setting_clear_secrets (NMSetting *setting);
gboolean _nm_setting_clear_secrets_with_flags (NMSetting *setting,
                                               NMSettingClearSecretsWithFlagsFn func,
                                               gpointer user_data);


/* NM_SETTING_COMPARE_FLAG_INFERRABLE: check whether a device-generated
 * connection can be replaced by a already-defined connection. This flag only
 * takes into account properties marked with the %NM_SETTING_PARAM_INFERRABLE
 * flag.
 */
#define NM_SETTING_COMPARE_FLAG_INFERRABLE 0x80000000

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

/* Ensure the setting's GType is registered at library load time */
#define NM_SETTING_REGISTER_TYPE(x) \
static void __attribute__((constructor)) register_setting (void) \
{ g_type_init (); g_type_ensure (x); }

NMSetting *nm_setting_find_in_list (GSList *settings_list, const char *setting_name);

/* Private NMSettingIP4Config methods */
#include "nm-setting-ip4-config.h"
const char *nm_setting_ip4_config_get_address_label      (NMSettingIP4Config *setting, guint32 i);
gboolean    nm_setting_ip4_config_add_address_with_label (NMSettingIP4Config *setting, NMIP4Address *address, const char *label);

#endif  /* NM_SETTING_PRIVATE_H */

