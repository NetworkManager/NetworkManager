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
 * Copyright 2017 Red Hat, Inc.
 */

#ifndef __NM_SETTING_USER_H__
#define __NM_SETTING_USER_H__

#if !defined (__NETWORKMANAGER_H_INSIDE__) && !defined (NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-setting.h"

G_BEGIN_DECLS

#define NM_TYPE_SETTING_USER            (nm_setting_user_get_type ())
#define NM_SETTING_USER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_USER, NMSettingUser))
#define NM_SETTING_USER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_USER, NMSettingUserClass))
#define NM_IS_SETTING_USER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_USER))
#define NM_IS_SETTING_USER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SETTING_USER))
#define NM_SETTING_USER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_USER, NMSettingUserClass))

#define NM_SETTING_USER_SETTING_NAME    "user"

#define NM_SETTING_USER_DATA            "data"

typedef struct _NMSettingUserClass NMSettingUserClass;

NM_AVAILABLE_IN_1_8
GType nm_setting_user_get_type (void);

NM_AVAILABLE_IN_1_8
NMSetting * nm_setting_user_new                  (void);

NM_AVAILABLE_IN_1_8
const char *const*nm_setting_user_get_keys       (NMSettingUser *setting, guint *out_len);

NM_AVAILABLE_IN_1_8
const char *nm_setting_user_get_data             (NMSettingUser *setting, const char *key);
NM_AVAILABLE_IN_1_8
gboolean    nm_setting_user_set_data             (NMSettingUser *setting, const char *key, const char *val, GError **error);

NM_AVAILABLE_IN_1_8
gboolean    nm_setting_user_check_key (const char *key, GError **error);
NM_AVAILABLE_IN_1_8
gboolean    nm_setting_user_check_val (const char *val, GError **error);

G_END_DECLS

#endif /* __NM_SETTING_USER_H__ */
