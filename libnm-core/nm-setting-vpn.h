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
 * Copyright 2007 - 2013 Red Hat, Inc.
 * Copyright 2007 - 2008 Novell, Inc.
 */

#ifndef __NM_SETTING_VPN_H__
#define __NM_SETTING_VPN_H__

#if !defined (__NETWORKMANAGER_H_INSIDE__) && !defined (NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-setting.h"

G_BEGIN_DECLS

#define NM_TYPE_SETTING_VPN            (nm_setting_vpn_get_type ())
#define NM_SETTING_VPN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_VPN, NMSettingVpn))
#define NM_SETTING_VPN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_VPN, NMSettingVpnClass))
#define NM_IS_SETTING_VPN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_VPN))
#define NM_IS_SETTING_VPN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SETTING_VPN))
#define NM_SETTING_VPN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_VPN, NMSettingVpnClass))

#define NM_SETTING_VPN_SETTING_NAME "vpn"

#define NM_SETTING_VPN_SERVICE_TYPE "service-type"
#define NM_SETTING_VPN_USER_NAME    "user-name"
#define NM_SETTING_VPN_PERSISTENT   "persistent"
#define NM_SETTING_VPN_DATA         "data"
#define NM_SETTING_VPN_SECRETS      "secrets"
#define NM_SETTING_VPN_TIMEOUT      "timeout"

/**
 * NMSettingVpn:
 *
 * VPN Settings
 */
struct _NMSettingVpn {
	NMSetting parent;
};

typedef struct {
	NMSettingClass parent;

	/*< private >*/
	gpointer padding[4];
} NMSettingVpnClass;

/**
 * NMVpnIterFunc:
 * @key: the name of the data or secret item
 * @value: the value of the data or secret item
 * @user_data: User data passed to nm_setting_vpn_foreach_data_item() or
 * nm_setting_vpn_foreach_secret()
 **/
typedef void (*NMVpnIterFunc) (const char *key, const char *value, gpointer user_data);

GType nm_setting_vpn_get_type (void);

NMSetting        *nm_setting_vpn_new               (void);
const char       *nm_setting_vpn_get_service_type  (NMSettingVpn *setting);
const char       *nm_setting_vpn_get_user_name     (NMSettingVpn *setting);
gboolean          nm_setting_vpn_get_persistent    (NMSettingVpn *setting);

guint32           nm_setting_vpn_get_num_data_items (NMSettingVpn *setting);
void              nm_setting_vpn_add_data_item     (NMSettingVpn *setting,
                                                    const char *key,
                                                    const char *item);
const char *      nm_setting_vpn_get_data_item     (NMSettingVpn *setting,
                                                    const char *key);
gboolean          nm_setting_vpn_remove_data_item  (NMSettingVpn *setting,
                                                    const char *key);
void              nm_setting_vpn_foreach_data_item (NMSettingVpn *setting,
                                                    NMVpnIterFunc func,
                                                    gpointer user_data);
NM_AVAILABLE_IN_1_12
const char **     nm_setting_vpn_get_data_keys     (NMSettingVpn *setting,
                                                    guint *out_length);

guint32           nm_setting_vpn_get_num_secrets   (NMSettingVpn *setting);
void              nm_setting_vpn_add_secret        (NMSettingVpn *setting,
                                                    const char *key,
                                                    const char *secret);
const char *      nm_setting_vpn_get_secret        (NMSettingVpn *setting,
                                                    const char *key);
gboolean          nm_setting_vpn_remove_secret     (NMSettingVpn *setting,
                                                    const char *key);
void              nm_setting_vpn_foreach_secret    (NMSettingVpn *setting,
                                                    NMVpnIterFunc func,
                                                    gpointer user_data);
NM_AVAILABLE_IN_1_12
const char **     nm_setting_vpn_get_secret_keys   (NMSettingVpn *setting,
                                                    guint *out_length);

NM_AVAILABLE_IN_1_2
guint32           nm_setting_vpn_get_timeout       (NMSettingVpn *setting);

G_END_DECLS

#endif /* __NM_SETTING_VPN_H__ */
