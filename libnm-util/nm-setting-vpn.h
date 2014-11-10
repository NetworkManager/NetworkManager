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

#ifndef NM_SETTING_VPN_H
#define NM_SETTING_VPN_H

#include <nm-setting.h>

G_BEGIN_DECLS

#define NM_TYPE_SETTING_VPN            (nm_setting_vpn_get_type ())
#define NM_SETTING_VPN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_VPN, NMSettingVPN))
#define NM_SETTING_VPN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_VPN, NMSettingVPNClass))
#define NM_IS_SETTING_VPN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_VPN))
#define NM_IS_SETTING_VPN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SETTING_VPN))
#define NM_SETTING_VPN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_VPN, NMSettingVPNClass))

#define NM_SETTING_VPN_SETTING_NAME "vpn"

/**
 * NMSettingVpnError:
 * @NM_SETTING_VPN_ERROR_UNKNOWN: unknown or unclassified error
 * @NM_SETTING_VPN_ERROR_INVALID_PROPERTY: the property was invalid
 * @NM_SETTING_VPN_ERROR_MISSING_PROPERTY: the property was missing and is
 * required
 */
typedef enum {
	NM_SETTING_VPN_ERROR_UNKNOWN = 0,      /*< nick=UnknownError >*/
	NM_SETTING_VPN_ERROR_INVALID_PROPERTY, /*< nick=InvalidProperty >*/
	NM_SETTING_VPN_ERROR_MISSING_PROPERTY, /*< nick=MissingProperty >*/
} NMSettingVpnError;

#define NM_SETTING_VPN_ERROR nm_setting_vpn_error_quark ()
GQuark nm_setting_vpn_error_quark (void);

#define NM_SETTING_VPN_SERVICE_TYPE "service-type"
#define NM_SETTING_VPN_USER_NAME    "user-name"
#define NM_SETTING_VPN_PERSISTENT   "persistent"
#define NM_SETTING_VPN_DATA         "data"
#define NM_SETTING_VPN_SECRETS      "secrets"

typedef struct {
	NMSetting parent;
} NMSettingVPN;

typedef struct {
	NMSettingClass parent;

	/* Padding for future expansion */
	void (*_reserved1) (void);
	void (*_reserved2) (void);
	void (*_reserved3) (void);
	void (*_reserved4) (void);
} NMSettingVPNClass;

/**
 * NMVPNIterFunc:
 * @key: the name of the data or secret item
 * @value: the value of the data or secret item
 * @user_data: User data passed to nm_setting_vpn_foreach_data_item() or
 * nm_setting_vpn_foreach_secret()
 **/
typedef void (*NMVPNIterFunc) (const char *key, const char *value, gpointer user_data);

GType nm_setting_vpn_get_type (void);

NMSetting        *nm_setting_vpn_new               (void);
const char       *nm_setting_vpn_get_service_type  (NMSettingVPN *setting);
const char       *nm_setting_vpn_get_user_name     (NMSettingVPN *setting);
gboolean          nm_setting_vpn_get_persistent    (NMSettingVPN *setting);

guint32           nm_setting_vpn_get_num_data_items (NMSettingVPN *setting);
void              nm_setting_vpn_add_data_item     (NMSettingVPN *setting,
                                                    const char *key,
                                                    const char *item);
const char *      nm_setting_vpn_get_data_item     (NMSettingVPN *setting,
                                                    const char *key);
gboolean          nm_setting_vpn_remove_data_item  (NMSettingVPN *setting,
                                                    const char *key);
void              nm_setting_vpn_foreach_data_item (NMSettingVPN *setting,
                                                    NMVPNIterFunc func,
                                                    gpointer user_data);

guint32           nm_setting_vpn_get_num_secrets   (NMSettingVPN *setting);
void              nm_setting_vpn_add_secret        (NMSettingVPN *setting,
                                                    const char *key,
                                                    const char *secret);
const char *      nm_setting_vpn_get_secret        (NMSettingVPN *setting,
                                                    const char *key);
gboolean          nm_setting_vpn_remove_secret     (NMSettingVPN *setting,
                                                    const char *key);
void              nm_setting_vpn_foreach_secret    (NMSettingVPN *setting,
                                                    NMVPNIterFunc func,
                                                    gpointer user_data);

#ifdef NM_VPN_LIBNM_COMPAT
#define NMSettingVpn NMSettingVPN
#endif

G_END_DECLS

#endif /* NM_SETTING_VPN_H */
