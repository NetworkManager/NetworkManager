/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

/*
 * Dan Williams <dcbw@redhat.com>
 * Tambet Ingo <tambet@gmail.com>
 *
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
 * (C) Copyright 2007 - 2008 Red Hat, Inc.
 * (C) Copyright 2007 - 2008 Novell, Inc.
 */

#ifndef NM_SETTING_WIRELESS_SECURITY_H
#define NM_SETTING_WIRELESS_SECURITY_H

#include <nm-setting.h>

G_BEGIN_DECLS

#define NM_TYPE_SETTING_WIRELESS_SECURITY            (nm_setting_wireless_security_get_type ())
#define NM_SETTING_WIRELESS_SECURITY(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_WIRELESS_SECURITY, NMSettingWirelessSecurity))
#define NM_SETTING_WIRELESS_SECURITY_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_WIRELESS_SECURITY, NMSettingWirelessSecurityClass))
#define NM_IS_SETTING_WIRELESS_SECURITY(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_WIRELESS_SECURITY))
#define NM_IS_SETTING_WIRELESS_SECURITY_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_SETTING_WIRELESS_SECURITY))
#define NM_SETTING_WIRELESS_SECURITY_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_WIRELESS_SECURITY, NMSettingWirelessSecurityClass))

#define NM_SETTING_WIRELESS_SECURITY_SETTING_NAME "802-11-wireless-security"

typedef enum
{
	NM_SETTING_WIRELESS_SECURITY_ERROR_UNKNOWN = 0,
	NM_SETTING_WIRELESS_SECURITY_ERROR_INVALID_PROPERTY,
	NM_SETTING_WIRELESS_SECURITY_ERROR_MISSING_PROPERTY,
	NM_SETTING_WIRELESS_SECURITY_ERROR_MISSING_802_1X_SETTING,
	NM_SETTING_WIRELESS_SECURITY_ERROR_LEAP_REQUIRES_802_1X,
	NM_SETTING_WIRELESS_SECURITY_ERROR_LEAP_REQUIRES_USERNAME,
	NM_SETTING_WIRELESS_SECURITY_ERROR_SHARED_KEY_REQUIRES_WEP
} NMSettingWirelessSecurityError;

#define NM_TYPE_SETTING_WIRELESS_SECURITY_ERROR (nm_setting_wireless_security_error_get_type ()) 
GType nm_setting_wireless_security_error_get_type (void);

#define NM_SETTING_WIRELESS_SECURITY_ERROR nm_setting_wireless_security_error_quark ()
GQuark nm_setting_wireless_security_error_quark (void);

typedef enum {
	NM_WEP_KEY_TYPE_UNKNOWN = 0,
	NM_WEP_KEY_TYPE_KEY = 1,          /* Hex or ASCII */
	NM_WEP_KEY_TYPE_PASSPHRASE = 2,   /* 104/128-bit Passphrase */

	NM_WEP_KEY_TYPE_LAST = NM_WEP_KEY_TYPE_PASSPHRASE
} NMWepKeyType;

#define NM_SETTING_WIRELESS_SECURITY_KEY_MGMT "key-mgmt"
#define NM_SETTING_WIRELESS_SECURITY_WEP_TX_KEYIDX "wep-tx-keyidx"
#define NM_SETTING_WIRELESS_SECURITY_AUTH_ALG "auth-alg"
#define NM_SETTING_WIRELESS_SECURITY_PROTO "proto"
#define NM_SETTING_WIRELESS_SECURITY_PAIRWISE "pairwise"
#define NM_SETTING_WIRELESS_SECURITY_GROUP "group"
#define NM_SETTING_WIRELESS_SECURITY_LEAP_USERNAME "leap-username"
#define NM_SETTING_WIRELESS_SECURITY_WEP_KEY0 "wep-key0"
#define NM_SETTING_WIRELESS_SECURITY_WEP_KEY1 "wep-key1"
#define NM_SETTING_WIRELESS_SECURITY_WEP_KEY2 "wep-key2"
#define NM_SETTING_WIRELESS_SECURITY_WEP_KEY3 "wep-key3"
#define NM_SETTING_WIRELESS_SECURITY_PSK "psk"
#define NM_SETTING_WIRELESS_SECURITY_LEAP_PASSWORD "leap-password"
#define NM_SETTING_WIRELESS_SECURITY_WEP_KEY_TYPE "wep-key-type"

typedef struct {
	NMSetting parent;
} NMSettingWirelessSecurity;

typedef struct {
	NMSettingClass parent;

	/* Padding for future expansion */
	void (*_reserved1) (void);
	void (*_reserved2) (void);
	void (*_reserved3) (void);
	void (*_reserved4) (void);
} NMSettingWirelessSecurityClass;

GType nm_setting_wireless_security_get_type (void);

NMSetting * nm_setting_wireless_security_new               (void);

const char *nm_setting_wireless_security_get_key_mgmt      (NMSettingWirelessSecurity *setting);

guint32     nm_setting_wireless_security_get_num_protos    (NMSettingWirelessSecurity *setting);
const char *nm_setting_wireless_security_get_proto         (NMSettingWirelessSecurity *setting, guint32 i);
gboolean    nm_setting_wireless_security_add_proto         (NMSettingWirelessSecurity *setting, const char *proto);
void        nm_setting_wireless_security_remove_proto      (NMSettingWirelessSecurity *setting, guint32 i);
void        nm_setting_wireless_security_clear_protos      (NMSettingWirelessSecurity *setting);

guint32     nm_setting_wireless_security_get_num_pairwise  (NMSettingWirelessSecurity *setting);
const char *nm_setting_wireless_security_get_pairwise      (NMSettingWirelessSecurity *setting, guint32 i);
gboolean    nm_setting_wireless_security_add_pairwise      (NMSettingWirelessSecurity *setting, const char *pairwise);
void        nm_setting_wireless_security_remove_pairwise   (NMSettingWirelessSecurity *setting, guint32 i);
void        nm_setting_wireless_security_clear_pairwise    (NMSettingWirelessSecurity *setting);

guint32     nm_setting_wireless_security_get_num_groups    (NMSettingWirelessSecurity *setting);
const char *nm_setting_wireless_security_get_group         (NMSettingWirelessSecurity *setting, guint32 i);
gboolean    nm_setting_wireless_security_add_group         (NMSettingWirelessSecurity *setting, const char *group);
void        nm_setting_wireless_security_remove_group      (NMSettingWirelessSecurity *setting, guint32 i);
void        nm_setting_wireless_security_clear_groups      (NMSettingWirelessSecurity *setting);

const char *nm_setting_wireless_security_get_psk           (NMSettingWirelessSecurity *setting);

const char *nm_setting_wireless_security_get_leap_username (NMSettingWirelessSecurity *setting);
const char *nm_setting_wireless_security_get_leap_password (NMSettingWirelessSecurity *setting);

const char *nm_setting_wireless_security_get_wep_key       (NMSettingWirelessSecurity *setting, guint32 idx);
void        nm_setting_wireless_security_set_wep_key       (NMSettingWirelessSecurity *setting, guint32 idx, const char *key);
guint32     nm_setting_wireless_security_get_wep_tx_keyidx (NMSettingWirelessSecurity *setting);
const char *nm_setting_wireless_security_get_auth_alg      (NMSettingWirelessSecurity *setting);
NMWepKeyType nm_setting_wireless_security_get_wep_key_type (NMSettingWirelessSecurity *setting);

G_END_DECLS

#endif /* NM_SETTING_WIRELESS_SECURITY_H */
