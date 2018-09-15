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
 * Copyright 2007 - 2014 Red Hat, Inc.
 * Copyright 2007 - 2008 Novell, Inc.
 */

#ifndef NM_SETTING_WIRELESS_SECURITY_H
#define NM_SETTING_WIRELESS_SECURITY_H

#include "nm-setting.h"

G_BEGIN_DECLS

#define NM_TYPE_SETTING_WIRELESS_SECURITY            (nm_setting_wireless_security_get_type ())
#define NM_SETTING_WIRELESS_SECURITY(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_WIRELESS_SECURITY, NMSettingWirelessSecurity))
#define NM_SETTING_WIRELESS_SECURITY_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_WIRELESS_SECURITY, NMSettingWirelessSecurityClass))
#define NM_IS_SETTING_WIRELESS_SECURITY(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_WIRELESS_SECURITY))
#define NM_IS_SETTING_WIRELESS_SECURITY_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SETTING_WIRELESS_SECURITY))
#define NM_SETTING_WIRELESS_SECURITY_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_WIRELESS_SECURITY, NMSettingWirelessSecurityClass))

#define NM_SETTING_WIRELESS_SECURITY_SETTING_NAME "802-11-wireless-security"

/**
 * NMSettingWirelessSecurityError:
 * @NM_SETTING_WIRELESS_SECURITY_ERROR_UNKNOWN: unknown or unclassified error
 * @NM_SETTING_WIRELESS_SECURITY_ERROR_INVALID_PROPERTY: the property was invalid
 * @NM_SETTING_WIRELESS_SECURITY_ERROR_MISSING_PROPERTY: the property was
 * missing and is required
 * @NM_SETTING_WIRELESS_SECURITY_ERROR_MISSING_802_1X_SETTING: a property contained
 * a value that requires the connection to contain a #NMSetting8021x setting
 * @NM_SETTING_WIRELESS_SECURITY_ERROR_LEAP_REQUIRES_802_1X: LEAP authentication
 * was specified but key management was not set to "8021x"
 * @NM_SETTING_WIRELESS_SECURITY_ERROR_LEAP_REQUIRES_USERNAME: LEAP authentication
 * was specified but no LEAP username was given
 * @NM_SETTING_WIRELESS_SECURITY_ERROR_SHARED_KEY_REQUIRES_WEP: Shared Key
 * authentication was specified but the setting did not specify WEP as the
 * encryption protocol
 */
typedef enum {
	NM_SETTING_WIRELESS_SECURITY_ERROR_UNKNOWN = 0,            /*< nick=UnknownError >*/
	NM_SETTING_WIRELESS_SECURITY_ERROR_INVALID_PROPERTY,       /*< nick=InvalidProperty >*/
	NM_SETTING_WIRELESS_SECURITY_ERROR_MISSING_PROPERTY,       /*< nick=MissingProperty >*/
	NM_SETTING_WIRELESS_SECURITY_ERROR_MISSING_802_1X_SETTING, /*< nick=Missing8021xSetting >*/
	NM_SETTING_WIRELESS_SECURITY_ERROR_LEAP_REQUIRES_802_1X,   /*< nick=LEAPRequires8021x >*/
	NM_SETTING_WIRELESS_SECURITY_ERROR_LEAP_REQUIRES_USERNAME, /*< nick=LEAPRequiresUsername >*/
	NM_SETTING_WIRELESS_SECURITY_ERROR_SHARED_KEY_REQUIRES_WEP /*< nick=SharedKeyRequiresWEP >*/
} NMSettingWirelessSecurityError;

#define NM_SETTING_WIRELESS_SECURITY_ERROR nm_setting_wireless_security_error_quark ()
GQuark nm_setting_wireless_security_error_quark (void);

/**
 * NMWepKeyType:
 * @NM_WEP_KEY_TYPE_UNKNOWN: unknown WEP key type
 * @NM_WEP_KEY_TYPE_KEY: indicates a hexadecimal or ASCII formatted WEP key.
 * Hex keys are either 10 or 26 hexadecimal characters (ie "5f782f2f5f" or
 * "732f2d712e4a394a375d366931"), while ASCII keys are either 5 or 13 ASCII
 * characters (ie "abcde" or "blahblah99$*1").
 * @NM_WEP_KEY_TYPE_PASSPHRASE: indicates a WEP passphrase (ex "I bought a duck
 * on my way back from the market 235Q&^%^*%") instead of a hexadecimal or ASCII
 * key.  Passphrases are between 8 and 64 characters inclusive and are hashed
 * the actual WEP key using the MD5 hash algorithm.
 * @NM_WEP_KEY_TYPE_LAST: placeholder value for bounds-checking
 *
 * The #NMWepKeyType values specify how any WEP keys present in the setting
 * are interpreted.  There are no standards governing how to hash the various WEP
 * key/passphrase formats into the actual WEP key.  Unfortunately some WEP keys
 * can be interpreted in multiple ways, requiring the setting to specify how to
 * interpret the any WEP keys.  For example, the key "732f2d712e4a394a375d366931"
 * is both a valid Hexadecimal WEP key and a WEP passphrase.  Further, many
 * ASCII keys are also valid WEP passphrases, but since passphrases and ASCII
 * keys are hashed differently to determine the actual WEP key the type must be
 * specified.
 */
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
#define NM_SETTING_WIRELESS_SECURITY_WEP_KEY_FLAGS "wep-key-flags"
#define NM_SETTING_WIRELESS_SECURITY_WEP_KEY_TYPE "wep-key-type"
#define NM_SETTING_WIRELESS_SECURITY_PSK "psk"
#define NM_SETTING_WIRELESS_SECURITY_PSK_FLAGS "psk-flags"
#define NM_SETTING_WIRELESS_SECURITY_LEAP_PASSWORD "leap-password"
#define NM_SETTING_WIRELESS_SECURITY_LEAP_PASSWORD_FLAGS "leap-password-flags"

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

guint32     nm_setting_wireless_security_get_num_protos        (NMSettingWirelessSecurity *setting);
const char *nm_setting_wireless_security_get_proto             (NMSettingWirelessSecurity *setting, guint32 i);
gboolean    nm_setting_wireless_security_add_proto             (NMSettingWirelessSecurity *setting, const char *proto);
void        nm_setting_wireless_security_remove_proto          (NMSettingWirelessSecurity *setting, guint32 i);
NM_AVAILABLE_IN_0_9_10
gboolean    nm_setting_wireless_security_remove_proto_by_value (NMSettingWirelessSecurity *setting, const char *proto);
void        nm_setting_wireless_security_clear_protos          (NMSettingWirelessSecurity *setting);

guint32     nm_setting_wireless_security_get_num_pairwise         (NMSettingWirelessSecurity *setting);
const char *nm_setting_wireless_security_get_pairwise             (NMSettingWirelessSecurity *setting, guint32 i);
gboolean    nm_setting_wireless_security_add_pairwise             (NMSettingWirelessSecurity *setting, const char *pairwise);
void        nm_setting_wireless_security_remove_pairwise          (NMSettingWirelessSecurity *setting, guint32 i);
NM_AVAILABLE_IN_0_9_10
gboolean    nm_setting_wireless_security_remove_pairwise_by_value (NMSettingWirelessSecurity *setting, const char *pairwise);
void        nm_setting_wireless_security_clear_pairwise           (NMSettingWirelessSecurity *setting);

guint32     nm_setting_wireless_security_get_num_groups        (NMSettingWirelessSecurity *setting);
const char *nm_setting_wireless_security_get_group             (NMSettingWirelessSecurity *setting, guint32 i);
gboolean    nm_setting_wireless_security_add_group             (NMSettingWirelessSecurity *setting, const char *group);
void        nm_setting_wireless_security_remove_group          (NMSettingWirelessSecurity *setting, guint32 i);
NM_AVAILABLE_IN_0_9_10
gboolean    nm_setting_wireless_security_remove_group_by_value (NMSettingWirelessSecurity *setting, const char *group);
void        nm_setting_wireless_security_clear_groups          (NMSettingWirelessSecurity *setting);

const char *nm_setting_wireless_security_get_psk           (NMSettingWirelessSecurity *setting);
NMSettingSecretFlags nm_setting_wireless_security_get_psk_flags (NMSettingWirelessSecurity *setting);

const char *nm_setting_wireless_security_get_leap_username (NMSettingWirelessSecurity *setting);
const char *nm_setting_wireless_security_get_leap_password (NMSettingWirelessSecurity *setting);
NMSettingSecretFlags nm_setting_wireless_security_get_leap_password_flags (NMSettingWirelessSecurity *setting);

const char *nm_setting_wireless_security_get_wep_key       (NMSettingWirelessSecurity *setting, guint32 idx);
void        nm_setting_wireless_security_set_wep_key       (NMSettingWirelessSecurity *setting, guint32 idx, const char *key);
guint32     nm_setting_wireless_security_get_wep_tx_keyidx (NMSettingWirelessSecurity *setting);
const char *nm_setting_wireless_security_get_auth_alg      (NMSettingWirelessSecurity *setting);

NMSettingSecretFlags nm_setting_wireless_security_get_wep_key_flags (NMSettingWirelessSecurity *setting);
NMWepKeyType nm_setting_wireless_security_get_wep_key_type (NMSettingWirelessSecurity *setting);

G_END_DECLS

#endif /* NM_SETTING_WIRELESS_SECURITY_H */
