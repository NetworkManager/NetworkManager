/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2007 - 2017 Red Hat, Inc.
 * Copyright (C) 2007 - 2008 Novell, Inc.
 */

#ifndef __NM_SETTING_WIRELESS_SECURITY_H__
#define __NM_SETTING_WIRELESS_SECURITY_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-setting.h"

G_BEGIN_DECLS

#define NM_TYPE_SETTING_WIRELESS_SECURITY (nm_setting_wireless_security_get_type())
#define NM_SETTING_WIRELESS_SECURITY(obj)                          \
    (G_TYPE_CHECK_INSTANCE_CAST((obj),                             \
                                NM_TYPE_SETTING_WIRELESS_SECURITY, \
                                NMSettingWirelessSecurity))
#define NM_SETTING_WIRELESS_SECURITY_CLASS(klass)               \
    (G_TYPE_CHECK_CLASS_CAST((klass),                           \
                             NM_TYPE_SETTING_WIRELESS_SECURITY, \
                             NMSettingWirelessSecurityClass))
#define NM_IS_SETTING_WIRELESS_SECURITY(obj) \
    (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_SETTING_WIRELESS_SECURITY))
#define NM_IS_SETTING_WIRELESS_SECURITY_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_SETTING_WIRELESS_SECURITY))
#define NM_SETTING_WIRELESS_SECURITY_GET_CLASS(obj)               \
    (G_TYPE_INSTANCE_GET_CLASS((obj),                             \
                               NM_TYPE_SETTING_WIRELESS_SECURITY, \
                               NMSettingWirelessSecurityClass))

#define NM_SETTING_WIRELESS_SECURITY_SETTING_NAME "802-11-wireless-security"

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
    NM_WEP_KEY_TYPE_UNKNOWN    = 0,
    NM_WEP_KEY_TYPE_KEY        = 1, /* Hex or ASCII */
    NM_WEP_KEY_TYPE_PASSPHRASE = 2, /* 104/128-bit Passphrase */

    NM_WEP_KEY_TYPE_LAST = NM_WEP_KEY_TYPE_PASSPHRASE, /*< skip >*/
} NMWepKeyType;

/**
 * NMSettingWirelessSecurityPmf:
 * @NM_SETTING_WIRELESS_SECURITY_PMF_DEFAULT: use the default value
 * @NM_SETTING_WIRELESS_SECURITY_PMF_DISABLE: disable PMF
 * @NM_SETTING_WIRELESS_SECURITY_PMF_OPTIONAL: enable PMF if the supplicant and the AP support it
 * @NM_SETTING_WIRELESS_SECURITY_PMF_REQUIRED: require PMF and fail if not available
 *
 * These flags indicate whether PMF must be enabled.
 **/
typedef enum {
    NM_SETTING_WIRELESS_SECURITY_PMF_DEFAULT  = 0,
    NM_SETTING_WIRELESS_SECURITY_PMF_DISABLE  = 1,
    NM_SETTING_WIRELESS_SECURITY_PMF_OPTIONAL = 2,
    NM_SETTING_WIRELESS_SECURITY_PMF_REQUIRED = 3,
    _NM_SETTING_WIRELESS_SECURITY_PMF_NUM,                                             /*< skip >*/
    NM_SETTING_WIRELESS_SECURITY_PMF_LAST = _NM_SETTING_WIRELESS_SECURITY_PMF_NUM - 1, /*< skip >*/
} NMSettingWirelessSecurityPmf;

/**
 * NMSettingWirelessSecurityWpsMethod:
 * @NM_SETTING_WIRELESS_SECURITY_WPS_METHOD_DEFAULT: Attempt whichever method AP supports
 * @NM_SETTING_WIRELESS_SECURITY_WPS_METHOD_DISABLED: WPS can not be used.
 * @NM_SETTING_WIRELESS_SECURITY_WPS_METHOD_AUTO: Use WPS, any method
 * @NM_SETTING_WIRELESS_SECURITY_WPS_METHOD_PBC: use WPS push-button method
 * @NM_SETTING_WIRELESS_SECURITY_WPS_METHOD_PIN: use PIN method
 *
 * Configure the use of WPS by a connection while it activates.
 *
 * Note: prior to 1.16, this was a GEnum type instead of a GFlags type
 * although, with the same numeric values.
 *
 * Since: 1.10
 **/
typedef enum { /*< flags >*/
               NM_SETTING_WIRELESS_SECURITY_WPS_METHOD_DEFAULT  = 0x00000000,
               NM_SETTING_WIRELESS_SECURITY_WPS_METHOD_DISABLED = 0x00000001,
               NM_SETTING_WIRELESS_SECURITY_WPS_METHOD_AUTO     = 0x00000002,
               NM_SETTING_WIRELESS_SECURITY_WPS_METHOD_PBC      = 0x00000004,
               NM_SETTING_WIRELESS_SECURITY_WPS_METHOD_PIN      = 0x00000008,
} NMSettingWirelessSecurityWpsMethod;

/**
 * NMSettingWirelessSecurityFils:
 * @NM_SETTING_WIRELESS_SECURITY_FILS_DEFAULT: use the default value
 * @NM_SETTING_WIRELESS_SECURITY_FILS_DISABLE: disable FILS
 * @NM_SETTING_WIRELESS_SECURITY_FILS_OPTIONAL: enable FILS if the supplicant and the AP support it
 * @NM_SETTING_WIRELESS_SECURITY_FILS_REQUIRED: require FILS and fail if not available
 * @_NM_SETTING_WIRELESS_SECURITY_FILS_NUM: placeholder value for bounds-checking
 * @NM_SETTING_WIRELESS_SECURITY_FILS_LAST: placeholder value for bounds-checking
 *
 * These flags indicate whether FILS must be enabled.
 *
 * Since: 1.12
 **/
/* clang-format off */
typedef enum {
    NM_SETTING_WIRELESS_SECURITY_FILS_DEFAULT  = 0,
    NM_SETTING_WIRELESS_SECURITY_FILS_DISABLE  = 1,
    NM_SETTING_WIRELESS_SECURITY_FILS_OPTIONAL = 2,
    NM_SETTING_WIRELESS_SECURITY_FILS_REQUIRED = 3,
    _NM_SETTING_WIRELESS_SECURITY_FILS_NUM, /*< skip >*/
    NM_SETTING_WIRELESS_SECURITY_FILS_LAST = _NM_SETTING_WIRELESS_SECURITY_FILS_NUM - 1, /*< skip >*/
} NMSettingWirelessSecurityFils;
/* clang-format on */

#define NM_SETTING_WIRELESS_SECURITY_KEY_MGMT            "key-mgmt"
#define NM_SETTING_WIRELESS_SECURITY_WEP_TX_KEYIDX       "wep-tx-keyidx"
#define NM_SETTING_WIRELESS_SECURITY_AUTH_ALG            "auth-alg"
#define NM_SETTING_WIRELESS_SECURITY_PROTO               "proto"
#define NM_SETTING_WIRELESS_SECURITY_PAIRWISE            "pairwise"
#define NM_SETTING_WIRELESS_SECURITY_GROUP               "group"
#define NM_SETTING_WIRELESS_SECURITY_PMF                 "pmf"
#define NM_SETTING_WIRELESS_SECURITY_LEAP_USERNAME       "leap-username"
#define NM_SETTING_WIRELESS_SECURITY_WEP_KEY0            "wep-key0"
#define NM_SETTING_WIRELESS_SECURITY_WEP_KEY1            "wep-key1"
#define NM_SETTING_WIRELESS_SECURITY_WEP_KEY2            "wep-key2"
#define NM_SETTING_WIRELESS_SECURITY_WEP_KEY3            "wep-key3"
#define NM_SETTING_WIRELESS_SECURITY_WEP_KEY_FLAGS       "wep-key-flags"
#define NM_SETTING_WIRELESS_SECURITY_WEP_KEY_TYPE        "wep-key-type"
#define NM_SETTING_WIRELESS_SECURITY_PSK                 "psk"
#define NM_SETTING_WIRELESS_SECURITY_PSK_FLAGS           "psk-flags"
#define NM_SETTING_WIRELESS_SECURITY_LEAP_PASSWORD       "leap-password"
#define NM_SETTING_WIRELESS_SECURITY_LEAP_PASSWORD_FLAGS "leap-password-flags"
#define NM_SETTING_WIRELESS_SECURITY_WPS_METHOD          "wps-method"
#define NM_SETTING_WIRELESS_SECURITY_FILS                "fils"

typedef struct _NMSettingWirelessSecurityClass NMSettingWirelessSecurityClass;

GType nm_setting_wireless_security_get_type(void);

NMSetting *nm_setting_wireless_security_new(void);

const char *nm_setting_wireless_security_get_key_mgmt(NMSettingWirelessSecurity *setting);

guint32     nm_setting_wireless_security_get_num_protos(NMSettingWirelessSecurity *setting);
const char *nm_setting_wireless_security_get_proto(NMSettingWirelessSecurity *setting, guint32 i);
gboolean    nm_setting_wireless_security_add_proto(NMSettingWirelessSecurity *setting,
                                                   const char                *proto);
void     nm_setting_wireless_security_remove_proto(NMSettingWirelessSecurity *setting, guint32 i);
gboolean nm_setting_wireless_security_remove_proto_by_value(NMSettingWirelessSecurity *setting,
                                                            const char                *proto);
void     nm_setting_wireless_security_clear_protos(NMSettingWirelessSecurity *setting);

guint32     nm_setting_wireless_security_get_num_pairwise(NMSettingWirelessSecurity *setting);
const char *nm_setting_wireless_security_get_pairwise(NMSettingWirelessSecurity *setting,
                                                      guint32                    i);
gboolean    nm_setting_wireless_security_add_pairwise(NMSettingWirelessSecurity *setting,
                                                      const char                *pairwise);
void nm_setting_wireless_security_remove_pairwise(NMSettingWirelessSecurity *setting, guint32 i);
gboolean nm_setting_wireless_security_remove_pairwise_by_value(NMSettingWirelessSecurity *setting,
                                                               const char                *pairwise);
void     nm_setting_wireless_security_clear_pairwise(NMSettingWirelessSecurity *setting);

guint32     nm_setting_wireless_security_get_num_groups(NMSettingWirelessSecurity *setting);
const char *nm_setting_wireless_security_get_group(NMSettingWirelessSecurity *setting, guint32 i);
gboolean    nm_setting_wireless_security_add_group(NMSettingWirelessSecurity *setting,
                                                   const char                *group);
void     nm_setting_wireless_security_remove_group(NMSettingWirelessSecurity *setting, guint32 i);
gboolean nm_setting_wireless_security_remove_group_by_value(NMSettingWirelessSecurity *setting,
                                                            const char                *group);
void     nm_setting_wireless_security_clear_groups(NMSettingWirelessSecurity *setting);

NM_AVAILABLE_IN_1_10
NMSettingWirelessSecurityPmf
nm_setting_wireless_security_get_pmf(NMSettingWirelessSecurity *setting);

const char          *nm_setting_wireless_security_get_psk(NMSettingWirelessSecurity *setting);
NMSettingSecretFlags nm_setting_wireless_security_get_psk_flags(NMSettingWirelessSecurity *setting);

const char *nm_setting_wireless_security_get_leap_username(NMSettingWirelessSecurity *setting);
const char *nm_setting_wireless_security_get_leap_password(NMSettingWirelessSecurity *setting);
NMSettingSecretFlags
nm_setting_wireless_security_get_leap_password_flags(NMSettingWirelessSecurity *setting);

const char *nm_setting_wireless_security_get_wep_key(NMSettingWirelessSecurity *setting,
                                                     guint32                    idx);
void        nm_setting_wireless_security_set_wep_key(NMSettingWirelessSecurity *setting,
                                                     guint32                    idx,
                                                     const char                *key);
guint32     nm_setting_wireless_security_get_wep_tx_keyidx(NMSettingWirelessSecurity *setting);
const char *nm_setting_wireless_security_get_auth_alg(NMSettingWirelessSecurity *setting);

NMSettingSecretFlags
             nm_setting_wireless_security_get_wep_key_flags(NMSettingWirelessSecurity *setting);
NMWepKeyType nm_setting_wireless_security_get_wep_key_type(NMSettingWirelessSecurity *setting);

NM_AVAILABLE_IN_1_10
NMSettingWirelessSecurityWpsMethod
nm_setting_wireless_security_get_wps_method(NMSettingWirelessSecurity *setting);

NM_AVAILABLE_IN_1_12
NMSettingWirelessSecurityFils
nm_setting_wireless_security_get_fils(NMSettingWirelessSecurity *setting);

G_END_DECLS

#endif /* __NM_SETTING_WIRELESS_SECURITY_H__ */
