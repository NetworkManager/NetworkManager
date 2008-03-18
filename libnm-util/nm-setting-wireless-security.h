/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

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

typedef struct {
	NMSetting parent;

	char *key_mgmt;
	guint32 wep_tx_keyidx;
	char *auth_alg;
	GSList *proto; /* GSList of strings */
	GSList *pairwise; /* GSList of strings */
	GSList *group; /* GSList of strings */
	char *leap_username;
	char *wep_key0;
	char *wep_key1;
	char *wep_key2;
	char *wep_key3;
	char *psk;
	char *leap_password;
} NMSettingWirelessSecurity;

typedef struct {
	NMSettingClass parent;
} NMSettingWirelessSecurityClass;

GType nm_setting_wireless_security_get_type (void);

NMSetting *nm_setting_wireless_security_new (void);

G_END_DECLS

#endif /* NM_SETTING_WIRELESS_SECURITY_H */
