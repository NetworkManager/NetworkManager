/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#ifndef NM_SETTING_WIRELESS_SECURITY_H
#define NM_SETTING_WIRELESS_SECURITY_H

#include <nm-setting.h>

G_BEGIN_DECLS

#define NM_TYPE_SETTING_WIRELESS_SECURITY            (nm_setting_wireless_security_get_type ())
#define NM_SETTING_WIRELESS_SECURITY(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_WIRELESS_SECURITY, NMSettingWirelessSecurity))
#define NM_SETTING_WIRELESS_SECURITY_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_WIRELESS_SECURITY, NMSettingWirelesSsecurityClass))
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
#define NM_SETTING_WIRELESS_SECURITY_EAP "eap"
#define NM_SETTING_WIRELESS_SECURITY_IDENTITY "identity"
#define NM_SETTING_WIRELESS_SECURITY_ANONYMOUS_IDENTITY "anonymous-identity"
#define NM_SETTING_WIRELESS_SECURITY_CA_CERT "ca-cert"
#define NM_SETTING_WIRELESS_SECURITY_CA_PATH "ca-path"
#define NM_SETTING_WIRELESS_SECURITY_CLIENT_CERT "client-cert"
#define NM_SETTING_WIRELESS_SECURITY_PRIVATE_KEY "private-key"
#define NM_SETTING_WIRELESS_SECURITY_PRIVATE_KEY_DECRYPTED "private-key-decrypted"
#define NM_SETTING_WIRELESS_SECURITY_PHASE1_PEAPVER "phase1-peapver"
#define NM_SETTING_WIRELESS_SECURITY_PHASE1_PEAPLABEL "phase1-peaplabel"
#define NM_SETTING_WIRELESS_SECURITY_PHASE1_FAST_PROVISIONING "phase1-fast-provisioning"
#define NM_SETTING_WIRELESS_SECURITY_PHASE2_AUTH "phase2-auth"
#define NM_SETTING_WIRELESS_SECURITY_PHASE2_AUTHEAP "phase2-autheap"
#define NM_SETTING_WIRELESS_SECURITY_PHASE2_CA_CERT "phase2-ca-cert"
#define NM_SETTING_WIRELESS_SECURITY_PHASE2_CA_PATH "phase2-ca-path"
#define NM_SETTING_WIRELESS_SECURITY_PHASE2_CLIENT_CERT "phase2-client-cert"
#define NM_SETTING_WIRELESS_SECURITY_PHASE2_PRIVATE_KEY "phase2-private-key"
#define NM_SETTING_WIRELESS_SECURITY_PHASE2_PRIVATE_KEY_DECRYPTED "phase2-private-key-decrypted"
#define NM_SETTING_WIRELESS_SECURITY_NAI "nai"
#define NM_SETTING_WIRELESS_SECURITY_WEP_KEY0 "wep-key0"
#define NM_SETTING_WIRELESS_SECURITY_WEP_KEY1 "wep-key1"
#define NM_SETTING_WIRELESS_SECURITY_WEP_KEY2 "wep-key2"
#define NM_SETTING_WIRELESS_SECURITY_WEP_KEY3 "wep-key3"
#define NM_SETTING_WIRELESS_SECURITY_PSK "psk"
#define NM_SETTING_WIRELESS_SECURITY_PASSWORD "password"
#define NM_SETTING_WIRELESS_SECURITY_PIN "pin"
#define NM_SETTING_WIRELESS_SECURITY_EAPPSK "eappsk"
#define NM_SETTING_WIRELESS_SECURITY_PRIVATE_KEY_PASSWD "private-key-passwd"
#define NM_SETTING_WIRELESS_SECURITY_PHASE2_PRIVATE_KEY_PASSWD "phase2-private-key-passwd"

typedef struct {
	NMSetting parent;

	char *key_mgmt;
	guint32 wep_tx_keyidx;
	char *auth_alg;
	GSList *proto; /* GSList of strings */
	GSList *pairwise; /* GSList of strings */
	GSList *group; /* GSList of strings */
	GSList *eap; /* GSList of strings */
	char *identity;
	char *anonymous_identity;
	GByteArray *ca_cert;
	char *ca_path;
	GByteArray *client_cert;
	GByteArray *private_key;
	gboolean private_key_decrypted;
	char *phase1_peapver;
	char *phase1_peaplabel;
	char *phase1_fast_provisioning;
	char *phase2_auth;
	char *phase2_autheap;
	GByteArray *phase2_ca_cert;
	char *phase2_ca_path;
	GByteArray *phase2_client_cert;
	gboolean phase2_private_key_decrypted;
	GByteArray *phase2_private_key;
	char *nai;
	char *wep_key0;
	char *wep_key1;
	char *wep_key2;
	char *wep_key3;
	char *psk;
	char *password;
	char *pin;
	char *eappsk;
	char *private_key_passwd;
	char *phase2_private_key_passwd;
} NMSettingWirelessSecurity;

typedef struct {
	NMSettingClass parent;
} NMSettingWirelessSecurityClass;

GType nm_setting_wireless_security_get_type (void);

NMSetting *nm_setting_wireless_security_new (void);

G_END_DECLS

#endif /* NM_SETTING_WIRELESS_SECURITY_H */
