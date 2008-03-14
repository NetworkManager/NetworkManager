/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#ifndef NM_SETTING_8021X_H
#define NM_SETTING_8021X_H

#include <nm-setting.h>

G_BEGIN_DECLS

#define NM_TYPE_SETTING_802_1X            (nm_setting_802_1x_get_type ())
#define NM_SETTING_802_1X(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_802_1X, NMSetting8021x))
#define NM_SETTING_802_1X_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_802_1X, NMSetting8021xClass))
#define NM_IS_SETTING_802_1X(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_802_1X))
#define NM_IS_SETTING_802_1X_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_SETTING_802_1X))
#define NM_SETTING_802_1X_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_802_1X, NMSetting8021xClass))

#define NM_SETTING_802_1X_SETTING_NAME "802.1X"

#define NM_SETTING_802_1X_EAP "eap"
#define NM_SETTING_802_1X_IDENTITY "identity"
#define NM_SETTING_802_1X_ANONYMOUS_IDENTITY "anonymous-identity"
#define NM_SETTING_802_1X_CA_CERT "ca-cert"
#define NM_SETTING_802_1X_CA_PATH "ca-path"
#define NM_SETTING_802_1X_CLIENT_CERT "client-cert"
#define NM_SETTING_802_1X_PHASE1_PEAPVER "phase1-peapver"
#define NM_SETTING_802_1X_PHASE1_PEAPLABEL "phase1-peaplabel"
#define NM_SETTING_802_1X_PHASE1_FAST_PROVISIONING "phase1-fast-provisioning"
#define NM_SETTING_802_1X_PHASE2_AUTH "phase2-auth"
#define NM_SETTING_802_1X_PHASE2_AUTHEAP "phase2-autheap"
#define NM_SETTING_802_1X_PHASE2_CA_CERT "phase2-ca-cert"
#define NM_SETTING_802_1X_PHASE2_CA_PATH "phase2-ca-path"
#define NM_SETTING_802_1X_PHASE2_CLIENT_CERT "phase2-client-cert"
#define NM_SETTING_802_1X_PASSWORD "password"
#define NM_SETTING_802_1X_PRIVATE_KEY "private-key"
#define NM_SETTING_802_1X_PHASE2_PRIVATE_KEY "phase2-private-key"

typedef struct {
	NMSetting parent;

	GSList *eap; /* GSList of strings */
	char *identity;
	char *anonymous_identity;
	GByteArray *ca_cert;
	char *ca_path;
	GByteArray *client_cert;
	char *phase1_peapver;
	char *phase1_peaplabel;
	char *phase1_fast_provisioning;
	char *phase2_auth;
	char *phase2_autheap;
	GByteArray *phase2_ca_cert;
	char *phase2_ca_path;
	GByteArray *phase2_client_cert;
	char *password;
	GByteArray *private_key;
	GByteArray *phase2_private_key;
} NMSetting8021x;

typedef struct {
	NMSettingClass parent;
} NMSetting8021xClass;

GType nm_setting_802_1x_get_type (void);

NMSetting *nm_setting_802_1x_new (void);

G_END_DECLS

#endif /* NM_SETTING_8021X_H */
