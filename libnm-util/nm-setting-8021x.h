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

#define NM_SETTING_802_1X_SETTING_NAME "802-1x"

typedef enum
{
	NM_SETTING_802_1X_ERROR_UNKNOWN = 0,
	NM_SETTING_802_1X_ERROR_INVALID_PROPERTY,
	NM_SETTING_802_1X_ERROR_MISSING_PROPERTY
} NMSetting8021xError;

#define NM_TYPE_SETTING_802_1X_ERROR (nm_setting_802_1x_error_get_type ()) 
GType nm_setting_802_1x_error_get_type (void);

#define NM_SETTING_802_1X_ERROR nm_setting_802_1x_error_quark ()
GQuark nm_setting_802_1x_error_quark (void);


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
#define NM_SETTING_802_1X_PIN "pin"
#define NM_SETTING_802_1X_PSK "psk"

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
	char *pin;
	char *psk;
	GByteArray *private_key;
	GByteArray *phase2_private_key;
} NMSetting8021x;

typedef struct {
	NMSettingClass parent;
} NMSetting8021xClass;

GType nm_setting_802_1x_get_type (void);

NMSetting *nm_setting_802_1x_new (void);

gboolean nm_setting_802_1x_set_ca_cert (NMSetting8021x *self,
								const char *filename,
								GError **err);

gboolean nm_setting_802_1x_set_client_cert (NMSetting8021x *self,
								    const char *filename,
								    GError **err);

gboolean nm_setting_802_1x_set_phase2_ca_cert (NMSetting8021x *self,
									  const char *filename,
									  GError **err);

gboolean nm_setting_802_1x_set_phase2_client_cert (NMSetting8021x *self,
										 const char *filename,
										 GError **err);

gboolean nm_setting_802_1x_set_private_key (NMSetting8021x *self,
								    const char *filename,
								    const char *password,
								    GError **err);

gboolean nm_setting_802_1x_set_phase2_private_key (NMSetting8021x *self,
										 const char *filename,
										 const char *password,
										 GError **err);

G_END_DECLS

#endif /* NM_SETTING_8021X_H */
