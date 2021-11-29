/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2007 - 2014 Red Hat, Inc.
 * Copyright (C) 2007 - 2008 Novell, Inc.
 */

#ifndef __NM_SETTING_8021X_H__
#define __NM_SETTING_8021X_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-setting.h"

G_BEGIN_DECLS

#define NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PATH   "file://"
#define NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PKCS11 "pkcs11:"

/**
 * NMSetting8021xCKFormat:
 * @NM_SETTING_802_1X_CK_FORMAT_UNKNOWN: unknown file format
 * @NM_SETTING_802_1X_CK_FORMAT_X509: file contains an X.509 format certificate
 * @NM_SETTING_802_1X_CK_FORMAT_RAW_KEY: file contains an old-style OpenSSL PEM
 * or DER private key
 * @NM_SETTING_802_1X_CK_FORMAT_PKCS12: file contains a PKCS#<!-- -->12 certificate
 * and private key
 *
 * #NMSetting8021xCKFormat values indicate the general type of a certificate
 * or private key
 */
typedef enum { /*< underscore_name=nm_setting_802_1x_ck_format >*/
               NM_SETTING_802_1X_CK_FORMAT_UNKNOWN = 0,
               NM_SETTING_802_1X_CK_FORMAT_X509,
               NM_SETTING_802_1X_CK_FORMAT_RAW_KEY,
               NM_SETTING_802_1X_CK_FORMAT_PKCS12
} NMSetting8021xCKFormat;

/**
 * NMSetting8021xCKScheme:
 * @NM_SETTING_802_1X_CK_SCHEME_UNKNOWN: unknown certificate or private key
 * scheme
 * @NM_SETTING_802_1X_CK_SCHEME_BLOB: certificate or key is stored as the raw
 * item data
 * @NM_SETTING_802_1X_CK_SCHEME_PATH: certificate or key is stored as a path
 * to a file containing the certificate or key data
 * @NM_SETTING_802_1X_CK_SCHEME_PKCS11: certificate or key is stored as a
 * URI of an object on a PKCS#11 token
 *
 * #NMSetting8021xCKScheme values indicate how a certificate or private key is
 * stored in the setting properties, either as a blob of the item's data, or as
 * a path to a certificate or private key file on the filesystem
 */
typedef enum { /*< underscore_name=nm_setting_802_1x_ck_scheme >*/
               NM_SETTING_802_1X_CK_SCHEME_UNKNOWN = 0,
               NM_SETTING_802_1X_CK_SCHEME_BLOB,
               NM_SETTING_802_1X_CK_SCHEME_PATH,
               NM_SETTING_802_1X_CK_SCHEME_PKCS11,
} NMSetting8021xCKScheme;

/**
 * NMSetting8021xAuthFlags:
 * @NM_SETTING_802_1X_AUTH_FLAGS_NONE: No flags
 * @NM_SETTING_802_1X_AUTH_FLAGS_TLS_1_0_DISABLE: Disable TLSv1.0
 * @NM_SETTING_802_1X_AUTH_FLAGS_TLS_1_1_DISABLE: Disable TLSv1.1
 * @NM_SETTING_802_1X_AUTH_FLAGS_TLS_1_2_DISABLE: Disable TLSv1.2
 * @NM_SETTING_802_1X_AUTH_FLAGS_ALL: All supported flags
 *
 * #NMSetting8021xAuthFlags values indicate which authentication settings
 * should be used.
 *
 * Before 1.22, this was wrongly marked as a enum and not as a flags
 * type.
 *
 * Since: 1.8
 */
typedef enum { /*< flags, underscore_name=nm_setting_802_1x_auth_flags >*/
               NM_SETTING_802_1X_AUTH_FLAGS_NONE            = 0,
               NM_SETTING_802_1X_AUTH_FLAGS_TLS_1_0_DISABLE = 0x1,
               NM_SETTING_802_1X_AUTH_FLAGS_TLS_1_1_DISABLE = 0x2,
               NM_SETTING_802_1X_AUTH_FLAGS_TLS_1_2_DISABLE = 0x4,

               NM_SETTING_802_1X_AUTH_FLAGS_ALL = 0x7,
} NMSetting8021xAuthFlags;

#define NM_TYPE_SETTING_802_1X (nm_setting_802_1x_get_type())
#define NM_SETTING_802_1X(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_SETTING_802_1X, NMSetting8021x))
#define NM_SETTING_802_1X_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_SETTING_802_1X, NMSetting8021xClass))
#define NM_IS_SETTING_802_1X(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_SETTING_802_1X))
#define NM_IS_SETTING_802_1X_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_SETTING_802_1X))
#define NM_SETTING_802_1X_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_SETTING_802_1X, NMSetting8021xClass))

#define NM_SETTING_802_1X_SETTING_NAME "802-1x"

#define NM_SETTING_802_1X_EAP                               "eap"
#define NM_SETTING_802_1X_IDENTITY                          "identity"
#define NM_SETTING_802_1X_ANONYMOUS_IDENTITY                "anonymous-identity"
#define NM_SETTING_802_1X_PAC_FILE                          "pac-file"
#define NM_SETTING_802_1X_CA_CERT                           "ca-cert"
#define NM_SETTING_802_1X_CA_CERT_PASSWORD                  "ca-cert-password"
#define NM_SETTING_802_1X_CA_CERT_PASSWORD_FLAGS            "ca-cert-password-flags"
#define NM_SETTING_802_1X_CA_PATH                           "ca-path"
#define NM_SETTING_802_1X_SUBJECT_MATCH                     "subject-match"
#define NM_SETTING_802_1X_ALTSUBJECT_MATCHES                "altsubject-matches"
#define NM_SETTING_802_1X_DOMAIN_SUFFIX_MATCH               "domain-suffix-match"
#define NM_SETTING_802_1X_DOMAIN_MATCH                      "domain-match"
#define NM_SETTING_802_1X_CLIENT_CERT                       "client-cert"
#define NM_SETTING_802_1X_CLIENT_CERT_PASSWORD              "client-cert-password"
#define NM_SETTING_802_1X_CLIENT_CERT_PASSWORD_FLAGS        "client-cert-password-flags"
#define NM_SETTING_802_1X_PHASE1_PEAPVER                    "phase1-peapver"
#define NM_SETTING_802_1X_PHASE1_PEAPLABEL                  "phase1-peaplabel"
#define NM_SETTING_802_1X_PHASE1_FAST_PROVISIONING          "phase1-fast-provisioning"
#define NM_SETTING_802_1X_PHASE1_AUTH_FLAGS                 "phase1-auth-flags"
#define NM_SETTING_802_1X_PHASE2_AUTH                       "phase2-auth"
#define NM_SETTING_802_1X_PHASE2_AUTHEAP                    "phase2-autheap"
#define NM_SETTING_802_1X_PHASE2_CA_CERT                    "phase2-ca-cert"
#define NM_SETTING_802_1X_PHASE2_CA_CERT_PASSWORD           "phase2-ca-cert-password"
#define NM_SETTING_802_1X_PHASE2_CA_CERT_PASSWORD_FLAGS     "phase2-ca-cert-password-flags"
#define NM_SETTING_802_1X_PHASE2_CA_PATH                    "phase2-ca-path"
#define NM_SETTING_802_1X_PHASE2_SUBJECT_MATCH              "phase2-subject-match"
#define NM_SETTING_802_1X_PHASE2_ALTSUBJECT_MATCHES         "phase2-altsubject-matches"
#define NM_SETTING_802_1X_PHASE2_DOMAIN_SUFFIX_MATCH        "phase2-domain-suffix-match"
#define NM_SETTING_802_1X_PHASE2_DOMAIN_MATCH               "phase2-domain-match"
#define NM_SETTING_802_1X_PHASE2_CLIENT_CERT                "phase2-client-cert"
#define NM_SETTING_802_1X_PHASE2_CLIENT_CERT_PASSWORD       "phase2-client-cert-password"
#define NM_SETTING_802_1X_PHASE2_CLIENT_CERT_PASSWORD_FLAGS "phase2-client-cert-password-flags"
#define NM_SETTING_802_1X_PASSWORD                          "password"
#define NM_SETTING_802_1X_PASSWORD_FLAGS                    "password-flags"
#define NM_SETTING_802_1X_PASSWORD_RAW                      "password-raw"
#define NM_SETTING_802_1X_PASSWORD_RAW_FLAGS                "password-raw-flags"
#define NM_SETTING_802_1X_PRIVATE_KEY                       "private-key"
#define NM_SETTING_802_1X_PRIVATE_KEY_PASSWORD              "private-key-password"
#define NM_SETTING_802_1X_PRIVATE_KEY_PASSWORD_FLAGS        "private-key-password-flags"
#define NM_SETTING_802_1X_PHASE2_PRIVATE_KEY                "phase2-private-key"
#define NM_SETTING_802_1X_PHASE2_PRIVATE_KEY_PASSWORD       "phase2-private-key-password"
#define NM_SETTING_802_1X_PHASE2_PRIVATE_KEY_PASSWORD_FLAGS "phase2-private-key-password-flags"
#define NM_SETTING_802_1X_PIN                               "pin"
#define NM_SETTING_802_1X_PIN_FLAGS                         "pin-flags"
#define NM_SETTING_802_1X_SYSTEM_CA_CERTS                   "system-ca-certs"
#define NM_SETTING_802_1X_AUTH_TIMEOUT                      "auth-timeout"
#define NM_SETTING_802_1X_OPTIONAL                          "optional"

/* PRIVATE KEY NOTE: when setting PKCS#12 private keys directly via properties
 * using the "blob" scheme, the data must be passed in PKCS#12 binary format.
 * In this case, the appropriate "client-cert" (or "phase2-client-cert")
 * property of the NMSetting8021x object must also contain the exact same
 * PKCS#12 binary data that the private key does.  This is because the
 * PKCS#12 file contains both the private key and client certificate, so both
 * properties need to be set to the same thing.  When using the "path" scheme,
 * just set both the private-key and client-cert properties to the same path.
 *
 * When setting OpenSSL-derived "traditional" format (ie S/MIME style, not
 * PKCS#8) RSA and DSA keys directly via properties with the "blob" scheme, they
 * should be passed to NetworkManager in PEM format with the "DEK-Info" and
 * "Proc-Type" tags intact.  Decrypted private keys should not be used as this
 * is insecure and could allow unprivileged users to access the decrypted
 * private key data.
 *
 * When using the "path" scheme, just set the private-key and client-cert
 * properties to the paths to their respective objects.
 */

typedef struct _NMSetting8021xClass NMSetting8021xClass;

GType nm_setting_802_1x_get_type(void);

NMSetting *nm_setting_802_1x_new(void);

NM_AVAILABLE_IN_1_2
NMSetting8021xCKScheme
nm_setting_802_1x_check_cert_scheme(gconstpointer pdata, gsize length, GError **error);

guint32     nm_setting_802_1x_get_num_eap_methods(NMSetting8021x *setting);
const char *nm_setting_802_1x_get_eap_method(NMSetting8021x *setting, guint32 i);
gboolean    nm_setting_802_1x_add_eap_method(NMSetting8021x *setting, const char *eap);
void        nm_setting_802_1x_remove_eap_method(NMSetting8021x *setting, guint32 i);
gboolean    nm_setting_802_1x_remove_eap_method_by_value(NMSetting8021x *setting, const char *eap);
void        nm_setting_802_1x_clear_eap_methods(NMSetting8021x *setting);

const char *nm_setting_802_1x_get_identity(NMSetting8021x *setting);

const char *nm_setting_802_1x_get_anonymous_identity(NMSetting8021x *setting);

const char *nm_setting_802_1x_get_pac_file(NMSetting8021x *setting);

gboolean    nm_setting_802_1x_get_system_ca_certs(NMSetting8021x *setting);
const char *nm_setting_802_1x_get_ca_path(NMSetting8021x *setting);
const char *nm_setting_802_1x_get_phase2_ca_path(NMSetting8021x *setting);

NMSetting8021xCKScheme nm_setting_802_1x_get_ca_cert_scheme(NMSetting8021x *setting);
GBytes                *nm_setting_802_1x_get_ca_cert_blob(NMSetting8021x *setting);
const char            *nm_setting_802_1x_get_ca_cert_path(NMSetting8021x *setting);
NM_AVAILABLE_IN_1_6
const char *nm_setting_802_1x_get_ca_cert_uri(NMSetting8021x *setting);
gboolean    nm_setting_802_1x_set_ca_cert(NMSetting8021x         *setting,
                                          const char             *value,
                                          NMSetting8021xCKScheme  scheme,
                                          NMSetting8021xCKFormat *out_format,
                                          GError                **error);

NM_AVAILABLE_IN_1_8
const char *nm_setting_802_1x_get_ca_cert_password(NMSetting8021x *setting);
NM_AVAILABLE_IN_1_8
NMSettingSecretFlags nm_setting_802_1x_get_ca_cert_password_flags(NMSetting8021x *setting);

const char *nm_setting_802_1x_get_subject_match(NMSetting8021x *setting);

guint32     nm_setting_802_1x_get_num_altsubject_matches(NMSetting8021x *setting);
const char *nm_setting_802_1x_get_altsubject_match(NMSetting8021x *setting, guint32 i);
gboolean    nm_setting_802_1x_add_altsubject_match(NMSetting8021x *setting,
                                                   const char     *altsubject_match);
void        nm_setting_802_1x_remove_altsubject_match(NMSetting8021x *setting, guint32 i);
gboolean    nm_setting_802_1x_remove_altsubject_match_by_value(NMSetting8021x *setting,
                                                               const char     *altsubject_match);
void        nm_setting_802_1x_clear_altsubject_matches(NMSetting8021x *setting);
NM_AVAILABLE_IN_1_2
const char *nm_setting_802_1x_get_domain_suffix_match(NMSetting8021x *setting);

NM_AVAILABLE_IN_1_24
const char *nm_setting_802_1x_get_domain_match(NMSetting8021x *setting);

NMSetting8021xCKScheme nm_setting_802_1x_get_client_cert_scheme(NMSetting8021x *setting);
GBytes                *nm_setting_802_1x_get_client_cert_blob(NMSetting8021x *setting);
const char            *nm_setting_802_1x_get_client_cert_path(NMSetting8021x *setting);
NM_AVAILABLE_IN_1_6
const char *nm_setting_802_1x_get_client_cert_uri(NMSetting8021x *setting);
gboolean    nm_setting_802_1x_set_client_cert(NMSetting8021x         *setting,
                                              const char             *value,
                                              NMSetting8021xCKScheme  scheme,
                                              NMSetting8021xCKFormat *out_format,
                                              GError                **error);

NM_AVAILABLE_IN_1_8
const char *nm_setting_802_1x_get_client_cert_password(NMSetting8021x *setting);
NM_AVAILABLE_IN_1_8
NMSettingSecretFlags nm_setting_802_1x_get_client_cert_password_flags(NMSetting8021x *setting);

const char *nm_setting_802_1x_get_phase1_peapver(NMSetting8021x *setting);

const char *nm_setting_802_1x_get_phase1_peaplabel(NMSetting8021x *setting);

const char *nm_setting_802_1x_get_phase1_fast_provisioning(NMSetting8021x *setting);

const char *nm_setting_802_1x_get_phase2_auth(NMSetting8021x *setting);

const char *nm_setting_802_1x_get_phase2_autheap(NMSetting8021x *setting);

NMSetting8021xCKScheme nm_setting_802_1x_get_phase2_ca_cert_scheme(NMSetting8021x *setting);
GBytes                *nm_setting_802_1x_get_phase2_ca_cert_blob(NMSetting8021x *setting);
const char            *nm_setting_802_1x_get_phase2_ca_cert_path(NMSetting8021x *setting);
NM_AVAILABLE_IN_1_6
const char *nm_setting_802_1x_get_phase2_ca_cert_uri(NMSetting8021x *setting);
gboolean    nm_setting_802_1x_set_phase2_ca_cert(NMSetting8021x         *setting,
                                                 const char             *value,
                                                 NMSetting8021xCKScheme  scheme,
                                                 NMSetting8021xCKFormat *out_format,
                                                 GError                **error);

NM_AVAILABLE_IN_1_8
const char *nm_setting_802_1x_get_phase2_ca_cert_password(NMSetting8021x *setting);
NM_AVAILABLE_IN_1_8
NMSettingSecretFlags nm_setting_802_1x_get_phase2_ca_cert_password_flags(NMSetting8021x *setting);

const char *nm_setting_802_1x_get_phase2_subject_match(NMSetting8021x *setting);

guint32     nm_setting_802_1x_get_num_phase2_altsubject_matches(NMSetting8021x *setting);
const char *nm_setting_802_1x_get_phase2_altsubject_match(NMSetting8021x *setting, guint32 i);
gboolean    nm_setting_802_1x_add_phase2_altsubject_match(NMSetting8021x *setting,
                                                          const char     *phase2_altsubject_match);
void        nm_setting_802_1x_remove_phase2_altsubject_match(NMSetting8021x *setting, guint32 i);
gboolean
     nm_setting_802_1x_remove_phase2_altsubject_match_by_value(NMSetting8021x *setting,
                                                               const char     *phase2_altsubject_match);
void nm_setting_802_1x_clear_phase2_altsubject_matches(NMSetting8021x *setting);
NM_AVAILABLE_IN_1_2
const char *nm_setting_802_1x_get_phase2_domain_suffix_match(NMSetting8021x *setting);

NM_AVAILABLE_IN_1_24
const char *nm_setting_802_1x_get_phase2_domain_match(NMSetting8021x *setting);

NMSetting8021xCKScheme nm_setting_802_1x_get_phase2_client_cert_scheme(NMSetting8021x *setting);
GBytes                *nm_setting_802_1x_get_phase2_client_cert_blob(NMSetting8021x *setting);
const char            *nm_setting_802_1x_get_phase2_client_cert_path(NMSetting8021x *setting);
NM_AVAILABLE_IN_1_6
const char *nm_setting_802_1x_get_phase2_client_cert_uri(NMSetting8021x *setting);
gboolean    nm_setting_802_1x_set_phase2_client_cert(NMSetting8021x         *setting,
                                                     const char             *value,
                                                     NMSetting8021xCKScheme  scheme,
                                                     NMSetting8021xCKFormat *out_format,
                                                     GError                **error);

NM_AVAILABLE_IN_1_8
const char *nm_setting_802_1x_get_phase2_client_cert_password(NMSetting8021x *setting);
NM_AVAILABLE_IN_1_8
NMSettingSecretFlags
nm_setting_802_1x_get_phase2_client_cert_password_flags(NMSetting8021x *setting);

const char          *nm_setting_802_1x_get_password(NMSetting8021x *setting);
NMSettingSecretFlags nm_setting_802_1x_get_password_flags(NMSetting8021x *setting);
GBytes              *nm_setting_802_1x_get_password_raw(NMSetting8021x *setting);
NMSettingSecretFlags nm_setting_802_1x_get_password_raw_flags(NMSetting8021x *setting);

const char          *nm_setting_802_1x_get_pin(NMSetting8021x *setting);
NMSettingSecretFlags nm_setting_802_1x_get_pin_flags(NMSetting8021x *setting);

NMSetting8021xCKScheme nm_setting_802_1x_get_private_key_scheme(NMSetting8021x *setting);
GBytes                *nm_setting_802_1x_get_private_key_blob(NMSetting8021x *setting);
const char            *nm_setting_802_1x_get_private_key_path(NMSetting8021x *setting);
NM_AVAILABLE_IN_1_6
const char          *nm_setting_802_1x_get_private_key_uri(NMSetting8021x *setting);
gboolean             nm_setting_802_1x_set_private_key(NMSetting8021x         *setting,
                                                       const char             *value,
                                                       const char             *password,
                                                       NMSetting8021xCKScheme  scheme,
                                                       NMSetting8021xCKFormat *out_format,
                                                       GError                **error);
const char          *nm_setting_802_1x_get_private_key_password(NMSetting8021x *setting);
NMSettingSecretFlags nm_setting_802_1x_get_private_key_password_flags(NMSetting8021x *setting);

NMSetting8021xCKFormat nm_setting_802_1x_get_private_key_format(NMSetting8021x *setting);

NMSetting8021xCKScheme nm_setting_802_1x_get_phase2_private_key_scheme(NMSetting8021x *setting);
GBytes                *nm_setting_802_1x_get_phase2_private_key_blob(NMSetting8021x *setting);
const char            *nm_setting_802_1x_get_phase2_private_key_path(NMSetting8021x *setting);
NM_AVAILABLE_IN_1_6
const char *nm_setting_802_1x_get_phase2_private_key_uri(NMSetting8021x *setting);
gboolean    nm_setting_802_1x_set_phase2_private_key(NMSetting8021x         *setting,
                                                     const char             *value,
                                                     const char             *password,
                                                     NMSetting8021xCKScheme  scheme,
                                                     NMSetting8021xCKFormat *out_format,
                                                     GError                **error);
const char *nm_setting_802_1x_get_phase2_private_key_password(NMSetting8021x *setting);
NMSettingSecretFlags
nm_setting_802_1x_get_phase2_private_key_password_flags(NMSetting8021x *setting);

NMSetting8021xCKFormat nm_setting_802_1x_get_phase2_private_key_format(NMSetting8021x *setting);

NM_AVAILABLE_IN_1_8
NMSetting8021xAuthFlags nm_setting_802_1x_get_phase1_auth_flags(NMSetting8021x *setting);
NM_AVAILABLE_IN_1_8
int nm_setting_802_1x_get_auth_timeout(NMSetting8021x *setting);
NM_AVAILABLE_IN_1_22
gboolean nm_setting_802_1x_get_optional(NMSetting8021x *setting);

G_END_DECLS

#endif /* __NM_SETTING_8021X_H__ */
