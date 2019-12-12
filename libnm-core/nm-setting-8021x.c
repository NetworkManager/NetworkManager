// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2007 - 2013 Red Hat, Inc.
 * Copyright (C) 2007 - 2008 Novell, Inc.
 */

#include "nm-default.h"

#include "nm-setting-8021x.h"

#include "nm-glib-aux/nm-secret-utils.h"
#include "nm-utils.h"
#include "nm-crypto.h"
#include "nm-utils-private.h"
#include "nm-setting-private.h"
#include "nm-core-enum-types.h"

/**
 * SECTION:nm-setting-8021x
 * @short_description: Describes 802.1x-authenticated connection properties
 *
 * The #NMSetting8021x object is a #NMSetting subclass that describes
 * properties necessary for connection to 802.1x-authenticated networks, such as
 * WPA and WPA2 Enterprise Wi-Fi networks and wired 802.1x networks.  802.1x
 * connections typically use certificates and/or EAP authentication methods to
 * securely verify, identify, and authenticate the client to the network itself,
 * instead of simply relying on a widely shared static key.
 *
 * It's a good idea to read up on wpa_supplicant configuration before using this
 * setting extensively, since most of the options here correspond closely with
 * the relevant wpa_supplicant configuration options.
 *
 * Furthermore, to get a good idea of 802.1x, EAP, TLS, TTLS, etc and their
 * applications to Wi-Fi and wired networks, you'll want to get copies of the
 * following books.
 *
 *  802.11 Wireless Networks: The Definitive Guide, Second Edition
 *       Author: Matthew Gast
 *       ISBN: 978-0596100520
 *
 *  Cisco Wireless LAN Security
 *       Authors: Krishna Sankar, Sri Sundaralingam, Darrin Miller, and Andrew Balinsky
 *       ISBN: 978-1587051548
 **/

/*****************************************************************************/

static NMSetting8021xCKFormat
_crypto_format_to_ck (NMCryptoFileFormat format)
{
	G_STATIC_ASSERT ( (NM_SETTING_802_1X_CK_FORMAT_UNKNOWN == (NMSetting8021xCKFormat) NM_CRYPTO_FILE_FORMAT_UNKNOWN) );
	G_STATIC_ASSERT ( (NM_SETTING_802_1X_CK_FORMAT_X509    == (NMSetting8021xCKFormat) NM_CRYPTO_FILE_FORMAT_X509) );
	G_STATIC_ASSERT ( (NM_SETTING_802_1X_CK_FORMAT_RAW_KEY == (NMSetting8021xCKFormat) NM_CRYPTO_FILE_FORMAT_RAW_KEY) );
	G_STATIC_ASSERT ( (NM_SETTING_802_1X_CK_FORMAT_PKCS12  == (NMSetting8021xCKFormat) NM_CRYPTO_FILE_FORMAT_PKCS12) );

	nm_assert (NM_IN_SET (format, NM_CRYPTO_FILE_FORMAT_UNKNOWN,
	                              NM_CRYPTO_FILE_FORMAT_X509,
	                              NM_CRYPTO_FILE_FORMAT_RAW_KEY,
	                              NM_CRYPTO_FILE_FORMAT_PKCS12));
	return (NMSetting8021xCKFormat) format;
}

/*****************************************************************************/

typedef void (*EAPMethodNeedSecretsFunc) (NMSetting8021x *self,
                                          GPtrArray *secrets,
                                          gboolean phase2);

typedef gboolean (*EAPMethodValidateFunc)(NMSetting8021x *self,
                                          gboolean phase2,
                                          GError **error);

typedef struct {
	const char *method;
	EAPMethodNeedSecretsFunc ns_func;
	EAPMethodValidateFunc v_func;
} EAPMethodsTable;

static const EAPMethodsTable eap_methods_table[];

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE (NMSetting8021x,
	PROP_EAP,
	PROP_IDENTITY,
	PROP_ANONYMOUS_IDENTITY,
	PROP_PAC_FILE,
	PROP_CA_CERT,
	PROP_CA_CERT_PASSWORD,
	PROP_CA_CERT_PASSWORD_FLAGS,
	PROP_CA_PATH,
	PROP_SUBJECT_MATCH,
	PROP_ALTSUBJECT_MATCHES,
	PROP_DOMAIN_SUFFIX_MATCH,
	PROP_CLIENT_CERT,
	PROP_CLIENT_CERT_PASSWORD,
	PROP_CLIENT_CERT_PASSWORD_FLAGS,
	PROP_PHASE1_PEAPVER,
	PROP_PHASE1_PEAPLABEL,
	PROP_PHASE1_FAST_PROVISIONING,
	PROP_PHASE1_AUTH_FLAGS,
	PROP_PHASE2_AUTH,
	PROP_PHASE2_AUTHEAP,
	PROP_PHASE2_CA_CERT,
	PROP_PHASE2_CA_CERT_PASSWORD,
	PROP_PHASE2_CA_CERT_PASSWORD_FLAGS,
	PROP_PHASE2_CA_PATH,
	PROP_PHASE2_SUBJECT_MATCH,
	PROP_PHASE2_ALTSUBJECT_MATCHES,
	PROP_PHASE2_DOMAIN_SUFFIX_MATCH,
	PROP_PHASE2_CLIENT_CERT,
	PROP_PHASE2_CLIENT_CERT_PASSWORD,
	PROP_PHASE2_CLIENT_CERT_PASSWORD_FLAGS,
	PROP_PASSWORD,
	PROP_PASSWORD_FLAGS,
	PROP_PASSWORD_RAW,
	PROP_PASSWORD_RAW_FLAGS,
	PROP_PRIVATE_KEY,
	PROP_PRIVATE_KEY_PASSWORD,
	PROP_PRIVATE_KEY_PASSWORD_FLAGS,
	PROP_PHASE2_PRIVATE_KEY,
	PROP_PHASE2_PRIVATE_KEY_PASSWORD,
	PROP_PHASE2_PRIVATE_KEY_PASSWORD_FLAGS,
	PROP_PIN,
	PROP_PIN_FLAGS,
	PROP_SYSTEM_CA_CERTS,
	PROP_OPTIONAL,
	PROP_AUTH_TIMEOUT,
);

typedef struct {
	GSList *eap; /* GSList of strings */
	char *identity;
	char *anonymous_identity;
	char *pac_file;
	GBytes *ca_cert;
	char *ca_cert_password;
	char *ca_path;
	char *subject_match;
	GSList *altsubject_matches;
	char *domain_suffix_match;
	GBytes *client_cert;
	char *client_cert_password;
	char *phase1_peapver;
	char *phase1_peaplabel;
	char *phase1_fast_provisioning;
	char *phase2_auth;
	char *phase2_autheap;
	GBytes *phase2_ca_cert;
	char *phase2_ca_cert_password;
	char *phase2_ca_path;
	char *phase2_subject_match;
	GSList *phase2_altsubject_matches;
	char *phase2_domain_suffix_match;
	GBytes *phase2_client_cert;
	char *phase2_client_cert_password;
	char *password;
	GBytes *password_raw;
	char *pin;
	GBytes *private_key;
	char *private_key_password;
	GBytes *phase2_private_key;
	char *phase2_private_key_password;
	int auth_timeout;
	NMSetting8021xAuthFlags phase1_auth_flags;
	NMSettingSecretFlags ca_cert_password_flags;
	NMSettingSecretFlags client_cert_password_flags;
	NMSettingSecretFlags phase2_ca_cert_password_flags;
	NMSettingSecretFlags phase2_client_cert_password_flags;
	NMSettingSecretFlags password_flags;
	NMSettingSecretFlags password_raw_flags;
	NMSettingSecretFlags pin_flags;
	NMSettingSecretFlags private_key_password_flags;
	NMSettingSecretFlags phase2_private_key_password_flags;
	bool optional:1;
	bool system_ca_certs:1;
} NMSetting8021xPrivate;

G_DEFINE_TYPE (NMSetting8021x, nm_setting_802_1x, NM_TYPE_SETTING)

#define NM_SETTING_802_1X_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_802_1X, NMSetting8021xPrivate))

/*****************************************************************************/

/**
 * nm_setting_802_1x_check_cert_scheme:
 * @pdata: (allow-none): the data pointer
 * @length: the length of the data
 * @error: (allow-none) (out): validation reason
 *
 * Determines and verifies the blob type.
 * When setting certificate properties of NMSetting8021x
 * the blob must be not UNKNOWN (or NULL).
 *
 * Returns: the scheme of the blob or %NM_SETTING_802_1X_CK_SCHEME_UNKNOWN.
 * For NULL it also returns NM_SETTING_802_1X_CK_SCHEME_UNKNOWN.
 *
 * Since: 1.2
 **/
NMSetting8021xCKScheme
nm_setting_802_1x_check_cert_scheme (gconstpointer pdata, gsize length, GError **error)
{
	const char *data = pdata;
	NMSetting8021xCKScheme scheme;
	gsize prefix_length;

	g_return_val_if_fail (!length || data, NM_SETTING_802_1X_CK_SCHEME_UNKNOWN);

	if (!length || !data) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("binary data missing"));
		return NM_SETTING_802_1X_CK_SCHEME_UNKNOWN;
	}

	if (   length >= NM_STRLEN (NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PATH)
	    && !memcmp (data, NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PATH, NM_STRLEN (NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PATH))) {
		scheme = NM_SETTING_802_1X_CK_SCHEME_PATH;
		prefix_length = NM_STRLEN (NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PATH);
	} else if (   length >= NM_STRLEN (NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PKCS11)
	           && !memcmp (data, NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PKCS11, NM_STRLEN (NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PKCS11))) {
		scheme = NM_SETTING_802_1X_CK_SCHEME_PKCS11;
		prefix_length = NM_STRLEN (NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PKCS11);
	} else {
		scheme = NM_SETTING_802_1X_CK_SCHEME_BLOB;
		prefix_length = 0;
	}

	if (scheme != NM_SETTING_802_1X_CK_SCHEME_BLOB) {
		/* An actual URI must be NUL terminated, contain at least
		 * one non-NUL character, and contain only one trailing NUL
		 * character.
		 * And ensure it's UTF-8 valid too so we can pass it through
		 * D-Bus and stuff like that. */

		if (data[length - 1] != '\0') {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     _("URI not NUL terminated"));
			return NM_SETTING_802_1X_CK_SCHEME_UNKNOWN;
		}
		length--;

		if (length <= prefix_length) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     _("URI is empty"));
			return NM_SETTING_802_1X_CK_SCHEME_UNKNOWN;
		}

		if (!g_utf8_validate (data + prefix_length, length - prefix_length, NULL)) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     _("URI is not valid UTF-8"));
			return NM_SETTING_802_1X_CK_SCHEME_UNKNOWN;
		}
	}

	return scheme;
}

NMSetting8021xCKScheme
_nm_setting_802_1x_cert_get_scheme (GBytes *bytes, GError **error)
{
	const char *data;
	gsize length;

	if (!bytes) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("data missing"));
		return NM_SETTING_802_1X_CK_SCHEME_UNKNOWN;
	}

	data = g_bytes_get_data (bytes, &length);
	return nm_setting_802_1x_check_cert_scheme (data, length, error);
}

static gboolean
_cert_verify_scheme (NMSetting8021xCKScheme scheme,
                     GBytes *bytes,
                     GError **error)
{
	GError *local = NULL;
	NMSetting8021xCKScheme scheme_detected;

	nm_assert (bytes);

	scheme_detected = _nm_setting_802_1x_cert_get_scheme (bytes, &local);
	if (scheme_detected == NM_SETTING_802_1X_CK_SCHEME_UNKNOWN) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("certificate is invalid: %s"), local->message);
		return FALSE;
	}

	if (scheme_detected != scheme) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("certificate detected as invalid scheme"));
		return FALSE;
	}

	return TRUE;
}

GBytes *
_nm_setting_802_1x_cert_value_to_bytes (NMSetting8021xCKScheme scheme,
                                        const guint8 *val_bin,
                                        gssize val_len,
                                        GError **error)
{
	gs_unref_bytes GBytes *bytes = NULL;
	guint8 *mem;
	gsize total_len;

	nm_assert (val_bin);

	switch (scheme) {
	case NM_SETTING_802_1X_CK_SCHEME_PKCS11:
		if (val_len < 0)
			val_len = strlen ((char *) val_bin) + 1;

		bytes = g_bytes_new (val_bin, val_len);
		break;
	case NM_SETTING_802_1X_CK_SCHEME_PATH:
		if (val_len < 0)
			val_len = strlen ((char *) val_bin) + 1;

		total_len = NM_STRLEN (NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PATH) + ((gsize) val_len);

		mem = g_new (guint8, total_len);
		memcpy (mem, NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PATH, NM_STRLEN (NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PATH));
		memcpy (&mem[NM_STRLEN (NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PATH)], val_bin, val_len);
		bytes = g_bytes_new_take (mem, total_len);
		break;
	default:
		g_return_val_if_reached (NULL);
	}

	if (!_cert_verify_scheme (scheme, bytes, error))
		return NULL;

	return g_steal_pointer (&bytes);
}

static const char *
_cert_get_path (GBytes *bytes)
{
	const guint8 *bin;

	nm_assert (bytes);
	nm_assert (g_bytes_get_size (bytes) >= NM_STRLEN (NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PATH));

	bin = g_bytes_get_data (bytes, NULL);

	nm_assert (bin);
	nm_assert (bin[g_bytes_get_size (bytes) - 1] == '\0');
	nm_assert (g_str_has_prefix ((const char *) bin, NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PATH));

	return (const char *) &bin[NM_STRLEN (NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PATH)];
}

#define _cert_assert_scheme(cert, check_scheme, ret_val) \
	G_STMT_START { \
		NMSetting8021xCKScheme scheme; \
		\
		scheme = _nm_setting_802_1x_cert_get_scheme ((cert), NULL); \
		if (scheme != check_scheme) { \
			g_return_val_if_fail (scheme == check_scheme, ret_val); \
			return ret_val; \
		} \
	} G_STMT_END

#define _cert_impl_get_scheme(setting, cert_field) \
	G_STMT_START { \
		NMSetting8021x *const _setting = (setting); \
		GBytes *_cert; \
		\
		g_return_val_if_fail (NM_IS_SETTING_802_1X (_setting), NM_SETTING_802_1X_CK_SCHEME_UNKNOWN); \
		\
		_cert = NM_SETTING_802_1X_GET_PRIVATE (_setting)->cert_field; \
		\
		return _nm_setting_802_1x_cert_get_scheme (_cert, NULL); \
	} G_STMT_END

#define _cert_impl_get_blob(setting, cert_field) \
	G_STMT_START { \
		NMSetting8021x *const _setting = (setting); \
		GBytes *_cert; \
		\
		g_return_val_if_fail (NM_IS_SETTING_802_1X (_setting), NULL); \
		\
		_cert = NM_SETTING_802_1X_GET_PRIVATE (_setting)->cert_field; \
		\
		_cert_assert_scheme (_cert, NM_SETTING_802_1X_CK_SCHEME_BLOB, NULL); \
		\
		return _cert; \
	} G_STMT_END

#define _cert_impl_get_path(setting, cert_field) \
	G_STMT_START { \
		NMSetting8021x *const _setting = (setting); \
		GBytes *_cert; \
		\
		g_return_val_if_fail (NM_IS_SETTING_802_1X (_setting), NULL); \
		\
		_cert = NM_SETTING_802_1X_GET_PRIVATE (_setting)->cert_field; \
		\
		_cert_assert_scheme (_cert, NM_SETTING_802_1X_CK_SCHEME_PATH, NULL); \
		\
		return _cert_get_path (_cert); \
	} G_STMT_END

#define _cert_impl_get_uri(setting, cert_field) \
	G_STMT_START { \
		NMSetting8021x *const _setting = (setting); \
		GBytes *_cert; \
		\
		g_return_val_if_fail (NM_IS_SETTING_802_1X (_setting), NULL); \
		\
		_cert = NM_SETTING_802_1X_GET_PRIVATE (_setting)->cert_field; \
		\
		_cert_assert_scheme (_cert, NM_SETTING_802_1X_CK_SCHEME_PKCS11, NULL); \
		\
		return g_bytes_get_data (_cert, NULL); \
	} G_STMT_END

static gboolean
_cert_impl_set (NMSetting8021x *setting,
                _PropertyEnums property,
                const char *value,
                const char *password,
                NMSetting8021xCKScheme scheme,
                NMSetting8021xCKFormat *out_format,
                GError **error)
{
	NMSetting8021xPrivate *priv;
	NMCryptoFileFormat format = NM_CRYPTO_FILE_FORMAT_UNKNOWN;
	gs_unref_bytes GBytes *cert = NULL;
	GBytes **p_cert = NULL;
	GBytes **p_client_cert = NULL;
	char **p_password = NULL;
	_PropertyEnums notify_cert = property;
	_PropertyEnums notify_password = PROP_0;
	_PropertyEnums notify_client_cert = PROP_0;

	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);
	if (value) {
		g_return_val_if_fail (g_utf8_validate (value, -1, NULL), FALSE);
		g_return_val_if_fail (NM_IN_SET (scheme, NM_SETTING_802_1X_CK_SCHEME_BLOB,
		                                         NM_SETTING_802_1X_CK_SCHEME_PATH,
		                                         NM_SETTING_802_1X_CK_SCHEME_PKCS11), FALSE);
	}

	if (!value) {
		/* coerce password to %NULL. It should be already. */
		password = NULL;
	}

	priv = NM_SETTING_802_1X_GET_PRIVATE (setting);

	if (!value) {
		/* pass. */
	} else if (scheme == NM_SETTING_802_1X_CK_SCHEME_PKCS11) {
		cert = _nm_setting_802_1x_cert_value_to_bytes (scheme, (guint8 *) value, -1, error);
		if (!cert)
			goto err;
	} else {
		gs_unref_bytes GBytes *file = NULL;

		if (NM_IN_SET (property, PROP_PRIVATE_KEY,
		                         PROP_PHASE2_PRIVATE_KEY)) {
			file = nm_crypto_read_file (value, error);
			if (!file)
				goto err;
			format = nm_crypto_verify_private_key_data (g_bytes_get_data (file, NULL),
			                                            g_bytes_get_size (file),
			                                            password,
			                                            NULL,
			                                            error);
			if (format == NM_CRYPTO_FILE_FORMAT_UNKNOWN)
				goto err;
		} else {
			if (!nm_crypto_load_and_verify_certificate (value, &format, &file, error))
				goto err;
		}

		nm_assert (format != NM_CRYPTO_FILE_FORMAT_UNKNOWN);
		nm_assert (file);

		if (scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB) {
			cert = g_steal_pointer (&file);
			if (!_cert_verify_scheme (scheme, cert, error))
				goto err;
		} else {
			cert = _nm_setting_802_1x_cert_value_to_bytes (scheme, (guint8 *) value, -1, error);
			if (!cert)
				goto err;
		}
	}

	switch (property) {
	case PROP_CA_CERT:
	case PROP_PHASE2_CA_CERT:
		if (   value
		    && scheme != NM_SETTING_802_1X_CK_SCHEME_PKCS11
		    && format != NM_CRYPTO_FILE_FORMAT_X509) {
			/* wpa_supplicant can only use raw x509 CA certs */
			g_set_error_literal (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("CA certificate must be in X.509 format"));
			goto err;
		}
		p_cert = (property == PROP_CA_CERT)
		         ? &priv->ca_cert
		         : &priv->phase2_ca_cert;
		break;
	case PROP_CLIENT_CERT:
	case PROP_PHASE2_CLIENT_CERT:
		if (   value
		    && scheme != NM_SETTING_802_1X_CK_SCHEME_PKCS11
		    && !NM_IN_SET (format, NM_CRYPTO_FILE_FORMAT_X509,
		                           NM_CRYPTO_FILE_FORMAT_PKCS12)) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     _("invalid certificate format"));
			goto err;
		}
		p_cert = (property == PROP_CLIENT_CERT)
		         ? &priv->client_cert
		         : &priv->phase2_client_cert;
		break;
	case PROP_PRIVATE_KEY:
		p_cert = &priv->private_key;
		p_password = &priv->private_key_password;
		p_client_cert = &priv->client_cert;
		notify_password = PROP_PRIVATE_KEY_PASSWORD;
		notify_client_cert = PROP_CLIENT_CERT;
		break;
	case PROP_PHASE2_PRIVATE_KEY:
		p_cert = &priv->phase2_private_key;
		p_password = &priv->phase2_private_key_password;
		p_client_cert = &priv->phase2_client_cert;
		notify_password = PROP_PHASE2_PRIVATE_KEY_PASSWORD;
		notify_client_cert = PROP_PHASE2_CLIENT_CERT;
		break;
	default:
		nm_assert_not_reached ();
		break;
	}

	/* As required by NM and wpa_supplicant, set the client-cert
	 * property to the same PKCS#12 data.
	 */
	if (   cert
	    && p_client_cert
	    && format == NM_CRYPTO_FILE_FORMAT_PKCS12
	    && !nm_gbytes_equal0 (cert, *p_client_cert)) {
		g_bytes_unref (*p_client_cert);
		*p_client_cert = g_bytes_ref (cert);
	} else
		notify_client_cert = PROP_0;

	if (   p_cert
	    && !nm_gbytes_equal0 (cert, *p_cert)) {
		g_bytes_unref (*p_cert);
		*p_cert = g_steal_pointer (&cert);
	} else
		notify_cert = PROP_0;

	if (   p_password
	    && !nm_streq0 (password, *p_password)) {
		nm_free_secret (*p_password);
		*p_password = g_strdup (password);
	} else
		notify_password = PROP_0;

	nm_gobject_notify_together (setting, notify_cert,
	                                     notify_password,
	                                     notify_client_cert);

	NM_SET_OUT (out_format, _crypto_format_to_ck (format));
	return TRUE;

err:
	g_prefix_error (error,
	                "%s.%s: ",
	                NM_SETTING_802_1X_SETTING_NAME,
	                obj_properties[property]->name);
	NM_SET_OUT (out_format, NM_SETTING_802_1X_CK_FORMAT_UNKNOWN);
	return FALSE;
}

static NMSetting8021xCKFormat
_cert_impl_get_key_format_from_bytes (GBytes *private_key)
{
	const char *path;
	GError *error = NULL;

	if (!private_key)
		return NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;

	switch (_nm_setting_802_1x_cert_get_scheme (private_key, NULL)) {
	case NM_SETTING_802_1X_CK_SCHEME_BLOB:
		if (nm_crypto_is_pkcs12_data (g_bytes_get_data (private_key, NULL),
		                              g_bytes_get_size (private_key),
		                              NULL))
			return NM_SETTING_802_1X_CK_FORMAT_PKCS12;
		return NM_SETTING_802_1X_CK_FORMAT_RAW_KEY;
	case NM_SETTING_802_1X_CK_SCHEME_PATH:
		path = _cert_get_path (private_key);
		if (nm_crypto_is_pkcs12_file (path, &error))
			return NM_SETTING_802_1X_CK_FORMAT_PKCS12;
		if (error && error->domain == G_FILE_ERROR) {
			g_error_free (error);
			return NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;
		}
		g_error_free (error);
		return NM_SETTING_802_1X_CK_FORMAT_RAW_KEY;
	default:
		break;
	}

	return NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;
}
#define _cert_impl_get_key_format(setting, private_key_field) \
	({ \
		NMSetting8021x *_setting = (setting); \
		NMSetting8021xPrivate *_priv; \
		\
		g_return_val_if_fail (NM_IS_SETTING_802_1X (_setting), NM_SETTING_802_1X_CK_FORMAT_UNKNOWN); \
		\
		_priv = NM_SETTING_802_1X_GET_PRIVATE (_setting); \
		_cert_impl_get_key_format_from_bytes (_priv->private_key_field); \
	})

static gboolean
_cert_verify_property (GBytes *bytes,
                       const char *prop_name,
                       const char *password,
                       const char *password_prop_name,
                       GError **error)
{
	GError *local = NULL;
	NMSetting8021xCKScheme scheme;

	if (!bytes)
		return TRUE;

	scheme = _nm_setting_802_1x_cert_get_scheme (bytes, &local);
	if (scheme == NM_SETTING_802_1X_CK_SCHEME_UNKNOWN) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("certificate is invalid: %s"), local->message);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, prop_name);
		g_error_free (local);
		return FALSE;
	}

	if (password && (scheme != NM_SETTING_802_1X_CK_SCHEME_PKCS11)) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("password is not supported when certificate is not on a PKCS#11 token"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, password_prop_name);
		return FALSE;
	}

	return TRUE;
}

/*****************************************************************************/

/**
 * nm_setting_802_1x_get_num_eap_methods:
 * @setting: the #NMSetting8021x
 *
 * Returns the number of eap methods allowed for use when connecting to the
 * network.  Generally only one EAP method is used.  Use the functions
 * nm_setting_802_1x_get_eap_method(), nm_setting_802_1x_add_eap_method(),
 * and nm_setting_802_1x_remove_eap_method() for adding, removing, and retrieving
 * allowed EAP methods.
 *
 * Returns: the number of allowed EAP methods
 **/
guint32
nm_setting_802_1x_get_num_eap_methods (NMSetting8021x *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), 0);

	return g_slist_length (NM_SETTING_802_1X_GET_PRIVATE (setting)->eap);
}

/**
 * nm_setting_802_1x_get_eap_method:
 * @setting: the #NMSetting8021x
 * @i: the index of the EAP method name to return
 *
 * Returns the name of the allowed EAP method at index @i.
 *
 * Returns: the name of the allowed EAP method at index @i
 **/
const char *
nm_setting_802_1x_get_eap_method (NMSetting8021x *setting, guint32 i)
{
	NMSetting8021xPrivate *priv;

	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NULL);

	priv = NM_SETTING_802_1X_GET_PRIVATE (setting);
	g_return_val_if_fail (i <= g_slist_length (priv->eap), NULL);

	return (const char *) g_slist_nth_data (priv->eap, i);
}

/**
 * nm_setting_802_1x_add_eap_method:
 * @setting: the #NMSetting8021x
 * @eap: the name of the EAP method to allow for this connection
 *
 * Adds an allowed EAP method.  The setting is not valid until at least one
 * EAP method has been added.  See #NMSetting8021x:eap property for a list of
 * allowed EAP methods.
 *
 * Returns: %TRUE if the EAP method was successfully added, %FALSE if it was
 *  not a valid method or if it was already allowed.
 **/
gboolean
nm_setting_802_1x_add_eap_method (NMSetting8021x *setting, const char *eap)
{
	NMSetting8021xPrivate *priv;
	GSList *iter;

	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), FALSE);
	g_return_val_if_fail (eap != NULL, FALSE);

	priv = NM_SETTING_802_1X_GET_PRIVATE (setting);
	for (iter = priv->eap; iter; iter = g_slist_next (iter)) {
		if (!strcmp (eap, (char *) iter->data))
			return FALSE;
	}

	priv->eap = g_slist_append (priv->eap, g_ascii_strdown (eap, -1));
	_notify (setting, PROP_EAP);
	return TRUE;
}

/**
 * nm_setting_802_1x_remove_eap_method:
 * @setting: the #NMSetting8021x
 * @i: the index of the EAP method to remove
 *
 * Removes the allowed EAP method at the specified index.
 **/
void
nm_setting_802_1x_remove_eap_method (NMSetting8021x *setting, guint32 i)
{
	NMSetting8021xPrivate *priv;
	GSList *elt;

	g_return_if_fail (NM_IS_SETTING_802_1X (setting));

	priv = NM_SETTING_802_1X_GET_PRIVATE (setting);
	elt = g_slist_nth (priv->eap, i);
	g_return_if_fail (elt != NULL);

	g_free (elt->data);
	priv->eap = g_slist_delete_link (priv->eap, elt);
	_notify (setting, PROP_EAP);
}

/**
 * nm_setting_802_1x_remove_eap_method_by_value:
 * @setting: the #NMSetting8021x
 * @eap: the name of the EAP method to remove
 *
 * Removes the allowed EAP method @method.
 *
 * Returns: %TRUE if the EAP method was founs and removed, %FALSE if it was not.
 **/
gboolean
nm_setting_802_1x_remove_eap_method_by_value (NMSetting8021x *setting,
                                              const char *eap)
{
	NMSetting8021xPrivate *priv;
	GSList *iter;

	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), FALSE);
	g_return_val_if_fail (eap != NULL, FALSE);

	priv = NM_SETTING_802_1X_GET_PRIVATE (setting);
	for (iter = priv->eap; iter; iter = g_slist_next (iter)) {
		if (!strcmp (eap, (char *) iter->data)) {
			priv->eap = g_slist_delete_link (priv->eap, iter);
			_notify (setting, PROP_EAP);
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * nm_setting_802_1x_clear_eap_methods:
 * @setting: the #NMSetting8021x
 *
 * Clears all allowed EAP methods.
 **/
void
nm_setting_802_1x_clear_eap_methods (NMSetting8021x *setting)
{
	NMSetting8021xPrivate *priv;

	g_return_if_fail (NM_IS_SETTING_802_1X (setting));

	priv = NM_SETTING_802_1X_GET_PRIVATE (setting);
	g_slist_free_full (priv->eap, g_free);
	priv->eap = NULL;
	_notify (setting, PROP_EAP);
}

/**
 * nm_setting_802_1x_get_identity:
 * @setting: the #NMSetting8021x
 *
 * Returns the identifier used by some EAP methods (like TLS) to
 * authenticate the user.  Often this is a username or login name.
 *
 * Returns: the user identifier
 **/
const char *
nm_setting_802_1x_get_identity (NMSetting8021x *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NULL);

	return NM_SETTING_802_1X_GET_PRIVATE (setting)->identity;
}

/**
 * nm_setting_802_1x_get_anonymous_identity:
 * @setting: the #NMSetting8021x
 *
 * Returns the anonymous identifier used by some EAP methods (like TTLS) to
 * authenticate the user in the outer unencrypted "phase 1" authentication.  The
 * inner "phase 2" authentication will use the #NMSetting8021x:identity in
 * a secure form, if applicable for that EAP method.
 *
 * Returns: the anonymous identifier
 **/
const char *
nm_setting_802_1x_get_anonymous_identity (NMSetting8021x *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NULL);

	return NM_SETTING_802_1X_GET_PRIVATE (setting)->anonymous_identity;
}

/**
 * nm_setting_802_1x_get_pac_file:
 * @setting: the #NMSetting8021x
 *
 * Returns the file containing PAC credentials used by EAP-FAST method.
 *
 * Returns: the PAC file
 **/
const char *
nm_setting_802_1x_get_pac_file (NMSetting8021x *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NULL);

	return NM_SETTING_802_1X_GET_PRIVATE (setting)->pac_file;
}

/**
 * nm_setting_802_1x_get_ca_path:
 * @setting: the #NMSetting8021x
 *
 * Returns the path of the CA certificate directory if previously set.  Systems
 * will often have a directory that contains multiple individual CA certificates
 * which the supplicant can then add to the verification chain.  This may be
 * used in addition to the #NMSetting8021x:ca-cert property to add more CA
 * certificates for verifying the network to client.
 *
 * Returns: the CA certificate directory path
 **/
const char *
nm_setting_802_1x_get_ca_path (NMSetting8021x *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NULL);

	return NM_SETTING_802_1X_GET_PRIVATE (setting)->ca_path;
}

/**
 * nm_setting_802_1x_get_system_ca_certs:
 * @setting: the #NMSetting8021x
 *
 * Sets the #NMSetting8021x:system-ca-certs property. The
 * #NMSetting8021x:ca-path and #NMSetting8021x:phase2-ca-path
 * properties are ignored if the #NMSetting8021x:system-ca-certs property is
 * %TRUE, in which case a system-wide CA certificate directory specified at
 * compile time (using the --system-ca-path configure option) is used in place
 * of these properties.
 *
 * Returns: %TRUE if a system CA certificate path should be used, %FALSE if not
 **/
gboolean
nm_setting_802_1x_get_system_ca_certs (NMSetting8021x *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), FALSE);

	return NM_SETTING_802_1X_GET_PRIVATE (setting)->system_ca_certs;
}

/**
 * nm_setting_802_1x_get_ca_cert_scheme:
 * @setting: the #NMSetting8021x
 *
 * Returns the scheme used to store the CA certificate.  If the returned scheme
 * is %NM_SETTING_802_1X_CK_SCHEME_BLOB, use nm_setting_802_1x_get_ca_cert_blob();
 * if %NM_SETTING_802_1X_CK_SCHEME_PATH, use nm_setting_802_1x_get_ca_cert_path();
 * if %NM_SETTING_802_1X_CK_SCHEME_PKCS11, use nm_setting_802_1x_get_ca_cert_uri().
 *
 * Returns: scheme used to store the CA certificate (blob or path)
 **/
NMSetting8021xCKScheme
nm_setting_802_1x_get_ca_cert_scheme (NMSetting8021x *setting)
{
	_cert_impl_get_scheme (setting, ca_cert);
}

/**
 * nm_setting_802_1x_get_ca_cert_blob:
 * @setting: the #NMSetting8021x
 *
 * Returns the CA certificate blob if the CA certificate is stored using the
 * %NM_SETTING_802_1X_CK_SCHEME_BLOB scheme.  Not all EAP methods use a
 * CA certificate (LEAP for example), and those that can take advantage of the
 * CA certificate allow it to be unset.  Note that lack of a CA certificate
 * reduces security by allowing man-in-the-middle attacks, because the identity
 * of the network cannot be confirmed by the client.
 *
 * Returns: (transfer none): the CA certificate data
 **/
GBytes *
nm_setting_802_1x_get_ca_cert_blob (NMSetting8021x *setting)
{
	_cert_impl_get_blob (setting, ca_cert);
}

/**
 * nm_setting_802_1x_get_ca_cert_path:
 * @setting: the #NMSetting8021x
 *
 * Returns the CA certificate path if the CA certificate is stored using the
 * %NM_SETTING_802_1X_CK_SCHEME_PATH scheme.  Not all EAP methods use a
 * CA certificate (LEAP for example), and those that can take advantage of the
 * CA certificate allow it to be unset.  Note that lack of a CA certificate
 * reduces security by allowing man-in-the-middle attacks, because the identity
 * of the network cannot be confirmed by the client.
 *
 * Returns: path to the CA certificate file
 **/
const char *
nm_setting_802_1x_get_ca_cert_path (NMSetting8021x *setting)
{
	_cert_impl_get_path (setting, ca_cert);
}

/**
 * nm_setting_802_1x_get_ca_cert_uri:
 * @setting: the #NMSetting8021x
 *
 * Returns the CA certificate URI analogously to
 * nm_setting_802_1x_get_ca_cert_blob() and
 * nm_setting_802_1x_get_ca_cert_path().
 *
 * Currently it's limited to PKCS#11 URIs ('pkcs11' scheme as defined by RFC
 * 7512), but may be extended to other schemes in future (such as 'file' URIs
 * for local files and 'data' URIs for inline certificate data).
 *
 * Returns: the URI string
 *
 * Since: 1.6
 **/
const char *
nm_setting_802_1x_get_ca_cert_uri (NMSetting8021x *setting)
{
	_cert_impl_get_uri (setting, ca_cert);
}

/**
 * nm_setting_802_1x_set_ca_cert:
 * @setting: the #NMSetting8021x
 * @value: when @scheme is set to either %NM_SETTING_802_1X_CK_SCHEME_PATH
 *   or %NM_SETTING_802_1X_CK_SCHEME_BLOB, pass the path of the CA certificate
 *   file (PEM or DER format).  The path must be UTF-8 encoded; use
 *   g_filename_to_utf8() to convert if needed.  Passing %NULL with any @scheme
 *   clears the CA certificate.
 * @scheme: desired storage scheme for the certificate
 * @out_format: on successful return, the type of the certificate added
 * @error: on unsuccessful return, an error
 *
 * Reads a certificate from disk and sets the #NMSetting8021x:ca-cert property
 * with the raw certificate data if using the %NM_SETTING_802_1X_CK_SCHEME_BLOB
 * scheme, or with the path to the certificate file if using the
 * %NM_SETTING_802_1X_CK_SCHEME_PATH scheme.
 *
 * Returns: %TRUE if the operation succeeded, %FALSE if it was unsuccessful
 **/
gboolean
nm_setting_802_1x_set_ca_cert (NMSetting8021x *setting,
                               const char *value,
                               NMSetting8021xCKScheme scheme,
                               NMSetting8021xCKFormat *out_format,
                               GError **error)
{
	return _cert_impl_set (setting, PROP_CA_CERT, value, NULL, scheme, out_format, error);
}

/**
 * nm_setting_802_1x_get_ca_cert_password:
 * @setting: the #NMSetting8021x
 *
 * Returns: the password used to access the CA certificate stored in
 * #NMSetting8021x:ca-cert property. Only makes sense if the certificate
 * is stored on a PKCS#<!-- -->11 token that requires a login.
 *
 * Since: 1.8
 **/
const char *
nm_setting_802_1x_get_ca_cert_password (NMSetting8021x *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NULL);

	return NM_SETTING_802_1X_GET_PRIVATE (setting)->ca_cert_password;
}

/**
 * nm_setting_802_1x_get_ca_cert_password_flags:
 * @setting: the #NMSetting8021x
 *
 * Returns: the #NMSettingSecretFlags pertaining to the
 * #NMSetting8021x:ca-cert-password
 *
 * Since: 1.8
 **/
NMSettingSecretFlags
nm_setting_802_1x_get_ca_cert_password_flags (NMSetting8021x *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NM_SETTING_SECRET_FLAG_NONE);

	return NM_SETTING_802_1X_GET_PRIVATE (setting)->ca_cert_password_flags;
}

/**
 * nm_setting_802_1x_get_subject_match:
 * @setting: the #NMSetting8021x
 *
 * Returns: the #NMSetting8021x:subject-match property. This is the
 * substring to be matched against the subject of the authentication
 * server certificate, or %NULL no subject verification is to be
 * performed.
 **/
const char *
nm_setting_802_1x_get_subject_match (NMSetting8021x *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NULL);

	return NM_SETTING_802_1X_GET_PRIVATE (setting)->subject_match;
}

/**
 * nm_setting_802_1x_get_num_altsubject_matches:
 * @setting: the #NMSetting8021x
 *
 * Returns the number of entries in the
 * #NMSetting8021x:altsubject-matches property of this setting.
 *
 * Returns: the number of altsubject-matches entries.
 **/
guint32
nm_setting_802_1x_get_num_altsubject_matches (NMSetting8021x *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), 0);

	return g_slist_length (NM_SETTING_802_1X_GET_PRIVATE (setting)->altsubject_matches);
}

/**
 * nm_setting_802_1x_get_altsubject_match:
 * @setting: the #NMSettingConnection
 * @i: the zero-based index of the array of altSubjectName matches
 *
 * Returns the altSubjectName match at index @i.
 *
 * Returns: the altSubjectName match at index @i
 **/
const char *
nm_setting_802_1x_get_altsubject_match (NMSetting8021x *setting, guint32 i)
{
	NMSetting8021xPrivate *priv;

	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NULL);

	priv = NM_SETTING_802_1X_GET_PRIVATE (setting);
	g_return_val_if_fail (i <= g_slist_length (priv->altsubject_matches), NULL);

	return (const char *) g_slist_nth_data (priv->altsubject_matches, i);
}

/**
 * nm_setting_802_1x_add_altsubject_match:
 * @setting: the #NMSetting8021x
 * @altsubject_match: the altSubjectName to allow for this connection
 *
 * Adds an allowed alternate subject name match.  Until at least one
 * match is added, the altSubjectName of the remote authentication
 * server is not verified.
 *
 * Returns: %TRUE if the alternative subject name match was
 *  successfully added, %FALSE if it was already allowed.
 **/
gboolean
nm_setting_802_1x_add_altsubject_match (NMSetting8021x *setting,
                                        const char *altsubject_match)
{
	NMSetting8021xPrivate *priv;
	GSList *iter;

	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), FALSE);
	g_return_val_if_fail (altsubject_match != NULL, FALSE);

	priv = NM_SETTING_802_1X_GET_PRIVATE (setting);
	for (iter = priv->altsubject_matches; iter; iter = g_slist_next (iter)) {
		if (!strcmp (altsubject_match, (char *) iter->data))
			return FALSE;
	}

	priv->altsubject_matches = g_slist_append (priv->altsubject_matches,
	                                           g_strdup (altsubject_match));
	_notify (setting, PROP_ALTSUBJECT_MATCHES);
	return TRUE;
}

/**
 * nm_setting_802_1x_remove_altsubject_match:
 * @setting: the #NMSetting8021x
 * @i: the index of the altSubjectName match to remove
 *
 * Removes the allowed altSubjectName at the specified index.
 **/
void
nm_setting_802_1x_remove_altsubject_match (NMSetting8021x *setting, guint32 i)
{
	NMSetting8021xPrivate *priv;
	GSList *elt;

	g_return_if_fail (NM_IS_SETTING_802_1X (setting));

	priv = NM_SETTING_802_1X_GET_PRIVATE (setting);
	elt = g_slist_nth (priv->altsubject_matches, i);
	g_return_if_fail (elt != NULL);

	g_free (elt->data);
	priv->altsubject_matches = g_slist_delete_link (priv->altsubject_matches, elt);
	_notify (setting, PROP_ALTSUBJECT_MATCHES);
}

/**
 * nm_setting_802_1x_remove_altsubject_match_by_value:
 * @setting: the #NMSetting8021x
 * @altsubject_match: the altSubjectName to remove
 *
 * Removes the allowed altSubjectName @altsubject_match.
 *
 * Returns: %TRUE if the alternative subject name match was found and removed,
 *          %FALSE if it was not.
 **/
gboolean
nm_setting_802_1x_remove_altsubject_match_by_value (NMSetting8021x *setting,
                                                    const char *altsubject_match)
{
	NMSetting8021xPrivate *priv;
	GSList *iter;

	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), FALSE);
	g_return_val_if_fail (altsubject_match != NULL, FALSE);

	priv = NM_SETTING_802_1X_GET_PRIVATE (setting);
	for (iter = priv->altsubject_matches; iter; iter = g_slist_next (iter)) {
		if (!strcmp (altsubject_match, (char *) iter->data)) {
			priv->altsubject_matches = g_slist_delete_link (priv->altsubject_matches, iter);
			_notify (setting, PROP_ALTSUBJECT_MATCHES);
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * nm_setting_802_1x_clear_altsubject_matches:
 * @setting: the #NMSetting8021x
 *
 * Clears all altSubjectName matches.
 **/
void
nm_setting_802_1x_clear_altsubject_matches (NMSetting8021x *setting)
{
	NMSetting8021xPrivate *priv;

	g_return_if_fail (NM_IS_SETTING_802_1X (setting));

	priv = NM_SETTING_802_1X_GET_PRIVATE (setting);
	g_slist_free_full (priv->altsubject_matches, g_free);
	priv->altsubject_matches = NULL;
	_notify (setting, PROP_ALTSUBJECT_MATCHES);
}

/**
 * nm_setting_802_1x_get_domain_suffix_match:
 * @setting: the #NMSetting8021x
 *
 * Returns: the #NMSetting8021x:domain-suffix-match property.
 *
 * Since: 1.2
 **/
const char *
nm_setting_802_1x_get_domain_suffix_match (NMSetting8021x *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NULL);

	return NM_SETTING_802_1X_GET_PRIVATE (setting)->domain_suffix_match;
}

/**
 * nm_setting_802_1x_get_client_cert_scheme:
 * @setting: the #NMSetting8021x
 *
 * Returns the scheme used to store the client certificate.  If the returned scheme
 * is %NM_SETTING_802_1X_CK_SCHEME_BLOB, use nm_setting_802_1x_get_client_cert_blob();
 * if %NM_SETTING_802_1X_CK_SCHEME_PATH, use nm_setting_802_1x_get_client_cert_path();
 * if %NM_SETTING_802_1X_CK_SCHEME_PKCS11, use nm_setting_802_1x_get_client_cert_uri().
 *
 * Returns: scheme used to store the client certificate (blob or path)
 **/
NMSetting8021xCKScheme
nm_setting_802_1x_get_client_cert_scheme (NMSetting8021x *setting)
{
	_cert_impl_get_scheme (setting, client_cert);
}

/**
 * nm_setting_802_1x_get_client_cert_blob:
 * @setting: the #NMSetting8021x
 *
 * Client certificates are used to identify the connecting client to the network
 * when EAP-TLS is used as either the "phase 1" or "phase 2" 802.1x
 * authentication method.
 *
 * Returns: (transfer none): the client certificate data
 **/
GBytes *
nm_setting_802_1x_get_client_cert_blob (NMSetting8021x *setting)
{
	_cert_impl_get_blob (setting, client_cert);
}

/**
 * nm_setting_802_1x_get_client_cert_path:
 * @setting: the #NMSetting8021x
 *
 * Client certificates are used to identify the connecting client to the network
 * when EAP-TLS is used as either the "phase 1" or "phase 2" 802.1x
 * authentication method.
 *
 * Returns: path to the client certificate file
 **/
const char *
nm_setting_802_1x_get_client_cert_path (NMSetting8021x *setting)
{
	_cert_impl_get_path (setting, client_cert);
}

/**
 * nm_setting_802_1x_get_client_cert_uri:
 * @setting: the #NMSetting8021x
 *
 * Returns the client certificate URI analogously to
 * nm_setting_802_1x_get_client_cert_blob() and
 * nm_setting_802_1x_get_client_cert_path().
 *
 * Currently it's limited to PKCS#11 URIs ('pkcs11' scheme as defined by RFC
 * 7512), but may be extended to other schemes in future (such as 'file' URIs
 * for local files and 'data' URIs for inline certificate data).
 *
 * Returns: the URI string
 *
 * Since: 1.6
 **/
const char *
nm_setting_802_1x_get_client_cert_uri (NMSetting8021x *setting)
{
	_cert_impl_get_uri (setting, client_cert);
}

/**
 * nm_setting_802_1x_set_client_cert:
 * @setting: the #NMSetting8021x
 * @value: when @scheme is set to either %NM_SETTING_802_1X_CK_SCHEME_PATH
 *   or %NM_SETTING_802_1X_CK_SCHEME_BLOB, pass the path of the client
 *   certificate file (PEM, DER, or PKCS#<!-- -->12 format).  The path must be UTF-8
 *   encoded; use g_filename_to_utf8() to convert if needed.  Passing %NULL with
 *   any @scheme clears the client certificate.
 * @scheme: desired storage scheme for the certificate
 * @out_format: on successful return, the type of the certificate added
 * @error: on unsuccessful return, an error
 *
 * Reads a certificate from disk and sets the #NMSetting8021x:client-cert
 * property with the raw certificate data if using the
 * %NM_SETTING_802_1X_CK_SCHEME_BLOB scheme, or with the path to the certificate
 * file if using the %NM_SETTING_802_1X_CK_SCHEME_PATH scheme.
 *
 * Client certificates are used to identify the connecting client to the network
 * when EAP-TLS is used as either the "phase 1" or "phase 2" 802.1x
 * authentication method.
 *
 * Returns: %TRUE if the operation succeeded, %FALSE if it was unsuccessful
 **/
gboolean
nm_setting_802_1x_set_client_cert (NMSetting8021x *setting,
                                   const char *value,
                                   NMSetting8021xCKScheme scheme,
                                   NMSetting8021xCKFormat *out_format,
                                   GError **error)
{
	return _cert_impl_set (setting, PROP_CLIENT_CERT, value, NULL, scheme, out_format, error);
}

/**
 * nm_setting_802_1x_get_client_cert_password:
 * @setting: the #NMSetting8021x
 *
 * Returns: the password used to access the client certificate stored in
 * #NMSetting8021x:client-cert property. Only makes sense if the certificate
 * is stored on a PKCS#<!-- -->11 token that requires a login.
 *
 * Since: 1.8
 **/
const char *
nm_setting_802_1x_get_client_cert_password (NMSetting8021x *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NULL);

	return NM_SETTING_802_1X_GET_PRIVATE (setting)->client_cert_password;
}

/**
 * nm_setting_802_1x_get_client_cert_password_flags:
 * @setting: the #NMSetting8021x
 *
 * Returns: the #NMSettingSecretFlags pertaining to the
 * #NMSetting8021x:client-cert-password
 *
 * Since: 1.8
 **/
NMSettingSecretFlags
nm_setting_802_1x_get_client_cert_password_flags (NMSetting8021x *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NM_SETTING_SECRET_FLAG_NONE);

	return NM_SETTING_802_1X_GET_PRIVATE (setting)->client_cert_password_flags;
}

/**
 * nm_setting_802_1x_get_phase1_peapver:
 * @setting: the #NMSetting8021x
 *
 * Returns: the "phase 1" PEAP version to be used when authenticating with
 *  EAP-PEAP as contained in the #NMSetting8021x:phase1-peapver property.  Valid
 *  values are %NULL (unset), "0" (PEAP version 0), and "1" (PEAP version 1).
 **/
const char *
nm_setting_802_1x_get_phase1_peapver (NMSetting8021x *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NULL);

	return NM_SETTING_802_1X_GET_PRIVATE (setting)->phase1_peapver;
}

/**
 * nm_setting_802_1x_get_phase1_peaplabel:
 * @setting: the #NMSetting8021x
 *
 * Returns: whether the "phase 1" PEAP label is new-style or old-style, to be
 *  used when authenticating with EAP-PEAP, as contained in the
 *  #NMSetting8021x:phase1-peaplabel property.  Valid values are %NULL (unset),
 *  "0" (use old-style label), and "1" (use new-style label).  See the
 *  wpa_supplicant documentation for more details.
 **/
const char *
nm_setting_802_1x_get_phase1_peaplabel (NMSetting8021x *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NULL);

	return NM_SETTING_802_1X_GET_PRIVATE (setting)->phase1_peaplabel;
}

/**
 * nm_setting_802_1x_get_phase1_fast_provisioning:
 * @setting: the #NMSetting8021x
 *
 * Returns: whether "phase 1" PEAP fast provisioning should be used, as specified
 *  by the #NMSetting8021x:phase1-fast-provisioning property.  See the
 *  wpa_supplicant documentation for more details.
 **/
const char *
nm_setting_802_1x_get_phase1_fast_provisioning (NMSetting8021x *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NULL);

	return NM_SETTING_802_1X_GET_PRIVATE (setting)->phase1_fast_provisioning;
}

/**
 * nm_setting_802_1x_get_phase1_auth_flags:
 * @setting: the #NMSetting8021x
 *
 * Returns: the authentication flags for "phase 1".
 *
 * Since: 1.8
 */
NMSetting8021xAuthFlags
nm_setting_802_1x_get_phase1_auth_flags (NMSetting8021x *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), 0);

	return NM_SETTING_802_1X_GET_PRIVATE (setting)->phase1_auth_flags;
}

/**
 * nm_setting_802_1x_get_phase2_auth:
 * @setting: the #NMSetting8021x
 *
 * Returns: the "phase 2" non-EAP (ex MD5) allowed authentication method as
 *   specified by the #NMSetting8021x:phase2-auth property.
 **/
const char *
nm_setting_802_1x_get_phase2_auth (NMSetting8021x *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NULL);

	return NM_SETTING_802_1X_GET_PRIVATE (setting)->phase2_auth;
}

/**
 * nm_setting_802_1x_get_phase2_autheap:
 * @setting: the #NMSetting8021x
 *
 * Returns: the "phase 2" EAP-based (ex TLS) allowed authentication method as
 *   specified by the #NMSetting8021x:phase2-autheap property.
 **/
const char *
nm_setting_802_1x_get_phase2_autheap (NMSetting8021x *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NULL);

	return NM_SETTING_802_1X_GET_PRIVATE (setting)->phase2_autheap;
}

/**
 * nm_setting_802_1x_get_phase2_ca_path:
 * @setting: the #NMSetting8021x
 *
 * Returns the path of the "phase 2" CA certificate directory if previously set.
 * Systems will often have a directory that contains multiple individual CA
 * certificates which the supplicant can then add to the verification chain.
 * This may be used in addition to the #NMSetting8021x:phase2-ca-cert property
 * to add more CA certificates for verifying the network to client.
 *
 * Returns: the "phase 2" CA certificate directory path
 **/
const char *
nm_setting_802_1x_get_phase2_ca_path (NMSetting8021x *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NULL);

	return NM_SETTING_802_1X_GET_PRIVATE (setting)->phase2_ca_path;
}

/**
 * nm_setting_802_1x_get_phase2_ca_cert_scheme:
 * @setting: the #NMSetting8021x
 *
 * Returns the scheme used to store the "phase 2" CA certificate.  If the
 * returned scheme is %NM_SETTING_802_1X_CK_SCHEME_BLOB, use
 * nm_setting_802_1x_get_ca_cert_blob(); if %NM_SETTING_802_1X_CK_SCHEME_PATH,
 * use nm_setting_802_1x_get_ca_cert_path(); if %NM_SETTING_802_1X_CK_SCHEME_PKCS11,
 * use nm_setting_802_1x_get_ca_cert_uri().
 *
 * Returns: scheme used to store the "phase 2" CA certificate (blob or path)
 **/
NMSetting8021xCKScheme
nm_setting_802_1x_get_phase2_ca_cert_scheme (NMSetting8021x *setting)
{
	_cert_impl_get_scheme (setting, phase2_ca_cert);
}

/**
 * nm_setting_802_1x_get_phase2_ca_cert_blob:
 * @setting: the #NMSetting8021x
 *
 * Returns the "phase 2" CA certificate blob if the CA certificate is stored
 * using the %NM_SETTING_802_1X_CK_SCHEME_BLOB scheme.  Not all EAP methods use
 * a CA certificate (LEAP for example), and those that can take advantage of the
 * CA certificate allow it to be unset.  Note that lack of a CA certificate
 * reduces security by allowing man-in-the-middle attacks, because the identity
 * of the network cannot be confirmed by the client.
 *
 * Returns: (transfer none): the "phase 2" CA certificate data
 **/
GBytes *
nm_setting_802_1x_get_phase2_ca_cert_blob (NMSetting8021x *setting)
{
	_cert_impl_get_blob (setting, phase2_ca_cert);
}

/**
 * nm_setting_802_1x_get_phase2_ca_cert_path:
 * @setting: the #NMSetting8021x
 *
 * Returns the "phase 2" CA certificate path if the CA certificate is stored
 * using the %NM_SETTING_802_1X_CK_SCHEME_PATH scheme.  Not all EAP methods use
 * a CA certificate (LEAP for example), and those that can take advantage of the
 * CA certificate allow it to be unset.  Note that lack of a CA certificate
 * reduces security by allowing man-in-the-middle attacks, because the identity
 * of the network cannot be confirmed by the client.
 *
 * Returns: path to the "phase 2" CA certificate file
 **/
const char *
nm_setting_802_1x_get_phase2_ca_cert_path (NMSetting8021x *setting)
{
	_cert_impl_get_path (setting, phase2_ca_cert);
}

/**
 * nm_setting_802_1x_get_phase2_ca_cert_uri:
 * @setting: the #NMSetting8021x
 *
 * Returns the "phase 2" CA certificate URI analogously to
 * nm_setting_802_1x_get_phase2_ca_cert_blob() and
 * nm_setting_802_1x_get_phase2_ca_cert_path().
 *
 * Currently it's limited to PKCS#11 URIs ('pkcs11' scheme as defined by RFC
 * 7512), but may be extended to other schemes in future (such as 'file' URIs
 * for local files and 'data' URIs for inline certificate data).
 *
 * Returns: the URI string
 *
 * Since: 1.6
 **/
const char *
nm_setting_802_1x_get_phase2_ca_cert_uri (NMSetting8021x *setting)
{
	_cert_impl_get_uri (setting, phase2_ca_cert);
}

/**
 * nm_setting_802_1x_set_phase2_ca_cert:
 * @setting: the #NMSetting8021x
 * @value: when @scheme is set to either %NM_SETTING_802_1X_CK_SCHEME_PATH
 *   or %NM_SETTING_802_1X_CK_SCHEME_BLOB, pass the path of the "phase2" CA
 *   certificate file (PEM or DER format).  The path must be UTF-8 encoded; use
 *   g_filename_to_utf8() to convert if needed.  Passing %NULL with any @scheme
 *   clears the "phase2" CA certificate.
 * @scheme: desired storage scheme for the certificate
 * @out_format: on successful return, the type of the certificate added
 * @error: on unsuccessful return, an error
 *
 * Reads a certificate from disk and sets the #NMSetting8021x:phase2-ca-cert
 * property with the raw certificate data if using the
 * %NM_SETTING_802_1X_CK_SCHEME_BLOB scheme, or with the path to the certificate
 * file if using the %NM_SETTING_802_1X_CK_SCHEME_PATH scheme.
 *
 * Returns: %TRUE if the operation succeeded, %FALSE if it was unsuccessful
 **/
gboolean
nm_setting_802_1x_set_phase2_ca_cert (NMSetting8021x *setting,
                                      const char *value,
                                      NMSetting8021xCKScheme scheme,
                                      NMSetting8021xCKFormat *out_format,
                                      GError **error)
{
	return _cert_impl_set (setting, PROP_PHASE2_CA_CERT, value, NULL, scheme, out_format, error);
}

/**
 * nm_setting_802_1x_get_phase2_ca_cert_password:
 * @setting: the #NMSetting8021x
 *
 * Returns: the password used to access the "phase2" CA certificate stored in
 * #NMSetting8021x:phase2-ca-cert property. Only makes sense if the certificate
 * is stored on a PKCS#<!-- -->11 token that requires a login.
 *
 * Since: 1.8
 **/
const char *
nm_setting_802_1x_get_phase2_ca_cert_password (NMSetting8021x *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NULL);

	return NM_SETTING_802_1X_GET_PRIVATE (setting)->phase2_ca_cert_password;
}

/**
 * nm_setting_802_1x_get_phase2_ca_cert_password_flags:
 * @setting: the #NMSetting8021x
 *
 * Returns: the #NMSettingSecretFlags pertaining to the
 * #NMSetting8021x:phase2-private-key-password
 *
 * Since: 1.8
 **/
NMSettingSecretFlags
nm_setting_802_1x_get_phase2_ca_cert_password_flags (NMSetting8021x *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NM_SETTING_SECRET_FLAG_NONE);

	return NM_SETTING_802_1X_GET_PRIVATE (setting)->phase2_ca_cert_password_flags;
}

/**
 * nm_setting_802_1x_get_phase2_subject_match:
 * @setting: the #NMSetting8021x
 *
 * Returns: the #NMSetting8021x:phase2-subject-match property. This is
 * the substring to be matched against the subject of the "phase 2"
 * authentication server certificate, or %NULL no subject verification
 * is to be performed.
 **/
const char *
nm_setting_802_1x_get_phase2_subject_match (NMSetting8021x *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NULL);

	return NM_SETTING_802_1X_GET_PRIVATE (setting)->phase2_subject_match;
}

/**
 * nm_setting_802_1x_get_num_phase2_altsubject_matches:
 * @setting: the #NMSetting8021x
 *
 * Returns the number of entries in the
 * #NMSetting8021x:phase2-altsubject-matches property of this setting.
 *
 * Returns: the number of phase2-altsubject-matches entries.
 **/
guint32
nm_setting_802_1x_get_num_phase2_altsubject_matches (NMSetting8021x *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), 0);

	return g_slist_length (NM_SETTING_802_1X_GET_PRIVATE (setting)->phase2_altsubject_matches);
}

/**
 * nm_setting_802_1x_get_phase2_domain_suffix_match:
 * @setting: the #NMSetting8021x
 *
 * Returns: the #NMSetting8021x:phase2-domain-suffix-match property.
 *
 * Since: 1.2
 **/
const char *
nm_setting_802_1x_get_phase2_domain_suffix_match (NMSetting8021x *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NULL);

	return NM_SETTING_802_1X_GET_PRIVATE (setting)->phase2_domain_suffix_match;
}

/**
 * nm_setting_802_1x_get_phase2_altsubject_match:
 * @setting: the #NMSettingConnection
 * @i: the zero-based index of the array of "phase 2" altSubjectName matches
 *
 * Returns the "phase 2" altSubjectName match at index @i.
 *
 * Returns: the "phase 2" altSubjectName match at index @i
 **/
const char *
nm_setting_802_1x_get_phase2_altsubject_match (NMSetting8021x *setting, guint32 i)
{
	NMSetting8021xPrivate *priv;

	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NULL);

	priv = NM_SETTING_802_1X_GET_PRIVATE (setting);
	g_return_val_if_fail (i <= g_slist_length (priv->phase2_altsubject_matches), NULL);

	return (const char *) g_slist_nth_data (priv->phase2_altsubject_matches, i);
}

/**
 * nm_setting_802_1x_add_phase2_altsubject_match:
 * @setting: the #NMSetting8021x
 * @phase2_altsubject_match: the "phase 2" altSubjectName to allow for this
 * connection
 *
 * Adds an allowed alternate subject name match for "phase 2".  Until
 * at least one match is added, the altSubjectName of the "phase 2"
 * remote authentication server is not verified.
 *
 * Returns: %TRUE if the "phase 2" alternative subject name match was
 *  successfully added, %FALSE if it was already allowed.
 **/
gboolean
nm_setting_802_1x_add_phase2_altsubject_match (NMSetting8021x *setting,
                                               const char *phase2_altsubject_match)
{
	NMSetting8021xPrivate *priv;
	GSList *iter;

	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), FALSE);
	g_return_val_if_fail (phase2_altsubject_match != NULL, FALSE);

	priv = NM_SETTING_802_1X_GET_PRIVATE (setting);
	for (iter = priv->phase2_altsubject_matches; iter; iter = g_slist_next (iter)) {
		if (!strcmp (phase2_altsubject_match, (char *) iter->data))
			return FALSE;
	}

	priv->phase2_altsubject_matches = g_slist_append (priv->phase2_altsubject_matches,
	                                                  g_strdup (phase2_altsubject_match));
	_notify (setting, PROP_PHASE2_ALTSUBJECT_MATCHES);
	return TRUE;
}

/**
 * nm_setting_802_1x_remove_phase2_altsubject_match:
 * @setting: the #NMSetting8021x
 * @i: the index of the "phase 2" altSubjectName match to remove
 *
 * Removes the allowed "phase 2" altSubjectName at the specified index.
 **/
void
nm_setting_802_1x_remove_phase2_altsubject_match (NMSetting8021x *setting, guint32 i)
{
	NMSetting8021xPrivate *priv;
	GSList *elt;

	g_return_if_fail (NM_IS_SETTING_802_1X (setting));

	priv = NM_SETTING_802_1X_GET_PRIVATE (setting);
	elt = g_slist_nth (priv->phase2_altsubject_matches, i);
	g_return_if_fail (elt != NULL);

	g_free (elt->data);
	priv->phase2_altsubject_matches = g_slist_delete_link (priv->phase2_altsubject_matches, elt);
	_notify (setting, PROP_PHASE2_ALTSUBJECT_MATCHES);
}

/**
 * nm_setting_802_1x_remove_phase2_altsubject_match_by_value:
 * @setting: the #NMSetting8021x
 * @phase2_altsubject_match: the "phase 2" altSubjectName to remove
 *
 * Removes the allowed "phase 2" altSubjectName @phase2_altsubject_match.
 *
 * Returns: %TRUE if the alternative subject name match for "phase 2" was found and removed,
 *          %FALSE if it was not.
 **/
gboolean
nm_setting_802_1x_remove_phase2_altsubject_match_by_value (NMSetting8021x *setting,
                                                           const char *phase2_altsubject_match)
{
	NMSetting8021xPrivate *priv;
	GSList *iter;

	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), FALSE);
	g_return_val_if_fail (phase2_altsubject_match != NULL, FALSE);

	priv = NM_SETTING_802_1X_GET_PRIVATE (setting);
	for (iter = priv->phase2_altsubject_matches; iter; iter = g_slist_next (iter)) {
		if (!strcmp (phase2_altsubject_match, (char *) iter->data)) {
			priv->phase2_altsubject_matches = g_slist_delete_link (priv->phase2_altsubject_matches, iter);
			_notify (setting, PROP_PHASE2_ALTSUBJECT_MATCHES);
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * nm_setting_802_1x_clear_phase2_altsubject_matches:
 * @setting: the #NMSetting8021x
 *
 * Clears all "phase 2" altSubjectName matches.
 **/
void
nm_setting_802_1x_clear_phase2_altsubject_matches (NMSetting8021x *setting)
{
	NMSetting8021xPrivate *priv;

	g_return_if_fail (NM_IS_SETTING_802_1X (setting));

	priv = NM_SETTING_802_1X_GET_PRIVATE (setting);
	g_slist_free_full (priv->phase2_altsubject_matches, g_free);
	priv->phase2_altsubject_matches = NULL;
	_notify (setting, PROP_PHASE2_ALTSUBJECT_MATCHES);
}

/**
 * nm_setting_802_1x_get_phase2_client_cert_scheme:
 * @setting: the #NMSetting8021x
 *
 * Returns the scheme used to store the "phase 2" client certificate.  If the
 * returned scheme is %NM_SETTING_802_1X_CK_SCHEME_BLOB, use
 * nm_setting_802_1x_get_client_cert_blob(); if
 * %NM_SETTING_802_1X_CK_SCHEME_PATH, use
 * nm_setting_802_1x_get_client_cert_path(); if
 * %NM_SETTING_802_1X_CK_SCHEME_PKCS11, use
 * nm_setting_802_1x_get_client_cert_uri().
 *
 * Returns: scheme used to store the "phase 2" client certificate (blob or path)
 **/
NMSetting8021xCKScheme
nm_setting_802_1x_get_phase2_client_cert_scheme (NMSetting8021x *setting)
{
	_cert_impl_get_scheme (setting, phase2_client_cert);
}

/**
 * nm_setting_802_1x_get_phase2_client_cert_blob:
 * @setting: the #NMSetting8021x
 *
 * Client certificates are used to identify the connecting client to the network
 * when EAP-TLS is used as either the "phase 1" or "phase 2" 802.1x
 * authentication method.
 *
 * Returns: (transfer none): the "phase 2" client certificate data
 **/
GBytes *
nm_setting_802_1x_get_phase2_client_cert_blob (NMSetting8021x *setting)
{
	_cert_impl_get_blob (setting, phase2_client_cert);
}

/**
 * nm_setting_802_1x_get_phase2_client_cert_path:
 * @setting: the #NMSetting8021x
 *
 * Client certificates are used to identify the connecting client to the network
 * when EAP-TLS is used as either the "phase 1" or "phase 2" 802.1x
 * authentication method.
 *
 * Returns: path to the "phase 2" client certificate file
 **/
const char *
nm_setting_802_1x_get_phase2_client_cert_path (NMSetting8021x *setting)
{
	_cert_impl_get_path (setting, phase2_client_cert);
}

/**
 * nm_setting_802_1x_get_phase2_client_cert_uri:
 * @setting: the #NMSetting8021x
 *
 * Returns the "phase 2" client certificate URI analogously to
 * nm_setting_802_1x_get_phase2_ca_cert_blob() and
 * nm_setting_802_1x_get_phase2_ca_cert_path().
 *
 * Currently it's limited to PKCS#11 URIs ('pkcs11' scheme as defined by RFC
 * 7512), but may be extended to other schemes in future (such as 'file' URIs
 * for local files and 'data' URIs for inline certificate data).
 *
 * Returns: the URI string
 *
 * Since: 1.6
 **/
const char *
nm_setting_802_1x_get_phase2_client_cert_uri (NMSetting8021x *setting)
{
	_cert_impl_get_uri (setting, phase2_client_cert);
}

/**
 * nm_setting_802_1x_set_phase2_client_cert:
 * @setting: the #NMSetting8021x
 * @value: when @scheme is set to either %NM_SETTING_802_1X_CK_SCHEME_PATH
 *   or %NM_SETTING_802_1X_CK_SCHEME_BLOB, pass the path of the "phase2" client
 *   certificate file (PEM, DER, or PKCS#<!-- -->12 format).  The path must be UTF-8
 *   encoded; use g_filename_to_utf8() to convert if needed.  Passing %NULL with
 *   any @scheme clears the "phase2" client certificate.
 * @scheme: desired storage scheme for the certificate
 * @out_format: on successful return, the type of the certificate added
 * @error: on unsuccessful return, an error
 *
 * Reads a certificate from disk and sets the #NMSetting8021x:phase2-client-cert
 * property with the raw certificate data if using the
 * %NM_SETTING_802_1X_CK_SCHEME_BLOB scheme, or with the path to the certificate
 * file if using the %NM_SETTING_802_1X_CK_SCHEME_PATH scheme.
 *
 * Client certificates are used to identify the connecting client to the network
 * when EAP-TLS is used as either the "phase 1" or "phase 2" 802.1x
 * authentication method.
 *
 * Returns: %TRUE if the operation succeeded, %FALSE if it was unsuccessful
 **/
gboolean
nm_setting_802_1x_set_phase2_client_cert (NMSetting8021x *setting,
                                          const char *value,
                                          NMSetting8021xCKScheme scheme,
                                          NMSetting8021xCKFormat *out_format,
                                          GError **error)
{
	return _cert_impl_set (setting, PROP_PHASE2_CLIENT_CERT, value, NULL, scheme, out_format, error);
}

/**
 * nm_setting_802_1x_get_phase2_client_cert_password:
 * @setting: the #NMSetting8021x
 *
 * Returns: the password used to access the "phase2" client certificate stored in
 * #NMSetting8021x:phase2-client-cert property. Only makes sense if the certificate
 * is stored on a PKCS#<!-- -->11 token that requires a login.
 *
 * Since: 1.8
 **/
const char *
nm_setting_802_1x_get_phase2_client_cert_password (NMSetting8021x *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NULL);

	return NM_SETTING_802_1X_GET_PRIVATE (setting)->phase2_client_cert_password;
}

/**
 * nm_setting_802_1x_get_phase2_client_cert_password_flags:
 * @setting: the #NMSetting8021x
 *
 * Returns: the #NMSettingSecretFlags pertaining to the
 * #NMSetting8021x:phase2-client-cert-password
 *
 * Since: 1.8
 **/
NMSettingSecretFlags
nm_setting_802_1x_get_phase2_client_cert_password_flags (NMSetting8021x *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NM_SETTING_SECRET_FLAG_NONE);

	return NM_SETTING_802_1X_GET_PRIVATE (setting)->phase2_client_cert_password_flags;
}

/**
 * nm_setting_802_1x_get_password:
 * @setting: the #NMSetting8021x
 *
 * Returns: the password used by the authentication method, if any, as specified
 *   by the #NMSetting8021x:password property
 **/
const char *
nm_setting_802_1x_get_password (NMSetting8021x *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NULL);

	return NM_SETTING_802_1X_GET_PRIVATE (setting)->password;
}

/**
 * nm_setting_802_1x_get_password_flags:
 * @setting: the #NMSetting8021x
 *
 * Returns: the #NMSettingSecretFlags pertaining to the #NMSetting8021x:password
 **/
NMSettingSecretFlags
nm_setting_802_1x_get_password_flags (NMSetting8021x *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NM_SETTING_SECRET_FLAG_NONE);

	return NM_SETTING_802_1X_GET_PRIVATE (setting)->password_flags;
}

/**
 * nm_setting_802_1x_get_password_raw:
 * @setting: the #NMSetting8021x
 *
 * Returns: (transfer none): the password used by the authentication method as a
 * UTF-8-encoded array of bytes, as specified by the
 * #NMSetting8021x:password-raw property
 **/
GBytes *
nm_setting_802_1x_get_password_raw (NMSetting8021x *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NULL);

	return NM_SETTING_802_1X_GET_PRIVATE (setting)->password_raw;
}

/**
 * nm_setting_802_1x_get_password_raw_flags:
 * @setting: the #NMSetting8021x
 *
 * Returns: the #NMSettingSecretFlags pertaining to the
 *   #NMSetting8021x:password-raw
 **/
NMSettingSecretFlags
nm_setting_802_1x_get_password_raw_flags (NMSetting8021x *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NM_SETTING_SECRET_FLAG_NONE);

	return NM_SETTING_802_1X_GET_PRIVATE (setting)->password_raw_flags;
}

/**
 * nm_setting_802_1x_get_pin:
 * @setting: the #NMSetting8021x
 *
 * Returns: the PIN used by the authentication method, if any, as specified
 *   by the #NMSetting8021x:pin property
 **/
const char *
nm_setting_802_1x_get_pin (NMSetting8021x *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NULL);

	return NM_SETTING_802_1X_GET_PRIVATE (setting)->pin;
}

/**
 * nm_setting_802_1x_get_pin_flags:
 * @setting: the #NMSetting8021x
 *
 * Returns: the #NMSettingSecretFlags pertaining to the
 * #NMSetting8021x:pin
 **/
NMSettingSecretFlags
nm_setting_802_1x_get_pin_flags (NMSetting8021x *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NM_SETTING_SECRET_FLAG_NONE);

	return NM_SETTING_802_1X_GET_PRIVATE (setting)->pin_flags;
}

/**
 * nm_setting_802_1x_get_private_key_scheme:
 * @setting: the #NMSetting8021x
 *
 * Returns the scheme used to store the private key.  If the returned scheme is
 * %NM_SETTING_802_1X_CK_SCHEME_BLOB, use
 * nm_setting_802_1x_get_client_cert_blob(); if
 * %NM_SETTING_802_1X_CK_SCHEME_PATH, use
 * nm_setting_802_1x_get_client_cert_path(); if
 * %NM_SETTING_802_1X_CK_SCHEME_PKCS11, use
 * nm_setting_802_1x_get_client_cert_uri().
 *
 * Returns: scheme used to store the private key (blob or path)
 **/
NMSetting8021xCKScheme
nm_setting_802_1x_get_private_key_scheme (NMSetting8021x *setting)
{
	_cert_impl_get_scheme (setting, private_key);
}

/**
 * nm_setting_802_1x_get_private_key_blob:
 * @setting: the #NMSetting8021x
 *
 * Private keys are used to authenticate the connecting client to the network
 * when EAP-TLS is used as either the "phase 1" or "phase 2" 802.1x
 * authentication method.
 *
 * WARNING: the private key property is not a "secret" property, and thus
 * unencrypted private key data may be readable by unprivileged users.  Private
 * keys should always be encrypted with a private key password.
 *
 * Returns: (transfer none): the private key data
 **/
GBytes *
nm_setting_802_1x_get_private_key_blob (NMSetting8021x *setting)
{
	_cert_impl_get_blob (setting, private_key);
}

/**
 * nm_setting_802_1x_get_private_key_path:
 * @setting: the #NMSetting8021x
 *
 * Private keys are used to authenticate the connecting client to the network
 * when EAP-TLS is used as either the "phase 1" or "phase 2" 802.1x
 * authentication method.
 *
 * Returns: path to the private key file
 **/
const char *
nm_setting_802_1x_get_private_key_path (NMSetting8021x *setting)
{
	_cert_impl_get_path (setting, private_key);
}

/**
 * nm_setting_802_1x_get_private_key_uri:
 * @setting: the #NMSetting8021x
 *
 * Returns the private key URI analogously to
 * nm_setting_802_1x_get_private_key_blob() and
 * nm_setting_802_1x_get_private_key_path().
 *
 * Currently it's limited to PKCS#11 URIs ('pkcs11' scheme as defined by RFC
 * 7512), but may be extended to other schemes in future (such as 'file' URIs
 * for local files and 'data' URIs for inline certificate data).
 *
 * Returns: the URI string
 *
 * Since: 1.6
 **/
const char *
nm_setting_802_1x_get_private_key_uri (NMSetting8021x *setting)
{
	_cert_impl_get_uri (setting, private_key);
}

/**
 * nm_setting_802_1x_set_private_key:
 * @setting: the #NMSetting8021x
 * @value: when @scheme is set to either %NM_SETTING_802_1X_CK_SCHEME_PATH or
 *   %NM_SETTING_802_1X_CK_SCHEME_BLOB, pass the path of the private key file
 *   (PEM, DER, or PKCS#<!-- -->12 format).  The path must be UTF-8 encoded; use
 *   g_filename_to_utf8() to convert if needed.  Passing %NULL with any @scheme
 *   clears the private key.
 * @password: password used to decrypt the private key, or %NULL if the password
 *   is unknown.  If the password is given but fails to decrypt the private key,
 *   an error is returned.
 * @scheme: desired storage scheme for the private key
 * @out_format: on successful return, the type of the private key added
 * @error: on unsuccessful return, an error
 *
 * Private keys are used to authenticate the connecting client to the network
 * when EAP-TLS is used as either the "phase 1" or "phase 2" 802.1x
 * authentication method.
 *
 * This function reads a private key from disk and sets the
 * #NMSetting8021x:private-key property with the private key file data if using
 * the %NM_SETTING_802_1X_CK_SCHEME_BLOB scheme, or with the path to the private
 * key file if using the %NM_SETTING_802_1X_CK_SCHEME_PATH scheme.
 *
 * If @password is given, this function attempts to decrypt the private key to
 * verify that @password is correct, and if it is, updates the
 * #NMSetting8021x:private-key-password property with the given @password.  If
 * the decryption is unsuccessful, %FALSE is returned, @error is set, and no
 * internal data is changed.  If no @password is given, the private key is
 * assumed to be valid, no decryption is performed, and the password may be set
 * at a later time.
 *
 * WARNING: the private key property is not a "secret" property, and thus
 * unencrypted private key data using the BLOB scheme may be readable by
 * unprivileged users.  Private keys should always be encrypted with a private
 * key password to prevent unauthorized access to unencrypted private key data.
 *
 * Returns: %TRUE if the operation succeeded, %FALSE if it was unsuccessful
 **/
gboolean
nm_setting_802_1x_set_private_key (NMSetting8021x *setting,
                                   const char *value,
                                   const char *password,
                                   NMSetting8021xCKScheme scheme,
                                   NMSetting8021xCKFormat *out_format,
                                   GError **error)
{
	return _cert_impl_set (setting, PROP_PRIVATE_KEY, value, password, scheme, out_format, error);
}

/**
 * nm_setting_802_1x_get_private_key_password:
 * @setting: the #NMSetting8021x
 *
 * Returns: the private key password used to decrypt the private key if
 *  previously set with nm_setting_802_1x_set_private_key(), or the
 *  #NMSetting8021x:private-key-password property.
 **/
const char *
nm_setting_802_1x_get_private_key_password (NMSetting8021x *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NULL);

	return NM_SETTING_802_1X_GET_PRIVATE (setting)->private_key_password;
}

/**
 * nm_setting_802_1x_get_private_key_password_flags:
 * @setting: the #NMSetting8021x
 *
 * Returns: the #NMSettingSecretFlags pertaining to the
 * #NMSetting8021x:private-key-password
 **/
NMSettingSecretFlags
nm_setting_802_1x_get_private_key_password_flags (NMSetting8021x *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NM_SETTING_SECRET_FLAG_NONE);

	return NM_SETTING_802_1X_GET_PRIVATE (setting)->private_key_password_flags;
}

/**
 * nm_setting_802_1x_get_private_key_format:
 * @setting: the #NMSetting8021x
 *
 * Returns: the data format of the private key data stored in the
 *   #NMSetting8021x:private-key property
 **/
NMSetting8021xCKFormat
nm_setting_802_1x_get_private_key_format (NMSetting8021x *setting)
{
	return _cert_impl_get_key_format (setting, private_key);
}

/**
 * nm_setting_802_1x_get_phase2_private_key_password:
 * @setting: the #NMSetting8021x
 *
 * Returns: the private key password used to decrypt the private key if
 *  previously set with nm_setting_802_1x_set_phase2_private_key() or the
 *  #NMSetting8021x:phase2-private-key-password property.
 **/
const char *
nm_setting_802_1x_get_phase2_private_key_password (NMSetting8021x *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NULL);

	return NM_SETTING_802_1X_GET_PRIVATE (setting)->phase2_private_key_password;
}

/**
 * nm_setting_802_1x_get_phase2_private_key_password_flags:
 * @setting: the #NMSetting8021x
 *
 * Returns: the #NMSettingSecretFlags pertaining to the
 * #NMSetting8021x:phase2-private-key-password
 **/
NMSettingSecretFlags
nm_setting_802_1x_get_phase2_private_key_password_flags (NMSetting8021x *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NM_SETTING_SECRET_FLAG_NONE);

	return NM_SETTING_802_1X_GET_PRIVATE (setting)->phase2_private_key_password_flags;
}

/**
 * nm_setting_802_1x_get_phase2_private_key_scheme:
 * @setting: the #NMSetting8021x
 *
 * Returns the scheme used to store the "phase 2" private key.  If the returned
 * scheme is %NM_SETTING_802_1X_CK_SCHEME_BLOB, use
 * nm_setting_802_1x_get_client_cert_blob(); if
 * %NM_SETTING_802_1X_CK_SCHEME_PATH, use
 * nm_setting_802_1x_get_client_cert_path(); if
 * %NM_SETTING_802_1X_CK_SCHEME_PKCS11, use
 * nm_setting_802_1x_get_client_cert_uri().
 *
 * Returns: scheme used to store the "phase 2" private key (blob or path)
 **/
NMSetting8021xCKScheme
nm_setting_802_1x_get_phase2_private_key_scheme (NMSetting8021x *setting)
{
	_cert_impl_get_scheme (setting, phase2_private_key);
}

/**
 * nm_setting_802_1x_get_phase2_private_key_blob:
 * @setting: the #NMSetting8021x
 *
 * Private keys are used to authenticate the connecting client to the network
 * when EAP-TLS is used as either the "phase 1" or "phase 2" 802.1x
 * authentication method.
 *
 * WARNING: the phase2 private key property is not a "secret" property, and thus
 * unencrypted private key data may be readable by unprivileged users.  Private
 * keys should always be encrypted with a private key password.
 *
 * Returns: (transfer none): the "phase 2" private key data
 **/
GBytes *
nm_setting_802_1x_get_phase2_private_key_blob (NMSetting8021x *setting)
{
	_cert_impl_get_blob (setting, phase2_private_key);
}

/**
 * nm_setting_802_1x_get_phase2_private_key_path:
 * @setting: the #NMSetting8021x
 *
 * Private keys are used to authenticate the connecting client to the network
 * when EAP-TLS is used as either the "phase 1" or "phase 2" 802.1x
 * authentication method.
 *
 * Returns: path to the "phase 2" private key file
 **/
const char *
nm_setting_802_1x_get_phase2_private_key_path (NMSetting8021x *setting)
{
	_cert_impl_get_path (setting, phase2_private_key);
}

/**
 * nm_setting_802_1x_get_phase2_private_key_uri:
 * @setting: the #NMSetting8021x
 *
 * Returns the "phase 2" private key URI analogously to
 * nm_setting_802_1x_get_phase2_private_key_blob() and
 * nm_setting_802_1x_get_phase2_private_key_path().
 *
 * Currently it's limited to PKCS#11 URIs ('pkcs11' scheme as defined by RFC
 * 7512), but may be extended to other schemes in future (such as 'file' URIs
 * for local files and 'data' URIs for inline certificate data).
 *
 * Returns: the URI string
 *
 * Since: 1.6
 **/
const char *
nm_setting_802_1x_get_phase2_private_key_uri (NMSetting8021x *setting)
{
	_cert_impl_get_uri (setting, phase2_private_key);
}

/**
 * nm_setting_802_1x_set_phase2_private_key:
 * @setting: the #NMSetting8021x
 * @value: when @scheme is set to either %NM_SETTING_802_1X_CK_SCHEME_PATH or
 *   %NM_SETTING_802_1X_CK_SCHEME_BLOB, pass the path of the "phase2" private
 *   key file (PEM, DER, or PKCS#<!-- -->12 format).  The path must be UTF-8 encoded;
 *   use g_filename_to_utf8() to convert if needed.  Passing %NULL with any
 *   @scheme clears the private key.
 * @password: password used to decrypt the private key, or %NULL if the password
 *   is unknown.  If the password is given but fails to decrypt the private key,
 *   an error is returned.
 * @scheme: desired storage scheme for the private key
 * @out_format: on successful return, the type of the private key added
 * @error: on unsuccessful return, an error
 *
 * Private keys are used to authenticate the connecting client to the network
 * when EAP-TLS is used as either the "phase 1" or "phase 2" 802.1x
 * authentication method.
 *
 * This function reads a private key from disk and sets the
 * #NMSetting8021x:phase2-private-key property with the private key file data if
 * using the %NM_SETTING_802_1X_CK_SCHEME_BLOB scheme, or with the path to the
 * private key file if using the %NM_SETTING_802_1X_CK_SCHEME_PATH scheme.
 *
 * If @password is given, this function attempts to decrypt the private key to
 * verify that @password is correct, and if it is, updates the
 * #NMSetting8021x:phase2-private-key-password property with the given
 * @password.  If the decryption is unsuccessful, %FALSE is returned, @error is
 * set, and no internal data is changed.  If no @password is given, the private
 * key is assumed to be valid, no decryption is performed, and the password may
 * be set at a later time.
 *
 * WARNING: the "phase2" private key property is not a "secret" property, and
 * thus unencrypted private key data using the BLOB scheme may be readable by
 * unprivileged users.  Private keys should always be encrypted with a private
 * key password to prevent unauthorized access to unencrypted private key data.
 *
 * Returns: %TRUE if the operation succeeded, %FALSE if it was unsuccessful
 **/
gboolean
nm_setting_802_1x_set_phase2_private_key (NMSetting8021x *setting,
                                          const char *value,
                                          const char *password,
                                          NMSetting8021xCKScheme scheme,
                                          NMSetting8021xCKFormat *out_format,
                                          GError **error)
{
	return _cert_impl_set (setting, PROP_PHASE2_PRIVATE_KEY, value, password, scheme, out_format, error);
}

/**
 * nm_setting_802_1x_get_phase2_private_key_format:
 * @setting: the #NMSetting8021x
 *
 * Returns: the data format of the "phase 2" private key data stored in the
 *   #NMSetting8021x:phase2-private-key property
 **/
NMSetting8021xCKFormat
nm_setting_802_1x_get_phase2_private_key_format (NMSetting8021x *setting)
{
	return _cert_impl_get_key_format (setting, phase2_private_key);
}

/**
 * nm_setting_802_1x_get_auth_timeout:
 * @setting: the #NMSetting8021x
 *
 * Returns the value contained in the #NMSetting8021x:auth-timeout property.
 *
 * Returns: the configured authentication timeout in seconds. Zero means the
 * global default value.
 *
 * Since: 1.8
 **/
int
nm_setting_802_1x_get_auth_timeout (NMSetting8021x *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), 0);

	return NM_SETTING_802_1X_GET_PRIVATE (setting)->auth_timeout;
}

/**
 * nm_setting_802_1x_get_optional:
 * @setting: the #NMSetting8021x
 *
 * Returns the value contained in the #NMSetting8021x:optional property.
 *
 * Returns: %TRUE if the activation should proceed even when the 802.1X
 *     authentication fails; %FALSE otherwise
 *
 * Since: 1.22
 **/
gboolean
nm_setting_802_1x_get_optional (NMSetting8021x *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), FALSE);

	return NM_SETTING_802_1X_GET_PRIVATE (setting)->optional;
}

/*****************************************************************************/

static void
need_secrets_password (NMSetting8021x *self,
                       GPtrArray *secrets,
                       gboolean phase2)
{
	NMSetting8021xPrivate *priv = NM_SETTING_802_1X_GET_PRIVATE (self);

	if (   (!priv->password || !strlen (priv->password))
	    && (!priv->password_raw || !g_bytes_get_size (priv->password_raw))) {
		g_ptr_array_add (secrets, NM_SETTING_802_1X_PASSWORD);
		g_ptr_array_add (secrets, NM_SETTING_802_1X_PASSWORD_RAW);
	}
}

static void
need_secrets_sim (NMSetting8021x *self,
                  GPtrArray *secrets,
                  gboolean phase2)
{
	NMSetting8021xPrivate *priv = NM_SETTING_802_1X_GET_PRIVATE (self);

	if (!priv->pin || !strlen (priv->pin))
		g_ptr_array_add (secrets, NM_SETTING_802_1X_PIN);
}

static gboolean
need_private_key_password (GBytes *blob,
                           NMSetting8021xCKScheme scheme,
                           const char *path,
                           const char *password,
                           NMSettingSecretFlags flags)
{
	NMCryptoFileFormat format = NM_CRYPTO_FILE_FORMAT_UNKNOWN;

	if (flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED)
		return FALSE;

	if (   scheme == NM_SETTING_802_1X_CK_SCHEME_PKCS11
	    && flags == NM_SETTING_SECRET_FLAG_NONE)
		return FALSE;

	/* Private key password is required */
	if (password) {
		if (path)
			format = nm_crypto_verify_private_key (path, password, NULL, NULL);
		else if (blob)
			format = nm_crypto_verify_private_key_data (g_bytes_get_data (blob, NULL),
			                                            g_bytes_get_size (blob),
			                                            password, NULL, NULL);
		else
			return FALSE;
	}

	return (format == NM_CRYPTO_FILE_FORMAT_UNKNOWN);
}

static void
need_secrets_tls (NMSetting8021x *self,
                  GPtrArray *secrets,
                  gboolean phase2)
{
	NMSetting8021xPrivate *priv = NM_SETTING_802_1X_GET_PRIVATE (self);
	NMSetting8021xCKScheme scheme;
	GBytes *blob = NULL;
	const char *path = NULL;

	if (phase2) {
		scheme = nm_setting_802_1x_get_phase2_private_key_scheme (self);
		if (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH)
			path = nm_setting_802_1x_get_phase2_private_key_path (self);
		else if (scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB)
			blob = nm_setting_802_1x_get_phase2_private_key_blob (self);
		else if (scheme != NM_SETTING_802_1X_CK_SCHEME_PKCS11)
			g_warning ("%s: unknown phase2 private key scheme %d", __func__, scheme);

		if (need_private_key_password (blob, scheme, path,
		                               priv->phase2_private_key_password,
		                               priv->phase2_private_key_password_flags))
			g_ptr_array_add (secrets, NM_SETTING_802_1X_PHASE2_PRIVATE_KEY_PASSWORD);

		scheme = nm_setting_802_1x_get_phase2_ca_cert_scheme (self);
		if (    scheme == NM_SETTING_802_1X_CK_SCHEME_PKCS11
		    && !(   priv->phase2_ca_cert_password_flags == NM_SETTING_SECRET_FLAG_NONE
		         || priv->phase2_ca_cert_password_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED)
		    && !priv->phase2_ca_cert_password)
			g_ptr_array_add (secrets, NM_SETTING_802_1X_PHASE2_CA_CERT_PASSWORD);

		scheme = nm_setting_802_1x_get_phase2_client_cert_scheme (self);
		if (    scheme == NM_SETTING_802_1X_CK_SCHEME_PKCS11
		    && !(   priv->phase2_client_cert_password_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED
		         || priv->phase2_client_cert_password_flags == NM_SETTING_SECRET_FLAG_NONE)
		    && !priv->phase2_client_cert_password)
			g_ptr_array_add (secrets, NM_SETTING_802_1X_PHASE2_CLIENT_CERT_PASSWORD);
	} else {
		scheme = nm_setting_802_1x_get_private_key_scheme (self);
		if (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH)
			path = nm_setting_802_1x_get_private_key_path (self);
		else if (scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB)
			blob = nm_setting_802_1x_get_private_key_blob (self);
		else if (scheme != NM_SETTING_802_1X_CK_SCHEME_PKCS11)
			g_warning ("%s: unknown private key scheme %d", __func__, scheme);

		if (need_private_key_password (blob, scheme, path,
		                               priv->private_key_password,
		                               priv->private_key_password_flags))
			g_ptr_array_add (secrets, NM_SETTING_802_1X_PRIVATE_KEY_PASSWORD);

		scheme = nm_setting_802_1x_get_ca_cert_scheme (self);
		if (    scheme == NM_SETTING_802_1X_CK_SCHEME_PKCS11
		    && !(   priv->ca_cert_password_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED
		         || priv->ca_cert_password_flags == NM_SETTING_SECRET_FLAG_NONE)
		    && !priv->ca_cert_password)
			g_ptr_array_add (secrets, NM_SETTING_802_1X_CA_CERT_PASSWORD);

		scheme = nm_setting_802_1x_get_client_cert_scheme (self);
		if (    scheme == NM_SETTING_802_1X_CK_SCHEME_PKCS11
		    && !(   priv->client_cert_password_flags == NM_SETTING_SECRET_FLAG_NONE
		         || priv->client_cert_password_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED)
		    && !priv->client_cert_password)
			g_ptr_array_add (secrets, NM_SETTING_802_1X_CLIENT_CERT_PASSWORD);
	}
}

static gboolean
verify_tls (NMSetting8021x *self, gboolean phase2, GError **error)
{
	NMSetting8021xPrivate *priv = NM_SETTING_802_1X_GET_PRIVATE (self);

	if (phase2) {
		if (!priv->phase2_client_cert) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_MISSING_PROPERTY,
			                     _("property is missing"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_PHASE2_CLIENT_CERT);
			return FALSE;
		} else if (!g_bytes_get_size (priv->phase2_client_cert)) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     _("property is empty"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_PHASE2_CLIENT_CERT);
			return FALSE;
		}

		/* Private key is required for TLS */
		if (!priv->phase2_private_key) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_MISSING_PROPERTY,
			                     _("property is missing"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_PHASE2_PRIVATE_KEY);
			return FALSE;
		} else if (!g_bytes_get_size (priv->phase2_private_key)) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     _("property is empty"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_PHASE2_PRIVATE_KEY);
			return FALSE;
		}

		/* If the private key is PKCS#12, check that it matches the client cert */
		if (nm_crypto_is_pkcs12_data (g_bytes_get_data (priv->phase2_private_key, NULL),
		                              g_bytes_get_size (priv->phase2_private_key),
		                              NULL)) {
			if (!g_bytes_equal (priv->phase2_private_key, priv->phase2_client_cert)) {
				g_set_error (error,
				             NM_CONNECTION_ERROR,
				             NM_CONNECTION_ERROR_INVALID_PROPERTY,
				             _("has to match '%s' property for PKCS#12"),
				             NM_SETTING_802_1X_PHASE2_PRIVATE_KEY);
				g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_PHASE2_CLIENT_CERT);
				return FALSE;
			}
		}
	} else {
		if (!priv->client_cert) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_MISSING_PROPERTY,
			                     _("property is missing"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_CLIENT_CERT);
			return FALSE;
		} else if (!g_bytes_get_size (priv->client_cert)) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     _("property is empty"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_CLIENT_CERT);
			return FALSE;
		}

		/* Private key is required for TLS */
		if (!priv->private_key) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_MISSING_PROPERTY,
			                     _("property is missing"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_PRIVATE_KEY);
			return FALSE;
		} else if (!g_bytes_get_size (priv->private_key)) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     _("property is empty"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_PRIVATE_KEY);
			return FALSE;
		}

		/* If the private key is PKCS#12, check that it matches the client cert */
		if (nm_crypto_is_pkcs12_data (g_bytes_get_data (priv->private_key, NULL),
		                              g_bytes_get_size (priv->private_key),
		                              NULL)) {
			if (!g_bytes_equal (priv->private_key, priv->client_cert)) {
				g_set_error (error,
				             NM_CONNECTION_ERROR,
				             NM_CONNECTION_ERROR_INVALID_PROPERTY,
				             _("has to match '%s' property for PKCS#12"),
				             NM_SETTING_802_1X_PRIVATE_KEY);
				g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_CLIENT_CERT);
				return FALSE;
			}
		}
	}

	return TRUE;
}

static gboolean
verify_ttls (NMSetting8021x *self, gboolean phase2, GError **error)
{
	NMSetting8021xPrivate *priv = NM_SETTING_802_1X_GET_PRIVATE (self);

	if (   (!priv->identity || !strlen (priv->identity))
	    && (!priv->anonymous_identity || !strlen (priv->anonymous_identity))) {
		if (!priv->identity) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_MISSING_PROPERTY,
			                     _("property is missing"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_IDENTITY);
		} else if (!strlen (priv->identity)) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     _("property is empty"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_IDENTITY);
		} else if (!priv->anonymous_identity) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_MISSING_PROPERTY,
			                     _("property is missing"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_ANONYMOUS_IDENTITY);
		} else {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     _("property is empty"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_ANONYMOUS_IDENTITY);
		}
		return FALSE;
	}

	if (   (!priv->phase2_auth || !strlen (priv->phase2_auth))
	    && (!priv->phase2_autheap || !strlen (priv->phase2_autheap))) {
		if (!priv->phase2_auth) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_MISSING_PROPERTY,
			                     _("property is missing"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_PHASE2_AUTH);
		} else if (!strlen (priv->phase2_auth)) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     _("property is empty"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_PHASE2_AUTH);
		} else if (!priv->phase2_autheap) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_MISSING_PROPERTY,
			                     _("property is missing"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_PHASE2_AUTHEAP);
		} else {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     _("property is empty"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_PHASE2_AUTHEAP);
		}
		return FALSE;
	}

	return TRUE;
}

static gboolean
verify_identity (NMSetting8021x *self, gboolean phase2, GError **error)
{
	NMSetting8021xPrivate *priv = NM_SETTING_802_1X_GET_PRIVATE (self);

	if (!priv->identity) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_MISSING_PROPERTY,
		                     _("property is missing"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_IDENTITY);
		return FALSE;
	} else if (!strlen (priv->identity)) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("property is empty"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_IDENTITY);
		return FALSE;
	}

	return TRUE;
}

static void
need_secrets_phase2 (NMSetting8021x *self,
                     GPtrArray *secrets,
                     gboolean phase2)
{
	NMSetting8021xPrivate *priv = NM_SETTING_802_1X_GET_PRIVATE (self);
	char *method = NULL;
	int i;

	g_return_if_fail (phase2 == FALSE);

	/* Check phase2_auth and phase2_autheap */
	method = priv->phase2_auth;
	if (!method && priv->phase2_autheap)
		method = priv->phase2_autheap;

	if (!method) {
		g_warning ("Couldn't find EAP method.");
		g_assert_not_reached();
		return;
	}

	/* Ask the configured phase2 method if it needs secrets */
	for (i = 0; eap_methods_table[i].method; i++) {
		if (eap_methods_table[i].ns_func == NULL)
			continue;
		if (!strcmp (eap_methods_table[i].method, method)) {
			(*eap_methods_table[i].ns_func) (self, secrets, TRUE);
			break;
		}
	}
}

static const EAPMethodsTable eap_methods_table[] = {
	{ "leap", need_secrets_password, verify_identity },
	{ "pwd", need_secrets_password, verify_identity },
	{ "md5", need_secrets_password, verify_identity },
	{ "pap", need_secrets_password, verify_identity },
	{ "chap", need_secrets_password, verify_identity },
	{ "mschap", need_secrets_password, verify_identity },
	{ "mschapv2", need_secrets_password, verify_identity },
	{ "fast", need_secrets_password, verify_identity },
	{ "tls", need_secrets_tls, verify_tls },
	{ "peap", need_secrets_phase2, verify_ttls },
	{ "ttls", need_secrets_phase2, verify_ttls },
	{ "sim", need_secrets_sim, NULL },
	{ "gtc", need_secrets_password, verify_identity },
	{ "otp", NULL, NULL },  // FIXME: implement
	{ "external", NULL, NULL },
	{ NULL, NULL, NULL }
};

static gboolean
verify (NMSetting *setting, NMConnection *connection, GError **error)
{
	NMSetting8021x *self = NM_SETTING_802_1X (setting);
	NMSetting8021xPrivate *priv = NM_SETTING_802_1X_GET_PRIVATE (self);
	const char *valid_eap[] = { "leap", "md5", "tls", "peap", "ttls", "sim", "fast", "pwd", "external", NULL };
	GSList *iter;

	if (error)
		g_return_val_if_fail (*error == NULL, FALSE);

	if (   connection
	    && priv->optional
	    && !nm_streq0 (nm_connection_get_connection_type (connection), NM_SETTING_WIRED_SETTING_NAME)) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("can be enabled only on Ethernet connections"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_OPTIONAL);
		return FALSE;
	}

	if (!priv->eap) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_MISSING_PROPERTY,
		                     _("property is missing"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_EAP);
		return FALSE;
	}

	if (!_nm_utils_string_slist_validate (priv->eap, valid_eap)) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("property is invalid"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_EAP);
		return FALSE;
	}

	/* Ask each configured EAP method if its valid */
	for (iter = priv->eap; iter; iter = g_slist_next (iter)) {
		const char *method = (const char *) iter->data;
		int i;

		for (i = 0; eap_methods_table[i].method; i++) {
			if (eap_methods_table[i].v_func == NULL)
				continue;
			if (!strcmp (eap_methods_table[i].method, method)) {
				if (!(*eap_methods_table[i].v_func) (self, FALSE, error))
					return FALSE;
				break;
			}
		}
	}

	if (!NM_IN_STRSET (priv->phase1_peapver, NULL,
	                                         "0",
	                                         "1")) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("'%s' is not a valid value for the property"),
		             priv->phase1_peapver);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_PHASE1_PEAPVER);
		return FALSE;
	}

	if (!NM_IN_STRSET (priv->phase1_peaplabel, NULL,
	                                           "0",
	                                           "1")) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("'%s' is not a valid value for the property"),
		             priv->phase1_peaplabel);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_PHASE1_PEAPLABEL);
		return FALSE;
	}

	if (!NM_IN_STRSET (priv->phase1_fast_provisioning, NULL,
	                                                   "0",
	                                                   "1",
	                                                   "2",
	                                                   "3")) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("'%s' is not a valid value for the property"),
		             priv->phase1_fast_provisioning);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_PHASE1_FAST_PROVISIONING);
		return FALSE;
	}

	if (NM_FLAGS_ANY (priv->phase1_auth_flags, ~NM_SETTING_802_1X_AUTH_FLAGS_ALL)) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("invalid auth flags"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_PHASE1_AUTH_FLAGS);
		return FALSE;
	}

	if (!NM_IN_STRSET (priv->phase2_auth, NULL,
	                                      "pap",
	                                      "chap",
	                                      "mschap",
	                                      "mschapv2",
	                                      "gtc",
	                                      "otp",
	                                      "md5",
	                                      "tls")) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("'%s' is not a valid value for the property"),
		             priv->phase2_auth);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_PHASE2_AUTH);
		return FALSE;
	}

	if (!NM_IN_STRSET (priv->phase2_autheap, NULL,
	                                         "md5",
	                                         "mschapv2",
	                                         "otp",
	                                         "gtc",
	                                         "tls")) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("'%s' is not a valid value for the property"),
		             priv->phase2_autheap);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_PHASE2_AUTHEAP);
		return FALSE;
	}

	if (!_cert_verify_property (priv->ca_cert,
	                            NM_SETTING_802_1X_CA_CERT,
	                            priv->ca_cert_password,
	                            NM_SETTING_802_1X_CA_CERT_PASSWORD,
	                            error))
		return FALSE;
	if (!_cert_verify_property (priv->phase2_ca_cert,
	                            NM_SETTING_802_1X_PHASE2_CA_CERT,
	                            priv->phase2_ca_cert_password,
	                            NM_SETTING_802_1X_PHASE2_CA_CERT_PASSWORD,
	                            error))
		return FALSE;

	if (!_cert_verify_property (priv->client_cert,
	                            NM_SETTING_802_1X_CLIENT_CERT,
	                            priv->client_cert_password,
	                            NM_SETTING_802_1X_CLIENT_CERT_PASSWORD,
	                            error))
		return FALSE;
	if (!_cert_verify_property (priv->phase2_client_cert,
	                            NM_SETTING_802_1X_PHASE2_CLIENT_CERT,
	                            priv->phase2_client_cert_password,
	                            NM_SETTING_802_1X_PHASE2_CLIENT_CERT_PASSWORD,
	                            error))
		return FALSE;

	if (!_cert_verify_property (priv->private_key,
	                            NM_SETTING_802_1X_PRIVATE_KEY,
	                            NULL,
	                            NULL,
	                            error))
		return FALSE;
	if (!_cert_verify_property (priv->phase2_private_key,
	                            NM_SETTING_802_1X_PHASE2_PRIVATE_KEY,
	                            NULL,
	                            NULL,
	                            error))
		return FALSE;

	return TRUE;
}

/*****************************************************************************/

static GPtrArray *
need_secrets (NMSetting *setting)
{
	NMSetting8021x *self = NM_SETTING_802_1X (setting);
	NMSetting8021xPrivate *priv = NM_SETTING_802_1X_GET_PRIVATE (self);
	GSList *iter;
	GPtrArray *secrets;
	gboolean eap_method_found = FALSE;

	secrets = g_ptr_array_sized_new (4);

	/* Ask each configured EAP method if it needs secrets */
	for (iter = priv->eap; iter && !eap_method_found; iter = g_slist_next (iter)) {
		const char *method = (const char *) iter->data;
		int i;

		for (i = 0; eap_methods_table[i].method; i++) {
			if (eap_methods_table[i].ns_func == NULL)
				continue;
			if (!strcmp (eap_methods_table[i].method, method)) {
				(*eap_methods_table[i].ns_func) (self, secrets, FALSE);

				/* Only break out of the outer loop if this EAP method
				 * needed secrets.
				 */
				if (secrets->len > 0)
					eap_method_found = TRUE;
				break;
			}
		}
	}

	if (secrets->len == 0) {
		g_ptr_array_free (secrets, TRUE);
		return NULL;
	}

	return secrets;
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMSetting8021x *setting = NM_SETTING_802_1X (object);
	NMSetting8021xPrivate *priv = NM_SETTING_802_1X_GET_PRIVATE (setting);

	switch (prop_id) {
	case PROP_EAP:
		g_value_take_boxed (value, _nm_utils_slist_to_strv (priv->eap, TRUE));
		break;
	case PROP_IDENTITY:
		g_value_set_string (value, priv->identity);
		break;
	case PROP_ANONYMOUS_IDENTITY:
		g_value_set_string (value, priv->anonymous_identity);
		break;
	case PROP_PAC_FILE:
		g_value_set_string (value, priv->pac_file);
		break;
	case PROP_CA_CERT:
		g_value_set_boxed (value, priv->ca_cert);
		break;
	case PROP_CA_CERT_PASSWORD:
		g_value_set_string (value, priv->ca_cert_password);
		break;
	case PROP_CA_CERT_PASSWORD_FLAGS:
		g_value_set_flags (value, priv->ca_cert_password_flags);
		break;
	case PROP_CA_PATH:
		g_value_set_string (value, priv->ca_path);
		break;
	case PROP_SUBJECT_MATCH:
		g_value_set_string (value, priv->subject_match);
		break;
	case PROP_ALTSUBJECT_MATCHES:
		g_value_take_boxed (value, _nm_utils_slist_to_strv (priv->altsubject_matches, TRUE));
		break;
	case PROP_DOMAIN_SUFFIX_MATCH:
		g_value_set_string (value, priv->domain_suffix_match);
		break;
	case PROP_CLIENT_CERT:
		g_value_set_boxed (value, priv->client_cert);
		break;
	case PROP_CLIENT_CERT_PASSWORD:
		g_value_set_string (value, priv->client_cert_password);
		break;
	case PROP_CLIENT_CERT_PASSWORD_FLAGS:
		g_value_set_flags (value, priv->client_cert_password_flags);
		break;
	case PROP_PHASE1_PEAPVER:
		g_value_set_string (value, priv->phase1_peapver);
		break;
	case PROP_PHASE1_PEAPLABEL:
		g_value_set_string (value, priv->phase1_peaplabel);
		break;
	case PROP_PHASE1_FAST_PROVISIONING:
		g_value_set_string (value, priv->phase1_fast_provisioning);
		break;
	case PROP_PHASE1_AUTH_FLAGS:
		g_value_set_uint (value, priv->phase1_auth_flags);
		break;
	case PROP_PHASE2_AUTH:
		g_value_set_string (value, priv->phase2_auth);
		break;
	case PROP_PHASE2_AUTHEAP:
		g_value_set_string (value, priv->phase2_autheap);
		break;
	case PROP_PHASE2_CA_CERT:
		g_value_set_boxed (value, priv->phase2_ca_cert);
		break;
	case PROP_PHASE2_CA_CERT_PASSWORD:
		g_value_set_string (value, priv->phase2_ca_cert_password);
		break;
	case PROP_PHASE2_CA_CERT_PASSWORD_FLAGS:
		g_value_set_flags (value, priv->phase2_ca_cert_password_flags);
		break;
	case PROP_PHASE2_CA_PATH:
		g_value_set_string (value, priv->phase2_ca_path);
		break;
	case PROP_PHASE2_SUBJECT_MATCH:
		g_value_set_string (value, priv->phase2_subject_match);
		break;
	case PROP_PHASE2_ALTSUBJECT_MATCHES:
		g_value_take_boxed (value, _nm_utils_slist_to_strv (priv->phase2_altsubject_matches, TRUE));
		break;
	case PROP_PHASE2_DOMAIN_SUFFIX_MATCH:
		g_value_set_string (value, priv->phase2_domain_suffix_match);
		break;
	case PROP_PHASE2_CLIENT_CERT:
		g_value_set_boxed (value, priv->phase2_client_cert);
		break;
	case PROP_PHASE2_CLIENT_CERT_PASSWORD:
		g_value_set_string (value, priv->phase2_client_cert_password);
		break;
	case PROP_PHASE2_CLIENT_CERT_PASSWORD_FLAGS:
		g_value_set_flags (value, priv->phase2_client_cert_password_flags);
		break;
	case PROP_PASSWORD:
		g_value_set_string (value, priv->password);
		break;
	case PROP_PASSWORD_FLAGS:
		g_value_set_flags (value, priv->password_flags);
		break;
	case PROP_PASSWORD_RAW:
		g_value_set_boxed (value, priv->password_raw);
		break;
	case PROP_PASSWORD_RAW_FLAGS:
		g_value_set_flags (value, priv->password_raw_flags);
		break;
	case PROP_PRIVATE_KEY:
		g_value_set_boxed (value, priv->private_key);
		break;
	case PROP_PRIVATE_KEY_PASSWORD:
		g_value_set_string (value, priv->private_key_password);
		break;
	case PROP_PRIVATE_KEY_PASSWORD_FLAGS:
		g_value_set_flags (value, priv->private_key_password_flags);
		break;
	case PROP_PHASE2_PRIVATE_KEY:
		g_value_set_boxed (value, priv->phase2_private_key);
		break;
	case PROP_PHASE2_PRIVATE_KEY_PASSWORD:
		g_value_set_string (value, priv->phase2_private_key_password);
		break;
	case PROP_PHASE2_PRIVATE_KEY_PASSWORD_FLAGS:
		g_value_set_flags (value, priv->phase2_private_key_password_flags);
		break;
	case PROP_PIN:
		g_value_set_string (value, priv->pin);
		break;
	case PROP_PIN_FLAGS:
		g_value_set_flags (value, priv->pin_flags);
		break;
	case PROP_SYSTEM_CA_CERTS:
		g_value_set_boolean (value, priv->system_ca_certs);
		break;
	case PROP_AUTH_TIMEOUT:
		g_value_set_int (value, priv->auth_timeout);
		break;
	case PROP_OPTIONAL:
		g_value_set_boolean (value, priv->optional);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMSetting8021x *setting = NM_SETTING_802_1X (object);
	NMSetting8021xPrivate *priv = NM_SETTING_802_1X_GET_PRIVATE (setting);

	switch (prop_id) {
	case PROP_EAP:
		g_slist_free_full (priv->eap, g_free);
		priv->eap = _nm_utils_strv_to_slist (g_value_get_boxed (value), TRUE);
		break;
	case PROP_IDENTITY:
		g_free (priv->identity);
		priv->identity = g_value_dup_string (value);
		break;
	case PROP_ANONYMOUS_IDENTITY:
		g_free (priv->anonymous_identity);
		priv->anonymous_identity = g_value_dup_string (value);
		break;
	case PROP_PAC_FILE:
		g_free (priv->pac_file);
		priv->pac_file = g_value_dup_string (value);
		break;
	case PROP_CA_CERT:
		g_bytes_unref (priv->ca_cert);
		priv->ca_cert = g_value_dup_boxed (value);
		break;
	case PROP_CA_CERT_PASSWORD:
		g_free (priv->ca_cert_password);
		priv->ca_cert_password = g_value_dup_string (value);
		break;
	case PROP_CA_CERT_PASSWORD_FLAGS:
		priv->ca_cert_password_flags = g_value_get_flags (value);
		break;
	case PROP_CA_PATH:
		g_free (priv->ca_path);
		priv->ca_path = g_value_dup_string (value);
		break;
	case PROP_SUBJECT_MATCH:
		g_free (priv->subject_match);
		priv->subject_match = nm_strdup_not_empty (g_value_get_string (value));
		break;
	case PROP_ALTSUBJECT_MATCHES:
		g_slist_free_full (priv->altsubject_matches, g_free);
		priv->altsubject_matches = _nm_utils_strv_to_slist (g_value_get_boxed (value), TRUE);
		break;
	case PROP_DOMAIN_SUFFIX_MATCH:
		g_free (priv->domain_suffix_match);
		priv->domain_suffix_match = nm_strdup_not_empty (g_value_get_string (value));
		break;
	case PROP_CLIENT_CERT:
		g_bytes_unref (priv->client_cert);
		priv->client_cert = g_value_dup_boxed (value);
		break;
	case PROP_CLIENT_CERT_PASSWORD:
		g_free (priv->client_cert_password);
		priv->client_cert_password = g_value_dup_string (value);
		break;
	case PROP_CLIENT_CERT_PASSWORD_FLAGS:
		priv->client_cert_password_flags = g_value_get_flags (value);
		break;
	case PROP_PHASE1_PEAPVER:
		g_free (priv->phase1_peapver);
		priv->phase1_peapver = g_value_dup_string (value);
		break;
	case PROP_PHASE1_PEAPLABEL:
		g_free (priv->phase1_peaplabel);
		priv->phase1_peaplabel = g_value_dup_string (value);
		break;
	case PROP_PHASE1_FAST_PROVISIONING:
		g_free (priv->phase1_fast_provisioning);
		priv->phase1_fast_provisioning = g_value_dup_string (value);
		break;
	case PROP_PHASE1_AUTH_FLAGS:
		priv->phase1_auth_flags = g_value_get_uint (value);
		break;
	case PROP_PHASE2_AUTH:
		g_free (priv->phase2_auth);
		priv->phase2_auth = g_value_dup_string (value);
		break;
	case PROP_PHASE2_AUTHEAP:
		g_free (priv->phase2_autheap);
		priv->phase2_autheap = g_value_dup_string (value);
		break;
	case PROP_PHASE2_CA_CERT:
		g_bytes_unref (priv->phase2_ca_cert);
		priv->phase2_ca_cert = g_value_dup_boxed (value);
		break;
	case PROP_PHASE2_CA_CERT_PASSWORD:
		g_free (priv->phase2_ca_cert_password);
		priv->phase2_ca_cert_password = g_value_dup_string (value);
		break;
	case PROP_PHASE2_CA_CERT_PASSWORD_FLAGS:
		priv->phase2_ca_cert_password_flags = g_value_get_flags (value);
		break;
	case PROP_PHASE2_CA_PATH:
		g_free (priv->phase2_ca_path);
		priv->phase2_ca_path = g_value_dup_string (value);
		break;
	case PROP_PHASE2_SUBJECT_MATCH:
		g_free (priv->phase2_subject_match);
		priv->phase2_subject_match = nm_strdup_not_empty (g_value_get_string (value));
		break;
	case PROP_PHASE2_ALTSUBJECT_MATCHES:
		g_slist_free_full (priv->phase2_altsubject_matches, g_free);
		priv->phase2_altsubject_matches = _nm_utils_strv_to_slist (g_value_get_boxed (value), TRUE);
		break;
	case PROP_PHASE2_DOMAIN_SUFFIX_MATCH:
		g_free (priv->phase2_domain_suffix_match);
		priv->phase2_domain_suffix_match = nm_strdup_not_empty (g_value_get_string (value));
		break;
	case PROP_PHASE2_CLIENT_CERT:
		g_bytes_unref (priv->phase2_client_cert);
		priv->phase2_client_cert = g_value_dup_boxed (value);
		break;
	case PROP_PHASE2_CLIENT_CERT_PASSWORD:
		g_free (priv->phase2_client_cert_password);
		priv->phase2_client_cert_password = g_value_dup_string (value);
		break;
	case PROP_PHASE2_CLIENT_CERT_PASSWORD_FLAGS:
		priv->phase2_client_cert_password_flags = g_value_get_flags (value);
		break;
	case PROP_PASSWORD:
		g_free (priv->password);
		priv->password = g_value_dup_string (value);
		break;
	case PROP_PASSWORD_FLAGS:
		priv->password_flags = g_value_get_flags (value);
		break;
	case PROP_PASSWORD_RAW:
		g_bytes_unref (priv->password_raw);
		priv->password_raw = g_value_dup_boxed (value);
		break;
	case PROP_PASSWORD_RAW_FLAGS:
		priv->password_raw_flags = g_value_get_flags (value);
		break;
	case PROP_PRIVATE_KEY:
		g_bytes_unref (priv->private_key);
		priv->private_key = g_value_dup_boxed (value);
		break;
	case PROP_PRIVATE_KEY_PASSWORD:
		nm_free_secret (priv->private_key_password);
		priv->private_key_password = g_value_dup_string (value);
		break;
	case PROP_PRIVATE_KEY_PASSWORD_FLAGS:
		priv->private_key_password_flags = g_value_get_flags (value);
		break;
	case PROP_PHASE2_PRIVATE_KEY:
		g_bytes_unref (priv->phase2_private_key);
		priv->phase2_private_key = g_value_dup_boxed (value);
		break;
	case PROP_PHASE2_PRIVATE_KEY_PASSWORD:
		nm_free_secret (priv->phase2_private_key_password);
		priv->phase2_private_key_password = g_value_dup_string (value);
		break;
	case PROP_PHASE2_PRIVATE_KEY_PASSWORD_FLAGS:
		priv->phase2_private_key_password_flags = g_value_get_flags (value);
		break;
	case PROP_PIN:
		g_free (priv->pin);
		priv->pin = g_value_dup_string (value);
		break;
	case PROP_PIN_FLAGS:
		priv->pin_flags = g_value_get_flags (value);
		break;
	case PROP_SYSTEM_CA_CERTS:
		priv->system_ca_certs = g_value_get_boolean (value);
		break;
	case PROP_AUTH_TIMEOUT:
		priv->auth_timeout = g_value_get_int (value);
		break;
	case PROP_OPTIONAL:
		priv->optional = g_value_get_boolean (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_setting_802_1x_init (NMSetting8021x *setting)
{
}

/**
 * nm_setting_802_1x_new:
 *
 * Creates a new #NMSetting8021x object with default values.
 *
 * Returns: the new empty #NMSetting8021x object
 **/
NMSetting *
nm_setting_802_1x_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_802_1X, NULL);
}

static void
finalize (GObject *object)
{
	NMSetting8021x *self = NM_SETTING_802_1X (object);
	NMSetting8021xPrivate *priv = NM_SETTING_802_1X_GET_PRIVATE (self);

	g_free (priv->identity);
	g_free (priv->anonymous_identity);
	g_free (priv->ca_path);
	g_free (priv->subject_match);
	g_free (priv->domain_suffix_match);
	g_free (priv->phase1_peapver);
	g_free (priv->phase1_peaplabel);
	g_free (priv->phase1_fast_provisioning);
	g_free (priv->phase2_auth);
	g_free (priv->phase2_autheap);
	g_free (priv->phase2_ca_path);
	g_free (priv->phase2_subject_match);
	g_free (priv->phase2_domain_suffix_match);
	g_free (priv->password);
	g_bytes_unref (priv->password_raw);
	g_free (priv->pin);

	g_slist_free_full (priv->eap, g_free);
	g_slist_free_full (priv->altsubject_matches, g_free);
	g_slist_free_full (priv->phase2_altsubject_matches, g_free);

	g_bytes_unref (priv->ca_cert);
	g_free (priv->ca_cert_password);
	g_bytes_unref (priv->client_cert);
	g_free (priv->client_cert_password);
	g_bytes_unref (priv->private_key);
	nm_free_secret (priv->private_key_password);
	g_bytes_unref (priv->phase2_ca_cert);
	g_free (priv->phase2_ca_cert_password);
	g_bytes_unref (priv->phase2_client_cert);
	g_free (priv->phase2_client_cert_password);
	g_bytes_unref (priv->phase2_private_key);
	nm_free_secret (priv->phase2_private_key_password);

	G_OBJECT_CLASS (nm_setting_802_1x_parent_class)->finalize (object);
}

static void
nm_setting_802_1x_class_init (NMSetting8021xClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMSettingClass *setting_class = NM_SETTING_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NMSetting8021xPrivate));

	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->finalize     = finalize;

	setting_class->verify       = verify;
	setting_class->need_secrets = need_secrets;

	/**
	 * NMSetting8021x:eap:
	 *
	 * The allowed EAP method to be used when authenticating to the network with
	 * 802.1x.  Valid methods are: "leap", "md5", "tls", "peap", "ttls", "pwd",
	 * and "fast".  Each method requires different configuration using the
	 * properties of this setting; refer to wpa_supplicant documentation for the
	 * allowed combinations.
	 **/
	/* ---ifcfg-rh---
	 * property: eap
	 * variable: IEEE_8021X_EAP_METHODS(+)
	 * values: "LEAP", "PWD", "TLS", "PEAP", "TTLS", "FAST"
	 * description: EAP method for 802.1X authentication.
	 * example: IEEE_8021X_EAP_METHODS=PEAP
	 * ---end---
	 */
	obj_properties[PROP_EAP] =
	    g_param_spec_boxed (NM_SETTING_802_1X_EAP, "", "",
	                        G_TYPE_STRV,
	                        G_PARAM_READWRITE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMSetting8021x:identity:
	 *
	 * Identity string for EAP authentication methods.  Often the user's user or
	 * login name.
	 **/
	/* ---ifcfg-rh---
	 * property: identity
	 * variable: IEEE_8021X_IDENTITY(+)
	 * description: Identity for EAP authentication methods.
	 * example: IEEE_8021X_IDENTITY=itsme
	 * ---end---
	 */
	obj_properties[PROP_IDENTITY] =
	    g_param_spec_string (NM_SETTING_802_1X_IDENTITY, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSetting8021x:anonymous-identity:
	 *
	 * Anonymous identity string for EAP authentication methods.  Used as the
	 * unencrypted identity with EAP types that support different tunneled
	 * identity like EAP-TTLS.
	 **/
	/* ---ifcfg-rh---
	 * property: anonymous-identity
	 * variable: IEEE_8021X_ANON_IDENTITY(+)
	 * description: Anonymous identity for EAP authentication methods.
	 * ---end---
	 */
	obj_properties[PROP_ANONYMOUS_IDENTITY] =
	    g_param_spec_string (NM_SETTING_802_1X_ANONYMOUS_IDENTITY, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSetting8021x:pac-file:
	 *
	 * UTF-8 encoded file path containing PAC for EAP-FAST.
	 **/
	/* ---ifcfg-rh---
	 * property: pac-file
	 * variable: IEEE_8021X_PAC_FILE(+)
	 * description: File with PAC (Protected Access Credential) for EAP-FAST.
	 * example: IEEE_8021X_PAC_FILE=/home/joe/my-fast.pac
	 * ---end---
	 */
	obj_properties[PROP_PAC_FILE] =
	    g_param_spec_string (NM_SETTING_802_1X_PAC_FILE, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSetting8021x:ca-cert:
	 *
	 * Contains the CA certificate if used by the EAP method specified in the
	 * #NMSetting8021x:eap property.
	 *
	 * Certificate data is specified using a "scheme"; two are currently
	 * supported: blob and path. When using the blob scheme (which is backwards
	 * compatible with NM 0.7.x) this property should be set to the
	 * certificate's DER encoded data. When using the path scheme, this property
	 * should be set to the full UTF-8 encoded path of the certificate, prefixed
	 * with the string "file://" and ending with a terminating NUL byte. This
	 * property can be unset even if the EAP method supports CA certificates,
	 * but this allows man-in-the-middle attacks and is NOT recommended.
	 *
	 * Setting this property directly is discouraged; use the
	 * nm_setting_802_1x_set_ca_cert() function instead.
	 **/
	/* ---ifcfg-rh---
	 * property: ca-cert
	 * variable: IEEE_8021X_CA_CERT(+)
	 * description: CA certificate for EAP.
	 * example: IEEE_8021X_CA_CERT=/home/joe/cacert.crt
	 * ---end---
	 */
	obj_properties[PROP_CA_CERT] =
	    g_param_spec_boxed (NM_SETTING_802_1X_CA_CERT, "", "",
	                        G_TYPE_BYTES,
	                        G_PARAM_READWRITE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMSetting8021x:ca-cert-password:
	 *
	 * The password used to access the CA certificate stored in
	 * #NMSetting8021x:ca-cert property. Only makes sense if the certificate
	 * is stored on a PKCS#<!-- -->11 token that requires a login.
	 *
	 * Since: 1.8
	 **/
	/* ---ifcfg-rh---
	 * ---end---
	 */
	obj_properties[PROP_CA_CERT_PASSWORD] =
	    g_param_spec_string (NM_SETTING_802_1X_CA_CERT_PASSWORD, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         NM_SETTING_PARAM_SECRET |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSetting8021x:ca-cert-password-flags:
	 *
	 * Flags indicating how to handle the #NMSetting8021x:ca-cert-password property.
	 *
	 * Since: 1.8
	 **/
	/* ---ifcfg-rh---
	 * ---end---
	 */
	obj_properties[PROP_CA_CERT_PASSWORD_FLAGS] =
	    g_param_spec_flags (NM_SETTING_802_1X_CA_CERT_PASSWORD_FLAGS, "", "",
	                        NM_TYPE_SETTING_SECRET_FLAGS,
	                        NM_SETTING_SECRET_FLAG_NONE,
	                        G_PARAM_READWRITE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMSetting8021x:ca-path:
	 *
	 * UTF-8 encoded path to a directory containing PEM or DER formatted
	 * certificates to be added to the verification chain in addition to the
	 * certificate specified in the #NMSetting8021x:ca-cert property.
	 **/
	/* ---ifcfg-rh---
	 * property: ca-path
	 * variable: (none)
	 * description: The property is not handled by ifcfg-rh plugin.
	 * ---end---
	 */
	obj_properties[PROP_CA_PATH] =
	    g_param_spec_string (NM_SETTING_802_1X_CA_PATH, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSetting8021x:subject-match:
	 *
	 * Substring to be matched against the subject of the certificate presented
	 * by the authentication server. When unset, no verification of the
	 * authentication server certificate's subject is performed.  This property
	 * provides little security, if any, and its use is deprecated in favor of
	 * NMSetting8021x:domain-suffix-match.
	 **/
	/* ---ifcfg-rh---
	 * property: subject-match
	 * variable: IEEE_8021X_SUBJECT_MATCH(+)
	 * description: Substring to match subject of server certificate against.
	 * example: IEEE_8021X_SUBJECT_MATCH="Red Hat"
	 * ---end---
	 */
	obj_properties[PROP_SUBJECT_MATCH] =
	    g_param_spec_string (NM_SETTING_802_1X_SUBJECT_MATCH, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSetting8021x:altsubject-matches:
	 *
	 * List of strings to be matched against the altSubjectName of the
	 * certificate presented by the authentication server. If the list is empty,
	 * no verification of the server certificate's altSubjectName is performed.
	 **/
	/* ---ifcfg-rh---
	 * property: altsubject-matches
	 * variable: IEEE_8021X_ALTSUBJECT_MATCHES(+)
	 * description: List of strings to be matched against the altSubjectName.
	 * example: IEEE_8021X_ALTSUBJECT_MATCHES="s1.domain.cc"
	 * ---end---
	 */
	obj_properties[PROP_ALTSUBJECT_MATCHES] =
	    g_param_spec_boxed (NM_SETTING_802_1X_ALTSUBJECT_MATCHES, "", "",
	                        G_TYPE_STRV,
	                        G_PARAM_READWRITE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMSetting8021x:domain-suffix-match:
	 *
	 * Constraint for server domain name. If set, this FQDN is used as a suffix
	 * match requirement for dNSName element(s) of the certificate presented by
	 * the authentication server.  If a matching dNSName is found, this
	 * constraint is met.  If no dNSName values are present, this constraint is
	 * matched against SubjectName CN using same suffix match comparison.
	 *
	 * Since: 1.2
	 **/
	/* ---ifcfg-rh---
	 * property: domain-suffix-match
	 * description: Suffix to match domain of server certificate against.
	 * variable: IEEE_8021X_DOMAIN_SUFFIX_MATCH(+)
	 * ---end---
	 */
	obj_properties[PROP_DOMAIN_SUFFIX_MATCH] =
	    g_param_spec_string (NM_SETTING_802_1X_DOMAIN_SUFFIX_MATCH, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSetting8021x:client-cert:
	 *
	 * Contains the client certificate if used by the EAP method specified in
	 * the #NMSetting8021x:eap property.
	 *
	 * Certificate data is specified using a "scheme"; two are currently
	 * supported: blob and path. When using the blob scheme (which is backwards
	 * compatible with NM 0.7.x) this property should be set to the
	 * certificate's DER encoded data. When using the path scheme, this property
	 * should be set to the full UTF-8 encoded path of the certificate, prefixed
	 * with the string "file://" and ending with a terminating NUL byte.
	 *
	 * Setting this property directly is discouraged; use the
	 * nm_setting_802_1x_set_client_cert() function instead.
	 **/
	/* ---ifcfg-rh---
	 * property: client-cert
	 * variable: IEEE_8021X_CLIENT_CERT(+)
	 * description: Client certificate for EAP.
	 * example: IEEE_8021X_CLIENT_CERT=/home/joe/mycert.crt
	 * ---end---
	 */
	obj_properties[PROP_CLIENT_CERT] =
	    g_param_spec_boxed (NM_SETTING_802_1X_CLIENT_CERT, "", "",
	                        G_TYPE_BYTES,
	                        G_PARAM_READWRITE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMSetting8021x:client-cert-password:
	 *
	 * The password used to access the client certificate stored in
	 * #NMSetting8021x:client-cert property. Only makes sense if the certificate
	 * is stored on a PKCS#<!-- -->11 token that requires a login.
	 *
	 * Since: 1.8
	 **/
	/* ---ifcfg-rh---
	 * ---end---
	 */
	obj_properties[PROP_CLIENT_CERT_PASSWORD] =
	    g_param_spec_string (NM_SETTING_802_1X_CLIENT_CERT_PASSWORD, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         NM_SETTING_PARAM_SECRET |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSetting8021x:client-cert-password-flags:
	 *
	 * Flags indicating how to handle the #NMSetting8021x:client-cert-password property.
	 *
	 * Since: 1.8
	 **/
	/* ---ifcfg-rh---
	 * ---end---
	 */
	obj_properties[PROP_CLIENT_CERT_PASSWORD_FLAGS] =
	    g_param_spec_flags (NM_SETTING_802_1X_CLIENT_CERT_PASSWORD_FLAGS, "", "",
	                        NM_TYPE_SETTING_SECRET_FLAGS,
	                        NM_SETTING_SECRET_FLAG_NONE,
	                        G_PARAM_READWRITE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMSetting8021x:phase1-peapver:
	 *
	 * Forces which PEAP version is used when PEAP is set as the EAP method in
	 * the #NMSetting8021x:eap property.  When unset, the version reported by
	 * the server will be used.  Sometimes when using older RADIUS servers, it
	 * is necessary to force the client to use a particular PEAP version.  To do
	 * so, this property may be set to "0" or "1" to force that specific PEAP
	 * version.
	 **/
	/* ---ifcfg-rh---
	 * property: phase1-peapver
	 * variable: IEEE_8021X_PEAP_VERSION(+)
	 * values: 0, 1
	 * description: Use to force a specific PEAP version.
	 * ---end---
	 */
	obj_properties[PROP_PHASE1_PEAPVER] =
	    g_param_spec_string (NM_SETTING_802_1X_PHASE1_PEAPVER, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSetting8021x:phase1-peaplabel:
	 *
	 * Forces use of the new PEAP label during key derivation.  Some RADIUS
	 * servers may require forcing the new PEAP label to interoperate with
	 * PEAPv1.  Set to "1" to force use of the new PEAP label.  See the
	 * wpa_supplicant documentation for more details.
	 **/
	/* ---ifcfg-rh---
	 * property: phase1-peaplabel
	 * variable: IEEE_8021X_PEAP_FORCE_NEW_LABEL(+)
	 * values: yes, no
	 * default: no
	 * description: Use to force the new PEAP label during key derivation.
	 * ---end---
	 */
	obj_properties[PROP_PHASE1_PEAPLABEL] =
	    g_param_spec_string (NM_SETTING_802_1X_PHASE1_PEAPLABEL, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSetting8021x:phase1-fast-provisioning:
	 *
	 * Enables or disables in-line provisioning of EAP-FAST credentials when
	 * FAST is specified as the EAP method in the #NMSetting8021x:eap property.
	 * Recognized values are "0" (disabled), "1" (allow unauthenticated
	 * provisioning), "2" (allow authenticated provisioning), and "3" (allow
	 * both authenticated and unauthenticated provisioning).  See the
	 * wpa_supplicant documentation for more details.
	 **/
	/* ---ifcfg-rh---
	 * property: phase1-fast-provisioning
	 * variable: IEEE_8021X_FAST_PROVISIONING(+)
	 * values: space-separated list of these values [allow-auth, allow-unauth]
	 * description: Enable in-line provisioning of EAP-FAST credentials.
	 * example: IEEE_8021X_FAST_PROVISIONING="allow-auth allow-unauth"
	 * ---end---
	 */
	obj_properties[PROP_PHASE1_FAST_PROVISIONING] =
	    g_param_spec_string (NM_SETTING_802_1X_PHASE1_FAST_PROVISIONING, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSetting8021x:phase1-auth-flags:
	 *
	 * Specifies authentication flags to use in "phase 1" outer
	 * authentication using #NMSetting8021xAuthFlags options.
	 * The individual TLS versions can be explicitly disabled. If a certain
	 * TLS disable flag is not set, it is up to the supplicant to allow
	 * or forbid it. The TLS options map to tls_disable_tlsv1_x settings.
	 * See the wpa_supplicant documentation for more details.
	 *
	 * Since: 1.8
	 */
	/* ---ifcfg-rh---
	 * property: phase1-auth-flags
	 * variable: IEEE_8021X_PHASE1_AUTH_FLAGS(+)
	 * values: space-separated list of authentication flags names
	 * description: Authentication flags for the supplicant
	 * example: IEEE_8021X_PHASE1_AUTH_FLAGS="tls-1-0-disable tls-1-1-disable"
	 * ---end---
	 */
	obj_properties[PROP_PHASE1_AUTH_FLAGS] =
	    g_param_spec_uint (NM_SETTING_802_1X_PHASE1_AUTH_FLAGS, "", "",
	                       0, G_MAXUINT32, NM_SETTING_802_1X_AUTH_FLAGS_NONE,
	                       G_PARAM_CONSTRUCT |
	                       G_PARAM_READWRITE |
	                       G_PARAM_STATIC_STRINGS);

	/**
	 * NMSetting8021x:phase2-auth:
	 *
	 * Specifies the allowed "phase 2" inner non-EAP authentication method when
	 * an EAP method that uses an inner TLS tunnel is specified in the
	 * #NMSetting8021x:eap property.  Recognized non-EAP "phase 2" methods are
	 * "pap", "chap", "mschap", "mschapv2", "gtc", "otp", "md5", and "tls".
	 * Each "phase 2" inner method requires specific parameters for successful
	 * authentication; see the wpa_supplicant documentation for more details.
	 **/
	/* ---ifcfg-rh---
	 * property: phase2-auth
	 * variable: IEEE_8021X_INNER_AUTH_METHODS(+)
	 * values: "PAP", "CHAP", "MSCHAP", "MSCHAPV2", "GTC", "OTP", "MD5" and "TLS"
	 * description: Inner non-EAP authentication methods. IEEE_8021X_INNER_AUTH_METHODS
	 *   can contain values both for 'phase2-auth' and 'phase2-autheap' properties.
	 * example: IEEE_8021X_INNER_AUTH_METHODS=PAP
	 * ---end---
	 */
	obj_properties[PROP_PHASE2_AUTH] =
	    g_param_spec_string (NM_SETTING_802_1X_PHASE2_AUTH, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSetting8021x:phase2-autheap:
	 *
	 * Specifies the allowed "phase 2" inner EAP-based authentication method
	 * when an EAP method that uses an inner TLS tunnel is specified in the
	 * #NMSetting8021x:eap property.  Recognized EAP-based "phase 2" methods are
	 * "md5", "mschapv2", "otp", "gtc", and "tls". Each "phase 2" inner method
	 * requires specific parameters for successful authentication; see the
	 * wpa_supplicant documentation for more details.
	 **/
	/* ---ifcfg-rh---
	 * property: phase2-autheap
	 * variable: IEEE_8021X_INNER_AUTH_METHODS(+)
	 * values: "EAP-MD5", "EAP-MSCHAPV2", "EAP-GTC", "EAP-OTP" and "EAP-TLS"
	 * description: Inner EAP-based authentication methods. Note that
	 *   IEEE_8021X_INNER_AUTH_METHODS is also used for 'phase2-auth' values.
	 * example: IEEE_8021X_INNER_AUTH_METHODS="MSCHAPV2 EAP-TLS"
	 * ---end---
	 */
	obj_properties[PROP_PHASE2_AUTHEAP] =
	    g_param_spec_string (NM_SETTING_802_1X_PHASE2_AUTHEAP, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSetting8021x:phase2-ca-cert:
	 *
	 * Contains the "phase 2" CA certificate if used by the EAP method specified
	 * in the #NMSetting8021x:phase2-auth or #NMSetting8021x:phase2-autheap
	 * properties.
	 *
	 * Certificate data is specified using a "scheme"; two are currently
	 * supported: blob and path. When using the blob scheme (which is backwards
	 * compatible with NM 0.7.x) this property should be set to the
	 * certificate's DER encoded data. When using the path scheme, this property
	 * should be set to the full UTF-8 encoded path of the certificate, prefixed
	 * with the string "file://" and ending with a terminating NUL byte. This
	 * property can be unset even if the EAP method supports CA certificates,
	 * but this allows man-in-the-middle attacks and is NOT recommended.
	 *
	 * Setting this property directly is discouraged; use the
	 * nm_setting_802_1x_set_phase2_ca_cert() function instead.
	 **/
	obj_properties[PROP_PHASE2_CA_CERT] =
	    g_param_spec_boxed (NM_SETTING_802_1X_PHASE2_CA_CERT, "", "",
	                        G_TYPE_BYTES,
	                        G_PARAM_READWRITE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMSetting8021x:phase2-ca-cert-password:
	 *
	 * The password used to access the "phase2" CA certificate stored in
	 * #NMSetting8021x:phase2-ca-cert property. Only makes sense if the certificate
	 * is stored on a PKCS#<!-- -->11 token that requires a login.
	 *
	 * Since: 1.8
	 **/
	/* ---ifcfg-rh---
	 * ---end---
	 */
	obj_properties[PROP_PHASE2_CA_CERT_PASSWORD] =
	    g_param_spec_string (NM_SETTING_802_1X_PHASE2_CA_CERT_PASSWORD, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         NM_SETTING_PARAM_SECRET |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSetting8021x:phase2-ca-cert-password-flags:
	 *
	 * Flags indicating how to handle the #NMSetting8021x:phase2-ca-cert-password property.
	 *
	 * Since: 1.8
	 **/
	/* ---ifcfg-rh---
	 * ---end---
	 */
	obj_properties[PROP_PHASE2_CA_CERT_PASSWORD_FLAGS] =
	    g_param_spec_flags (NM_SETTING_802_1X_PHASE2_CA_CERT_PASSWORD_FLAGS, "", "",
	                        NM_TYPE_SETTING_SECRET_FLAGS,
	                        NM_SETTING_SECRET_FLAG_NONE,
	                        G_PARAM_READWRITE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMSetting8021x:phase2-ca-path:
	 *
	 * UTF-8 encoded path to a directory containing PEM or DER formatted
	 * certificates to be added to the verification chain in addition to the
	 * certificate specified in the #NMSetting8021x:phase2-ca-cert property.
	 **/
	obj_properties[PROP_PHASE2_CA_PATH] =
	    g_param_spec_string (NM_SETTING_802_1X_PHASE2_CA_PATH, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSetting8021x:phase2-subject-match:
	 *
	 * Substring to be matched against the subject of the certificate presented
	 * by the authentication server during the inner "phase 2"
	 * authentication. When unset, no verification of the authentication server
	 * certificate's subject is performed.  This property provides little security,
	 * if any, and its use is deprecated in favor of
	 * NMSetting8021x:phase2-domain-suffix-match.
	 **/
	/* ---ifcfg-rh---
	 * property: phase2-subject-match
	 * variable: IEEE_8021X_PHASE2_SUBJECT_MATCH(+)
	 * description: Substring to match subject of server certificate against.
	 * example: IEEE_8021X_PHASE2_SUBJECT_MATCH="Red Hat"
	 * ---end---
	 */
	obj_properties[PROP_PHASE2_SUBJECT_MATCH] =
	    g_param_spec_string (NM_SETTING_802_1X_PHASE2_SUBJECT_MATCH, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSetting8021x:phase2-altsubject-matches:
	 *
	 * List of strings to be matched against the altSubjectName of the
	 * certificate presented by the authentication server during the inner
	 * "phase 2" authentication. If the list is empty, no verification of the
	 * server certificate's altSubjectName is performed.
	 **/
	/* ---ifcfg-rh---
	 * property: phase2-altsubject-matches
	 * variable: IEEE_8021X_PHASE2_ALTSUBJECT_MATCHES(+)
	 * ---end---
	 */
	obj_properties[PROP_PHASE2_ALTSUBJECT_MATCHES] =
	    g_param_spec_boxed (NM_SETTING_802_1X_PHASE2_ALTSUBJECT_MATCHES, "", "",
	                        G_TYPE_STRV,
	                        G_PARAM_READWRITE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMSetting8021x:phase2-domain-suffix-match:
	 *
	 * Constraint for server domain name. If set, this FQDN is used as a suffix
	 * match requirement for dNSName element(s) of the certificate presented by
	 * the authentication server during the inner "phase 2" authentication.  If
	 * a matching dNSName is found, this constraint is met.  If no dNSName
	 * values are present, this constraint is matched against SubjectName CN
	 * using same suffix match comparison.
	 *
	 * Since: 1.2
	 **/
	/* ---ifcfg-rh---
	 * property: phase2-domain-suffix-match
	 * description: Suffix to match domain of server certificate for phase 2 against.
	 * variable: IEEE_8021X_PHASE2_DOMAIN_SUFFIX_MATCH(+)
	 * ---end---
	 */
	obj_properties[PROP_PHASE2_DOMAIN_SUFFIX_MATCH] =
	    g_param_spec_string (NM_SETTING_802_1X_PHASE2_DOMAIN_SUFFIX_MATCH, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSetting8021x:phase2-client-cert:
	 *
	 * Contains the "phase 2" client certificate if used by the EAP method
	 * specified in the #NMSetting8021x:phase2-auth or
	 * #NMSetting8021x:phase2-autheap properties.
	 *
	 * Certificate data is specified using a "scheme"; two are currently
	 * supported: blob and path. When using the blob scheme (which is backwards
	 * compatible with NM 0.7.x) this property should be set to the
	 * certificate's DER encoded data. When using the path scheme, this property
	 * should be set to the full UTF-8 encoded path of the certificate, prefixed
	 * with the string "file://" and ending with a terminating NUL byte. This
	 * property can be unset even if the EAP method supports CA certificates,
	 * but this allows man-in-the-middle attacks and is NOT recommended.
	 *
	 * Setting this property directly is discouraged; use the
	 * nm_setting_802_1x_set_phase2_client_cert() function instead.
	 **/
	/* ---ifcfg-rh---
	 * property: phase2-client-cert
	 * variable: IEEE_8021X_INNER_CLIENT_CERT(+)
	 * description: Client certificate for inner EAP method.
	 * example: IEEE_8021X_INNER_CLIENT_CERT=/home/joe/mycert.crt
	 * ---end---
	 */
	obj_properties[PROP_PHASE2_CLIENT_CERT] =
	    g_param_spec_boxed (NM_SETTING_802_1X_PHASE2_CLIENT_CERT, "", "",
	                        G_TYPE_BYTES,
	                        G_PARAM_READWRITE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMSetting8021x:phase2-client-cert-password:
	 *
	 * The password used to access the "phase2" client certificate stored in
	 * #NMSetting8021x:phase2-client-cert property. Only makes sense if the certificate
	 * is stored on a PKCS#<!-- -->11 token that requires a login.
	 *
	 * Since: 1.8
	 **/
	/* ---ifcfg-rh---
	 * ---end---
	 */
	obj_properties[PROP_PHASE2_CLIENT_CERT_PASSWORD] =
	    g_param_spec_string (NM_SETTING_802_1X_PHASE2_CLIENT_CERT_PASSWORD, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         NM_SETTING_PARAM_SECRET |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSetting8021x:phase2-client-cert-password-flags:
	 *
	 * Flags indicating how to handle the #NMSetting8021x:phase2-client-cert-password property.
	 *
	 * Since: 1.8
	 **/
	/* ---ifcfg-rh---
	 * ---end---
	 */
	obj_properties[PROP_PHASE2_CLIENT_CERT_PASSWORD_FLAGS] =
	    g_param_spec_flags (NM_SETTING_802_1X_PHASE2_CLIENT_CERT_PASSWORD_FLAGS, "", "",
	                        NM_TYPE_SETTING_SECRET_FLAGS,
	                        NM_SETTING_SECRET_FLAG_NONE,
	                        G_PARAM_READWRITE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMSetting8021x:password:
	 *
	 * UTF-8 encoded password used for EAP authentication methods. If both the
	 * #NMSetting8021x:password property and the #NMSetting8021x:password-raw
	 * property are specified, #NMSetting8021x:password is preferred.
	 **/
	/* ---ifcfg-rh---
	 * property: password
	 * variable: IEEE_8021X_PASSWORD(+)
	 * description: UTF-8 encoded password used for EAP. It can also go to "key-"
	 *   lookaside file, or it can be owned by a secret agent.
	 * ---end---
	 */
	obj_properties[PROP_PASSWORD] =
	    g_param_spec_string (NM_SETTING_802_1X_PASSWORD, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         NM_SETTING_PARAM_SECRET |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSetting8021x:password-flags:
	 *
	 * Flags indicating how to handle the #NMSetting8021x:password property.
	 **/
	/* ---ifcfg-rh---
	 * property: password-flags
	 * variable: IEEE_8021X_PASSWORD_FLAGS(+)
	 * format: NMSettingSecretFlags
	 * description: Password flags for IEEE_8021X_PASSWORD password.
	 * ---end---
	 */
	obj_properties[PROP_PASSWORD_FLAGS] =
	    g_param_spec_flags (NM_SETTING_802_1X_PASSWORD_FLAGS, "", "",
	                        NM_TYPE_SETTING_SECRET_FLAGS,
	                        NM_SETTING_SECRET_FLAG_NONE,
	                        G_PARAM_READWRITE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMSetting8021x:password-raw:
	 *
	 * Password used for EAP authentication methods, given as a byte array to
	 * allow passwords in other encodings than UTF-8 to be used. If both the
	 * #NMSetting8021x:password property and the #NMSetting8021x:password-raw
	 * property are specified, #NMSetting8021x:password is preferred.
	 **/
	/* ---ifcfg-rh---
	 * property: password-raw
	 * variable: IEEE_8021X_PASSWORD_RAW(+)
	 * description: password used for EAP, encoded as a hexadecimal string. It
	 *   can also go to "key-" lookaside file.
	 * example: IEEE_8021X_PASSWORD_RAW=041c8320083aa4bf
	 * ---end---
	 */
	obj_properties[PROP_PASSWORD_RAW] =
	    g_param_spec_boxed (NM_SETTING_802_1X_PASSWORD_RAW, "", "",
	                        G_TYPE_BYTES,
	                        G_PARAM_READWRITE |
	                        NM_SETTING_PARAM_SECRET |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMSetting8021x:password-raw-flags:
	 *
	 * Flags indicating how to handle the #NMSetting8021x:password-raw property.
	 **/
	/* ---ifcfg-rh---
	 * property: password-raw-flags
	 * variable: (none)
	 * description: The property is not handled by ifcfg-rh plugin.
	 * ---end---
	 */
	obj_properties[PROP_PASSWORD_RAW_FLAGS] =
	    g_param_spec_flags (NM_SETTING_802_1X_PASSWORD_RAW_FLAGS, "", "",
	                        NM_TYPE_SETTING_SECRET_FLAGS,
	                        NM_SETTING_SECRET_FLAG_NONE,
	                        G_PARAM_READWRITE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMSetting8021x:private-key:
	 *
	 * Contains the private key when the #NMSetting8021x:eap property is set to
	 * "tls".
	 *
	 * Key data is specified using a "scheme"; two are currently supported: blob
	 * and path. When using the blob scheme and private keys, this property
	 * should be set to the key's encrypted PEM encoded data. When using private
	 * keys with the path scheme, this property should be set to the full UTF-8
	 * encoded path of the key, prefixed with the string "file://" and ending
	 * with a terminating NUL byte. When using PKCS#<!-- -->12 format private
	 * keys and the blob scheme, this property should be set to the
	 * PKCS#<!-- -->12 data and the #NMSetting8021x:private-key-password
	 * property must be set to password used to decrypt the PKCS#<!-- -->12
	 * certificate and key. When using PKCS#<!-- -->12 files and the path
	 * scheme, this property should be set to the full UTF-8 encoded path of the
	 * key, prefixed with the string "file://" and ending with a terminating
	 * NUL byte, and as with the blob scheme the "private-key-password" property
	 * must be set to the password used to decode the PKCS#<!-- -->12 private
	 * key and certificate.
	 *
	 * Setting this property directly is discouraged; use the
	 * nm_setting_802_1x_set_private_key() function instead.
	 *
	 * WARNING: #NMSetting8021x:private-key is not a "secret" property, and thus
	 * unencrypted private key data using the BLOB scheme may be readable by
	 * unprivileged users.  Private keys should always be encrypted with a
	 * private key password to prevent unauthorized access to unencrypted
	 * private key data.
	 **/
	/* ---ifcfg-rh---
	 * property: private-key
	 * variable: IEEE_8021X_PRIVATE_KEY(+)
	 * description: Private key for EAP-TLS.
	 * example: IEEE_8021X_PRIVATE_KEY=/home/joe/mykey.p12
	 * ---end---
	 */
	obj_properties[PROP_PRIVATE_KEY] =
	    g_param_spec_boxed (NM_SETTING_802_1X_PRIVATE_KEY, "", "",
	                        G_TYPE_BYTES,
	                        G_PARAM_READWRITE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMSetting8021x:private-key-password:
	 *
	 * The password used to decrypt the private key specified in the
	 * #NMSetting8021x:private-key property when the private key either uses the
	 * path scheme, or if the private key is a PKCS#<!-- -->12 format key.  Setting this
	 * property directly is not generally necessary except when returning
	 * secrets to NetworkManager; it is generally set automatically when setting
	 * the private key by the nm_setting_802_1x_set_private_key() function.
	 **/
	/* ---ifcfg-rh---
	 * property: private-key-password
	 * variable: IEEE_8021X_PRIVATE_KEY_PASSWORD(+)
	 * description: Password for IEEE_8021X_PRIVATE_KEY. It can also go to "key-"
	 *   lookaside file, or it can be owned by a secret agent.
	 * ---end---
	 */
	obj_properties[PROP_PRIVATE_KEY_PASSWORD] =
	    g_param_spec_string (NM_SETTING_802_1X_PRIVATE_KEY_PASSWORD, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         NM_SETTING_PARAM_SECRET |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSetting8021x:private-key-password-flags:
	 *
	 * Flags indicating how to handle the #NMSetting8021x:private-key-password
	 * property.
	 **/
	/* ---ifcfg-rh---
	 * property: private-key-password-flags
	 * variable: IEEE_8021X_PRIVATE_KEY_PASSWORD_FLAGS(+)
	 * format: NMSettingSecretFlags
	 * description: Password flags for IEEE_8021X_PRIVATE_KEY_PASSWORD password.
	 * ---end---
	 */
	obj_properties[PROP_PRIVATE_KEY_PASSWORD_FLAGS] =
	    g_param_spec_flags (NM_SETTING_802_1X_PRIVATE_KEY_PASSWORD_FLAGS, "", "",
	                        NM_TYPE_SETTING_SECRET_FLAGS,
	                        NM_SETTING_SECRET_FLAG_NONE,
	                        G_PARAM_READWRITE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMSetting8021x:phase2-private-key:
	 *
	 * Contains the "phase 2" inner private key when the
	 * #NMSetting8021x:phase2-auth or #NMSetting8021x:phase2-autheap property is
	 * set to "tls".
	 *
	 * Key data is specified using a "scheme"; two are currently supported: blob
	 * and path. When using the blob scheme and private keys, this property
	 * should be set to the key's encrypted PEM encoded data. When using private
	 * keys with the path scheme, this property should be set to the full UTF-8
	 * encoded path of the key, prefixed with the string "file://" and ending
	 * with a terminating NUL byte. When using PKCS#<!-- -->12 format private
	 * keys and the blob scheme, this property should be set to the
	 * PKCS#<!-- -->12 data and the #NMSetting8021x:phase2-private-key-password
	 * property must be set to password used to decrypt the PKCS#<!-- -->12
	 * certificate and key. When using PKCS#<!-- -->12 files and the path
	 * scheme, this property should be set to the full UTF-8 encoded path of the
	 * key, prefixed with the string "file://" and ending with a terminating
	 * NUL byte, and as with the blob scheme the
	 * #NMSetting8021x:phase2-private-key-password property must be set to the
	 * password used to decode the PKCS#<!-- -->12 private key and certificate.
	 *
	 * Setting this property directly is discouraged; use the
	 * nm_setting_802_1x_set_phase2_private_key() function instead.
	 **/
	/* ---ifcfg-rh---
	 * property: phase2-private-key
	 * variable: IEEE_8021X_INNER_PRIVATE_KEY(+)
	 * description: Private key for inner authentication method for EAP-TLS.
	 * ---end---
	 */
	obj_properties[PROP_PHASE2_PRIVATE_KEY] =
	    g_param_spec_boxed (NM_SETTING_802_1X_PHASE2_PRIVATE_KEY, "", "",
	                        G_TYPE_BYTES,
	                        G_PARAM_READWRITE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMSetting8021x:phase2-private-key-password:
	 *
	 * The password used to decrypt the "phase 2" private key specified in the
	 * #NMSetting8021x:phase2-private-key property when the private key either
	 * uses the path scheme, or is a PKCS#<!-- -->12 format key.  Setting this
	 * property directly is not generally necessary except when returning
	 * secrets to NetworkManager; it is generally set automatically when setting
	 * the private key by the nm_setting_802_1x_set_phase2_private_key()
	 * function.
	 **/
	/* ---ifcfg-rh---
	 * property: phase2-private-key-password
	 * variable: IEEE_8021X_INNER_PRIVATE_KEY_PASSWORD(+)
	 * description: Password for IEEE_8021X_INNER_PRIVATE_KEY. It can also go to "key-"
	 *   lookaside file, or it can be owned by a secret agent.
	 * ---end---
	 */
	obj_properties[PROP_PHASE2_PRIVATE_KEY_PASSWORD] =
	    g_param_spec_string (NM_SETTING_802_1X_PHASE2_PRIVATE_KEY_PASSWORD, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         NM_SETTING_PARAM_SECRET |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSetting8021x:phase2-private-key-password-flags:
	 *
	 * Flags indicating how to handle the
	 * #NMSetting8021x:phase2-private-key-password property.
	 **/
	/* ---ifcfg-rh---
	 * property: phase2-private-key-password-flags
	 * variable: IEEE_8021X_INNER_PRIVATE_KEY_PASSWORD_FLAGS(+)
	 * format: NMSettingSecretFlags
	 * description: Password flags for IEEE_8021X_INNER_PRIVATE_KEY_PASSWORD password.
	 * ---end---
	 */
	obj_properties[PROP_PHASE2_PRIVATE_KEY_PASSWORD_FLAGS] =
	    g_param_spec_flags (NM_SETTING_802_1X_PHASE2_PRIVATE_KEY_PASSWORD_FLAGS, "", "",
	                        NM_TYPE_SETTING_SECRET_FLAGS,
	                        NM_SETTING_SECRET_FLAG_NONE,
	                        G_PARAM_READWRITE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMSetting8021x:pin:
	 *
	 * PIN used for EAP authentication methods.
	 **/
	/* ---ifcfg-rh---
	 * property: pin
	 * variable: (none)
	 * description: The property is not handled by ifcfg-rh plugin.
	 * ---end---
	 */
	obj_properties[PROP_PIN] =
	    g_param_spec_string (NM_SETTING_802_1X_PIN, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         NM_SETTING_PARAM_SECRET |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSetting8021x:pin-flags:
	 *
	 * Flags indicating how to handle the #NMSetting8021x:pin property.
	 **/
	/* ---ifcfg-rh---
	 * property: pin-flags
	 * variable: (none)
	 * description: The property is not handled by ifcfg-rh plugin.
	 * ---end---
	 */
	obj_properties[PROP_PIN_FLAGS] =
	    g_param_spec_flags (NM_SETTING_802_1X_PIN_FLAGS, "", "",
	                        NM_TYPE_SETTING_SECRET_FLAGS,
	                        NM_SETTING_SECRET_FLAG_NONE,
	                        G_PARAM_READWRITE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMSetting8021x:system-ca-certs:
	 *
	 * When %TRUE, overrides the #NMSetting8021x:ca-path and
	 * #NMSetting8021x:phase2-ca-path properties using the system CA directory
	 * specified at configure time with the --system-ca-path switch.  The
	 * certificates in this directory are added to the verification chain in
	 * addition to any certificates specified by the #NMSetting8021x:ca-cert and
	 * #NMSetting8021x:phase2-ca-cert properties. If the path provided with
	 * --system-ca-path is rather a file name (bundle of trusted CA certificates),
	 * it overrides #NMSetting8021x:ca-cert and #NMSetting8021x:phase2-ca-cert
	 * properties instead (sets ca_cert/ca_cert2 options for wpa_supplicant).
	 **/
	/* ---ifcfg-rh---
	 * property: system-ca-certs
	 * variable: (none)
	 * description: The property is not handled by ifcfg-rh plugin.
	 * ---end---
	 */
	obj_properties[PROP_SYSTEM_CA_CERTS] =
	    g_param_spec_boolean (NM_SETTING_802_1X_SYSTEM_CA_CERTS, "", "",
	                          FALSE,
	                          G_PARAM_READWRITE |
	                          G_PARAM_CONSTRUCT |
	                          G_PARAM_STATIC_STRINGS);

	/**
	 * NMSetting8021x:auth-timeout:
	 *
	 * A timeout for the authentication. Zero means the global default; if the
	 * global default is not set, the authentication timeout is 25 seconds.
	 *
	 * Since: 1.8
	 **/
	/* ---ifcfg-rh---
	 * property: auth-timeout
	 * variable: IEEE_8021X_AUTH_TIMEOUT(+)
	 * default: 0
	 * description: Timeout in seconds for the 802.1X authentication. Zero means the global default or 25.
	 * ---end---
	 */
	obj_properties[PROP_AUTH_TIMEOUT] =
	    g_param_spec_int (NM_SETTING_802_1X_AUTH_TIMEOUT, "", "",
	                      0, G_MAXINT32, 0,
	                      G_PARAM_READWRITE |
	                      NM_SETTING_PARAM_FUZZY_IGNORE |
	                      G_PARAM_STATIC_STRINGS);

	/**
	 * NMSetting8021x:optional:
	 *
	 * Whether the 802.1X authentication is optional. If %TRUE, the activation
	 * will continue even after a timeout or an authentication failure. Setting
	 * the property to %TRUE is currently allowed only for Ethernet connections.
	 * If set to %FALSE, the activation can continue only after a successful
	 * authentication.
	 *
	 * Since: 1.22
	 **/
	/* ---ifcfg-rh---
	 * property: optional
	 * variable: IEEE_8021X_OPTIONAL(+)
	 * default=no
	 * description: whether the 802.1X authentication is optional
	 * ---end---
	 */
	obj_properties[PROP_OPTIONAL] =
	    g_param_spec_boolean (NM_SETTING_802_1X_OPTIONAL, "", "",
	                          FALSE,
	                          G_PARAM_READWRITE |
	                          G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);

	_nm_setting_class_commit (setting_class, NM_META_SETTING_TYPE_802_1X);
}
