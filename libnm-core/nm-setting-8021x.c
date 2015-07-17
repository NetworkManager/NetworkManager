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

#include "config.h"

#include <string.h>
#include <glib/gi18n-lib.h>

#include "nm-default.h"
#include "nm-setting-8021x.h"
#include "nm-utils.h"
#include "crypto.h"
#include "nm-utils-private.h"
#include "nm-setting-private.h"
#include "nm-core-enum-types.h"
#include "nm-macros-internal.h"

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

G_DEFINE_TYPE_WITH_CODE (NMSetting8021x, nm_setting_802_1x, NM_TYPE_SETTING,
                         _nm_register_setting (802_1X, 2))
NM_SETTING_REGISTER_TYPE (NM_TYPE_SETTING_802_1X)

#define NM_SETTING_802_1X_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_802_1X, NMSetting8021xPrivate))

G_STATIC_ASSERT ( (NM_SETTING_802_1X_CK_FORMAT_UNKNOWN == (NMSetting8021xCKFormat) NM_CRYPTO_FILE_FORMAT_UNKNOWN) );
G_STATIC_ASSERT ( (NM_SETTING_802_1X_CK_FORMAT_X509    == (NMSetting8021xCKFormat) NM_CRYPTO_FILE_FORMAT_X509) );
G_STATIC_ASSERT ( (NM_SETTING_802_1X_CK_FORMAT_RAW_KEY == (NMSetting8021xCKFormat) NM_CRYPTO_FILE_FORMAT_RAW_KEY) );
G_STATIC_ASSERT ( (NM_SETTING_802_1X_CK_FORMAT_PKCS12  == (NMSetting8021xCKFormat) NM_CRYPTO_FILE_FORMAT_PKCS12) );

typedef struct {
	GSList *eap; /* GSList of strings */
	char *identity;
	char *anonymous_identity;
	char *pac_file;
	GBytes *ca_cert;
	char *ca_path;
	char *subject_match;
	GSList *altsubject_matches;
	GBytes *client_cert;
	char *phase1_peapver;
	char *phase1_peaplabel;
	char *phase1_fast_provisioning;
	char *phase2_auth;
	char *phase2_autheap;
	GBytes *phase2_ca_cert;
	char *phase2_ca_path;
	char *phase2_subject_match;
	GSList *phase2_altsubject_matches;
	GBytes *phase2_client_cert;
	char *password;
	NMSettingSecretFlags password_flags;
	GBytes *password_raw;
	NMSettingSecretFlags password_raw_flags;
	char *pin;
	NMSettingSecretFlags pin_flags;
	GBytes *private_key;
	char *private_key_password;
	NMSettingSecretFlags private_key_password_flags;
	GBytes *phase2_private_key;
	char *phase2_private_key_password;
	NMSettingSecretFlags phase2_private_key_password_flags;
	gboolean system_ca_certs;
} NMSetting8021xPrivate;

enum {
	PROP_0,
	PROP_EAP,
	PROP_IDENTITY,
	PROP_ANONYMOUS_IDENTITY,
	PROP_PAC_FILE,
	PROP_CA_CERT,
	PROP_CA_PATH,
	PROP_SUBJECT_MATCH,
	PROP_ALTSUBJECT_MATCHES,
	PROP_CLIENT_CERT,
	PROP_PHASE1_PEAPVER,
	PROP_PHASE1_PEAPLABEL,
	PROP_PHASE1_FAST_PROVISIONING,
	PROP_PHASE2_AUTH,
	PROP_PHASE2_AUTHEAP,
	PROP_PHASE2_CA_CERT,
	PROP_PHASE2_CA_PATH,
	PROP_PHASE2_SUBJECT_MATCH,
	PROP_PHASE2_ALTSUBJECT_MATCHES,
	PROP_PHASE2_CLIENT_CERT,
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

	LAST_PROP
};

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
	g_object_notify (G_OBJECT (setting), NM_SETTING_802_1X_EAP);
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
	g_object_notify (G_OBJECT (setting), NM_SETTING_802_1X_EAP);
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
			g_object_notify (G_OBJECT (setting), NM_SETTING_802_1X_EAP);
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
	g_object_notify (G_OBJECT (setting), NM_SETTING_802_1X_EAP);
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

static NMSetting8021xCKScheme
get_cert_scheme (GBytes *bytes, GError **error)
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

/**
 * nm_setting_802_1x_check_cert_scheme:
 * @pdata: (allow-none): the data pointer
 * @length: the length of the data
 * @error: (allow-none): (out): validation reason
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

	g_return_val_if_fail (!length || data, NM_SETTING_802_1X_CK_SCHEME_UNKNOWN);

	if (!length || !data) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("binary data missing"));
		return NM_SETTING_802_1X_CK_SCHEME_UNKNOWN;
	}

	/* interpret the blob as PATH if it starts with "file://". */
	if (   length >= STRLEN (NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PATH)
	    && !memcmp (data, NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PATH, STRLEN (NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PATH))) {
		/* But it must also be NUL terminated, contain at least
		 * one non-NUL character, and contain only one trailing NUL
		 * chracter.
		 * And ensure it's UTF-8 valid too so we can pass it through
		 * D-Bus and stuff like that. */

		if (data[length - 1] != '\0') {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     _("file:// URI not NUL terminated"));
			return NM_SETTING_802_1X_CK_SCHEME_UNKNOWN;
		}
		length--;

		if (length <= STRLEN (NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PATH)) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     _("file:// URI is empty"));
			return NM_SETTING_802_1X_CK_SCHEME_UNKNOWN;
		}

		if (!g_utf8_validate (data + STRLEN (NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PATH), length - STRLEN (NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PATH), NULL)) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     _("file:// URI is not valid UTF-8"));
			return NM_SETTING_802_1X_CK_SCHEME_UNKNOWN;
		}

		return NM_SETTING_802_1X_CK_SCHEME_PATH;
	}

	return NM_SETTING_802_1X_CK_SCHEME_BLOB;
}

static GByteArray *
load_and_verify_certificate (const char *cert_path,
                             NMSetting8021xCKScheme scheme,
                             NMCryptoFileFormat *out_file_format,
                             GError **error)
{
	NMCryptoFileFormat format = NM_CRYPTO_FILE_FORMAT_UNKNOWN;
	GByteArray *array;

	array = crypto_load_and_verify_certificate (cert_path, &format, error);

	if (!array || !array->len || format == NM_CRYPTO_FILE_FORMAT_UNKNOWN) {
		/* the array is empty or the format is already unknown. */
		format = NM_CRYPTO_FILE_FORMAT_UNKNOWN;
	} else if (scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB) {
		/* If we load the file as blob, we must ensure that the binary data does not
		 * start with file://. NMSetting8021x cannot represent blobs that start with
		 * file://.
		 * If that's the case, coerce the format to UNKNOWN. The callers will take care
		 * of that and not set the blob. */
		if (nm_setting_802_1x_check_cert_scheme (array->data, array->len, NULL) != NM_SETTING_802_1X_CK_SCHEME_BLOB)
			format = NM_CRYPTO_FILE_FORMAT_UNKNOWN;
	}

	if (out_file_format)
		*out_file_format = format;
	return array;
}

/**
 * nm_setting_802_1x_get_ca_cert_scheme:
 * @setting: the #NMSetting8021x
 *
 * Returns the scheme used to store the CA certificate.  If the returned scheme
 * is %NM_SETTING_802_1X_CK_SCHEME_BLOB, use nm_setting_802_1x_get_ca_cert_blob();
 * if %NM_SETTING_802_1X_CK_SCHEME_PATH, use nm_setting_802_1x_get_ca_cert_path().
 *
 * Returns: scheme used to store the CA certificate (blob or path)
 **/
NMSetting8021xCKScheme
nm_setting_802_1x_get_ca_cert_scheme (NMSetting8021x *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NM_SETTING_802_1X_CK_SCHEME_UNKNOWN);

	return get_cert_scheme (NM_SETTING_802_1X_GET_PRIVATE (setting)->ca_cert, NULL);
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
	NMSetting8021xCKScheme scheme;

	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NULL);

	scheme = nm_setting_802_1x_get_ca_cert_scheme (setting);
	g_return_val_if_fail (scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB, NULL);

	return NM_SETTING_802_1X_GET_PRIVATE (setting)->ca_cert;
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
	NMSetting8021xCKScheme scheme;
	gconstpointer data;

	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NULL);

	scheme = nm_setting_802_1x_get_ca_cert_scheme (setting);
	g_return_val_if_fail (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH, NULL);

	data = g_bytes_get_data (NM_SETTING_802_1X_GET_PRIVATE (setting)->ca_cert, NULL);
	return (const char *)data + strlen (NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PATH);
}

static GBytes *
path_to_scheme_value (const char *path)
{
	GByteArray *array;
	gsize len;

	g_return_val_if_fail (path != NULL && path[0], NULL);

	len = strlen (path);

	/* Add the path scheme tag to the front, then the filename */
	array = g_byte_array_sized_new (len + strlen (NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PATH) + 1);
	g_byte_array_append (array, (const guint8 *) NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PATH, strlen (NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PATH));
	g_byte_array_append (array, (const guint8 *) path, len);
	g_byte_array_append (array, (const guint8 *) "\0", 1);

	return g_byte_array_free_to_bytes (array);
}

/**
 * nm_setting_802_1x_set_ca_cert:
 * @setting: the #NMSetting8021x
 * @cert_path: when @scheme is set to either %NM_SETTING_802_1X_CK_SCHEME_PATH
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
                               const char *cert_path,
                               NMSetting8021xCKScheme scheme,
                               NMSetting8021xCKFormat *out_format,
                               GError **error)
{
	NMSetting8021xPrivate *priv;
	NMCryptoFileFormat format = NM_CRYPTO_FILE_FORMAT_UNKNOWN;
	GByteArray *data;

	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), FALSE);

	if (cert_path) {
		g_return_val_if_fail (g_utf8_validate (cert_path, -1, NULL), FALSE);
		g_return_val_if_fail (   scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB
		                      || scheme == NM_SETTING_802_1X_CK_SCHEME_PATH,
		                      FALSE);
	}

	if (out_format)
		g_return_val_if_fail (*out_format == NM_SETTING_802_1X_CK_FORMAT_UNKNOWN, FALSE);

	priv = NM_SETTING_802_1X_GET_PRIVATE (setting);

	g_clear_pointer (&priv->ca_cert, g_bytes_unref);

	if (!cert_path) {
		g_object_notify (G_OBJECT (setting), NM_SETTING_802_1X_CA_CERT);
		return TRUE;
	}

	data = load_and_verify_certificate (cert_path, scheme, &format, error);
	if (data) {
		/* wpa_supplicant can only use raw x509 CA certs */
		if (format == NM_CRYPTO_FILE_FORMAT_X509) {
			if (out_format)
				*out_format = NM_SETTING_802_1X_CK_FORMAT_X509;

			if (scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB) {
				priv->ca_cert = g_byte_array_free_to_bytes (data);
				data = NULL;
			} else if (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH)
				priv->ca_cert = path_to_scheme_value (cert_path);
			else
				g_assert_not_reached ();
		} else {
			g_set_error_literal (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("CA certificate must be in X.509 format"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_CA_CERT);
		}
		if (data)
			g_byte_array_unref (data);
	}

	g_object_notify (G_OBJECT (setting), NM_SETTING_802_1X_CA_CERT);
	return priv->ca_cert != NULL;
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
	g_object_notify (G_OBJECT (setting), NM_SETTING_802_1X_ALTSUBJECT_MATCHES);
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
	g_object_notify (G_OBJECT (setting), NM_SETTING_802_1X_ALTSUBJECT_MATCHES);
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
			g_object_notify (G_OBJECT (setting), NM_SETTING_802_1X_ALTSUBJECT_MATCHES);
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
	g_object_notify (G_OBJECT (setting), NM_SETTING_802_1X_ALTSUBJECT_MATCHES);
}

/**
 * nm_setting_802_1x_get_client_cert_scheme:
 * @setting: the #NMSetting8021x
 *
 * Returns the scheme used to store the client certificate.  If the returned scheme
 * is %NM_SETTING_802_1X_CK_SCHEME_BLOB, use nm_setting_802_1x_get_client_cert_blob();
 * if %NM_SETTING_802_1X_CK_SCHEME_PATH, use nm_setting_802_1x_get_client_cert_path().
 *
 * Returns: scheme used to store the client certificate (blob or path)
 **/
NMSetting8021xCKScheme
nm_setting_802_1x_get_client_cert_scheme (NMSetting8021x *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NM_SETTING_802_1X_CK_SCHEME_UNKNOWN);

	return get_cert_scheme (NM_SETTING_802_1X_GET_PRIVATE (setting)->client_cert, NULL);
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
	NMSetting8021xCKScheme scheme;

	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NULL);

	scheme = nm_setting_802_1x_get_client_cert_scheme (setting);
	g_return_val_if_fail (scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB, NULL);

	return NM_SETTING_802_1X_GET_PRIVATE (setting)->client_cert;
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
	NMSetting8021xCKScheme scheme;
	gconstpointer data;

	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NULL);

	scheme = nm_setting_802_1x_get_client_cert_scheme (setting);
	g_return_val_if_fail (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH, NULL);

	data = g_bytes_get_data (NM_SETTING_802_1X_GET_PRIVATE (setting)->client_cert, NULL);
	return (const char *)data + strlen (NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PATH);
}

/**
 * nm_setting_802_1x_set_client_cert:
 * @setting: the #NMSetting8021x
 * @cert_path: when @scheme is set to either %NM_SETTING_802_1X_CK_SCHEME_PATH
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
                                   const char *cert_path,
                                   NMSetting8021xCKScheme scheme,
                                   NMSetting8021xCKFormat *out_format,
                                   GError **error)
{
	NMSetting8021xPrivate *priv;
	NMCryptoFileFormat format = NM_CRYPTO_FILE_FORMAT_UNKNOWN;
	GByteArray *data;

	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), FALSE);

	if (cert_path) {
		g_return_val_if_fail (g_utf8_validate (cert_path, -1, NULL), FALSE);
		g_return_val_if_fail (   scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB
		                      || scheme == NM_SETTING_802_1X_CK_SCHEME_PATH,
		                      FALSE);
	}

	if (out_format)
		g_return_val_if_fail (*out_format == NM_SETTING_802_1X_CK_FORMAT_UNKNOWN, FALSE);

	priv = NM_SETTING_802_1X_GET_PRIVATE (setting);

	g_clear_pointer (&priv->client_cert, g_bytes_unref);

	if (!cert_path) {
		g_object_notify (G_OBJECT (setting), NM_SETTING_802_1X_CLIENT_CERT);
		return TRUE;
	}

	data = load_and_verify_certificate (cert_path, scheme, &format, error);
	if (data) {
		gboolean valid = FALSE;

		switch (format) {
		case NM_CRYPTO_FILE_FORMAT_X509:
			if (out_format)
				*out_format = NM_SETTING_802_1X_CK_FORMAT_X509;
			valid = TRUE;
			break;
		case NM_CRYPTO_FILE_FORMAT_PKCS12:
			if (out_format)
				*out_format = NM_SETTING_802_1X_CK_FORMAT_PKCS12;
			valid = TRUE;
			break;
		default:
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     _("invalid certificate format"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_CLIENT_CERT);
			break;
		}

		if (valid) {
			if (scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB) {
				priv->client_cert = g_byte_array_free_to_bytes (data);
				data = NULL;
			} else if (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH)
				priv->client_cert = path_to_scheme_value (cert_path);
			else
				g_assert_not_reached ();
		}
		if (data)
			g_byte_array_unref (data);
	}

	g_object_notify (G_OBJECT (setting), NM_SETTING_802_1X_CLIENT_CERT);
	return priv->client_cert != NULL;
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
 * use nm_setting_802_1x_get_ca_cert_path().
 *
 * Returns: scheme used to store the "phase 2" CA certificate (blob or path)
 **/
NMSetting8021xCKScheme
nm_setting_802_1x_get_phase2_ca_cert_scheme (NMSetting8021x *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NM_SETTING_802_1X_CK_SCHEME_UNKNOWN);

	return get_cert_scheme (NM_SETTING_802_1X_GET_PRIVATE (setting)->phase2_ca_cert, NULL);
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
	NMSetting8021xCKScheme scheme;

	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NULL);

	scheme = nm_setting_802_1x_get_phase2_ca_cert_scheme (setting);
	g_return_val_if_fail (scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB, NULL);

	return NM_SETTING_802_1X_GET_PRIVATE (setting)->phase2_ca_cert;
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
	NMSetting8021xCKScheme scheme;
	gconstpointer data;

	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NULL);

	scheme = nm_setting_802_1x_get_phase2_ca_cert_scheme (setting);
	g_return_val_if_fail (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH, NULL);

	data = g_bytes_get_data (NM_SETTING_802_1X_GET_PRIVATE (setting)->phase2_ca_cert, NULL);
	return (const char *)data + strlen (NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PATH);
}

/**
 * nm_setting_802_1x_set_phase2_ca_cert:
 * @setting: the #NMSetting8021x
 * @cert_path: when @scheme is set to either %NM_SETTING_802_1X_CK_SCHEME_PATH
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
                                      const char *cert_path,
                                      NMSetting8021xCKScheme scheme,
                                      NMSetting8021xCKFormat *out_format,
                                      GError **error)
{
	NMSetting8021xPrivate *priv;
	NMCryptoFileFormat format = NM_CRYPTO_FILE_FORMAT_UNKNOWN;
	GByteArray *data;

	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), FALSE);

	if (cert_path) {
		g_return_val_if_fail (g_utf8_validate (cert_path, -1, NULL), FALSE);
		g_return_val_if_fail (   scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB
		                      || scheme == NM_SETTING_802_1X_CK_SCHEME_PATH,
		                      FALSE);
	}

	if (out_format)
		g_return_val_if_fail (*out_format == NM_SETTING_802_1X_CK_FORMAT_UNKNOWN, FALSE);

	priv = NM_SETTING_802_1X_GET_PRIVATE (setting);

	g_clear_pointer (&priv->phase2_ca_cert, g_bytes_unref);

	if (!cert_path) {
		g_object_notify (G_OBJECT (setting), NM_SETTING_802_1X_PHASE2_CA_CERT);
		return TRUE;
	}

	data = load_and_verify_certificate (cert_path, scheme, &format, error);
	if (data) {
		/* wpa_supplicant can only use raw x509 CA certs */
		if (format == NM_CRYPTO_FILE_FORMAT_X509) {
			if (out_format)
				*out_format = NM_SETTING_802_1X_CK_FORMAT_X509;

			if (scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB) {
				priv->phase2_ca_cert = g_byte_array_free_to_bytes (data);
				data = NULL;
			} else if (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH)
				priv->phase2_ca_cert = path_to_scheme_value (cert_path);
			else
				g_assert_not_reached ();
		} else {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     _("invalid certificate format"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_PHASE2_CA_CERT);
		}
		if (data)
			g_byte_array_unref (data);
	}

	g_object_notify (G_OBJECT (setting), NM_SETTING_802_1X_PHASE2_CA_CERT);
	return priv->phase2_ca_cert != NULL;
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
	g_object_notify (G_OBJECT (setting), NM_SETTING_802_1X_PHASE2_ALTSUBJECT_MATCHES);
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
	g_object_notify (G_OBJECT (setting), NM_SETTING_802_1X_PHASE2_ALTSUBJECT_MATCHES);
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
			g_object_notify (G_OBJECT (setting), NM_SETTING_802_1X_PHASE2_ALTSUBJECT_MATCHES);
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
	g_object_notify (G_OBJECT (setting), NM_SETTING_802_1X_PHASE2_ALTSUBJECT_MATCHES);
}

/**
 * nm_setting_802_1x_get_phase2_client_cert_scheme:
 * @setting: the #NMSetting8021x
 *
 * Returns the scheme used to store the "phase 2" client certificate.  If the
 * returned scheme is %NM_SETTING_802_1X_CK_SCHEME_BLOB, use
 * nm_setting_802_1x_get_client_cert_blob(); if
 * %NM_SETTING_802_1X_CK_SCHEME_PATH, use
 * nm_setting_802_1x_get_client_cert_path().
 *
 * Returns: scheme used to store the "phase 2" client certificate (blob or path)
 **/
NMSetting8021xCKScheme
nm_setting_802_1x_get_phase2_client_cert_scheme (NMSetting8021x *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NM_SETTING_802_1X_CK_SCHEME_UNKNOWN);

	return get_cert_scheme (NM_SETTING_802_1X_GET_PRIVATE (setting)->phase2_client_cert, NULL);
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
	NMSetting8021xCKScheme scheme;

	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NULL);

	scheme = nm_setting_802_1x_get_phase2_client_cert_scheme (setting);
	g_return_val_if_fail (scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB, NULL);

	return NM_SETTING_802_1X_GET_PRIVATE (setting)->phase2_client_cert;
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
	NMSetting8021xCKScheme scheme;
	gconstpointer data;

	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NULL);

	scheme = nm_setting_802_1x_get_phase2_client_cert_scheme (setting);
	g_return_val_if_fail (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH, NULL);

	data = g_bytes_get_data (NM_SETTING_802_1X_GET_PRIVATE (setting)->phase2_client_cert, NULL);
	return (const char *)data + strlen (NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PATH);
}

/**
 * nm_setting_802_1x_set_phase2_client_cert:
 * @setting: the #NMSetting8021x
 * @cert_path: when @scheme is set to either %NM_SETTING_802_1X_CK_SCHEME_PATH
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
                                          const char *cert_path,
                                          NMSetting8021xCKScheme scheme,
                                          NMSetting8021xCKFormat *out_format,
                                          GError **error)
{
	NMSetting8021xPrivate *priv;
	NMCryptoFileFormat format = NM_CRYPTO_FILE_FORMAT_UNKNOWN;
	GByteArray *data;

	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), FALSE);

	if (cert_path) {
		g_return_val_if_fail (g_utf8_validate (cert_path, -1, NULL), FALSE);
		g_return_val_if_fail (   scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB
		                      || scheme == NM_SETTING_802_1X_CK_SCHEME_PATH,
		                      FALSE);
	}

	if (out_format)
		g_return_val_if_fail (*out_format == NM_SETTING_802_1X_CK_FORMAT_UNKNOWN, FALSE);

	priv = NM_SETTING_802_1X_GET_PRIVATE (setting);

	g_clear_pointer (&priv->phase2_client_cert, g_bytes_unref);

	if (!cert_path) {
		g_object_notify (G_OBJECT (setting), NM_SETTING_802_1X_PHASE2_CLIENT_CERT);
		return TRUE;
	}

	data = load_and_verify_certificate (cert_path, scheme, &format, error);
	if (data) {
		gboolean valid = FALSE;

		/* wpa_supplicant can only use raw x509 CA certs */
		switch (format) {
		case NM_CRYPTO_FILE_FORMAT_X509:
			if (out_format)
				*out_format = NM_SETTING_802_1X_CK_FORMAT_X509;
			valid = TRUE;
			break;
		case NM_CRYPTO_FILE_FORMAT_PKCS12:
			if (out_format)
				*out_format = NM_SETTING_802_1X_CK_FORMAT_PKCS12;
			valid = TRUE;
			break;
		default:
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     _("invalid certificate format"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_PHASE2_CLIENT_CERT);
			break;
		}

		if (valid) {
			if (scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB) {
				priv->phase2_client_cert = g_byte_array_free_to_bytes (data);
				data = NULL;
			} else if (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH)
				priv->phase2_client_cert = path_to_scheme_value (cert_path);
			else
				g_assert_not_reached ();
		}
		if (data)
			g_byte_array_unref (data);
	}

	g_object_notify (G_OBJECT (setting), NM_SETTING_802_1X_PHASE2_CLIENT_CERT);
	return priv->phase2_client_cert != NULL;
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
 * nm_setting_802_1x_get_client_cert_path().
 *
 * Returns: scheme used to store the private key (blob or path)
 **/
NMSetting8021xCKScheme
nm_setting_802_1x_get_private_key_scheme (NMSetting8021x *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NM_SETTING_802_1X_CK_SCHEME_UNKNOWN);

	return get_cert_scheme (NM_SETTING_802_1X_GET_PRIVATE (setting)->private_key, NULL);
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
	NMSetting8021xCKScheme scheme;

	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NULL);

	scheme = nm_setting_802_1x_get_private_key_scheme (setting);
	g_return_val_if_fail (scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB, NULL);

	return NM_SETTING_802_1X_GET_PRIVATE (setting)->private_key;
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
	NMSetting8021xCKScheme scheme;
	gconstpointer data;

	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NULL);

	scheme = nm_setting_802_1x_get_private_key_scheme (setting);
	g_return_val_if_fail (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH, NULL);

	data = g_bytes_get_data (NM_SETTING_802_1X_GET_PRIVATE (setting)->private_key, NULL);
	return (const char *)data + strlen (NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PATH);
}

static void
free_secure_bytes (gpointer data)
{
	GByteArray *array = data;

	memset (array->data, 0, array->len);
	g_byte_array_unref (array);
}

static GBytes *
file_to_secure_bytes (const char *filename)
{
	char *contents;
	GByteArray *array = NULL;
	gsize length = 0;

	if (g_file_get_contents (filename, &contents, &length, NULL)) {
		array = g_byte_array_sized_new (length);
		g_byte_array_append (array, (guint8 *) contents, length);
		memset (contents, 0, length);
		g_free (contents);
		return g_bytes_new_with_free_func (array->data, array->len, free_secure_bytes, array);
	}
	return NULL;
}

/**
 * nm_setting_802_1x_set_private_key:
 * @setting: the #NMSetting8021x
 * @key_path: when @scheme is set to either %NM_SETTING_802_1X_CK_SCHEME_PATH or
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
                                   const char *key_path,
                                   const char *password,
                                   NMSetting8021xCKScheme scheme,
                                   NMSetting8021xCKFormat *out_format,
                                   GError **error)
{
	NMSetting8021xPrivate *priv;
	NMCryptoFileFormat format = NM_CRYPTO_FILE_FORMAT_UNKNOWN;
	gboolean key_cleared = FALSE, password_cleared = FALSE;
	GError *local_err = NULL;

	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), FALSE);

	if (key_path) {
		g_return_val_if_fail (g_utf8_validate (key_path, -1, NULL), FALSE);
		g_return_val_if_fail (   scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB
		                      || scheme == NM_SETTING_802_1X_CK_SCHEME_PATH,
		                      FALSE);
	}

	if (out_format)
		g_return_val_if_fail (*out_format == NM_SETTING_802_1X_CK_FORMAT_UNKNOWN, FALSE);

	/* Ensure the private key is a recognized format and if the password was
	 * given, that it decrypts the private key.
	 */
	if (key_path) {
		format = crypto_verify_private_key (key_path, password, NULL, &local_err);
		if (format == NM_CRYPTO_FILE_FORMAT_UNKNOWN) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     local_err ? local_err->message : _("invalid private key"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_PRIVATE_KEY);
			g_clear_error (&local_err);
			return FALSE;
		}
	}

	priv = NM_SETTING_802_1X_GET_PRIVATE (setting);

	/* Clear out any previous private key data */
	if (priv->private_key) {
		g_bytes_unref (priv->private_key);
		priv->private_key = NULL;
		key_cleared = TRUE;
	}

	if (priv->private_key_password) {
		g_free (priv->private_key_password);
		priv->private_key_password = NULL;
		password_cleared = TRUE;
	}

	if (key_path == NULL) {
		if (key_cleared)
			g_object_notify (G_OBJECT (setting), NM_SETTING_802_1X_PRIVATE_KEY);
		if (password_cleared)
			g_object_notify (G_OBJECT (setting), NM_SETTING_802_1X_PRIVATE_KEY_PASSWORD);
		return TRUE;
	}

	priv->private_key_password = g_strdup (password);
	if (scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB) {
		/* FIXME: potential race after verifying the private key above */
		/* FIXME: ensure blob doesn't start with file:// */
		priv->private_key = file_to_secure_bytes (key_path);
		g_assert (priv->private_key);
	} else if (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH)
		priv->private_key = path_to_scheme_value (key_path);
	else
		g_assert_not_reached ();

	/* As required by NM and wpa_supplicant, set the client-cert
	 * property to the same PKCS#12 data.
	 */
	g_assert (format != NM_CRYPTO_FILE_FORMAT_UNKNOWN);
	if (format == NM_CRYPTO_FILE_FORMAT_PKCS12) {
		if (priv->client_cert)
			g_bytes_unref (priv->client_cert);
		priv->client_cert = g_bytes_ref (priv->private_key);
		g_object_notify (G_OBJECT (setting), NM_SETTING_802_1X_CLIENT_CERT);
	}

	g_object_notify (G_OBJECT (setting), NM_SETTING_802_1X_PRIVATE_KEY);
	if (password_cleared || password)
		g_object_notify (G_OBJECT (setting), NM_SETTING_802_1X_PRIVATE_KEY_PASSWORD);

	if (out_format)
		*out_format = (NMSetting8021xCKFormat) format;
	return priv->private_key != NULL;
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
	NMSetting8021xPrivate *priv;
	const char *path;
	GError *error = NULL;

	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NM_SETTING_802_1X_CK_FORMAT_UNKNOWN);
	priv = NM_SETTING_802_1X_GET_PRIVATE (setting);

	if (!priv->private_key)
		return NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;

	switch (nm_setting_802_1x_get_private_key_scheme (setting)) {
	case NM_SETTING_802_1X_CK_SCHEME_BLOB:
		if (crypto_is_pkcs12_data (g_bytes_get_data (priv->private_key, NULL),
		                           g_bytes_get_size (priv->private_key),
		                           NULL))
			return NM_SETTING_802_1X_CK_FORMAT_PKCS12;
		return NM_SETTING_802_1X_CK_FORMAT_RAW_KEY;
	case NM_SETTING_802_1X_CK_SCHEME_PATH:
		path = nm_setting_802_1x_get_private_key_path (setting);
		if (crypto_is_pkcs12_file (path, &error))
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
 * nm_setting_802_1x_get_client_cert_path().
 *
 * Returns: scheme used to store the "phase 2" private key (blob or path)
 **/
NMSetting8021xCKScheme
nm_setting_802_1x_get_phase2_private_key_scheme (NMSetting8021x *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NM_SETTING_802_1X_CK_SCHEME_UNKNOWN);

	return get_cert_scheme (NM_SETTING_802_1X_GET_PRIVATE (setting)->phase2_private_key, NULL);
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
	NMSetting8021xCKScheme scheme;

	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NULL);

	scheme = nm_setting_802_1x_get_phase2_private_key_scheme (setting);
	g_return_val_if_fail (scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB, NULL);

	return NM_SETTING_802_1X_GET_PRIVATE (setting)->phase2_private_key;
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
	NMSetting8021xCKScheme scheme;
	gconstpointer data;

	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NULL);

	scheme = nm_setting_802_1x_get_phase2_private_key_scheme (setting);
	g_return_val_if_fail (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH, NULL);

	data = g_bytes_get_data (NM_SETTING_802_1X_GET_PRIVATE (setting)->phase2_private_key, NULL);
	return (const char *)data + strlen (NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PATH);
}

/**
 * nm_setting_802_1x_set_phase2_private_key:
 * @setting: the #NMSetting8021x
 * @key_path: when @scheme is set to either %NM_SETTING_802_1X_CK_SCHEME_PATH or
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
                                          const char *key_path,
                                          const char *password,
                                          NMSetting8021xCKScheme scheme,
                                          NMSetting8021xCKFormat *out_format,
                                          GError **error)
{
	NMSetting8021xPrivate *priv;
	NMCryptoFileFormat format = NM_CRYPTO_FILE_FORMAT_UNKNOWN;
	gboolean key_cleared = FALSE, password_cleared = FALSE;
	GError *local_err = NULL;

	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), FALSE);

	if (key_path) {
		g_return_val_if_fail (g_utf8_validate (key_path, -1, NULL), FALSE);
		g_return_val_if_fail (   scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB
		                      || scheme == NM_SETTING_802_1X_CK_SCHEME_PATH,
		                      FALSE);
	}

	if (out_format)
		g_return_val_if_fail (*out_format == NM_SETTING_802_1X_CK_FORMAT_UNKNOWN, FALSE);

	/* Ensure the private key is a recognized format and if the password was
	 * given, that it decrypts the private key.
	 */
	if (key_path) {
		format = crypto_verify_private_key (key_path, password, NULL, &local_err);
		if (format == NM_CRYPTO_FILE_FORMAT_UNKNOWN) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     local_err ? local_err->message : _("invalid phase2 private key"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_PHASE2_PRIVATE_KEY);
			g_clear_error (&local_err);
			return FALSE;
		}
	}

	priv = NM_SETTING_802_1X_GET_PRIVATE (setting);

	/* Clear out any previous private key data */
	if (priv->phase2_private_key) {
		g_bytes_unref (priv->phase2_private_key);
		priv->phase2_private_key = NULL;
		key_cleared = TRUE;
	}

	if (priv->phase2_private_key_password) {
		g_free (priv->phase2_private_key_password);
		priv->phase2_private_key_password = NULL;
		password_cleared = TRUE;
	}

	if (key_path == NULL) {
		if (key_cleared)
			g_object_notify (G_OBJECT (setting), NM_SETTING_802_1X_PHASE2_PRIVATE_KEY);
		if (password_cleared)
			g_object_notify (G_OBJECT (setting), NM_SETTING_802_1X_PHASE2_PRIVATE_KEY_PASSWORD);
		return TRUE;
	}

	priv->phase2_private_key_password = g_strdup (password);
	if (scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB) {
		/* FIXME: potential race after verifying the private key above */
		/* FIXME: ensure blob doesn't start with file:// */
		priv->phase2_private_key = file_to_secure_bytes (key_path);
		g_assert (priv->phase2_private_key);
	} else if (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH)
		priv->phase2_private_key = path_to_scheme_value (key_path);
	else
		g_assert_not_reached ();

	/* As required by NM and wpa_supplicant, set the client-cert
	 * property to the same PKCS#12 data.
	 */
	g_assert (format != NM_CRYPTO_FILE_FORMAT_UNKNOWN);
	if (format == NM_CRYPTO_FILE_FORMAT_PKCS12) {
		if (priv->phase2_client_cert)
			g_bytes_unref (priv->phase2_client_cert);

		priv->phase2_client_cert = g_bytes_ref (priv->phase2_private_key);
		g_object_notify (G_OBJECT (setting), NM_SETTING_802_1X_PHASE2_CLIENT_CERT);
	}

	g_object_notify (G_OBJECT (setting), NM_SETTING_802_1X_PHASE2_PRIVATE_KEY);
	if (password_cleared || password)
		g_object_notify (G_OBJECT (setting), NM_SETTING_802_1X_PHASE2_PRIVATE_KEY_PASSWORD);

	if (out_format)
		*out_format = (NMSetting8021xCKFormat) format;
	return priv->phase2_private_key != NULL;
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
	NMSetting8021xPrivate *priv;
	const char *path;
	GError *error = NULL;

	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NM_SETTING_802_1X_CK_FORMAT_UNKNOWN);
	priv = NM_SETTING_802_1X_GET_PRIVATE (setting);

	if (!priv->phase2_private_key)
		return NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;

	switch (nm_setting_802_1x_get_phase2_private_key_scheme (setting)) {
	case NM_SETTING_802_1X_CK_SCHEME_BLOB:
		if (crypto_is_pkcs12_data (g_bytes_get_data (priv->phase2_private_key, NULL),
		                           g_bytes_get_size (priv->phase2_private_key),
		                           NULL))
			return NM_SETTING_802_1X_CK_FORMAT_PKCS12;
		return NM_SETTING_802_1X_CK_FORMAT_RAW_KEY;
	case NM_SETTING_802_1X_CK_SCHEME_PATH:
		path = nm_setting_802_1x_get_phase2_private_key_path (setting);
		if (crypto_is_pkcs12_file (path, &error))
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
                           const char *path,
                           const char *password)
{
	NMCryptoFileFormat format = NM_CRYPTO_FILE_FORMAT_UNKNOWN;

	/* Private key password is required */
	if (password) {
		if (path)
			format = crypto_verify_private_key (path, password, NULL, NULL);
		else if (blob)
			format = crypto_verify_private_key_data (g_bytes_get_data (blob, NULL),
			                                         g_bytes_get_size (blob),
			                                         password, NULL, NULL);
		else
			g_warning ("%s: unknown private key password scheme", __func__);
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
		else {
			g_warning ("%s: unknown phase2 private key scheme %d", __func__, scheme);
			g_ptr_array_add (secrets, NM_SETTING_802_1X_PHASE2_PRIVATE_KEY);
			return;
		}

		if (need_private_key_password (blob, path, priv->phase2_private_key_password))
			g_ptr_array_add (secrets, NM_SETTING_802_1X_PHASE2_PRIVATE_KEY_PASSWORD);
	} else {
		scheme = nm_setting_802_1x_get_private_key_scheme (self);
		if (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH)
			path = nm_setting_802_1x_get_private_key_path (self);
		else if (scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB)
			blob = nm_setting_802_1x_get_private_key_blob (self);
		else {
			g_warning ("%s: unknown private key scheme %d", __func__, scheme);
			g_ptr_array_add (secrets, NM_SETTING_802_1X_PRIVATE_KEY);
			return;
		}

		if (need_private_key_password (blob, path, priv->private_key_password))
			g_ptr_array_add (secrets, NM_SETTING_802_1X_PRIVATE_KEY_PASSWORD);
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
		if (crypto_is_pkcs12_data (g_bytes_get_data (priv->phase2_private_key, NULL),
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
		if (crypto_is_pkcs12_data (g_bytes_get_data (priv->private_key, NULL),
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

/* Implemented below... */
static void need_secrets_phase2 (NMSetting8021x *self,
                                 GPtrArray *secrets,
                                 gboolean phase2);


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

static EAPMethodsTable eap_methods_table[] = {
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
	{ NULL, NULL, NULL }
};

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
		secrets = NULL;
	}

	return secrets;
}

static gboolean
verify_cert (GBytes *bytes, const char *prop_name, GError **error)
{
	GError *local = NULL;

	if (   !bytes
	    || get_cert_scheme (bytes, &local) != NM_SETTING_802_1X_CK_SCHEME_UNKNOWN)
		return TRUE;

	g_set_error (error,
	             NM_CONNECTION_ERROR,
	             NM_CONNECTION_ERROR_INVALID_PROPERTY,
	             _("certificate is invalid: %s"), local->message);
	g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, prop_name);
	g_error_free (local);
	return FALSE;
}

static gboolean
verify (NMSetting *setting, NMConnection *connection, GError **error)
{
	NMSetting8021x *self = NM_SETTING_802_1X (setting);
	NMSetting8021xPrivate *priv = NM_SETTING_802_1X_GET_PRIVATE (self);
	const char *valid_eap[] = { "leap", "md5", "tls", "peap", "ttls", "sim", "fast", "pwd", NULL };
	const char *valid_phase1_peapver[] = { "0", "1", NULL };
	const char *valid_phase1_peaplabel[] = { "0", "1", NULL };
	const char *valid_phase1_fast_pac[] = { "0", "1", "2", "3", NULL };
	const char *valid_phase2_auth[] = { "pap", "chap", "mschap", "mschapv2", "gtc", "otp", "md5", "tls", NULL };
	const char *valid_phase2_autheap[] = { "md5", "mschapv2", "otp", "gtc", "tls", NULL };
	GSList *iter;

	if (error)
		g_return_val_if_fail (*error == NULL, FALSE);

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

	if (priv->phase1_peapver && !_nm_utils_string_in_list (priv->phase1_peapver, valid_phase1_peapver)) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("'%s' is not a valid value for the property"),
		             priv->phase1_peapver);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_PHASE1_PEAPVER);
		return FALSE;
	}

	if (priv->phase1_peaplabel && !_nm_utils_string_in_list (priv->phase1_peaplabel, valid_phase1_peaplabel)) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("'%s' is not a valid value for the property"),
		             priv->phase1_peaplabel);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_PHASE1_PEAPLABEL);
		return FALSE;
	}

	if (priv->phase1_fast_provisioning && !_nm_utils_string_in_list (priv->phase1_fast_provisioning, valid_phase1_fast_pac)) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("'%s' is not a valid value for the property"),
		             priv->phase1_fast_provisioning);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_PHASE1_FAST_PROVISIONING);
		return FALSE;
	}

	if (priv->phase2_auth && !_nm_utils_string_in_list (priv->phase2_auth, valid_phase2_auth)) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("'%s' is not a valid value for the property"),
		             priv->phase2_auth);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_PHASE2_AUTH);
		return FALSE;
	}

	if (priv->phase2_autheap && !_nm_utils_string_in_list (priv->phase2_autheap, valid_phase2_autheap)) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("'%s' is not a valid value for the property"),
		             priv->phase2_autheap);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_PHASE2_AUTHEAP);
		return FALSE;
	}

	if (!verify_cert (priv->ca_cert, NM_SETTING_802_1X_CA_CERT, error))
		return FALSE;
	if (!verify_cert (priv->phase2_ca_cert, NM_SETTING_802_1X_PHASE2_CA_CERT, error))
		return FALSE;

	if (!verify_cert (priv->client_cert, NM_SETTING_802_1X_CLIENT_CERT, error))
		return FALSE;
	if (!verify_cert (priv->phase2_client_cert, NM_SETTING_802_1X_PHASE2_CLIENT_CERT, error))
		return FALSE;

	if (!verify_cert (priv->private_key, NM_SETTING_802_1X_PRIVATE_KEY, error))
		return FALSE;
	if (!verify_cert (priv->phase2_private_key, NM_SETTING_802_1X_PHASE2_PRIVATE_KEY, error))
		return FALSE;

	/* FIXME: finish */

	return TRUE;
}

static void
nm_setting_802_1x_init (NMSetting8021x *setting)
{
}

static void
finalize (GObject *object)
{
	NMSetting8021x *self = NM_SETTING_802_1X (object);
	NMSetting8021xPrivate *priv = NM_SETTING_802_1X_GET_PRIVATE (self);

	/* Strings first. g_free() already checks for NULLs so we don't have to */

	g_free (priv->identity);
	g_free (priv->anonymous_identity);
	g_free (priv->ca_path);
	g_free (priv->subject_match);
	g_free (priv->phase1_peapver);
	g_free (priv->phase1_peaplabel);
	g_free (priv->phase1_fast_provisioning);
	g_free (priv->phase2_auth);
	g_free (priv->phase2_autheap);
	g_free (priv->phase2_ca_path);
	g_free (priv->phase2_subject_match);
	g_free (priv->password);
	if (priv->password_raw)
		g_bytes_unref (priv->password_raw);
	g_free (priv->pin);

	g_slist_free_full (priv->eap, g_free);
	g_slist_free_full (priv->altsubject_matches, g_free);
	g_slist_free_full (priv->phase2_altsubject_matches, g_free);

	if (priv->ca_cert)
		g_bytes_unref (priv->ca_cert);
	if (priv->client_cert)
		g_bytes_unref (priv->client_cert);
	if (priv->private_key)
		g_bytes_unref (priv->private_key);
	g_free (priv->private_key_password);
	if (priv->phase2_ca_cert)
		g_bytes_unref (priv->phase2_ca_cert);
	if (priv->phase2_client_cert)
		g_bytes_unref (priv->phase2_client_cert);
	if (priv->phase2_private_key)
		g_bytes_unref (priv->phase2_private_key);
	g_free (priv->phase2_private_key_password);

	G_OBJECT_CLASS (nm_setting_802_1x_parent_class)->finalize (object);
}

static GBytes *
set_cert_prop_helper (const GValue *value, const char *prop_name, GError **error)
{
	gboolean valid;
	GBytes *bytes = NULL;

	bytes = g_value_dup_boxed (value);
	/* Verify the new data */
	if (bytes) {
		valid = verify_cert (bytes, prop_name, error);
		if (!valid)
			g_clear_pointer (&bytes, g_bytes_unref);
	}
	return bytes;
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMSetting8021x *setting = NM_SETTING_802_1X (object);
	NMSetting8021xPrivate *priv = NM_SETTING_802_1X_GET_PRIVATE (setting);
	GError *error = NULL;

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
		if (priv->ca_cert)
			g_bytes_unref (priv->ca_cert);
		priv->ca_cert = set_cert_prop_helper (value, NM_SETTING_802_1X_CA_CERT, &error);
		if (error) {
			g_warning ("Error setting certificate (invalid data): (%d) %s",
			           error->code, error->message);
			g_error_free (error);
		}
		break;
	case PROP_CA_PATH:
		g_free (priv->ca_path);
		priv->ca_path = g_value_dup_string (value);
		break;
	case PROP_SUBJECT_MATCH:
		g_free (priv->subject_match);
		priv->subject_match = g_value_dup_string (value);
		break;
	case PROP_ALTSUBJECT_MATCHES:
		g_slist_free_full (priv->altsubject_matches, g_free);
		priv->altsubject_matches = _nm_utils_strv_to_slist (g_value_get_boxed (value), TRUE);
		break;
	case PROP_CLIENT_CERT:
		if (priv->client_cert)
			g_bytes_unref (priv->client_cert);
		priv->client_cert = set_cert_prop_helper (value, NM_SETTING_802_1X_CLIENT_CERT, &error);
		if (error) {
			g_warning ("Error setting certificate (invalid data): (%d) %s",
			           error->code, error->message);
			g_error_free (error);
		}
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
	case PROP_PHASE2_AUTH:
		g_free (priv->phase2_auth);
		priv->phase2_auth = g_value_dup_string (value);
		break;
	case PROP_PHASE2_AUTHEAP:
		g_free (priv->phase2_autheap);
		priv->phase2_autheap = g_value_dup_string (value);
		break;
	case PROP_PHASE2_CA_CERT:
		if (priv->phase2_ca_cert)
			g_bytes_unref (priv->phase2_ca_cert);
		priv->phase2_ca_cert = set_cert_prop_helper (value, NM_SETTING_802_1X_PHASE2_CA_CERT, &error);
		if (error) {
			g_warning ("Error setting certificate (invalid data): (%d) %s",
			           error->code, error->message);
			g_error_free (error);
		}
		break;
	case PROP_PHASE2_CA_PATH:
		g_free (priv->phase2_ca_path);
		priv->phase2_ca_path = g_value_dup_string (value);
		break;
	case PROP_PHASE2_SUBJECT_MATCH:
		g_free (priv->phase2_subject_match);
		priv->phase2_subject_match = g_value_dup_string (value);
		break;
	case PROP_PHASE2_ALTSUBJECT_MATCHES:
		g_slist_free_full (priv->phase2_altsubject_matches, g_free);
		priv->phase2_altsubject_matches = _nm_utils_strv_to_slist (g_value_get_boxed (value), TRUE);
		break;
	case PROP_PHASE2_CLIENT_CERT:
		if (priv->phase2_client_cert)
			g_bytes_unref (priv->phase2_client_cert);
		priv->phase2_client_cert = set_cert_prop_helper (value, NM_SETTING_802_1X_PHASE2_CLIENT_CERT, &error);
		if (error) {
			g_warning ("Error setting certificate (invalid data): (%d) %s",
			           error->code, error->message);
			g_error_free (error);
		}
		break;
	case PROP_PASSWORD:
		g_free (priv->password);
		priv->password = g_value_dup_string (value);
		break;
	case PROP_PASSWORD_FLAGS:
		priv->password_flags = g_value_get_flags (value);
		break;
	case PROP_PASSWORD_RAW:
		if (priv->password_raw)
			g_bytes_unref (priv->password_raw);
		priv->password_raw = g_value_dup_boxed (value);
		break;
	case PROP_PASSWORD_RAW_FLAGS:
		priv->password_raw_flags = g_value_get_flags (value);
		break;
	case PROP_PRIVATE_KEY:
		if (priv->private_key)
			g_bytes_unref (priv->private_key);
		priv->private_key = set_cert_prop_helper (value, NM_SETTING_802_1X_PRIVATE_KEY, &error);
		if (error) {
			g_warning ("Error setting private key (invalid data): (%d) %s",
			           error->code, error->message);
			g_error_free (error);
		}
		break;
	case PROP_PRIVATE_KEY_PASSWORD:
		g_free (priv->private_key_password);
		priv->private_key_password = g_value_dup_string (value);
		break;
	case PROP_PRIVATE_KEY_PASSWORD_FLAGS:
		priv->private_key_password_flags = g_value_get_flags (value);
		break;
	case PROP_PHASE2_PRIVATE_KEY:
		if (priv->phase2_private_key)
			g_bytes_unref (priv->phase2_private_key);
		priv->phase2_private_key = set_cert_prop_helper (value, NM_SETTING_802_1X_PHASE2_PRIVATE_KEY, &error);
		if (error) {
			g_warning ("Error setting private key (invalid data): (%d) %s",
			           error->code, error->message);
			g_error_free (error);
		}
		break;
	case PROP_PHASE2_PRIVATE_KEY_PASSWORD:
		g_free (priv->phase2_private_key_password);
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
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

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
	case PROP_CA_PATH:
		g_value_set_string (value, priv->ca_path);
		break;
	case PROP_SUBJECT_MATCH:
		g_value_set_string (value, priv->subject_match);
		break;
	case PROP_ALTSUBJECT_MATCHES:
		g_value_take_boxed (value, _nm_utils_slist_to_strv (priv->altsubject_matches, TRUE));
		break;
	case PROP_CLIENT_CERT:
		g_value_set_boxed (value, priv->client_cert);
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
	case PROP_PHASE2_AUTH:
		g_value_set_string (value, priv->phase2_auth);
		break;
	case PROP_PHASE2_AUTHEAP:
		g_value_set_string (value, priv->phase2_autheap);
		break;
	case PROP_PHASE2_CA_CERT:
		g_value_set_boxed (value, priv->phase2_ca_cert);
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
	case PROP_PHASE2_CLIENT_CERT:
		g_value_set_boxed (value, priv->phase2_client_cert);
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
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_setting_802_1x_class_init (NMSetting8021xClass *setting_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (setting_class);
	NMSettingClass *parent_class = NM_SETTING_CLASS (setting_class);

	g_type_class_add_private (setting_class, sizeof (NMSetting8021xPrivate));

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize     = finalize;

	parent_class->verify         = verify;
	parent_class->need_secrets   = need_secrets;

	/* Properties */

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
	g_object_class_install_property
		(object_class, PROP_EAP,
		 g_param_spec_boxed (NM_SETTING_802_1X_EAP, "", "",
		                     G_TYPE_STRV,
		                     G_PARAM_READWRITE |
		                     G_PARAM_STATIC_STRINGS));

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
	g_object_class_install_property
		(object_class, PROP_IDENTITY,
		 g_param_spec_string (NM_SETTING_802_1X_IDENTITY, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));

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
	g_object_class_install_property
		(object_class, PROP_ANONYMOUS_IDENTITY,
		 g_param_spec_string (NM_SETTING_802_1X_ANONYMOUS_IDENTITY, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));

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
	g_object_class_install_property
		(object_class, PROP_PAC_FILE,
		 g_param_spec_string (NM_SETTING_802_1X_PAC_FILE, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));

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
	g_object_class_install_property
		(object_class, PROP_CA_CERT,
		 g_param_spec_boxed (NM_SETTING_802_1X_CA_CERT, "", "",
		                     G_TYPE_BYTES,
		                     G_PARAM_READWRITE |
		                     G_PARAM_STATIC_STRINGS));

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
	g_object_class_install_property
		(object_class, PROP_CA_PATH,
		 g_param_spec_string (NM_SETTING_802_1X_CA_PATH, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMSetting8021x:subject-match:
	 *
	 * Substring to be matched against the subject of the certificate presented
	 * by the authentication server. When unset, no verification of the
	 * authentication server certificate's subject is performed.
	 **/
	/* ---ifcfg-rh---
	 * property: subject-match
	 * variable: IEEE_8021X_SUBJECT_MATCH(+)
	 * description: Substring to match subject of server certificate against.
	 * example: IEEE_8021X_SUBJECT_MATCH="Red Hat"
	 * ---end---
	 */
	g_object_class_install_property
		(object_class, PROP_SUBJECT_MATCH,
		 g_param_spec_string (NM_SETTING_802_1X_SUBJECT_MATCH, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));

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
	g_object_class_install_property
		(object_class, PROP_ALTSUBJECT_MATCHES,
		 g_param_spec_boxed (NM_SETTING_802_1X_ALTSUBJECT_MATCHES, "", "",
		                     G_TYPE_STRV,
		                     G_PARAM_READWRITE |
		                     G_PARAM_STATIC_STRINGS));

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
	g_object_class_install_property
		(object_class, PROP_CLIENT_CERT,
		 g_param_spec_boxed (NM_SETTING_802_1X_CLIENT_CERT, "", "",
		                     G_TYPE_BYTES,
		                     G_PARAM_READWRITE |
		                     G_PARAM_STATIC_STRINGS));

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
	g_object_class_install_property
		(object_class, PROP_PHASE1_PEAPVER,
		 g_param_spec_string (NM_SETTING_802_1X_PHASE1_PEAPVER, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));

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
	g_object_class_install_property
		(object_class, PROP_PHASE1_PEAPLABEL,
		 g_param_spec_string (NM_SETTING_802_1X_PHASE1_PEAPLABEL, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));

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
	g_object_class_install_property
		(object_class, PROP_PHASE1_FAST_PROVISIONING,
		 g_param_spec_string (NM_SETTING_802_1X_PHASE1_FAST_PROVISIONING, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMSetting8021x:phase2-auth:
	 *
	 * Specifies the allowed "phase 2" inner non-EAP authentication methods when
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
	g_object_class_install_property
		(object_class, PROP_PHASE2_AUTH,
		 g_param_spec_string (NM_SETTING_802_1X_PHASE2_AUTH, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMSetting8021x:phase2-autheap:
	 *
	 * Specifies the allowed "phase 2" inner EAP-based authentication methods
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
	g_object_class_install_property
		(object_class, PROP_PHASE2_AUTHEAP,
		 g_param_spec_string (NM_SETTING_802_1X_PHASE2_AUTHEAP, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));

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
	g_object_class_install_property
		(object_class, PROP_PHASE2_CA_CERT,
		 g_param_spec_boxed (NM_SETTING_802_1X_PHASE2_CA_CERT, "", "",
		                     G_TYPE_BYTES,
		                     G_PARAM_READWRITE |
		                     G_PARAM_STATIC_STRINGS));

	/**
	 * NMSetting8021x:phase2-ca-path:
	 *
	 * UTF-8 encoded path to a directory containing PEM or DER formatted
	 * certificates to be added to the verification chain in addition to the
	 * certificate specified in the #NMSetting8021x:phase2-ca-cert property.
	 **/
	g_object_class_install_property
		(object_class, PROP_PHASE2_CA_PATH,
		 g_param_spec_string (NM_SETTING_802_1X_PHASE2_CA_PATH, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMSetting8021x:phase2-subject-match:
	 *
	 * Substring to be matched against the subject of the certificate presented
	 * by the authentication server during the inner "phase 2"
	 * authentication. When unset, no verification of the authentication server
	 * certificate's subject is performed.
	 **/
	/* ---ifcfg-rh---
	 * property: phase2-subject-match
	 * variable: IEEE_8021X_PHASE2_SUBJECT_MATCH(+)
	 * description: Substring to match subject of server certificate against.
	 * example: IEEE_8021X_PHASE2_SUBJECT_MATCH="Red Hat"
	 * ---end---
	 */
	g_object_class_install_property
		(object_class, PROP_PHASE2_SUBJECT_MATCH,
		 g_param_spec_string (NM_SETTING_802_1X_PHASE2_SUBJECT_MATCH, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));

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
	g_object_class_install_property
		(object_class, PROP_PHASE2_ALTSUBJECT_MATCHES,
		 g_param_spec_boxed (NM_SETTING_802_1X_PHASE2_ALTSUBJECT_MATCHES, "", "",
		                     G_TYPE_STRV,
		                     G_PARAM_READWRITE |
		                     G_PARAM_STATIC_STRINGS));

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
	g_object_class_install_property
		(object_class, PROP_PHASE2_CLIENT_CERT,
		 g_param_spec_boxed (NM_SETTING_802_1X_PHASE2_CLIENT_CERT, "", "",
		                     G_TYPE_BYTES,
		                     G_PARAM_READWRITE |
		                     G_PARAM_STATIC_STRINGS));

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
	g_object_class_install_property
		(object_class, PROP_PASSWORD,
		 g_param_spec_string (NM_SETTING_802_1X_PASSWORD, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      NM_SETTING_PARAM_SECRET |
		                      G_PARAM_STATIC_STRINGS));

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
	g_object_class_install_property
		(object_class, PROP_PASSWORD_FLAGS,
		 g_param_spec_flags (NM_SETTING_802_1X_PASSWORD_FLAGS, "", "",
		                     NM_TYPE_SETTING_SECRET_FLAGS,
		                     NM_SETTING_SECRET_FLAG_NONE,
		                     G_PARAM_READWRITE |
		                     G_PARAM_STATIC_STRINGS));

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
	 * variable: (none)
	 * description: The property is not handled by ifcfg-rh plugin.
	 * ---end---
	 */
	g_object_class_install_property
		(object_class, PROP_PASSWORD_RAW,
		 g_param_spec_boxed (NM_SETTING_802_1X_PASSWORD_RAW, "", "",
		                     G_TYPE_BYTES,
		                     G_PARAM_READWRITE |
		                     NM_SETTING_PARAM_SECRET |
		                     G_PARAM_STATIC_STRINGS));

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
	g_object_class_install_property
		(object_class, PROP_PASSWORD_RAW_FLAGS,
		 g_param_spec_flags (NM_SETTING_802_1X_PASSWORD_RAW_FLAGS, "", "",
		                     NM_TYPE_SETTING_SECRET_FLAGS,
		                     NM_SETTING_SECRET_FLAG_NONE,
		                     G_PARAM_READWRITE |
		                     G_PARAM_STATIC_STRINGS));

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
	 * key, prefixed with the string "file://" and and ending with a terminating
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
	g_object_class_install_property
		(object_class, PROP_PRIVATE_KEY,
		 g_param_spec_boxed (NM_SETTING_802_1X_PRIVATE_KEY, "", "",
		                     G_TYPE_BYTES,
		                     G_PARAM_READWRITE |
		                     G_PARAM_STATIC_STRINGS));

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
	g_object_class_install_property
		(object_class, PROP_PRIVATE_KEY_PASSWORD,
		 g_param_spec_string (NM_SETTING_802_1X_PRIVATE_KEY_PASSWORD, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      NM_SETTING_PARAM_SECRET |
		                      G_PARAM_STATIC_STRINGS));

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
	g_object_class_install_property
		(object_class, PROP_PRIVATE_KEY_PASSWORD_FLAGS,
		 g_param_spec_flags (NM_SETTING_802_1X_PRIVATE_KEY_PASSWORD_FLAGS, "", "",
		                     NM_TYPE_SETTING_SECRET_FLAGS,
		                     NM_SETTING_SECRET_FLAG_NONE,
		                     G_PARAM_READWRITE |
		                     G_PARAM_STATIC_STRINGS));

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
	 * key, prefixed with the string "file://" and and ending with a terminating
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
	g_object_class_install_property
		(object_class, PROP_PHASE2_PRIVATE_KEY,
		 g_param_spec_boxed (NM_SETTING_802_1X_PHASE2_PRIVATE_KEY, "", "",
		                     G_TYPE_BYTES,
		                     G_PARAM_READWRITE |
		                     G_PARAM_STATIC_STRINGS));

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
	g_object_class_install_property
		(object_class, PROP_PHASE2_PRIVATE_KEY_PASSWORD,
		 g_param_spec_string (NM_SETTING_802_1X_PHASE2_PRIVATE_KEY_PASSWORD, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      NM_SETTING_PARAM_SECRET |
		                      G_PARAM_STATIC_STRINGS));

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
	g_object_class_install_property
		(object_class, PROP_PHASE2_PRIVATE_KEY_PASSWORD_FLAGS,
		 g_param_spec_flags (NM_SETTING_802_1X_PHASE2_PRIVATE_KEY_PASSWORD_FLAGS, "", "",
		                     NM_TYPE_SETTING_SECRET_FLAGS,
		                     NM_SETTING_SECRET_FLAG_NONE,
		                     G_PARAM_READWRITE |
		                     G_PARAM_STATIC_STRINGS));

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
	g_object_class_install_property
		(object_class, PROP_PIN,
		 g_param_spec_string (NM_SETTING_802_1X_PIN, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      NM_SETTING_PARAM_SECRET |
		                      G_PARAM_STATIC_STRINGS));

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
	g_object_class_install_property
		(object_class, PROP_PIN_FLAGS,
		 g_param_spec_flags (NM_SETTING_802_1X_PIN_FLAGS, "", "",
		                     NM_TYPE_SETTING_SECRET_FLAGS,
		                     NM_SETTING_SECRET_FLAG_NONE,
		                     G_PARAM_READWRITE |
		                     G_PARAM_STATIC_STRINGS));

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
	g_object_class_install_property
		(object_class, PROP_SYSTEM_CA_CERTS,
		 g_param_spec_boolean (NM_SETTING_802_1X_SYSTEM_CA_CERTS, "", "",
		                       FALSE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_CONSTRUCT |
		                       G_PARAM_STATIC_STRINGS));
}
