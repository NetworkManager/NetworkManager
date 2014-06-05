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
 * (C) Copyright 2007 - 2013 Red Hat, Inc.
 * (C) Copyright 2007 - 2008 Novell, Inc.
 */

#include <string.h>
#include <dbus/dbus-glib.h>
#include <glib/gi18n.h>

#include "nm-setting-8021x.h"
#include "nm-param-spec-specialized.h"
#include "nm-utils.h"
#include "nm-dbus-glib-types.h"
#include "crypto.h"
#include "nm-utils-private.h"
#include "nm-setting-private.h"

/**
 * SECTION:nm-setting-8021x
 * @short_description: Describes 802.1x-authenticated connection properties
 * @include: nm-setting-8021x.h
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

#define SCHEME_PATH "file://"

/**
 * nm_setting_802_1x_error_quark:
 *
 * Registers an error quark for #NMSetting8021x if necessary.
 *
 * Returns: the error quark used for #NMSetting8021x errors.
 **/
GQuark
nm_setting_802_1x_error_quark (void)
{
	static GQuark quark;

	if (G_UNLIKELY (!quark))
		quark = g_quark_from_static_string ("nm-setting-802-1x-error-quark");
	return quark;
}

G_DEFINE_TYPE_WITH_CODE (NMSetting8021x, nm_setting_802_1x, NM_TYPE_SETTING,
                         _nm_register_setting (NM_SETTING_802_1X_SETTING_NAME,
                                               g_define_type_id,
                                               2,
                                               NM_SETTING_802_1X_ERROR))
NM_SETTING_REGISTER_TYPE (NM_TYPE_SETTING_802_1X)

#define NM_SETTING_802_1X_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_802_1X, NMSetting8021xPrivate))

typedef struct {
	GSList *eap; /* GSList of strings */
	char *identity;
	char *anonymous_identity;
	char *pac_file;
	GByteArray *ca_cert;
	char *ca_path;
	char *subject_match;
	GSList *altsubject_matches;
	GByteArray *client_cert;
	char *phase1_peapver;
	char *phase1_peaplabel;
	char *phase1_fast_provisioning;
	char *phase2_auth;
	char *phase2_autheap;
	GByteArray *phase2_ca_cert;
	char *phase2_ca_path;
	char *phase2_subject_match;
	GSList *phase2_altsubject_matches;
	GByteArray *phase2_client_cert;
	char *password;
	NMSettingSecretFlags password_flags;
	GByteArray *password_raw;
	NMSettingSecretFlags password_raw_flags;
	char *pin;
	NMSettingSecretFlags pin_flags;
	GByteArray *private_key;
	char *private_key_password;
	NMSettingSecretFlags private_key_password_flags;
	GByteArray *phase2_private_key;
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
 *
 * Since: 0.9.10
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
get_cert_scheme (GByteArray *array)
{
	if (!array || !array->len)
		return NM_SETTING_802_1X_CK_SCHEME_UNKNOWN;

	if (   (array->len > strlen (SCHEME_PATH))
	    && !memcmp (array->data, SCHEME_PATH, strlen (SCHEME_PATH)))
		return NM_SETTING_802_1X_CK_SCHEME_PATH;

	return NM_SETTING_802_1X_CK_SCHEME_BLOB;
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

	return get_cert_scheme (NM_SETTING_802_1X_GET_PRIVATE (setting)->ca_cert);
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
 * Returns: the CA certificate data
 **/
const GByteArray *
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

	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NULL);

	scheme = nm_setting_802_1x_get_ca_cert_scheme (setting);
	g_return_val_if_fail (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH, NULL);

	return (const char *) (NM_SETTING_802_1X_GET_PRIVATE (setting)->ca_cert->data + strlen (SCHEME_PATH));
}

static GByteArray *
path_to_scheme_value (const char *path)
{
	GByteArray *array;

	g_return_val_if_fail (path != NULL, NULL);

	/* Add the path scheme tag to the front, then the fielname */
	array = g_byte_array_sized_new (strlen (path) + strlen (SCHEME_PATH) + 1);
	g_assert (array);
	g_byte_array_append (array, (const guint8 *) SCHEME_PATH, strlen (SCHEME_PATH));
	g_byte_array_append (array, (const guint8 *) path, strlen (path));
	g_byte_array_append (array, (const guint8 *) "\0", 1);
	return array;
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

	/* Clear out any previous ca_cert blob */
	if (priv->ca_cert) {
		g_byte_array_free (priv->ca_cert, TRUE);
		priv->ca_cert = NULL;
	}

	if (!cert_path) {
		g_object_notify (G_OBJECT (setting), NM_SETTING_802_1X_CA_CERT);
		return TRUE;
	}

	data = crypto_load_and_verify_certificate (cert_path, &format, error);
	if (data) {
		/* wpa_supplicant can only use raw x509 CA certs */
		if (format == NM_CRYPTO_FILE_FORMAT_X509) {
			if (out_format)
				*out_format = NM_SETTING_802_1X_CK_FORMAT_X509;

			if (scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB)
				priv->ca_cert = g_byte_array_ref (data);
			else if (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH)
				priv->ca_cert = path_to_scheme_value (cert_path);
			else
				g_assert_not_reached ();
		} else {
			g_set_error_literal (error,
			             NM_SETTING_802_1X_ERROR,
			             NM_SETTING_802_1X_ERROR_INVALID_PROPERTY,
			             _("CA certificate must be in X.509 format"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_CA_CERT);
		}
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
 *
 * Since: 0.9.10
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

	return get_cert_scheme (NM_SETTING_802_1X_GET_PRIVATE (setting)->client_cert);
}

/**
 * nm_setting_802_1x_get_client_cert_blob:
 * @setting: the #NMSetting8021x
 *
 * Client certificates are used to identify the connecting client to the network
 * when EAP-TLS is used as either the "phase 1" or "phase 2" 802.1x
 * authentication method.
 *
 * Returns: the client certificate data
 **/
const GByteArray *
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

	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NULL);

	scheme = nm_setting_802_1x_get_client_cert_scheme (setting);
	g_return_val_if_fail (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH, NULL);

	return (const char *) (NM_SETTING_802_1X_GET_PRIVATE (setting)->client_cert->data + strlen (SCHEME_PATH));
}

/**
 * nm_setting_802_1x_set_client_cert:
 * @setting: the #NMSetting8021x
 * @cert_path: when @scheme is set to either %NM_SETTING_802_1X_CK_SCHEME_PATH
 *   or %NM_SETTING_802_1X_CK_SCHEME_BLOB, pass the path of the client
 *   certificate file (PEM, DER, or PKCS#12 format).  The path must be UTF-8
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

	/* Clear out any previous ca_cert blob */
	if (priv->client_cert) {
		g_byte_array_free (priv->client_cert, TRUE);
		priv->client_cert = NULL;
	}

	if (!cert_path) {
		g_object_notify (G_OBJECT (setting), NM_SETTING_802_1X_CLIENT_CERT);
		return TRUE;
	}

	data = crypto_load_and_verify_certificate (cert_path, &format, error);
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
			                     NM_SETTING_802_1X_ERROR,
			                     NM_SETTING_802_1X_ERROR_INVALID_PROPERTY,
			                     _("invalid certificate format"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_CLIENT_CERT);
			break;
		}

		if (valid) {
			if (scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB)
				priv->client_cert = g_byte_array_ref (data);
			else if (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH)
				priv->client_cert = path_to_scheme_value (cert_path);
			else
				g_assert_not_reached ();
		}
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

	return get_cert_scheme (NM_SETTING_802_1X_GET_PRIVATE (setting)->phase2_ca_cert);
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
 * Returns: the "phase 2" CA certificate data
 **/
const GByteArray *
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

	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NULL);

	scheme = nm_setting_802_1x_get_phase2_ca_cert_scheme (setting);
	g_return_val_if_fail (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH, NULL);

	return (const char *) (NM_SETTING_802_1X_GET_PRIVATE (setting)->phase2_ca_cert->data + strlen (SCHEME_PATH));
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

	/* Clear out any previous ca_cert blob */
	if (priv->phase2_ca_cert) {
		g_byte_array_free (priv->phase2_ca_cert, TRUE);
		priv->phase2_ca_cert = NULL;
	}

	if (!cert_path) {
		g_object_notify (G_OBJECT (setting), NM_SETTING_802_1X_PHASE2_CA_CERT);
		return TRUE;
	}

	data = crypto_load_and_verify_certificate (cert_path, &format, error);
	if (data) {
		/* wpa_supplicant can only use raw x509 CA certs */
		if (format == NM_CRYPTO_FILE_FORMAT_X509) {
			if (out_format)
				*out_format = NM_SETTING_802_1X_CK_FORMAT_X509;

			if (scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB)
				priv->phase2_ca_cert = g_byte_array_ref (data);
			else if (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH)
				priv->phase2_ca_cert = path_to_scheme_value (cert_path);
			else
				g_assert_not_reached ();
		} else {
			g_set_error_literal (error,
			                     NM_SETTING_802_1X_ERROR,
			                     NM_SETTING_802_1X_ERROR_INVALID_PROPERTY,
			                     _("invalid certificate format"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_PHASE2_CA_CERT);
		}
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
 *
 * Since: 0.9.10
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

	return get_cert_scheme (NM_SETTING_802_1X_GET_PRIVATE (setting)->phase2_client_cert);
}

/**
 * nm_setting_802_1x_get_phase2_client_cert_blob:
 * @setting: the #NMSetting8021x
 *
 * Client certificates are used to identify the connecting client to the network
 * when EAP-TLS is used as either the "phase 1" or "phase 2" 802.1x
 * authentication method.
 *
 * Returns: the "phase 2" client certificate data
 **/
const GByteArray *
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

	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NULL);

	scheme = nm_setting_802_1x_get_phase2_client_cert_scheme (setting);
	g_return_val_if_fail (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH, NULL);

	return (const char *) (NM_SETTING_802_1X_GET_PRIVATE (setting)->phase2_client_cert->data + strlen (SCHEME_PATH));
}

/**
 * nm_setting_802_1x_set_phase2_client_cert:
 * @setting: the #NMSetting8021x
 * @cert_path: when @scheme is set to either %NM_SETTING_802_1X_CK_SCHEME_PATH
 *   or %NM_SETTING_802_1X_CK_SCHEME_BLOB, pass the path of the "phase2" client
 *   certificate file (PEM, DER, or PKCS#12 format).  The path must be UTF-8
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

	/* Clear out any previous ca_cert blob */
	if (priv->phase2_client_cert) {
		g_byte_array_free (priv->phase2_client_cert, TRUE);
		priv->phase2_client_cert = NULL;
	}

	if (!cert_path) {
		g_object_notify (G_OBJECT (setting), NM_SETTING_802_1X_PHASE2_CLIENT_CERT);
		return TRUE;
	}

	data = crypto_load_and_verify_certificate (cert_path, &format, error);
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
			                     NM_SETTING_802_1X_ERROR,
			                     NM_SETTING_802_1X_ERROR_INVALID_PROPERTY,
			                     _("invalid certificate format"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_PHASE2_CLIENT_CERT);
			break;
		}

		if (valid) {
			if (scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB)
				priv->phase2_client_cert = g_byte_array_ref (data);
			else if (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH)
				priv->phase2_client_cert = path_to_scheme_value (cert_path);
			else
				g_assert_not_reached ();
		}
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
 * Returns: the password used by the authentication method as a
 * UTF-8-encoded array of bytes, as specified by the
 * #NMSetting8021x:password-raw property
 **/
const GByteArray *
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

	return get_cert_scheme (NM_SETTING_802_1X_GET_PRIVATE (setting)->private_key);
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
 * Returns: the private key data
 **/
const GByteArray *
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

	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NULL);

	scheme = nm_setting_802_1x_get_private_key_scheme (setting);
	g_return_val_if_fail (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH, NULL);

	return (const char *) (NM_SETTING_802_1X_GET_PRIVATE (setting)->private_key->data + strlen (SCHEME_PATH));
}

static GByteArray *
file_to_byte_array (const char *filename)
{
	char *contents;
	GByteArray *array = NULL;
	gsize length = 0;

	if (g_file_get_contents (filename, &contents, &length, NULL)) {
		array = g_byte_array_sized_new (length);
		g_byte_array_append (array, (guint8 *) contents, length);
		g_assert (array->len == length);
		g_free (contents);
	}
	return array;
}

/**
 * nm_setting_802_1x_set_private_key:
 * @setting: the #NMSetting8021x
 * @key_path: when @scheme is set to either %NM_SETTING_802_1X_CK_SCHEME_PATH or
 *   %NM_SETTING_802_1X_CK_SCHEME_BLOB, pass the path of the private key file
 *   (PEM, DER, or PKCS#12 format).  The path must be UTF-8 encoded; use
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
		format = crypto_verify_private_key (key_path, password, &local_err);
		if (format == NM_CRYPTO_FILE_FORMAT_UNKNOWN) {
			g_set_error_literal (error,
			                     NM_SETTING_802_1X_ERROR,
			                     NM_SETTING_802_1X_ERROR_INVALID_PROPERTY,
			                     local_err ? local_err->message : _("invalid private key"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_PRIVATE_KEY);
			g_clear_error (&local_err);
			return FALSE;
		}
	}

	priv = NM_SETTING_802_1X_GET_PRIVATE (setting);

	/* Clear out any previous private key data */
	if (priv->private_key) {
		/* Try not to leave the private key around in memory */
		memset (priv->private_key->data, 0, priv->private_key->len);
		g_byte_array_free (priv->private_key, TRUE);
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
		/* Shouldn't fail this since we just verified the private key above */
		priv->private_key = file_to_byte_array (key_path);
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
			g_byte_array_free (priv->client_cert, TRUE);

		priv->client_cert = g_byte_array_sized_new (priv->private_key->len);
		g_byte_array_append (priv->client_cert, priv->private_key->data, priv->private_key->len);
		g_object_notify (G_OBJECT (setting), NM_SETTING_802_1X_CLIENT_CERT);
	}

	g_object_notify (G_OBJECT (setting), NM_SETTING_802_1X_PRIVATE_KEY);
	if (password_cleared || password)
		g_object_notify (G_OBJECT (setting), NM_SETTING_802_1X_PRIVATE_KEY_PASSWORD);

	if (out_format)
		*out_format = format;
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
		if (crypto_is_pkcs12_data (priv->private_key))
			return NM_SETTING_802_1X_CK_FORMAT_PKCS12;
		return NM_SETTING_802_1X_CK_FORMAT_RAW_KEY;
	case NM_SETTING_802_1X_CK_SCHEME_PATH:
		path = nm_setting_802_1x_get_private_key_path (setting);
		if (crypto_is_pkcs12_file (path, &error))
			return NM_SETTING_802_1X_CK_FORMAT_PKCS12;
		if (error) {
			/* Couldn't read the file or something */
			g_error_free (error);
			return NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;
		}
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

	return get_cert_scheme (NM_SETTING_802_1X_GET_PRIVATE (setting)->phase2_private_key);
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
 * Returns: the "phase 2" private key data
 **/
const GByteArray *
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

	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NULL);

	scheme = nm_setting_802_1x_get_phase2_private_key_scheme (setting);
	g_return_val_if_fail (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH, NULL);

	return (const char *) (NM_SETTING_802_1X_GET_PRIVATE (setting)->phase2_private_key->data + strlen (SCHEME_PATH));
}

/**
 * nm_setting_802_1x_set_phase2_private_key:
 * @setting: the #NMSetting8021x
 * @key_path: when @scheme is set to either %NM_SETTING_802_1X_CK_SCHEME_PATH or
 *   %NM_SETTING_802_1X_CK_SCHEME_BLOB, pass the path of the "phase2" private
 *   key file (PEM, DER, or PKCS#12 format).  The path must be UTF-8 encoded;
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
		format = crypto_verify_private_key (key_path, password, &local_err);
		if (format == NM_CRYPTO_FILE_FORMAT_UNKNOWN) {
			g_set_error_literal (error,
			                     NM_SETTING_802_1X_ERROR,
			                     NM_SETTING_802_1X_ERROR_INVALID_PROPERTY,
			                     local_err ? local_err->message : _("invalid phase2 private key"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_PHASE2_PRIVATE_KEY);
			g_clear_error (&local_err);
			return FALSE;
		}
	}

	priv = NM_SETTING_802_1X_GET_PRIVATE (setting);

	/* Clear out any previous private key data */
	if (priv->phase2_private_key) {
		/* Try not to leave the private key around in memory */
		memset (priv->phase2_private_key->data, 0, priv->phase2_private_key->len);
		g_byte_array_free (priv->phase2_private_key, TRUE);
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
		/* Shouldn't fail this since we just verified the private key above */
		priv->phase2_private_key = file_to_byte_array (key_path);
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
			g_byte_array_free (priv->phase2_client_cert, TRUE);

		priv->phase2_client_cert = g_byte_array_sized_new (priv->phase2_private_key->len);
		g_byte_array_append (priv->phase2_client_cert, priv->phase2_private_key->data, priv->phase2_private_key->len);
		g_object_notify (G_OBJECT (setting), NM_SETTING_802_1X_PHASE2_CLIENT_CERT);
	}

	g_object_notify (G_OBJECT (setting), NM_SETTING_802_1X_PHASE2_PRIVATE_KEY);
	if (password_cleared || password)
		g_object_notify (G_OBJECT (setting), NM_SETTING_802_1X_PHASE2_PRIVATE_KEY_PASSWORD);

	if (out_format)
		*out_format = format;
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
		if (crypto_is_pkcs12_data (priv->phase2_private_key))
			return NM_SETTING_802_1X_CK_FORMAT_PKCS12;
		return NM_SETTING_802_1X_CK_FORMAT_RAW_KEY;
	case NM_SETTING_802_1X_CK_SCHEME_PATH:
		path = nm_setting_802_1x_get_phase2_private_key_path (setting);
		if (crypto_is_pkcs12_file (path, &error))
			return NM_SETTING_802_1X_CK_FORMAT_PKCS12;
		if (error) {
			/* Couldn't read the file or something */
			g_error_free (error);
			return NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;
		}
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
	    && (!priv->password_raw || !priv->password_raw->len)) {
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
need_private_key_password (const GByteArray *blob,
                           const char *path,
                           const char *password)
{
	NMCryptoFileFormat format = NM_CRYPTO_FILE_FORMAT_UNKNOWN;

	/* Private key password is required */
	if (password) {
		if (path)
			format = crypto_verify_private_key (path, password, NULL);
		else if (blob)
			format = crypto_verify_private_key_data (blob, password, NULL);
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
	const GByteArray *blob = NULL;
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
			                     NM_SETTING_802_1X_ERROR,
			                     NM_SETTING_802_1X_ERROR_MISSING_PROPERTY,
			                     _("property is missing"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_PHASE2_CLIENT_CERT);
			return FALSE;
		} else if (!priv->phase2_client_cert->len) {
			g_set_error_literal (error,
			                     NM_SETTING_802_1X_ERROR,
			                     NM_SETTING_802_1X_ERROR_INVALID_PROPERTY,
			                     _("property is empty"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_PHASE2_CLIENT_CERT);
			return FALSE;
		}

		/* Private key is required for TLS */
		if (!priv->phase2_private_key) {
			g_set_error_literal (error,
			                     NM_SETTING_802_1X_ERROR,
			                     NM_SETTING_802_1X_ERROR_MISSING_PROPERTY,
			                     _("property is missing"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_PHASE2_PRIVATE_KEY);
			return FALSE;
		} else if (!priv->phase2_private_key->len) {
			g_set_error_literal (error,
			                     NM_SETTING_802_1X_ERROR,
			                     NM_SETTING_802_1X_ERROR_INVALID_PROPERTY,
			                     _("property is empty"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_PHASE2_PRIVATE_KEY);
			return FALSE;
		}

		/* If the private key is PKCS#12, check that it matches the client cert */
		if (crypto_is_pkcs12_data (priv->phase2_private_key)) {
			if (priv->phase2_private_key->len != priv->phase2_client_cert->len) {
				g_set_error (error,
				             NM_SETTING_802_1X_ERROR,
				             NM_SETTING_802_1X_ERROR_INVALID_PROPERTY,
				             _("has to match '%s' property for PKCS#12"),
				             NM_SETTING_802_1X_PHASE2_PRIVATE_KEY);
				g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_PHASE2_CLIENT_CERT);
				return FALSE;
			}

			if (memcmp (priv->phase2_private_key->data,
			            priv->phase2_client_cert->data,
			            priv->phase2_private_key->len)) {
				g_set_error (error,
				             NM_SETTING_802_1X_ERROR,
				             NM_SETTING_802_1X_ERROR_INVALID_PROPERTY,
				             _("has to match '%s' property for PKCS#12"),
				             NM_SETTING_802_1X_PHASE2_PRIVATE_KEY);
				g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_PHASE2_CLIENT_CERT);
				return FALSE;
			}
		}
	} else {
		if (!priv->client_cert) {
			g_set_error_literal (error,
			                     NM_SETTING_802_1X_ERROR,
			                     NM_SETTING_802_1X_ERROR_MISSING_PROPERTY,
			                     _("property is missing"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_CLIENT_CERT);
			return FALSE;
		} else if (!priv->client_cert->len) {
			g_set_error_literal (error,
			                     NM_SETTING_802_1X_ERROR,
			                     NM_SETTING_802_1X_ERROR_INVALID_PROPERTY,
			                     _("property is empty"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_CLIENT_CERT);
			return FALSE;
		}

		/* Private key is required for TLS */
		if (!priv->private_key) {
			g_set_error_literal (error,
			                     NM_SETTING_802_1X_ERROR,
			                     NM_SETTING_802_1X_ERROR_MISSING_PROPERTY,
			                     _("property is missing"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_PRIVATE_KEY);
			return FALSE;
		} else if (!priv->private_key->len) {
			g_set_error_literal (error,
			                     NM_SETTING_802_1X_ERROR,
			                     NM_SETTING_802_1X_ERROR_INVALID_PROPERTY,
			                     _("property is empty"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_PRIVATE_KEY);
			return FALSE;
		}

		/* If the private key is PKCS#12, check that it matches the client cert */
		if (crypto_is_pkcs12_data (priv->private_key)) {
			if (priv->private_key->len != priv->client_cert->len) {
				g_set_error (error,
				             NM_SETTING_802_1X_ERROR,
				             NM_SETTING_802_1X_ERROR_INVALID_PROPERTY,
				             _("has to match '%s' property for PKCS#12"),
				             NM_SETTING_802_1X_PRIVATE_KEY);
				g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_CLIENT_CERT);
				return FALSE;
			}

			if (memcmp (priv->private_key->data,
			            priv->client_cert->data,
			            priv->private_key->len)) {
				g_set_error (error,
				             NM_SETTING_802_1X_ERROR,
				             NM_SETTING_802_1X_ERROR_INVALID_PROPERTY,
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
			                     NM_SETTING_802_1X_ERROR,
			                     NM_SETTING_802_1X_ERROR_MISSING_PROPERTY,
			                     _("property is missing"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_IDENTITY);
		} else if (!strlen (priv->identity)) {
			g_set_error_literal (error,
			                     NM_SETTING_802_1X_ERROR,
			                     NM_SETTING_802_1X_ERROR_INVALID_PROPERTY,
			                     _("property is empty"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_IDENTITY);
		} else if (!priv->anonymous_identity) {
			g_set_error_literal (error,
			                     NM_SETTING_802_1X_ERROR,
			                     NM_SETTING_802_1X_ERROR_MISSING_PROPERTY,
			                     _("property is missing"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_ANONYMOUS_IDENTITY);
		} else {
			g_set_error_literal (error,
			                     NM_SETTING_802_1X_ERROR,
			                     NM_SETTING_802_1X_ERROR_INVALID_PROPERTY,
			                     _("property is empty"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_ANONYMOUS_IDENTITY);
		}
		return FALSE;
	}

	if (   (!priv->phase2_auth || !strlen (priv->phase2_auth))
	    && (!priv->phase2_autheap || !strlen (priv->phase2_autheap))) {
		if (!priv->phase2_auth) {
			g_set_error_literal (error,
			                     NM_SETTING_802_1X_ERROR,
			                     NM_SETTING_802_1X_ERROR_MISSING_PROPERTY,
			                     _("property is missing"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_PHASE2_AUTH);
		} else if (!strlen (priv->phase2_auth)) {
			g_set_error_literal (error,
			                     NM_SETTING_802_1X_ERROR,
			                     NM_SETTING_802_1X_ERROR_INVALID_PROPERTY,
			                     _("property is empty"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_PHASE2_AUTH);
		} else if (!priv->phase2_autheap) {
			g_set_error_literal (error,
			                     NM_SETTING_802_1X_ERROR,
			                     NM_SETTING_802_1X_ERROR_MISSING_PROPERTY,
			                     _("property is missing"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_PHASE2_AUTHEAP);
		} else {
			g_set_error_literal (error,
			                     NM_SETTING_802_1X_ERROR,
			                     NM_SETTING_802_1X_ERROR_INVALID_PROPERTY,
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
		                     NM_SETTING_802_1X_ERROR,
		                     NM_SETTING_802_1X_ERROR_MISSING_PROPERTY,
		                     _("property is missing"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_IDENTITY);
		return FALSE;
	} else if (!strlen (priv->identity)) {
		g_set_error_literal (error,
		                     NM_SETTING_802_1X_ERROR,
		                     NM_SETTING_802_1X_ERROR_INVALID_PROPERTY,
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
verify_cert (GByteArray *array, const char *prop_name, GError **error)
{
	if (!array)
		return TRUE;

	switch (get_cert_scheme (array)) {
	case NM_SETTING_802_1X_CK_SCHEME_BLOB:
		return TRUE;
	case NM_SETTING_802_1X_CK_SCHEME_PATH:
		/* For path-based schemes, verify that the path is zero-terminated */
		if (array->data[array->len - 1] == '\0') {
			/* And ensure it's UTF-8 valid too so we can pass it through
			 * D-Bus and stuff like that.
			 */
			if (g_utf8_validate ((const char *) (array->data + strlen (SCHEME_PATH)), -1, NULL))
				return TRUE;
		}
		break;
	default:
		break;
	}

	g_set_error_literal (error,
	                     NM_SETTING_802_1X_ERROR,
	                     NM_SETTING_802_1X_ERROR_INVALID_PROPERTY,
	                     _("property is invalid"));
	g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, prop_name);
	return FALSE;
}

static gboolean
verify (NMSetting *setting, GSList *all_settings, GError **error)
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
		                     NM_SETTING_802_1X_ERROR,
		                     NM_SETTING_802_1X_ERROR_MISSING_PROPERTY,
		                     _("property is missing"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_EAP);
		return FALSE;
	}

	if (!_nm_utils_string_slist_validate (priv->eap, valid_eap)) {
		g_set_error_literal (error,
		                     NM_SETTING_802_1X_ERROR,
		                     NM_SETTING_802_1X_ERROR_INVALID_PROPERTY,
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
		             NM_SETTING_802_1X_ERROR,
		             NM_SETTING_802_1X_ERROR_INVALID_PROPERTY,
		             _("'%s' is not a valid value for the property"),
		             priv->phase1_peapver);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_PHASE1_PEAPVER);
		return FALSE;
	}

	if (priv->phase1_peaplabel && !_nm_utils_string_in_list (priv->phase1_peaplabel, valid_phase1_peaplabel)) {
		g_set_error (error,
		             NM_SETTING_802_1X_ERROR,
		             NM_SETTING_802_1X_ERROR_INVALID_PROPERTY,
		             _("'%s' is not a valid value for the property"),
		             priv->phase1_peaplabel);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_PHASE1_PEAPLABEL);
		return FALSE;
	}

	if (priv->phase1_fast_provisioning && !_nm_utils_string_in_list (priv->phase1_fast_provisioning, valid_phase1_fast_pac)) {
		g_set_error (error,
		             NM_SETTING_802_1X_ERROR,
		             NM_SETTING_802_1X_ERROR_INVALID_PROPERTY,
		             _("'%s' is not a valid value for the property"),
		             priv->phase1_fast_provisioning);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_PHASE1_FAST_PROVISIONING);
		return FALSE;
	}

	if (priv->phase2_auth && !_nm_utils_string_in_list (priv->phase2_auth, valid_phase2_auth)) {
		g_set_error (error,
		             NM_SETTING_802_1X_ERROR,
		             NM_SETTING_802_1X_ERROR_INVALID_PROPERTY,
		             _("'%s' is not a valid value for the property"),
		             priv->phase2_auth);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_802_1X_SETTING_NAME, NM_SETTING_802_1X_PHASE2_AUTH);
		return FALSE;
	}

	if (priv->phase2_autheap && !_nm_utils_string_in_list (priv->phase2_autheap, valid_phase2_autheap)) {
		g_set_error (error,
		             NM_SETTING_802_1X_ERROR,
		             NM_SETTING_802_1X_ERROR_INVALID_PROPERTY,
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
		g_byte_array_free (priv->password_raw, TRUE);
	g_free (priv->pin);

	g_slist_free_full (priv->eap, g_free);
	g_slist_free_full (priv->altsubject_matches, g_free);
	g_slist_free_full (priv->phase2_altsubject_matches, g_free);

	if (priv->ca_cert)
		g_byte_array_free (priv->ca_cert, TRUE);
	if (priv->client_cert)
		g_byte_array_free (priv->client_cert, TRUE);
	if (priv->private_key)
		g_byte_array_free (priv->private_key, TRUE);
	g_free (priv->private_key_password);
	if (priv->phase2_ca_cert)
		g_byte_array_free (priv->phase2_ca_cert, TRUE);
	if (priv->phase2_client_cert)
		g_byte_array_free (priv->phase2_client_cert, TRUE);
	if (priv->phase2_private_key)
		g_byte_array_free (priv->phase2_private_key, TRUE);
	g_free (priv->phase2_private_key_password);

	G_OBJECT_CLASS (nm_setting_802_1x_parent_class)->finalize (object);
}

static GByteArray *
set_cert_prop_helper (const GValue *value, const char *prop_name, GError **error)
{
	gboolean valid;
	GByteArray *data = NULL;

	data = g_value_dup_boxed (value);
	/* Verify the new data */
	if (data) {
		valid = verify_cert (data, prop_name, error);
		if (!valid) {
			g_byte_array_free (data, TRUE);
			data = NULL;
		}
	}
	return data;
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
		priv->eap = g_value_dup_boxed (value);
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
		if (priv->ca_cert) {
			g_byte_array_free (priv->ca_cert, TRUE);
			priv->ca_cert = NULL;
		}
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
		priv->altsubject_matches = g_value_dup_boxed (value);
		break;
	case PROP_CLIENT_CERT:
		if (priv->client_cert) {
			g_byte_array_free (priv->client_cert, TRUE);
			priv->client_cert = NULL;
		}
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
		if (priv->phase2_ca_cert) {
			g_byte_array_free (priv->phase2_ca_cert, TRUE);
			priv->phase2_ca_cert = NULL;
		}
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
		priv->phase2_altsubject_matches = g_value_dup_boxed (value);
		break;
	case PROP_PHASE2_CLIENT_CERT:
		if (priv->phase2_client_cert) {
			g_byte_array_free (priv->phase2_client_cert, TRUE);
			priv->phase2_client_cert = NULL;
		}
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
		priv->password_flags = g_value_get_uint (value);
		break;
	case PROP_PASSWORD_RAW:
		if (priv->password_raw)
			g_byte_array_free (priv->password_raw, TRUE);
		priv->password_raw = g_value_dup_boxed (value);
		break;
	case PROP_PASSWORD_RAW_FLAGS:
		priv->password_raw_flags = g_value_get_uint (value);
		break;
	case PROP_PRIVATE_KEY:
		if (priv->private_key) {
			g_byte_array_free (priv->private_key, TRUE);
			priv->private_key = NULL;
		}
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
		priv->private_key_password_flags = g_value_get_uint (value);
		break;
	case PROP_PHASE2_PRIVATE_KEY:
		if (priv->phase2_private_key) {
			g_byte_array_free (priv->phase2_private_key, TRUE);
			priv->phase2_private_key = NULL;
		}
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
		priv->phase2_private_key_password_flags = g_value_get_uint (value);
		break;
	case PROP_PIN:
		g_free (priv->pin);
		priv->pin = g_value_dup_string (value);
		break;
	case PROP_PIN_FLAGS:
		priv->pin_flags = g_value_get_uint (value);
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
		g_value_set_boxed (value, priv->eap);
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
		g_value_set_boxed (value, priv->altsubject_matches);
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
		g_value_set_boxed (value, priv->phase2_altsubject_matches);
		break;
	case PROP_PHASE2_CLIENT_CERT:
		g_value_set_boxed (value, priv->phase2_client_cert);
		break;
	case PROP_PASSWORD:
		g_value_set_string (value, priv->password);
		break;
	case PROP_PASSWORD_FLAGS:
		g_value_set_uint (value, priv->password_flags);
		break;
	case PROP_PASSWORD_RAW:
		g_value_set_boxed (value, priv->password_raw);
		break;
	case PROP_PASSWORD_RAW_FLAGS:
		g_value_set_uint (value, priv->password_raw_flags);
		break;
	case PROP_PRIVATE_KEY:
		g_value_set_boxed (value, priv->private_key);
		break;
	case PROP_PRIVATE_KEY_PASSWORD:
		g_value_set_string (value, priv->private_key_password);
		break;
	case PROP_PRIVATE_KEY_PASSWORD_FLAGS:
		g_value_set_uint (value, priv->private_key_password_flags);
		break;
	case PROP_PHASE2_PRIVATE_KEY:
		g_value_set_boxed (value, priv->phase2_private_key);
		break;
	case PROP_PHASE2_PRIVATE_KEY_PASSWORD:
		g_value_set_string (value, priv->phase2_private_key_password);
		break;
	case PROP_PHASE2_PRIVATE_KEY_PASSWORD_FLAGS:
		g_value_set_uint (value, priv->phase2_private_key_password_flags);
		break;
	case PROP_PIN:
		g_value_set_string (value, priv->pin);
		break;
	case PROP_PIN_FLAGS:
		g_value_set_uint (value, priv->pin_flags);
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
	GError *error = NULL;

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
	g_object_class_install_property
		(object_class, PROP_EAP,
		 _nm_param_spec_specialized (NM_SETTING_802_1X_EAP,
							   "EAP",
							   "The allowed EAP method to be used when "
							   "authenticating to the network with 802.1x. "
							   "Valid methods are: 'leap', 'md5', 'tls', 'peap', "
							   "'ttls', 'pwd', and 'fast'. Each method requires "
							   "different configuration using the properties of "
							   "this setting; refer to wpa_supplicant "
							   "documentation for the allowed combinations.",
							   DBUS_TYPE_G_LIST_OF_STRING,
							   G_PARAM_READWRITE));

	/**
	 * NMSetting8021x:identity:
	 *
	 * Identity string for EAP authentication methods.  Often the user's user or
	 * login name.
	 **/
	g_object_class_install_property
		(object_class, PROP_IDENTITY,
		 g_param_spec_string (NM_SETTING_802_1X_IDENTITY,
						  "Identity",
						  "Identity string for EAP authentication methods.  "
						  "Often the user's user or login name.",
						  NULL,
						  G_PARAM_READWRITE));

	/**
	 * NMSetting8021x:anonymous-identity:
	 *
	 * Anonymous identity string for EAP authentication methods.  Used as the
	 * unencrypted identity with EAP types that support different tunneled
	 * identity like EAP-TTLS.
	 **/
	g_object_class_install_property
		(object_class, PROP_ANONYMOUS_IDENTITY,
		 g_param_spec_string (NM_SETTING_802_1X_ANONYMOUS_IDENTITY,
						  "Anonymous identity",
						  "Anonymous identity string for EAP authentication "
						  "methods.  Used as the unencrypted identity with EAP "
						  "types that support different tunneled identity like "
						  "EAP-TTLS.",
						  NULL,
						  G_PARAM_READWRITE));

	/**
	 * NMSetting8021x:pac-file:
	 *
	 * UTF-8 encoded file path containing PAC for EAP-FAST.
	 **/
	g_object_class_install_property
		(object_class, PROP_PAC_FILE,
		 g_param_spec_string (NM_SETTING_802_1X_PAC_FILE,
						  "PAC file",
						  "UTF-8 encoded file path containing PAC for EAP-FAST.",
						  NULL,
						  G_PARAM_READWRITE));

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
	g_object_class_install_property
		(object_class, PROP_CA_CERT,
		 _nm_param_spec_specialized (NM_SETTING_802_1X_CA_CERT,
							   "CA certificate",
							   "Contains the CA certificate if used by the EAP "
							   "method specified in the 'eap' property.  "
							   "Certificate data is specified using a 'scheme'; "
							   "two are currently supported: blob and path.  "
							   "When using the blob scheme (which is backwards "
							   "compatible with NM 0.7.x) this property should "
							   "be set to the certificate's DER encoded data.  "
							   "When using the path scheme, this property should "
							   "be set to the full UTF-8 encoded path of the "
							   "certificate, prefixed with the string 'file://' "
							   "and ending with a terminating NULL byte.  This "
							   "property can be unset even if the EAP method "
							   "supports CA certificates, but this allows "
							   "man-in-the-middle attacks and is NOT recommended.",
							   DBUS_TYPE_G_UCHAR_ARRAY,
							   G_PARAM_READWRITE));

	/**
	 * NMSetting8021x:ca-path:
	 *
	 * UTF-8 encoded path to a directory containing PEM or DER formatted
	 * certificates to be added to the verification chain in addition to the
	 * certificate specified in the #NMSetting8021x:ca-cert property.
	 **/
	g_object_class_install_property
		(object_class, PROP_CA_PATH,
		 g_param_spec_string (NM_SETTING_802_1X_CA_PATH,
						  "CA path",
						  "UTF-8 encoded path to a directory containing PEM or "
						  "DER formatted certificates to be added to the "
						  "verification chain in addition to the certificate "
						  "specified in the 'ca-cert' property.",
						  NULL,
						  G_PARAM_READWRITE));

	/**
	 * NMSetting8021x:subject-match:
	 *
	 * Substring to be matched against the subject of the certificate presented
	 * by the authentication server. When unset, no verification of the
	 * authentication server certificate's subject is performed.
	 **/
	g_object_class_install_property
		(object_class, PROP_SUBJECT_MATCH,
		 g_param_spec_string (NM_SETTING_802_1X_SUBJECT_MATCH,
							  "Subject match",
							  "Substring to be matched against the subject of "
							  "the certificate presented by the authentication "
							  "server. When unset, no verification of the "
							  "authentication server certificate's subject is "
							  "performed.",
							  NULL,
							  G_PARAM_READWRITE));

	/**
	 * NMSetting8021x:altsubject-matches:
	 *
	 * List of strings to be matched against the altSubjectName of the
	 * certificate presented by the authentication server. If the list is empty,
	 * no verification of the server certificate's altSubjectName is performed.
	 **/
	 g_object_class_install_property
		 (object_class, PROP_ALTSUBJECT_MATCHES,
		  _nm_param_spec_specialized (NM_SETTING_802_1X_ALTSUBJECT_MATCHES,
									  "altSubjectName matches",
									  "List of strings to be matched against "
									  "the altSubjectName of the certificate "
									  "presented by the authentication server. "
									  "If the list is empty, no verification "
									  "of the server certificate's "
									  "altSubjectName is performed.",
									  DBUS_TYPE_G_LIST_OF_STRING,
									  G_PARAM_READWRITE));

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
	g_object_class_install_property
		(object_class, PROP_CLIENT_CERT,
		 _nm_param_spec_specialized (NM_SETTING_802_1X_CLIENT_CERT,
							   "Client certificate",
							   "Contains the client certificate if used by the "
							   "EAP method specified in the 'eap' property.  "
							   "Certificate data is specified using a 'scheme'; "
							   "two are currently supported: blob and path.  "
							   "When using the blob scheme (which is backwards "
							   "compatible with NM 0.7.x) this property should "
							   "be set to the certificate's DER encoded data.  "
							   "When using the path scheme, this property should "
							   "be set to the full UTF-8 encoded path of the "
							   "certificate, prefixed with the string 'file://' "
							   "and ending with a terminating NULL byte.",
							   DBUS_TYPE_G_UCHAR_ARRAY,
							   G_PARAM_READWRITE));

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
	g_object_class_install_property
		(object_class, PROP_PHASE1_PEAPVER,
		 g_param_spec_string (NM_SETTING_802_1X_PHASE1_PEAPVER,
						  "Phase1 PEAPVER",
						  "Forces which PEAP version is used when PEAP is set "
						  "as the EAP method in 'eap' property.  When unset, "
						  "the version reported by the server will be used.  "
						  "Sometimes when using older RADIUS servers, it is "
						  "necessary to force the client to use a particular "
						  "PEAP version.  To do so, this property may be set to "
						  "'0' or '1' to force that specific PEAP version.",
						  NULL,
						  G_PARAM_READWRITE));

	/**
	 * NMSetting8021x:phase1-peaplabel:
	 *
	 * Forces use of the new PEAP label during key derivation.  Some RADIUS
	 * servers may require forcing the new PEAP label to interoperate with
	 * PEAPv1.  Set to "1" to force use of the new PEAP label.  See the
	 * wpa_supplicant documentation for more details.
	 **/
	g_object_class_install_property
		(object_class, PROP_PHASE1_PEAPLABEL,
		 g_param_spec_string (NM_SETTING_802_1X_PHASE1_PEAPLABEL,
						  "Phase1 PEAP label",
						  "Forces use of the new PEAP label during key "
						  "derivation.  Some RADIUS servers may require forcing "
						  "the new PEAP label to interoperate with PEAPv1.  "
						  "Set to '1' to force use of the new PEAP label.  See "
						  "the wpa_supplicant documentation for more details.",
						  NULL,
						  G_PARAM_READWRITE));

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
	g_object_class_install_property
		(object_class, PROP_PHASE1_FAST_PROVISIONING,
		 g_param_spec_string (NM_SETTING_802_1X_PHASE1_FAST_PROVISIONING,
						  "Phase1 fast provisioning",
						  "Enables or disables in-line provisioning of EAP-FAST "
						  "credentials when FAST is specified as the EAP method "
						  "in the #NMSetting8021x:eap property. Allowed values "
						  "are '0' (disabled), '1' (allow unauthenticated "
						  "provisioning), '2' (allow authenticated provisioning), "
						  "and '3' (allow both authenticated and unauthenticated "
						  "provisioning).  See the wpa_supplicant documentation "
						  "for more details.",
						  NULL,
						  G_PARAM_READWRITE));

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
	g_object_class_install_property
		(object_class, PROP_PHASE2_AUTH,
		 g_param_spec_string (NM_SETTING_802_1X_PHASE2_AUTH,
						  "Phase2 auth",
						  "Specifies the allowed 'phase 2' inner non-EAP "
						  "authentication methods when an EAP method that uses "
						  "an inner TLS tunnel is specified in the 'eap' "
						  "property. Recognized non-EAP phase2 methods are 'pap', "
						  "'chap', 'mschap', 'mschapv2', 'gtc', 'otp', 'md5', "
						  "and 'tls'.  Each 'phase 2' inner method requires "
						  "specific parameters for successful authentication; "
						  "see the wpa_supplicant documentation for more details.",
						  NULL,
						  G_PARAM_READWRITE));

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
	g_object_class_install_property
		(object_class, PROP_PHASE2_AUTHEAP,
		 g_param_spec_string (NM_SETTING_802_1X_PHASE2_AUTHEAP,
						  "Phase2 autheap",
						  "Specifies the allowed 'phase 2' inner EAP-based "
						  "authentication methods when an EAP method that uses "
						  "an inner TLS tunnel is specified in the 'eap' "
						  "property. Recognized EAP-based 'phase 2' methods are "
						  "'md5', 'mschapv2', 'otp', 'gtc', and 'tls'. Each "
						  "'phase 2' inner method requires specific parameters "
						  "for successful authentication; see the wpa_supplicant "
						  "documentation for more details.",
						  NULL,
						  G_PARAM_READWRITE));

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
		 _nm_param_spec_specialized (NM_SETTING_802_1X_PHASE2_CA_CERT,
							   "Phase2 CA certificate",
							   "Contains the 'phase 2' CA certificate if used by "
							   "the EAP method specified in the 'phase2-auth' or "
							   "'phase2-autheap' properties.  Certificate data "
							   "is specified using a 'scheme'; two are currently"
							   "supported: blob and path. When using the blob "
							   "scheme (which is backwards compatible with NM "
							   "0.7.x) this property should be set to the "
							   "certificate's DER encoded data. When using the "
							   "path scheme, this property should be set to the "
							   "full UTF-8 encoded path of the certificate, "
							   "prefixed with the string 'file://' and ending "
							   "with a terminating NULL byte.  This property can "
							   "be unset even if the EAP method supports CA "
							   "certificates, but this allows man-in-the-middle "
							   "attacks and is NOT recommended.",
							   DBUS_TYPE_G_UCHAR_ARRAY,
							   G_PARAM_READWRITE));

	/**
	 * NMSetting8021x:phase2-ca-path:
	 *
	 * UTF-8 encoded path to a directory containing PEM or DER formatted
	 * certificates to be added to the verification chain in addition to the
	 * certificate specified in the #NMSetting8021x:phase2-ca-cert property.
	 **/
	g_object_class_install_property
		(object_class, PROP_PHASE2_CA_PATH,
		 g_param_spec_string (NM_SETTING_802_1X_PHASE2_CA_PATH,
						  "Phase2 auth CA path",
						  "UTF-8 encoded path to a directory containing PEM or "
						  "DER formatted certificates to be added to the "
						  "verification chain in addition to the certificate "
						  "specified in the 'phase2-ca-cert' property.",
						  NULL,
						  G_PARAM_READWRITE));

	/**
	 * NMSetting8021x:phase2-subject-match:
	 *
	 * Substring to be matched against the subject of the certificate presented
	 * by the authentication server during the inner "phase 2"
	 * authentication. When unset, no verification of the authentication server
	 * certificate's subject is performed.
	 **/
	g_object_class_install_property
		(object_class, PROP_PHASE2_SUBJECT_MATCH,
		 g_param_spec_string (NM_SETTING_802_1X_PHASE2_SUBJECT_MATCH,
							  "Phase2 subject match",
							  "Substring to be matched against the subject of "
							  "the certificate presented by the authentication "
							  "server during the inner 'phase2' "
							  "authentication. When unset, no verification of "
							  "the authentication server certificate's subject "
							  "is performed.",
							  NULL,
							  G_PARAM_READWRITE));

	/**
	 * NMSetting8021x:phase2-altsubject-matches:
	 *
	 * List of strings to be matched against the altSubjectName of the
	 * certificate presented by the authentication server during the inner
	 * "phase 2" authentication. If the list is empty, no verification of the
	 * server certificate's altSubjectName is performed.
	 **/
	 g_object_class_install_property
		 (object_class, PROP_PHASE2_ALTSUBJECT_MATCHES,
		  _nm_param_spec_specialized (NM_SETTING_802_1X_PHASE2_ALTSUBJECT_MATCHES,
									  "altSubjectName matches",
									  "List of strings to be matched against "
									  "List of strings to be matched against "
									  "the altSubjectName of the certificate "
									  "presented by the authentication server "
									  "during the inner 'phase 2' "
									  "authentication. If the list is empty, no "
									  "verification of the server certificate's "
									  "altSubjectName is performed.",
									  DBUS_TYPE_G_LIST_OF_STRING,
									  G_PARAM_READWRITE));

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
	g_object_class_install_property
		(object_class, PROP_PHASE2_CLIENT_CERT,
		 _nm_param_spec_specialized (NM_SETTING_802_1X_PHASE2_CLIENT_CERT,
							   "Phase2 client certificate",
							   "Contains the 'phase 2' client certificate if "
							   "used by the EAP method specified in the "
							   "'phase2-auth' or 'phase2-autheap' properties. "
							   "Certificate data is specified using a 'scheme'; "
							   "two are currently supported: blob and path.  "
							   "When using the blob scheme (which is backwards "
							   "compatible with NM 0.7.x) this property should "
							   "be set to the certificate's DER encoded data.  "
							   "When using the path scheme, this property should "
							   "be set to the full UTF-8 encoded path of the "
							   "certificate, prefixed with the string 'file://' "
							   "and ending with a terminating NULL byte.",
							   DBUS_TYPE_G_UCHAR_ARRAY,
							   G_PARAM_READWRITE));

	/**
	 * NMSetting8021x:password:
	 *
	 * UTF-8 encoded password used for EAP authentication methods. If both the
	 * #NMSetting8021x:password property and the #NMSetting8021x:password-raw
	 * property are specified, #NMSetting8021x:password is preferred.
	 **/
	g_object_class_install_property
		(object_class, PROP_PASSWORD,
		 g_param_spec_string (NM_SETTING_802_1X_PASSWORD,
						  "Password",
						  "UTF-8 encoded password used for EAP authentication methods.",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SECRET));

	/**
	 * NMSetting8021x:password-flags:
	 *
	 * Flags indicating how to handle the #NMSetting8021x:password property.
	 **/
	g_object_class_install_property (object_class, PROP_PASSWORD_FLAGS,
		 g_param_spec_uint (NM_SETTING_802_1X_PASSWORD_FLAGS,
		                    "Password Flags",
		                    "Flags indicating how to handle the 802.1x password.",
		                    NM_SETTING_SECRET_FLAG_NONE,
		                    NM_SETTING_SECRET_FLAGS_ALL,
		                    NM_SETTING_SECRET_FLAG_NONE,
		                    G_PARAM_READWRITE));

	/**
	 * NMSetting8021x:password-raw:
	 *
	 * Password used for EAP authentication methods, given as a byte array to
	 * allow passwords in other encodings than UTF-8 to be used. If both the
	 * #NMSetting8021x:password property and the #NMSetting8021x:password-raw
	 * property are specified, #NMSetting8021x:password is preferred.
	 **/
	g_object_class_install_property
		(object_class, PROP_PASSWORD_RAW,
		 _nm_param_spec_specialized (NM_SETTING_802_1X_PASSWORD_RAW,
		                             "Password byte array",
		                             "Password used for EAP authentication "
		                             "methods, given as a byte array to allow "
		                             "passwords in other encodings than UTF-8 "
		                             "to be used.  If both 'password' and "
		                             "'password-raw' are given, 'password' is "
		                             "preferred.",
		                             DBUS_TYPE_G_UCHAR_ARRAY,
		                             G_PARAM_READWRITE | NM_SETTING_PARAM_SECRET));

	/**
	 * NMSetting8021x:password-raw-flags:
	 *
	 * Flags indicating how to handle the #NMSetting8021x:password-raw property.
	 **/
	g_object_class_install_property (object_class, PROP_PASSWORD_RAW_FLAGS,
		 g_param_spec_uint (NM_SETTING_802_1X_PASSWORD_RAW_FLAGS,
		                    "Password byte array Flags",
		                    "Flags indicating how to handle the 802.1x password byte array.",
		                    NM_SETTING_SECRET_FLAG_NONE,
		                    NM_SETTING_SECRET_FLAGS_ALL,
		                    NM_SETTING_SECRET_FLAG_NONE,
		                    G_PARAM_READWRITE));

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
	 * with a terminating NUL byte. When using PKCS#12 format private keys and
	 * the blob scheme, this property should be set to the PKCS#12 data and the
	 * #NMSetting8021x:private-key-password property must be set to password
	 * used to decrypt the PKCS#12 certificate and key. When using PKCS#12 files
	 * and the path scheme, this property should be set to the full UTF-8
	 * encoded path of the key, prefixed with the string "file://" and and
	 * ending with a terminating NUL byte, and as with the blob scheme the
	 * "private-key-password" property must be set to the password used to
	 * decode the PKCS#12 private key and certificate.
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
	g_object_class_install_property
		(object_class, PROP_PRIVATE_KEY,
		 _nm_param_spec_specialized (NM_SETTING_802_1X_PRIVATE_KEY,
							   "Private key",
							   "Contains the private key when the 'eap' property "
							   "is set to 'tls'.  Key data is specified using a "
							   "'scheme'; two are currently supported: blob and "
							   "path. When using the blob scheme and private "
							   "keys, this property should be set to the key's "
							   "encrypted PEM encoded data. When using private "
							   "keys with the path scheme, this property should "
							   "be set to the full UTF-8 encoded path of the key, "
							   "prefixed with the string 'file://' and ending "
							   "with a terminating NULL byte.  When using "
							   "PKCS#12 format private keys and the blob "
							   "scheme, this property should be set to the "
							   "PKCS#12 data and the 'private-key-password' "
							   "property must be set to password used to "
							   "decrypt the PKCS#12 certificate and key.  When "
							   "using PKCS#12 files and the path scheme, this "
							   "property should be set to the full UTF-8 encoded "
							   "path of the key, prefixed with the string "
							   "'file://' and and ending with a terminating NULL "
							   "byte, and as with the blob scheme the "
							   "'private-key-password' property must be set to "
							   "the password used to decode the PKCS#12 private "
							   "key and certificate.",
							   DBUS_TYPE_G_UCHAR_ARRAY,
							   G_PARAM_READWRITE));

	/**
	 * NMSetting8021x:private-key-password:
	 *
	 * The password used to decrypt the private key specified in the
	 * #NMSetting8021x:private-key property when the private key either uses the
	 * path scheme, or if the private key is a PKCS#12 format key.  Setting this
	 * property directly is not generally necessary except when returning
	 * secrets to NetworkManager; it is generally set automatically when setting
	 * the private key by the nm_setting_802_1x_set_private_key() function.
	 **/
	g_object_class_install_property
		(object_class, PROP_PRIVATE_KEY_PASSWORD,
		 g_param_spec_string (NM_SETTING_802_1X_PRIVATE_KEY_PASSWORD,
						  "Private key password",
						  "The password used to decrypt the private key "
						  "specified in the 'private-key' property when the "
						  "private key either uses the path scheme, or if the "
						  "private key is a PKCS#12 format key.",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SECRET));

	/**
	 * NMSetting8021x:private-key-password-flags:
	 *
	 * Flags indicating how to handle the #NMSetting8021x:private-key-password
	 * property.
	 **/
	g_object_class_install_property (object_class, PROP_PRIVATE_KEY_PASSWORD_FLAGS,
		 g_param_spec_uint (NM_SETTING_802_1X_PRIVATE_KEY_PASSWORD_FLAGS,
		                    "Private Key Password Flags",
		                    "Flags indicating how to handle the 802.1x private "
		                    "key password.",
		                    NM_SETTING_SECRET_FLAG_NONE,
		                    NM_SETTING_SECRET_FLAGS_ALL,
		                    NM_SETTING_SECRET_FLAG_NONE,
		                    G_PARAM_READWRITE));

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
	 * with a terminating NUL byte. When using PKCS#12 format private keys and
	 * the blob scheme, this property should be set to the PKCS#12 data and the
	 * #NMSetting8021x:phase2-private-key-password property must be set to
	 * password used to decrypt the PKCS#12 certificate and key. When using
	 * PKCS#12 files and the path scheme, this property should be set to the
	 * full UTF-8 encoded path of the key, prefixed with the string "file://"
	 * and and ending with a terminating NUL byte, and as with the blob scheme
	 * the #NMSetting8021x:phase2-private-key-password property must be set to
	 * the password used to decode the PKCS#12 private key and certificate.
	 *
	 * Setting this property directly is discouraged; use the
	 * nm_setting_802_1x_set_phase2_private_key() function instead.
	 **/
	g_object_class_install_property
		(object_class, PROP_PHASE2_PRIVATE_KEY,
		 _nm_param_spec_specialized (NM_SETTING_802_1X_PHASE2_PRIVATE_KEY,
							   "Phase2 private key",
							   "Contains the 'phase 2' inner private key when "
							   "the 'phase2-auth' or 'phase2-autheap' property "
							   "is set to 'tls'.  Key data is specified using a "
							   "'scheme'; two are currently supported: blob and "
							   "path. When using the blob scheme and private "
							   "keys, this property should be set to the key's "
							   "encrypted PEM encoded data. When using private "
							   "keys with the path scheme, this property should "
							   "be set to the full UTF-8 encoded path of the key, "
							   "prefixed with the string 'file://' and ending "
							   "with a terminating NULL byte.  When using "
							   "PKCS#12 format private keys and the blob "
							   "scheme, this property should be set to the "
							   "PKCS#12 data and the 'phase2-private-key-password' "
							   "property must be set to password used to "
							   "decrypt the PKCS#12 certificate and key.  When "
							   "using PKCS#12 files and the path scheme, this "
							   "property should be set to the full UTF-8 encoded "
							   "path of the key, prefixed with the string "
							   "'file://' and and ending with a terminating NULL "
							   "byte, and as with the blob scheme the "
							   "'phase2-private-key-password' property must be "
							   "set to the password used to decode the PKCS#12 "
							   "private key and certificate.",
							   DBUS_TYPE_G_UCHAR_ARRAY,
							   G_PARAM_READWRITE));

	/**
	 * NMSetting8021x:phase2-private-key-password:
	 *
	 * The password used to decrypt the "phase 2" private key specified in the
	 * #NMSetting8021x:phase2-private-key property when the private key either
	 * uses the path scheme, or is a PKCS#12 format key.  Setting this property
	 * directly is not generally necessary except when returning secrets to
	 * NetworkManager; it is generally set automatically when setting the
	 * private key by the nm_setting_802_1x_set_phase2_private_key() function.
	 **/
	g_object_class_install_property
		(object_class, PROP_PHASE2_PRIVATE_KEY_PASSWORD,
		 g_param_spec_string (NM_SETTING_802_1X_PHASE2_PRIVATE_KEY_PASSWORD,
						  "Phase2 private key password",
						  "The password used to decrypt the 'phase 2' private "
						  "key specified in the 'private-key' property when the "
						  "phase2 private key either uses the path scheme, or "
						  "if the phase2 private key is a PKCS#12 format key.",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SECRET));

	/**
	 * NMSetting8021x:phase2-private-key-password-flags:
	 *
	 * Flags indicating how to handle the
	 * #NMSetting8021x:phase2-private-key-password property.
	 **/
	g_object_class_install_property (object_class, PROP_PHASE2_PRIVATE_KEY_PASSWORD_FLAGS,
		 g_param_spec_uint (NM_SETTING_802_1X_PHASE2_PRIVATE_KEY_PASSWORD_FLAGS,
		                    "Phase2 Private Key Password Flags",
		                    "Flags indicating how to handle the 802.1x phase2 "
		                    "private key password.",
		                    NM_SETTING_SECRET_FLAG_NONE,
		                    NM_SETTING_SECRET_FLAGS_ALL,
		                    NM_SETTING_SECRET_FLAG_NONE,
		                    G_PARAM_READWRITE));

	/**
	 * NMSetting8021x:pin:
	 *
	 * PIN used for EAP authentication methods.
	 **/
	g_object_class_install_property
		(object_class, PROP_PIN,
		 g_param_spec_string (NM_SETTING_802_1X_PIN,
		                      "PIN",
		                      "PIN used for EAP authentication methods.",
		                      NULL,
		                      G_PARAM_READWRITE | NM_SETTING_PARAM_SECRET));

	/**
	 * NMSetting8021x:pin-flags:
	 *
	 * Flags indicating how to handle the #NMSetting8021x:pin property.
	 **/
	g_object_class_install_property (object_class, PROP_PIN_FLAGS,
		 g_param_spec_uint (NM_SETTING_802_1X_PIN_FLAGS,
		                    "PIN Flags",
		                    "Flags indicating how to handle the 802.1x PIN.",
		                    NM_SETTING_SECRET_FLAG_NONE,
		                    NM_SETTING_SECRET_FLAGS_ALL,
		                    NM_SETTING_SECRET_FLAG_NONE,
		                    G_PARAM_READWRITE));

	/**
	 * NMSetting8021x:system-ca-certs:
	 *
	 * When %TRUE, overrides the #NMSetting8021x:ca-path and
	 * #NMSetting8021x:phase2-ca-path properties using the system CA directory
	 * specified at configure time with the --system-ca-path switch.  The
	 * certificates in this directory are added to the verification chain in
	 * addition to any certificates specified by the #NMSetting8021x:ca-cert and
	 * #NMSetting8021x:phase2-ca-cert properties.
	 **/
	g_object_class_install_property
		(object_class, PROP_SYSTEM_CA_CERTS,
		 g_param_spec_boolean (NM_SETTING_802_1X_SYSTEM_CA_CERTS,
							   "Use system CA certificates",
							   "When TRUE, overrides 'ca-path' and 'phase2-ca-path' "
							   "properties using the system CA directory "
							   "specified at configure time with the "
							   "--system-ca-path switch.  The certificates in "
							   "this directory are added to the verification "
							   "chain in addition to any certificates specified "
							   "by the 'ca-cert' and 'phase2-ca-cert' properties.",
							   FALSE,
							   G_PARAM_READWRITE | G_PARAM_CONSTRUCT));

	/* Initialize crypto lbrary. */
	if (!nm_utils_init (&error)) {
		g_warning ("Couldn't initilize nm-utils/crypto system: %d %s",
		           error->code, error->message);
		g_error_free (error);
	}

}
