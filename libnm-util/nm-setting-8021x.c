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

#include <string.h>
#include <ctype.h>
#include <dbus/dbus-glib.h>
#include "nm-setting-8021x.h"
#include "nm-param-spec-specialized.h"
#include "nm-utils.h"
#include "nm-dbus-glib-types.h"
#include "crypto.h"
#include "nm-utils-private.h"

/**
 * SECTION:nm-setting-8021x
 * @short_description: Describes 802.1x-authenticated connection properties
 * @include: nm-setting-8021x.h
 *
 * The #NMSetting8021x object is a #NMSetting subclass that describes
 * properties necessary for connection to 802.1x-authenticated networks, such as
 * WPA and WPA2 Enterprise WiFi networks and wired 802.1x networks.  802.1x
 * connections typically use certificates and/or EAP authentication methods to
 * securely verify, identify, and authenticate the client to the network itself,
 * instead of simply relying on a widely shared static key.
 *
 * It's a good idea to read up on wpa_supplicant configuration before using this
 * setting extensively, since most of the options here correspond closely with
 * the relevant wpa_supplicant configuration options.
 *
 * Furthermore, to get a good idea of 802.1x, EAP, TLS, TTLS, etc and their
 * applications to WiFi and wired networks, you'll want to get copies of the
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

/* This should really be standard. */
#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

GType
nm_setting_802_1x_error_get_type (void)
{
	static GType etype = 0;

	if (etype == 0) {
		static const GEnumValue values[] = {
			/* Unknown error. */
			ENUM_ENTRY (NM_SETTING_802_1X_ERROR_UNKNOWN, "UnknownError"),
			/* The specified property was invalid. */
			ENUM_ENTRY (NM_SETTING_802_1X_ERROR_INVALID_PROPERTY, "InvalidProperty"),
			/* The specified property was missing and is required. */
			ENUM_ENTRY (NM_SETTING_802_1X_ERROR_MISSING_PROPERTY, "MissingProperty"),
			{ 0, 0, 0 }
		};
		etype = g_enum_register_static ("NMSetting8021xError", values);
	}
	return etype;
}


G_DEFINE_TYPE (NMSetting8021x, nm_setting_802_1x, NM_TYPE_SETTING)

#define NM_SETTING_802_1X_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_802_1X, NMSetting8021xPrivate))

typedef struct {
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
	char *private_key_password;
	GByteArray *phase2_private_key;
	char *phase2_private_key_password;
	gboolean system_ca_certs;
} NMSetting8021xPrivate;

enum {
	PROP_0,
	PROP_EAP,
	PROP_IDENTITY,
	PROP_ANONYMOUS_IDENTITY,
	PROP_CA_CERT,
	PROP_CA_PATH,
	PROP_CLIENT_CERT,
	PROP_PHASE1_PEAPVER,
	PROP_PHASE1_PEAPLABEL,
	PROP_PHASE1_FAST_PROVISIONING,
	PROP_PHASE2_AUTH,
	PROP_PHASE2_AUTHEAP,
	PROP_PHASE2_CA_CERT,
	PROP_PHASE2_CA_PATH,
	PROP_PHASE2_CLIENT_CERT,
	PROP_PASSWORD,
	PROP_PRIVATE_KEY,
	PROP_PRIVATE_KEY_PASSWORD,
	PROP_PHASE2_PRIVATE_KEY,
	PROP_PHASE2_PRIVATE_KEY_PASSWORD,
	PROP_PIN,
	PROP_PSK,
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
 * Returns: TRUE if the EAP method was successfully added, FALSE if it was
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
	nm_utils_slist_free (priv->eap, g_free);
	priv->eap = NULL;
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
 * TRUE, in which case a system-wide CA certificate directory specified at
 * compile time (using the --system-ca-path configure option) is used in place
 * of these properties. 
 *
 * Returns: TRUE if a system CA certificate path should be used, FALSE if not
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
 * nm_setting_802_1x_get_ca_cert:
 * @setting: the #NMSetting8021x
 *
 * Returns the CA certificate blob if the CA certificate is stored using the
 * %NM_SETTING_802_1X_CK_SCHEME_BLOB scheme.  Not all EAP methods use a
 * CA certificate (LEAP for example), and those that can take advantage of the
 * CA certificate allow it to be unset.  Note that lack of a CA certificate
 * reduces security by allowing man-in-the-middle attacks, because the identity
 * of the network cannot be confirmed by the client.
 *
 * Deprecated: 0.8: This function has been deprecated and should
 *   not be used in newly written code. Calling this function is
 *   equivalent to calling nm_setting_802_1x_get_ca_cert_blob().
 *
 * Returns: the CA certificate data
 **/
const GByteArray *
nm_setting_802_1x_get_ca_cert (NMSetting8021x *setting)
{
	return nm_setting_802_1x_get_ca_cert_blob (setting);
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

/**
 * nm_setting_802_1x_set_ca_cert:
 * @setting: the #NMSetting8021x
 * @value: when @scheme is set to either %NM_SETTING_802_1X_CK_SCHEME_PATH or
 *   %NM_SETTING_802_1X_CK_SCHEME_BLOB, pass the path of the CA certificate file
 *   (PEM or DER format).  The path must be UTF-8 encoded; use
 *   g_filename_to_utf8() to convert if needed.  Passing NULL with any @scheme
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
 * Returns: TRUE if the operation succeeded, FALSE if it was unsuccessful
 **/
gboolean
nm_setting_802_1x_set_ca_cert (NMSetting8021x *self,
                               const char *value,
                               NMSetting8021xCKScheme scheme,
                               NMSetting8021xCKFormat *out_format,
                               GError **error)
{
	NMSetting8021xPrivate *priv;
	NMCryptoFileFormat format = NM_CRYPTO_FILE_FORMAT_UNKNOWN;
	GByteArray *data;

	g_return_val_if_fail (NM_IS_SETTING_802_1X (self), FALSE);

	if (value) {
		g_return_val_if_fail (g_utf8_validate (value, -1, NULL), FALSE);
		g_return_val_if_fail (   scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB
		                      || scheme == NM_SETTING_802_1X_CK_SCHEME_PATH,
		                      FALSE);
	}

	if (out_format)
		g_return_val_if_fail (*out_format == NM_SETTING_802_1X_CK_FORMAT_UNKNOWN, FALSE);

	priv = NM_SETTING_802_1X_GET_PRIVATE (self);

	/* Clear out any previous ca_cert blob */
	if (priv->ca_cert) {
		g_byte_array_free (priv->ca_cert, TRUE);
		priv->ca_cert = NULL;
	}

	if (!value)
		return TRUE;

	data = crypto_load_and_verify_certificate (value, &format, error);
	if (data) {
		/* wpa_supplicant can only use raw x509 CA certs */
		switch (format) {
		case NM_CRYPTO_FILE_FORMAT_X509:
			if (out_format)
				*out_format = NM_SETTING_802_1X_CK_FORMAT_X509;
			break;
		default:
			g_byte_array_free (data, TRUE);
			data = NULL;
			g_set_error (error,
			             NM_SETTING_802_1X_ERROR,
			             NM_SETTING_802_1X_ERROR_INVALID_PROPERTY,
			             NM_SETTING_802_1X_CA_CERT);
			break;
		}

		if (data) {
			if (scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB)
				priv->ca_cert = data;
			else if (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH) {
				/* Add the path scheme tag to the front, then the fielname */
				priv->ca_cert = g_byte_array_sized_new (strlen (value) + strlen (SCHEME_PATH) + 1);
				g_byte_array_append (priv->ca_cert, (const guint8 *) SCHEME_PATH, strlen (SCHEME_PATH));
				g_byte_array_append (priv->ca_cert, (const guint8 *) value, strlen (value));
				g_byte_array_append (priv->ca_cert, (const guint8 *) "\0", 1);
			} else
				g_assert_not_reached ();
		}
	}

	return priv->ca_cert != NULL;
}

static NMSetting8021xCKType
ck_format_to_type (NMSetting8021xCKFormat format)
{
	switch (format) {
	case NM_SETTING_802_1X_CK_FORMAT_X509:
		return NM_SETTING_802_1X_CK_TYPE_X509;
	case NM_SETTING_802_1X_CK_FORMAT_RAW_KEY:
		return NM_SETTING_802_1X_CK_TYPE_RAW_KEY;
	case NM_SETTING_802_1X_CK_FORMAT_PKCS12:
		return NM_SETTING_802_1X_CK_TYPE_PKCS12;
	default:
		break;
	}
	return NM_SETTING_802_1X_CK_TYPE_UNKNOWN;
}

/**
 * nm_setting_802_1x_set_ca_cert_from_file:
 * @setting: the #NMSetting8021x
 * @filename: the path of the CA certificate file (PEM or DER format). Passing
 *   NULL clears the CA certificate.
 * @out_ck_type: on successful return, the type of the certificate added
 * @error: on unsuccessful return, an error
 *
 * Reads a certificate from disk and sets the #NMSetting8021x:ca-cert property
 * with the raw certificate data using the %NM_SETTING_802_1X_CK_SCHEME_BLOB
 * scheme.
 *
 * Deprecated: 0.8: This function has been deprecated and should
 *   not be used in newly written code. Calling this function is
 *   equivalent to calling nm_setting_802_1x_set_ca_cert() with the
 *   %NM_SETTING_802_1X_CK_SCHEME_BLOB scheme.
 *
 * Returns: TRUE if the operation succeeded, FALSE if it was unsuccessful
 **/
gboolean
nm_setting_802_1x_set_ca_cert_from_file (NMSetting8021x *setting,
                                         const char *filename,
                                         NMSetting8021xCKType *out_ck_type,
                                         GError **error)
{
	gboolean success;
	NMSetting8021xCKFormat format = NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;

	success = nm_setting_802_1x_set_ca_cert (setting,
	                                         filename,
	                                         NM_SETTING_802_1X_CK_SCHEME_BLOB,
	                                         &format,
	                                         error);
	if (success && out_ck_type)
		*out_ck_type = ck_format_to_type (format);

	return success;
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
 * nm_setting_802_1x_get_client_cert:
 * @setting: the #NMSetting8021x
 *
 * Client certificates are used to identify the connecting client to the network
 * when EAP-TLS is used as either the "phase 1" or "phase 2" 802.1x
 * authentication method.
 *
 * Deprecated: 0.8: This function has been deprecated and should
 *   not be used in newly written code. Calling this function is
 *   equivalent to calling nm_setting_802_1x_get_client_cert_blob().
 *
 * Returns: the client certificate data
 **/
const GByteArray *
nm_setting_802_1x_get_client_cert (NMSetting8021x *setting)
{
	return nm_setting_802_1x_get_client_cert_blob (setting);
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
 * @value: when @scheme is set to either %NM_SETTING_802_1X_CK_SCHEME_PATH or
 *   %NM_SETTING_802_1X_CK_SCHEME_BLOB, pass the path of the client certificate
 *   file (PEM, DER, or PKCS#12 format).  The path must be UTF-8 encoded; use
 *   g_filename_to_utf8() to convert if needed.  Passing NULL with any @scheme
 *   clears the client certificate.
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
 * Returns: TRUE if the operation succeeded, FALSE if it was unsuccessful
 **/
gboolean
nm_setting_802_1x_set_client_cert (NMSetting8021x *self,
                                   const char *value,
                                   NMSetting8021xCKScheme scheme,
                                   NMSetting8021xCKFormat *out_format,
                                   GError **error)
{
	NMSetting8021xPrivate *priv;
	NMCryptoFileFormat format = NM_CRYPTO_FILE_FORMAT_UNKNOWN;
	GByteArray *data;

	g_return_val_if_fail (NM_IS_SETTING_802_1X (self), FALSE);

	if (value) {
		g_return_val_if_fail (g_utf8_validate (value, -1, NULL), FALSE);
		g_return_val_if_fail (   scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB
		                      || scheme == NM_SETTING_802_1X_CK_SCHEME_PATH,
		                      FALSE);
	}

	if (out_format)
		g_return_val_if_fail (*out_format == NM_SETTING_802_1X_CK_FORMAT_UNKNOWN, FALSE);

	priv = NM_SETTING_802_1X_GET_PRIVATE (self);

	/* Clear out any previous ca_cert blob */
	if (priv->client_cert) {
		g_byte_array_free (priv->client_cert, TRUE);
		priv->client_cert = NULL;
	}

	if (!value)
		return TRUE;

	data = crypto_load_and_verify_certificate (value, &format, error);
	if (data) {
		/* wpa_supplicant can only use raw x509 CA certs */
		switch (format) {
		case NM_CRYPTO_FILE_FORMAT_X509:
			if (out_format)
				*out_format = NM_SETTING_802_1X_CK_FORMAT_X509;
			break;
		case NM_CRYPTO_FILE_FORMAT_PKCS12:
			if (out_format)
				*out_format = NM_SETTING_802_1X_CK_FORMAT_PKCS12;
			break;
		default:
			g_byte_array_free (data, TRUE);
			data = NULL;
			g_set_error (error,
			             NM_SETTING_802_1X_ERROR,
			             NM_SETTING_802_1X_ERROR_INVALID_PROPERTY,
			             NM_SETTING_802_1X_CLIENT_CERT);
			break;
		}

		if (data) {
			if (scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB)
				priv->client_cert = data;
			else if (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH) {
				/* Add the path scheme tag to the front, then the fielname */
				priv->client_cert = g_byte_array_sized_new (strlen (value) + strlen (SCHEME_PATH) + 1);
				g_byte_array_append (priv->client_cert, (const guint8 *) SCHEME_PATH, strlen (SCHEME_PATH));
				g_byte_array_append (priv->client_cert, (const guint8 *) value, strlen (value));
				g_byte_array_append (priv->client_cert, (const guint8 *) "\0", 1);
			} else
				g_assert_not_reached ();
		}
	}

	return priv->client_cert != NULL;
}

/**
 * nm_setting_802_1x_set_client_cert_from_file:
 * @setting: the #NMSetting8021x
 * @filename: the path of the client certificate file (PEM, DER, or
 *   PKCS#12 format).  Passing NULL clears the client certificate.
 * @out_ck_type: on successful return, the type of the certificate added
 * @error: on unsuccessful return, an error
 *
 * Reads a certificate from disk and sets the #NMSetting8021x:client-cert
 * property with the raw certificate data.
 *
 * Client certificates are used to identify the connecting client to the network
 * when EAP-TLS is used as either the "phase 1" or "phase 2" 802.1x
 * authentication method.
 *
 * Deprecated: 0.8: This function has been deprecated and should
 *   not be used in newly written code. Calling this function is
 *   equivalent to calling nm_setting_802_1x_set_client_cert() with the
 *   %NM_SETTING_802_1X_CK_SCHEME_BLOB scheme.
 *
 * Returns: TRUE if the operation succeeded, FALSE if it was unsuccessful
 **/
gboolean
nm_setting_802_1x_set_client_cert_from_file (NMSetting8021x *setting,
                                             const char *filename,
                                             NMSetting8021xCKType *out_ck_type,
                                             GError **error)
{
	gboolean success;
	NMSetting8021xCKFormat format = NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;

	success = nm_setting_802_1x_set_client_cert (setting,
	                                             filename,
	                                             NM_SETTING_802_1X_CK_SCHEME_BLOB,
	                                             &format,
	                                             error);
	if (success && out_ck_type)
		*out_ck_type = ck_format_to_type (format);

	return success;
}

/**
 * nm_setting_802_1x_get_phase1_peapver:
 * @setting: the #NMSetting8021x
 *
 * Returns: the "phase 1" PEAP version to be used when authenticating with
 *  EAP-PEAP as contained in the #NMSetting8021x:phase1-peapver property.  Valid
 *  values are NULL (unset), "0" (PEAP version 0), and "1" (PEAP version 1).
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
 *  #NMSetting8021x:phase1-peaplabel property.  Valid values are NULL (unset),
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
 * nm_setting_802_1x_get_phase2_ca_cert:
 * @setting: the #NMSetting8021x
 *
 * Returns the "phase 2" CA certificate blob.  Not all EAP methods use
 * a CA certificate (LEAP for example), and those that can take advantage of the
 * CA certificate allow it to be unset.  Note that lack of a CA certificate
 * reduces security by allowing man-in-the-middle attacks, because the identity
 * of the network cannot be confirmed by the client.
 *
 * Deprecated: 0.8: This function has been deprecated and should
 *   not be used in newly written code. Calling this function is
 *   equivalent to calling nm_setting_802_1x_get_phase2_ca_cert_blob().
 *
 * Returns: the "phase 2" CA certificate data
 **/
const GByteArray *
nm_setting_802_1x_get_phase2_ca_cert (NMSetting8021x *setting)
{
	return nm_setting_802_1x_get_phase2_ca_cert_blob (setting);
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
 * @value: when @scheme is set to either %NM_SETTING_802_1X_CK_SCHEME_PATH or
 *   %NM_SETTING_802_1X_CK_SCHEME_BLOB, pass the path of the "phase2" CA
 *   certificate file (PEM or DER format).  The path must be UTF-8 encoded; use
 *   g_filename_to_utf8() to convert if needed.  Passing NULL with any @scheme
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
 * Returns: TRUE if the operation succeeded, FALSE if it was unsuccessful
 **/
gboolean
nm_setting_802_1x_set_phase2_ca_cert (NMSetting8021x *self,
                                      const char *value,
                                      NMSetting8021xCKScheme scheme,
                                      NMSetting8021xCKFormat *out_format,
                                      GError **error)
{
	NMSetting8021xPrivate *priv;
	NMCryptoFileFormat format = NM_CRYPTO_FILE_FORMAT_UNKNOWN;
	GByteArray *data;

	g_return_val_if_fail (NM_IS_SETTING_802_1X (self), FALSE);

	if (value) {
		g_return_val_if_fail (g_utf8_validate (value, -1, NULL), FALSE);
		g_return_val_if_fail (   scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB
		                      || scheme == NM_SETTING_802_1X_CK_SCHEME_PATH,
		                      FALSE);
	}

	if (out_format)
		g_return_val_if_fail (*out_format == NM_SETTING_802_1X_CK_FORMAT_UNKNOWN, FALSE);

	priv = NM_SETTING_802_1X_GET_PRIVATE (self);

	/* Clear out any previous ca_cert blob */
	if (priv->phase2_ca_cert) {
		g_byte_array_free (priv->phase2_ca_cert, TRUE);
		priv->phase2_ca_cert = NULL;
	}

	if (!value)
		return TRUE;

	data = crypto_load_and_verify_certificate (value, &format, error);
	if (data) {
		/* wpa_supplicant can only use raw x509 CA certs */
		switch (format) {
		case NM_CRYPTO_FILE_FORMAT_X509:
			if (out_format)
				*out_format = NM_SETTING_802_1X_CK_FORMAT_X509;
			break;
		default:
			g_byte_array_free (data, TRUE);
			data = NULL;
			g_set_error (error,
			             NM_SETTING_802_1X_ERROR,
			             NM_SETTING_802_1X_ERROR_INVALID_PROPERTY,
			             NM_SETTING_802_1X_PHASE2_CA_CERT);
			break;
		}

		if (data) {
			if (scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB)
				priv->phase2_ca_cert = data;
			else if (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH) {
				/* Add the path scheme tag to the front, then the fielname */
				priv->phase2_ca_cert = g_byte_array_sized_new (strlen (value) + strlen (SCHEME_PATH) + 1);
				g_byte_array_append (priv->phase2_ca_cert, (const guint8 *) SCHEME_PATH, strlen (SCHEME_PATH));
				g_byte_array_append (priv->phase2_ca_cert, (const guint8 *) value, strlen (value));
				g_byte_array_append (priv->phase2_ca_cert, (const guint8 *) "\0", 1);
			} else
				g_assert_not_reached ();
		}
	}

	return priv->phase2_ca_cert != NULL;
}

/**
 * nm_setting_802_1x_set_phase2_ca_cert_from_file:
 * @setting: the #NMSetting8021x
 * @filename: the path of the "phase2" CA certificate file (PEM or DER format).
 *   Passing NULL with any @scheme clears the "phase2" CA certificate.
 * @out_ck_type: on successful return, the type of the certificate added
 * @error: on unsuccessful return, an error
 *
 * Reads a certificate from disk and sets the #NMSetting8021x:phase2-ca-cert
 * property with the raw certificate data.
 *
 * Deprecated: 0.8: This function has been deprecated and should
 *   not be used in newly written code. Calling this function is
 *   equivalent to calling nm_setting_802_1x_set_phase2_ca_cert().
 *   with the %NM_SETTING_802_1X_CK_SCHEME_BLOB scheme.
 *
 * Returns: TRUE if the operation succeeded, FALSE if it was unsuccessful
 **/
gboolean
nm_setting_802_1x_set_phase2_ca_cert_from_file (NMSetting8021x *setting,
                                                const char *filename,
                                                NMSetting8021xCKType *out_ck_type,
                                                GError **error)
{
	gboolean success;
	NMSetting8021xCKFormat format = NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;

	success = nm_setting_802_1x_set_phase2_ca_cert (setting,
	                                                filename,
	                                                NM_SETTING_802_1X_CK_SCHEME_BLOB,
	                                                &format,
	                                                error);
	if (success && out_ck_type)
		*out_ck_type = ck_format_to_type (format);

	return success;
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
 * nm_setting_802_1x_get_phase2_client_cert:
 * @setting: the #NMSetting8021x
 *
 * Client certificates are used to identify the connecting client to the network
 * when EAP-TLS is used as either the "phase 1" or "phase 2" 802.1x
 * authentication method.
 *
 * Deprecated: 0.8: This function has been deprecated and should
 *   not be used in newly written code. Calling this function is
 *   equivalent to calling nm_setting_802_1x_get_phase2_client_cert_blob().
 *
 * Returns: the "phase 2" client certificate data
 **/
const GByteArray *
nm_setting_802_1x_get_phase2_client_cert (NMSetting8021x *setting)
{
	return nm_setting_802_1x_get_phase2_client_cert_blob (setting);
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
 * @value: when @scheme is set to either %NM_SETTING_802_1X_CK_SCHEME_PATH or
 *   %NM_SETTING_802_1X_CK_SCHEME_BLOB, pass the path of the "phase2" client
 *   certificate file (PEM, DER, or PKCS#12 format).  The path must be UTF-8
 *   encoded; use g_filename_to_utf8() to convert if needed.  Passing NULL with
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
 * Returns: TRUE if the operation succeeded, FALSE if it was unsuccessful
 **/
gboolean
nm_setting_802_1x_set_phase2_client_cert (NMSetting8021x *self,
                                          const char *value,
                                          NMSetting8021xCKScheme scheme,
                                          NMSetting8021xCKFormat *out_format,
                                          GError **error)
{
	NMSetting8021xPrivate *priv;
	NMCryptoFileFormat format = NM_CRYPTO_FILE_FORMAT_UNKNOWN;
	GByteArray *data;

	g_return_val_if_fail (NM_IS_SETTING_802_1X (self), FALSE);

	if (value) {
		g_return_val_if_fail (g_utf8_validate (value, -1, NULL), FALSE);
		g_return_val_if_fail (   scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB
		                      || scheme == NM_SETTING_802_1X_CK_SCHEME_PATH,
		                      FALSE);
	}

	if (out_format)
		g_return_val_if_fail (*out_format == NM_SETTING_802_1X_CK_FORMAT_UNKNOWN, FALSE);

	priv = NM_SETTING_802_1X_GET_PRIVATE (self);

	/* Clear out any previous ca_cert blob */
	if (priv->phase2_client_cert) {
		g_byte_array_free (priv->phase2_client_cert, TRUE);
		priv->phase2_client_cert = NULL;
	}

	if (!value)
		return TRUE;

	data = crypto_load_and_verify_certificate (value, &format, error);
	if (data) {
		/* wpa_supplicant can only use raw x509 CA certs */
		switch (format) {
		case NM_CRYPTO_FILE_FORMAT_X509:
			if (out_format)
				*out_format = NM_SETTING_802_1X_CK_FORMAT_X509;
			break;
		case NM_CRYPTO_FILE_FORMAT_PKCS12:
			if (out_format)
				*out_format = NM_SETTING_802_1X_CK_FORMAT_PKCS12;
			break;
		default:
			g_byte_array_free (data, TRUE);
			data = NULL;
			g_set_error (error,
			             NM_SETTING_802_1X_ERROR,
			             NM_SETTING_802_1X_ERROR_INVALID_PROPERTY,
			             NM_SETTING_802_1X_PHASE2_CLIENT_CERT);
			break;
		}

		if (data) {
			if (scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB)
				priv->phase2_client_cert = data;
			else if (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH) {
				/* Add the path scheme tag to the front, then the fielname */
				priv->phase2_client_cert = g_byte_array_sized_new (strlen (value) + strlen (SCHEME_PATH) + 1);
				g_byte_array_append (priv->phase2_client_cert, (const guint8 *) SCHEME_PATH, strlen (SCHEME_PATH));
				g_byte_array_append (priv->phase2_client_cert, (const guint8 *) value, strlen (value));
				g_byte_array_append (priv->phase2_client_cert, (const guint8 *) "\0", 1);
			} else
				g_assert_not_reached ();
		}
	}

	return priv->phase2_client_cert != NULL;
}

/**
 * nm_setting_802_1x_set_phase2_client_cert_from_file:
 * @setting: the #NMSetting8021x
 * @filename: pass the path of the "phase2" client certificate file (PEM, DER,
 *   or PKCS#12 format).  Passing NULL clears the "phase2" client certificate.
 * @out_ck_type: on successful return, the type of the certificate added
 * @error: on unsuccessful return, an error
 *
 * Reads a certificate from disk and sets the #NMSetting8021x:phase2-client-cert
 * property with the raw certificate data.
 *
 * Client certificates are used to identify the connecting client to the network
 * when EAP-TLS is used as either the "phase 1" or "phase 2" 802.1x
 * authentication method.
 *
 * Deprecated: 0.8: This function has been deprecated and should
 *   not be used in newly written code. Calling this function is
 *   equivalent to calling nm_setting_802_1x_set_phase2_client_cert() with the.
 *   %NM_SETTING_802_1X_CK_SCHEME_BLOB scheme.
 *
 * Returns: TRUE if the operation succeeded, FALSE if it was unsuccessful
 **/
gboolean
nm_setting_802_1x_set_phase2_client_cert_from_file (NMSetting8021x *setting,
                                                    const char *filename,
                                                    NMSetting8021xCKType *out_ck_type,
                                                    GError **error)
{
	gboolean success;
	NMSetting8021xCKFormat format = NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;

	success = nm_setting_802_1x_set_phase2_client_cert (setting,
	                                                    filename,
	                                                    NM_SETTING_802_1X_CK_SCHEME_BLOB,
	                                                    &format,
	                                                    error);
	if (success && out_ck_type)
		*out_ck_type = ck_format_to_type (format);

	return success;
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
 * nm_setting_802_1x_get_psk:
 * @setting: the #NMSetting8021x
 *
 * Returns: the Pre-Shared-Key used by the authentication method, if any, as
 *   specified by the #NMSetting8021x:psk property
 **/
const char *
nm_setting_802_1x_get_psk (NMSetting8021x *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NULL);

	return NM_SETTING_802_1X_GET_PRIVATE (setting)->psk;
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
 * nm_setting_802_1x_get_private_key:
 * @setting: the #NMSetting8021x
 *
 * Private keys are used to authenticate the connecting client to the network
 * when EAP-TLS is used as either the "phase 1" or "phase 2" 802.1x
 * authentication method.
 *
 * Deprecated: 0.8: This function has been deprecated and should
 *   not be used in newly written code. Calling this function is
 *   equivalent to calling nm_setting_802_1x_get_private_key_blob().
 *
 * Returns: the private key data
 **/
const GByteArray *
nm_setting_802_1x_get_private_key (NMSetting8021x *setting)
{
	return nm_setting_802_1x_get_private_key_blob (setting);
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

/**
 * nm_setting_802_1x_set_private_key:
 * @setting: the #NMSetting8021x
 * @value: when @scheme is set to either %NM_SETTING_802_1X_CK_SCHEME_PATH or
 *   %NM_SETTING_802_1X_CK_SCHEME_BLOB, pass the path of the private key file
 *   (PEM, DER, or PKCS#12 format).  The path must be UTF-8 encoded; use
 *   g_filename_to_utf8() to convert if needed.  Passing NULL with any @scheme
 *   clears the private key.
 * @password: password used to decrypt the private key
 * @scheme: desired storage scheme for the private key
 * @out_format: on successful return, the type of the private key added
 * @error: on unsuccessful return, an error
 *
 * Reads a private key from disk and sets the #NMSetting8021x:private-key
 * property with the raw private key data if using the
 * %NM_SETTING_802_1X_CK_SCHEME_BLOB scheme, or with the path to the private key
 * file if using the %NM_SETTING_802_1X_CK_SCHEME_PATH scheme.
 *
 * Private keys are used to authenticate the connecting client to the network
 * when EAP-TLS is used as either the "phase 1" or "phase 2" 802.1x
 * authentication method.
 *
 * Returns: TRUE if the operation succeeded, FALSE if it was unsuccessful
 **/
gboolean
nm_setting_802_1x_set_private_key (NMSetting8021x *self,
                                   const char *value,
                                   const char *password,
                                   NMSetting8021xCKScheme scheme,
                                   NMSetting8021xCKFormat *out_format,
                                   GError **error)
{
	NMSetting8021xPrivate *priv;
	NMCryptoFileFormat format = NM_CRYPTO_FILE_FORMAT_UNKNOWN;
	NMCryptoKeyType key_type = NM_CRYPTO_KEY_TYPE_UNKNOWN;
	GByteArray *data;

	g_return_val_if_fail (NM_IS_SETTING_802_1X (self), FALSE);

	if (value) {
		g_return_val_if_fail (g_utf8_validate (value, -1, NULL), FALSE);
		g_return_val_if_fail (   scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB
		                      || scheme == NM_SETTING_802_1X_CK_SCHEME_PATH,
		                      FALSE);
	}

	if (out_format)
		g_return_val_if_fail (*out_format == NM_SETTING_802_1X_CK_FORMAT_UNKNOWN, FALSE);

	priv = NM_SETTING_802_1X_GET_PRIVATE (self);

	/* Clear out any previous private key blob */
	if (priv->private_key) {
		/* Try not to leave the private key around in memory */
		memset (priv->private_key, 0, priv->private_key->len);
		g_byte_array_free (priv->private_key, TRUE);
		priv->private_key = NULL;
	}

	g_free (priv->private_key_password);
	priv->private_key_password = NULL;

	if (!value)
		return TRUE;

	/* Verify the key and the private key password */
	data = crypto_get_private_key (value,
	                               password,
	                               &key_type,
	                               &format,
	                               error);
	if (!data) {
		/* As a special case for private keys, even if the decrypt fails,
		 * return the key's file type.
		 */
		if (out_format && crypto_is_pkcs12_file (value, NULL))
			*out_format = NM_SETTING_802_1X_CK_FORMAT_PKCS12;

		return FALSE;
	}

	switch (format) {
	case NM_CRYPTO_FILE_FORMAT_RAW_KEY:
		if (out_format)
			*out_format = NM_SETTING_802_1X_CK_FORMAT_RAW_KEY;
		break;
	case NM_CRYPTO_FILE_FORMAT_X509:
		if (out_format)
			*out_format = NM_SETTING_802_1X_CK_FORMAT_X509;
		break;
	case NM_CRYPTO_FILE_FORMAT_PKCS12:
		if (out_format)
			*out_format = NM_SETTING_802_1X_CK_FORMAT_PKCS12;
		break;
	default:
		memset (data->data, 0, data->len);
		g_byte_array_free (data, TRUE);
		g_set_error (error,
		             NM_SETTING_802_1X_ERROR,
		             NM_SETTING_802_1X_ERROR_INVALID_PROPERTY,
		             NM_SETTING_802_1X_PRIVATE_KEY);
		return FALSE;
	}

	g_assert (data);
	if (scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB) {
		priv->private_key = data;
		data = NULL;

		/* Always update the private key for blob + pkcs12 since the
		 * pkcs12 files are encrypted
		 */
		if (format == NM_CRYPTO_FILE_FORMAT_PKCS12)
			priv->private_key_password = g_strdup (password);
	} else if (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH) {
		/* Add the path scheme tag to the front, then the fielname */
		priv->private_key = g_byte_array_sized_new (strlen (value) + strlen (SCHEME_PATH) + 1);
		g_byte_array_append (priv->private_key, (const guint8 *) SCHEME_PATH, strlen (SCHEME_PATH));
		g_byte_array_append (priv->private_key, (const guint8 *) value, strlen (value));
		g_byte_array_append (priv->private_key, (const guint8 *) "\0", 1);

		/* Always update the private key with paths since the key the
		 * cert refers to is encrypted.
		 */
		priv->private_key_password = g_strdup (password);
	} else
		g_assert_not_reached ();

	/* Clear and free private key data if it's no longer needed */
	if (data) {
		memset (data->data, 0, data->len);
		g_byte_array_free (data, TRUE);
	}

	/* As required by NM and wpa_supplicant, set the client-cert
	 * property to the same PKCS#12 data.
	 */
	if (format == NM_CRYPTO_FILE_FORMAT_PKCS12) {
		if (priv->client_cert)
			g_byte_array_free (priv->client_cert, TRUE);

		priv->client_cert = g_byte_array_sized_new (priv->private_key->len);
		g_byte_array_append (priv->client_cert, priv->private_key->data, priv->private_key->len);
	}

	return priv->private_key != NULL;
}

/**
 * nm_setting_802_1x_set_private_key_from_file:
 * @setting: the #NMSetting8021x
 * @filename: the path of the private key file (PEM, DER, or PKCS#12 format).
 *   Passing NULL clears the private key.
 * @password: password used to decrypt the private key
 * @out_ck_type: on successful return, the type of the private key added
 * @error: on unsuccessful return, an error
 *
 * Reads a private key from disk and sets the #NMSetting8021x:private-key
 * property with the raw private key data.
 *
 * Private keys are used to authenticate the connecting client to the network
 * when EAP-TLS is used as either the "phase 1" or "phase 2" 802.1x
 * authentication method.
 *
 * Deprecated: 0.8: This function has been deprecated and should
 *   not be used in newly written code. Calling this function is
 *   equivalent to calling nm_setting_802_1x_set_private_key() with.
 *   the %NM_SETTING_802_1X_CK_SCHEME_BLOB scheme.
 *
 * Returns: TRUE if the operation succeeded, FALSE if it was unsuccessful
 **/
gboolean
nm_setting_802_1x_set_private_key_from_file (NMSetting8021x *setting,
                                             const char *filename,
                                             const char *password,
                                             NMSetting8021xCKType *out_ck_type,
                                             GError **error)
{
	gboolean success;
	NMSetting8021xCKFormat format = NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;

	success = nm_setting_802_1x_set_private_key (setting,
	                                             filename,
	                                             password,
	                                             NM_SETTING_802_1X_CK_SCHEME_BLOB,
	                                             &format,
	                                             error);
	if (success && out_ck_type)
		*out_ck_type = ck_format_to_type (format);

	return success;
}

/**
 * nm_setting_802_1x_get_private_key_password:
 * @setting: the #NMSetting8021x
 *
 * Returns: the private key password used to decrypt the private key if
 *  previously set with nm_setting_802_1x_set_private_key_from_file(),
 *  nm_setting_802_1x_set_private_key_path(), or the
 *  #NMSetting8021x:private-key-password property.
 **/
const char *
nm_setting_802_1x_get_private_key_password (NMSetting8021x *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NULL);

	return NM_SETTING_802_1X_GET_PRIVATE (setting)->private_key_password;
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
		return NM_SETTING_802_1X_CK_FORMAT_X509;
	case NM_SETTING_802_1X_CK_SCHEME_PATH:
		path = nm_setting_802_1x_get_private_key_path (setting);
		if (crypto_is_pkcs12_file (path, &error))
			return NM_SETTING_802_1X_CK_FORMAT_PKCS12;
		if (error) {
			/* Couldn't read the file or something */
			g_error_free (error);
			return NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;
		}
		return NM_SETTING_802_1X_CK_FORMAT_X509;
	default:
		break;
	}

	return NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;
}

/**
 * nm_setting_802_1x_get_private_key_type:
 * @setting: the #NMSetting8021x
 *
 * Deprecated: 0.8: This function has been deprecated and should
 *   not be used in newly written code. Calling this function is
 *   equivalent to calling nm_setting_802_1x_get_private_key_format().
 *
 * Returns: the data format of the private key data stored in the
 *   #NMSetting8021x:private-key property
 **/
NMSetting8021xCKType
nm_setting_802_1x_get_private_key_type (NMSetting8021x *setting)
{
	return ck_format_to_type (nm_setting_802_1x_get_private_key_format (setting));
}

/**
 * nm_setting_802_1x_get_phase2_private_key_password:
 * @setting: the #NMSetting8021x
 *
 * Returns: the private key password used to decrypt the private key if
 *  previously set with nm_setting_802_1x_set_phase2_private_key_from_file(),
 *  nm_setting_802_1x_set_phase2_private_key_path(), or the
 *  #NMSetting8021x:phase2-private-key-password property.
 **/
const char *
nm_setting_802_1x_get_phase2_private_key_password (NMSetting8021x *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), NULL);

	return NM_SETTING_802_1X_GET_PRIVATE (setting)->phase2_private_key_password;
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
 * nm_setting_802_1x_get_phase2_private_key:
 * @setting: the #NMSetting8021x
 *
 * Private keys are used to authenticate the connecting client to the network
 * when EAP-TLS is used as either the "phase 1" or "phase 2" 802.1x
 * authentication method.
 *
 * Deprecated: 0.8: This function has been deprecated and should
 *   not be used in newly written code. Calling this function is
 *   equivalent to calling nm_setting_802_1x_get_private_key_blob().
 *
 * Returns: the "phase 2" private key data
 **/
const GByteArray *
nm_setting_802_1x_get_phase2_private_key (NMSetting8021x *setting)
{
	return nm_setting_802_1x_get_phase2_private_key_blob (setting);
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
 * @value: when @scheme is set to either %NM_SETTING_802_1X_CK_SCHEME_PATH or
 *   %NM_SETTING_802_1X_CK_SCHEME_BLOB, pass the path of the "phase2" private 
 *   key file (PEM, DER, or PKCS#12 format).  The path must be UTF-8 encoded;
 *   use g_filename_to_utf8() to convert if needed.  Passing NULL with any
 *   @scheme clears the "phase2" private key.
 * @password: password used to decrypt the private key
 * @scheme: desired storage scheme for the private key
 * @out_format: on successful return, the type of the private key added
 * @error: on unsuccessful return, an error
 *
 * Reads a "phase 2" private key from disk and sets the
 * #NMSetting8021x:phase2-private-key property with the raw private key data if
 * using the %NM_SETTING_802_1X_CK_SCHEME_BLOB scheme, or with the path to the
 * private key file if using the %NM_SETTING_802_1X_CK_SCHEME_PATH scheme.
 *
 * Private keys are used to authenticate the connecting client to the network
 * when EAP-TLS is used as either the "phase 1" or "phase 2" 802.1x
 * authentication method.
 *
 * Returns: TRUE if the operation succeeded, FALSE if it was unsuccessful
 **/
gboolean
nm_setting_802_1x_set_phase2_private_key (NMSetting8021x *self,
                                          const char *value,
                                          const char *password,
                                          NMSetting8021xCKScheme scheme,
                                          NMSetting8021xCKFormat *out_format,
                                          GError **error)
{
	NMSetting8021xPrivate *priv;
	NMCryptoFileFormat format = NM_CRYPTO_FILE_FORMAT_UNKNOWN;
	NMCryptoKeyType key_type = NM_CRYPTO_KEY_TYPE_UNKNOWN;
	GByteArray *data;

	g_return_val_if_fail (NM_IS_SETTING_802_1X (self), FALSE);

	if (value) {
		g_return_val_if_fail (g_utf8_validate (value, -1, NULL), FALSE);
		g_return_val_if_fail (   scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB
		                      || scheme == NM_SETTING_802_1X_CK_SCHEME_PATH,
		                      FALSE);
	}

	if (out_format)
		g_return_val_if_fail (*out_format == NM_SETTING_802_1X_CK_FORMAT_UNKNOWN, FALSE);

	priv = NM_SETTING_802_1X_GET_PRIVATE (self);

	/* Clear out any previous private key blob */
	if (priv->phase2_private_key) {
		/* Try not to leave the private key around in memory */
		memset (priv->phase2_private_key, 0, priv->phase2_private_key->len);
		g_byte_array_free (priv->phase2_private_key, TRUE);
		priv->phase2_private_key = NULL;
	}

	g_free (priv->phase2_private_key_password);
	priv->phase2_private_key_password = NULL;

	if (!value)
		return TRUE;

	/* Verify the key and the private key password */
	data = crypto_get_private_key (value,
	                               password,
	                               &key_type,
	                               &format,
	                               error);
	if (!data) {
		/* As a special case for private keys, even if the decrypt fails,
		 * return the key's file type.
		 */
		if (out_format && crypto_is_pkcs12_file (value, NULL))
			*out_format = NM_SETTING_802_1X_CK_FORMAT_PKCS12;

		return FALSE;
	}

	switch (format) {
	case NM_CRYPTO_FILE_FORMAT_RAW_KEY:
		if (out_format)
			*out_format = NM_SETTING_802_1X_CK_FORMAT_RAW_KEY;
		break;
	case NM_CRYPTO_FILE_FORMAT_X509:
		if (out_format)
			*out_format = NM_SETTING_802_1X_CK_FORMAT_X509;
		break;
	case NM_CRYPTO_FILE_FORMAT_PKCS12:
		if (out_format)
			*out_format = NM_SETTING_802_1X_CK_FORMAT_PKCS12;
		break;
	default:
		memset (data->data, 0, data->len);
		g_byte_array_free (data, TRUE);
		g_set_error (error,
		             NM_SETTING_802_1X_ERROR,
		             NM_SETTING_802_1X_ERROR_INVALID_PROPERTY,
		             NM_SETTING_802_1X_PHASE2_PRIVATE_KEY);
		return FALSE;
	}

	g_assert (data);
	if (scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB) {
		priv->phase2_private_key = data;
		data = NULL;

		/* Always update the private key for blob + pkcs12 since the
		 * pkcs12 files are encrypted
		 */
		if (format == NM_CRYPTO_FILE_FORMAT_PKCS12)
			priv->phase2_private_key_password = g_strdup (password);
	} else if (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH) {
		/* Add the path scheme tag to the front, then the fielname */
		priv->phase2_private_key = g_byte_array_sized_new (strlen (value) + strlen (SCHEME_PATH) + 1);
		g_byte_array_append (priv->phase2_private_key, (const guint8 *) SCHEME_PATH, strlen (SCHEME_PATH));
		g_byte_array_append (priv->phase2_private_key, (const guint8 *) value, strlen (value));
		g_byte_array_append (priv->phase2_private_key, (const guint8 *) "\0", 1);

		/* Always update the private key with paths since the key the
		 * cert refers to is encrypted.
		 */
		priv->phase2_private_key_password = g_strdup (password);
	} else
		g_assert_not_reached ();

	/* Clear and free private key data if it's no longer needed */
	if (data) {
		memset (data->data, 0, data->len);
		g_byte_array_free (data, TRUE);
	}

	/* As required by NM and wpa_supplicant, set the client-cert
	 * property to the same PKCS#12 data.
	 */
	if (format == NM_CRYPTO_FILE_FORMAT_PKCS12) {
		if (priv->phase2_client_cert)
			g_byte_array_free (priv->phase2_client_cert, TRUE);

		priv->phase2_client_cert = g_byte_array_sized_new (priv->phase2_private_key->len);
		g_byte_array_append (priv->phase2_client_cert, priv->phase2_private_key->data, priv->phase2_private_key->len);
	}

	return priv->phase2_private_key != NULL;
}

/**
 * nm_setting_802_1x_set_phase2_private_key_from_file:
 * @setting: the #NMSetting8021x
 * @filename: the path of the "phase2" private key file (PEM, DER, or PKCS#12
 *   format).  Passing NULL clears the "phase2" private key.
 * @password: password used to decrypt the private key
 * @out_ck_type: on successful return, the type of the private key added
 * @error: on unsuccessful return, an error
 *
 * Reads a "phase 2" private key from disk and sets the
 * #NMSetting8021x:phase2-private-key property with the raw private key data.
 *
 * Private keys are used to authenticate the connecting client to the network
 * when EAP-TLS is used as either the "phase 1" or "phase 2" 802.1x
 * authentication method.
 *
 * Deprecated: 0.8: This function has been deprecated and should
 *   not be used in newly written code. Calling this function is
 *   equivalent to calling nm_setting_802_1x_set_phase2_private_key() with
 *   the %NM_SETTING_802_1X_CK_SCHEME_BLOB scheme.
 *
 * Returns: TRUE if the operation succeeded, FALSE if it was unsuccessful
 **/
gboolean
nm_setting_802_1x_set_phase2_private_key_from_file (NMSetting8021x *setting,
                                                    const char *filename,
                                                    const char *password,
                                                    NMSetting8021xCKType *out_ck_type,
                                                    GError **error)
{
	gboolean success;
	NMSetting8021xCKFormat format = NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;

	success = nm_setting_802_1x_set_phase2_private_key (setting,
	                                                    filename,
	                                                    password,
	                                                    NM_SETTING_802_1X_CK_SCHEME_BLOB,
	                                                    &format,
	                                                    error);
	if (success && out_ck_type)
		*out_ck_type = ck_format_to_type (format);

	return success;
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
		return NM_SETTING_802_1X_CK_FORMAT_X509;
	case NM_SETTING_802_1X_CK_SCHEME_PATH:
		path = nm_setting_802_1x_get_phase2_private_key_path (setting);
		if (crypto_is_pkcs12_file (path, &error))
			return NM_SETTING_802_1X_CK_FORMAT_PKCS12;
		if (error) {
			/* Couldn't read the file or something */
			g_error_free (error);
			return NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;
		}
		return NM_SETTING_802_1X_CK_FORMAT_X509;
	default:
		break;
	}

	return NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;
}

/**
 * nm_setting_802_1x_get_phase2_private_key_type:
 * @setting: the #NMSetting8021x
 *
 * Deprecated: 0.8: This function has been deprecated and should
 *   not be used in newly written code. Calling this function is
 *   equivalent to calling nm_setting_802_1x_get_phase2_private_key_format().
 *
 * Returns: the data format of the private key data stored in the
 *   #NMSetting8021x:phase2-private-key property
 **/
NMSetting8021xCKType
nm_setting_802_1x_get_phase2_private_key_type (NMSetting8021x *setting)
{
	return ck_format_to_type (nm_setting_802_1x_get_phase2_private_key_format (setting));
}

static void
need_secrets_password (NMSetting8021x *self,
                       GPtrArray *secrets,
                       gboolean phase2)
{
	NMSetting8021xPrivate *priv = NM_SETTING_802_1X_GET_PRIVATE (self);

	if (!priv->password || !strlen (priv->password))
		g_ptr_array_add (secrets, NM_SETTING_802_1X_PASSWORD);
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
	/* Private key password is only un-needed if the private key scheme is BLOB,
	 * because BLOB keys are decrypted by the settings service.  A private key
	 * password is required if the private key is PKCS#12 format, or if the
	 * private key scheme is PATH.
	 */
	if (path) {
		GByteArray *tmp;
		NMCryptoKeyType key_type = NM_CRYPTO_KEY_TYPE_UNKNOWN;
		NMCryptoFileFormat key_format = NM_CRYPTO_FILE_FORMAT_UNKNOWN;

		/* check the password */
		tmp = crypto_get_private_key (path, password, &key_type, &key_format, NULL);
		if (tmp) {
			/* Decrypt/verify successful; password must be OK */
			g_byte_array_free (tmp, TRUE);
			return FALSE;
		}
	} else if (blob) {
		/* Non-PKCS#12 blob-scheme keys are already decrypted by their settings
		 * service, thus if the private key is not PKCS#12 format, a new password
		 * is not required.  If the PKCS#12 key can be decrypted with the given
		 * password, then we don't need a new password either.
		 */
		if (!crypto_is_pkcs12_data (blob) || crypto_verify_pkcs12 (blob, password, NULL))
			return FALSE;
	} else
		g_warning ("%s: unknown private key password scheme", __func__);

	return TRUE;
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
		if (!priv->phase2_private_key || !priv->phase2_private_key->len) {
			g_ptr_array_add (secrets, NM_SETTING_802_1X_PHASE2_PRIVATE_KEY);
			return;
		}

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
		if (!priv->private_key || !priv->private_key->len) {
			g_ptr_array_add (secrets, NM_SETTING_802_1X_PRIVATE_KEY);
			return;
		}

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
			g_set_error (error,
			             NM_SETTING_802_1X_ERROR,
			             NM_SETTING_802_1X_ERROR_MISSING_PROPERTY,
			             NM_SETTING_802_1X_PHASE2_CLIENT_CERT);
			return FALSE;
		} else if (!priv->phase2_client_cert->len) {
			g_set_error (error,
			             NM_SETTING_802_1X_ERROR,
			             NM_SETTING_802_1X_ERROR_INVALID_PROPERTY,
			             NM_SETTING_802_1X_PHASE2_CLIENT_CERT);
			return FALSE;
		}

		/* If the private key is PKCS#12, check that it matches the client cert */
		if (priv->phase2_private_key && crypto_is_pkcs12_data (priv->phase2_private_key)) {
			if (priv->phase2_private_key->len != priv->phase2_client_cert->len) {
				g_set_error (error,
				             NM_SETTING_802_1X_ERROR,
				             NM_SETTING_802_1X_ERROR_INVALID_PROPERTY,
				             NM_SETTING_802_1X_PHASE2_CLIENT_CERT);
				return FALSE;
			}

			if (memcmp (priv->phase2_private_key->data,
			            priv->phase2_client_cert->data,
			            priv->phase2_private_key->len)) {
				g_set_error (error,
				             NM_SETTING_802_1X_ERROR,
				             NM_SETTING_802_1X_ERROR_INVALID_PROPERTY,
				             NM_SETTING_802_1X_PHASE2_CLIENT_CERT);
				return FALSE;
			}
		}
	} else {
		if (!priv->client_cert) {
			g_set_error (error,
			             NM_SETTING_802_1X_ERROR,
			             NM_SETTING_802_1X_ERROR_MISSING_PROPERTY,
			             NM_SETTING_802_1X_CLIENT_CERT);
			return FALSE;
		} else if (!priv->client_cert->len) {
			g_set_error (error,
			             NM_SETTING_802_1X_ERROR,
			             NM_SETTING_802_1X_ERROR_INVALID_PROPERTY,
			             NM_SETTING_802_1X_CLIENT_CERT);
			return FALSE;
		}

		/* If the private key is PKCS#12, check that it matches the client cert */
		if (priv->private_key && crypto_is_pkcs12_data (priv->private_key)) {
			if (priv->private_key->len != priv->client_cert->len) {
				g_set_error (error,
				             NM_SETTING_802_1X_ERROR,
				             NM_SETTING_802_1X_ERROR_INVALID_PROPERTY,
				             NM_SETTING_802_1X_CLIENT_CERT);
				return FALSE;
			}

			if (memcmp (priv->private_key->data,
			            priv->client_cert->data,
			            priv->private_key->len)) {
				g_set_error (error,
				             NM_SETTING_802_1X_ERROR,
				             NM_SETTING_802_1X_ERROR_INVALID_PROPERTY,
				             NM_SETTING_802_1X_CLIENT_CERT);
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
			g_set_error (error,
			             NM_SETTING_802_1X_ERROR,
			             NM_SETTING_802_1X_ERROR_MISSING_PROPERTY,
			             NM_SETTING_802_1X_IDENTITY);
		} else if (!strlen (priv->identity)) {
			g_set_error (error,
			             NM_SETTING_802_1X_ERROR,
			             NM_SETTING_802_1X_ERROR_INVALID_PROPERTY,
			             NM_SETTING_802_1X_IDENTITY);
		} else if (!priv->anonymous_identity) {
			g_set_error (error,
			             NM_SETTING_802_1X_ERROR,
			             NM_SETTING_802_1X_ERROR_MISSING_PROPERTY,
			             NM_SETTING_802_1X_ANONYMOUS_IDENTITY);
		} else {
			g_set_error (error,
			             NM_SETTING_802_1X_ERROR,
			             NM_SETTING_802_1X_ERROR_INVALID_PROPERTY,
			             NM_SETTING_802_1X_ANONYMOUS_IDENTITY);
		}
		return FALSE;
	}

	if (   (!priv->phase2_auth || !strlen (priv->phase2_auth))
	    && (!priv->phase2_autheap || !strlen (priv->phase2_autheap))) {
		if (!priv->phase2_auth) {
			g_set_error (error,
			             NM_SETTING_802_1X_ERROR,
			             NM_SETTING_802_1X_ERROR_MISSING_PROPERTY,
			             NM_SETTING_802_1X_PHASE2_AUTH);
		} else if (!strlen (priv->phase2_auth)) {
			g_set_error (error,
			             NM_SETTING_802_1X_ERROR,
			             NM_SETTING_802_1X_ERROR_INVALID_PROPERTY,
			             NM_SETTING_802_1X_PHASE2_AUTH);
		} else if (!priv->phase2_autheap) {
			g_set_error (error,
			             NM_SETTING_802_1X_ERROR,
			             NM_SETTING_802_1X_ERROR_MISSING_PROPERTY,
			             NM_SETTING_802_1X_PHASE2_AUTHEAP);
		} else {
			g_set_error (error,
			             NM_SETTING_802_1X_ERROR,
			             NM_SETTING_802_1X_ERROR_INVALID_PROPERTY,
			             NM_SETTING_802_1X_PHASE2_AUTHEAP);
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
		g_set_error (error,
		             NM_SETTING_802_1X_ERROR,
		             NM_SETTING_802_1X_ERROR_MISSING_PROPERTY,
		             NM_SETTING_802_1X_IDENTITY);
	} else if (!strlen (priv->identity)) {
		g_set_error (error,
		             NM_SETTING_802_1X_ERROR,
		             NM_SETTING_802_1X_ERROR_INVALID_PROPERTY,
		             NM_SETTING_802_1X_IDENTITY);
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

	g_set_error (error,
	             NM_SETTING_802_1X_ERROR,
	             NM_SETTING_802_1X_ERROR_INVALID_PROPERTY,
	             "%s", prop_name);
	return FALSE;
}

static gboolean
verify (NMSetting *setting, GSList *all_settings, GError **error)
{
	NMSetting8021x *self = NM_SETTING_802_1X (setting);
	NMSetting8021xPrivate *priv = NM_SETTING_802_1X_GET_PRIVATE (self);
	const char *valid_eap[] = { "leap", "md5", "tls", "peap", "ttls", "sim", "fast", NULL };
	const char *valid_phase1_peapver[] = { "0", "1", NULL };
	const char *valid_phase1_peaplabel[] = { "0", "1", NULL };
	const char *valid_phase1_fast_pac[] = { "0", "1", "2", "3", NULL };
	const char *valid_phase2_auth[] = { "pap", "chap", "mschap", "mschapv2", "gtc", "otp", "md5", "tls", NULL };
	const char *valid_phase2_autheap[] = { "md5", "mschapv2", "otp", "gtc", "tls", NULL };
	GSList *iter;

	if (error)
		g_return_val_if_fail (*error == NULL, FALSE);

	if (!priv->eap) {
		g_set_error (error,
		             NM_SETTING_802_1X_ERROR,
		             NM_SETTING_802_1X_ERROR_MISSING_PROPERTY,
		             NM_SETTING_802_1X_EAP);
		return FALSE;
	}

	if (!_nm_utils_string_slist_validate (priv->eap, valid_eap)) {
		g_set_error (error,
		             NM_SETTING_802_1X_ERROR,
		             NM_SETTING_802_1X_ERROR_INVALID_PROPERTY,
		             NM_SETTING_802_1X_EAP);
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
		             NM_SETTING_802_1X_PHASE1_PEAPVER);
		return FALSE;
	}

	if (priv->phase1_peaplabel && !_nm_utils_string_in_list (priv->phase1_peaplabel, valid_phase1_peaplabel)) {
		g_set_error (error,
		             NM_SETTING_802_1X_ERROR,
		             NM_SETTING_802_1X_ERROR_INVALID_PROPERTY,
		             NM_SETTING_802_1X_PHASE1_PEAPLABEL);
		return FALSE;
	}

	if (priv->phase1_fast_provisioning && !_nm_utils_string_in_list (priv->phase1_fast_provisioning, valid_phase1_fast_pac)) {
		g_set_error (error,
		             NM_SETTING_802_1X_ERROR,
		             NM_SETTING_802_1X_ERROR_INVALID_PROPERTY,
		             NM_SETTING_802_1X_PHASE1_FAST_PROVISIONING);
		return FALSE;
	}

	if (priv->phase2_auth && !_nm_utils_string_in_list (priv->phase2_auth, valid_phase2_auth)) {
		g_set_error (error,
		             NM_SETTING_802_1X_ERROR,
		             NM_SETTING_802_1X_ERROR_INVALID_PROPERTY,
		             NM_SETTING_802_1X_PHASE2_AUTH);
		return FALSE;
	}

	if (priv->phase2_autheap && !_nm_utils_string_in_list (priv->phase2_autheap, valid_phase2_autheap)) {
		g_set_error (error,
		             NM_SETTING_802_1X_ERROR,
		             NM_SETTING_802_1X_ERROR_INVALID_PROPERTY,
		             NM_SETTING_802_1X_PHASE2_AUTHEAP);
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
	g_object_set (setting, NM_SETTING_NAME, NM_SETTING_802_1X_SETTING_NAME, NULL);
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
	g_free (priv->phase1_peapver);
	g_free (priv->phase1_peaplabel);
	g_free (priv->phase1_fast_provisioning);
	g_free (priv->phase2_auth);
	g_free (priv->phase2_autheap);
	g_free (priv->phase2_ca_path);
	g_free (priv->password);

	nm_utils_slist_free (priv->eap, g_free);

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
		nm_utils_slist_free (priv->eap, g_free);
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
	case PROP_CA_CERT:
		g_value_set_boxed (value, priv->ca_cert);
		break;
	case PROP_CA_PATH:
		g_value_set_string (value, priv->ca_path);
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
	case PROP_PHASE2_CLIENT_CERT:
		g_value_set_boxed (value, priv->phase2_client_cert);
		break;
	case PROP_PASSWORD:
		g_value_set_string (value, priv->password);
		break;
	case PROP_PRIVATE_KEY:
		g_value_set_boxed (value, priv->private_key);
		break;
	case PROP_PRIVATE_KEY_PASSWORD:
		g_value_set_string (value, priv->private_key_password);
		break;
	case PROP_PHASE2_PRIVATE_KEY:
		g_value_set_boxed (value, priv->phase2_private_key);
		break;
	case PROP_PHASE2_PRIVATE_KEY_PASSWORD:
		g_value_set_string (value, priv->phase2_private_key_password);
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
	 * 802.1x.  Valid methods are: "leap", "md5", "tls", "peap", "ttls", and
	 * "fast".  Each method requires different configuration using the
	 * properties of this object; refer to wpa_supplicant documentation for the
	 * allowed combinations.
	 **/
	g_object_class_install_property
		(object_class, PROP_EAP,
		 _nm_param_spec_specialized (NM_SETTING_802_1X_EAP,
							   "EAP",
							   "The allowed EAP method to be used when "
							   "authenticating to the network with 802.1x. "
							   "Valid methods are: 'leap', 'md5', 'tls', 'peap', "
							   "'ttls', and 'fast'. Each method requires "
							   "different configuration using the properties of "
							   "this setting; refer to wpa_supplicant "
							   "documentation for the allowed combinations.",
							   DBUS_TYPE_G_LIST_OF_STRING,
							   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSetting8021x:identity:
	 *
	 * Identity string for EAP authentication methods.  Often the user's
	 * user or login name.
	 **/
	g_object_class_install_property
		(object_class, PROP_IDENTITY,
		 g_param_spec_string (NM_SETTING_802_1X_IDENTITY,
						  "Identity",
						  "Identity string for EAP authentication methods.  "
						  "Often the user's user or login name.",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

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
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSetting8021x:ca-cert:
	 *
	 * Contains the CA certificate if used by the EAP method specified in the
	 * #NMSetting8021x:eap property.  Setting this property directly is
	 * discouraged; use the nm_setting_802_1x_set_ca_cert() function instead.
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
							   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

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
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSetting8021x:client-cert:
	 *
	 * Contains the client certificate if used by the EAP method specified in
	 * the #NMSetting8021x:eap property.  Setting this property directly is
	 * discouraged; use the nm_setting_802_1x_set_client_cert() function instead.
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
							   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

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
						  "'0' or '1; to force that specific PEAP version.",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

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
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

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
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSetting8021x:phase2-auth:
	 *
	 * Specifies the allowed "phase 2" inner non-EAP authentication methods when
	 * an EAP method that uses an inner TLS tunnel is specified in the
	 * #NMSetting8021x:eap property.  Recognized non-EAP phase2 methods are
	 * "pap", "chap", "mschap", "mschapv2", "gtc", "otp", "md5", and "tls".
	 * Each 'phase 2' inner method requires specific parameters for successful
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
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSetting8021x:phase2-autheap:
	 *
	 * Specifies the allowed "phase 2" inner EAP-based authentication methods
	 * when an EAP method that uses an inner TLS tunnel is specified in the
	 * #NMSetting8021x:eap property.  Recognized EAP-based phase2 methods are
	 * "md5", "mschapv2", "otp", "gtc", and "tls". Each 'phase 2' inner method
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
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSetting8021x:phase2-ca-cert:
	 *
	 * Contains the CA certificate if used by the EAP method specified in the
	 * #NMSetting8021x:phase2-auth or #NMSetting8021x:phase2-autheap properties.
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
							   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

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
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSetting8021x:phase2-client-cert:
	 *
	 * Contains the client certificate if used by the EAP method specified in
	 * the #NMSetting8021x:phase2-auth or #NMSetting8021x:phase2-autheap
	 * properties.  Setting this property directly is discouraged; use the
	 * nm_setting_802_1x_set_phase2_client_cert() function instead.
	 **/
	g_object_class_install_property
		(object_class, PROP_PHASE2_CLIENT_CERT,
		 _nm_param_spec_specialized (NM_SETTING_802_1X_PHASE2_CLIENT_CERT,
							   "Phase2 client certificate",
							   "Contains the 'phase 2' client certificate if "
							   "used by the EAP method specified in the "
							   "'phase2-eap' or 'phase2-autheap' properties. "
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
							   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSetting8021x:password:
	 *
	 * Password used for EAP authentication methods.
	 **/
	g_object_class_install_property
		(object_class, PROP_PASSWORD,
		 g_param_spec_string (NM_SETTING_802_1X_PASSWORD,
						  "Password",
						  "Password used for EAP authentication methods.",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE | NM_SETTING_PARAM_SECRET));

	/**
	 * NMSetting8021x:private-key:
	 *
	 * Contains the private key if the #NMSetting8021x:eap property is set to
	 * 'tls'.  Setting this property directly is discouraged; use the
	 * nm_setting_802_1x_set_private_key() function instead.
	 **/
	g_object_class_install_property
		(object_class, PROP_PRIVATE_KEY,
		 _nm_param_spec_specialized (NM_SETTING_802_1X_PRIVATE_KEY,
							   "Private key",
							   "Contains the private key when the 'eap' property "
							   "is set to 'tls'.  Key data is specified using a "
							   "'scheme'; two are currently supported: blob and "
							   "path. When using the blob scheme and X.509 private "
							   "keys, this property should be set to the keys's "
							   "decrypted DER encoded data.  When using X.509 "
							   "private keys with the path scheme, this property "
							   "should be set to the full UTF-8 encoded path of "
							   "the key, prefixed with the string 'file://' and "
							   "and ending with a terminating NULL byte.  When "
							   "using PKCS#12 format private keys and the blob "
							   "scheme, this property should be set to the "
							   "PKCS#12 data (which is encrypted) and the "
							   "'private-key-password' property must be set to "
							   "password used to decrypt the PKCS#12 certificate "
							   "and key.  When using PKCS#12 files and the path "
							   "scheme, this property should be set to the full "
							   "UTF-8 encoded path of the key, prefixed with the "
							   "string 'file://' and and ending with a "
							   "terminating NULL byte, and as with the blob "
							   "scheme the 'private-key-password' property must "
							   "be set to the password used to decode the PKCS#12 "
							   "private key and certificate.",
							   DBUS_TYPE_G_UCHAR_ARRAY,
							   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE | NM_SETTING_PARAM_SECRET));

	/**
	 * NMSetting8021x:private-key-password:
	 *
	 * The password used to decrypt the private key specified in
	 * #NMSetting8021x:private-key when the private key either uses the path
	 * scheme, or if the private key is a PKCS#12 format key.  Setting this
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
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE | NM_SETTING_PARAM_SECRET));

	/**
	 * NMSetting8021x:phase2-private-key:
	 *
	 * Private key data used by "phase 2" inner authentication methods.
	 *
	 * Contains the "phase 2" inner private key if the #NMSetting8021x:auth or
	 * #NMSetting8021x:phase2-autheap property is set to 'tls'.  Setting this
	 * property directly is discouraged; use the
	 * nm_setting_802_1x_set_phase2_private_key() function instead.
	 **/
	g_object_class_install_property
		(object_class, PROP_PHASE2_PRIVATE_KEY,
		 _nm_param_spec_specialized (NM_SETTING_802_1X_PHASE2_PRIVATE_KEY,
							   "Phase2 private key",
							   "Contains the 'phase 2' inner private key when "
							   "the 'phase2-eap' or 'phase2-autheap' property "
							   "is set to 'tls'.  Key data is specified using a "
							   "'scheme'; two are currently supported: blob and "
							   "path. When using the blob scheme and X.509 private "
							   "keys, this property should be set to the keys's "
							   "decrypted DER encoded data.  When using X.509 "
							   "private keys with the path scheme, this property "
							   "should be set to the full UTF-8 encoded path of "
							   "the key, prefixed with the string 'file://' and "
							   "and ending with a terminating NULL byte.  When "
							   "using PKCS#12 format private keys and the blob "
							   "scheme, this property should be set to the "
							   "PKCS#12 data (which is encrypted) and the "
							   "'private-key-password' property must be set to "
							   "password used to decrypt the PKCS#12 certificate "
							   "and key.  When using PKCS#12 files and the path "
							   "scheme, this property should be set to the full "
							   "UTF-8 encoded path of the key, prefixed with the "
							   "string 'file://' and and ending with a "
							   "terminating NULL byte, and as with the blob "
							   "scheme the 'private-key-password' property must "
							   "be set to the password used to decode the PKCS#12 "
							   "private key and certificate.",
							   DBUS_TYPE_G_UCHAR_ARRAY,
							   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE | NM_SETTING_PARAM_SECRET));

	/**
	 * NMSetting8021x:phase2-private-key-password:
	 *
	 * The password used to decrypt the private key specified in
	 * #NMSetting8021x:phase2-private-key when the private key either uses the
	 * path scheme, or if the private key is a PKCS#12 format key.  Setting this
	 * property directly is not generally necessary except when returning
	 * secrets to NetworkManager; it is generally set automatically when setting
	 * the private key by the nm_setting_802_1x_set_phase2_private_key() function.
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
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE | NM_SETTING_PARAM_SECRET));

	/**
	 * NMSetting8021x:system-ca-certs:
	 *
	 * When TRUE, overrides #NMSetting8021x:ca-path and
	 * #NMSetting8021x:phase2-ca-path properties using the system CA directory
	 * specified at configure time with the --system-ca-path switch.  The
	 * certificates in this directory are added to the verification chain in
	 * addition to any certificates specified by the #NMSetting8021x:ca-cert,
	 * #NMSetting8021x:ca-cert-path, #NMSetting8021x:phase2-ca-cert and
	 * #NMSetting8021x:phase2-ca-cert-path properties.
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
							   G_PARAM_READWRITE | G_PARAM_CONSTRUCT | NM_SETTING_PARAM_SERIALIZE));

	/* Initialize crypto lbrary. */
	if (!nm_utils_init (&error)) {
		g_warning ("Couldn't initilize nm-utils/crypto system: %d %s",
		           error->code, error->message);
		g_error_free (error);
	}

}
