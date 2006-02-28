/* NetworkManager Wireless Applet -- Display wireless access points and allow user control
 *
 * Dan Williams <dcbw@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * (C) Copyright 2005 Red Hat, Inc.
 */


#include <dbus/dbus.h>
#include <glib.h>
#include <iwlib.h>

#include "NetworkManager.h"
#include "dbus-helpers.h"
#include "cipher.h"


static void we_cipher_append_helper (DBusMessageIter *iter, int we_cipher)
{
	dbus_int32_t	dbus_we_cipher = (dbus_int32_t) we_cipher;

	g_return_if_fail (iter != NULL);

	dbus_message_iter_append_basic (iter, DBUS_TYPE_INT32, &dbus_we_cipher);
}

dbus_bool_t
nmu_security_serialize_wep (DBusMessageIter *iter,
					   const char *key,
					   int auth_alg)
{
	const char *	fake_key = "";

	g_return_val_if_fail (iter != NULL, FALSE);
	g_return_val_if_fail ((auth_alg == IW_AUTH_ALG_OPEN_SYSTEM) || (auth_alg == IW_AUTH_ALG_SHARED_KEY), FALSE);

	/* Second arg: hashed key (STRING) */
	dbus_message_iter_append_basic (iter, DBUS_TYPE_STRING, key ? &key : &fake_key);

	/* Third arg: WEP authentication algorithm (INT32) */
	dbus_message_iter_append_basic (iter, DBUS_TYPE_INT32, &auth_alg);

	return TRUE;
}

/*
 * nmu_security_deserialize_wep
 *
 * Callers are responsible for freeing 'key' via dbus_free().
 */
dbus_bool_t
nmu_security_deserialize_wep (DBusMessageIter *iter,
						char **key,
						int *key_len,
						int *auth_alg)
{
	char *			dbus_key;
	dbus_int32_t		dbus_auth_alg;

	g_return_val_if_fail (iter != NULL, FALSE);
	g_return_val_if_fail (key != NULL, FALSE);
	g_return_val_if_fail (*key == NULL, FALSE);
	g_return_val_if_fail (key_len != NULL, FALSE);
	g_return_val_if_fail (auth_alg != NULL, FALSE);

	/* Next arg: key (STRING) */
	g_return_val_if_fail (dbus_message_iter_get_arg_type (iter) == DBUS_TYPE_STRING, FALSE);

	dbus_message_iter_get_basic (iter, &dbus_key);
	g_return_val_if_fail (dbus_key != NULL, FALSE);

	/* Next arg: authentication algorithm (INT32) */
	g_return_val_if_fail (dbus_message_iter_next (iter), FALSE);
	g_return_val_if_fail (dbus_message_iter_get_arg_type (iter) == DBUS_TYPE_INT32, FALSE);

	dbus_message_iter_get_basic (iter, &dbus_auth_alg);
	g_return_val_if_fail ((dbus_auth_alg == IW_AUTH_ALG_OPEN_SYSTEM)
			|| (dbus_auth_alg == IW_AUTH_ALG_SHARED_KEY), FALSE);

	*key = strlen (dbus_key) > 0 ? dbus_key : NULL;
	*key_len = strlen (dbus_key);
	*auth_alg = dbus_auth_alg;
	return TRUE;
}


dbus_bool_t
nmu_security_serialize_none_with_cipher (DBusMessage *message)
{
	dbus_bool_t		result = TRUE;
	DBusMessageIter	iter;

	g_return_val_if_fail (message != NULL, FALSE);

	dbus_message_iter_init_append (message, &iter);

	/* First arg: WE Cipher (INT32) */
	we_cipher_append_helper (&iter, IW_AUTH_CIPHER_NONE);

	return result;
}


dbus_bool_t
nmu_security_serialize_wep_with_cipher (DBusMessage *message,
					IEEE_802_11_Cipher *cipher,
					const char *ssid,
					const char *input,
					int auth_alg)
{
	char *			key = NULL;
	dbus_bool_t		result = TRUE;
	DBusMessageIter	iter;

	g_return_val_if_fail (message != NULL, FALSE);
	g_return_val_if_fail (cipher != NULL, FALSE);
	g_return_val_if_fail ((auth_alg == IW_AUTH_ALG_OPEN_SYSTEM) || (auth_alg == IW_AUTH_ALG_SHARED_KEY), FALSE);

	dbus_message_iter_init_append (message, &iter);

	/* First arg: WE Cipher (INT32) */
	we_cipher_append_helper (&iter, ieee_802_11_cipher_get_we_cipher (cipher));

	key = ieee_802_11_cipher_hash (cipher, ssid, input);
	result = nmu_security_serialize_wep (&iter, key, auth_alg);
	g_free (key);

	return result;
}


dbus_bool_t
nmu_security_serialize_wpa_psk (DBusMessageIter *iter,
					const char *key,
					int wpa_version,
					int key_mgt)
{
	const char *	fake_key = "";

	g_return_val_if_fail (iter != NULL, FALSE);
	g_return_val_if_fail ((wpa_version == IW_AUTH_WPA_VERSION_WPA) || (wpa_version == IW_AUTH_WPA_VERSION_WPA2), FALSE);
	g_return_val_if_fail ((key_mgt == IW_AUTH_KEY_MGMT_802_1X) || (key_mgt == IW_AUTH_KEY_MGMT_PSK), FALSE);

	/* Second arg: hashed key (STRING) */
	dbus_message_iter_append_basic (iter, DBUS_TYPE_STRING, key ? &key : &fake_key);

	/* Third arg: WPA version (INT32) */
	dbus_message_iter_append_basic (iter, DBUS_TYPE_INT32, &wpa_version);

	/* Fourth arg: WPA key management (INT32) */
	dbus_message_iter_append_basic (iter, DBUS_TYPE_INT32, &key_mgt);

	return TRUE;
}

/*
 * nmu_security_deserialize_wpa_psk
 *
 * Callers are responsible for freeing 'key' via dbus_free().
 */
dbus_bool_t
nmu_security_deserialize_wpa_psk (DBusMessageIter *iter,
						    char **key,
						    int *key_len,
						    int *wpa_version,
						    int *key_mgt)
{
	char *			dbus_key;
	dbus_int32_t		dbus_wpa_version;
	dbus_int32_t		dbus_key_mgt;

	g_return_val_if_fail (iter != NULL, FALSE);
	g_return_val_if_fail (key != NULL, FALSE);
	g_return_val_if_fail (*key == NULL, FALSE);
	g_return_val_if_fail (key_len != NULL, FALSE);
	g_return_val_if_fail (wpa_version != NULL, FALSE);
	g_return_val_if_fail (key_mgt != NULL, FALSE);

	/* Next arg: key (STRING) */
	g_return_val_if_fail (dbus_message_iter_get_arg_type (iter) == DBUS_TYPE_STRING, FALSE);

	dbus_message_iter_get_basic (iter, &dbus_key);
	g_return_val_if_fail (dbus_key != NULL, FALSE);

	/* Next arg: WPA version (INT32) */
	g_return_val_if_fail (dbus_message_iter_next (iter), FALSE);
	g_return_val_if_fail (dbus_message_iter_get_arg_type (iter) == DBUS_TYPE_INT32, FALSE);

	dbus_message_iter_get_basic (iter, &dbus_wpa_version);
	g_return_val_if_fail ((dbus_wpa_version == IW_AUTH_WPA_VERSION_WPA)
			|| (dbus_wpa_version == IW_AUTH_WPA_VERSION_WPA2), FALSE);

	/* Next arg: WPA key management (INT32) */
	g_return_val_if_fail (dbus_message_iter_next (iter), FALSE);
	g_return_val_if_fail (dbus_message_iter_get_arg_type (iter) == DBUS_TYPE_INT32, FALSE);

	dbus_message_iter_get_basic (iter, &dbus_key_mgt);
	g_return_val_if_fail ((dbus_key_mgt == IW_AUTH_KEY_MGMT_802_1X)
			|| (dbus_key_mgt == IW_AUTH_KEY_MGMT_PSK), FALSE);

	*key = strlen (dbus_key) > 0 ? dbus_key : NULL;
	*key_len = strlen (dbus_key);
	*wpa_version = dbus_wpa_version;
	*key_mgt = dbus_key_mgt;
	return TRUE;
}


dbus_bool_t
nmu_security_serialize_wpa_psk_with_cipher (DBusMessage *message,
								    IEEE_802_11_Cipher *cipher,
								    const char *ssid,
								    const char *input,
								    int wpa_version,
								    int key_mgt)
{
	char *			key = NULL;
	dbus_bool_t		result = TRUE;
	DBusMessageIter	iter;

	g_return_val_if_fail (message != NULL, FALSE);
	g_return_val_if_fail (cipher != NULL, FALSE);
	g_return_val_if_fail ((wpa_version == IW_AUTH_WPA_VERSION_WPA) || (wpa_version == IW_AUTH_WPA_VERSION_WPA2), FALSE);
	g_return_val_if_fail ((key_mgt == IW_AUTH_KEY_MGMT_802_1X) || (key_mgt == IW_AUTH_KEY_MGMT_PSK), FALSE);

	dbus_message_iter_init_append (message, &iter);

	/* First arg: WE Cipher (INT32) */
	we_cipher_append_helper (&iter, ieee_802_11_cipher_get_we_cipher (cipher));

	key = ieee_802_11_cipher_hash (cipher, ssid, input);
	result = nmu_security_serialize_wpa_psk (&iter, key, wpa_version, key_mgt);
	g_free (key);

	return result;
}


dbus_bool_t
nmu_security_serialize_wpa_eap (DBusMessageIter *iter,
						  int eap_method,
						  const char *identity,
						  const char *passwd,
						  const char *anon_identity,
						  const char *private_key_passwd,
						  const char *private_key_file,
						  const char *client_cert_file,
						  const char *ca_cert_file,
						  int wpa_version)
{
	g_return_val_if_fail (iter != NULL, FALSE);
	g_return_val_if_fail ((wpa_version == IW_AUTH_WPA_VERSION_WPA) || (wpa_version == IW_AUTH_WPA_VERSION_WPA2), FALSE);
	g_return_val_if_fail ((eap_method == NM_EAP_METHOD_MD5)
				    || (eap_method == NM_EAP_METHOD_MSCHAP)
				    || (eap_method == NM_EAP_METHOD_OTP)
				    || (eap_method == NM_EAP_METHOD_GTC)
				    || (eap_method == NM_EAP_METHOD_PEAP)
				    || (eap_method == NM_EAP_METHOD_TLS)
				    || (eap_method == NM_EAP_METHOD_TTLS), FALSE);

	/* Second arg: EAP method (INT32) */
	dbus_message_iter_append_basic (iter, DBUS_TYPE_INT32, &eap_method);

	/* Third arg: Identity (STRING) */
	dbus_message_iter_append_basic (iter, DBUS_TYPE_STRING, &identity);

	/* Fourth arg: Password (STRING) */
	dbus_message_iter_append_basic (iter, DBUS_TYPE_STRING, &passwd);

	/* Fifth arg: Anonymous Identity (STRING) */
	dbus_message_iter_append_basic (iter, DBUS_TYPE_STRING, &anon_identity);

	/* Sixth arg: Private key password (STRING) */
	dbus_message_iter_append_basic (iter, DBUS_TYPE_STRING, &private_key_passwd);

	/* Seventh arg: Private key file (STRING) */
	dbus_message_iter_append_basic (iter, DBUS_TYPE_STRING, &private_key_file);

	/* Eighth arg: Client certificate file (STRING) */
	dbus_message_iter_append_basic (iter, DBUS_TYPE_STRING, &client_cert_file);

	/* Ninth arg: CA certificate file (STRING) */
	dbus_message_iter_append_basic (iter, DBUS_TYPE_STRING, &ca_cert_file);

	/* Tenth and final arg: WPA version (INT32) */
	dbus_message_iter_append_basic (iter, DBUS_TYPE_INT32, &wpa_version);

	return TRUE;
}


dbus_bool_t
nmu_security_serialize_wpa_eap_with_cipher (DBusMessageIter *iter,
								    int eap_method,
								    const char *identity,
								    const char *passwd,
								    const char *anon_identity,
								    const char *private_key_passwd,
								    const char *private_key_file,
								    const char *client_cert_file,
								    const char *ca_cert_file,
								    int wpa_version)
{
	dbus_bool_t	result;

	g_return_val_if_fail (iter != NULL, FALSE);
	g_return_val_if_fail ((wpa_version == IW_AUTH_WPA_VERSION_WPA) || (wpa_version == IW_AUTH_WPA_VERSION_WPA2), FALSE);
	g_return_val_if_fail ((eap_method == NM_EAP_METHOD_MD5)
				    || (eap_method == NM_EAP_METHOD_MSCHAP)
				    || (eap_method == NM_EAP_METHOD_OTP)
				    || (eap_method == NM_EAP_METHOD_GTC)
				    || (eap_method == NM_EAP_METHOD_PEAP)
				    || (eap_method == NM_EAP_METHOD_TLS)
				    || (eap_method == NM_EAP_METHOD_TTLS), FALSE);

	/* First arg: WE Cipher (INT32) */
	we_cipher_append_helper (iter, NM_AUTH_TYPE_WPA_EAP);

	result = nmu_security_serialize_wpa_eap (iter, eap_method, identity, passwd, anon_identity, private_key_passwd,
									 private_key_file, client_cert_file, ca_cert_file, wpa_version);

	return result;
}

/*
 * nmu_security_deserialize_wpa_eap
 *
 * Callers are responsible for freeing identity, passwd, anon_identity,
 * private_key_passwd, private_key_file, client_cert_file, and ca_cert_file
 * via dbus_free().
 */
dbus_bool_t
nmu_security_deserialize_wpa_eap (DBusMessageIter *iter,
						    int *eap_method,
						    char **identity,
						    char **passwd,
						    char **anon_identity,
						    char **private_key_passwd,
						    char **private_key_file,
						    char **client_cert_file,
						    char **ca_cert_file,
						    int *wpa_version)
{
	char *		dbus_identity;
	char *		dbus_password;
	char *		dbus_anon_identity;
	char *		dbus_private_key_passwd;
	char *		dbus_private_key_file;
	char *		dbus_client_cert_file;
	char *		dbus_ca_cert_file;
	dbus_int32_t	dbus_wpa_version;
	dbus_int32_t	dbus_eap_method;

	g_return_val_if_fail (iter != NULL, FALSE);
	g_return_val_if_fail (identity != NULL, FALSE);
	g_return_val_if_fail (*identity == NULL, FALSE);
	g_return_val_if_fail (passwd != NULL, FALSE);
	g_return_val_if_fail (*passwd == NULL, FALSE);
	g_return_val_if_fail (anon_identity != NULL, FALSE);
	g_return_val_if_fail (*anon_identity == NULL, FALSE);
	g_return_val_if_fail (private_key_passwd != NULL, FALSE);
	g_return_val_if_fail (*private_key_passwd == NULL, FALSE);
	g_return_val_if_fail (private_key_file != NULL, FALSE);
	g_return_val_if_fail (*private_key_file == NULL, FALSE);
	g_return_val_if_fail (client_cert_file != NULL, FALSE);
	g_return_val_if_fail (*client_cert_file == NULL, FALSE);
	g_return_val_if_fail (ca_cert_file != NULL, FALSE);
	g_return_val_if_fail (*ca_cert_file == NULL, FALSE);
	g_return_val_if_fail (wpa_version != NULL, FALSE);

	/* Second arg: EAP method (INT32) */
	g_return_val_if_fail (dbus_message_iter_get_arg_type (iter) == DBUS_TYPE_INT32, FALSE);
	dbus_message_iter_get_basic (iter, &dbus_eap_method);
	g_return_val_if_fail ((dbus_eap_method == NM_EAP_METHOD_MD5)
				    || (dbus_eap_method == NM_EAP_METHOD_MSCHAP)
				    || (dbus_eap_method == NM_EAP_METHOD_OTP)
				    || (dbus_eap_method == NM_EAP_METHOD_GTC)
				    || (dbus_eap_method == NM_EAP_METHOD_PEAP)
				    || (dbus_eap_method == NM_EAP_METHOD_TLS)
				    || (dbus_eap_method == NM_EAP_METHOD_TTLS), FALSE);

	/* Third arg: Identity (STRING) */
	g_return_val_if_fail (dbus_message_iter_next (iter), FALSE);
	g_return_val_if_fail (dbus_message_iter_get_arg_type (iter) == DBUS_TYPE_STRING, FALSE);
	dbus_message_iter_get_basic (iter, &dbus_identity);
	g_return_val_if_fail (dbus_identity != NULL, FALSE);

	/* Fourth arg: Password (STRING) */
	g_return_val_if_fail (dbus_message_iter_next (iter), FALSE);
	g_return_val_if_fail (dbus_message_iter_get_arg_type (iter) == DBUS_TYPE_STRING, FALSE);
	dbus_message_iter_get_basic (iter, &dbus_password);
	g_return_val_if_fail (dbus_password != NULL, FALSE);

	/* Fifth arg: Anonymous Identity (STRING) */
	g_return_val_if_fail (dbus_message_iter_next (iter), FALSE);
	g_return_val_if_fail (dbus_message_iter_get_arg_type (iter) == DBUS_TYPE_STRING, FALSE);
	dbus_message_iter_get_basic (iter, &dbus_anon_identity);
	g_return_val_if_fail (dbus_anon_identity != NULL, FALSE);

	/* Sixth arg: Private key password (STRING) */
	g_return_val_if_fail (dbus_message_iter_next (iter), FALSE);
	g_return_val_if_fail (dbus_message_iter_get_arg_type (iter) == DBUS_TYPE_STRING, FALSE);
	dbus_message_iter_get_basic (iter, &dbus_private_key_passwd);
	g_return_val_if_fail (dbus_private_key_passwd != NULL, FALSE);

	/* Seventh arg: Private key file (STRING) */
	g_return_val_if_fail (dbus_message_iter_next (iter), FALSE);
	g_return_val_if_fail (dbus_message_iter_get_arg_type (iter) == DBUS_TYPE_STRING, FALSE);
	dbus_message_iter_get_basic (iter, &dbus_private_key_file);
	g_return_val_if_fail (dbus_private_key_file != NULL, FALSE);

	/* Eighth arg: Client certificate file (STRING) */
	g_return_val_if_fail (dbus_message_iter_next (iter), FALSE);
	g_return_val_if_fail (dbus_message_iter_get_arg_type (iter) == DBUS_TYPE_STRING, FALSE);
	dbus_message_iter_get_basic (iter, &dbus_client_cert_file);
	g_return_val_if_fail (dbus_client_cert_file != NULL, FALSE);

	/* Ninth arg: CA certificate file (STRING) */
	g_return_val_if_fail (dbus_message_iter_next (iter), FALSE);
	g_return_val_if_fail (dbus_message_iter_get_arg_type (iter) == DBUS_TYPE_STRING, FALSE);
	dbus_message_iter_get_basic (iter, &dbus_ca_cert_file);
	g_return_val_if_fail (dbus_ca_cert_file != NULL, FALSE);

	/* Tenth and final arg: WPA version (INT32) */
	g_return_val_if_fail (dbus_message_iter_next (iter), FALSE);
	g_return_val_if_fail (dbus_message_iter_get_arg_type (iter) == DBUS_TYPE_INT32, FALSE);
	dbus_message_iter_get_basic (iter, &dbus_wpa_version);
	g_return_val_if_fail ((dbus_wpa_version == IW_AUTH_WPA_VERSION_WPA)
			|| (dbus_wpa_version == IW_AUTH_WPA_VERSION_WPA2), FALSE);

	*eap_method = dbus_eap_method;
	*identity = strlen (dbus_identity) > 0 ? dbus_identity : NULL;
	*passwd = strlen (dbus_password) > 0 ? dbus_password : NULL;
	*anon_identity = strlen (dbus_anon_identity) > 0 ? dbus_anon_identity : NULL;
	*private_key_passwd = strlen (dbus_private_key_passwd) > 0 ? dbus_private_key_passwd : NULL;
	*private_key_file = strlen (dbus_private_key_file) > 0 ? dbus_private_key_file : NULL;
	*client_cert_file = strlen (dbus_client_cert_file) > 0 ? dbus_client_cert_file : NULL;
	*ca_cert_file = strlen (dbus_ca_cert_file) > 0 ? dbus_ca_cert_file : NULL;
	*wpa_version = dbus_wpa_version;

	return TRUE;
}


/*
 * nmu_create_dbus_error_message
 *
 * Make a pretty DBus error message
 *
 */
DBusMessage *
nmu_create_dbus_error_message (DBusMessage *message,
                               const char *exception_namespace,
                               const char *exception,
                               const char *format,
                               ...)
{
	DBusMessage *	reply;
	va_list		args;
	char *		errmsg;
	char *		full_exception;

	errmsg = g_malloc0 (513);
	va_start (args, format);
	vsnprintf (errmsg, 512, format, args);
	va_end (args);

	full_exception = g_strdup_printf ("%s.%s", exception_namespace, exception);
	reply = dbus_message_new_error (message, full_exception, errmsg);
	g_free (full_exception);
	g_free (errmsg);

	return reply;
}


