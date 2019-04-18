/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager Wireless Applet -- Display wireless access points and allow user control
 *
 * Dan Williams <dcbw@redhat.com>
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
 * Copyright 2007 - 2015 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-crypto-impl.h"

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/x509.h>
#include <gnutls/pkcs12.h>

#include "nm-glib-aux/nm-secret-utils.h"
#include "nm-errors.h"

/*****************************************************************************/

static gboolean
_get_cipher_info (NMCryptoCipherType cipher,
                  int *out_cipher_mech,
                  guint8 *out_real_iv_len)
{
	static const int cipher_mechs[] = {
		[NM_CRYPTO_CIPHER_DES_EDE3_CBC] = GNUTLS_CIPHER_3DES_CBC,
		[NM_CRYPTO_CIPHER_DES_CBC]      = GNUTLS_CIPHER_DES_CBC,
		[NM_CRYPTO_CIPHER_AES_128_CBC]  = GNUTLS_CIPHER_AES_128_CBC,
		[NM_CRYPTO_CIPHER_AES_192_CBC]  = GNUTLS_CIPHER_AES_192_CBC,
		[NM_CRYPTO_CIPHER_AES_256_CBC]  = GNUTLS_CIPHER_AES_256_CBC,
	};

	g_return_val_if_fail (_NM_INT_NOT_NEGATIVE (cipher) && (gsize) cipher < G_N_ELEMENTS (cipher_mechs), FALSE);

	if (cipher_mechs[cipher] == 0)
		return FALSE;

	NM_SET_OUT (out_cipher_mech, cipher_mechs[cipher]);
	NM_SET_OUT (out_real_iv_len, nm_crypto_cipher_get_info (cipher)->real_iv_len);
	return TRUE;
}

/*****************************************************************************/

gboolean
_nm_crypto_init (GError **error)
{
	static gboolean initialized = FALSE;

	if (initialized)
		return TRUE;

	if (gnutls_global_init () != 0) {
		gnutls_global_deinit ();
		g_set_error_literal (error, NM_CRYPTO_ERROR,
		                     NM_CRYPTO_ERROR_FAILED,
		                     _("Failed to initialize the crypto engine."));
		return FALSE;
	}

	initialized = TRUE;
	return TRUE;
}

/*****************************************************************************/

guint8 *
_nmtst_crypto_decrypt (NMCryptoCipherType cipher,
                       const guint8 *data,
                       gsize data_len,
                       const guint8 *iv,
                       gsize iv_len,
                       const guint8 *key,
                       gsize key_len,
                       gsize *out_len,
                       GError **error)
{
	gnutls_cipher_hd_t ctx;
	gnutls_datum_t key_dt, iv_dt;
	int err;
	int cipher_mech;
	nm_auto_clear_secret_ptr NMSecretPtr output = { 0 };
	guint8 pad_i, pad_len;
	guint8 real_iv_len;

	if (!_get_cipher_info (cipher, &cipher_mech, &real_iv_len)) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_UNKNOWN_CIPHER,
		             _("Unsupported key cipher for decryption"));
		return NULL;
	}

	if (!_nm_crypto_init (error))
		return NULL;

	if (iv_len < real_iv_len) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_INVALID_DATA,
		             _("Invalid IV length (must be at least %u)."),
		             (guint) real_iv_len);
		return NULL;
	}

	output.len = data_len;
	output.bin = g_malloc (data_len);

	key_dt.data = (unsigned char *) key;
	key_dt.size = key_len;
	iv_dt.data = (unsigned char *) iv;
	iv_dt.size = iv_len;

	err = gnutls_cipher_init (&ctx, cipher_mech, &key_dt, &iv_dt);
	if (err < 0) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_DECRYPTION_FAILED,
		             _("Failed to initialize the decryption cipher context: %s (%s)"),
		             gnutls_strerror_name (err), gnutls_strerror (err));
		return NULL;
	}

	err = gnutls_cipher_decrypt2 (ctx, data, data_len, output.bin, output.len);

	gnutls_cipher_deinit (ctx);

	if (err < 0) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_DECRYPTION_FAILED,
		             _("Failed to decrypt the private key: %s (%s)"),
		             gnutls_strerror_name (err), gnutls_strerror (err));
		return NULL;
	}

	pad_len = output.len > 0
	          ? output.bin[output.len - 1]
	          : 0;

	/* Check if the padding at the end of the decrypted data is valid */
	if (   pad_len == 0
	    || pad_len > real_iv_len) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_DECRYPTION_FAILED,
		             _("Failed to decrypt the private key: unexpected padding length."));
		return NULL;
	}

	/* Validate tail padding; last byte is the padding size, and all pad bytes
	 * should contain the padding size.
	 */
	for (pad_i = 1; pad_i <= pad_len; ++pad_i) {
		if (output.bin[data_len - pad_i] != pad_len) {
			g_set_error (error, NM_CRYPTO_ERROR,
			             NM_CRYPTO_ERROR_DECRYPTION_FAILED,
			             _("Failed to decrypt the private key."));
			return NULL;
		}
	}

	*out_len = output.len - pad_len;
	return g_steal_pointer (&output.bin);
}

guint8 *
_nmtst_crypto_encrypt (NMCryptoCipherType cipher,
                       const guint8 *data,
                       gsize data_len,
                       const guint8 *iv,
                       gsize iv_len,
                       const guint8 *key,
                       gsize key_len,
                       gsize *out_len,
                       GError **error)
{
	gnutls_cipher_hd_t ctx;
	gnutls_datum_t key_dt, iv_dt;
	int err;
	int cipher_mech;
	nm_auto_clear_secret_ptr NMSecretPtr output = { 0 };
	nm_auto_clear_secret_ptr NMSecretPtr padded_buf = { 0 };
	gsize i, pad_len;

	nm_assert (iv_len);

	if (   cipher == NM_CRYPTO_CIPHER_DES_CBC
	    || !_get_cipher_info (cipher, &cipher_mech, NULL)) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_UNKNOWN_CIPHER,
		             _("Unsupported key cipher for encryption"));
		return NULL;
	}

	if (!_nm_crypto_init (error))
		return NULL;

	key_dt.data = (unsigned char *) key;
	key_dt.size = key_len;
	iv_dt.data = (unsigned char *) iv;
	iv_dt.size = iv_len;

	err = gnutls_cipher_init (&ctx, cipher_mech, &key_dt, &iv_dt);
	if (err < 0) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_ENCRYPTION_FAILED,
		             _("Failed to initialize the encryption cipher context: %s (%s)"),
		             gnutls_strerror_name (err), gnutls_strerror (err));
		return NULL;
	}

	/* If data_len % ivlen == 0, then we add another complete block
	 * onto the end so that the decrypter knows there's padding.
	 */
	pad_len = iv_len - (data_len % iv_len);

	padded_buf.len = data_len + pad_len;
	padded_buf.bin = g_malloc (padded_buf.len);
	memcpy (padded_buf.bin, data, data_len);
	for (i = 0; i < pad_len; i++)
		padded_buf.bin[data_len + i] = (guint8) (pad_len & 0xFF);

	output.len = padded_buf.len;
	output.bin = g_malloc (output.len);

	err = gnutls_cipher_encrypt2 (ctx, padded_buf.bin, padded_buf.len, output.bin, output.len);

	gnutls_cipher_deinit (ctx);

	if (err < 0) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_ENCRYPTION_FAILED,
		             _("Failed to encrypt the data: %s (%s)"),
		             gnutls_strerror_name (err), gnutls_strerror (err));
		return NULL;
	}

	*out_len = output.len;
	return g_steal_pointer (&output.bin);
}

gboolean
_nm_crypto_verify_x509 (const guint8 *data,
                        gsize len,
                        GError **error)
{
	gnutls_x509_crt_t der;
	gnutls_datum_t dt;
	int err;

	if (!_nm_crypto_init (error))
		return FALSE;

	err = gnutls_x509_crt_init (&der);
	if (err < 0) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_INVALID_DATA,
		             _("Error initializing certificate data: %s"),
		             gnutls_strerror (err));
		return FALSE;
	}

	/* Try DER first */
	dt.data = (unsigned char *) data;
	dt.size = len;
	err = gnutls_x509_crt_import (der, &dt, GNUTLS_X509_FMT_DER);
	if (err == GNUTLS_E_SUCCESS) {
		gnutls_x509_crt_deinit (der);
		return TRUE;
	}

	/* And PEM next */
	err = gnutls_x509_crt_import (der, &dt, GNUTLS_X509_FMT_PEM);
	gnutls_x509_crt_deinit (der);
	if (err == GNUTLS_E_SUCCESS)
		return TRUE;

	g_set_error (error, NM_CRYPTO_ERROR,
	             NM_CRYPTO_ERROR_INVALID_DATA,
	             _("Couldn't decode certificate: %s"),
	             gnutls_strerror (err));
	return FALSE;
}

gboolean
_nm_crypto_verify_pkcs12 (const guint8 *data,
                          gsize data_len,
                          const char *password,
                          GError **error)
{
	gnutls_pkcs12_t p12;
	gnutls_datum_t dt;
	int err;

	g_return_val_if_fail (data != NULL, FALSE);

	if (!_nm_crypto_init (error))
		return FALSE;

	dt.data = (unsigned char *) data;
	dt.size = data_len;

	err = gnutls_pkcs12_init (&p12);
	if (err < 0) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_FAILED,
		             _("Couldn't initialize PKCS#12 decoder: %s"),
		             gnutls_strerror (err));
		return FALSE;
	}

	/* DER first */
	err = gnutls_pkcs12_import (p12, &dt, GNUTLS_X509_FMT_DER, 0);
	if (err < 0) {
		/* PEM next */
		err = gnutls_pkcs12_import (p12, &dt, GNUTLS_X509_FMT_PEM, 0);
		if (err < 0) {
			g_set_error (error, NM_CRYPTO_ERROR,
			             NM_CRYPTO_ERROR_INVALID_DATA,
			             _("Couldn't decode PKCS#12 file: %s"),
			             gnutls_strerror (err));
			gnutls_pkcs12_deinit (p12);
			return FALSE;
		}
	}

	err = gnutls_pkcs12_verify_mac (p12, password);

	gnutls_pkcs12_deinit (p12);

	if (err != GNUTLS_E_SUCCESS) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_DECRYPTION_FAILED,
		             _("Couldn't verify PKCS#12 file: %s"),
		             gnutls_strerror (err));
		return FALSE;
	}

	return TRUE;
}

gboolean
_nm_crypto_verify_pkcs8 (const guint8 *data,
                         gsize data_len,
                         gboolean is_encrypted,
                         const char *password,
                         GError **error)
{
	gnutls_x509_privkey_t p8;
	gnutls_datum_t dt;
	int err;

	g_return_val_if_fail (data != NULL, FALSE);

	if (!_nm_crypto_init (error))
		return FALSE;

	err = gnutls_x509_privkey_init (&p8);
	if (err < 0) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_FAILED,
		             _("Couldn't initialize PKCS#8 decoder: %s"),
		             gnutls_strerror (err));
		return FALSE;
	}

	dt.data = (unsigned char *) data;
	dt.size = data_len;

	err = gnutls_x509_privkey_import_pkcs8 (p8,
	                                        &dt,
	                                        GNUTLS_X509_FMT_DER,
	                                        is_encrypted ? password : NULL,
	                                        is_encrypted ? 0 : GNUTLS_PKCS_PLAIN);

	gnutls_x509_privkey_deinit (p8);

	if (err < 0) {
		if (err == GNUTLS_E_UNKNOWN_CIPHER_TYPE) {
			/* HACK: gnutls < 3.5.4 doesn't support all the cipher types that openssl
			 * can use with PKCS#8, so if we encounter one, we have to assume
			 * the given password works.  gnutls needs to unsuckify, apparently.
			 * Specifically, by default openssl uses pbeWithMD5AndDES-CBC
			 * which gnutls does not support.
			 */
		} else {
			g_set_error (error, NM_CRYPTO_ERROR,
			             NM_CRYPTO_ERROR_INVALID_DATA,
			             _("Couldn't decode PKCS#8 file: %s"),
			             gnutls_strerror (err));
			return FALSE;
		}
	}

	return TRUE;
}

gboolean
_nm_crypto_randomize (void *buffer, gsize buffer_len, GError **error)
{
	if (!_nm_crypto_init (error))
		return FALSE;

	gnutls_rnd (GNUTLS_RND_RANDOM, buffer, buffer_len);
	return TRUE;
}
