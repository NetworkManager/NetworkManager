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
 * (C) Copyright 2007 - 2009 Red Hat, Inc.
 */

#include "config.h"
#include <glib.h>
#include <glib/gi18n.h>

#include <gcrypt.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/pkcs12.h>

#include "crypto.h"

#define SALT_LEN 8

static gboolean initialized = FALSE;

gboolean
crypto_init (GError **error)
{
	if (initialized)
		return TRUE;

	if (gnutls_global_init() != 0) {
		gnutls_global_deinit();
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_INIT_FAILED,
		             "%s",
		             _("Failed to initialize the crypto engine."));
		return FALSE;
	}

	initialized = TRUE;
	return TRUE;
}

void
crypto_deinit (void)
{
}

gboolean
crypto_md5_hash (const char *salt,
                 const gsize salt_len,
                 const char *password,
                 gsize password_len,
                 char *buffer,
                 gsize buflen,
                 GError **error)
{
	gcry_md_hd_t ctx;
	gcry_error_t err;
	int nkey = buflen;
	const gsize digest_len = 16;
	int count = 0;
	char digest[MD5_HASH_LEN];
	char *p = buffer;

	if (salt)
		g_return_val_if_fail (salt_len >= SALT_LEN, FALSE);

	g_return_val_if_fail (password != NULL, FALSE);
	g_return_val_if_fail (password_len > 0, FALSE);
	g_return_val_if_fail (buffer != NULL, FALSE);
	g_return_val_if_fail (buflen > 0, FALSE);

	err = gcry_md_open (&ctx, GCRY_MD_MD5, 0);
	if (err) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_MD5_INIT_FAILED,
		             _("Failed to initialize the MD5 engine: %s / %s."),
		             gcry_strsource (err), gcry_strerror (err));
		return FALSE;
	}

	while (nkey > 0) {
		int i = 0;

		if (count++)
			gcry_md_write (ctx, digest, digest_len);
		gcry_md_write (ctx, password, password_len);
		if (salt)
			gcry_md_write (ctx, salt, SALT_LEN); /* Only use 8 bytes of salt */
		gcry_md_final (ctx);
		memcpy (digest, gcry_md_read (ctx, 0), digest_len);
		gcry_md_reset (ctx);
		
		while (nkey && (i < digest_len)) {
			*(p++) = digest[i++];
			nkey--;
		}
	}

	memset (digest, 0, sizeof (digest));
	gcry_md_close (ctx);
	return TRUE;
}

char *
crypto_decrypt (const char *cipher,
                int key_type,
                GByteArray *data,
                const char *iv,
                const gsize iv_len,
                const char *key,
                const gsize key_len,
                gsize *out_len,
                GError **error)
{
	gcry_cipher_hd_t ctx;
	gcry_error_t err;
	int cipher_mech, i;
	char *output = NULL;
	gboolean success = FALSE;
	gsize pad_len, real_iv_len;

	if (!strcmp (cipher, CIPHER_DES_EDE3_CBC)) {
		cipher_mech = GCRY_CIPHER_3DES;
		real_iv_len = SALT_LEN;
	} else if (!strcmp (cipher, CIPHER_DES_CBC)) {
		cipher_mech = GCRY_CIPHER_DES;
		real_iv_len = SALT_LEN;
	} else if (!strcmp (cipher, CIPHER_AES_CBC)) {
		cipher_mech = GCRY_CIPHER_AES;
		real_iv_len = 16;
	} else {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_UNKNOWN_CIPHER,
		             _("Private key cipher '%s' was unknown."),
		             cipher);
		return NULL;
	}

	if (iv_len < real_iv_len) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_RAW_IV_INVALID,
		             _("Invalid IV length (must be at least %zd)."),
		             real_iv_len);
		return NULL;
	}

	output = g_malloc0 (data->len);

	err = gcry_cipher_open (&ctx, cipher_mech, GCRY_CIPHER_MODE_CBC, 0);
	if (err) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_CIPHER_INIT_FAILED,
		             _("Failed to initialize the decryption cipher context: %s / %s."),
		             gcry_strsource (err), gcry_strerror (err));
		goto out;
	}

	err = gcry_cipher_setkey (ctx, key, key_len);
	if (err) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_CIPHER_SET_KEY_FAILED,
		             _("Failed to set symmetric key for decryption: %s / %s."),
		             gcry_strsource (err), gcry_strerror (err));
		goto out;
	}

	err = gcry_cipher_setiv (ctx, iv, iv_len);
	if (err) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_CIPHER_SET_IV_FAILED,
		             _("Failed to set IV for decryption: %s / %s."),
		             gcry_strsource (err), gcry_strerror (err));
		goto out;
	}

	err = gcry_cipher_decrypt (ctx, output, data->len, data->data, data->len);
	if (err) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_CIPHER_DECRYPT_FAILED,
		             _("Failed to decrypt the private key: %s / %s."),
		             gcry_strsource (err), gcry_strerror (err));
		goto out;
	}
	pad_len = output[data->len - 1];

	/* Check if the padding at the end of the decrypted data is valid */
	if (pad_len == 0 || pad_len > real_iv_len) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_CIPHER_DECRYPT_FAILED,
		             _("Failed to decrypt the private key: unexpected padding length."));
		goto out;
	}

	/* Validate tail padding; last byte is the padding size, and all pad bytes
	 * should contain the padding size.
	 */
	for (i = 1; i <= pad_len; ++i) {
		if (output[data->len - i] != pad_len) {
			g_set_error (error, NM_CRYPTO_ERROR,
			             NM_CRYPTO_ERR_CIPHER_DECRYPT_FAILED,
			             _("Failed to decrypt the private key."));
			goto out;
		}
	}

	*out_len = data->len - pad_len;
	success = TRUE;

out:
	if (!success) {
		if (output) {
			/* Don't expose key material */
			memset (output, 0, data->len);
			g_free (output);
			output = NULL;
		}
	}
	gcry_cipher_close (ctx);
	return output;
}

char *
crypto_encrypt (const char *cipher,
                const GByteArray *data,
                const char *iv,
                const gsize iv_len,
                const char *key,
                gsize key_len,
                gsize *out_len,
                GError **error)
{
	gcry_cipher_hd_t ctx;
	gcry_error_t err;
	int cipher_mech;
	char *output = NULL;
	gboolean success = FALSE;
	gsize padded_buf_len, pad_len, output_len;
	char *padded_buf = NULL;
	guint32 i;
	gsize salt_len;

	if (!strcmp (cipher, CIPHER_DES_EDE3_CBC)) {
		cipher_mech = GCRY_CIPHER_3DES;
		salt_len = SALT_LEN;
	} else if (!strcmp (cipher, CIPHER_AES_CBC)) {
		cipher_mech = GCRY_CIPHER_AES;
		salt_len = iv_len;
	} else {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_UNKNOWN_CIPHER,
		             _("Private key cipher '%s' was unknown."),
		             cipher);
		return NULL;
	}

	/* If data->len % ivlen == 0, then we add another complete block
	 * onto the end so that the decrypter knows there's padding.
	 */
	pad_len = iv_len - (data->len % iv_len);
	output_len = padded_buf_len = data->len + pad_len;
	padded_buf = g_malloc0 (padded_buf_len);

	memcpy (padded_buf, data->data, data->len);
	for (i = 0; i < pad_len; i++)
		padded_buf[data->len + i] = (guint8) (pad_len & 0xFF);

	output = g_malloc0 (output_len);

	err = gcry_cipher_open (&ctx, cipher_mech, GCRY_CIPHER_MODE_CBC, 0);
	if (err) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_CIPHER_INIT_FAILED,
		             _("Failed to initialize the encryption cipher context: %s / %s."),
		             gcry_strsource (err), gcry_strerror (err));
		goto out;
	}

	err = gcry_cipher_setkey (ctx, key, key_len);
	if (err) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_CIPHER_SET_KEY_FAILED,
		             _("Failed to set symmetric key for encryption: %s / %s."),
		             gcry_strsource (err), gcry_strerror (err));
		goto out;
	}

	/* gcrypt only wants 8 bytes of the IV (same as the DES block length) */
	err = gcry_cipher_setiv (ctx, iv, salt_len);
	if (err) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_CIPHER_SET_IV_FAILED,
		             _("Failed to set IV for encryption: %s / %s."),
		             gcry_strsource (err), gcry_strerror (err));
		goto out;
	}

	err = gcry_cipher_encrypt (ctx, output, output_len, padded_buf, padded_buf_len);
	if (err) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_CIPHER_DECRYPT_FAILED,
		             _("Failed to encrypt the data: %s / %s."),
		             gcry_strsource (err), gcry_strerror (err));
		goto out;
	}

	*out_len = output_len;
	success = TRUE;

out:
	if (padded_buf) {
		memset (padded_buf, 0, padded_buf_len);
		g_free (padded_buf);
		padded_buf = NULL;
	}

	if (!success) {
		if (output) {
			/* Don't expose key material */
			memset (output, 0, output_len);
			g_free (output);
			output = NULL;
		}
	}
	gcry_cipher_close (ctx);
	return output;
}

NMCryptoFileFormat
crypto_verify_cert (const unsigned char *data,
                    gsize len,
                    GError **error)
{
	gnutls_x509_crt_t der;
	gnutls_datum dt;
	int err;

	err = gnutls_x509_crt_init (&der);
	if (err < 0) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_CERT_FORMAT_INVALID,
		             _("Error initializing certificate data: %s"),
		             gnutls_strerror (err));
		return NM_CRYPTO_FILE_FORMAT_UNKNOWN;
	}

	/* Try DER first */
	dt.data = (unsigned char *) data;
	dt.size = len;
	err = gnutls_x509_crt_import (der, &dt, GNUTLS_X509_FMT_DER);
	if (err == GNUTLS_E_SUCCESS) {
		gnutls_x509_crt_deinit (der);
		return NM_CRYPTO_FILE_FORMAT_X509;
	}

	/* And PEM next */
	err = gnutls_x509_crt_import (der, &dt, GNUTLS_X509_FMT_PEM);
	gnutls_x509_crt_deinit (der);
	if (err == GNUTLS_E_SUCCESS)
		return NM_CRYPTO_FILE_FORMAT_X509;

	g_set_error (error, NM_CRYPTO_ERROR,
	             NM_CRYPTO_ERR_CERT_FORMAT_INVALID,
	             _("Couldn't decode certificate: %s"),
	             gnutls_strerror (err));
	return NM_CRYPTO_FILE_FORMAT_UNKNOWN;
}

gboolean
crypto_verify_pkcs12 (const GByteArray *data,
                      const char *password,
                      GError **error)
{
	gnutls_pkcs12_t p12;
	gnutls_datum dt;
	gboolean success = FALSE;
	int err;

	g_return_val_if_fail (data != NULL, FALSE);

	dt.data = (unsigned char *) data->data;
	dt.size = data->len;

	err = gnutls_pkcs12_init (&p12);
	if (err < 0) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_DECODE_FAILED,
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
			             NM_CRYPTO_ERR_FILE_FORMAT_INVALID,
			             _("Couldn't decode PKCS#12 file: %s"),
			             gnutls_strerror (err));
			goto out;
		}
	}

	err = gnutls_pkcs12_verify_mac (p12, password);
	if (err == GNUTLS_E_SUCCESS)
		success = TRUE;
	else {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_CIPHER_DECRYPT_FAILED,
		             _("Couldn't verify PKCS#12 file: %s"),
		             gnutls_strerror (err));
	}

out:
	gnutls_pkcs12_deinit (p12);
	return success;
}

gboolean
crypto_verify_pkcs8 (const GByteArray *data,
                     gboolean is_encrypted,
                     const char *password,
                     GError **error)
{
	gnutls_x509_privkey_t p8;
	gnutls_datum dt;
	int err;

	g_return_val_if_fail (data != NULL, FALSE);

	dt.data = (unsigned char *) data->data;
	dt.size = data->len;

	err = gnutls_x509_privkey_init (&p8);
	if (err < 0) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_DECODE_FAILED,
		             _("Couldn't initialize PKCS#8 decoder: %s"),
		             gnutls_strerror (err));
		return FALSE;
	}

	err = gnutls_x509_privkey_import_pkcs8 (p8,
	                                        &dt,
	                                        GNUTLS_X509_FMT_DER,
	                                        is_encrypted ? password : NULL,
	                                        is_encrypted ? 0 : GNUTLS_PKCS_PLAIN);
	gnutls_x509_privkey_deinit (p8);

	if (err < 0) {
		if (err == GNUTLS_E_UNKNOWN_CIPHER_TYPE) {
			/* HACK: gnutls doesn't support all the cipher types that openssl
			 * can use with PKCS#8, so if we encounter one, we have to assume
			 * the given password works.  gnutls needs to unsuckify, apparently.
			 * Specifically, by default openssl uses pbeWithMD5AndDES-CBC
			 * which gnutls does not support.
			 */
		} else {
			g_set_error (error, NM_CRYPTO_ERROR,
				         NM_CRYPTO_ERR_FILE_FORMAT_INVALID,
				         _("Couldn't decode PKCS#8 file: %s"),
				         gnutls_strerror (err));
			return FALSE;
		}
	}

	return TRUE;
}

gboolean
crypto_randomize (void *buffer, gsize buffer_len, GError **error)
{
	gcry_randomize (buffer, buffer_len, GCRY_STRONG_RANDOM);
	return TRUE;
}

