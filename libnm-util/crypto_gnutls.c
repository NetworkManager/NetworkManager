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
 * (C) Copyright 2007 Red Hat, Inc.
 */

#include <glib.h>
#include <glib/gi18n.h>

#include <gcrypt.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include "crypto.h"

gboolean
crypto_init (GError **error)
{
	gnutls_global_init();
	return TRUE;
}

void
crypto_deinit (void)
{
	gnutls_global_deinit();
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

	g_return_val_if_fail (salt != NULL, FALSE);
	g_return_val_if_fail (salt_len >= 8, FALSE);
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
		gcry_md_write (ctx, salt, 8); /* Only use 8 bytes of salt */
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
                const char *data,
                gsize data_len,
                const char *iv,
                const gsize iv_len,
                const char *key,
                const gsize key_len,
                gsize *out_len,
                GError **error)
{
	gcry_cipher_hd_t ctx;
	gcry_error_t err;
	int cipher_mech;
	char *output = NULL;
	gboolean success = FALSE;
	gsize len;

	if (!strcmp (cipher, CIPHER_DES_EDE3_CBC))
		cipher_mech = GCRY_CIPHER_3DES;
	else if (!strcmp (cipher, CIPHER_DES_CBC))
		cipher_mech = GCRY_CIPHER_DES;
	else {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_UNKNOWN_CIPHER,
		             _("Private key cipher '%s' was unknown."),
		             cipher);
		return NULL;
	}

	output = g_malloc0 (data_len + 1);
	if (!output) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_OUT_OF_MEMORY,
		             _("Not enough memory for decrypted key buffer."));
		return NULL;
	}

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

	err = gcry_cipher_decrypt (ctx, output, data_len, data, data_len);
	if (err) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_CIPHER_DECRYPT_FAILED,
		             _("Failed to decrypt the private key: %s / %s."),
		             gcry_strsource (err), gcry_strerror (err));
		goto out;
	}
	len = data_len - output[data_len - 1];
	if (len > data_len)
		goto out;

	*out_len = len;
	output[*out_len] = '\0';
	success = TRUE;

out:
	if (!success) {
		if (output) {
			/* Don't expose key material */
			memset (output, 0, data_len);
			g_free (output);
			output = NULL;
		}
	}
	gcry_cipher_close (ctx);
	return output;
}

gboolean
crypto_verify_cert (const unsigned char *data,
                    gsize len,
                    GError **error)
{
	gnutls_x509_crt_t crt;
	gnutls_datum dt;
	int err;

	err = gnutls_x509_crt_init (&crt);
	if (err < 0) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_CERT_FORMAT_INVALID,
		             _("Error initializing certificate data: %s"),
		             gnutls_strerror (err));
		return FALSE;
	}

	dt.data = (unsigned char *) data;
	dt.size = len;

	err = gnutls_x509_crt_import (crt, &dt, GNUTLS_X509_FMT_DER);
	if (err < 0) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_CERT_FORMAT_INVALID,
		             _("Couldn't decode certificate: %s"),
		             gnutls_strerror (err));
		return FALSE;
	}

	gnutls_x509_crt_deinit (crt);
	return TRUE;
}

