/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

/*
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
 * Copyright 2007 - 2009 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-crypto-impl.h"

#include <prinit.h>
#include <nss.h>
#include <pk11pub.h>
#include <pkcs11t.h>
#include <cert.h>
#include <prerror.h>
#include <p12.h>
#include <ciferfam.h>
#include <p12plcy.h>

#include "nm-utils/nm-secret-utils.h"
#include "nm-errors.h"

static gboolean initialized = FALSE;

gboolean
_nm_crypto_init (GError **error)
{
	SECStatus ret;

	if (initialized)
		return TRUE;

	PR_Init(PR_USER_THREAD, PR_PRIORITY_NORMAL, 1);
	ret = NSS_NoDB_Init (NULL);
	if (ret != SECSuccess) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_FAILED,
		             _("Failed to initialize the crypto engine: %d."),
		             PR_GetError ());
		PR_Cleanup ();
		return FALSE;
	}

	SEC_PKCS12EnableCipher(PKCS12_RC4_40, 1);
	SEC_PKCS12EnableCipher(PKCS12_RC4_128, 1);
	SEC_PKCS12EnableCipher(PKCS12_RC2_CBC_40, 1);
	SEC_PKCS12EnableCipher(PKCS12_RC2_CBC_128, 1);
	SEC_PKCS12EnableCipher(PKCS12_DES_56, 1);
	SEC_PKCS12EnableCipher(PKCS12_DES_EDE3_168, 1);
	SEC_PKCS12SetPreferredCipher(PKCS12_DES_EDE3_168, 1);

	initialized = TRUE;
	return TRUE;
}

char *
_nm_crypto_decrypt (const char *cipher,
                    int key_type,
                    const guint8 *data,
                    gsize data_len,
                    const char *iv,
                    const gsize iv_len,
                    const char *key,
                    const gsize key_len,
                    gsize *out_len,
                    GError **error)
{
	char *output = NULL;
	int decrypted_len = 0;
	CK_MECHANISM_TYPE cipher_mech;
	PK11SlotInfo *slot = NULL;
	SECItem key_item;
	PK11SymKey *sym_key = NULL;
	SECItem *sec_param = NULL;
	PK11Context *ctx = NULL;
	SECStatus s;
	gboolean success = FALSE;
	unsigned pad_len = 0, extra = 0;
	guint32 i, real_iv_len = 0;

	if (!_nm_crypto_init (error))
		return NULL;

	if (!strcmp (cipher, CIPHER_DES_EDE3_CBC)) {
		cipher_mech = CKM_DES3_CBC_PAD;
		real_iv_len = 8;
	} else if (!strcmp (cipher, CIPHER_DES_CBC)) {
		cipher_mech = CKM_DES_CBC_PAD;
		real_iv_len = 8;
	} else if (NM_IN_STRSET (cipher, CIPHER_AES_128_CBC,
	                                 CIPHER_AES_192_CBC,
	                                 CIPHER_AES_256_CBC)) {
		cipher_mech = CKM_AES_CBC_PAD;
		real_iv_len = 16;
	} else {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_UNKNOWN_CIPHER,
		             _("Private key cipher '%s' was unknown."),
		             cipher);
		return NULL;
	}

	if (iv_len < real_iv_len) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_INVALID_DATA,
		             _("Invalid IV length (must be at least %d)."),
		             real_iv_len);
		return NULL;
	}

	output = g_malloc0 (data_len);

	slot = PK11_GetBestSlot (cipher_mech, NULL);
	if (!slot) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_FAILED,
		             _("Failed to initialize the decryption cipher slot."));
		goto out;
	}

	key_item.data = (unsigned char *) key;
	key_item.len = key_len;
	sym_key = PK11_ImportSymKey (slot, cipher_mech, PK11_OriginUnwrap, CKA_DECRYPT, &key_item, NULL);
	if (!sym_key) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_DECRYPTION_FAILED,
		             _("Failed to set symmetric key for decryption."));
		goto out;
	}

	key_item.data = (unsigned char *) iv;
	key_item.len = real_iv_len;
	sec_param = PK11_ParamFromIV (cipher_mech, &key_item);
	if (!sec_param) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_DECRYPTION_FAILED,
		             _("Failed to set IV for decryption."));
		goto out;
	}

	ctx = PK11_CreateContextBySymKey (cipher_mech, CKA_DECRYPT, sym_key, sec_param);
	if (!ctx) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_DECRYPTION_FAILED,
		             _("Failed to initialize the decryption context."));
		goto out;
	}

	s = PK11_CipherOp (ctx,
	                   (unsigned char *) output,
	                   &decrypted_len,
	                   data_len,
	                   data,
	                   data_len);
	if (s != SECSuccess) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_DECRYPTION_FAILED,
		             _("Failed to decrypt the private key: %d."),
		             PORT_GetError ());
		goto out;
	}

	if (decrypted_len > data_len) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_DECRYPTION_FAILED,
		             _("Failed to decrypt the private key: decrypted data too large."));
		goto out;
	}

	s = PK11_DigestFinal (ctx,
	                      (unsigned char *) (output + decrypted_len),
	                      &extra,
	                      data_len - decrypted_len);
	if (s != SECSuccess) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_DECRYPTION_FAILED,
		             _("Failed to finalize decryption of the private key: %d."),
		             PORT_GetError ());
		goto out;
	}
	decrypted_len += extra;
	pad_len = data_len - decrypted_len;

	/* Check if the padding at the end of the decrypted data is valid */
	if (pad_len == 0 || pad_len > real_iv_len) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_DECRYPTION_FAILED,
		             _("Failed to decrypt the private key: unexpected padding length."));
		goto out;
	}

	/* Validate tail padding; last byte is the padding size, and all pad bytes
	 * should contain the padding size.
	 */
	for (i = pad_len; i > 0; i--) {
		if (output[data_len - i] != pad_len) {
			g_set_error (error, NM_CRYPTO_ERROR,
			             NM_CRYPTO_ERROR_DECRYPTION_FAILED,
			             _("Failed to decrypt the private key."));
			goto out;
		}
	}

	*out_len = decrypted_len;
	success = TRUE;

out:
	if (ctx)
		PK11_DestroyContext (ctx, PR_TRUE);
	if (sym_key)
		PK11_FreeSymKey (sym_key);
	if (sec_param)
		SECITEM_FreeItem (sec_param, PR_TRUE);
	if (slot)
		PK11_FreeSlot (slot);

	if (!success) {
		if (output) {
			nm_explicit_bzero (output, data_len);
			g_free (output);
			output = NULL;
		}
	}
	return output;
}

char *
_nm_crypto_encrypt (const char *cipher,
                    const guint8 *data,
                    gsize data_len,
                    const char *iv,
                    gsize iv_len,
                    const char *key,
                    gsize key_len,
                    gsize *out_len,
                    GError **error)
{
	SECStatus ret;
	CK_MECHANISM_TYPE cipher_mech = CKM_DES3_CBC_PAD;
	PK11SlotInfo *slot = NULL;
	SECItem key_item = { .data = (unsigned char *) key, .len = key_len };
	SECItem iv_item = { .data = (unsigned char *) iv, .len = iv_len };
	PK11SymKey *sym_key = NULL;
	SECItem *sec_param = NULL;
	PK11Context *ctx = NULL;
	unsigned char *output, *padded_buf;
	gsize output_len;
	int encrypted_len = 0, i;
	gboolean success = FALSE;
	gsize padded_buf_len, pad_len;

	if (!_nm_crypto_init (error))
		return NULL;

	if (!strcmp (cipher, CIPHER_DES_EDE3_CBC))
		cipher_mech = CKM_DES3_CBC_PAD;
	else if (NM_IN_STRSET (cipher,
	                       CIPHER_AES_128_CBC,
	                       CIPHER_AES_192_CBC,
	                       CIPHER_AES_256_CBC))
		cipher_mech = CKM_AES_CBC_PAD;
	else {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_UNKNOWN_CIPHER,
		             _("Private key cipher '%s' was unknown."),
		             cipher);
		return NULL;
	}

	/* If data->len % ivlen == 0, then we add another complete block
	 * onto the end so that the decrypter knows there's padding.
	 */
	pad_len = iv_len - (data_len % iv_len);
	output_len = padded_buf_len = data_len + pad_len;
	padded_buf = g_malloc0 (padded_buf_len);

	memcpy (padded_buf, data, data_len);
	for (i = 0; i < pad_len; i++)
		padded_buf[data_len + i] = (guint8) (pad_len & 0xFF);

	output = g_malloc0 (output_len);

	slot = PK11_GetBestSlot (cipher_mech, NULL);
	if (!slot) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_FAILED,
		             _("Failed to initialize the encryption cipher slot."));
		goto out;
	}

	sym_key = PK11_ImportSymKey (slot, cipher_mech, PK11_OriginUnwrap, CKA_ENCRYPT, &key_item, NULL);
	if (!sym_key) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_ENCRYPTION_FAILED,
		             _("Failed to set symmetric key for encryption."));
		goto out;
	}

	sec_param = PK11_ParamFromIV (cipher_mech, &iv_item);
	if (!sec_param) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_ENCRYPTION_FAILED,
		             _("Failed to set IV for encryption."));
		goto out;
	}

	ctx = PK11_CreateContextBySymKey (cipher_mech, CKA_ENCRYPT, sym_key, sec_param);
	if (!ctx) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_ENCRYPTION_FAILED,
		             _("Failed to initialize the encryption context."));
		goto out;
	}

	ret = PK11_CipherOp (ctx, output, &encrypted_len, output_len, padded_buf, padded_buf_len);
	if (ret != SECSuccess) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_ENCRYPTION_FAILED,
		             _("Failed to encrypt: %d."),
		             PORT_GetError ());
		goto out;
	}

	if (encrypted_len != output_len) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_ENCRYPTION_FAILED,
		             _("Unexpected amount of data after encrypting."));
		goto out;
	}

	*out_len = encrypted_len;
	success = TRUE;

out:
	if (ctx)
		PK11_DestroyContext (ctx, PR_TRUE);
	if (sym_key)
		PK11_FreeSymKey (sym_key);
	if (sec_param)
		SECITEM_FreeItem (sec_param, PR_TRUE);
	if (slot)
		PK11_FreeSlot (slot);

	nm_explicit_bzero (padded_buf, padded_buf_len);
	g_free (padded_buf);

	if (!success) {
		nm_explicit_bzero (output, output_len);
		g_free (output);
		output = NULL;
	}
	return (char *) output;
}

gboolean
_nm_crypto_verify_x509 (const unsigned char *data,
                        gsize len,
                        GError **error)
{
	CERTCertificate *cert;

	if (!_nm_crypto_init (error))
		return FALSE;

	/* Try DER/PEM first */
	cert = CERT_DecodeCertFromPackage ((char *) data, len);
	if (!cert) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_INVALID_DATA,
		             _("Couldn't decode certificate: %d"),
		             PORT_GetError());
		return FALSE;
	}

	CERT_DestroyCertificate (cert);
	return TRUE;
}

gboolean
_nm_crypto_verify_pkcs12 (const guint8 *data,
                          gsize data_len,
                          const char *password,
                          GError **error)
{
	SEC_PKCS12DecoderContext *p12ctx = NULL;
	SECItem pw = { 0 };
	PK11SlotInfo *slot = NULL;
	SECStatus s;
	gunichar2 *ucs2_password;
	long ucs2_chars = 0;
#ifndef WORDS_BIGENDIAN
	guint16 *p;
#endif /* WORDS_BIGENDIAN */

	if (error)
		g_return_val_if_fail (*error == NULL, FALSE);

	if (!_nm_crypto_init (error))
		return FALSE;

	/* PKCS#12 passwords are apparently UCS2 BIG ENDIAN, and NSS doesn't do
	 * any conversions for us.
	 */
	if (password && *password) {
		if (!g_utf8_validate (password, -1, NULL)) {
			g_set_error (error, NM_CRYPTO_ERROR,
			             NM_CRYPTO_ERROR_INVALID_PASSWORD,
			             _("Password must be UTF-8"));
			return FALSE;
		}
		ucs2_password = g_utf8_to_utf16 (password, strlen (password), NULL, &ucs2_chars, NULL);
		/* Can't fail if g_utf8_validate() succeeded */
		g_return_val_if_fail (ucs2_password != NULL && ucs2_chars != 0, FALSE);

		ucs2_chars *= 2;  /* convert # UCS2 characters -> bytes */
		pw.data = PORT_ZAlloc(ucs2_chars + 2);
		memcpy (pw.data, ucs2_password, ucs2_chars);
		pw.len = ucs2_chars + 2;  /* include terminating NULL */

		nm_explicit_bzero (ucs2_password, ucs2_chars);
		g_free (ucs2_password);

#ifndef WORDS_BIGENDIAN
		for (p = (guint16 *) pw.data; p < (guint16 *) (pw.data + pw.len); p++)
			*p = GUINT16_SWAP_LE_BE (*p);
#endif /* WORDS_BIGENDIAN */
	} else {
		/* NULL password */
		pw.data = NULL;
		pw.len = 0;
	}

	slot = PK11_GetInternalKeySlot();
	p12ctx = SEC_PKCS12DecoderStart (&pw, slot, NULL, NULL, NULL, NULL, NULL, NULL);
	if (!p12ctx) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_FAILED,
		             _("Couldn't initialize PKCS#12 decoder: %d"),
		             PORT_GetError());
		goto error;
	}

	s = SEC_PKCS12DecoderUpdate (p12ctx, (guint8 *)data, data_len);
	if (s != SECSuccess) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_INVALID_DATA,
		             _("Couldn't decode PKCS#12 file: %d"),
		             PORT_GetError());
		goto error;
	}

	s = SEC_PKCS12DecoderVerify (p12ctx);
	if (s != SECSuccess) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_DECRYPTION_FAILED,
		             _("Couldn't verify PKCS#12 file: %d"),
		             PORT_GetError());
		goto error;
	}

	SEC_PKCS12DecoderFinish (p12ctx);
	SECITEM_ZfreeItem (&pw, PR_FALSE);
	return TRUE;

error:
	if (p12ctx)
		SEC_PKCS12DecoderFinish (p12ctx);

	if (slot)
		PK11_FreeSlot(slot);

	SECITEM_ZfreeItem (&pw, PR_FALSE);
	return FALSE;
}

gboolean
_nm_crypto_verify_pkcs8 (const guint8 *data,
                         gsize data_len,
                         gboolean is_encrypted,
                         const char *password,
                         GError **error)
{
	g_return_val_if_fail (data != NULL, FALSE);

	if (!_nm_crypto_init (error))
		return FALSE;

	/* NSS apparently doesn't do PKCS#8 natively, but you have to put the
	 * PKCS#8 key into a PKCS#12 file and import that??  So until we figure
	 * all that out, we can only assume the password is valid.
	 */
	return TRUE;
}

gboolean
_nm_crypto_randomize (void *buffer, gsize buffer_len, GError **error)
{
	SECStatus s;

	if (!_nm_crypto_init (error))
		return FALSE;

	s = PK11_GenerateRandom (buffer, buffer_len);
	if (s != SECSuccess) {
		g_set_error_literal (error, NM_CRYPTO_ERROR,
		                     NM_CRYPTO_ERROR_FAILED,
		                     _("Could not generate random data."));
		return FALSE;
	}
	return TRUE;
}
