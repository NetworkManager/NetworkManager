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

#include "nm-glib-aux/nm-secret-utils.h"
#include "nm-errors.h"

/*****************************************************************************/

static gboolean
_get_cipher_info (NMCryptoCipherType cipher,
                  CK_MECHANISM_TYPE *out_cipher_mech,
                  guint8 *out_real_iv_len)
{
	static const CK_MECHANISM_TYPE cipher_mechs[] = {
		[NM_CRYPTO_CIPHER_DES_EDE3_CBC] = CKM_DES3_CBC_PAD,
		[NM_CRYPTO_CIPHER_DES_CBC]      = CKM_DES_CBC_PAD,
		[NM_CRYPTO_CIPHER_AES_128_CBC]  = CKM_AES_CBC_PAD,
		[NM_CRYPTO_CIPHER_AES_192_CBC]  = CKM_AES_CBC_PAD,
		[NM_CRYPTO_CIPHER_AES_256_CBC]  = CKM_AES_CBC_PAD,
	};

	g_return_val_if_fail (_NM_INT_NOT_NEGATIVE (cipher) && (gsize) cipher < G_N_ELEMENTS (cipher_mechs), FALSE);

	if (!cipher_mechs[cipher])
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
	SECStatus ret;

	if (initialized)
		return TRUE;

	PR_Init (PR_USER_THREAD, PR_PRIORITY_NORMAL, 1);
	ret = NSS_NoDB_Init (NULL);
	if (ret != SECSuccess) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_FAILED,
		             _("Failed to initialize the crypto engine: %d."),
		             PR_GetError ());
		PR_Cleanup ();
		return FALSE;
	}

	SEC_PKCS12EnableCipher (PKCS12_RC4_40, 1);
	SEC_PKCS12EnableCipher (PKCS12_RC4_128, 1);
	SEC_PKCS12EnableCipher (PKCS12_RC2_CBC_40, 1);
	SEC_PKCS12EnableCipher (PKCS12_RC2_CBC_128, 1);
	SEC_PKCS12EnableCipher (PKCS12_DES_56, 1);
	SEC_PKCS12EnableCipher (PKCS12_DES_EDE3_168, 1);
	SEC_PKCS12SetPreferredCipher (PKCS12_DES_EDE3_168, 1);

	initialized = TRUE;
	return TRUE;
}

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
	CK_MECHANISM_TYPE cipher_mech;
	PK11SlotInfo *slot = NULL;
	SECItem key_item;
	PK11SymKey *sym_key = NULL;
	SECItem *sec_param = NULL;
	PK11Context *ctx = NULL;
	nm_auto_clear_secret_ptr NMSecretPtr output = { 0 };
	SECStatus s;
	gboolean success = FALSE;
	int decrypted_len = 0;
	unsigned extra = 0;
	unsigned pad_len = 0;
	guint32 i;
	guint8 real_iv_len;

	if (!_get_cipher_info (cipher, &cipher_mech, &real_iv_len)) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_UNKNOWN_CIPHER,
		             _("Unsupported key cipher for decryption"));
		return NULL;
	}

	if (iv_len < real_iv_len) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_INVALID_DATA,
		             _("Invalid IV length (must be at least %u)."),
		             (guint) real_iv_len);
		return NULL;
	}

	if (!_nm_crypto_init (error))
		return NULL;

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

	output.len = data_len;
	output.bin = g_malloc (data_len);

	s = PK11_CipherOp (ctx,
	                   (unsigned char *) output.bin,
	                   &decrypted_len,
	                   output.len,
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
	                      (unsigned char *) &output.bin[decrypted_len],
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
		if (output.bin[data_len - i] != pad_len) {
			g_set_error (error, NM_CRYPTO_ERROR,
			             NM_CRYPTO_ERROR_DECRYPTION_FAILED,
			             _("Failed to decrypt the private key."));
			goto out;
		}
	}

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

	if (!success)
		return NULL;

	if (decrypted_len < output.len)
		nm_explicit_bzero (&output.bin[decrypted_len], output.len - decrypted_len);
	*out_len = decrypted_len;
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
	SECStatus ret;
	CK_MECHANISM_TYPE cipher_mech = CKM_DES3_CBC_PAD;
	PK11SlotInfo *slot = NULL;
	SECItem key_item = { .data = (unsigned char *) key, .len = key_len };
	SECItem iv_item = { .data = (unsigned char *) iv, .len = iv_len };
	PK11SymKey *sym_key = NULL;
	SECItem *sec_param = NULL;
	PK11Context *ctx = NULL;
	nm_auto_clear_secret_ptr NMSecretPtr padded_buf = { 0 };
	nm_auto_clear_secret_ptr NMSecretPtr output = { 0 };
	int encrypted_len = 0, i;
	gboolean success = FALSE;
	gsize pad_len;

	if (   cipher == NM_CRYPTO_CIPHER_DES_CBC
	    || !_get_cipher_info (cipher, &cipher_mech, NULL)) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_UNKNOWN_CIPHER,
		             _("Unsupported key cipher for encryption"));
		return NULL;
	}

	if (!_nm_crypto_init (error))
		return NULL;

	slot = PK11_GetBestSlot (cipher_mech, NULL);
	if (!slot) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_FAILED,
		             _("Failed to initialize the encryption cipher slot."));
		return NULL;
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

	/* If data->len % ivlen == 0, then we add another complete block
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

	ret = PK11_CipherOp (ctx, output.bin, &encrypted_len, output.len, padded_buf.bin, padded_buf.len);
	if (ret != SECSuccess) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_ENCRYPTION_FAILED,
		             _("Failed to encrypt: %d."),
		             PORT_GetError ());
		goto out;
	}

	if (encrypted_len != output.len) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_ENCRYPTION_FAILED,
		             _("Unexpected amount of data after encrypting."));
		goto out;
	}

	success = TRUE;

out:
	if (ctx)
		PK11_DestroyContext (ctx, PR_TRUE);
	if (sec_param)
		SECITEM_FreeItem (sec_param, PR_TRUE);
	if (sym_key)
		PK11_FreeSymKey (sym_key);
	if (slot)
		PK11_FreeSlot (slot);

	if (!success)
		return NULL;

	*out_len = output.len;
	return g_steal_pointer (&output.bin);
}

gboolean
_nm_crypto_verify_x509 (const guint8 *data,
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
		             PORT_GetError ());
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
	gboolean success = FALSE;

	g_return_val_if_fail (!error || !*error, FALSE);

	if (!_nm_crypto_init (error))
		return FALSE;

	/* PKCS#12 passwords are apparently UCS2 BIG ENDIAN, and NSS doesn't do
	 * any conversions for us.
	 */
	if (password && *password) {
		nm_auto_clear_secret_ptr NMSecretPtr ucs2_password = { 0 };

		if (g_utf8_validate (password, -1, NULL)) {
			long ucs2_chars;

			ucs2_password.bin = (guint8 *) g_utf8_to_utf16 (password, strlen (password), NULL, &ucs2_chars, NULL);

			/* cannot fail, because password is valid UTF-8*/
			nm_assert (ucs2_password.bin && ucs2_chars > 0);

			ucs2_password.len = ucs2_chars * 2;
		}

		if (!ucs2_password.bin || ucs2_password.len == 0) {
			g_set_error (error, NM_CRYPTO_ERROR,
			             NM_CRYPTO_ERROR_INVALID_PASSWORD,
			             _("Password must be UTF-8"));
			return FALSE;
		}

		pw.data = PORT_ZAlloc (ucs2_password.len + 2);
		memcpy (pw.data, ucs2_password.bin, ucs2_password.len);
		pw.len = ucs2_password.len + 2;

#if __BYTE_ORDER == __LITTLE_ENDIAN
		{
			guint16 *p, *p_end;

			p_end = (guint16 *) &(((guint8 *) pw.data)[ucs2_password.len]);
			for (p = (guint16 *) pw.data; p < p_end; p++)
				*p = GUINT16_SWAP_LE_BE (*p);
		}
#endif
	}

	slot = PK11_GetInternalKeySlot ();
	if (!slot) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_FAILED,
		             _("Couldn't initialize slot"));
		goto out;
	}

	p12ctx = SEC_PKCS12DecoderStart (&pw, slot, NULL, NULL, NULL, NULL, NULL, NULL);
	if (!p12ctx) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_FAILED,
		             _("Couldn't initialize PKCS#12 decoder: %d"),
		             PORT_GetError ());
		goto out;
	}

	s = SEC_PKCS12DecoderUpdate (p12ctx, (guint8 *)data, data_len);
	if (s != SECSuccess) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_INVALID_DATA,
		             _("Couldn't decode PKCS#12 file: %d"),
		             PORT_GetError ());
		goto out;
	}

	s = SEC_PKCS12DecoderVerify (p12ctx);
	if (s != SECSuccess) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_DECRYPTION_FAILED,
		             _("Couldn't verify PKCS#12 file: %d"),
		             PORT_GetError ());
		goto out;
	}

	success = TRUE;

out:
	if (p12ctx)
		SEC_PKCS12DecoderFinish (p12ctx);
	if (slot)
		PK11_FreeSlot (slot);

	if (pw.data)
		SECITEM_ZfreeItem (&pw, PR_FALSE);

	return success;
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
