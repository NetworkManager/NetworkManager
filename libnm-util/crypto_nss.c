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
 * (C) Copyright 2007 - 2008 Red Hat, Inc.
 */

#include "config.h"

#include <glib.h>
#include <glib/gi18n.h>

#include <prinit.h>
#include <nss.h>
#include <pk11pub.h>
#include <pkcs11t.h>
#include <cert.h>
#include <prerror.h>
#include <p12.h>
#include <ciferfam.h>
#include <p12plcy.h>

#include "crypto.h"

static gboolean initialized = FALSE;

gboolean
crypto_init (GError **error)
{
	SECStatus ret;

	if (initialized)
		return TRUE;

	PR_Init(PR_USER_THREAD, PR_PRIORITY_NORMAL, 1);
	ret = NSS_NoDB_Init (NULL);
	if (ret != SECSuccess) {
		PR_Cleanup ();
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_INIT_FAILED,
		             _("Failed to initialize the crypto engine: %d."),
		             PR_GetError ());
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

void
crypto_deinit (void)
{
	if (initialized) {
		NSS_Shutdown ();
		PR_Cleanup ();
	}
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
	PK11Context *ctx;
	int nkey = buflen;
	unsigned int digest_len;
	int count = 0;
	char digest[MD5_HASH_LEN];
	char *p = buffer;

	if (salt)
		g_return_val_if_fail (salt_len >= 8, FALSE);

	g_return_val_if_fail (password != NULL, FALSE);
	g_return_val_if_fail (password_len > 0, FALSE);
	g_return_val_if_fail (buffer != NULL, FALSE);
	g_return_val_if_fail (buflen > 0, FALSE);

	ctx = PK11_CreateDigestContext (SEC_OID_MD5);
	if (!ctx) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_MD5_INIT_FAILED,
		             _("Failed to initialize the MD5 context: %d."),
		             PORT_GetError ());
		return FALSE;
	}

	while (nkey > 0) {
		int i = 0;

		PK11_DigestBegin (ctx);
		if (count++)
			PK11_DigestOp (ctx, (const unsigned char *) digest, digest_len);
		PK11_DigestOp (ctx, (const unsigned char *) password, password_len);
		if (salt)
			PK11_DigestOp (ctx, (const unsigned char *) salt, 8); /* Only use 8 bytes of salt */
		PK11_DigestFinal (ctx, (unsigned char *) digest, &digest_len, sizeof (digest));

		while (nkey && (i < digest_len)) {
			*(p++) = digest[i++];
			nkey--;
		}
	}

	memset (digest, 0, sizeof (digest));
	PK11_DestroyContext (ctx, PR_TRUE);
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
	char *output = NULL;
	int tmp1_len = 0;
	unsigned int tmp2_len = 0;
	CK_MECHANISM_TYPE cipher_mech;
	PK11SlotInfo *slot = NULL;
	SECItem key_item;
	PK11SymKey *sym_key = NULL;
	SECItem *sec_param = NULL;
	PK11Context *ctx = NULL;
	SECStatus s;
	gboolean success = FALSE;
	gsize len;

	if (!strcmp (cipher, CIPHER_DES_EDE3_CBC))
		cipher_mech = CKM_DES3_CBC_PAD;
	else if (!strcmp (cipher, CIPHER_DES_CBC))
		cipher_mech = CKM_DES_CBC_PAD;
	else {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_UNKNOWN_CIPHER,
		             _("Private key cipher '%s' was unknown."),
		             cipher);
		return NULL;
	}

	output = g_malloc0 (data->len + 1);
	if (!output) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_OUT_OF_MEMORY,
		             _("Not enough memory for decrypted key buffer."));
		return NULL;
	}

	slot = PK11_GetBestSlot (cipher_mech, NULL);
	if (!slot) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_CIPHER_INIT_FAILED,
		             _("Failed to initialize the decryption cipher slot."));
		goto out;
	}

	key_item.data = (unsigned char *) key;
	key_item.len = key_len;
	sym_key = PK11_ImportSymKey (slot, cipher_mech, PK11_OriginUnwrap, CKA_DECRYPT, &key_item, NULL);
	if (!sym_key) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_CIPHER_SET_KEY_FAILED,
		             _("Failed to set symmetric key for decryption."));
		goto out;
	}

	key_item.data = (unsigned char *) iv;
	key_item.len = iv_len;
	sec_param = PK11_ParamFromIV (cipher_mech, &key_item);
	if (!sec_param) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_CIPHER_SET_IV_FAILED,
		             _("Failed to set IV for decryption."));
		goto out;
	}

	ctx = PK11_CreateContextBySymKey (cipher_mech, CKA_DECRYPT, sym_key, sec_param);
	if (!ctx) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_CIPHER_INIT_FAILED,
		             _("Failed to initialize the decryption context."));
		goto out;
	}

	s = PK11_CipherOp (ctx,
	                   (unsigned char *) output,
	                   &tmp1_len,
	                   data->len,
	                   data->data,
	                   data->len);
	if (s != SECSuccess) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_CIPHER_DECRYPT_FAILED,
		             _("Failed to decrypt the private key: %d."),
		             PORT_GetError ());
		goto out;
	}

	s = PK11_DigestFinal (ctx,
	                      (unsigned char *) (output + tmp1_len),
	                      &tmp2_len,
	                      data->len - tmp1_len);
	if (s != SECSuccess) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_CIPHER_DECRYPT_FAILED,
		             _("Failed to finalize decryption of the private key: %d."),
		             PORT_GetError ());
		goto out;
	}
	len = tmp1_len + tmp2_len;
	if (len > data->len)
		goto out;

	*out_len = len;
	output[*out_len] = '\0';
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
			/* Don't expose key material */
			memset (output, 0, data->len);
			g_free (output);
			output = NULL;
		}
	}
	return output;
}

NMCryptoFileFormat
crypto_verify_cert (const unsigned char *data,
                    gsize len,
                    GError **error)
{
	CERTCertificate *cert;

	/* Try DER/PEM first */
	cert = CERT_DecodeCertFromPackage ((char *) data, len);
	if (!cert) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_CERT_FORMAT_INVALID,
		             _("Couldn't decode certificate: %d"),
		             PORT_GetError());
		return NM_CRYPTO_FILE_FORMAT_UNKNOWN;
	}

	CERT_DestroyCertificate (cert);
	return NM_CRYPTO_FILE_FORMAT_X509;
}

gboolean
crypto_verify_pkcs12 (const GByteArray *data,
                      const char *password,
                      GError **error)
{
	SEC_PKCS12DecoderContext *p12ctx = NULL;
	SECItem pw = { 0 };
	PK11SlotInfo *slot = NULL;
	SECStatus s;
	char *ucs2_password;
	glong ucs2_chars = 0;
#ifndef WORDS_BIGENDIAN
	guint16 *p;
#endif /* WORDS_BIGENDIAN */

	if (error)
		g_return_val_if_fail (*error == NULL, FALSE);

	/* PKCS#12 passwords are apparently UCS2 BIG ENDIAN, and NSS doesn't do
	 * any conversions for us.
	 */
	if (password && strlen (password)) {
		ucs2_password = (char *) g_utf8_to_utf16 (password, strlen (password), NULL, &ucs2_chars, NULL);
		if (!ucs2_password || !ucs2_chars) {
			g_set_error (error, NM_CRYPTO_ERROR,
			             NM_CRYPTO_ERR_INVALID_PASSWORD,
			             _("Couldn't convert password to UCS2: %d"),
			             PORT_GetError());
			return FALSE;
		}

		ucs2_chars *= 2;  /* convert # UCS2 characters -> bytes */
		pw.data = PORT_ZAlloc(ucs2_chars + 2);
		memcpy (pw.data, ucs2_password, ucs2_chars);
		pw.len = ucs2_chars + 2;  /* include terminating NULL */

		memset (ucs2_password, 0, ucs2_chars);
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
		             NM_CRYPTO_ERR_DECODE_FAILED,
		             _("Couldn't initialize PKCS#12 decoder: %d"),
		             PORT_GetError());
		goto error;
	}

	s = SEC_PKCS12DecoderUpdate (p12ctx, data->data, data->len);
	if (s != SECSuccess) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_FILE_FORMAT_INVALID,
		             _("Couldn't decode PKCS#12 file: %d"),
		             PORT_GetError());
		goto error;
	}

	s = SEC_PKCS12DecoderVerify (p12ctx);
	if (s != SECSuccess) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_CIPHER_DECRYPT_FAILED,
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

