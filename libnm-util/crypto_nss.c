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

#include <prinit.h>
#include <nss.h>
#include <pk11pub.h>
#include <pkcs11t.h>
#include <cert.h>

#include "crypto.h"


gboolean
crypto_init (GError **error)
{
	PR_Init(PR_USER_THREAD, PR_PRIORITY_NORMAL, 1);
	NSS_NoDB_Init (NULL);
	return TRUE;
}

void
crypto_deinit (void)
{
	NSS_Shutdown ();
	PR_Cleanup ();
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

	g_return_val_if_fail (salt != NULL, FALSE);
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
                const char *data,
                gsize data_len,
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

	output = g_malloc0 (data_len + 1);
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
	                   data_len,
	                   (unsigned char *) data,
	                   data_len);
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
	                      data_len - tmp1_len);
	if (s != SECSuccess) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_CIPHER_DECRYPT_FAILED,
		             _("Failed to finalize decryption of the private key: %d."),
		             PORT_GetError ());
		goto out;
	}
	len = tmp1_len + tmp2_len;
	if (len > data_len)
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
			memset (output, 0, data_len);
			g_free (output);
			output = NULL;
		}
	}
	return output;
}

gboolean
crypto_verify_cert (const unsigned char *data,
                    gsize len,
                    GError **error)
{
	CERTCertificate *cert;

	cert = CERT_DecodeCertFromPackage ((char *) data, len);
	if (!cert) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_CERT_FORMAT_INVALID,
		             _("Couldn't decode certificate: %d"),
		             PORT_GetError());
		return FALSE;
	}

    CERT_DestroyCertificate (cert);
	return TRUE;
}

