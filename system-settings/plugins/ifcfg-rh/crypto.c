/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager system settings service - keyfile plugin
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2009 Red Hat, Inc.
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

#include "common.h"
#include "crypto.h"
#include "utils.h"

static gboolean initialized = FALSE;

static gboolean
crypto_init (GError **error)
{
	SECStatus ret;

	if (initialized)
		return TRUE;

	PR_Init(PR_USER_THREAD, PR_PRIORITY_NORMAL, 1);
	ret = NSS_NoDB_Init (NULL);
	if (ret != SECSuccess) {
		PR_Cleanup ();
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             _("Failed to initialize the crypto engine: %d."),
		             PR_GetError ());
		return FALSE;
	}

	initialized = TRUE;
	return TRUE;
}

static gboolean
nss_md5_hash (const unsigned char *salt,
              const gsize salt_len,
              const char *password,
              gsize password_len,
              unsigned char *buffer,
              gsize buflen,
              GError **error)
{
	PK11Context *ctx;
	int nkey = buflen;
	unsigned int digest_len;
	int count = 0;
	char digest[20]; /* MD5 hash length */
	unsigned char *p = buffer;

	if (salt)
		g_return_val_if_fail (salt_len >= 8, FALSE);

	g_return_val_if_fail (password != NULL, FALSE);
	g_return_val_if_fail (password_len > 0, FALSE);
	g_return_val_if_fail (buffer != NULL, FALSE);
	g_return_val_if_fail (buflen > 0, FALSE);

	ctx = PK11_CreateDigestContext (SEC_OID_MD5);
	if (!ctx) {
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "Failed to initialize the MD5 context: %d.",
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
			PK11_DigestOp (ctx, salt, 8); /* Only use 8 bytes of salt */
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

static unsigned char *
make_key (const unsigned char *salt,
          gsize salt_len,
          const char *password,
          gsize *out_len,
          GError **error)
{
	unsigned char *key;
	guint32 digest_len = 24; /* DES-EDE3-CBC */

	g_return_val_if_fail (salt != NULL, NULL);
	g_return_val_if_fail (salt_len >= 8, NULL);
	g_return_val_if_fail (password != NULL, NULL);
	g_return_val_if_fail (out_len != NULL, NULL);

	key = g_malloc0 (digest_len + 1);
	if (!key) {
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "Not enough memory to decrypt private key.");
		return NULL;
	}

	if (!nss_md5_hash (salt, salt_len, password, strlen (password), key, digest_len, error)) {
		*out_len = 0;
		memset (key, 0, digest_len);
		g_free (key);
		key = NULL;
	} else
		*out_len = digest_len;

	return key;
}

static unsigned char *
nss_des3_encrypt (const unsigned char *key,
                  gsize key_len,
                  const unsigned char *iv,
                  gsize iv_len,
                  const unsigned char *data,
                  gsize data_len,
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
	unsigned char *buf;
	gsize buflen = data_len + 64;
	int tmp1_len = 0;
	unsigned int tmp2_len = 0, len;
	gboolean success = FALSE;

	buf = g_malloc0 (buflen);
	if (!buf) {
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "Could not allocate memory encrypting private key.");
		return NULL;
	}

	slot = PK11_GetBestSlot (cipher_mech, NULL);
	if (!slot) {
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "Failed to initialize the encryption cipher slot.");
		goto out;
	}

	sym_key = PK11_ImportSymKey (slot, cipher_mech, PK11_OriginUnwrap, CKA_ENCRYPT, &key_item, NULL);
	if (!sym_key) {
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "Failed to set symmetric key for encryption.");
		goto out;
	}

	sec_param = PK11_ParamFromIV (cipher_mech, &iv_item);
	if (!sec_param) {
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "Failed to set IV for encryption.");
		goto out;
	}

	ctx = PK11_CreateContextBySymKey (cipher_mech, CKA_ENCRYPT, sym_key, sec_param);
	if (!ctx) {
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "Failed to initialize the encryption context.");
		goto out;
	}

	ret = PK11_CipherOp (ctx, buf, &tmp1_len, buflen, (unsigned char *) data, data_len);
	if (ret != SECSuccess) {
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "Failed to encrypt the private key: %d.",
		             PORT_GetError ());
		goto out;
	}

	ret = PK11_DigestFinal (ctx,
	                        (unsigned char *) (buf + tmp1_len),
	                        &tmp2_len,
	                        buflen - tmp1_len);
	if (ret != SECSuccess) {
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "Failed to finalize encryption of the private key: %d.",
		             PORT_GetError ());
		goto out;
	}
	len = tmp1_len + tmp2_len;
	if (len > buflen) {
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "Error encrypting private key; too much data.");
		goto out;
	}

	*out_len = len;
	buf[*out_len] = '\0';
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
		memset (buf, 0, buflen);
		g_free (buf);
		buf = NULL;
	}
	return buf;
}

#define PEM_RSA_KEY_BEGIN "-----BEGIN RSA PRIVATE KEY-----";
#define PEM_RSA_KEY_END "-----END RSA PRIVATE KEY-----";

GByteArray *
crypto_key_to_pem (const GByteArray *data,
                   const char *password,
                   GError **error)
{
	SECStatus s;
	unsigned char salt[32];
	unsigned char *key = NULL, *enc = NULL;
	gsize key_len = 0, enc_len = 0;
	GString *pem = NULL;
	char *tmp;
	gboolean success = FALSE;
	int left;
	const char *p;
	GByteArray *ret = NULL;

	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (data->len > 0, NULL);
	g_return_val_if_fail (password != NULL, NULL);

	if (!crypto_init (error))
		return NULL;

	s = PK11_GenerateRandom (salt, sizeof (salt));
	if (s != SECSuccess) {
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "Could not generate random IV for encrypting private key.");
		return NULL;
	}

	key = make_key (&salt[0], sizeof (salt), password, &key_len, error);
	if (!key)
		return NULL;

	enc = nss_des3_encrypt (key, key_len, salt, sizeof (salt), data->data, data->len, &enc_len, error);
	if (!enc)
		goto out;

	pem = g_string_sized_new (enc_len * 2 + 100);
	if (!pem) {
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "Could not allocate memory for PEM file creation.");
		goto out;
	}
	
	g_string_append (pem, "-----BEGIN RSA PRIVATE KEY-----\n");
	g_string_append (pem, "Proc-Type: 4,ENCRYPTED\n");

	/* Convert the salt to a hex string */
	tmp = utils_bin2hexstr ((const char *) salt, sizeof (salt), 16);
	if (!tmp) {
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "Could not allocate memory for writing IV to PEM file.");
		goto out;
	}

	g_string_append_printf (pem, "DEK-Info: DES-EDE3-CBC,%s\n\n", tmp);
	g_free (tmp);

	/* Convert the encrypted key to a base64 string */
	p = tmp = g_base64_encode (enc, enc_len);
	if (!tmp) {
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "Could not allocate memory for writing encrypted key to PEM file.");
		goto out;
	}

	left = strlen (tmp);
	while (left > 0) {
		g_string_append_len (pem, p, (left < 64) ? left : 64);
		g_string_append_c (pem, '\n');
		left -= 64;
		p += 64;
	}
	g_free (tmp);

	g_string_append (pem, "-----END RSA PRIVATE KEY-----\n");

	ret = g_byte_array_sized_new (pem->len);
	if (!ret) {
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "Could not allocate memory for PEM file data.");
		goto out;
	}
	g_byte_array_append (ret, (const unsigned char *) pem->str, pem->len);
	success = TRUE;

out:
	if (key) {
		memset (key, 0, key_len);
		g_free (key);
	}
	if (!enc) {
		memset (enc, 0, enc_len);
		g_free (enc);
	}
	if (pem)
		g_string_free (pem, TRUE);

	return ret;
}

GByteArray *
crypto_random (gsize len, GError **error)
{
	SECStatus s;
	GByteArray *array;
	unsigned char *buf;

	if (!crypto_init (error))
		return NULL;

	buf = g_malloc (len);
	if (!buf) {
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "Could not allocate memory for random data.");
		return NULL;
	}

	s = PK11_GenerateRandom (buf, len);
	if (s != SECSuccess) {
		g_set_error (error, ifcfg_plugin_error_quark (), 0,
		             "Could not generate random IV for encrypting private key.");
		g_free (buf);
		return NULL;
	}

	array = g_byte_array_sized_new (len);
	g_byte_array_append (array, buf, len);
	memset (buf, 0, len);
	g_free (buf);

	return array;
}

