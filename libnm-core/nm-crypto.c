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
 * Copyright 2007 - 2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-crypto.h"

#include <strings.h>
#include <unistd.h>
#include <stdlib.h>

#include "nm-glib-aux/nm-secret-utils.h"
#include "nm-glib-aux/nm-io-utils.h"

#include "nm-crypto-impl.h"
#include "nm-utils.h"
#include "nm-errors.h"

#define PEM_RSA_KEY_BEGIN "-----BEGIN RSA PRIVATE KEY-----"
#define PEM_RSA_KEY_END   "-----END RSA PRIVATE KEY-----"

#define PEM_DSA_KEY_BEGIN "-----BEGIN DSA PRIVATE KEY-----"
#define PEM_DSA_KEY_END   "-----END DSA PRIVATE KEY-----"

#define PEM_CERT_BEGIN    "-----BEGIN CERTIFICATE-----"
#define PEM_CERT_END      "-----END CERTIFICATE-----"

#define PEM_PKCS8_ENC_KEY_BEGIN "-----BEGIN ENCRYPTED PRIVATE KEY-----"
#define PEM_PKCS8_ENC_KEY_END   "-----END ENCRYPTED PRIVATE KEY-----"

#define PEM_PKCS8_DEC_KEY_BEGIN "-----BEGIN PRIVATE KEY-----"
#define PEM_PKCS8_DEC_KEY_END   "-----END PRIVATE KEY-----"

/*****************************************************************************/

static const NMCryptoCipherInfo cipher_infos[] = {
#define _CI(_cipher, _name, _digest_len, _real_iv_len) \
	[(_cipher) - 1] = { .cipher = _cipher, .name = ""_name"", .digest_len = _digest_len, .real_iv_len = _real_iv_len }
	_CI (NM_CRYPTO_CIPHER_DES_EDE3_CBC, "DES-EDE3-CBC", 24,  8),
	_CI (NM_CRYPTO_CIPHER_DES_CBC,      "DES-CBC",       8,  8),
	_CI (NM_CRYPTO_CIPHER_AES_128_CBC,  "AES-128-CBC",  16, 16),
	_CI (NM_CRYPTO_CIPHER_AES_192_CBC,  "AES-192-CBC",  24, 16),
	_CI (NM_CRYPTO_CIPHER_AES_256_CBC,  "AES-256-CBC",  32, 16),
};

const NMCryptoCipherInfo *
nm_crypto_cipher_get_info (NMCryptoCipherType cipher)
{
	g_return_val_if_fail (cipher > NM_CRYPTO_CIPHER_UNKNOWN && (gsize) cipher < G_N_ELEMENTS (cipher_infos) + 1, NULL);

#if NM_MORE_ASSERTS > 10
	{
		int i, j;

		for (i = 0; i < (int) G_N_ELEMENTS (cipher_infos); i++) {
			const NMCryptoCipherInfo *info = &cipher_infos[i];

			nm_assert (info->cipher == (NMCryptoCipherType) (i + 1));
			nm_assert (info->name && info->name[0]);
			for (j = 0; j < i; j++)
				nm_assert (g_ascii_strcasecmp (info->name, cipher_infos[j].name) != 0);
		}
	}
#endif

	return &cipher_infos[cipher - 1];
}

const NMCryptoCipherInfo *
nm_crypto_cipher_get_info_by_name (const char *cipher_name, gssize p_len)
{
	int i;

	nm_assert (nm_crypto_cipher_get_info (NM_CRYPTO_CIPHER_DES_CBC)->cipher == NM_CRYPTO_CIPHER_DES_CBC);

	if (p_len < 0) {
		if (!cipher_name)
			return FALSE;
		p_len = strlen (cipher_name);
	}

	for (i = 0; i < (int) G_N_ELEMENTS (cipher_infos); i++) {
		const NMCryptoCipherInfo *info = &cipher_infos[i];

		if (   (gsize) p_len == strlen (info->name)
		    && g_ascii_strncasecmp (info->name, cipher_name, p_len) == 0)
			return info;
	}
	return NULL;
}

/*****************************************************************************/

static gboolean
find_tag (const char *tag,
          const guint8 *data,
          gsize data_len,
          gsize start_at,
          gsize *out_pos)
{
	gsize i, taglen;
	gsize len = data_len - start_at;

	g_return_val_if_fail (out_pos != NULL, FALSE);

	taglen = strlen (tag);
	if (len >= taglen) {
		for (i = 0; i < len - taglen + 1; i++) {
			if (memcmp (data + start_at + i, tag, taglen) == 0) {
				*out_pos = start_at + i;
				return TRUE;
			}
		}
	}
	return FALSE;
}

#define DEK_INFO_TAG "DEK-Info: "
#define PROC_TYPE_TAG "Proc-Type: "

static char *
_extract_line (const guint8 **p, const guint8 *p_end)
{
	const guint8 *x, *x0;

	nm_assert (p);
	nm_assert (p_end);
	nm_assert (*p);
	nm_assert (*p < p_end);

	x = x0 = *p;
	while (TRUE) {
		if (x == p_end) {
			*p = p_end;
			break;
		}
		if (*x == '\0') {
			/* the data contains embedded NUL. This is the end. */
			*p = p_end;
			break;
		}
		if (*x == '\n') {
			*p = x + 1;
			break;
		}
		x++;
	}

	if (x == x0)
		return NULL;
	return g_strndup ((char *) x0, x - x0);
}

static gboolean
parse_old_openssl_key_file (const guint8 *data,
                            gsize data_len,
                            NMSecretPtr *out_parsed,
                            NMCryptoKeyType *out_key_type,
                            NMCryptoCipherType *out_cipher,
                            char **out_iv,
                            GError **error)
{
	gsize start = 0, end = 0;
	nm_auto_free_secret char *str = NULL;
	char *str_p;
	gsize str_len;
	int enc_tags = 0;
	NMCryptoKeyType key_type;
	nm_auto_clear_secret_ptr NMSecretPtr parsed = { 0 };
	nm_auto_free_secret char *iv = NULL;
	NMCryptoCipherType cipher = NM_CRYPTO_CIPHER_UNKNOWN;
	const char *start_tag;
	const char *end_tag;
	const guint8 *data_start, *data_end;

	nm_assert (!out_parsed || (out_parsed->len == 0 && !out_parsed->bin));
	nm_assert (!out_iv || !*out_iv);

	NM_SET_OUT (out_key_type, NM_CRYPTO_KEY_TYPE_UNKNOWN);
	NM_SET_OUT (out_cipher, NM_CRYPTO_CIPHER_UNKNOWN);

	if (find_tag (PEM_RSA_KEY_BEGIN, data, data_len, 0, &start)) {
		key_type = NM_CRYPTO_KEY_TYPE_RSA;
		start_tag = PEM_RSA_KEY_BEGIN;
		end_tag = PEM_RSA_KEY_END;
	} else if (find_tag (PEM_DSA_KEY_BEGIN, data, data_len, 0, &start)) {
		key_type = NM_CRYPTO_KEY_TYPE_DSA;
		start_tag = PEM_DSA_KEY_BEGIN;
		end_tag = PEM_DSA_KEY_END;
	} else {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_INVALID_DATA,
		             _("PEM key file had no start tag"));
		return FALSE;
	}

	start += strlen (start_tag);
	if (!find_tag (end_tag, data, data_len, start, &end)) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_INVALID_DATA,
		             _("PEM key file had no end tag '%s'."),
		             end_tag);
		return FALSE;
	}

	str_len = end - start + 1;
	str = g_new (char, str_len);
	str[0] = '\0';
	str_p = str;

	data_start = &data[start];
	data_end = &data[end];

	while (data_start < data_end) {
		nm_auto_free_secret char *line = NULL;
		char *p;

		line = _extract_line (&data_start, data_end);
		if (!line)
			continue;

		p = nm_secret_strchomp (nm_str_skip_leading_spaces (line));

		if (!strncmp (p, PROC_TYPE_TAG, strlen (PROC_TYPE_TAG))) {
			if (enc_tags++ != 0 || str_p != str) {
				g_set_error (error, NM_CRYPTO_ERROR,
				             NM_CRYPTO_ERROR_INVALID_DATA,
				             _("Malformed PEM file: Proc-Type was not first tag."));
				return FALSE;
			}

			p += strlen (PROC_TYPE_TAG);
			if (strcmp (p, "4,ENCRYPTED")) {
				g_set_error (error, NM_CRYPTO_ERROR,
				             NM_CRYPTO_ERROR_INVALID_DATA,
				             _("Malformed PEM file: unknown Proc-Type tag '%s'."),
				             p);
				return FALSE;
			}
		} else if (!strncmp (p, DEK_INFO_TAG, strlen (DEK_INFO_TAG))) {
			const NMCryptoCipherInfo *cipher_info;
			char *comma;
			gsize p_len;

			if (enc_tags++ != 1 || str_p != str) {
				g_set_error (error, NM_CRYPTO_ERROR,
				             NM_CRYPTO_ERROR_INVALID_DATA,
				             _("Malformed PEM file: DEK-Info was not the second tag."));
				return FALSE;
			}

			p += strlen (DEK_INFO_TAG);

			/* Grab the IV first */
			comma = strchr (p, ',');
			if (!comma || (*(comma + 1) == '\0')) {
				g_set_error (error, NM_CRYPTO_ERROR,
				             NM_CRYPTO_ERROR_INVALID_DATA,
				             _("Malformed PEM file: no IV found in DEK-Info tag."));
				return FALSE;
			}
			p_len = comma - p;
			comma++;
			if (!g_ascii_isxdigit (*comma)) {
				g_set_error (error, NM_CRYPTO_ERROR,
				             NM_CRYPTO_ERROR_INVALID_DATA,
				             _("Malformed PEM file: invalid format of IV in DEK-Info tag."));
				return FALSE;
			}
			nm_free_secret (iv);
			iv = g_strdup (comma);

			/* Get the private key cipher */
			cipher_info = nm_crypto_cipher_get_info_by_name (p, p_len);
			if (!cipher_info) {
				g_set_error (error, NM_CRYPTO_ERROR,
				             NM_CRYPTO_ERROR_INVALID_DATA,
				             _("Malformed PEM file: unknown private key cipher '%s'."),
				             p);
				return FALSE;
			}
			cipher = cipher_info->cipher;
		} else {
			if (enc_tags == 1) {
				g_set_error (error, NM_CRYPTO_ERROR,
				             NM_CRYPTO_ERROR_INVALID_DATA,
				             "Malformed PEM file: both Proc-Type and DEK-Info tags are required.");
				return FALSE;
			}
			nm_utils_strbuf_append_str (&str_p, &str_len, p);
			nm_assert (str_len > 0);
		}
	}

	parsed.bin = (guint8 *) g_base64_decode (str, &parsed.len);
	if (!parsed.bin || parsed.len == 0) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_INVALID_DATA,
		             _("Could not decode private key."));
		nm_secret_ptr_clear (&parsed);
		return FALSE;
	}

	NM_SET_OUT (out_key_type, key_type);
	NM_SET_OUT (out_iv, g_steal_pointer (&iv));
	NM_SET_OUT (out_cipher, cipher);
	nm_secret_ptr_move (out_parsed, &parsed);
	return TRUE;
}

static gboolean
parse_pkcs8_key_file (const guint8 *data,
                      gsize data_len,
                      NMSecretPtr *parsed,
                      gboolean *out_encrypted,
                      GError **error)
{
	gsize start = 0, end = 0;
	const char *start_tag = NULL, *end_tag = NULL;
	gboolean encrypted = FALSE;
	nm_auto_free_secret char *der_base64 = NULL;

	nm_assert (parsed);
	nm_assert (!parsed->bin);
	nm_assert (parsed->len == 0);
	nm_assert (out_encrypted);

	/* Try encrypted first, decrypted next */
	if (find_tag (PEM_PKCS8_ENC_KEY_BEGIN, data, data_len, 0, &start)) {
		start_tag = PEM_PKCS8_ENC_KEY_BEGIN;
		end_tag = PEM_PKCS8_ENC_KEY_END;
		encrypted = TRUE;
	} else if (find_tag (PEM_PKCS8_DEC_KEY_BEGIN, data, data_len, 0, &start)) {
		start_tag = PEM_PKCS8_DEC_KEY_BEGIN;
		end_tag = PEM_PKCS8_DEC_KEY_END;
		encrypted = FALSE;
	} else {
		g_set_error_literal (error, NM_CRYPTO_ERROR,
		                     NM_CRYPTO_ERROR_INVALID_DATA,
		                     _("Failed to find expected PKCS#8 start tag."));
		return FALSE;
	}

	start += strlen (start_tag);
	if (!find_tag (end_tag, data, data_len, start, &end)) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_INVALID_DATA,
		             _("Failed to find expected PKCS#8 end tag '%s'."),
		             end_tag);
		return FALSE;
	}

	/* g_base64_decode() wants a NULL-terminated string */
	der_base64 = g_strndup ((char *) &data[start], end - start);

	parsed->bin = (guint8 *) g_base64_decode (der_base64, &parsed->len);
	if (!parsed->bin || parsed->len == 0) {
		g_set_error_literal (error, NM_CRYPTO_ERROR,
		                     NM_CRYPTO_ERROR_INVALID_DATA,
		                     _("Failed to decode PKCS#8 private key."));
		nm_secret_ptr_clear (parsed);
		return FALSE;
	}

	*out_encrypted = encrypted;
	return TRUE;
}

static gboolean
file_read_contents (const char *filename,
                    NMSecretPtr *out_contents,
                    GError **error)
{
	nm_assert (out_contents);
	nm_assert (out_contents->len == 0);
	nm_assert (!out_contents->str);

	return nm_utils_file_get_contents (-1,
	                                   filename,
	                                   100*1024*1024,
	                                   NM_UTILS_FILE_GET_CONTENTS_FLAG_SECRET,
	                                   &out_contents->str,
	                                   &out_contents->len,
	                                   error) >= 0;
}

GBytes *
nm_crypto_read_file (const char *filename,
                     GError **error)
{
	nm_auto_clear_secret_ptr NMSecretPtr contents = { 0 };

	g_return_val_if_fail (filename, NULL);

	if (!file_read_contents (filename, &contents, error))
		return NULL;
	return nm_secret_copy_to_gbytes (contents.bin, contents.len);
}

/*
 * Convert a hex string into bytes.
 */
static guint8 *
_nmtst_convert_iv (const char *src,
                   gsize *out_len,
                   GError **error)
{
	gsize i, num;
	gs_free guint8 *c = NULL;
	int c0, c1;

	nm_assert (src);

	num = strlen (src);
	if (   num == 0
	    || (num % 2) != 0) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_INVALID_DATA,
		             _("IV must be an even number of bytes in length."));
		return NULL;
	}

	num /= 2;
	c = g_malloc (num + 1);

	/* defensively add trailing NUL. This function returns binary data,
	 * do not assume it's NUL terminated. */
	c[num] = '\0';

	for (i = 0; i < num; i++) {
		if (   ((c0 = nm_utils_hexchar_to_int (*(src++))) < 0)
		    || ((c1 = nm_utils_hexchar_to_int (*(src++))) < 0)) {
			g_set_error (error, NM_CRYPTO_ERROR,
			             NM_CRYPTO_ERROR_INVALID_DATA,
			             _("IV contains non-hexadecimal digits."));
			nm_explicit_bzero (c, i);
			return FALSE;
		}

		c[i] = (c0 << 4) + c1;
	}
	*out_len = num;
	return g_steal_pointer (&c);
}

guint8 *
nmtst_crypto_make_des_aes_key (NMCryptoCipherType cipher,
                               const guint8 *salt,
                               gsize salt_len,
                               const char *password,
                               gsize *out_len,
                               GError **error)
{
	guint8 *key;
	const NMCryptoCipherInfo *cipher_info;

	g_return_val_if_fail (salt != NULL, NULL);
	g_return_val_if_fail (salt_len >= 8, NULL);
	g_return_val_if_fail (password != NULL, NULL);
	g_return_val_if_fail (out_len != NULL, NULL);

	*out_len = 0;

	cipher_info = nm_crypto_cipher_get_info (cipher);

	g_return_val_if_fail (cipher_info, NULL);

	if (password[0] == '\0')
		return NULL;

	key = g_malloc (cipher_info->digest_len);

	nm_crypto_md5_hash (salt,
	                    8,
	                    (guint8 *) password,
	                    strlen (password),
	                    key,
	                    cipher_info->digest_len);

	*out_len = cipher_info->digest_len;
	return key;
}

static gboolean
_nmtst_decrypt_key (NMCryptoCipherType cipher,
                    const guint8 *data,
                    gsize data_len,
                    const char *iv,
                    const char *password,
                    NMSecretPtr *parsed,
                    GError **error)
{
	nm_auto_clear_secret_ptr NMSecretPtr bin_iv = { 0 };
	nm_auto_clear_secret_ptr NMSecretPtr key = { 0 };

	nm_assert (password);
	nm_assert (cipher != NM_CRYPTO_CIPHER_UNKNOWN);
	nm_assert (iv);
	nm_assert (parsed);
	nm_assert (!parsed->bin);
	nm_assert (parsed->len == 0);

	bin_iv.bin = _nmtst_convert_iv (iv, &bin_iv.len, error);
	if (!bin_iv.bin)
		return FALSE;

	if (bin_iv.len < 8) {
		g_set_error (error,
		             NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_INVALID_DATA,
		             _("IV must contain at least 8 characters"));
		return FALSE;
	}

	/* Convert the password and IV into a DES or AES key */
	key.bin = nmtst_crypto_make_des_aes_key (cipher, bin_iv.bin, bin_iv.len, password, &key.len, error);
	if (!key.bin || !key.len)
		return FALSE;

	parsed->bin = _nmtst_crypto_decrypt (cipher,
	                                     data,
	                                     data_len,
	                                     bin_iv.bin,
	                                     bin_iv.len,
	                                     key.bin,
	                                     key.len,
	                                     &parsed->len,
	                                     error);
	if (!parsed->bin || parsed->len == 0) {
		nm_secret_ptr_clear (parsed);
		return FALSE;
	}

	return TRUE;
}

GBytes *
nmtst_crypto_decrypt_openssl_private_key_data (const guint8 *data,
                                               gsize data_len,
                                               const char *password,
                                               NMCryptoKeyType *out_key_type,
                                               GError **error)
{
	NMCryptoKeyType key_type = NM_CRYPTO_KEY_TYPE_UNKNOWN;
	nm_auto_clear_secret_ptr NMSecretPtr parsed = { 0 };
	nm_auto_free_secret char *iv = NULL;
	NMCryptoCipherType cipher = NM_CRYPTO_CIPHER_UNKNOWN;

	g_return_val_if_fail (data != NULL, NULL);

	NM_SET_OUT (out_key_type, NM_CRYPTO_KEY_TYPE_UNKNOWN);

	if (!_nm_crypto_init (error))
		return NULL;

	if (!parse_old_openssl_key_file (data, data_len, &parsed, &key_type, &cipher, &iv, NULL)) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_INVALID_DATA,
		             _("Unable to determine private key type."));
		return NULL;
	}

	NM_SET_OUT (out_key_type, key_type);

	if (password) {
		nm_auto_clear_secret_ptr NMSecretPtr parsed2 = { 0 };

		if (cipher == NM_CRYPTO_CIPHER_UNKNOWN || !iv) {
			g_set_error (error, NM_CRYPTO_ERROR,
			             NM_CRYPTO_ERROR_INVALID_PASSWORD,
			             _("Password provided, but key was not encrypted."));
			return NULL;
		}

		if (!_nmtst_decrypt_key (cipher,
		                         parsed.bin,
		                         parsed.len,
		                         iv,
		                         password,
		                         &parsed2,
		                         error))
			return NULL;

		return nm_secret_copy_to_gbytes (parsed2.bin, parsed2.len);
	}

	if (cipher != NM_CRYPTO_CIPHER_UNKNOWN || iv)
		return NULL;

	return nm_secret_copy_to_gbytes (parsed.bin, parsed.len);
}

GBytes *
nmtst_crypto_decrypt_openssl_private_key (const char *file,
                                          const char *password,
                                          NMCryptoKeyType *out_key_type,
                                          GError **error)
{
	nm_auto_clear_secret_ptr NMSecretPtr contents = { 0 };

	if (!_nm_crypto_init (error))
		return NULL;

	if (!file_read_contents (file, &contents, error))
		return NULL;

	return nmtst_crypto_decrypt_openssl_private_key_data (contents.bin,
	                                                      contents.len,
	                                                      password,
	                                                      out_key_type,
	                                                      error);
}

static gboolean
extract_pem_cert_data (const guint8 *contents,
                       gsize contents_len,
                       NMSecretPtr *out_cert,
                       GError **error)
{
	gsize start = 0;
	gsize end = 0;
	nm_auto_free_secret char *der_base64 = NULL;

	nm_assert (contents);
	nm_assert (out_cert);
	nm_assert (out_cert->len == 0);
	nm_assert (!out_cert->ptr);

	if (!find_tag (PEM_CERT_BEGIN, contents, contents_len, 0, &start)) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_INVALID_DATA,
		             _("PEM certificate had no start tag '%s'."),
		             PEM_CERT_BEGIN);
		return FALSE;
	}

	start += strlen (PEM_CERT_BEGIN);
	if (!find_tag (PEM_CERT_END, contents, contents_len, start, &end)) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_INVALID_DATA,
		             _("PEM certificate had no end tag '%s'."),
		             PEM_CERT_END);
		return FALSE;
	}

	/* g_base64_decode() wants a NULL-terminated string */
	der_base64 = g_strndup ((const char *) &contents[start], end - start);

	out_cert->bin = (guint8 *) g_base64_decode (der_base64, &out_cert->len);
	if (!out_cert->bin || !out_cert->len) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_INVALID_DATA,
		             _("Failed to decode certificate."));
		nm_secret_ptr_clear (out_cert);
		return FALSE;
	}

	return TRUE;
}

gboolean
nm_crypto_load_and_verify_certificate (const char *file,
                                       NMCryptoFileFormat *out_file_format,
                                       GBytes **out_certificate,
                                       GError **error)
{
	nm_auto_clear_secret_ptr NMSecretPtr contents = { 0 };

	g_return_val_if_fail (file, FALSE);
	nm_assert (!error || !*error);

	if (!_nm_crypto_init (error))
		goto out;

	if (!file_read_contents (file, &contents, error))
		goto out;

	if (contents.len == 0) {
		g_set_error (error,
		             NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_INVALID_DATA,
		             _("Certificate file is empty"));
		goto out;
	}

	/* Check for PKCS#12 */
	if (nm_crypto_is_pkcs12_data (contents.bin, contents.len, NULL)) {
		NM_SET_OUT (out_file_format, NM_CRYPTO_FILE_FORMAT_PKCS12);
		NM_SET_OUT (out_certificate, nm_secret_copy_to_gbytes (contents.bin, contents.len));
		return TRUE;
	}

	/* Check for plain DER format */
	if (contents.len > 2 && contents.bin[0] == 0x30 && contents.bin[1] == 0x82) {
		if (_nm_crypto_verify_x509 (contents.bin, contents.len, NULL)) {
			NM_SET_OUT (out_file_format, NM_CRYPTO_FILE_FORMAT_X509);
			NM_SET_OUT (out_certificate, nm_secret_copy_to_gbytes (contents.bin, contents.len));
			return TRUE;
		}
	} else {
		nm_auto_clear_secret_ptr NMSecretPtr pem_cert = { 0 };

		if (extract_pem_cert_data (contents.bin, contents.len, &pem_cert, NULL)) {
			if (_nm_crypto_verify_x509 (pem_cert.bin, pem_cert.len, NULL)) {
				NM_SET_OUT (out_file_format, NM_CRYPTO_FILE_FORMAT_X509);
				NM_SET_OUT (out_certificate, nm_secret_copy_to_gbytes (contents.bin, contents.len));
				return TRUE;
			}
		}
	}

	g_set_error (error,
	             NM_CRYPTO_ERROR,
	             NM_CRYPTO_ERROR_INVALID_DATA,
	             _("Failed to recognize certificate"));

out:
	NM_SET_OUT (out_file_format, NM_CRYPTO_FILE_FORMAT_UNKNOWN);
	NM_SET_OUT (out_certificate, NULL);
	return FALSE;
}

gboolean
nm_crypto_is_pkcs12_data (const guint8 *data,
                          gsize data_len,
                          GError **error)
{
	GError *local = NULL;
	gboolean success;

	if (!data_len) {
		g_set_error (error,
		             NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_INVALID_DATA,
		             _("Certificate file is empty"));
		return FALSE;
	}

	g_return_val_if_fail (data != NULL, FALSE);

	if (!_nm_crypto_init (error))
		return FALSE;

	success = _nm_crypto_verify_pkcs12 (data, data_len, NULL, &local);
	if (success == FALSE) {
		/* If the error was just a decryption error, then it's pkcs#12 */
		if (local) {
			if (g_error_matches (local, NM_CRYPTO_ERROR, NM_CRYPTO_ERROR_DECRYPTION_FAILED)) {
				success = TRUE;
				g_error_free (local);
			} else
				g_propagate_error (error, local);
		}
	}
	return success;
}

gboolean
nm_crypto_is_pkcs12_file (const char *file, GError **error)
{
	nm_auto_clear_secret_ptr NMSecretPtr contents = { 0 };

	g_return_val_if_fail (file != NULL, FALSE);

	if (!_nm_crypto_init (error))
		return FALSE;

	if (!file_read_contents (file, &contents, error))
		return FALSE;

	return nm_crypto_is_pkcs12_data (contents.bin, contents.len, error);
}

/* Verifies that a private key can be read, and if a password is given, that
 * the private key can be decrypted with that password.
 */
NMCryptoFileFormat
nm_crypto_verify_private_key_data (const guint8 *data,
                                   gsize data_len,
                                   const char *password,
                                   gboolean *out_is_encrypted,
                                   GError **error)
{
	NMCryptoFileFormat format = NM_CRYPTO_FILE_FORMAT_UNKNOWN;
	gboolean is_encrypted = FALSE;

	g_return_val_if_fail (data != NULL, NM_CRYPTO_FILE_FORMAT_UNKNOWN);
	g_return_val_if_fail (out_is_encrypted == NULL || *out_is_encrypted == FALSE, NM_CRYPTO_FILE_FORMAT_UNKNOWN);

	if (!_nm_crypto_init (error))
		return NM_CRYPTO_FILE_FORMAT_UNKNOWN;

	/* Check for PKCS#12 first */
	if (nm_crypto_is_pkcs12_data (data, data_len, NULL)) {
		is_encrypted = TRUE;
		if (   !password
		    || _nm_crypto_verify_pkcs12 (data, data_len, password, error))
			format = NM_CRYPTO_FILE_FORMAT_PKCS12;
	} else {
		nm_auto_clear_secret_ptr NMSecretPtr parsed = { 0 };

		/* Maybe it's PKCS#8 */
		if (parse_pkcs8_key_file (data, data_len, &parsed, &is_encrypted, NULL)) {
			if (   !password
			    || _nm_crypto_verify_pkcs8 (parsed.bin, parsed.len, is_encrypted, password, error))
				format = NM_CRYPTO_FILE_FORMAT_RAW_KEY;
		} else {
			NMCryptoCipherType cipher;
			nm_auto_free_secret char *iv = NULL;

			/* Or it's old-style OpenSSL */
			if (parse_old_openssl_key_file (data, data_len, NULL, NULL, &cipher, &iv, NULL)) {
				format = NM_CRYPTO_FILE_FORMAT_RAW_KEY;
				is_encrypted = (cipher != NM_CRYPTO_CIPHER_UNKNOWN && iv);
			}
		}
	}

	if (   format == NM_CRYPTO_FILE_FORMAT_UNKNOWN
	    && error
	    && !*error) {
		g_set_error (error,
		             NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_INVALID_DATA,
		             _("not a valid private key"));
	}

	if (out_is_encrypted)
		*out_is_encrypted = is_encrypted;
	return format;
}

NMCryptoFileFormat
nm_crypto_verify_private_key (const char *filename,
                              const char *password,
                              gboolean *out_is_encrypted,
                              GError **error)
{
	nm_auto_clear_secret_ptr NMSecretPtr contents = { 0 };

	g_return_val_if_fail (filename != NULL, NM_CRYPTO_FILE_FORMAT_UNKNOWN);

	if (!_nm_crypto_init (error))
		return NM_CRYPTO_FILE_FORMAT_UNKNOWN;

	if (!file_read_contents (filename, &contents, error))
		return NM_CRYPTO_FILE_FORMAT_UNKNOWN;

	return nm_crypto_verify_private_key_data (contents.bin, contents.len, password, out_is_encrypted, error);
}

void
nm_crypto_md5_hash (const guint8 *salt,
                    gsize salt_len,
                    const guint8 *password,
                    gsize password_len,
                    guint8 *buffer,
                    gsize buflen)
{
	nm_auto_free_checksum GChecksum *ctx = NULL;
	nm_auto_clear_static_secret_ptr const NMSecretPtr digest = NM_SECRET_PTR_STATIC (NM_UTILS_CHECKSUM_LENGTH_MD5);
	gsize bufidx = 0;
	int i;

	g_return_if_fail (password_len == 0 || password);
	g_return_if_fail (buffer);
	g_return_if_fail (buflen > 0);
	g_return_if_fail (salt_len == 0 || salt);

	ctx = g_checksum_new (G_CHECKSUM_MD5);

	for (;;) {
		if (password_len > 0)
			g_checksum_update (ctx, (const guchar *) password, password_len);
		if (salt_len > 0)
			g_checksum_update (ctx, (const guchar *) salt, salt_len);

		nm_utils_checksum_get_digest_len (ctx, digest.bin, NM_UTILS_CHECKSUM_LENGTH_MD5);

		for (i = 0; i < NM_UTILS_CHECKSUM_LENGTH_MD5; i++) {
			if (bufidx >= buflen)
				return;
			buffer[bufidx++] = digest.bin[i];
		}

		g_checksum_reset (ctx);
		g_checksum_update (ctx, digest.ptr, NM_UTILS_CHECKSUM_LENGTH_MD5);
	}
}

gboolean
nm_crypto_randomize (void *buffer, gsize buffer_len, GError **error)
{
	return _nm_crypto_randomize (buffer, buffer_len, error);
}


/**
 * nmtst_crypto_rsa_key_encrypt:
 * @data: (array length=len): RSA private key data to be encrypted
 * @len: length of @data
 * @in_password: (allow-none): existing password to use, if any
 * @out_password: (out) (allow-none): if @in_password was %NULL, a random
 *  password will be generated and returned in this argument
 * @error: detailed error information on return, if an error occurred
 *
 * Encrypts the given RSA private key data with the given password (or generates
 * a password if no password was given) and converts the data to PEM format
 * suitable for writing to a file. It uses Triple DES cipher for the encryption.
 *
 * Returns: (transfer full): on success, PEM-formatted data suitable for writing
 * to a PEM-formatted certificate/private key file.
 **/
GBytes *
nmtst_crypto_rsa_key_encrypt (const guint8 *data,
                              gsize len,
                              const char *in_password,
                              char **out_password,
                              GError **error)
{
	guint8 salt[8];
	nm_auto_clear_secret_ptr NMSecretPtr key = { 0 };
	nm_auto_clear_secret_ptr NMSecretPtr enc = { 0 };
	gs_unref_ptrarray GPtrArray *pem = NULL;
	nm_auto_free_secret char *tmp_password = NULL;
	nm_auto_free_secret char *enc_base64 = NULL;
	gsize enc_base64_len;
	const char *p;
	gsize ret_len, ret_idx;
	guint i;
	NMSecretBuf *ret;

	g_return_val_if_fail (data, NULL);
	g_return_val_if_fail (len > 0, NULL);
	g_return_val_if_fail (!out_password || !*out_password, NULL);

	/* Make the password if needed */
	if (!in_password) {
		nm_auto_clear_static_secret_ptr NMSecretPtr pw_buf = NM_SECRET_PTR_STATIC (32);

		if (!nm_crypto_randomize (pw_buf.bin, pw_buf.len, error))
			return NULL;
		tmp_password = nm_utils_bin2hexstr (pw_buf.bin, pw_buf.len, -1);
		in_password = tmp_password;
	}

	if (!nm_crypto_randomize (salt, sizeof (salt), error))
		return NULL;

	key.bin = nmtst_crypto_make_des_aes_key (NM_CRYPTO_CIPHER_DES_EDE3_CBC, salt, sizeof (salt), in_password, &key.len, NULL);
	if (!key.bin)
		g_return_val_if_reached (NULL);

	enc.bin = _nmtst_crypto_encrypt (NM_CRYPTO_CIPHER_DES_EDE3_CBC, data, len, salt, sizeof (salt), key.bin, key.len, &enc.len, error);
	if (!enc.bin)
		return NULL;

	/* What follows is not the most efficient way to construct the pem
	 * file line-by-line. At least, it makes sure, that the data will be cleared
	 * again and not left around in memory.
	 *
	 * If this would not be test code, we should improve the implementation
	 * to avoid some of the copying. */
	pem = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_free_secret);

	g_ptr_array_add (pem, g_strdup ("-----BEGIN RSA PRIVATE KEY-----\n"));
	g_ptr_array_add (pem, g_strdup ("Proc-Type: 4,ENCRYPTED\n"));

	/* Convert the salt to a hex string */
	g_ptr_array_add (pem, g_strdup_printf ("DEK-Info: %s,",
	                                       nm_crypto_cipher_get_info (NM_CRYPTO_CIPHER_DES_EDE3_CBC)->name));
	g_ptr_array_add (pem, nm_utils_bin2hexstr (salt, sizeof (salt), sizeof (salt) * 2));
	g_ptr_array_add (pem, g_strdup ("\n\n"));

	/* Convert the encrypted key to a base64 string */
	enc_base64 = g_base64_encode ((const guchar *) enc.bin, enc.len);
	enc_base64_len = strlen (enc_base64);
	for (p = enc_base64; (p - enc_base64) < (ptrdiff_t) enc_base64_len; p += 64) {
		g_ptr_array_add (pem, g_strndup (p, 64));
		g_ptr_array_add (pem, g_strdup ("\n"));
	}

	g_ptr_array_add (pem, g_strdup ("-----END RSA PRIVATE KEY-----\n"));

	ret_len = 0;
	for (i = 0; i < pem->len; i++)
		ret_len += strlen (pem->pdata[i]);

	ret = nm_secret_buf_new (ret_len + 1);
	ret_idx = 0;
	for (i = 0; i < pem->len; i++) {
		const char *line = pem->pdata[i];
		gsize line_l = strlen (line);

		memcpy (&ret->bin[ret_idx], line, line_l);
		ret_idx += line_l;
		nm_assert (ret_idx <= ret_len);
	}
	nm_assert (ret_idx == ret_len);
	ret->bin[ret_len] = '\0';

	NM_SET_OUT (out_password, g_strdup (tmp_password));
	return nm_secret_buf_to_gbytes_take (ret, ret_len);
}
