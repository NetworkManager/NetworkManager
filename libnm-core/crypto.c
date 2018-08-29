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

#include "crypto.h"

#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <stdlib.h>

#include "nm-utils/nm-secret-utils.h"

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

static GByteArray *
to_gbyte_array_mem (gconstpointer mem, gsize len)
{
	GByteArray *arr;

	arr = g_byte_array_sized_new (len);
	if (len > 0)
		g_byte_array_append (arr, mem, len);
	return arr;
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

static GByteArray *
parse_old_openssl_key_file (const guint8 *data,
                            gsize data_len,
                            NMCryptoKeyType *out_key_type,
                            const char **out_cipher,
                            char **out_iv,
                            GError **error)
{
	GByteArray *bindata = NULL;
	gs_strfreev char **lines = NULL;
	char **ln = NULL;
	gsize start = 0, end = 0;
	nm_auto_free_gstring GString *str = NULL;
	int enc_tags = 0;
	NMCryptoKeyType key_type;
	gs_free char *iv = NULL;
	const char *cipher = NULL;
	gs_free unsigned char *tmp = NULL;
	gsize tmp_len = 0;
	const char *start_tag;
	const char *end_tag;
	guint8 save_end = 0;

	*out_key_type = NM_CRYPTO_KEY_TYPE_UNKNOWN;
	*out_iv = NULL;
	*out_cipher = NULL;

	if (find_tag (PEM_RSA_KEY_BEGIN, data, data_len, 0, &start)) {
		key_type = NM_CRYPTO_KEY_TYPE_RSA;
		start_tag = PEM_RSA_KEY_BEGIN;
		end_tag = PEM_RSA_KEY_END;
	} else if (find_tag (PEM_DSA_KEY_BEGIN, data, data_len, 0, &start)) {
		key_type = NM_CRYPTO_KEY_TYPE_DSA;
		start_tag = PEM_DSA_KEY_BEGIN;
		end_tag = PEM_DSA_KEY_END;
	} else
		return NULL;

	start += strlen (start_tag);
	if (!find_tag (end_tag, data, data_len, start, &end)) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_INVALID_DATA,
		             _("PEM key file had no end tag '%s'."),
		             end_tag);
		return NULL;
	}

	save_end = data[end];
	((guint8 *)data)[end] = '\0';
	lines = g_strsplit ((const char *) (data + start), "\n", 0);
	((guint8 *)data)[end] = save_end;

	if (!lines || g_strv_length (lines) <= 1) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_INVALID_DATA,
		             _("Doesn't look like a PEM private key file."));
		return NULL;
	}

	str = g_string_new_len (NULL, end - start);
	for (ln = lines; *ln; ln++) {
		char *p = *ln;

		/* Chug leading spaces */
		p = g_strstrip (p);
		if (!*p)
			continue;

		if (!strncmp (p, PROC_TYPE_TAG, strlen (PROC_TYPE_TAG))) {
			if (enc_tags++ != 0 || str->len != 0) {
				g_set_error (error, NM_CRYPTO_ERROR,
				             NM_CRYPTO_ERROR_INVALID_DATA,
				             _("Malformed PEM file: Proc-Type was not first tag."));
				return NULL;
			}

			p += strlen (PROC_TYPE_TAG);
			if (strcmp (p, "4,ENCRYPTED")) {
				g_set_error (error, NM_CRYPTO_ERROR,
				             NM_CRYPTO_ERROR_INVALID_DATA,
				             _("Malformed PEM file: unknown Proc-Type tag '%s'."),
				             p);
				return NULL;
			}
		} else if (!strncmp (p, DEK_INFO_TAG, strlen (DEK_INFO_TAG))) {
			static const char *const known_ciphers[] = { CIPHER_DES_EDE3_CBC,
			                                             CIPHER_DES_CBC,
			                                             CIPHER_AES_128_CBC,
			                                             CIPHER_AES_192_CBC,
			                                             CIPHER_AES_256_CBC };
			char *comma;
			guint i;

			if (enc_tags++ != 1 || str->len != 0) {
				g_set_error (error, NM_CRYPTO_ERROR,
				             NM_CRYPTO_ERROR_INVALID_DATA,
				             _("Malformed PEM file: DEK-Info was not the second tag."));
				return NULL;
			}

			p += strlen (DEK_INFO_TAG);

			/* Grab the IV first */
			comma = strchr (p, ',');
			if (!comma || (*(comma + 1) == '\0')) {
				g_set_error (error, NM_CRYPTO_ERROR,
				             NM_CRYPTO_ERROR_INVALID_DATA,
				             _("Malformed PEM file: no IV found in DEK-Info tag."));
				return NULL;
			}
			*comma++ = '\0';
			if (!g_ascii_isxdigit (*comma)) {
				g_set_error (error, NM_CRYPTO_ERROR,
				             NM_CRYPTO_ERROR_INVALID_DATA,
				             _("Malformed PEM file: invalid format of IV in DEK-Info tag."));
				return NULL;
			}
			iv = g_strdup (comma);

			/* Get the private key cipher */
			for (i = 0; i < G_N_ELEMENTS (known_ciphers); i++) {
				if (!g_ascii_strcasecmp (p, known_ciphers[i])) {
					cipher = known_ciphers[i];
					break;
				}
			}
			if (!cipher) {
				g_set_error (error, NM_CRYPTO_ERROR,
				             NM_CRYPTO_ERROR_INVALID_DATA,
				             _("Malformed PEM file: unknown private key cipher '%s'."),
				             p);
				return NULL;
			}
		} else {
			if (enc_tags == 1) {
				g_set_error (error, NM_CRYPTO_ERROR,
				             NM_CRYPTO_ERROR_INVALID_DATA,
				             "Malformed PEM file: both Proc-Type and DEK-Info tags are required.");
				return NULL;
			}
			g_string_append (str, p);
		}
	}

	tmp = g_base64_decode (str->str, &tmp_len);
	if (tmp == NULL || !tmp_len) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_INVALID_DATA,
		             _("Could not decode private key."));
		return NULL;
	}

	bindata = g_byte_array_sized_new (tmp_len);
	g_byte_array_append (bindata, tmp, tmp_len);

	*out_key_type = key_type;
	*out_iv = g_steal_pointer (&iv);
	*out_cipher = cipher;
	return bindata;
}

static GByteArray *
parse_pkcs8_key_file (const guint8 *data,
                      gsize data_len,
                      gboolean *out_encrypted,
                      GError **error)
{
	GByteArray *key;
	gsize start = 0, end = 0;
	gs_free guchar *der = NULL;
	guint8 save_end;
	gsize length = 0;
	const char *start_tag = NULL, *end_tag = NULL;
	gboolean encrypted = FALSE;

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
		return NULL;
	}

	start += strlen (start_tag);
	if (!find_tag (end_tag, data, data_len, start, &end)) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_INVALID_DATA,
		             _("Failed to find expected PKCS#8 end tag '%s'."),
		             end_tag);
		return NULL;
	}

	/* g_base64_decode() wants a NULL-terminated string */
	save_end = data[end];
	((guint8 *)data)[end] = '\0';
	der = g_base64_decode ((const char *) (data + start), &length);
	((guint8 *)data)[end] = save_end;

	if (!der || !length) {
		g_set_error_literal (error, NM_CRYPTO_ERROR,
		                     NM_CRYPTO_ERROR_INVALID_DATA,
		                     _("Failed to decode PKCS#8 private key."));
		return NULL;
	}

	key = g_byte_array_sized_new (length);
	g_byte_array_append (key, der, length);
	*out_encrypted = encrypted;
	return key;
}

static gboolean
file_read_contents (const char *filename,
                    NMSecretPtr *out_contents,
                    GError **error)
{
	nm_assert (out_contents);
	nm_assert (out_contents->len == 0);
	nm_assert (!out_contents->str);

	return g_file_get_contents (filename, &out_contents->str, &out_contents->len, error);
}

/*
 * Convert a hex string into bytes.
 */
static guint8 *
convert_iv (const char *src,
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

char *
crypto_make_des_aes_key (const char *cipher,
                         const char *salt,
                         const gsize salt_len,
                         const char *password,
                         gsize *out_len,
                         GError **error)
{
	char *key;
	guint32 digest_len;

	g_return_val_if_fail (cipher != NULL, NULL);
	g_return_val_if_fail (salt != NULL, NULL);
	g_return_val_if_fail (salt_len >= 8, NULL);
	g_return_val_if_fail (password != NULL, NULL);
	g_return_val_if_fail (out_len != NULL, NULL);

	*out_len = 0;

	if (!strcmp (cipher, CIPHER_DES_EDE3_CBC))
		digest_len = 24;
	else if (!strcmp (cipher, CIPHER_DES_CBC))
		digest_len = 8;
	else if (!strcmp (cipher, CIPHER_AES_128_CBC))
		digest_len = 16;
	else if (!strcmp (cipher, CIPHER_AES_192_CBC))
		digest_len = 24;
	else if (!strcmp (cipher, CIPHER_AES_256_CBC))
		digest_len = 32;
	else {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_UNKNOWN_CIPHER,
		             _("Private key cipher '%s' was unknown."),
		             cipher);
		return NULL;
	}

	if (password[0] == '\0')
		return NULL;

	key = g_malloc0 (digest_len + 1);

	crypto_md5_hash ((guint8 *) salt,
	                 8,
	                 (guint8 *) password,
	                 strlen (password),
	                 (guint8 *) key,
	                 digest_len);

	*out_len = digest_len;
	return key;
}

static GByteArray *
decrypt_key (const char *cipher,
             int key_type,
             const guint8 *data,
             gsize data_len,
             const char *iv,
             const char *password,
             GError **error)
{
	nm_auto_clear_secret_ptr NMSecretPtr bin_iv = { 0 };
	nm_auto_clear_secret_ptr NMSecretPtr key = { 0 };
	gs_free char *output = NULL;
	gsize decrypted_len = 0;
	GByteArray *decrypted = NULL;

	g_return_val_if_fail (password != NULL, NULL);
	g_return_val_if_fail (iv, NULL);

	bin_iv.bin = convert_iv (iv, &bin_iv.len, error);
	if (!bin_iv.bin)
		return NULL;

	if (bin_iv.len < 8) {
		g_set_error (error,
		             NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_INVALID_DATA,
		             _("IV must contain at least 8 characters"));
		return NULL;
	}

	/* Convert the password and IV into a DES or AES key */
	key.str = crypto_make_des_aes_key (cipher, bin_iv.str, bin_iv.len, password, &key.len, error);
	if (!key.str || !key.len)
		return NULL;

	output = crypto_decrypt (cipher,
	                         key_type,
	                         data,
	                         data_len,
	                         bin_iv.str,
	                         bin_iv.len,
	                         key.str,
	                         key.len,
	                         &decrypted_len,
	                         error);
	if (output && decrypted_len) {
		decrypted = g_byte_array_sized_new (decrypted_len);
		g_byte_array_append (decrypted, (guint8 *) output, decrypted_len);
	}

	return decrypted;
}

GByteArray *
nmtst_crypto_decrypt_openssl_private_key_data (const guint8 *data,
                                               gsize data_len,
                                               const char *password,
                                               NMCryptoKeyType *out_key_type,
                                               GError **error)
{
	NMCryptoKeyType key_type = NM_CRYPTO_KEY_TYPE_UNKNOWN;
	nm_auto_unref_bytearray GByteArray *parsed = NULL;
	gs_free char *iv = NULL;
	const char *cipher = NULL;

	g_return_val_if_fail (data != NULL, NULL);

	NM_SET_OUT (out_key_type, NM_CRYPTO_KEY_TYPE_UNKNOWN);

	if (!crypto_init (error))
		return NULL;

	parsed = parse_old_openssl_key_file (data, data_len, &key_type, &cipher, &iv, NULL);
	if (!parsed) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_INVALID_DATA,
		             _("Unable to determine private key type."));
		return NULL;
	}

	NM_SET_OUT (out_key_type, key_type);

	if (password) {
		if (!cipher || !iv) {
			g_set_error (error, NM_CRYPTO_ERROR,
			             NM_CRYPTO_ERROR_INVALID_PASSWORD,
			             _("Password provided, but key was not encrypted."));
			return NULL;
		}

		return decrypt_key (cipher,
		                    key_type,
		                    parsed->data,
		                    parsed->len,
		                    iv,
		                    password,
		                    error);
	}

	if (cipher || iv)
		return NULL;

	return g_steal_pointer (&parsed);
}

GByteArray *
nmtst_crypto_decrypt_openssl_private_key (const char *file,
                                          const char *password,
                                          NMCryptoKeyType *out_key_type,
                                          GError **error)
{
	nm_auto_clear_secret_ptr NMSecretPtr contents = { 0 };

	if (!crypto_init (error))
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

GByteArray *
crypto_load_and_verify_certificate (const char *file,
                                    NMCryptoFileFormat *out_file_format,
                                    GError **error)
{
	nm_auto_clear_secret_ptr NMSecretPtr contents = { 0 };

	g_return_val_if_fail (file != NULL, NULL);
	g_return_val_if_fail (out_file_format != NULL, NULL);

	*out_file_format = NM_CRYPTO_FILE_FORMAT_UNKNOWN;

	if (!crypto_init (error))
		return NULL;

	if (!file_read_contents (file, &contents, error))
		return NULL;

	/* Check for PKCS#12 */
	if (crypto_is_pkcs12_data (contents.bin, contents.len, NULL)) {
		*out_file_format = NM_CRYPTO_FILE_FORMAT_PKCS12;
		return to_gbyte_array_mem (contents.bin, contents.len);
	}

	/* Check for plain DER format */
	if (contents.len > 2 && contents.bin[0] == 0x30 && contents.bin[1] == 0x82) {
		*out_file_format = crypto_verify_cert (contents.bin, contents.len, error);
	} else {
		nm_auto_clear_secret_ptr NMSecretPtr pem_cert = { 0 };

		if (!extract_pem_cert_data (contents.bin, contents.len, &pem_cert, error))
			return NULL;

		*out_file_format = crypto_verify_cert (pem_cert.bin, pem_cert.len, error);
	}

	if (*out_file_format != NM_CRYPTO_FILE_FORMAT_X509)
		return NULL;

	return to_gbyte_array_mem (contents.bin, contents.len);
}

gboolean
crypto_is_pkcs12_data (const guint8 *data,
                       gsize data_len,
                       GError **error)
{
	GError *local = NULL;
	gboolean success;

	if (!data_len)
		return FALSE;

	g_return_val_if_fail (data != NULL, FALSE);

	if (!crypto_init (error))
		return FALSE;

	success = crypto_verify_pkcs12 (data, data_len, NULL, &local);
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
crypto_is_pkcs12_file (const char *file, GError **error)
{
	nm_auto_clear_secret_ptr NMSecretPtr contents = { 0 };

	g_return_val_if_fail (file != NULL, FALSE);

	if (!crypto_init (error))
		return FALSE;

	if (!file_read_contents (file, &contents, error))
		return FALSE;

	return crypto_is_pkcs12_data (contents.bin, contents.len, error);
}

/* Verifies that a private key can be read, and if a password is given, that
 * the private key can be decrypted with that password.
 */
NMCryptoFileFormat
crypto_verify_private_key_data (const guint8 *data,
                                gsize data_len,
                                const char *password,
                                gboolean *out_is_encrypted,
                                GError **error)
{
	NMCryptoFileFormat format = NM_CRYPTO_FILE_FORMAT_UNKNOWN;
	NMCryptoKeyType ktype = NM_CRYPTO_KEY_TYPE_UNKNOWN;
	gboolean is_encrypted = FALSE;

	g_return_val_if_fail (data != NULL, NM_CRYPTO_FILE_FORMAT_UNKNOWN);
	g_return_val_if_fail (out_is_encrypted == NULL || *out_is_encrypted == FALSE, NM_CRYPTO_FILE_FORMAT_UNKNOWN);

	if (!crypto_init (error))
		return NM_CRYPTO_FILE_FORMAT_UNKNOWN;

	/* Check for PKCS#12 first */
	if (crypto_is_pkcs12_data (data, data_len, NULL)) {
		is_encrypted = TRUE;
		if (!password || crypto_verify_pkcs12 (data, data_len, password, error))
			format = NM_CRYPTO_FILE_FORMAT_PKCS12;
	} else {
		nm_auto_unref_bytearray GByteArray *tmp = NULL;

		/* Maybe it's PKCS#8 */
		tmp = parse_pkcs8_key_file (data, data_len, &is_encrypted, NULL);
		if (tmp) {
			if (!password || crypto_verify_pkcs8 (tmp->data, tmp->len, is_encrypted, password, error))
				format = NM_CRYPTO_FILE_FORMAT_RAW_KEY;
		} else {
			const char *cipher;
			gs_free char *iv = NULL;

			/* Or it's old-style OpenSSL */
			tmp = parse_old_openssl_key_file (data, data_len, &ktype,
			                                  &cipher, &iv, NULL);
			if (tmp) {
				format = NM_CRYPTO_FILE_FORMAT_RAW_KEY;
				is_encrypted = (cipher && iv);
			}
		}

		if (tmp) {
			/* Don't leave key data around */
			memset (tmp->data, 0, tmp->len);
		}
	}

	if (out_is_encrypted)
		*out_is_encrypted = is_encrypted;
	return format;
}

NMCryptoFileFormat
crypto_verify_private_key (const char *filename,
                           const char *password,
                           gboolean *out_is_encrypted,
                           GError **error)
{
	nm_auto_clear_secret_ptr NMSecretPtr contents = { 0 };

	g_return_val_if_fail (filename != NULL, NM_CRYPTO_FILE_FORMAT_UNKNOWN);

	if (!crypto_init (error))
		return NM_CRYPTO_FILE_FORMAT_UNKNOWN;

	if (!file_read_contents (filename, &contents, error))
		return NM_CRYPTO_FILE_FORMAT_UNKNOWN;

	return crypto_verify_private_key_data (contents.bin, contents.len, password, out_is_encrypted, error);
}

void
crypto_md5_hash (const guint8 *salt,
                 gsize salt_len,
                 const guint8 *password,
                 gsize password_len,
                 guint8 *buffer,
                 gsize buflen)
{
	nm_auto_free_checksum GChecksum *ctx = NULL;
#define MD5_DIGEST_LEN 16
	nm_auto_clear_static_secret_ptr const NMSecretPtr digest = NM_SECRET_PTR_STATIC (MD5_DIGEST_LEN);
	gsize bufidx = 0;
	int i;

	nm_assert (g_checksum_type_get_length (G_CHECKSUM_MD5) == MD5_DIGEST_LEN);

	g_return_if_fail (password_len == 0 || password);
	g_return_if_fail (buffer);
	g_return_if_fail (buflen > 0);
	g_return_if_fail (salt_len == 0 || salt);

	ctx = g_checksum_new (G_CHECKSUM_MD5);

	for (;;) {
		gsize digest_len;

		if (password_len > 0)
			g_checksum_update (ctx, (const guchar *) password, password_len);
		if (salt_len > 0)
			g_checksum_update (ctx, (const guchar *) salt, salt_len);

		digest_len = MD5_DIGEST_LEN;
		g_checksum_get_digest (ctx, digest.bin, &digest_len);
		nm_assert (digest_len == MD5_DIGEST_LEN);

		for (i = 0; i < MD5_DIGEST_LEN; i++) {
			if (bufidx >= buflen)
				return;
			buffer[bufidx++] = digest.bin[i];
		}

		g_checksum_reset (ctx);
		g_checksum_update (ctx, digest.ptr, MD5_DIGEST_LEN);
	}
}
