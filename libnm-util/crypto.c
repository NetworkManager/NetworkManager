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
 * Copyright 2007 - 2011 Red Hat, Inc.
 */

#include "nm-default.h"

#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <stdlib.h>

#include "crypto.h"

GQuark
_nm_crypto_error_quark (void)
{
	static GQuark quark;

	if (G_UNLIKELY (!quark))
		quark = g_quark_from_static_string ("nm-crypto-error-quark");
	return quark;
}

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

static gboolean
find_tag (const char *tag,
          const GByteArray *array,
          gsize start_at,
          gsize *out_pos)
{
	gsize i, taglen;
	gsize len = array->len - start_at;

	g_return_val_if_fail (out_pos != NULL, FALSE);

	taglen = strlen (tag);
	if (len >= taglen) {
		for (i = 0; i < len - taglen + 1; i++) {
			if (memcmp (array->data + start_at + i, tag, taglen) == 0) {
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
parse_old_openssl_key_file (const GByteArray *contents,
                            int key_type,
                            char **out_cipher,
                            char **out_iv,
                            GError **error)
{
	GByteArray *bindata = NULL;
	char **lines = NULL;
	char **ln = NULL;
	gsize start = 0, end = 0;
	GString *str = NULL;
	int enc_tags = 0;
	char *iv = NULL;
	char *cipher = NULL;
	unsigned char *tmp = NULL;
	gsize tmp_len = 0;
	const char *start_tag;
	const char *end_tag;
	guint8 save_end = 0;

	switch (key_type) {
	case NM_CRYPTO_KEY_TYPE_RSA:
		start_tag = PEM_RSA_KEY_BEGIN;
		end_tag = PEM_RSA_KEY_END;
		break;
	case NM_CRYPTO_KEY_TYPE_DSA:
		start_tag = PEM_DSA_KEY_BEGIN;
		end_tag = PEM_DSA_KEY_END;
		break;
	default:
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_UNKNOWN_KEY_TYPE,
		             "Unknown key type %d",
		             key_type);
		g_assert_not_reached ();
		return NULL;
	}

	if (!find_tag (start_tag, contents, 0, &start))
		goto parse_error;

	start += strlen (start_tag);
	if (!find_tag (end_tag, contents, start, &end)) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_FILE_FORMAT_INVALID,
		             _("PEM key file had no end tag '%s'."),
		             end_tag);
		goto parse_error;
	}

	save_end = contents->data[end];
	contents->data[end] = '\0';
	lines = g_strsplit ((const char *) (contents->data + start), "\n", 0);
	contents->data[end] = save_end;

	if (!lines || g_strv_length (lines) <= 1) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_FILE_FORMAT_INVALID,
		             _("Doesn't look like a PEM private key file."));
		goto parse_error;
	}

	str = g_string_new_len (NULL, end - start);
	for (ln = lines; *ln; ln++) {
		char *p = *ln;

		/* Chug leading spaces */
		p = g_strstrip (p);
		if (!*p)
			continue;

		if (!strncmp (p, PROC_TYPE_TAG, strlen (PROC_TYPE_TAG))) {
			if (enc_tags++ != 0) {
				g_set_error (error, NM_CRYPTO_ERROR,
				             NM_CRYPTO_ERR_FILE_FORMAT_INVALID,
				             _("Malformed PEM file: Proc-Type was not first tag."));
				goto parse_error;
			}

			p += strlen (PROC_TYPE_TAG);
			if (strcmp (p, "4,ENCRYPTED")) {
				g_set_error (error, NM_CRYPTO_ERROR,
				             NM_CRYPTO_ERR_FILE_FORMAT_INVALID,
				             _("Malformed PEM file: unknown Proc-Type tag '%s'."),
				             p);
				goto parse_error;
			}
		} else if (!strncmp (p, DEK_INFO_TAG, strlen (DEK_INFO_TAG))) {
			char *comma;

			if (enc_tags++ != 1) {
				g_set_error (error, NM_CRYPTO_ERROR,
				             NM_CRYPTO_ERR_FILE_FORMAT_INVALID,
				             _("Malformed PEM file: DEK-Info was not the second tag."));
				goto parse_error;
			}

			p += strlen (DEK_INFO_TAG);

			/* Grab the IV first */
			comma = strchr (p, ',');
			if (!comma || (*(comma + 1) == '\0')) {
				g_set_error (error, NM_CRYPTO_ERROR,
				             NM_CRYPTO_ERR_FILE_FORMAT_INVALID,
				             _("Malformed PEM file: no IV found in DEK-Info tag."));
				goto parse_error;
			}
			*comma++ = '\0';
			if (!g_ascii_isxdigit (*comma)) {
				g_set_error (error, NM_CRYPTO_ERROR,
				             NM_CRYPTO_ERR_FILE_FORMAT_INVALID,
				             _("Malformed PEM file: invalid format of IV in DEK-Info tag."));
				goto parse_error;
			}
			iv = g_strdup (comma);

			/* Get the private key cipher */
			if (!strcasecmp (p, "DES-EDE3-CBC")) {
				cipher = g_strdup (p);
			} else if (!strcasecmp (p, "DES-CBC")) {
				cipher = g_strdup (p);
			} else if (!strcasecmp (p, "AES-128-CBC")) {
				cipher = g_strdup (p);
			} else {
				g_set_error (error, NM_CRYPTO_ERROR,
				             NM_CRYPTO_ERR_UNKNOWN_KEY_TYPE,
				             _("Malformed PEM file: unknown private key cipher '%s'."),
				             p);
				goto parse_error;
			}
		} else {
			if ((enc_tags != 0) && (enc_tags != 2)) {
				g_set_error (error, NM_CRYPTO_ERROR,
				             NM_CRYPTO_ERR_FILE_FORMAT_INVALID,
				             "Malformed PEM file: both Proc-Type and DEK-Info tags are required.");
				goto parse_error;
			}
			g_string_append (str, p);
		}
	}

	tmp = g_base64_decode (str->str, &tmp_len);
	if (tmp == NULL || !tmp_len) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_DECODE_FAILED,
		             _("Could not decode private key."));
		goto parse_error;
	}
	g_string_free (str, TRUE);

	if (lines)
		g_strfreev (lines);

	bindata = g_byte_array_sized_new (tmp_len);
	g_byte_array_append (bindata, tmp, tmp_len);
	g_free (tmp);

	*out_iv = iv;
	*out_cipher = cipher;
	return bindata;

parse_error:
	g_free (tmp);
	g_free (cipher);
	g_free (iv);
	if (str)
		g_string_free (str, TRUE);
	if (lines)
		g_strfreev (lines);
	return NULL;
}

static GByteArray *
parse_pkcs8_key_file (const GByteArray *contents,
                      gboolean *out_encrypted,
                      GError **error)
{
	GByteArray *key = NULL;
	gsize start = 0, end = 0;
	unsigned char *der = NULL;
	guint8 save_end;
	gsize length = 0;
	const char *start_tag = NULL, *end_tag = NULL;
	gboolean encrypted = FALSE;

	/* Try encrypted first, decrypted next */
	if (find_tag (PEM_PKCS8_ENC_KEY_BEGIN, contents, 0, &start)) {
		start_tag = PEM_PKCS8_ENC_KEY_BEGIN;
		end_tag = PEM_PKCS8_ENC_KEY_END;
		encrypted = TRUE;
	} else if (find_tag (PEM_PKCS8_DEC_KEY_BEGIN, contents, 0, &start)) {
		start_tag = PEM_PKCS8_DEC_KEY_BEGIN;
		end_tag = PEM_PKCS8_DEC_KEY_END;
		encrypted = FALSE;
	} else {
		g_set_error_literal (error, NM_CRYPTO_ERROR,
		                     NM_CRYPTO_ERR_FILE_FORMAT_INVALID,
		                     _("Failed to find expected PKCS#8 start tag."));
		return NULL;
	}

	start += strlen (start_tag);
	if (!find_tag (end_tag, contents, start, &end)) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_FILE_FORMAT_INVALID,
		             _("Failed to find expected PKCS#8 end tag '%s'."),
		             end_tag);
		return NULL;
	}

	/* g_base64_decode() wants a NULL-terminated string */
	save_end = contents->data[end];
	contents->data[end] = '\0';
	der = g_base64_decode ((const char *) (contents->data + start), &length);
	contents->data[end] = save_end;

	if (der && length) {
		key = g_byte_array_sized_new (length);
		g_byte_array_append (key, der, length);
		g_assert (key->len == length);
		*out_encrypted = encrypted;
	} else {
		g_set_error_literal (error, NM_CRYPTO_ERROR,
		                     NM_CRYPTO_ERR_DECODE_FAILED,
		                     _("Failed to decode PKCS#8 private key."));
	}

	g_free (der);
	return key;
}

static GByteArray *
file_to_g_byte_array (const char *filename, GError **error)
{
	char *contents;
	GByteArray *array = NULL;
	gsize length = 0;

	if (g_file_get_contents (filename, &contents, &length, error)) {
		array = g_byte_array_sized_new (length);
		g_byte_array_append (array, (guint8 *) contents, length);
		g_assert (array->len == length);
		g_free (contents);
	}
	return array;
}

/*
 * Convert a hex string into bytes.
 */
static char *
convert_iv (const char *src,
            gsize *out_len,
            GError **error)
{
	int num;
	int i;
	char conv[3];
	char *c;

	g_return_val_if_fail (src != NULL, NULL);

	num = strlen (src);
	if (num % 2) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_RAW_IV_INVALID,
		             _("IV must be an even number of bytes in length."));
		return NULL;
	}

	num /= 2;
	c = g_malloc0 (num + 1);

	conv[2] = '\0';
	for (i = 0; i < num; i++) {
		conv[0] = src[(i * 2)];
		conv[1] = src[(i * 2) + 1];
		if (!g_ascii_isxdigit (conv[0]) || !g_ascii_isxdigit (conv[1])) {
			g_set_error (error, NM_CRYPTO_ERROR,
			             NM_CRYPTO_ERR_RAW_IV_INVALID,
			             _("IV contains non-hexadecimal digits."));
			goto error;
		}

		c[i] = strtol(conv, NULL, 16);
	}
	*out_len = num;
	return c;

error:
	g_free (c);
	return NULL;
}

static char *
make_des_aes_key (const char *cipher,
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

	if (!strcmp (cipher, "DES-EDE3-CBC"))
		digest_len = 24;
	else if (!strcmp (cipher, "DES-CBC"))
		digest_len = 8;
	else if (!strcmp (cipher, "AES-128-CBC"))
		digest_len = 16;
	else {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_UNKNOWN_CIPHER,
		             _("Private key cipher '%s' was unknown."),
		             cipher);
		return NULL;
	}

	if (password[0] == '\0')
		return NULL;

	key = g_malloc0 (digest_len + 1);

	if (!crypto_md5_hash (salt,
	                      salt_len,
	                      password,
	                      strlen (password),
	                      key,
	                      digest_len,
	                      error))
		goto error;

	*out_len = digest_len;
	return key;

error:
	if (key) {
		/* Don't leak stale key material */
		memset (key, 0, digest_len);
		g_free (key);
	}
	return NULL;
}

static GByteArray *
decrypt_key (const char *cipher,
             int key_type,
             GByteArray *data,
             const char *iv,
             const char *password,
             GError **error)
{
	char *bin_iv = NULL;
	gsize bin_iv_len = 0;
	char *key = NULL;
	gsize key_len = 0;
	char *output = NULL;
	gsize decrypted_len = 0;
	GByteArray *decrypted = NULL;

	g_return_val_if_fail (password != NULL, NULL);

	bin_iv = convert_iv (iv, &bin_iv_len, error);
	if (!bin_iv)
		return NULL;

	/* Convert the password and IV into a DES or AES key */
	key = make_des_aes_key (cipher, bin_iv, bin_iv_len, password, &key_len, error);
	if (!key || !key_len)
		goto out;

	output = crypto_decrypt (cipher, key_type,
	                         data,
	                         bin_iv, bin_iv_len,
	                         key, key_len,
	                         &decrypted_len,
	                         error);
	if (output && decrypted_len) {
		decrypted = g_byte_array_sized_new (decrypted_len);
		g_byte_array_append (decrypted, (guint8 *) output, decrypted_len);
	}

out:
	/* Don't leak stale key material */
	if (key)
		memset (key, 0, key_len);
	g_free (output);
	g_free (key);
	g_free (bin_iv);

	return decrypted;
}

GByteArray *
crypto_decrypt_private_key_data (const GByteArray *contents,
                                 const char *password,
                                 NMCryptoKeyType *out_key_type,
                                 GError **error)
{
	GByteArray *decrypted = NULL;
	NMCryptoKeyType key_type = NM_CRYPTO_KEY_TYPE_RSA;
	GByteArray *data;
	char *iv = NULL;
	char *cipher = NULL;

	g_return_val_if_fail (contents != NULL, NULL);
	if (out_key_type)
		g_return_val_if_fail (*out_key_type == NM_CRYPTO_KEY_TYPE_UNKNOWN, NULL);

	/* OpenSSL non-standard legacy PEM files */

	/* Try RSA keys first */
	data = parse_old_openssl_key_file (contents, key_type, &cipher, &iv, error);
	if (!data) {
		g_clear_error (error);

		/* DSA next */
		key_type = NM_CRYPTO_KEY_TYPE_DSA;
		data = parse_old_openssl_key_file (contents, key_type, &cipher, &iv, error);
		if (!data) {
			g_clear_error (error);
			g_set_error (error, NM_CRYPTO_ERROR,
			             NM_CRYPTO_ERR_FILE_FORMAT_INVALID,
			             _("Unable to determine private key type."));
		}
	}

	if (data) {
		/* return the key type even if decryption failed */
		if (out_key_type)
			*out_key_type = key_type;

		if (password) {
			decrypted = decrypt_key (cipher,
			                         key_type,
			                         data,
			                         iv,
			                         password,
			                         error);
		}
		g_byte_array_free (data, TRUE);
	}

	g_free (cipher);
	g_free (iv);

	return decrypted;
}

GByteArray *
crypto_decrypt_private_key (const char *file,
                            const char *password,
                            NMCryptoKeyType *out_key_type,
                            GError **error)
{
	GByteArray *contents;
	GByteArray *key = NULL;

	contents = file_to_g_byte_array (file, error);
	if (contents) {
		key = crypto_decrypt_private_key_data (contents, password, out_key_type, error);
		g_byte_array_free (contents, TRUE);
	}
	return key;
}

static GByteArray *
extract_pem_cert_data (GByteArray *contents, GError **error)
{
	GByteArray *cert = NULL;
	gsize start = 0, end = 0;
	unsigned char *der = NULL;
	guint8 save_end;
	gsize length = 0;

	if (!find_tag (PEM_CERT_BEGIN, contents, 0, &start)) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_FILE_FORMAT_INVALID,
		             _("PEM certificate had no start tag '%s'."),
		             PEM_CERT_BEGIN);
		goto done;
	}

	start += strlen (PEM_CERT_BEGIN);
	if (!find_tag (PEM_CERT_END, contents, start, &end)) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_FILE_FORMAT_INVALID,
		             _("PEM certificate had no end tag '%s'."),
		             PEM_CERT_END);
		goto done;
	}

	/* g_base64_decode() wants a NULL-terminated string */
	save_end = contents->data[end];
	contents->data[end] = '\0';
	der = g_base64_decode ((const char *) (contents->data + start), &length);
	contents->data[end] = save_end;

	if (der && length) {
		cert = g_byte_array_sized_new (length);
		g_byte_array_append (cert, der, length);
		g_assert (cert->len == length);
	} else {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_DECODE_FAILED,
		             _("Failed to decode certificate."));
	}

done:
	g_free (der);
	return cert;
}

GByteArray *
crypto_load_and_verify_certificate (const char *file,
                                    NMCryptoFileFormat *out_file_format,
                                    GError **error)
{
	GByteArray *array, *contents;

	g_return_val_if_fail (file != NULL, NULL);
	g_return_val_if_fail (out_file_format != NULL, NULL);
	g_return_val_if_fail (*out_file_format == NM_CRYPTO_FILE_FORMAT_UNKNOWN, NULL);

	contents = file_to_g_byte_array (file, error);
	if (!contents)
		return NULL;

	/* Check for PKCS#12 */
	if (crypto_is_pkcs12_data (contents)) {
		*out_file_format = NM_CRYPTO_FILE_FORMAT_PKCS12;
		return contents;
	}

	/* Check for plain DER format */
	if (contents->len > 2 && contents->data[0] == 0x30 && contents->data[1] == 0x82) {
		*out_file_format = crypto_verify_cert (contents->data, contents->len, error);
	} else {
		array = extract_pem_cert_data (contents, error);
		if (!array) {
			g_byte_array_free (contents, TRUE);
			return NULL;
		}

		*out_file_format = crypto_verify_cert (array->data, array->len, error);
		g_byte_array_free (array, TRUE);
	}

	if (*out_file_format != NM_CRYPTO_FILE_FORMAT_X509) {
		g_byte_array_free (contents, TRUE);
		contents = NULL;
	}

	return contents;
}

gboolean
crypto_is_pkcs12_data (const GByteArray *data)
{
	GError *error = NULL;
	gboolean success;

	g_return_val_if_fail (data != NULL, FALSE);

	if (!data->len)
		return FALSE;

	success = crypto_verify_pkcs12 (data, NULL, &error);
	if (success == FALSE) {
		/* If the error was just a decryption error, then it's pkcs#12 */
		if (error) {
			if (g_error_matches (error, NM_CRYPTO_ERROR, NM_CRYPTO_ERR_CIPHER_DECRYPT_FAILED))
				success = TRUE;
			g_error_free (error);
		}
	}
	return success;
}

gboolean
crypto_is_pkcs12_file (const char *file, GError **error)
{
	GByteArray *contents;
	gboolean success = FALSE;

	g_return_val_if_fail (file != NULL, FALSE);

	contents = file_to_g_byte_array (file, error);
	if (contents) {
		success = crypto_is_pkcs12_data (contents);
		g_byte_array_free (contents, TRUE);
	}
	return success;
}

/* Verifies that a private key can be read, and if a password is given, that
 * the private key can be decrypted with that password.
 */
NMCryptoFileFormat
crypto_verify_private_key_data (const GByteArray *contents,
                                const char *password,
                                GError **error)
{
	GByteArray *tmp;
	NMCryptoFileFormat format = NM_CRYPTO_FILE_FORMAT_UNKNOWN;
	NMCryptoKeyType ktype = NM_CRYPTO_KEY_TYPE_UNKNOWN;
	gboolean is_encrypted = FALSE;

	g_return_val_if_fail (contents != NULL, FALSE);

	/* Check for PKCS#12 first */
	if (crypto_is_pkcs12_data (contents)) {
		if (!password || crypto_verify_pkcs12 (contents, password, error))
			format = NM_CRYPTO_FILE_FORMAT_PKCS12;
	} else {
		/* Maybe it's PKCS#8 */
		tmp = parse_pkcs8_key_file (contents, &is_encrypted, error);
		if (tmp) {
			if (!password || crypto_verify_pkcs8 (tmp, is_encrypted, password, error))
				format = NM_CRYPTO_FILE_FORMAT_RAW_KEY;
		} else {
			g_clear_error (error);

			/* Or it's old-style OpenSSL */
			tmp = crypto_decrypt_private_key_data (contents, password, &ktype, error);
			if (tmp)
				format = NM_CRYPTO_FILE_FORMAT_RAW_KEY;
			else if (!password && (ktype != NM_CRYPTO_KEY_TYPE_UNKNOWN))
				format = NM_CRYPTO_FILE_FORMAT_RAW_KEY;
		}

		if (tmp) {
			/* Don't leave decrypted key data around */
			memset (tmp->data, 0, tmp->len);
			g_byte_array_free (tmp, TRUE);
		}
	}

	return format;
}

NMCryptoFileFormat
crypto_verify_private_key (const char *filename,
                           const char *password,
                           GError **error)
{
	GByteArray *contents;
	NMCryptoFileFormat format = NM_CRYPTO_FILE_FORMAT_UNKNOWN;

	g_return_val_if_fail (filename != NULL, FALSE);

	contents = file_to_g_byte_array (filename, error);
	if (contents) {
		format = crypto_verify_private_key_data (contents, password, error);
		g_byte_array_free (contents, TRUE);
	}
	return format;
}
