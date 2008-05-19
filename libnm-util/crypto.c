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
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <glib/gi18n.h>

#include "crypto.h"

GQuark
nm_crypto_error_quark (void)
{
	static GQuark quark;

	if (G_UNLIKELY (!quark))
		quark = g_quark_from_static_string ("nm-crypto-error-quark");
	return quark;
}


static const char *pem_rsa_key_begin = "-----BEGIN RSA PRIVATE KEY-----";
static const char *pem_rsa_key_end = "-----END RSA PRIVATE KEY-----";

static const char *pem_dsa_key_begin = "-----BEGIN DSA PRIVATE KEY-----";
static const char *pem_dsa_key_end = "-----END DSA PRIVATE KEY-----";

static const char *pem_cert_begin = "-----BEGIN CERTIFICATE-----";
static const char *pem_cert_end = "-----END CERTIFICATE-----";

static const char *
find_tag (const char *tag, const char *buf, gsize len)
{
	gsize i, taglen;

	taglen = strlen (tag);
	if (len < taglen)
		return NULL;

	for (i = 0; i < len - taglen; i++) {
		if (memcmp (buf + i, tag, taglen) == 0)
			return buf + i;
	}
	return NULL;
}

#define DEK_INFO_TAG "DEK-Info: "
#define PROC_TYPE_TAG "Proc-Type: "

static char *
parse_key_file (const char *filename,
                int key_type,
                gsize *out_length,
                char **out_cipher,
                char **out_iv,
                GError **error)
{
	char *contents = NULL;
	char **lines = NULL;
	char **ln = NULL;
	gsize length = 0;
	const char *pos;
	const char *end;
	GString *str = NULL;
	int enc_tags = 0;
	char *iv = NULL;
	char *cipher = NULL;
	char *bindata = NULL;
	gsize bindata_len = 0;
	const char *start_tag;
	const char *end_tag;

	switch (key_type) {
	case NM_CRYPTO_KEY_TYPE_RSA:
		start_tag = pem_rsa_key_begin;
		end_tag = pem_rsa_key_end;
		break;
	case NM_CRYPTO_KEY_TYPE_DSA:
		start_tag = pem_dsa_key_begin;
		end_tag = pem_dsa_key_end;
		break;
	default:
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_UNKNOWN_KEY_TYPE,
		             "Unknown key type %d",
		             key_type);
		g_assert_not_reached ();
		return NULL;
	}

	if (!g_file_get_contents (filename, &contents, &length, error))
		return NULL;

	pos = find_tag (start_tag, contents, length);
	if (!pos)
		goto parse_error;

	pos += strlen (start_tag);

	end = find_tag (end_tag, pos, contents + length - pos);
	if (end == NULL) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_PEM_FORMAT_INVALID,
		             _("PEM key file had no end tag '%s'."),
		             end_tag);
		goto parse_error;
	}
	*((char *) end) = '\0';

	lines = g_strsplit (pos, "\n", 0);
	if (!lines || g_strv_length (lines) <= 1) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_PEM_FORMAT_INVALID,
		             _("Doesn't look like a PEM private key file."));
		goto parse_error;
	}

	str = g_string_new_len (NULL, end - pos);
	if (!str) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_OUT_OF_MEMORY,
		             _("Not enough memory to store PEM file data."));
		goto parse_error;
	}

	for (ln = lines; *ln; ln++) {
		char *p = *ln;

		/* Chug leading spaces */
		p = g_strstrip (p);
		if (!*p)
			continue;

		if (!strncmp (p, PROC_TYPE_TAG, strlen (PROC_TYPE_TAG))) {
			if (enc_tags++ != 0) {
				g_set_error (error, NM_CRYPTO_ERROR,
				             NM_CRYPTO_ERR_PEM_FORMAT_INVALID,
				             _("Malformed PEM file: Proc-Type was not first tag."));
				goto parse_error;
			}

			p += strlen (PROC_TYPE_TAG);
			if (strcmp (p, "4,ENCRYPTED")) {
				g_set_error (error, NM_CRYPTO_ERROR,
				             NM_CRYPTO_ERR_PEM_FORMAT_INVALID,
				             _("Malformed PEM file: unknown Proc-Type tag '%s'."),
				             p);
				goto parse_error;
			}
		} else if (!strncmp (p, DEK_INFO_TAG, strlen (DEK_INFO_TAG))) {
			char *comma;

			if (enc_tags++ != 1) {
				g_set_error (error, NM_CRYPTO_ERROR,
				             NM_CRYPTO_ERR_PEM_FORMAT_INVALID,
				             _("Malformed PEM file: DEK-Info was not the second tag."));
				goto parse_error;
			}

			p += strlen (DEK_INFO_TAG);

			/* Grab the IV first */
			comma = strchr (p, ',');
			if (!comma || (*(comma + 1) == '\0')) {
				g_set_error (error, NM_CRYPTO_ERROR,
				             NM_CRYPTO_ERR_PEM_FORMAT_INVALID,
				             _("Malformed PEM file: no IV found in DEK-Info tag."));
				goto parse_error;
			}
			*comma++ = '\0';
			if (!g_ascii_isxdigit (*comma)) {
				g_set_error (error, NM_CRYPTO_ERROR,
				             NM_CRYPTO_ERR_PEM_FORMAT_INVALID,
				             _("Malformed PEM file: invalid format of IV in DEK-Info tag."));
				goto parse_error;
			}
			iv = g_strdup (comma);

			/* Get the private key cipher */
			if (!strcasecmp (p, "DES-EDE3-CBC")) {
				cipher = g_strdup (p);
			} else if (!strcasecmp (p, "DES-CBC")) {
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
				             NM_CRYPTO_ERR_PEM_FORMAT_INVALID,
				             "Malformed PEM file: both Proc-Type and DEK-Info tags are required.");
				goto parse_error;
			}
			g_string_append (str, p);
		}
	}

	bindata = (char *) g_base64_decode (str->str, &bindata_len);
	if (bindata == NULL || !bindata_len) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_DECODE_FAILED,
		             _("Could not decode private key."));
		goto parse_error;
	}

	if (lines)
		g_strfreev (lines);
	g_free (contents);

	*out_iv = iv;
	*out_cipher = cipher;
	*out_length = bindata_len;
	return bindata;

parse_error:
	g_free (bindata);
	g_free (cipher);
	g_free (iv);
	if (lines)
		g_strfreev (lines);
	g_free (contents);
	return NULL;
}

static GByteArray *
file_to_g_byte_array (const char *filename,
                      GError **error)
{
	char *contents, *der = NULL;
	GByteArray *array = NULL;
	gsize length = 0;
	const char *pos;

	if (!g_file_get_contents (filename, &contents, &length, error))
		return NULL;

	pos = find_tag (pem_cert_begin, contents, length);
	if (pos) {
		const char *end;

		pos += strlen (pem_cert_begin);
		end = find_tag (pem_cert_end, pos, contents + length - pos);
		if (end == NULL) {
			g_set_error (error, NM_CRYPTO_ERROR,
			             NM_CRYPTO_ERR_PEM_FORMAT_INVALID,
			             _("PEM certificate '%s' had no end tag '%s'."),
			             filename, pem_cert_end);
			goto done;
		}

		contents[end - contents - 1] = '\0';
		der = (char *) g_base64_decode (pos, &length);
		if (der == NULL || !length) {
			g_set_error (error, NM_CRYPTO_ERROR,
			             NM_CRYPTO_ERR_DECODE_FAILED,
			             _("Failed to decode certificate."));
			goto done;
		}
	}

	array = g_byte_array_sized_new (length);
	if (!array) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_OUT_OF_MEMORY,
		             _("Not enough memory to store certificate data."));
		goto done;
	}

	g_byte_array_append (array, der ? (unsigned char *) der : (unsigned char *) contents, length);
	if (array->len != length) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_OUT_OF_MEMORY,
		             _("Not enough memory to store certificate data."));
		g_byte_array_free (array, TRUE);
		array = NULL;
	}

done:
	g_free (der);
	g_free (contents);
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
    if (c == NULL) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_OUT_OF_MEMORY,
		             _("Not enough memory to store the IV."));
        return NULL;
	}

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
make_des_key (const char *cipher,
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
	else {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_UNKNOWN_CIPHER,
		             _("Private key cipher '%s' was unknown."),
		             cipher);
		return NULL;
	}

	key = g_malloc0 (digest_len + 1);
	if (!key) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_OUT_OF_MEMORY,
		             _("Not enough memory to create private key decryption key."));
		return NULL;
	}

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

static char *
decrypt_key (const char *cipher,
             int key_type,
             const char *data,
             gsize data_len,
             const char *iv,
             const char *password,
             gsize *out_len,
             GError **error)
{
	char *bin_iv = NULL;
	gsize bin_iv_len = 0;
	char *key = NULL;
	gsize key_len = 0;
	char *output = NULL;

	bin_iv = convert_iv (iv, &bin_iv_len, error);
	if (!bin_iv)
		return NULL;

	/* Convert the PIN and IV into a DES key */
	key = make_des_key (cipher, bin_iv, bin_iv_len, password, &key_len, error);
	if (!key || !key_len)
		goto out;

	output = crypto_decrypt (cipher, key_type,
	                         data, data_len,
	                         bin_iv, bin_iv_len,
	                         key, key_len,
	                         out_len,
	                         error);
	if (!output)
		goto out;

	if (*out_len == 0) {
		g_free (output);
		output = NULL;
		goto out;
	}
 
out:
	if (key) {
		/* Don't leak stale key material */
		memset (key, 0, key_len);
		g_free (key);
	}
	g_free (bin_iv);
	return output;
}


GByteArray *
crypto_get_private_key (const char *file,
                        const char *password,
                        guint32 *out_key_type,
                        GError **error)
{
	GByteArray *array = NULL;
	guint32 key_type = NM_CRYPTO_KEY_TYPE_RSA;
	char *data = NULL;
	gsize data_len = 0;
	char *iv = NULL;
	char *cipher = NULL;
	char *decrypted = NULL;
	gsize decrypted_len = 0;

	/* Try RSA first */
	data = parse_key_file (file, key_type, &data_len, &cipher, &iv, error);
	if (!data) {
		g_clear_error (error);

		/* DSA next */
		key_type = NM_CRYPTO_KEY_TYPE_DSA;
		data = parse_key_file (file, key_type, &data_len, &cipher, &iv, error);
		if (!data)
			goto out;
	}

	decrypted = decrypt_key (cipher,
	                         key_type,
	                         data,
	                         data_len,
	                         iv,
	                         password,
	                         &decrypted_len,
	                         error);
	if (!decrypted)
		goto out;

	array = g_byte_array_sized_new (decrypted_len);
	if (!array) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERR_OUT_OF_MEMORY,
		             _("Not enough memory to store decrypted private key."));
		goto out;
	}

	g_byte_array_append (array, (const guint8 *) decrypted, decrypted_len);
	*out_key_type = key_type;

out:
	if (decrypted) {
		/* Don't expose key material */
		memset (decrypted, 0, decrypted_len);
		g_free (decrypted);
	}
	g_free (data);
	g_free (cipher);
	g_free (iv);
	return array;
}

GByteArray *
crypto_load_and_verify_certificate (const char *file,
                                    GError **error)
{
	GByteArray *array;

	array = file_to_g_byte_array (file, error);
	if (!array)
		return NULL;

	if (!crypto_verify_cert (array->data, array->len, error)) {
		g_byte_array_free (array, TRUE);
		array = NULL;
	}

	return array;
}

