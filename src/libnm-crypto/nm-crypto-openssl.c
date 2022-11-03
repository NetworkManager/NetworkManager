/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Joel Holdsworth <joel.holdsworth@vcatechnology.com>
 * Copyright (C) 2015 VCA Technology Ltd.
 */

#include "libnm-glib-aux/nm-default-glib-i18n-lib.h"

#include "nm-crypto-impl.h"

#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

gboolean
_nm_crypto_init(GError **error)
{
    static gboolean initialized = FALSE;

    if (initialized)
        return TRUE;

    CRYPTO_malloc_init();
    OpenSSL_add_all_algorithms();
    ENGINE_load_builtin_engines();

    initialized = TRUE;
    return TRUE;
}

static const EVP_CIPHER *
get_cipher(const char *cipher, GError **error)
{
    if (strcmp(cipher, CIPHER_DES_EDE3_CBC) == 0)
        return EVP_des_ede3_cbc();
    else if (strcmp(cipher, CIPHER_DES_CBC) == 0)
        return EVP_des_cbc();
    else if (strcmp(cipher, CIPHER_AES_CBC) == 0)
        return EVP_aes_128_cbc();
    else {
        g_set_error(error,
                    NM_CRYPTO_ERROR,
                    NM_CRYPTO_ERROR_UNKNOWN_CIPHER,
                    _("Private key cipher '%s' was unknown."),
                    cipher);
        return NULL;
    }
}

char *
crypto_decrypt(const char   *cipher,
               int           key_type,
               const guint8 *data,
               gsize         data_len,
               const char   *iv,
               const gsize   iv_len,
               const char   *key,
               const gsize   key_len,
               gsize        *out_len,
               GError      **error)
{
    const EVP_CIPHER *evp_cipher = NULL;
    EVP_CIPHER_CTX    ctx;
    char             *output      = NULL;
    gboolean          success     = FALSE;
    gsize             real_iv_len = 0;
    int               initial_len = 0, final_len = 0;

    if (!(evp_cipher = get_cipher(cipher, error)))
        return NULL;

    real_iv_len = EVP_CIPHER_iv_length(evp_cipher);
    if (iv_len < real_iv_len) {
        g_set_error(error,
                    NM_CRYPTO_ERROR,
                    NM_CRYPTO_ERROR_INVALID_DATA,
                    _("Invalid IV length (must be at least %zd)."),
                    real_iv_len);
        return NULL;
    }

    EVP_CIPHER_CTX_init(&ctx);
    if (!EVP_DecryptInit_ex(&ctx,
                            evp_cipher,
                            NULL,
                            (const unsigned char *) key,
                            (const unsigned char *) iv)) {
        g_set_error(error,
                    NM_CRYPTO_ERROR,
                    NM_CRYPTO_ERROR_DECRYPTION_FAILED,
                    _("Failed to initialize the decryption cipher context."));
        goto out;
    }

    output = g_malloc0(data_len);

    if (!EVP_DecryptUpdate(&ctx, (unsigned char *) output, &initial_len, data, data_len)) {
        g_set_error(error,
                    NM_CRYPTO_ERROR,
                    NM_CRYPTO_ERROR_DECRYPTION_FAILED,
                    _("Failed to decrypt the private key."));
        goto out;
    }

    /* Finalise decryption, and check the padding */
    if (!EVP_DecryptFinal_ex(&ctx, (unsigned char *) output + initial_len, &final_len)) {
        g_set_error(error,
                    NM_CRYPTO_ERROR,
                    NM_CRYPTO_ERROR_DECRYPTION_FAILED,
                    _("Failed to finalize decryption of the private key."));
        goto out;
    }

    *out_len = initial_len + final_len;
    success  = TRUE;

out:
    if (!success && output) {
        /* Don't expose key material */
        memset(output, 0, data_len);
        g_free(output);
        output = NULL;
    }
    EVP_CIPHER_CTX_cleanup(&ctx);
    return output;
}

char *
crypto_encrypt(const char   *cipher,
               const guint8 *data,
               gsize         data_len,
               const char   *iv,
               const gsize   iv_len,
               const char   *key,
               gsize         key_len,
               gsize        *out_len,
               GError      **error)
{
    const EVP_CIPHER *evp_cipher = NULL;
    EVP_CIPHER_CTX    ctx;
    char             *output  = NULL;
    gboolean          success = FALSE;
    gsize             pad_len, output_len;
    int               initial_len = 0, final_len = 0;

    if (!(evp_cipher = get_cipher(cipher, error)))
        return NULL;

    /* If data_len % ivlen == 0, then we add another complete block
	 * onto the end so that the decrypter knows there's padding.
	 */
    pad_len    = iv_len - (data_len % iv_len);
    output_len = data_len + pad_len;
    output     = g_malloc0(output_len);

    EVP_CIPHER_CTX_init(&ctx);
    if (!EVP_EncryptInit_ex(&ctx,
                            evp_cipher,
                            NULL,
                            (const unsigned char *) key,
                            (const unsigned char *) iv)) {
        g_set_error(error,
                    NM_CRYPTO_ERROR,
                    NM_CRYPTO_ERROR_DECRYPTION_FAILED,
                    _("Failed to initialize the encryption cipher context."));
        goto out;
    }

    if (!EVP_EncryptUpdate(&ctx, (unsigned char *) output, &initial_len, data, data_len)) {
        g_set_error(error,
                    NM_CRYPTO_ERROR,
                    NM_CRYPTO_ERROR_DECRYPTION_FAILED,
                    _("Failed to encrypt the private key."));
        goto out;
    }

    /* Finalise encryption, and add the padding */
    if (!EVP_EncryptFinal_ex(&ctx, (unsigned char *) output + initial_len, &final_len)) {
        g_set_error(error,
                    NM_CRYPTO_ERROR,
                    NM_CRYPTO_ERROR_DECRYPTION_FAILED,
                    _("Failed to finalize encryption of the private key."));
        goto out;
    }

    *out_len = initial_len + final_len;
    success  = TRUE;

out:
    if (!success && output) {
        /* Don't expose key material */
        memset(output, 0, output_len);
        g_free(output);
        output = NULL;
    }
    EVP_CIPHER_CTX_cleanup(&ctx);
    return output;
}

NMCryptoFileFormat
crypto_verify_cert(const unsigned char *data, gsize len, GError **error)
{
    BIO  *in = NULL;
    X509 *x  = NULL;

    /* Try PEM */
    in = BIO_new_mem_buf((void *) data, len);
    x  = PEM_read_bio_X509_AUX(in, NULL, NULL, NULL);
    BIO_free(in);
    X509_free(x);
    if (x)
        return NM_CRYPTO_FILE_FORMAT_X509;

    /* Try DER */
    in = BIO_new_mem_buf((void *) data, len);
    x  = d2i_X509_bio(in, NULL);
    BIO_free(in);
    X509_free(x);
    if (x)
        return NM_CRYPTO_FILE_FORMAT_X509;

    g_set_error(error,
                NM_CRYPTO_ERROR,
                NM_CRYPTO_ERROR_INVALID_DATA,
                _("Couldn't decode certificate"));
    return NM_CRYPTO_FILE_FORMAT_UNKNOWN;
}

gboolean
crypto_verify_pkcs12(const guint8 *data, gsize data_len, const char *password, GError **error)
{
    BIO     *in      = NULL;
    PKCS12  *p12     = NULL;
    gboolean success = FALSE;

    g_return_val_if_fail(data != NULL, FALSE);

    in  = BIO_new_mem_buf((void *) data, data_len);
    p12 = d2i_PKCS12_bio(in, NULL);
    BIO_free(in);

    if (!p12) {
        /* Currently only DER format PKCS12 files are supported. */
        g_set_error(error,
                    NM_CRYPTO_ERROR,
                    NM_CRYPTO_ERROR_INVALID_DATA,
                    _("Couldn't decode PKCS#12 file"));
        goto out;
    }

    if (password) {
        if (!(success = PKCS12_verify_mac(p12, password, -1)))
            g_set_error(error,
                        NM_CRYPTO_ERROR,
                        NM_CRYPTO_ERROR_DECRYPTION_FAILED,
                        _("Couldn't verify PKCS#12 file."));
    } else
        success = TRUE;

out:
    if (p12)
        PKCS12_free(p12);
    return success;
}

gboolean
crypto_verify_pkcs8(const guint8 *data,
                    gsize         data_len,
                    gboolean      is_encrypted,
                    const char   *password,
                    GError      **error)
{
    BIO                 *in    = NULL;
    X509_SIG            *p8    = NULL;
    PKCS8_PRIV_KEY_INFO *p8inf = NULL;

    g_return_val_if_fail(data != NULL, FALSE);

    if (is_encrypted) {
        in = BIO_new_mem_buf((void *) data, data_len);
        p8 = d2i_PKCS8_bio(in, NULL);
        BIO_free(in);

        if (p8) {
            X509_SIG_free(p8);
            return TRUE;
        } else {
            g_set_error(error,
                        NM_CRYPTO_ERROR,
                        NM_CRYPTO_ERROR_INVALID_DATA,
                        _("Couldn't decode PKCS#8 file"));
        }
    } else {
        in    = BIO_new_mem_buf((void *) data, data_len);
        p8inf = d2i_PKCS8_PRIV_KEY_INFO_bio(in, NULL);
        BIO_free(in);

        if (p8inf) {
            PKCS8_PRIV_KEY_INFO_free(p8inf);
            return p8inf->broken == 0;
        } else {
            g_set_error(error,
                        NM_CRYPTO_ERROR,
                        NM_CRYPTO_ERROR_INVALID_DATA,
                        _("Couldn't decode PKCS#8 file"));
        }
    }

    return FALSE;
}

gboolean
_nm_crypto_randomize(void *buffer, gsize buffer_len, GError **error)
{
    RAND_bytes(buffer, buffer_len);
    buffer_len = (buffer_len > 16) ? 16 : buffer_len;
    return TRUE;
}
