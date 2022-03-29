/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Christian Eggers <ceggers@arri.de>
 * Copyright (C) 2020 - 2022 ARRI Lighting
 */

#include "libnm-glib-aux/nm-default-glib-i18n-lib.h"

#include "nm-crypto-impl.h"

#include "libnm-glib-aux/nm-secret-utils.h"

/*****************************************************************************/

gboolean
_nm_crypto_init(GError **error)
{
    g_set_error(error,
                _NM_CRYPTO_ERROR,
                _NM_CRYPTO_ERROR_FAILED,
                _("Compiled without crypto support."));
    return FALSE;
}

guint8 *
_nmtst_crypto_decrypt(NMCryptoCipherType cipher,
                      const guint8      *data,
                      gsize              data_len,
                      const guint8      *iv,
                      gsize              iv_len,
                      const guint8      *key,
                      gsize              key_len,
                      gsize             *out_len,
                      GError           **error)
{
    g_set_error(error,
                _NM_CRYPTO_ERROR,
                _NM_CRYPTO_ERROR_FAILED,
                _("Compiled without crypto support."));
    return NULL;
}

guint8 *
_nmtst_crypto_encrypt(NMCryptoCipherType cipher,
                      const guint8      *data,
                      gsize              data_len,
                      const guint8      *iv,
                      gsize              iv_len,
                      const guint8      *key,
                      gsize              key_len,
                      gsize             *out_len,
                      GError           **error)
{
    g_set_error(error,
                _NM_CRYPTO_ERROR,
                _NM_CRYPTO_ERROR_FAILED,
                _("Compiled without crypto support."));
    return NULL;
}

gboolean
_nm_crypto_verify_x509(const guint8 *data, gsize len, GError **error)
{
    g_set_error(error,
                _NM_CRYPTO_ERROR,
                _NM_CRYPTO_ERROR_FAILED,
                _("Compiled without crypto support."));
    return FALSE;
}

gboolean
_nm_crypto_verify_pkcs12(const guint8 *data, gsize data_len, const char *password, GError **error)
{
    g_set_error(error,
                _NM_CRYPTO_ERROR,
                _NM_CRYPTO_ERROR_FAILED,
                _("Compiled without crypto support."));
    return FALSE;
}

gboolean
_nm_crypto_verify_pkcs8(const guint8 *data,
                        gsize         data_len,
                        gboolean      is_encrypted,
                        const char   *password,
                        GError      **error)
{
    g_set_error(error,
                _NM_CRYPTO_ERROR,
                _NM_CRYPTO_ERROR_FAILED,
                _("Compiled without crypto support."));
    return FALSE;
}

gboolean
_nm_crypto_randomize(void *buffer, gsize buffer_len, GError **error)
{
    g_set_error(error,
                _NM_CRYPTO_ERROR,
                _NM_CRYPTO_ERROR_FAILED,
                _("Compiled without crypto support."));
    return FALSE;
}
