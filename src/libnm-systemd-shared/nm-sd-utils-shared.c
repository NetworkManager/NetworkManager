/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2018 Red Hat, Inc.
 */

#include "libnm-systemd-shared/nm-default-systemd-shared.h"

#include "nm-sd-utils-shared.h"

#include "nm-sd-adapt-shared.h"

#include "dns-domain.h"
#include "hexdecoct.h"
#include "hostname-util.h"
#include "path-util.h"
#include "web-util.h"

/*****************************************************************************/

const bool mempool_use_allowed = true;

/*****************************************************************************/

gboolean
nm_sd_utils_path_equal(const char *a, const char *b)
{
    return path_equal(a, b);
}

char *
nm_sd_utils_path_simplify(char *path, gboolean kill_dots)
{
    return path_simplify(path, kill_dots);
}

const char *
nm_sd_utils_path_startswith(const char *path, const char *prefix)
{
    return path_startswith(path, prefix);
}

/*****************************************************************************/

int
nm_sd_utils_unbase64char(char ch, gboolean accept_padding_equal)
{
    if (ch == '=' && accept_padding_equal)
        return G_MAXINT;
    return unbase64char(ch);
}

/**
 * nm_sd_utils_unbase64mem:
 * @p: a valid base64 string. Whitespace is ignored, but invalid encodings
 *   will cause the function to fail.
 * @l: the length of @p. @p is not treated as NUL terminated string but
 *   merely as a buffer of ascii characters.
 * @secure: whether the temporary memory will be cleared to avoid leaving
 *   secrets in memory (see also nm_explicit_bzero()).
 * @mem: (transfer full): the decoded buffer on success.
 * @len: the length of @mem on success.
 *
 * glib provides g_base64_decode(), but that does not report any errors
 * from invalid encodings. Expose systemd's implementation which does
 * reject invalid inputs.
 *
 * Returns: a non-negative code on success. Invalid encoding let the
 *   function fail.
 */
int
nm_sd_utils_unbase64mem(const char *p, size_t l, gboolean secure, guint8 **mem, size_t *len)
{
    return unbase64mem_full(p, l, secure, (void **) mem, len);
}

int
nm_sd_dns_name_to_wire_format(const char *domain, guint8 *buffer, size_t len, gboolean canonical)
{
    return dns_name_to_wire_format(domain, buffer, len, canonical);
}

int
nm_sd_dns_name_is_valid(const char *s)
{
    return dns_name_is_valid(s);
}

gboolean
nm_sd_hostname_is_valid(const char *s, bool allow_trailing_dot)
{
    return hostname_is_valid(s,
                             allow_trailing_dot ? VALID_HOSTNAME_TRAILING_DOT
                                                : (ValidHostnameFlags) 0);
}

char *
nm_sd_dns_name_normalize(const char *s)
{
    nm_auto_free char *n = NULL;
    int                r;

    r = dns_name_normalize(s, 0, &n);
    if (r < 0)
        return NULL;

    nm_assert(n);

    /* usually we try not to mix malloc/g_malloc and free/g_free. In practice,
     * they are the same. So here we return a buffer allocated with malloc(),
     * and the caller should free it with g_free(). */
    return g_steal_pointer(&n);
}

/*****************************************************************************/

static gboolean
_http_url_is_valid(const char *url, gboolean only_https)
{
    if (!url || !url[0])
        return FALSE;

    if (!only_https && NM_STR_HAS_PREFIX(url, "http://"))
        url += NM_STRLEN("http://");
    else if (NM_STR_HAS_PREFIX(url, "https://"))
        url += NM_STRLEN("https://");
    else
        return FALSE;

    if (!url[0])
        return FALSE;

    return !NM_STRCHAR_ANY(url, ch, (guchar) ch >= 128u);
}

gboolean
nm_sd_http_url_is_valid_https(const char *url)
{
    /* We use this function to verify connection:mud-url property, it must thus
     * not change behavior.
     *
     * Note that sd_dhcp_client_set_mud_url() and sd_dhcp6_client_set_request_mud_url()
     * assert with http_url_is_valid() that the argument is valid. We thus must make
     * sure to only pass URLs that are valid according to http_url_is_valid().
     *
     * This is given, because our nm_sd_http_url_is_valid_https() is more strict
     * than http_url_is_valid().
     *
     * We only must make sure that this is also correct in the future, when we
     * re-import systemd code. */
    nm_assert(_http_url_is_valid(url, FALSE) == http_url_is_valid(url));
    return _http_url_is_valid(url, TRUE);
}

/*****************************************************************************/

int
nmtst_systemd_extract_first_word_all(const char *str, char ***out_strv)
{
    gs_unref_ptrarray GPtrArray *arr = NULL;

    /* we implement a str split function to parse `/proc/cmdline`. This
     * code should behave like systemd, which uses extract_first_word()
     * for that.
     *
     * As we want to unit-test our implementation to match systemd,
     * expose this function for testing. */

    g_assert(out_strv);
    g_assert(!*out_strv);

    if (!str)
        return 0;

    arr = g_ptr_array_new_with_free_func(g_free);

    for (;;) {
        gs_free char *word = NULL;
        int           r;

        r = extract_first_word(&str, &word, NULL, EXTRACT_UNQUOTE | EXTRACT_RELAX);
        if (r < 0)
            return r;
        if (r == 0)
            break;
        g_ptr_array_add(arr, g_steal_pointer(&word));
    }

    g_ptr_array_add(arr, NULL);

    *out_strv = (char **) g_ptr_array_free(g_steal_pointer(&arr), FALSE);
    return 1;
}
