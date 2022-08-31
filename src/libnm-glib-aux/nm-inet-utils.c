/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "libnm-glib-aux/nm-default-glib-i18n-lib.h"

#include "nm-inet-utils.h"

#include <netinet/in.h>
#include <arpa/inet.h>

/*****************************************************************************/

const NMIPAddr nm_ip_addr_zero = {};

/* We use _nm_alignas(NMIPAddr) to ensure that fields for in_addr_t and
 * struct in6_addr have all the same alignment. Ensure that this is suitable. */
G_STATIC_ASSERT(_nm_alignof(in_addr_t) <= _nm_alignof(NMIPAddr));
G_STATIC_ASSERT(_nm_alignof(struct in_addr) <= _nm_alignof(NMIPAddr));
G_STATIC_ASSERT(_nm_alignof(struct in6_addr) <= _nm_alignof(NMIPAddr));
G_STATIC_ASSERT(_nm_alignof(NMEtherAddr) <= _nm_alignof(NMIPAddr));

int
nm_ip_addr_cmp_for_sort(gconstpointer a, gconstpointer b, gpointer user_data)
{
    /* This is a compare function that can be used for sorting IP addresses.
     * Essentially, it calls memcmp(). @user_data must be GINT_TO_POINTER(addr_family).
     * @a and @b must be either pointers to in_addr_t, struct in6_addr or NMIPAddr. */
    return nm_ip_addr_cmp(GPOINTER_TO_INT(user_data), a, b);
}

/* this initializes a struct in_addr/in6_addr and allows for untrusted
 * arguments (like unsuitable @addr_family or @src_len). It's almost safe
 * in the sense that it verifies input arguments strictly. Also, it
 * uses memcpy() to access @src, so alignment is not an issue.
 *
 * Only potential pitfalls:
 *
 * - it allows for @addr_family to be AF_UNSPEC. If that is the case (and the
 *   caller allows for that), the caller MUST provide @out_addr_family.
 * - when setting @dst to an IPv4 address, the trailing bytes are not touched.
 *   Meaning, if @dst is an NMIPAddr union, only the first bytes will be set.
 *   If that matter to you, clear @dst before. */
gboolean
nm_ip_addr_set_from_untrusted(int           addr_family,
                              gpointer      dst,
                              gconstpointer src,
                              gsize         src_len,
                              int          *out_addr_family)
{
    nm_assert(dst);

    switch (addr_family) {
    case AF_UNSPEC:
        if (!out_addr_family) {
            /* when the callers allow undefined @addr_family, they must provide
             * an @out_addr_family argument. */
            nm_assert_not_reached();
            return FALSE;
        }
        switch (src_len) {
        case sizeof(struct in_addr):
            addr_family = AF_INET;
            break;
        case sizeof(struct in6_addr):
            addr_family = AF_INET6;
            break;
        default:
            return FALSE;
        }
        break;
    case AF_INET:
        if (src_len != sizeof(struct in_addr))
            return FALSE;
        break;
    case AF_INET6:
        if (src_len != sizeof(struct in6_addr))
            return FALSE;
        break;
    default:
        /* when the callers allow undefined @addr_family, they must provide
         * an @out_addr_family argument. */
        nm_assert(out_addr_family);
        return FALSE;
    }

    nm_assert(src);

    memcpy(dst, src, src_len);
    NM_SET_OUT(out_addr_family, addr_family);
    return TRUE;
}

gboolean
nm_ip_addr_set_from_variant(int addr_family, gpointer dst, GVariant *variant, int *out_addr_family)
{
    gconstpointer bytes;
    gsize         len;

    g_return_val_if_fail(dst, FALSE);
    g_return_val_if_fail(variant, FALSE);

    /* This function always expects IP addresses as byte arrays ("ay"). Note that
     * several NetworkManager API uses "u" (32 bit unsigned intergers) for IPv4 addresses.
     * So this function won't work in those cases.
     *
     * Btw, using "u" for IPv4 address messes badly with the endianness (host
     * vs network byte order). Don't do that.
     */
    g_return_val_if_fail(g_variant_is_of_type(variant, G_VARIANT_TYPE("ay")), FALSE);

    bytes = g_variant_get_fixed_array(variant, &len, sizeof(guint8));

    return nm_ip_addr_set_from_untrusted(addr_family, dst, bytes, len, out_addr_family);
}

/*****************************************************************************/

guint32
nm_ip4_addr_get_default_prefix0(in_addr_t ip)
{
    /* The function is originally from ipcalc.c of Red Hat's initscripts. */
    switch (ntohl(ip) >> 24) {
    case 0 ... 127:
        return 8; /* Class A */
    case 128 ... 191:
        return 16; /* Class B */
    case 192 ... 223:
        return 24; /* Class C */
    }
    return 0;
}

guint32
nm_ip4_addr_get_default_prefix(in_addr_t ip)
{
    return nm_ip4_addr_get_default_prefix0(ip) ?: 24;
}

gboolean
nm_ip_addr_is_site_local(int addr_family, const void *address)
{
    NMIPAddr a;

    nm_ip_addr_set(addr_family, &a, address);

    switch (addr_family) {
    case AF_INET:
        /* RFC1918 private addresses
         * 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 */
        return (a.addr4 & htonl(0xff000000)) == htonl(0x0a000000)
               || (a.addr4 & htonl(0xfff00000)) == htonl(0xac100000)
               || (a.addr4 & htonl(0xffff0000)) == htonl(0xc0a80000);
    case AF_INET6:
        /* IN6_IS_ADDR_SITELOCAL() is for deprecated fec0::/10 addresses (see rfc3879, 4.).
         * Note that for unique local IPv6 addresses (ULA, fc00::/7) this returns false.
         * This may or may not be a bug of this function. */
        return IN6_IS_ADDR_SITELOCAL(&a.addr6);
    default:
        g_return_val_if_reached(FALSE);
    }
}

gboolean
nm_ip6_addr_is_ula(const struct in6_addr *address)
{
    /* Unique local IPv6 address (ULA) fc00::/7 */
    return (address->s6_addr32[0] & htonl(0xfe000000u)) == htonl(0xfc000000u);
}

/*****************************************************************************/

gconstpointer
nm_ip_addr_clear_host_address(int family, gpointer dst, gconstpointer src, guint32 plen)
{
    NMIPAddr a;
    NMIPAddr a2;

    g_return_val_if_fail(dst, NULL);

    if (!src) {
        /* allow "self-assignment", by specifying %NULL as source. */
        src = dst;
    }

    nm_ip_addr_set(family, &a, src);

    switch (family) {
    case AF_INET:
        g_return_val_if_fail(plen <= 32, NULL);

        a2.addr4 = nm_ip4_addr_clear_host_address(a.addr4, plen);
        break;
    case AF_INET6:
        nm_ip6_addr_clear_host_address(&a2.addr6, &a.addr6, plen);
        break;
    default:
        g_return_val_if_reached(NULL);
    }

    nm_ip_addr_set(family, dst, &a2);

    return dst;
}

/* nm_ip6_addr_clear_host_address:
 * @dst: destination output buffer, will contain the network part of the @src address
 * @src: source ip6 address. If NULL, this does an in-place update of @dst.
 *   Also, @src and @dst are allowed to be the same pointers.
 * @plen: prefix length of network
 *
 * Note: this function is self assignment safe, to update @src inplace, set both
 * @dst and @src to the same destination or set @src NULL.
 */
const struct in6_addr *
nm_ip6_addr_clear_host_address(struct in6_addr *dst, const struct in6_addr *src, guint32 plen)
{
    g_return_val_if_fail(plen <= 128, NULL);
    g_return_val_if_fail(dst, NULL);

    if (!src)
        src = dst;

    if (plen < 128) {
        guint nbytes = plen / 8;
        guint nbits  = plen % 8;

        if (nbytes && dst != src)
            memcpy(dst, src, nbytes);
        if (nbits) {
            dst->s6_addr[nbytes] = (src->s6_addr[nbytes] & (0xFF << (8 - nbits)));
            nbytes++;
        }
        if (nbytes <= 15)
            memset(&dst->s6_addr[nbytes], 0, 16 - nbytes);
    } else if (src != dst)
        *dst = *src;

    return dst;
}

int
nm_ip6_addr_same_prefix_cmp(const struct in6_addr *addr_a,
                            const struct in6_addr *addr_b,
                            guint32                plen)
{
    int    nbytes;
    guint8 va, vb, m;

    if (plen >= 128) {
        nm_assert(plen == 128);
        NM_CMP_DIRECT_MEMCMP(addr_a, addr_b, sizeof(struct in6_addr));
    } else {
        nbytes = plen / 8;
        if (nbytes)
            NM_CMP_DIRECT_MEMCMP(addr_a, addr_b, nbytes);

        plen = plen % 8;
        if (plen != 0) {
            m  = ~((1 << (8 - plen)) - 1);
            va = ((((const guint8 *) addr_a))[nbytes]) & m;
            vb = ((((const guint8 *) addr_b))[nbytes]) & m;
            NM_CMP_DIRECT(va, vb);
        }
    }
    return 0;
}

/*****************************************************************************/

static gboolean
_parse_legacy_addr4(const char *text, in_addr_t *out_addr, GError **error)
{
    gs_free char  *s_free = NULL;
    struct in_addr a1;
    guint8         bin[sizeof(a1)];
    char          *s;
    int            i;

    if (inet_aton(text, &a1) != 1) {
        g_set_error_literal(error,
                            NM_UTILS_ERROR,
                            NM_UTILS_ERROR_INVALID_ARGUMENT,
                            "address invalid according to inet_aton()");
        return FALSE;
    }

    /* OK, inet_aton() accepted the format. That's good, because we want
     * to accept IPv4 addresses in octal format, like 255.255.000.000.
     * That's what "legacy" means here. inet_pton() doesn't accept those.
     *
     * But inet_aton() also ignores trailing garbage and formats with fewer than
     * 4 digits. That is just too crazy and we don't do that. Perform additional checks
     * and reject some forms that inet_aton() accepted.
     *
     * Note that we still should (of course) accept everything that inet_pton()
     * accepts. However this code never gets called if inet_pton() succeeds
     * (see below, aside the assertion code). */

    if (NM_STRCHAR_ANY(text, ch, (!(ch >= '0' && ch <= '9') && !NM_IN_SET(ch, '.', 'x')))) {
        /* We only accepts '.', digits, and 'x' for "0x". */
        g_set_error_literal(error,
                            NM_UTILS_ERROR,
                            NM_UTILS_ERROR_INVALID_ARGUMENT,
                            "contains an invalid character");
        return FALSE;
    }

    s = nm_memdup_maybe_a(300, text, strlen(text) + 1, &s_free);

    for (i = 0; i < G_N_ELEMENTS(bin); i++) {
        char  *current_token = s;
        gint32 v;

        s = strchr(s, '.');
        if (s) {
            s[0] = '\0';
            s++;
        }

        if ((i == G_N_ELEMENTS(bin) - 1) != (s == NULL)) {
            /* Exactly for the last digit, we expect to have no more following token.
             * But this isn't the case. Abort. */
            g_set_error(error,
                        NM_UTILS_ERROR,
                        NM_UTILS_ERROR_INVALID_ARGUMENT,
                        "wrong number of tokens (index %d, token '%s')",
                        i,
                        s);
            return FALSE;
        }

        v = _nm_utils_ascii_str_to_int64(current_token, 0, 0, 0xFF, -1);
        if (v == -1) {
            int errsv = errno;

            /* we do accept octal and hex (even with leading "0x"). But something
             * about this token is wrong. */
            g_set_error(error,
                        NM_UTILS_ERROR,
                        NM_UTILS_ERROR_INVALID_ARGUMENT,
                        "invalid token '%s': %s (%d)",
                        current_token,
                        nm_strerror_native(errsv),
                        errsv);
            return FALSE;
        }

        bin[i] = v;
    }

    if (memcmp(bin, &a1, sizeof(bin)) != 0) {
        /* our parsing did not agree with what inet_aton() gave. Something
         * is wrong. Abort. */
        g_set_error(
            error,
            NM_UTILS_ERROR,
            NM_UTILS_ERROR_INVALID_ARGUMENT,
            "inet_aton() result 0x%08x differs from computed value 0x%02hhx%02hhx%02hhx%02hhx",
            a1.s_addr,
            bin[0],
            bin[1],
            bin[2],
            bin[3]);
        return FALSE;
    }

    *out_addr = a1.s_addr;
    return TRUE;
}

gboolean
nm_inet_parse_bin_full(int         addr_family,
                       gboolean    accept_legacy,
                       const char *text,
                       int        *out_addr_family,
                       gpointer    out_addr)
{
    NMIPAddr addrbin;

    g_return_val_if_fail(text, FALSE);

    if (addr_family == AF_UNSPEC) {
        g_return_val_if_fail(!out_addr || out_addr_family, FALSE);
        addr_family = strchr(text, ':') ? AF_INET6 : AF_INET;
    } else
        g_return_val_if_fail(NM_IN_SET(addr_family, AF_INET, AF_INET6), FALSE);

    if (inet_pton(addr_family, text, &addrbin) != 1) {
        if (accept_legacy && addr_family == AF_INET
            && _parse_legacy_addr4(text, &addrbin.addr4, NULL)) {
            /* The address is in some legacy format which inet_aton() accepts, but not inet_pton().
             * Most likely octal digits (leading zeros). We accept the address. */
        } else
            return FALSE;
    }

#if NM_MORE_ASSERTS > 10
    if (addr_family == AF_INET) {
        NM_PRAGMA_WARNING_DISABLE_DANGLING_POINTER
        gs_free_error GError *error = NULL;
        in_addr_t             a;

        /* The legacy parser should accept everything that inet_pton() accepts too. Meaning,
         * it should strictly parse *more* formats. And of course, parse it the same way. */
        if (!_parse_legacy_addr4(text, &a, &error)) {
            char buf[INET_ADDRSTRLEN];

            g_error("unexpected assertion failure: could parse \"%s\" as %s, but not accepted by "
                    "legacy parser: %s",
                    text,
                    nm_inet4_ntop(addrbin.addr4, buf),
                    error->message);
        }
        nm_assert(addrbin.addr4 == a);
        NM_PRAGMA_WARNING_REENABLE
    }
#endif

    NM_SET_OUT(out_addr_family, addr_family);
    if (out_addr)
        nm_ip_addr_set(addr_family, out_addr, &addrbin);
    return TRUE;
}

gboolean
nm_inet_parse_str(int addr_family, const char *text, char **out_addr)
{
    NMIPAddr addrbin;

    if (!nm_inet_parse_bin(addr_family, text, &addr_family, &addrbin))
        return FALSE;

    NM_SET_OUT(out_addr, nm_inet_ntop_dup(addr_family, &addrbin));
    return TRUE;
}

gboolean
nm_inet_parse_with_prefix_bin(int         addr_family,
                              const char *text,
                              int        *out_addr_family,
                              gpointer    out_addr,
                              int        *out_prefix)
{
    gs_free char *addrstr_free = NULL;
    int           prefix       = -1;
    const char   *slash;
    const char   *addrstr;
    NMIPAddr      addrbin;

    g_return_val_if_fail(text, FALSE);

    if (addr_family == AF_UNSPEC) {
        g_return_val_if_fail(!out_addr || out_addr_family, FALSE);
        addr_family = strchr(text, ':') ? AF_INET6 : AF_INET;
    } else
        g_return_val_if_fail(NM_IN_SET(addr_family, AF_INET, AF_INET6), FALSE);

    slash = strchr(text, '/');
    if (slash)
        addrstr = nm_strndup_a(300, text, slash - text, &addrstr_free);
    else
        addrstr = text;

    if (inet_pton(addr_family, addrstr, &addrbin) != 1)
        return FALSE;

    if (slash) {
        /* For IPv4, `ip addr add` supports the prefix-length as a netmask. We don't
         * do that. */
        prefix =
            _nm_utils_ascii_str_to_int64(&slash[1], 10, 0, addr_family == AF_INET ? 32 : 128, -1);
        if (prefix == -1)
            return FALSE;
    }

    NM_SET_OUT(out_addr_family, addr_family);
    if (out_addr)
        nm_ip_addr_set(addr_family, out_addr, &addrbin);
    NM_SET_OUT(out_prefix, prefix);
    return TRUE;
}

gboolean
nm_inet_parse_with_prefix_str(int addr_family, const char *text, char **out_addr, int *out_prefix)
{
    NMIPAddr addrbin;

    if (!nm_inet_parse_with_prefix_bin(addr_family, text, &addr_family, &addrbin, out_prefix))
        return FALSE;

    NM_SET_OUT(out_addr, nm_inet_ntop_dup(addr_family, &addrbin));
    return TRUE;
}

/*****************************************************************************/

gboolean
nm_inet_is_valid(int addr_family, const char *str_addr)
{
    nm_assert(NM_IN_SET(addr_family, AF_UNSPEC, AF_INET, AF_INET6));

    return str_addr && nm_inet_parse_bin(addr_family, str_addr, NULL, NULL);
}

gboolean
nm_inet_is_normalized(int addr_family, const char *str_addr)
{
    NMIPAddr addr;
    char     sbuf[NM_INET_ADDRSTRLEN];

    nm_assert(NM_IN_SET(addr_family, AF_UNSPEC, AF_INET, AF_INET6));

    if (!str_addr)
        return FALSE;

    if (!nm_inet_parse_bin(addr_family, str_addr, &addr_family, &addr))
        return FALSE;

    nm_inet_ntop(addr_family, &addr, sbuf);
    return nm_streq(sbuf, str_addr);
}

/*****************************************************************************/

NM_UTILS_ENUM2STR_DEFINE(nm_icmpv6_router_pref_to_string,
                         NMIcmpv6RouterPref,
                         NM_UTILS_ENUM2STR(NM_ICMPV6_ROUTER_PREF_LOW, "low"),
                         NM_UTILS_ENUM2STR(NM_ICMPV6_ROUTER_PREF_MEDIUM, "medium"),
                         NM_UTILS_ENUM2STR(NM_ICMPV6_ROUTER_PREF_HIGH, "high"),
                         NM_UTILS_ENUM2STR(NM_ICMPV6_ROUTER_PREF_INVALID, "invalid"), );
