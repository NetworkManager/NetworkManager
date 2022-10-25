/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef __NM_INET_UTILS_H__
#define __NM_INET_UTILS_H__

typedef struct _NMIPAddr {
    union {
        guint8          addr_ptr[sizeof(struct in6_addr)];
        in_addr_t       addr4;
        struct in_addr  addr4_struct;
        struct in6_addr addr6;

        /* NMIPAddr is really a union for IP addresses.
         * However, as ethernet addresses fit in here nicely, use
         * it also for an ethernet MAC address. */
        guint8      ether_addr_octet[6 /*ETH_ALEN*/];
        NMEtherAddr ether_addr;

        guint8 array[sizeof(struct in6_addr)];
    };
} NMIPAddr;

#define NM_IP_ADDR_INIT \
    {                   \
        .array = { 0 }  \
    }

#define _NM_IN6ADDR_INIT(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, aa, ab, ac, ad, ae, af) \
    {                                                                                    \
        .s6_addr = {                                                                     \
            (a0),                                                                        \
            (a1),                                                                        \
            (a2),                                                                        \
            (a3),                                                                        \
            (a4),                                                                        \
            (a5),                                                                        \
            (a6),                                                                        \
            (a7),                                                                        \
            (a8),                                                                        \
            (a9),                                                                        \
            (aa),                                                                        \
            (ab),                                                                        \
            (ac),                                                                        \
            (ad),                                                                        \
            (ae),                                                                        \
            (af),                                                                        \
        }                                                                                \
    }

#define NM_IN6ADDR_INIT(...) ((struct in6_addr) _NM_IN6ADDR_INIT(__VA_ARGS__))

extern const NMIPAddr nm_ip_addr_zero;

static inline int
nm_ip_addr_cmp(int addr_family, gconstpointer a, gconstpointer b)
{
    /* Note that @a and @b are not required to be full NMIPAddr unions.
     * Depending on @addr_family, they can also be only in_addr_t or
     * struct in6_addr. */
    NM_CMP_SELF(a, b);
    NM_CMP_DIRECT_MEMCMP(a, b, nm_utils_addr_family_to_size(addr_family));
    return 0;
}

int nm_ip_addr_cmp_for_sort(gconstpointer a, gconstpointer b, gpointer user_data);

static inline gboolean
nm_ip_addr_equal(int addr_family, gconstpointer a, gconstpointer b)
{
    return nm_ip_addr_cmp(addr_family, a, b) == 0;
}

static inline void
nm_ip_addr_set(int addr_family, gpointer dst, gconstpointer src)
{
    nm_assert(dst);
    nm_assert(src);

    /* this MUST use memcpy() to support unaligned src/dst pointers. */
    memcpy(dst, src, nm_utils_addr_family_to_size(addr_family));

    /* Note that @dst is not necessarily a NMIPAddr, it could also be just
     * an in_addr_t/struct in6_addr. We thus can only set the bytes that
     * we know are present based on the address family.
     *
     * Using this function to initialize an NMIPAddr union (for IPv4) leaves
     * uninitalized bytes. Avoid that by using nm_ip_addr_init() instead. */
}

static inline gboolean
nm_ip_addr_is_null(int addr_family, gconstpointer addr)
{
    NMIPAddr a;

    nm_ip_addr_set(addr_family, &a, addr);

    if (NM_IS_IPv4(addr_family))
        return a.addr4 == 0;

    return IN6_IS_ADDR_UNSPECIFIED(&a.addr6);
}

static inline NMIPAddr
nm_ip_addr_init(int addr_family, gconstpointer src)
{
    NMIPAddr a;

    nm_assert_addr_family(addr_family);
    nm_assert(src);

    G_STATIC_ASSERT_EXPR(sizeof(NMIPAddr) == sizeof(struct in6_addr));

    /* this MUST use memcpy() to support unaligned src/dst pointers. */

    if (NM_IS_IPv4(addr_family)) {
        memcpy(&a, src, sizeof(in_addr_t));

        /* ensure all bytes of the union are initialized. If only to make
         * valgrind happy. */
        memset(&a.array[sizeof(in_addr_t)], 0, sizeof(a) - sizeof(in_addr_t));
    } else
        memcpy(&a, src, sizeof(struct in6_addr));

    return a;
}

gboolean nm_ip_addr_set_from_untrusted(int           addr_family,
                                       gpointer      dst,
                                       gconstpointer src,
                                       gsize         src_len,
                                       int          *out_addr_family);

gboolean
nm_ip_addr_set_from_variant(int addr_family, gpointer dst, GVariant *variant, int *out_addr_family);

static inline gconstpointer
nm_ip_addr_from_packed_array(int addr_family, gconstpointer ipaddr_arr, gsize idx)
{
    return NM_IS_IPv4(addr_family)
               ? ((gconstpointer) & (((const struct in_addr *) ipaddr_arr)[idx]))
               : ((gconstpointer) & (((const struct in6_addr *) ipaddr_arr)[idx]));
}

/*****************************************************************************/

static inline guint32
nm_ip4_addr_netmask_to_prefix(in_addr_t subnetmask)
{
    G_STATIC_ASSERT_EXPR(__SIZEOF_INT__ == 4);
    G_STATIC_ASSERT_EXPR(sizeof(int) == 4);
    G_STATIC_ASSERT_EXPR(sizeof(guint) == 4);
    G_STATIC_ASSERT_EXPR(sizeof(subnetmask) == 4);

    return ((subnetmask != 0u) ? (guint32) (32 - __builtin_ctz(ntohl(subnetmask))) : 0u);
}

/**
 * nm_ip4_addr_netmask_from_prefix:
 * @prefix: a CIDR prefix
 *
 * Returns: the netmask represented by the prefix, in network byte order
 **/
static inline in_addr_t
nm_ip4_addr_netmask_from_prefix(guint32 prefix)
{
    nm_assert(prefix <= 32);
    return prefix < 32 ? ~htonl(0xFFFFFFFFu >> prefix) : 0xFFFFFFFFu;
}

guint32 nm_ip4_addr_get_default_prefix0(in_addr_t ip);
guint32 nm_ip4_addr_get_default_prefix(in_addr_t ip);

static inline in_addr_t
nm_ip4_addr_get_broadcast_address(in_addr_t address, guint8 plen)
{
    return address | ~nm_ip4_addr_netmask_from_prefix(plen);
}

gconstpointer
nm_ip_addr_clear_host_address(int family, gpointer dst, gconstpointer src, guint32 plen);

/* nm_ip4_addr_clear_host_address:
 * @addr: source ip6 address
 * @plen: prefix length of network
 *
 * returns: the input address, with the host address set to 0.
 */
static inline in_addr_t
nm_ip4_addr_clear_host_address(in_addr_t addr, guint32 plen)
{
    return addr & nm_ip4_addr_netmask_from_prefix(plen);
}

const struct in6_addr *
nm_ip6_addr_clear_host_address(struct in6_addr *dst, const struct in6_addr *src, guint32 plen);

/*****************************************************************************/

static inline int
nm_ip4_addr_same_prefix_cmp(in_addr_t addr_a, in_addr_t addr_b, guint32 plen)
{
    NM_CMP_DIRECT(htonl(nm_ip4_addr_clear_host_address(addr_a, plen)),
                  htonl(nm_ip4_addr_clear_host_address(addr_b, plen)));
    return 0;
}

int nm_ip6_addr_same_prefix_cmp(const struct in6_addr *addr_a,
                                const struct in6_addr *addr_b,
                                guint32                plen);

static inline gboolean
nm_ip4_addr_same_prefix(in_addr_t addr_a, in_addr_t addr_b, guint32 plen)
{
    return nm_ip4_addr_same_prefix_cmp(addr_a, addr_b, plen) == 0;
}

static inline gboolean
nm_ip6_addr_same_prefix(const struct in6_addr *addr_a, const struct in6_addr *addr_b, guint8 plen)
{
    return nm_ip6_addr_same_prefix_cmp(addr_a, addr_b, plen) == 0;
}

static inline int
nm_ip_addr_same_prefix_cmp(int addr_family, gconstpointer addr_a, gconstpointer addr_b, guint8 plen)
{
    NMIPAddr a;
    NMIPAddr b;

    NM_CMP_SELF(addr_a, addr_b);

    nm_ip_addr_set(addr_family, &a, addr_a);
    nm_ip_addr_set(addr_family, &b, addr_b);

    if (NM_IS_IPv4(addr_family))
        return nm_ip4_addr_same_prefix_cmp(a.addr4, b.addr4, plen);

    return nm_ip6_addr_same_prefix_cmp(&a.addr6, &b.addr6, plen);
}

static inline gboolean
nm_ip_addr_same_prefix(int addr_family, gconstpointer addr_a, gconstpointer addr_b, guint8 plen)
{
    return nm_ip_addr_same_prefix_cmp(addr_family, addr_a, addr_b, plen) == 0;
}

#define NM_CMP_DIRECT_IP4_ADDR_SAME_PREFIX(a, b, plen) \
    NM_CMP_RETURN(nm_ip4_addr_same_prefix_cmp((a), (b), (plen)))

#define NM_CMP_DIRECT_IP6_ADDR_SAME_PREFIX(a, b, plen) \
    NM_CMP_RETURN(nm_ip6_addr_same_prefix_cmp((a), (b), (plen)))

/*****************************************************************************/

gboolean nm_ip_addr_is_site_local(int addr_family, const void *address);
gboolean nm_ip6_addr_is_ula(const struct in6_addr *address);

/*****************************************************************************/

#define NM_IPV4LL_NETWORK   ((in_addr_t) htonl(0xA9FE0000lu)) /* 169.254.0.0 */
#define NM_IPV4LL_NETMASK   ((in_addr_t) htonl(0xFFFF0000lu)) /* 255.255.0.0 */
#define NM_IPV4LO_NETWORK   ((in_addr_t) htonl(0x7F000000lu)) /* 127.0.0.0 */
#define NM_IPV4LO_NETMASK   ((in_addr_t) htonl(0xFF000000lu)) /* 255.0.0.0 */
#define NM_IPV4LO_PREFIXLEN 8
#define NM_IPV4LO_ADDR1     ((in_addr_t) htonl(0x7F000001lu)) /* 127.0.0.1 */

static inline gboolean
nm_ip4_addr_is_loopback(in_addr_t addr)
{
    /* There is also IN_LOOPBACK() in <linux/in.h>, but there the
     * argument is in host order not `in_addr_t`. */
    return (addr & NM_IPV4LO_NETMASK) == NM_IPV4LO_NETWORK;
}

static inline gboolean
nm_ip4_addr_is_link_local(in_addr_t addr)
{
    return (addr & NM_IPV4LL_NETMASK) == NM_IPV4LL_NETWORK;
}

static inline gboolean
nm_ip4_addr_is_zeronet(in_addr_t network)
{
    /* Same as ipv4_is_zeronet() from kernel's include/linux/in.h. */
    return (network & htonl(0xFF000000u)) == htonl(0x00000000u);
}

/*****************************************************************************/

#define NM_INET_ADDRSTRLEN INET6_ADDRSTRLEN

/* Forward declare function so we don't have to drag in <arpa/inet.h>. */
const char *inet_ntop(int af, const void *src, char *dst, socklen_t size);

static inline const char *
nm_inet_ntop(int addr_family, gconstpointer addr, char *dst)
{
    const char *s;

    nm_assert_addr_family(addr_family);
    nm_assert(addr);
    nm_assert(dst);

    s = inet_ntop(addr_family,
                  addr,
                  dst,
                  addr_family == AF_INET6 ? INET6_ADDRSTRLEN : INET_ADDRSTRLEN);
    nm_assert(s);
    return s;
}

static inline const char *
nm_inet4_ntop(in_addr_t addr, char dst[static INET_ADDRSTRLEN])
{
    return nm_inet_ntop(AF_INET, &addr, dst);
}

static inline const char *
nm_inet6_ntop(const struct in6_addr *addr, char dst[static INET6_ADDRSTRLEN])
{
    return nm_inet_ntop(AF_INET6, addr, dst);
}

static inline char *
nm_inet_ntop_dup(int addr_family, gconstpointer addr)
{
    char buf[NM_INET_ADDRSTRLEN];

    return g_strdup(nm_inet_ntop(addr_family, addr, buf));
}

static inline char *
nm_inet4_ntop_dup(in_addr_t addr)
{
    return nm_inet_ntop_dup(AF_INET, &addr);
}

static inline char *
nm_inet6_ntop_dup(const struct in6_addr *addr)
{
    return nm_inet_ntop_dup(AF_INET6, addr);
}

/*****************************************************************************/

gboolean nm_inet_parse_bin_full(int         addr_family,
                                gboolean    accept_legacy,
                                const char *text,
                                int        *out_addr_family,
                                gpointer    out_addr);
static inline gboolean
nm_inet_parse_bin(int addr_family, const char *text, int *out_addr_family, gpointer out_addr)
{
    return nm_inet_parse_bin_full(addr_family, FALSE, text, out_addr_family, out_addr);
}

gboolean nm_inet_parse_str(int addr_family, const char *text, char **out_addr);

gboolean nm_inet_parse_with_prefix_bin(int         addr_family,
                                       const char *text,
                                       int        *out_addr_family,
                                       gpointer    out_addr,
                                       int        *out_prefix);

gboolean
nm_inet_parse_with_prefix_str(int addr_family, const char *text, char **out_addr, int *out_prefix);

/*****************************************************************************/

gboolean nm_inet_is_valid(int addr_family, const char *str_addr);

gboolean nm_inet_is_normalized(int addr_family, const char *str_addr);

/*****************************************************************************/

/* this enum is compatible with ICMPV6_ROUTER_PREF_* (from <linux/icmpv6.h>,
 * the values for netlink attribute RTA_PREF) and "enum ndp_route_preference"
 * from <ndp.h>. */
typedef enum _nm_packed {
    NM_ICMPV6_ROUTER_PREF_MEDIUM  = 0x0, /* ICMPV6_ROUTER_PREF_MEDIUM */
    NM_ICMPV6_ROUTER_PREF_LOW     = 0x3, /* ICMPV6_ROUTER_PREF_LOW */
    NM_ICMPV6_ROUTER_PREF_HIGH    = 0x1, /* ICMPV6_ROUTER_PREF_HIGH */
    NM_ICMPV6_ROUTER_PREF_INVALID = 0x2, /* ICMPV6_ROUTER_PREF_INVALID */
} NMIcmpv6RouterPref;

const char *nm_icmpv6_router_pref_to_string(NMIcmpv6RouterPref pref, char *buf, gsize len);

/*****************************************************************************/

#endif /* __NM_INET_UTILS_H__ */
