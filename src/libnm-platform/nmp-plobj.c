/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2015 - 2018 Red Hat, Inc.
 */

#include "libnm-glib-aux/nm-default-glib-i18n-lib.h"

#include "nmp-plobj.h"

#include "nm-compat-headers/linux/if_addr.h"

#include "libnm-glib-aux/nm-time-utils.h"
#include "nm-platform-utils.h"

/*****************************************************************************/

#define TO_STRING_IFA_FLAGS_BUF_SIZE 256

static const char *
_to_string_ifa_flags(guint32 ifa_flags, char *buf, gsize size)
{
#define S_FLAGS_PREFIX " flags "
    nm_assert(buf && size >= TO_STRING_IFA_FLAGS_BUF_SIZE && size > NM_STRLEN(S_FLAGS_PREFIX));

    if (!ifa_flags)
        buf[0] = '\0';
    else {
        nm_platform_addr_flags2str(ifa_flags,
                                   &buf[NM_STRLEN(S_FLAGS_PREFIX)],
                                   size - NM_STRLEN(S_FLAGS_PREFIX));
        if (buf[NM_STRLEN(S_FLAGS_PREFIX)] == '\0')
            buf[0] = '\0';
        else
            memcpy(buf, S_FLAGS_PREFIX, NM_STRLEN(S_FLAGS_PREFIX));
    }
    return buf;
}

#define _to_string_dev(arr, ifindex)                                                   \
    ({                                                                                 \
        const int _ifindex = (ifindex);                                                \
                                                                                       \
        _ifindex ? nm_sprintf_buf((arr), " dev %d", ifindex) : nm_str_truncate((arr)); \
    })

static const char *
_lifetime_to_string(guint32 timestamp, guint32 lifetime, gint32 now, char *buf, size_t buf_size)
{
    if (lifetime == NM_PLATFORM_LIFETIME_PERMANENT)
        return "forever";

    g_snprintf(buf,
               buf_size,
               "%usec",
               nmp_utils_lifetime_rebase_relative_time_on_now(timestamp, lifetime, now));
    return buf;
}

static const char *
_lifetime_summary_to_string(gint32  now,
                            guint32 timestamp,
                            guint32 preferred,
                            guint32 lifetime,
                            char   *buf,
                            size_t  buf_size)
{
    g_snprintf(buf,
               buf_size,
               " lifetime %d-%u[%u,%u]",
               (signed) now,
               (unsigned) timestamp,
               (unsigned) preferred,
               (unsigned) lifetime);
    return buf;
}

static int
_address_cmp_expiry(const NMPlatformIPAddress *a, const NMPlatformIPAddress *b)
{
    guint32 lifetime_a;
    guint32 lifetime_b;
    guint32 preferred_a;
    guint32 preferred_b;
    gint32  now = 0;

    lifetime_a =
        nmp_utils_lifetime_get(a->timestamp, a->lifetime, a->preferred, &now, &preferred_a);
    lifetime_b =
        nmp_utils_lifetime_get(b->timestamp, b->lifetime, b->preferred, &now, &preferred_b);

    NM_CMP_DIRECT(lifetime_a, lifetime_b);
    NM_CMP_DIRECT(preferred_a, preferred_b);
    return 0;
}

/*****************************************************************************/

void
nm_platform_ip4_address_hash_update(const NMPlatformIP4Address *obj, NMHashState *h)
{
    nm_hash_update_vals(h,
                        obj->ifindex,
                        obj->addr_source,
                        obj->use_ip4_broadcast_address ? obj->broadcast_address : ((in_addr_t) 0u),
                        obj->timestamp,
                        obj->lifetime,
                        obj->preferred,
                        obj->n_ifa_flags,
                        obj->plen,
                        obj->address,
                        obj->peer_address,
                        NM_HASH_COMBINE_BOOLS(guint8,
                                              obj->use_ip4_broadcast_address,
                                              obj->a_acd_not_ready,
                                              obj->a_force_commit));
    nm_hash_update_strarr(h, obj->label);
}

int
nm_platform_ip4_address_cmp(const NMPlatformIP4Address *a,
                            const NMPlatformIP4Address *b,
                            NMPlatformIPAddressCmpType  cmp_type)
{
    NM_CMP_SELF(a, b);

    NM_CMP_FIELD(a, b, ifindex);
    NM_CMP_FIELD(a, b, plen);
    NM_CMP_FIELD(a, b, address);

    switch (cmp_type) {
    case NM_PLATFORM_IP_ADDRESS_CMP_TYPE_ID:
        /* for IPv4 addresses, you can add the same local address with differing peer-address
         * (IFA_ADDRESS), provided that their net-part differs. */
        NM_CMP_DIRECT_IP4_ADDR_SAME_PREFIX(a->peer_address, b->peer_address, a->plen);
        return 0;
    case NM_PLATFORM_IP_ADDRESS_CMP_TYPE_SEMANTICALLY:
    case NM_PLATFORM_IP_ADDRESS_CMP_TYPE_FULL:
        NM_CMP_FIELD(a, b, peer_address);
        NM_CMP_FIELD_STR(a, b, label);
        if (cmp_type == NM_PLATFORM_IP_ADDRESS_CMP_TYPE_SEMANTICALLY) {
            NM_CMP_RETURN(_address_cmp_expiry((const NMPlatformIPAddress *) a,
                                              (const NMPlatformIPAddress *) b));

            /* Most flags are set by kernel. We only compare the ones that
             * NetworkManager actively sets.
             *
             * NM actively only sets IFA_F_NOPREFIXROUTE (and IFA_F_MANAGETEMPADDR for IPv6),
             * where nm_platform_ip_address_sync() sets IFA_F_NOPREFIXROUTE depending on
             * NMP_IP_ADDRESS_SYNC_FLAGS_WITH_NOPREFIXROUTE.
             * There are thus no flags to compare for IPv4. */

            NM_CMP_DIRECT(nm_platform_ip4_broadcast_address_from_addr(a),
                          nm_platform_ip4_broadcast_address_from_addr(b));
        } else {
            NM_CMP_FIELD(a, b, timestamp);
            NM_CMP_FIELD(a, b, lifetime);
            NM_CMP_FIELD(a, b, preferred);
            NM_CMP_FIELD(a, b, n_ifa_flags);
            NM_CMP_FIELD(a, b, addr_source);
            NM_CMP_FIELD_UNSAFE(a, b, use_ip4_broadcast_address);
            if (a->use_ip4_broadcast_address)
                NM_CMP_FIELD(a, b, broadcast_address);
            NM_CMP_FIELD_UNSAFE(a, b, a_acd_not_ready);
            NM_CMP_FIELD_UNSAFE(a, b, a_force_commit);
        }
        return 0;
    }
    return nm_assert_unreachable_val(0);
}

/*****************************************************************************/

void
nm_platform_ip6_address_hash_update(const NMPlatformIP6Address *obj, NMHashState *h)
{
    nm_hash_update_vals(h,
                        obj->ifindex,
                        obj->addr_source,
                        obj->timestamp,
                        obj->lifetime,
                        obj->preferred,
                        obj->n_ifa_flags,
                        obj->plen,
                        obj->address,
                        obj->peer_address,
                        NM_HASH_COMBINE_BOOLS(guint8, obj->a_force_commit));
}

int
nm_platform_ip6_address_cmp(const NMPlatformIP6Address *a,
                            const NMPlatformIP6Address *b,
                            NMPlatformIPAddressCmpType  cmp_type)
{
    const struct in6_addr *p_a, *p_b;

    NM_CMP_SELF(a, b);

    NM_CMP_FIELD(a, b, ifindex);
    NM_CMP_FIELD_IN6ADDR(a, b, address);

    switch (cmp_type) {
    case NM_PLATFORM_IP_ADDRESS_CMP_TYPE_ID:
        /* for IPv6 addresses, the prefix length is not part of the primary identifier. */
        return 0;
    case NM_PLATFORM_IP_ADDRESS_CMP_TYPE_SEMANTICALLY:
    case NM_PLATFORM_IP_ADDRESS_CMP_TYPE_FULL:
        NM_CMP_FIELD(a, b, plen);
        p_a = nm_platform_ip6_address_get_peer(a);
        p_b = nm_platform_ip6_address_get_peer(b);
        NM_CMP_DIRECT_MEMCMP(p_a, p_b, sizeof(*p_a));
        if (cmp_type == NM_PLATFORM_IP_ADDRESS_CMP_TYPE_SEMANTICALLY) {
            NM_CMP_RETURN(_address_cmp_expiry((const NMPlatformIPAddress *) a,
                                              (const NMPlatformIPAddress *) b));

            /* Most flags are set by kernel. We only compare the ones that
             * NetworkManager actively sets.
             *
             * NM actively only sets IFA_F_NOPREFIXROUTE and IFA_F_MANAGETEMPADDR,
             * where nm_platform_ip_address_sync() sets IFA_F_NOPREFIXROUTE depending on
             * NMP_IP_ADDRESS_SYNC_FLAGS_WITH_NOPREFIXROUTE.
             * We thus only care about IFA_F_MANAGETEMPADDR. */
            NM_CMP_DIRECT(a->n_ifa_flags & IFA_F_MANAGETEMPADDR,
                          b->n_ifa_flags & IFA_F_MANAGETEMPADDR);
        } else {
            NM_CMP_FIELD(a, b, timestamp);
            NM_CMP_FIELD(a, b, lifetime);
            NM_CMP_FIELD(a, b, preferred);
            NM_CMP_FIELD(a, b, n_ifa_flags);
            NM_CMP_FIELD(a, b, addr_source);
            NM_CMP_FIELD_UNSAFE(a, b, a_force_commit);
        }
        return 0;
    }
    return nm_assert_unreachable_val(0);
}

/*****************************************************************************/

static int
_address_pretty_sort_get_prio_4(in_addr_t addr)
{
    if (nm_ip4_addr_is_link_local(addr))
        return 0;
    return 1;
}

static int
_address_pretty_sort_get_prio_6(const struct in6_addr *addr)
{
    if (IN6_IS_ADDR_V4MAPPED(addr))
        return 0;
    if (IN6_IS_ADDR_V4COMPAT(addr))
        return 1;
    if (IN6_IS_ADDR_UNSPECIFIED(addr))
        return 2;
    if (IN6_IS_ADDR_LOOPBACK(addr))
        return 3;
    if (IN6_IS_ADDR_LINKLOCAL(addr))
        return 4;
    if (IN6_IS_ADDR_SITELOCAL(addr))
        return 5;
    return 6;
}

int
nm_platform_ip4_address_pretty_sort_cmp(const NMPlatformIP4Address *a1,
                                        const NMPlatformIP4Address *a2)
{
    in_addr_t n1;
    in_addr_t n2;

    nm_assert(a1);
    nm_assert(a2);

    /* Sort by address type. For example link local will
     * be sorted *after* a global address. */
    NM_CMP_DIRECT(_address_pretty_sort_get_prio_4(a2->address),
                  _address_pretty_sort_get_prio_4(a1->address));

    /* Sort the addresses based on their source. */
    NM_CMP_DIRECT(a2->addr_source, a1->addr_source);

    NM_CMP_DIRECT((a2->label[0] == '\0'), (a1->label[0] == '\0'));

    /* Finally, sort addresses lexically. We compare only the
     * network part so that the order of addresses in the same
     * subnet (and thus also the primary/secondary role) is
     * preserved.
     */
    n1 = nm_ip4_addr_clear_host_address(a1->address, a1->plen);
    n2 = nm_ip4_addr_clear_host_address(a2->address, a2->plen);
    NM_CMP_DIRECT_MEMCMP(&n1, &n2, sizeof(guint32));
    return 0;
}

int
nm_platform_ip6_address_pretty_sort_cmp(const NMPlatformIP6Address *a1,
                                        const NMPlatformIP6Address *a2,
                                        gboolean                    prefer_temp)
{
    gboolean ipv6_privacy1;
    gboolean ipv6_privacy2;

    nm_assert(a1);
    nm_assert(a2);

    /* tentative addresses are always sorted back... */
    /* sort tentative addresses after non-tentative. */
    NM_CMP_DIRECT(NM_FLAGS_HAS(a1->n_ifa_flags, IFA_F_TENTATIVE),
                  NM_FLAGS_HAS(a2->n_ifa_flags, IFA_F_TENTATIVE));

    /* Sort by address type. For example link local will
     * be sorted *after* site local or global. */
    NM_CMP_DIRECT(_address_pretty_sort_get_prio_6(&a2->address),
                  _address_pretty_sort_get_prio_6(&a1->address));

    ipv6_privacy1 = NM_FLAGS_ANY(a1->n_ifa_flags, IFA_F_MANAGETEMPADDR | IFA_F_SECONDARY);
    ipv6_privacy2 = NM_FLAGS_ANY(a2->n_ifa_flags, IFA_F_MANAGETEMPADDR | IFA_F_SECONDARY);
    if (ipv6_privacy1 || ipv6_privacy2) {
        gboolean public1 = TRUE;
        gboolean public2 = TRUE;

        if (ipv6_privacy1) {
            if (a1->n_ifa_flags & IFA_F_SECONDARY)
                public1 = prefer_temp;
            else
                public1 = !prefer_temp;
        }
        if (ipv6_privacy2) {
            if (a2->n_ifa_flags & IFA_F_SECONDARY)
                public2 = prefer_temp;
            else
                public2 = !prefer_temp;
        }

        NM_CMP_DIRECT(public2, public1);
    }

    /* Sort the addresses based on their source. */
    NM_CMP_DIRECT(a2->addr_source, a1->addr_source);

    /* sort permanent addresses before non-permanent. */
    NM_CMP_DIRECT(NM_FLAGS_HAS(a2->n_ifa_flags, IFA_F_PERMANENT),
                  NM_FLAGS_HAS(a1->n_ifa_flags, IFA_F_PERMANENT));

    /* finally sort addresses lexically */
    NM_CMP_DIRECT_IN6ADDR(&a1->address, &a2->address);
    NM_CMP_DIRECT_MEMCMP(a1, a2, sizeof(*a1));
    return 0;
}

void
nm_platform_ip4_address_set_addr(NMPlatformIP4Address *addr, in_addr_t address, guint8 plen)
{
    nm_assert(plen <= 32);

    addr->address      = address;
    addr->peer_address = address;
    addr->plen         = plen;
}

const struct in6_addr *
nm_platform_ip6_address_get_peer(const NMPlatformIP6Address *addr)
{
    if (IN6_IS_ADDR_UNSPECIFIED(&addr->peer_address)
        || IN6_ARE_ADDR_EQUAL(&addr->peer_address, &addr->address))
        return &addr->address;
    return &addr->peer_address;
}

/*****************************************************************************/

/**
 * nm_platform_ip4_address_to_string:
 * @route: pointer to NMPlatformIP4Address address structure
 * @buf: (nullable): an optional buffer. If %NULL, a static buffer is used.
 * @len: the size of the @buf. If @buf is %NULL, this argument is ignored.
 *
 * A method for converting an address struct into a string representation.
 *
 * Example output: ""
 *
 * Returns: a string representation of the address.
 */
const char *
nm_platform_ip4_address_to_string(const NMPlatformIP4Address *address, char *buf, gsize len)
{
    char        s_flags[TO_STRING_IFA_FLAGS_BUF_SIZE];
    char        s_address[INET_ADDRSTRLEN];
    char        s_peer[INET_ADDRSTRLEN];
    char        str_dev[30];
    char        str_label[32];
    char        str_lft[30];
    char        str_pref[30];
    char        str_time[50];
    char        s_source[50];
    char       *str_peer = NULL;
    const char *str_lft_p, *str_pref_p, *str_time_p;
    gint32      now = nm_utils_get_monotonic_timestamp_sec();
    in_addr_t   broadcast_address;
    char        str_broadcast[INET_ADDRSTRLEN];

    if (!nm_utils_to_string_buffer_init_null(address, &buf, &len))
        return buf;

    inet_ntop(AF_INET, &address->address, s_address, sizeof(s_address));

    if (address->peer_address != address->address) {
        inet_ntop(AF_INET, &address->peer_address, s_peer, sizeof(s_peer));
        str_peer = g_strconcat(" ptp ", s_peer, NULL);
    }

    if (*address->label)
        g_snprintf(str_label, sizeof(str_label), " label %s", address->label);
    else
        str_label[0] = 0;

    str_lft_p = _lifetime_to_string(address->timestamp,
                                    address->lifetime ?: NM_PLATFORM_LIFETIME_PERMANENT,
                                    now,
                                    str_lft,
                                    sizeof(str_lft)),
    str_pref_p =
        (address->lifetime == address->preferred)
            ? str_lft_p
            : (_lifetime_to_string(address->timestamp,
                                   address->lifetime ? MIN(address->preferred, address->lifetime)
                                                     : NM_PLATFORM_LIFETIME_PERMANENT,
                                   now,
                                   str_pref,
                                   sizeof(str_pref)));
    str_time_p = _lifetime_summary_to_string(now,
                                             address->timestamp,
                                             address->preferred,
                                             address->lifetime,
                                             str_time,
                                             sizeof(str_time));

    broadcast_address = nm_platform_ip4_broadcast_address_from_addr(address);

    g_snprintf(
        buf,
        len,
        "%s/%d"
        "%s%s" /* broadcast */
        " lft %s"
        " pref %s"
        "%s" /* time */
        "%s" /* peer  */
        "%s" /* dev */
        "%s" /* flags */
        "%s" /* label */
        " src %s"
        "%s" /* a_acd_not_ready */
        "%s" /* a_force_commit */
        "",
        s_address,
        address->plen,
        broadcast_address != 0u || address->use_ip4_broadcast_address
            ? (address->use_ip4_broadcast_address ? " brd " : " brd* ")
            : "",
        broadcast_address != 0u || address->use_ip4_broadcast_address
            ? nm_inet4_ntop(broadcast_address, str_broadcast)
            : "",
        str_lft_p,
        str_pref_p,
        str_time_p,
        str_peer ?: "",
        _to_string_dev(str_dev, address->ifindex),
        _to_string_ifa_flags(address->n_ifa_flags, s_flags, sizeof(s_flags)),
        str_label,
        nmp_utils_ip_config_source_to_string(address->addr_source, s_source, sizeof(s_source)),
        address->a_acd_not_ready ? " ip4acd-not-ready" : "",
        address->a_force_commit ? " force-commit" : "");
    g_free(str_peer);
    return buf;
}

/**
 * nm_platform_ip6_address_to_string:
 * @route: pointer to NMPlatformIP6Address address structure
 * @buf: (nullable): an optional buffer. If %NULL, a static buffer is used.
 * @len: the size of the @buf. If @buf is %NULL, this argument is ignored.
 *
 * A method for converting an address struct into a string representation.
 *
 * Example output: "2001:db8:0:f101::1/64 lft 4294967295 pref 4294967295 time 16922666 on dev em1"
 *
 * Returns: a string representation of the address.
 */
const char *
nm_platform_ip6_address_to_string(const NMPlatformIP6Address *address, char *buf, gsize len)
{
    char        s_flags[TO_STRING_IFA_FLAGS_BUF_SIZE];
    char        s_address[INET6_ADDRSTRLEN];
    char        s_peer[INET6_ADDRSTRLEN];
    char        str_lft[30];
    char        str_pref[30];
    char        str_time[50];
    char        s_source[50];
    char        str_dev[30];
    char       *str_peer = NULL;
    const char *str_lft_p, *str_pref_p, *str_time_p;
    gint32      now = nm_utils_get_monotonic_timestamp_sec();

    if (!nm_utils_to_string_buffer_init_null(address, &buf, &len))
        return buf;

    inet_ntop(AF_INET6, &address->address, s_address, sizeof(s_address));

    if (!IN6_IS_ADDR_UNSPECIFIED(&address->peer_address)) {
        inet_ntop(AF_INET6, &address->peer_address, s_peer, sizeof(s_peer));
        str_peer = g_strconcat(" ptp ", s_peer, NULL);
    }

    str_lft_p = _lifetime_to_string(address->timestamp,
                                    address->lifetime ?: NM_PLATFORM_LIFETIME_PERMANENT,
                                    now,
                                    str_lft,
                                    sizeof(str_lft)),
    str_pref_p =
        (address->lifetime == address->preferred)
            ? str_lft_p
            : (_lifetime_to_string(address->timestamp,
                                   address->lifetime ? MIN(address->preferred, address->lifetime)
                                                     : NM_PLATFORM_LIFETIME_PERMANENT,
                                   now,
                                   str_pref,
                                   sizeof(str_pref)));
    str_time_p = _lifetime_summary_to_string(now,
                                             address->timestamp,
                                             address->preferred,
                                             address->lifetime,
                                             str_time,
                                             sizeof(str_time));

    g_snprintf(
        buf,
        len,
        "%s/%d lft %s pref %s%s%s%s%s src %s"
        "%s" /* a_force_commit */
        "",
        s_address,
        address->plen,
        str_lft_p,
        str_pref_p,
        str_time_p,
        str_peer ?: "",
        _to_string_dev(str_dev, address->ifindex),
        _to_string_ifa_flags(address->n_ifa_flags, s_flags, sizeof(s_flags)),
        nmp_utils_ip_config_source_to_string(address->addr_source, s_source, sizeof(s_source)),
        address->a_force_commit ? " force-commit" : "");
    g_free(str_peer);
    return buf;
}

/*****************************************************************************/

gboolean
nm_platform_ip_address_match(int                        addr_family,
                             const NMPlatformIPAddress *address,
                             NMPlatformMatchFlags       match_flag)
{
    nm_assert(!NM_FLAGS_ANY(
        match_flag,
        ~(NM_PLATFORM_MATCH_WITH_ADDRTYPE__ANY | NM_PLATFORM_MATCH_WITH_ADDRSTATE__ANY)));
    nm_assert(NM_FLAGS_ANY(match_flag, NM_PLATFORM_MATCH_WITH_ADDRTYPE__ANY));
    nm_assert(NM_FLAGS_ANY(match_flag, NM_PLATFORM_MATCH_WITH_ADDRSTATE__ANY));

    if (addr_family == AF_INET) {
        if (nm_ip4_addr_is_link_local(((NMPlatformIP4Address *) address)->address)) {
            if (!NM_FLAGS_HAS(match_flag, NM_PLATFORM_MATCH_WITH_ADDRTYPE_LINKLOCAL))
                return FALSE;
        } else {
            if (!NM_FLAGS_HAS(match_flag, NM_PLATFORM_MATCH_WITH_ADDRTYPE_NORMAL))
                return FALSE;
        }
    } else {
        if (IN6_IS_ADDR_LINKLOCAL(address->address_ptr)) {
            if (!NM_FLAGS_HAS(match_flag, NM_PLATFORM_MATCH_WITH_ADDRTYPE_LINKLOCAL))
                return FALSE;
        } else {
            if (!NM_FLAGS_HAS(match_flag, NM_PLATFORM_MATCH_WITH_ADDRTYPE_NORMAL))
                return FALSE;
        }
    }

    if (NM_FLAGS_HAS(address->n_ifa_flags, IFA_F_DADFAILED)) {
        if (!NM_FLAGS_HAS(match_flag, NM_PLATFORM_MATCH_WITH_ADDRSTATE_DADFAILED))
            return FALSE;
    } else if (NM_FLAGS_HAS(address->n_ifa_flags, IFA_F_TENTATIVE)
               && !NM_FLAGS_HAS(address->n_ifa_flags, IFA_F_OPTIMISTIC)) {
        if (!NM_FLAGS_HAS(match_flag, NM_PLATFORM_MATCH_WITH_ADDRSTATE_TENTATIVE))
            return FALSE;
    } else if (NM_FLAGS_HAS(address->n_ifa_flags, IFA_F_DEPRECATED)) {
        if (!NM_FLAGS_HAS(match_flag, NM_PLATFORM_MATCH_WITH_ADDRSTATE_DEPRECATED))
            return FALSE;
    } else {
        if (!NM_FLAGS_HAS(match_flag, NM_PLATFORM_MATCH_WITH_ADDRSTATE_NORMAL))
            return FALSE;
    }

    return TRUE;
}

/*****************************************************************************/

const _NMPlatformVTableAddressUnion nm_platform_vtable_address = {
    .v4 =
        {
            .is_ip4         = TRUE,
            .obj_type       = NMP_OBJECT_TYPE_IP4_ADDRESS,
            .addr_family    = AF_INET,
            .sizeof_address = sizeof(NMPlatformIP4Address),
            .address_cmp =
                (int (*)(const NMPlatformIPXAddress *a,
                         const NMPlatformIPXAddress *b,
                         NMPlatformIPAddressCmpType  cmp_type)) nm_platform_ip4_address_cmp,
            .address_to_string = (const char *(*) (const NMPlatformIPXAddress *address,
                                                   char                       *buf,
                                                   gsize len)) nm_platform_ip4_address_to_string,
        },
    .v6 =
        {
            .is_ip4         = FALSE,
            .obj_type       = NMP_OBJECT_TYPE_IP6_ADDRESS,
            .addr_family    = AF_INET6,
            .sizeof_address = sizeof(NMPlatformIP6Address),
            .address_cmp =
                (int (*)(const NMPlatformIPXAddress *a,
                         const NMPlatformIPXAddress *b,
                         NMPlatformIPAddressCmpType  cmp_type)) nm_platform_ip6_address_cmp,
            .address_to_string = (const char *(*) (const NMPlatformIPXAddress *address,
                                                   char                       *buf,
                                                   gsize len)) nm_platform_ip6_address_to_string,
        },
};
