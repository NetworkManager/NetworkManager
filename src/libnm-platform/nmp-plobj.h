/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2015 - 2018 Red Hat, Inc.
 */

#ifndef __NMP_PLOBJ_H__
#define __NMP_PLOBJ_H__

#include "libnm-base/nm-base.h"

#include "nmp-base.h"

/*****************************************************************************/

/* This is used with _nm_align() on the platform structs. Note that
 * "align" attribute can only increase the natural alignment, unless
 * also "packed" is specified. That's what we want.
 * https://gcc.gnu.org/onlinedocs/gcc/Common-Type-Attributes.html#Common-Type-Attributes.
 */
#define _NMPlatformObject_Align (MAX(_nm_alignof(void *), _nm_alignof(gint64)))

struct _NMPlatformObject {
    /* the object type has no fields of its own, it is only used to having
     * a special pointer type that can be used to indicate "any" type. */
    char _dummy_don_t_use_me;
} _nm_align(_NMPlatformObject_Align);

/*****************************************************************************/

#define __NMPlatformObjWithIfindex_COMMON \
    int ifindex;                          \
    ;

/*****************************************************************************/

#define __NMPlatformIPAddress_COMMON                                                         \
    __NMPlatformObjWithIfindex_COMMON;                                                       \
    NMIPConfigSource addr_source;                                                            \
                                                                                             \
    /* Timestamp in seconds in the reference system of nm_utils_get_monotonic_timestamp_*().
     *
     * The rules are:
     * 1 @lifetime==0: @timestamp and @preferred is irrelevant (but mostly set to 0 too). Such addresses
     *   are permanent. This rule is so that unset addresses (calloc) are permanent by default.
     * 2 @lifetime==@preferred==NM_PLATFORM_LIFETIME_PERMANENT: @timestamp is irrelevant (but mostly
     *   set to 0). Such addresses are permanent.
     * 3 Non permanent addresses should (almost) always have @timestamp > 0. 0 is not a valid timestamp
     *   and never returned by nm_utils_get_monotonic_timestamp_sec(). In this case @valid/@preferred
     *   is anchored at @timestamp.
     * 4 Non permanent addresses with @timestamp == 0 are implicitly anchored at *now*, thus the time
     *   moves as time goes by. This is usually not useful, except e.g. nm_platform_ip[46]_address_add().
     *
     * Non permanent addresses from DHCP/RA might have the @timestamp set to the moment of when the
     * lease was received. Addresses from kernel might have the @timestamp based on the last modification
     * time of the addresses. But don't rely on this behaviour, the @timestamp is only defined for anchoring
     * @lifetime and @preferred.
     */ \
    guint32 timestamp;                                                                       \
    guint32 lifetime;  /* seconds since timestamp */                                         \
    guint32 preferred; /* seconds since timestamp */                                         \
                                                                                             \
    /* ifa_flags in 'struct ifaddrmsg' from <linux/if_addr.h>, extended to 32 bit by
     * IFA_FLAGS attribute. */         \
    guint32 n_ifa_flags;                                                                     \
                                                                                             \
    bool use_ip4_broadcast_address : 1;                                                      \
                                                                                             \
    /* Meta flags not honored by NMPlatform (netlink code). Instead, they can be
     * used by the upper layers which use NMPlatformIPRoute to track addresses that
     * should be configured. */             \
    bool a_force_commit : 1;                                                                 \
                                                                                             \
    /* Don't have a bitfield as last field in __NMPlatformIPAddress_COMMON. It would then
     * be unclear how the following fields get merged. We could also use a zero bitfield,
     * but instead we just have there the uint8 field. */    \
    guint8 plen;                                                                             \
    ;

/**
 * NMPlatformIPAddress:
 *
 * Common parts of NMPlatformIP4Address and NMPlatformIP6Address.
 **/
typedef struct {
    __NMPlatformIPAddress_COMMON;
    _nm_alignas(NMIPAddr) guint8 address_ptr[];
} _nm_alignas(NMPlatformObject) NMPlatformIPAddress;

/**
 * NMPlatformIP4Address:
 * @timestamp: timestamp as returned by nm_utils_get_monotonic_timestamp_sec()
 **/
struct _NMPlatformIP4Address {
    __NMPlatformIPAddress_COMMON;

    /* The local address IFA_LOCAL. */
    _nm_alignas(NMIPAddr) in_addr_t address;

    /* The IFA_ADDRESS PTP peer address. This field is rather important, because
     * it constitutes the identifier for the IPv4 address (e.g. you can add two
     * addresses that only differ by their peer's network-part.
     *
     * Beware that for most cases, NetworkManager doesn't want to set an explicit
     * peer-address. However, that corresponds to setting the peer address to @address
     * itself. Leaving peer-address unset/zero, means explicitly setting the peer
     * address to 0.0.0.0, which you probably don't want.
     * */
    in_addr_t peer_address; /* PTP peer address */

    /* IFA_BROADCAST.
     *
     * This parameter is ignored unless use_ip4_broadcast_address is TRUE.
     * See nm_platform_ip4_broadcast_address_from_addr(). */
    in_addr_t broadcast_address;

    char label[NMP_IFNAMSIZ];

    /* Whether the address is ready to be configured. By default, an address is, but this
     * flag may indicate that the address is just for tracking purpose only, but the ACD
     * state is not yet ready for the address to be configured. */
    bool a_acd_not_ready : 1;
} _nm_alignas(NMPlatformObject);

/**
 * NMPlatformIP6Address:
 * @timestamp: timestamp as returned by nm_utils_get_monotonic_timestamp_sec()
 **/
struct _NMPlatformIP6Address {
    __NMPlatformIPAddress_COMMON;
    _nm_alignas(NMIPAddr) struct in6_addr address;
    struct in6_addr peer_address;
} _nm_alignas(NMPlatformObject);

typedef union {
    NMPlatformIPAddress  ax;
    NMPlatformIP4Address a4;
    NMPlatformIP6Address a6;
} NMPlatformIPXAddress;

#undef __NMPlatformIPAddress_COMMON

/*****************************************************************************/

typedef enum {
    NM_PLATFORM_IP_ADDRESS_CMP_TYPE_ID,

    NM_PLATFORM_IP_ADDRESS_CMP_TYPE_SEMANTICALLY,

    NM_PLATFORM_IP_ADDRESS_CMP_TYPE_FULL,
} NMPlatformIPAddressCmpType;

#define NM_PLATFORM_IP_ADDRESS_CAST(address) \
    NM_CONSTCAST(NMPlatformIPAddress,        \
                 (address),                  \
                 NMPlatformIPXAddress,       \
                 NMPlatformIP4Address,       \
                 NMPlatformIP6Address)

#define NM_PLATFORM_IP4_ADDRESS_INIT(...) (&((const NMPlatformIP4Address){__VA_ARGS__}))

#define NM_PLATFORM_IP6_ADDRESS_INIT(...) (&((const NMPlatformIP6Address){__VA_ARGS__}))

/*****************************************************************************/

typedef struct {
    bool          is_ip4;
    NMPObjectType obj_type;
    gint8         addr_family;
    guint8        sizeof_address;
    int (*address_cmp)(const NMPlatformIPXAddress *a,
                       const NMPlatformIPXAddress *b,
                       NMPlatformIPAddressCmpType  cmp_type);
    const char *(*address_to_string)(const NMPlatformIPXAddress *address, char *buf, gsize len);
} NMPlatformVTableAddress;

typedef union {
    struct {
        NMPlatformVTableAddress v6;
        NMPlatformVTableAddress v4;
    };
    NMPlatformVTableAddress vx[2];
} _NMPlatformVTableAddressUnion;

extern const _NMPlatformVTableAddressUnion nm_platform_vtable_address;

void nm_platform_ip4_address_hash_update(const NMPlatformIP4Address *obj, NMHashState *h);

int nm_platform_ip4_address_cmp(const NMPlatformIP4Address *a,
                                const NMPlatformIP4Address *b,
                                NMPlatformIPAddressCmpType  cmp_type);

static inline int
nm_platform_ip4_address_cmp_full(const NMPlatformIP4Address *a, const NMPlatformIP4Address *b)
{
    return nm_platform_ip4_address_cmp(a, b, NM_PLATFORM_IP_ADDRESS_CMP_TYPE_FULL);
}

void nm_platform_ip6_address_hash_update(const NMPlatformIP6Address *obj, NMHashState *h);

int nm_platform_ip6_address_cmp(const NMPlatformIP6Address *a,
                                const NMPlatformIP6Address *b,
                                NMPlatformIPAddressCmpType  cmp_type);

static inline int
nm_platform_ip6_address_cmp_full(const NMPlatformIP6Address *a, const NMPlatformIP6Address *b)
{
    return nm_platform_ip6_address_cmp(a, b, NM_PLATFORM_IP_ADDRESS_CMP_TYPE_FULL);
}

int nm_platform_ip4_address_pretty_sort_cmp(const NMPlatformIP4Address *a1,
                                            const NMPlatformIP4Address *a2);

int nm_platform_ip6_address_pretty_sort_cmp(const NMPlatformIP6Address *a1,
                                            const NMPlatformIP6Address *a2,
                                            gboolean                    prefer_temp);

static inline in_addr_t
nm_platform_ip4_broadcast_address_from_addr(const NMPlatformIP4Address *addr)
{
    nm_assert(addr);

    if (addr->use_ip4_broadcast_address)
        return addr->broadcast_address;

    /* the set broadcast-address gets ignored, and we determine a default brd base
     * on the peer IFA_ADDRESS. */
    if (addr->peer_address != 0u && addr->plen < 31 /* RFC3021 */)
        return nm_ip4_addr_get_broadcast_address(addr->peer_address, addr->plen);
    return 0u;
}

void nm_platform_ip4_address_set_addr(NMPlatformIP4Address *addr, in_addr_t address, guint8 plen);

const struct in6_addr *nm_platform_ip6_address_get_peer(const NMPlatformIP6Address *addr);

static inline gpointer
nm_platform_ip_address_get_peer_address(int addr_family, const NMPlatformIPAddress *addr)
{
    nm_assert_addr_family(addr_family);
    nm_assert(addr);

    if (NM_IS_IPv4(addr_family))
        return &((NMPlatformIP4Address *) addr)->peer_address;
    return &((NMPlatformIP6Address *) addr)->peer_address;
}

const char *
nm_platform_ip4_address_to_string(const NMPlatformIP4Address *address, char *buf, gsize len);
const char *
nm_platform_ip6_address_to_string(const NMPlatformIP6Address *address, char *buf, gsize len);

int nm_platform_ip_address_cmp_expiry(const NMPlatformIPAddress *a, const NMPlatformIPAddress *b);

NMPlatformIP4Route *nm_platform_ip4_address_generate_device_route(const NMPlatformIP4Address *addr,
                                                                  int                 ifindex,
                                                                  guint32             route_table,
                                                                  guint32             route_metric,
                                                                  gboolean            force_commit,
                                                                  NMPlatformIP4Route *dst);

typedef enum {

    /* match-flags are strictly inclusive. That means,
     * by default nothing is matched, but if you enable a particular
     * flag, a candidate that matches passes the check.
     *
     * In other words: adding more flags can only extend the result
     * set of matching objects.
     *
     * Also, the flags form partitions. Like, an address can be either of
     * ADDRTYPE_NORMAL or ADDRTYPE_LINKLOCAL, but never both. Same for
     * the ADDRSTATE match types.
     */
    NM_PLATFORM_MATCH_WITH_NONE = 0,

    NM_PLATFORM_MATCH_WITH_ADDRTYPE_NORMAL    = (1LL << 0),
    NM_PLATFORM_MATCH_WITH_ADDRTYPE_LINKLOCAL = (1LL << 1),
    NM_PLATFORM_MATCH_WITH_ADDRTYPE__ANY =
        NM_PLATFORM_MATCH_WITH_ADDRTYPE_NORMAL | NM_PLATFORM_MATCH_WITH_ADDRTYPE_LINKLOCAL,

    NM_PLATFORM_MATCH_WITH_ADDRSTATE_NORMAL     = (1LL << 2),
    NM_PLATFORM_MATCH_WITH_ADDRSTATE_TENTATIVE  = (1LL << 3),
    NM_PLATFORM_MATCH_WITH_ADDRSTATE_DADFAILED  = (1LL << 4),
    NM_PLATFORM_MATCH_WITH_ADDRSTATE_DEPRECATED = (1LL << 5),
    NM_PLATFORM_MATCH_WITH_ADDRSTATE__ANY =
        NM_PLATFORM_MATCH_WITH_ADDRSTATE_NORMAL | NM_PLATFORM_MATCH_WITH_ADDRSTATE_TENTATIVE
        | NM_PLATFORM_MATCH_WITH_ADDRSTATE_DADFAILED | NM_PLATFORM_MATCH_WITH_ADDRSTATE_DEPRECATED,
} NMPlatformMatchFlags;

gboolean nm_platform_ip_address_match(int                        addr_family,
                                      const NMPlatformIPAddress *addr,
                                      NMPlatformMatchFlags       match_flag);

/*****************************************************************************/

#endif /* __NMP_PLOBJ_H__ */
