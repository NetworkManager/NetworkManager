/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2009 - 2018 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_PLATFORM_H__
#define __NETWORKMANAGER_PLATFORM_H__

#include "libnm-platform/nmp-base.h"
#include "libnm-base/nm-base.h"
#include "nmp-plobj.h"

#define NM_TYPE_PLATFORM (nm_platform_get_type())
#define NM_PLATFORM(obj) (_NM_G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_PLATFORM, NMPlatform))
#define NM_PLATFORM_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_PLATFORM, NMPlatformClass))
#define NM_IS_PLATFORM(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_PLATFORM))
#define NM_IS_PLATFORM_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_PLATFORM))
#define NM_PLATFORM_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_PLATFORM, NMPlatformClass))

#define NM_PLATFORM_NETNS_SUPPORT_DEFAULT FALSE

/*****************************************************************************/

#define NM_PLATFORM_CACHE_TC      "cache-tc"
#define NM_PLATFORM_LOG_WITH_PTR  "log-with-ptr"
#define NM_PLATFORM_MULTI_IDX     "multi-idx"
#define NM_PLATFORM_NETNS_SUPPORT "netns-support"
#define NM_PLATFORM_USE_UDEV      "use-udev"

/*****************************************************************************/

struct _NMPWireGuardPeer;

struct udev_device;

typedef gboolean (*NMPObjectPredicateFunc)(const NMPObject *obj, gpointer user_data);

#define NM_RT_SCOPE_LINK 253 /* RT_SCOPE_LINK */

#define NM_IFF_MULTI_QUEUE 0x0100 /* IFF_MULTI_QUEUE */

#define NM_MPTCP_PM_ADDR_FLAG_SIGNAL   ((guint32) (1 << 0))
#define NM_MPTCP_PM_ADDR_FLAG_SUBFLOW  ((guint32) (1 << 1))
#define NM_MPTCP_PM_ADDR_FLAG_BACKUP   ((guint32) (1 << 2))
#define NM_MPTCP_PM_ADDR_FLAG_FULLMESH ((guint32) (1 << 3))
#define NM_MPTCP_PM_ADDR_FLAG_IMPLICIT ((guint32) (1 << 4))

/* Redefine this in host's endianness */
#define NM_GRE_KEY 0x2000

typedef enum {
    NMP_NLM_FLAG_F_ECHO = 0x08, /* NLM_F_ECHO, Echo this request */

    /* use our own platform enum for the nlmsg-flags. Otherwise, we'd have
     * to include <linux/netlink.h> */
    NMP_NLM_FLAG_F_REPLACE = 0x100, /* NLM_F_REPLACE, Override existing */
    NMP_NLM_FLAG_F_EXCL    = 0x200, /* NLM_F_EXCL, Do not touch, if it exists */
    NMP_NLM_FLAG_F_CREATE  = 0x400, /* NLM_F_CREATE, Create, if it does not exist */
    NMP_NLM_FLAG_F_APPEND  = 0x800, /* NLM_F_APPEND, Add to end of list */

    NMP_NLM_FLAG_FMASK = 0xFFFF, /* a mask for all NMP_NLM_FLAG_F_* flags */

    /* instructs NM to suppress logging an error message for any failures
     * received from kernel.
     *
     * It will still log with debug-level, and it will still log
     * other failures aside the kernel response. */
    NMP_NLM_FLAG_SUPPRESS_NETLINK_FAILURE = 0x10000,

    /* the following aliases correspond to iproute2's `ip route CMD` for
     * RTM_NEWROUTE, with CMD being one of add, change, replace, prepend,
     * append and test. */
    NMP_NLM_FLAG_ADD     = NMP_NLM_FLAG_F_CREATE | NMP_NLM_FLAG_F_EXCL,
    NMP_NLM_FLAG_CHANGE  = NMP_NLM_FLAG_F_REPLACE,
    NMP_NLM_FLAG_REPLACE = NMP_NLM_FLAG_F_CREATE | NMP_NLM_FLAG_F_REPLACE,
    NMP_NLM_FLAG_PREPEND = NMP_NLM_FLAG_F_CREATE,
    NMP_NLM_FLAG_APPEND  = NMP_NLM_FLAG_F_CREATE | NMP_NLM_FLAG_F_APPEND,
    NMP_NLM_FLAG_TEST    = NMP_NLM_FLAG_F_EXCL,
} NMPNlmFlags;

typedef enum {
    /* compare fields which kernel considers as similar routes.
     * It is a looser comparisong then NM_PLATFORM_IP_ROUTE_CMP_TYPE_ID
     * and means that `ip route add` would fail to add two routes
     * that have the same NM_PLATFORM_IP_ROUTE_CMP_TYPE_WEAK_ID.
     * On the other hand, `ip route append` would allow that, as
     * long as NM_PLATFORM_IP_ROUTE_CMP_TYPE_ID differs. */
    NM_PLATFORM_IP_ROUTE_CMP_TYPE_WEAK_ID,

    /* compare two routes as kernel would allow to add them with
     * `ip route append`. In other words, kernel does not allow you to
     * add two routes (at the same time) which compare equal according
     * to NM_PLATFORM_IP_ROUTE_CMP_TYPE_ID.
     *
     * For the ID we can only recognize route fields that we actually implement.
     * However, kernel supports more routing options, some of them also part of
     * the ID. NetworkManager is oblivious to these options and will wrongly think
     * that two routes are identical, while they are not. That can lead to an
     * inconsistent platform cache. Not much what we can do about that, except
     * implementing all options that kernel supports *sigh*. See rh#1337860.
     */
    NM_PLATFORM_IP_ROUTE_CMP_TYPE_ID,

    /* IPv4 route can have multiple hops. This is the ID, by which multiple
     * routes are merged according to the next hop. This is basically NM_PLATFORM_IP_ROUTE_CMP_TYPE_ID
     * which ignores the next hops. */
    NM_PLATFORM_IP_ROUTE_CMP_TYPE_ECMP_ID,

    /* compare all fields as they make sense for kernel. For example,
     * a route destination 192.168.1.5/24 is not accepted by kernel and
     * we treat it identical to 192.168.1.0/24. Semantically these
     * routes are identical, but NM_PLATFORM_IP_ROUTE_CMP_TYPE_FULL will
     * report them as different.
     *
     * The result shall be identical to call first nm_platform_ip_route_normalize()
     * on both routes and then doing a full comparison. */
    NM_PLATFORM_IP_ROUTE_CMP_TYPE_SEMANTICALLY,

    /* compare all fields. This should have the same effect as memcmp(),
     * except allowing for undefined data in holes between field alignment.
     */
    NM_PLATFORM_IP_ROUTE_CMP_TYPE_FULL,

} NMPlatformIPRouteCmpType;

typedef enum {
    NM_PLATFORM_ROUTING_RULE_CMP_TYPE_ID,

    NM_PLATFORM_ROUTING_RULE_CMP_TYPE_SEMANTICALLY,

    NM_PLATFORM_ROUTING_RULE_CMP_TYPE_FULL,
} NMPlatformRoutingRuleCmpType;

typedef struct {
    union {
        guint8      data[20 /* _NM_UTILS_HWADDR_LEN_MAX */];
        NMEtherAddr ether_addr;
    };
    guint8 len;
} NMPLinkAddress;

/* assert that NMEtherAddr does not affect the alignment of NMPLinkAddress struct. */
G_STATIC_ASSERT(_nm_alignof(NMEtherAddr) == 1);
G_STATIC_ASSERT(_nm_alignof(NMPLinkAddress) == 1);

gconstpointer nmp_link_address_get(const NMPLinkAddress *addr, size_t *length);
GBytes       *nmp_link_address_get_as_bytes(const NMPLinkAddress *addr);

#define NM_PLATFORM_LINK_OTHER_NETNS (-1)

typedef struct {
    guint32 tx_queue_length;
    guint32 gso_max_size;
    guint32 gso_max_segments;
    guint32 gro_max_size;
} NMPlatformLinkProps;

typedef enum {
    NM_PLATFORM_LINK_CHANGE_NONE             = 0,
    NM_PLATFORM_LINK_CHANGE_TX_QUEUE_LENGTH  = (1 << 0),
    NM_PLATFORM_LINK_CHANGE_GSO_MAX_SIZE     = (1 << 1),
    NM_PLATFORM_LINK_CHANGE_GSO_MAX_SEGMENTS = (1 << 2),
    NM_PLATFORM_LINK_CHANGE_GRO_MAX_SIZE     = (1 << 3),
} NMPlatformLinkChangeFlags;

struct _NMPlatformObjWithIfindex {
    __NMPlatformObjWithIfindex_COMMON;
} _nm_alignas(NMPlatformObject);

typedef struct {
    gint32  prio;
    guint16 queue_id;
    bool    prio_has : 1;
} NMPlatformLinkBondPort;

typedef union {
    NMPlatformLinkBondPort bond;
} NMPlatformLinkPortData;

struct _NMPlatformLink {
    __NMPlatformObjWithIfindex_COMMON;
    char       name[NM_IFNAMSIZ];
    NMLinkType type;

    /* rtnl_link_get_type(), IFLA_INFO_KIND. */
    /* NMPlatform initializes this field with a static string. */
    const char *kind;

    /* NMPlatform initializes this field with a static string. */
    const char *driver;

    int master;

    /* rtnl_link_get_link(), IFLA_LINK.
     * If IFLA_LINK_NETNSID indicates that the parent is in another namespace,
     * this field be set to (negative) NM_PLATFORM_LINK_OTHER_NETNS. */
    int parent;

    /* IFF_* flags. Note that the flags in 'struct ifinfomsg' are declared as 'unsigned'. */
    guint n_ifi_flags;

    guint mtu;

    /* rtnl_link_get_arptype(), ifinfomsg.ifi_type. */
    guint32 arptype;

    /* IFLA_ADDRESS */
    NMPLinkAddress l_address;

    /* IFLA_PERM_ADDRESS */
    NMPLinkAddress l_perm_address;

    /* IFLA_BROADCAST */
    NMPLinkAddress l_broadcast;

    /* rtnl_link_inet6_get_token(), IFLA_INET6_TOKEN */
    NMUtilsIPv6IfaceId inet6_token;

    /* The bitwise inverse of rtnl_link_inet6_get_addr_gen_mode(). It is inverse
     * to have a default of 0 -- meaning: unspecified. That way, a struct
     * initialized with memset(0) has and unset value.*/
    guint8 inet6_addr_gen_mode_inv;

    /* Statistics */
    guint64 rx_packets;
    guint64 rx_bytes;
    guint64 tx_packets;
    guint64 tx_bytes;

    NMPlatformLinkProps link_props;

    /* an interface can only hold IFLA_INFO_SLAVE_DATA for one link type */
    NMPlatformLinkPortData port_data;

    /* IFLA_INFO_SLAVE_KIND */
    NMPortKind port_kind;

    /* @connected is mostly identical to (@n_ifi_flags & IFF_UP). Except for bridge/bond masters,
     * where we coerce the link as disconnect if it has no slaves. */
    bool connected : 1;

    bool initialized : 1;
} _nm_alignas(NMPlatformObject);

typedef enum {
    NM_PLATFORM_SIGNAL_ID_NONE,
    NM_PLATFORM_SIGNAL_ID_LINK,
    NM_PLATFORM_SIGNAL_ID_IP4_ADDRESS,
    NM_PLATFORM_SIGNAL_ID_IP6_ADDRESS,
    NM_PLATFORM_SIGNAL_ID_IP4_ROUTE,
    NM_PLATFORM_SIGNAL_ID_IP6_ROUTE,
    NM_PLATFORM_SIGNAL_ID_ROUTING_RULE,
    NM_PLATFORM_SIGNAL_ID_QDISC,
    NM_PLATFORM_SIGNAL_ID_TFILTER,
    _NM_PLATFORM_SIGNAL_ID_LAST,
} NMPlatformSignalIdType;

guint _nm_platform_signal_id_get(NMPlatformSignalIdType signal_type);

/* Default value for adding an IPv4 route. This is also what iproute2 does.
 * Note that contrary to IPv6, you can add routes with metric 0 and it is even
 * the default.
 */
#define NM_PLATFORM_ROUTE_METRIC_DEFAULT_IP4 ((guint32) 0u)

/* Default value for adding an IPv6 route. This is also what iproute2 does.
 * Adding an IPv6 route with metric 0, kernel translates to IP6_RT_PRIO_USER (1024).
 *
 * Note that kernel doesn't allow adding IPv6 routes with metric zero via netlink.
 * It however can itself add routes with metric zero. */
#define NM_PLATFORM_ROUTE_METRIC_DEFAULT_IP6 ((guint32) 1024u)

/* For IPv4, kernel adds a device route (subnet routes) with metric 0 when user
 * configures addresses. */
#define NM_PLATFORM_ROUTE_METRIC_IP4_DEVICE_ROUTE ((guint32) 0u)

#define __NMPlatformIPRoute_COMMON                                                        \
    __NMPlatformObjWithIfindex_COMMON;                                                    \
                                                                                          \
    /* rtnh_flags
     *
     * Routes with rtm_flags RTM_F_CLONED are hidden by platform and
     * do not exist from the point-of-view of platform users.
     * Such a route is not alive, according to nmp_object_is_alive().
     *
     * NOTE: currently we ignore all flags except RTM_F_CLONED
     * and RTNH_F_ONLINK.
     * We also may not properly consider the flags as part of the ID
     * in route-cmp. */                                                                         \
    unsigned r_rtm_flags;                                                                 \
                                                                                          \
    /* RTA_METRICS.RTAX_ADVMSS (iproute2: advmss) */                                      \
    guint32 mss;                                                                          \
                                                                                          \
    /* RTA_METRICS.RTAX_WINDOW (iproute2: window) */                                      \
    guint32 window;                                                                       \
                                                                                          \
    /* RTA_METRICS.RTAX_CWND (iproute2: cwnd) */                                          \
    guint32 cwnd;                                                                         \
                                                                                          \
    /* RTA_METRICS.RTAX_INITCWND (iproute2: initcwnd) */                                  \
    guint32 initcwnd;                                                                     \
                                                                                          \
    /* RTA_METRICS.RTAX_INITRWND (iproute2: initrwnd) */                                  \
    guint32 initrwnd;                                                                     \
                                                                                          \
    /* RTA_METRICS.RTAX_RTO_MIN (iproute2: rto_min) */                                    \
    guint32 rto_min;                                                                      \
                                                                                          \
    /* RTA_METRICS.RTAX_MTU (iproute2: mtu) */                                            \
    guint32 mtu;                                                                          \
                                                                                          \
    /* RTA_PRIORITY (iproute2: metric)
     * If "metric_any" is %TRUE, then this is interpreted as an offset that will be
     * added to a default base metric. In such cases, the offset is usually zero. */                                                    \
    guint32 metric;                                                                       \
                                                                                          \
    /* rtm_table, RTA_TABLE.
     *
     * This is not the original table ID. Instead, 254 (RT_TABLE_MAIN) and
     * zero (RT_TABLE_UNSPEC) are swapped, so that the default is the main
     * table. Use nm_platform_route_table_coerce()/nm_platform_route_table_uncoerce(). */                                                              \
    guint32 table_coerced;                                                                \
    /* The NMIPConfigSource. For routes that we receive from cache this corresponds
     * to the rtm_protocol field (and is one of the NM_IP_CONFIG_SOURCE_RTPROT_* values).
     * When adding a route, the source will be coerced to the protocol using
     * nmp_utils_ip_config_source_coerce_to_rtprot().
     *
     * rtm_protocol is part of the primary key of an IPv4 route (meaning, you can add
     * two IPv4 routes that only differ in their rtm_protocol. For IPv6, that is not
     * the case.
     *
     * When deleting an IPv4/IPv6 route, the rtm_protocol field must match (even
     * if it is not part of the primary key for IPv6) -- unless rtm_protocol is set
     * to zero, in which case the first matching route (with proto ignored) is deleted. */       \
    NMIPConfigSource rt_source;                                                           \
                                                                                          \
    /* RTA_METRICS:
     *
     * For IPv4 routes, these properties are part of their
     * ID (meaning: you can add otherwise identical IPv4 routes that
     * only differ by the metric property).
     * On the other hand, for IPv6 you cannot add two IPv6 routes that only differ
     * by an RTA_METRICS property.
     *
     * When deleting a route, kernel seems to ignore the RTA_METRICS properties.
     * That is a problem/bug for IPv4 because you cannot explicitly select which
     * route to delete. Kernel just picks the first. See rh#1475642. */                                                                       \
                                                                                          \
    /* RTA_METRICS.RTAX_LOCK (iproute2: "lock" arguments) */                              \
    bool lock_window : 1;                                                                 \
    bool lock_cwnd : 1;                                                                   \
    bool lock_initcwnd : 1;                                                               \
    bool lock_initrwnd : 1;                                                               \
    bool lock_mtu : 1;                                                                    \
    bool lock_mss : 1;                                                                    \
                                                                                          \
    /* RTA_METRICS.RTAX_QUICKACK (iproute2: quickack) */                                  \
    bool quickack : 1;                                                                    \
                                                                                          \
    /* if TRUE, the "metric" field is interpreted as an offset that is added to a default
     * metric. For example, form a DHCP lease we don't know the actually used metric, because
     * that is determined by upper layers (the configuration). However, we have a default
     * metric that should be used. So we set "metric_any" to %TRUE, which means to use
     * the default metric. However, we still treat the "metric" field as an offset that
     * will be added to the default metric. In most case, you want that "metric" is zero
     * when setting "metric_any". */ \
    bool metric_any : 1;                                                                  \
                                                                                          \
    /* like "metric_any", the table is determined by other layers of the code.
     * This field overrides "table_coerced" field. If "table_any" is true, then
     * the "table_coerced" field is ignored (unlike for the metric). */            \
    bool table_any : 1;                                                                   \
    /* Meta flags not honored by NMPlatform (netlink code). Instead, they can be
     * used by the upper layers which use NMPlatformIPRoute to track routes that
     * should be configured. */          \
    /* Whether the route should be committed even if it was removed externally. */        \
    bool r_force_commit : 1;                                                              \
                                                                                          \
    /* rtm_type.
     *
     * This is not the original type, if type_coerced is 0 then
     * it means RTN_UNSPEC otherwise the type value is preserved.
     */                                                                          \
    guint8 type_coerced;                                                                  \
                                                                                          \
    /* Don't have a bitfield as last field in __NMPlatformIPRoute_COMMON. It would then
     * be unclear how the following fields get merged. We could also use a zero bitfield,
     * but instead we just have there the uint8 field. */   \
    guint8 plen;                                                                          \
    ;

typedef struct {
    __NMPlatformIPRoute_COMMON;
    _nm_alignas(NMIPAddr) guint8 network_ptr[];
} _nm_alignas(NMPlatformObject) NMPlatformIPRoute;

#define NM_PLATFORM_IP_ROUTE_CAST(route) \
    NM_CONSTCAST(NMPlatformIPRoute,      \
                 (route),                \
                 NMPlatformIPXRoute,     \
                 NMPlatformIP4Route,     \
                 NMPlatformIP6Route)

#define NM_PLATFORM_IP_ROUTE_IS_DEFAULT(route) (NM_PLATFORM_IP_ROUTE_CAST(route)->plen <= 0)

struct _NMPlatformIP4Route {
    __NMPlatformIPRoute_COMMON;

    in_addr_t network;

    /* If n_nexthops is zero, the the address has no next hops. That applies
     *    to certain route types like blackhole.
     * If n_nexthops is 1, then the fields "ifindex", "gateway" and "weight"
     *   are the first next-hop. There are no further nexthops.
     * If n_nexthops is greater than 1, the first next hop is in the fields
     *   "ifindex", "gateway", "weight", and the (n_nexthops-1) hops are in
     *   NMPObjectIP4Route.extra_nexthops field (outside the NMPlatformIP4Route
     *   struct).
     *
     * For convenience, if ifindex > 0 and n_nexthops == 0, we assume that n_nexthops
     * is in fact 1. If ifindex is <= 0, n_nexthops must be zero.
     * See nm_platform_ip4_route_get_n_nexthops(). */
    guint n_nexthops;

    /* RTA_GATEWAY. The gateway is part of the primary key for a route.
     * If n_nexthops is zero, this value is undefined (should be zero).
     * If n_nexthops is greater or equal to one, this is the gateway of
     * the first hop. */
    in_addr_t gateway;

    /* RTA_PREFSRC (called "src" by iproute2).
     *
     * pref_src is part of the ID of an IPv4 route. When deleting a route,
     * pref_src must match, unless set to 0.0.0.0 to match any. */
    in_addr_t pref_src;

    /* This is the weight of for the first next-hop, in case of n_nexthops > 1.
     *
     * If n_nexthops is zero, this value is undefined (should be zero).
     * If n_nexthops is 1, this also doesn't matter, but it's usually set to
     * zero.
     * If n_nexthops is greater or equal to one, this is the weight of
     * the first hop.
     *
     * Note that upper layers (nm_utils_ip_route_attribute_to_platform()) use this flag to indicate
     * whether this is a multihop route. Single-hop, non-ECMP routes will have a weight of zero.
     *
     * The valid range for weight in kernel is 1-256. */
    guint16 weight;

    /* rtm_tos (iproute2: tos)
     *
     * For IPv4, tos is part of the weak-id (like metric).
     *
     * For IPv6, tos is ignored by kernel.  */
    guint8 tos;

    /* The bitwise inverse of the route scope rtm_scope. It is inverted so that the
     * default value (RT_SCOPE_NOWHERE) is zero. Use nm_platform_route_scope_inv()
     * to convert back and forth between the inverse representation and the
     * real value.
     *
     * rtm_scope is part of the primary key for IPv4 routes. When deleting a route,
     * the scope must match, unless it is left at RT_SCOPE_NOWHERE, in which case the first
     * matching route is deleted.
     *
     * For IPv6 routes, the scope is ignored and kernel always assumes global scope.
     * Hence, this field is only in NMPlatformIP4Route. */
    guint8 scope_inv;
} _nm_alignas(NMPlatformObject);

struct _NMPlatformIP6Route {
    __NMPlatformIPRoute_COMMON;
    struct in6_addr network;

    /* RTA_GATEWAY. The gateway is part of the primary key for a route */
    struct in6_addr gateway;

    /* RTA_PREFSRC (called "src" by iproute2).
     *
     * pref_src is not part of the ID for an IPv6 route. You cannot add two
     * routes that only differ by pref_src.
     *
     * When deleting a route, pref_src is ignored by kernel. */
    struct in6_addr pref_src;

    /* RTA_SRC and rtm_src_len (called "from" by iproute2).
     *
     * Kernel clears the host part of src/src_plen.
     *
     * src/src_plen is part of the ID of a route just like network/plen. That is,
     * Not only `ip route append`, but also `ip route add` allows to add routes that only
     * differ in their src/src_plen.
     */
    struct in6_addr src;
    guint8          src_plen;

    /* RTA_PREF router preference.
     *
     * The type is guint8 to keep the struct size small. But the values are compatible with
     * the NMIcmpv6RouterPref enum. */
    guint8 rt_pref;
} _nm_alignas(NMPlatformObject);

typedef union {
    NMPlatformIPRoute  rx;
    NMPlatformIP4Route r4;
    NMPlatformIP6Route r6;
} NMPlatformIPXRoute;

#undef __NMPlatformIPRoute_COMMON

#define NM_PLATFORM_IP4_ROUTE_INIT(...) (&((const NMPlatformIP4Route){__VA_ARGS__}))

#define NM_PLATFORM_IP6_ROUTE_INIT(...) (&((const NMPlatformIP6Route){__VA_ARGS__}))

typedef struct {
    /* struct fib_rule_uid_range */
    guint32 start;
    guint32 end;
} NMFibRuleUidRange;

typedef struct {
    /* struct fib_rule_port_range */
    guint16 start;
    guint16 end;
} NMFibRulePortRange;

typedef struct {
    NMIPAddr           src;                        /* FRA_SRC */
    NMIPAddr           dst;                        /* FRA_DST */
    guint64            tun_id;                     /* betoh64(FRA_TUN_ID) */
    guint32            table;                      /* (struct fib_rule_hdr).table, FRA_TABLE */
    guint32            flags;                      /* (struct fib_rule_hdr).flags */
    guint32            priority;                   /* RA_PRIORITY */
    guint32            fwmark;                     /* FRA_FWMARK */
    guint32            fwmask;                     /* FRA_FWMASK */
    guint32            goto_target;                /* FRA_GOTO */
    guint32            flow;                       /* FRA_FLOW */
    guint32            suppress_prefixlen_inverse; /* ~(FRA_SUPPRESS_PREFIXLEN) */
    guint32            suppress_ifgroup_inverse;   /* ~(FRA_SUPPRESS_IFGROUP) */
    NMFibRuleUidRange  uid_range;                  /* FRA_UID_RANGE */
    NMFibRulePortRange sport_range;                /* FRA_SPORT_RANGE */
    NMFibRulePortRange dport_range;                /* FRA_DPORT_RANGE */
    char               iifname[NM_IFNAMSIZ];       /* FRA_IIFNAME */
    char               oifname[NM_IFNAMSIZ];       /* FRA_OIFNAME */
    guint8             addr_family;                /* (struct fib_rule_hdr).family */
    guint8             action;                     /* (struct fib_rule_hdr).action */
    guint8             tos;                        /* (struct fib_rule_hdr).tos */
    guint8             src_len;                    /* (struct fib_rule_hdr).src_len */
    guint8             dst_len;                    /* (struct fib_rule_hdr).dst_len */
    guint8             l3mdev;                     /* FRA_L3MDEV */
    guint8             protocol;                   /* FRA_PROTOCOL */
    guint8             ip_proto;                   /* FRA_IP_PROTO */

    bool uid_range_has : 1; /* has(FRA_UID_RANGE) */
} _nm_alignas(NMPlatformObject) NMPlatformRoutingRule;

#define NM_PLATFORM_FQ_CODEL_MEMORY_LIMIT_UNSET (~((guint32) 0))

#define NM_PLATFORM_FQ_CODEL_CE_THRESHOLD_DISABLED ((guint32) 0x83126E97u)

G_STATIC_ASSERT(((((guint64) NM_PLATFORM_FQ_CODEL_CE_THRESHOLD_DISABLED) * 1000u) >> 10)
                == (guint64) INT_MAX);

typedef struct {
    guint32 limit;
    guint32 flows;
    guint32 target;
    guint32 interval;
    guint32 quantum;

    /* TCA_FQ_CODEL_CE_THRESHOLD: kernel internally stores this value as
     * ((val64 * NSEC_PER_USEC) >> CODEL_SHIFT). The default value (in
     * the domain with this coercion) is CODEL_DISABLED_THRESHOLD (INT_MAX).
     * That means, "disabled" is expressed on RTM_NEWQDISC netlink API by absence of the
     * netlink attribute but also as the special value 0x83126E97u
     * (NM_PLATFORM_FQ_CODEL_CE_THRESHOLD_DISABLED).
     * Beware: zero is not the default you must always explicitly set this value. */
    guint32 ce_threshold;

    /* TCA_FQ_CODEL_MEMORY_LIMIT: note that only values <= 2^31 are accepted by kernel
     * and kernel defaults to 32MB.
     * Note that we use the special value NM_PLATFORM_FQ_CODEL_MEMORY_LIMIT_UNSET
     * to indicate that no explicit limit is set (when we send a RTM_NEWQDISC request).
     * This will cause kernel to choose the default (32MB).
     * Beware: zero is not the default you must always explicitly set this value. */
    guint32 memory_limit;

    bool ecn : 1;
} NMPlatformQdiscFqCodel;

typedef struct {
    unsigned quantum;
    int      perturb_period;
    guint32  limit;
    unsigned divisor;
    unsigned flows;
    unsigned depth;
} NMPlatformQdiscSfq;

typedef struct {
    guint64 rate;
    guint32 burst;
    guint32 limit;
    guint32 latency;
} NMPlatformQdiscTbf;

typedef struct {
    __NMPlatformObjWithIfindex_COMMON;

    /* beware, kind is embedded in an NMPObject, hence you must
     * take care of the lifetime of the string. */
    const char *kind;

    int     addr_family;
    guint32 handle;
    guint32 parent;
    guint32 info;
    union {
        NMPlatformQdiscFqCodel fq_codel;
        NMPlatformQdiscSfq     sfq;
        NMPlatformQdiscTbf     tbf;
    };
} _nm_alignas(NMPlatformObject) NMPlatformQdisc;

typedef struct {
    char sdata[32];
} NMPlatformActionSimple;

typedef struct {
    int  ifindex;
    bool egress : 1;
    bool ingress : 1;
    bool mirror : 1;
    bool redirect : 1;
} NMPlatformActionMirred;

typedef struct {
    /* beware, kind is embedded in an NMPObject, hence you must
     * take care of the lifetime of the string. */
    const char *kind;

    union {
        NMPlatformActionSimple simple;
        NMPlatformActionMirred mirred;
    };
} NMPlatformAction;

#define NM_PLATFORM_ACTION_KIND_SIMPLE "simple"
#define NM_PLATFORM_ACTION_KIND_MIRRED "mirred"

typedef struct {
    __NMPlatformObjWithIfindex_COMMON;

    /* beware, kind is embedded in an NMPObject, hence you must
     * take care of the lifetime of the string. */
    const char *kind;

    int              addr_family;
    guint32          handle;
    guint32          parent;
    guint32          info;
    NMPlatformAction action;
} _nm_alignas(NMPlatformObject) NMPlatformTfilter;

typedef struct {
    bool          is_ip4;
    gint8         addr_family;
    guint8        sizeof_route;
    NMPObjectType obj_type;
    int (*route_cmp)(const NMPlatformIPXRoute *a,
                     const NMPlatformIPXRoute *b,
                     NMPlatformIPRouteCmpType  cmp_type);
    const char *(*route_to_string)(const NMPlatformIPXRoute *route, char *buf, gsize len);
} NMPlatformVTableRoute;

typedef union {
    struct {
        NMPlatformVTableRoute v6;
        NMPlatformVTableRoute v4;
    };
    NMPlatformVTableRoute vx[2];
} _NMPlatformVTableRouteUnion;

extern const _NMPlatformVTableRouteUnion nm_platform_vtable_route;

typedef struct {
    guint16 id;
    guint32 qos;
    bool    proto_ad : 1;
} NMPlatformVFVlan;

typedef struct {
    int       ifindex;
    in_addr_t gateway;
    /* The valid range for weight is 1-256. Single hop routes in kernel
     * don't have a weight, we assign them weight zero (to indicate the
     * weight is missing).
     *
     * Upper layers (nm_utils_ip_route_attribute_to_platform()) care about
     * the distinction of unset weight (no-ECMP). They express no-ECMP as
     * zero.
     */
    guint16 weight;

    /* FIXME: each next hop in kernel also has a rtnh_flags (for example to
     * set RTNH_F_ONLINK). As the next hop is part of the identifier of an
     * IPv4 route, so is their flags. We must also track the flag, otherwise
     * two routes that look different for kernel, get merged by platform cache. */
} NMPlatformIP4RtNextHop;

typedef struct {
    guint             num_vlans;
    guint32           index;
    guint32           min_tx_rate;
    guint32           max_tx_rate;
    NMPlatformVFVlan *vlans;
    struct {
        guint8 data[20]; /* _NM_UTILS_HWADDR_LEN_MAX */
        guint8 len;
    } mac;
    gint8 spoofchk;
    gint8 trust;
} NMPlatformVF;

typedef struct {
    guint16 vid_start;
    guint16 vid_end;
    bool    untagged : 1;
    bool    pvid : 1;
} NMPlatformBridgeVlan;

typedef struct {
    guint16 vlan_default_pvid_val;
    bool    vlan_filtering_val : 1;
    bool    vlan_default_pvid_has : 1;
    bool    vlan_filtering_has : 1;
} NMPlatformLinkSetBridgeInfoData;

typedef struct {
    guint64     mcast_last_member_interval;
    guint64     mcast_membership_interval;
    guint64     mcast_querier_interval;
    guint64     mcast_query_interval;
    guint64     mcast_query_response_interval;
    guint64     mcast_startup_query_interval;
    guint32     ageing_time;
    guint32     forward_delay;
    guint32     hello_time;
    guint32     max_age;
    guint32     mcast_hash_max;
    guint32     mcast_last_member_count;
    guint32     mcast_startup_query_count;
    guint16     group_fwd_mask;
    guint16     priority;
    guint16     vlan_protocol;
    NMEtherAddr group_addr;
    guint8      mcast_router;
    bool        mcast_querier : 1;
    bool        mcast_query_use_ifaddr : 1;
    bool        mcast_snooping : 1;
    bool        stp_state : 1;
    bool        vlan_stats_enabled : 1;
} _nm_alignas(NMPlatformObject) NMPlatformLnkBridge;

extern const NMPlatformLnkBridge nm_platform_lnk_bridge_default;

/* Defined in net/bonding.h. */
#define NM_BOND_MAX_ARP_TARGETS 16

typedef struct {
    struct in6_addr ns_ip6_target[NM_BOND_MAX_ARP_TARGETS];
    int             primary;
    in_addr_t       arp_ip_target[NM_BOND_MAX_ARP_TARGETS];
    guint32         arp_all_targets;
    guint32         arp_interval;
    guint32         arp_validate;
    guint32         downdelay;
    guint32         lp_interval;
    guint32         miimon;
    guint32         min_links;
    guint32         packets_per_port;
    guint32         peer_notif_delay;
    guint32         resend_igmp;
    guint32         updelay;
    guint16         ad_actor_sys_prio;
    guint16         ad_user_port_key;
    NMEtherAddr     ad_actor_system;
    guint8          ad_select;
    guint8          all_ports_active;
    guint8          arp_missed_max;
    guint8          arp_ip_targets_num;
    guint8          fail_over_mac;
    guint8          lacp_active;
    guint8          lacp_rate;
    guint8          ns_ip6_targets_num;
    guint8          num_grat_arp;
    guint8          mode;
    guint8          primary_reselect;
    guint8          xmit_hash_policy;
    bool            downdelay_has : 1;
    bool            lacp_active_has : 1;
    bool            lp_interval_has : 1;
    bool            miimon_has : 1;
    bool            peer_notif_delay_has : 1;
    bool            resend_igmp_has : 1;
    bool            tlb_dynamic_lb : 1;
    bool            tlb_dynamic_lb_has : 1;
    bool            updelay_has : 1;
    bool            use_carrier : 1;
} _nm_alignas(NMPlatformObject) NMPlatformLnkBond;

typedef struct {
    int       parent_ifindex;
    in_addr_t local;
    in_addr_t remote;
    guint32   input_key;
    guint32   output_key;
    guint16   input_flags;
    guint16   output_flags;
    guint8    ttl;
    guint8    tos;
    bool      path_mtu_discovery : 1;
    bool      is_tap : 1;
} _nm_alignas(NMPlatformObject) NMPlatformLnkGre;

typedef struct {
    int         p_key;
    const char *mode;
} _nm_alignas(NMPlatformObject) NMPlatformLnkInfiniband;

typedef struct {
    struct in6_addr local;
    struct in6_addr remote;
    int             parent_ifindex;
    guint           flow_label;
    guint32         flags;
    guint8          ttl;
    guint8          tclass;
    guint8          encap_limit;
    guint8          proto;

    /* IP6GRE only */
    guint32 input_key;
    guint32 output_key;
    guint16 input_flags;
    guint16 output_flags;
    bool    is_tap : 1;
    bool    is_gre : 1;
} _nm_alignas(NMPlatformObject) NMPlatformLnkIp6Tnl;

typedef struct {
    int       parent_ifindex;
    in_addr_t local;
    in_addr_t remote;
    guint8    ttl;
    guint8    tos;
    bool      path_mtu_discovery : 1;
} _nm_alignas(NMPlatformObject) NMPlatformLnkIpIp;

typedef struct {
    int       parent_ifindex;
    in_addr_t local;
    in_addr_t remote;
    guint32   ikey;
    guint32   okey;
    guint32   fwmark;
} _nm_alignas(NMPlatformObject) NMPlatformLnkVti;

typedef struct {
    int             parent_ifindex;
    struct in6_addr local;
    struct in6_addr remote;
    guint32         ikey;
    guint32         okey;
    guint32         fwmark;
} _nm_alignas(NMPlatformObject) NMPlatformLnkVti6;

typedef struct {
    int     parent_ifindex;
    guint64 sci; /* host byte order */
    guint64 cipher_suite;
    guint32 window;
    guint8  icv_length;
    guint8  encoding_sa;
    guint8  validation;
    bool    encrypt : 1;
    bool    protect : 1;
    bool    include_sci : 1;
    bool    es : 1;
    bool    scb : 1;
    bool    replay_protect : 1;
} _nm_alignas(NMPlatformObject) NMPlatformLnkMacsec;

typedef struct {
    guint mode;
    bool  no_promisc : 1;
    bool  tap : 1;
} _nm_alignas(NMPlatformObject) NMPlatformLnkMacvlan;

typedef struct {
    int       parent_ifindex;
    in_addr_t local;
    in_addr_t remote;
    guint16   flags;
    guint8    ttl;
    guint8    tos;
    guint8    proto;
    bool      path_mtu_discovery : 1;
} _nm_alignas(NMPlatformObject) NMPlatformLnkSit;

typedef struct {
    guint32 owner;
    guint32 group;

    guint8 type;

    bool owner_valid : 1;
    bool group_valid : 1;

    bool pi : 1;
    bool vnet_hdr : 1;
    bool multi_queue : 1;
    bool persist : 1;
} _nm_alignas(NMPlatformObject) NMPlatformLnkTun;

typedef struct {
    guint16      id;
    guint16      protocol;
    _NMVlanFlags flags;
} _nm_alignas(NMPlatformObject) NMPlatformLnkVlan;

typedef struct {
    guint32 table;
} _nm_alignas(NMPlatformObject) NMPlatformLnkVrf;

typedef struct {
    struct in6_addr group6;
    struct in6_addr local6;
    int             parent_ifindex;
    in_addr_t       group;
    in_addr_t       local;
    guint32         id;
    guint32         ageing;
    guint32         limit;
    guint16         dst_port;
    guint16         src_port_min;
    guint16         src_port_max;
    guint8          tos;
    guint8          ttl;
    bool            learning : 1;
    bool            proxy : 1;
    bool            rsc : 1;
    bool            l2miss : 1;
    bool            l3miss : 1;
} _nm_alignas(NMPlatformObject) NMPlatformLnkVxlan;

#define NMP_WIREGUARD_PUBLIC_KEY_LEN    32
#define NMP_WIREGUARD_SYMMETRIC_KEY_LEN 32

typedef struct {
    guint32 fwmark;
    guint16 listen_port;
    guint8  private_key[NMP_WIREGUARD_PUBLIC_KEY_LEN];
    guint8  public_key[NMP_WIREGUARD_PUBLIC_KEY_LEN];
} _nm_alignas(NMPlatformObject) NMPlatformLnkWireGuard;

typedef enum {
    NM_PLATFORM_WIREGUARD_CHANGE_FLAG_NONE            = 0,
    NM_PLATFORM_WIREGUARD_CHANGE_FLAG_REPLACE_PEERS   = (1LL << 0),
    NM_PLATFORM_WIREGUARD_CHANGE_FLAG_HAS_PRIVATE_KEY = (1LL << 1),
    NM_PLATFORM_WIREGUARD_CHANGE_FLAG_HAS_LISTEN_PORT = (1LL << 2),
    NM_PLATFORM_WIREGUARD_CHANGE_FLAG_HAS_FWMARK      = (1LL << 3),
} NMPlatformWireGuardChangeFlags;

typedef enum {
    NM_PLATFORM_WIREGUARD_CHANGE_PEER_FLAG_NONE                   = 0,
    NM_PLATFORM_WIREGUARD_CHANGE_PEER_FLAG_REMOVE_ME              = (1LL << 0),
    NM_PLATFORM_WIREGUARD_CHANGE_PEER_FLAG_HAS_PRESHARED_KEY      = (1LL << 1),
    NM_PLATFORM_WIREGUARD_CHANGE_PEER_FLAG_HAS_KEEPALIVE_INTERVAL = (1LL << 2),
    NM_PLATFORM_WIREGUARD_CHANGE_PEER_FLAG_HAS_ENDPOINT           = (1LL << 3),
    NM_PLATFORM_WIREGUARD_CHANGE_PEER_FLAG_HAS_ALLOWEDIPS         = (1LL << 4),
    NM_PLATFORM_WIREGUARD_CHANGE_PEER_FLAG_REPLACE_ALLOWEDIPS     = (1LL << 5),

    NM_PLATFORM_WIREGUARD_CHANGE_PEER_FLAG_DEFAULT =
        NM_PLATFORM_WIREGUARD_CHANGE_PEER_FLAG_HAS_PRESHARED_KEY
        | NM_PLATFORM_WIREGUARD_CHANGE_PEER_FLAG_HAS_KEEPALIVE_INTERVAL
        | NM_PLATFORM_WIREGUARD_CHANGE_PEER_FLAG_HAS_ENDPOINT
        | NM_PLATFORM_WIREGUARD_CHANGE_PEER_FLAG_HAS_ALLOWEDIPS,

} NMPlatformWireGuardChangePeerFlags;

typedef void (*NMPlatformAsyncCallback)(GError *error, gpointer user_data);

typedef struct {
    __NMPlatformObjWithIfindex_COMMON;
    guint32  id;
    guint32  flags;
    guint16  port;
    NMIPAddr addr;
    gint8    addr_family;
} NMPlatformMptcpAddr;

#undef __NMPlatformObjWithIfindex_COMMON

/*****************************************************************************/

typedef struct _NMPlatformCsmeConnInfo {
    guint8      ssid[32];
    guint32     channel;
    NMEtherAddr addr;
    guint8      sta_cipher;
    guint8      auth_mode;
} NMPlatformCsmeConnInfo;

typedef enum {
    NM_PLATFORM_KERNEL_SUPPORT_TYPE_FRA_L3MDEV,
    NM_PLATFORM_KERNEL_SUPPORT_TYPE_FRA_UID_RANGE,
    NM_PLATFORM_KERNEL_SUPPORT_TYPE_FRA_PROTOCOL,
    NM_PLATFORM_KERNEL_SUPPORT_TYPE_IFLA_BR_VLAN_STATS_ENABLED,
    NM_PLATFORM_KERNEL_SUPPORT_TYPE_IFLA_PERM_ADDRESS,

    /* this also includes FRA_SPORT_RANGE and FRA_DPORT_RANGE which
     * were added at the same time. */
    NM_PLATFORM_KERNEL_SUPPORT_TYPE_FRA_IP_PROTO,

    NM_PLATFORM_KERNEL_SUPPORT_TYPE_IFLA_BOND_SLAVE_PRIO,

    _NM_PLATFORM_KERNEL_SUPPORT_NUM,
} NMPlatformKernelSupportType;

extern volatile int _nm_platform_kernel_support_state[_NM_PLATFORM_KERNEL_SUPPORT_NUM];

int _nm_platform_kernel_support_init(NMPlatformKernelSupportType type, int value);

static inline gboolean
_nm_platform_kernel_support_detected(NMPlatformKernelSupportType type)
{
    nm_assert(_NM_INT_NOT_NEGATIVE(type) && type < G_N_ELEMENTS(_nm_platform_kernel_support_state));

    return G_LIKELY(g_atomic_int_get(&_nm_platform_kernel_support_state[type]) != 0);
}

static inline NMOptionBool
nm_platform_kernel_support_get_full(NMPlatformKernelSupportType type, gboolean init_if_not_set)
{
    int v;

    nm_assert(_NM_INT_NOT_NEGATIVE(type) && type < G_N_ELEMENTS(_nm_platform_kernel_support_state));

    v = g_atomic_int_get(&_nm_platform_kernel_support_state[type]);
    if (G_UNLIKELY(v == 0)) {
        if (!init_if_not_set)
            return NM_OPTION_BOOL_DEFAULT;
        v = _nm_platform_kernel_support_init(type, 0);
    }
    return (v >= 0);
}

static inline gboolean
nm_platform_kernel_support_get(NMPlatformKernelSupportType type)
{
    return nm_platform_kernel_support_get_full(type, TRUE) != NM_OPTION_BOOL_FALSE;
}

typedef enum {
    NMP_GENL_FAMILY_TYPE_ETHTOOL,
    NMP_GENL_FAMILY_TYPE_MPTCP_PM,
    NMP_GENL_FAMILY_TYPE_NL80211,
    NMP_GENL_FAMILY_TYPE_NL802154,
    NMP_GENL_FAMILY_TYPE_WIREGUARD,

    _NMP_GENL_FAMILY_TYPE_NUM,
    _NMP_GENL_FAMILY_TYPE_NONE = _NMP_GENL_FAMILY_TYPE_NUM,
} NMPGenlFamilyType;

typedef struct {
    const char *name;
} NMPGenlFamilyInfo;

extern const NMPGenlFamilyInfo nmp_genl_family_infos[_NMP_GENL_FAMILY_TYPE_NUM];

NMPGenlFamilyType nmp_genl_family_type_from_name(const char *name);

/*****************************************************************************/

struct _NMPlatformPrivate;

struct _NMPlatform {
    GObject                    parent;
    NMPNetns                  *_netns;
    struct _NMPlatformPrivate *_priv;
};

typedef struct {
    GObjectClass parent;

    gboolean (*sysctl_set)(NMPlatform *self,
                           const char *pathid,
                           int         dirfd,
                           const char *path,
                           const char *value);
    void (*sysctl_set_async)(NMPlatform             *self,
                             const char             *pathid,
                             int                     dirfd,
                             const char             *path,
                             const char *const      *values,
                             NMPlatformAsyncCallback callback,
                             gpointer                data,
                             GCancellable           *cancellable);
    char *(*sysctl_get)(NMPlatform *self, const char *pathid, int dirfd, const char *path);

    void (*refresh_all)(NMPlatform *self, NMPObjectType obj_type);
    void (*process_events)(NMPlatform *self);

    int (*link_add)(NMPlatform            *self,
                    NMLinkType             type,
                    const char            *name,
                    int                    parent,
                    const void            *address,
                    size_t                 address_len,
                    guint32                mtu,
                    gconstpointer          extra_data,
                    const NMPlatformLink **out_link);
    int (*link_change_extra)(NMPlatform   *self,
                             NMLinkType    type,
                             int           ifindex,
                             gconstpointer extra_data);
    gboolean (*link_change)(NMPlatform                   *self,
                            int                           ifindex,
                            NMPlatformLinkProps          *props,
                            NMPortKind                    port_kind,
                            const NMPlatformLinkPortData *port_data,
                            NMPlatformLinkChangeFlags     flags);
    gboolean (*link_delete)(NMPlatform *self, int ifindex);
    gboolean (*link_refresh)(NMPlatform *self, int ifindex);
    gboolean (*link_set_netns)(NMPlatform *self, int ifindex, int netns_fd);
    int (*link_change_flags)(NMPlatform *platform,
                             int         ifindex,
                             unsigned    flags_mask,
                             unsigned    flags_set);

    int (*link_set_inet6_addr_gen_mode)(NMPlatform *self, int ifindex, guint8 enabled);
    gboolean (*link_set_token)(NMPlatform *self, int ifindex, const NMUtilsIPv6IfaceId *iid);

    gboolean (*link_get_permanent_address_ethtool)(NMPlatform     *self,
                                                   int             ifindex,
                                                   NMPLinkAddress *out_address);
    int (*link_set_address)(NMPlatform *self, int ifindex, gconstpointer address, size_t length);
    int (*link_set_mtu)(NMPlatform *self, int ifindex, guint32 mtu);
    gboolean (*link_set_name)(NMPlatform *self, int ifindex, const char *name);
    void (*link_set_sriov_params_async)(NMPlatform             *self,
                                        int                     ifindex,
                                        guint                   num_vfs,
                                        NMOptionBool            autoprobe,
                                        NMPlatformAsyncCallback callback,
                                        gpointer                callback_data,
                                        GCancellable           *cancellable);
    gboolean (*link_set_sriov_vfs)(NMPlatform *self, int ifindex, const NMPlatformVF *const *vfs);
    gboolean (*link_set_bridge_vlans)(NMPlatform                        *self,
                                      int                                ifindex,
                                      gboolean                           on_master,
                                      const NMPlatformBridgeVlan *const *vlans);
    gboolean (*link_set_bridge_info)(NMPlatform                            *self,
                                     int                                    ifindex,
                                     const NMPlatformLinkSetBridgeInfoData *bridge_info);

    char *(*link_get_physical_port_id)(NMPlatform *self, int ifindex);
    guint (*link_get_dev_id)(NMPlatform *self, int ifindex);
    gboolean (*link_get_wake_on_lan)(NMPlatform *self, int ifindex);
    gboolean (*link_get_driver_info)(NMPlatform *self,
                                     int         ifindex,
                                     char      **out_driver_name,
                                     char      **out_driver_version,
                                     char      **out_fw_version);

    gboolean (*link_supports_carrier_detect)(NMPlatform *self, int ifindex);
    gboolean (*link_supports_vlans)(NMPlatform *self, int ifindex);
    gboolean (*link_supports_sriov)(NMPlatform *self, int ifindex);

    gboolean (*link_enslave)(NMPlatform *self, int master, int slave);
    gboolean (*link_release)(NMPlatform *self, int master, int slave);

    gboolean (*link_can_assume)(NMPlatform *self, int ifindex);

    int (*link_wireguard_change)(NMPlatform                               *self,
                                 int                                       ifindex,
                                 const NMPlatformLnkWireGuard             *lnk_wireguard,
                                 const struct _NMPWireGuardPeer           *peers,
                                 const NMPlatformWireGuardChangePeerFlags *peer_flags,
                                 guint                                     peers_len,
                                 NMPlatformWireGuardChangeFlags            change_flags);

    gboolean (*link_vlan_change)(NMPlatform             *self,
                                 int                     ifindex,
                                 _NMVlanFlags            flags_mask,
                                 _NMVlanFlags            flags_set,
                                 gboolean                ingress_reset_all,
                                 const NMVlanQosMapping *ingress_map,
                                 gsize                   n_ingress_map,
                                 gboolean                egress_reset_all,
                                 const NMVlanQosMapping *egress_map,
                                 gsize                   n_egress_map);

    gboolean (*link_tun_add)(NMPlatform             *self,
                             const char             *name,
                             const NMPlatformLnkTun *props,
                             const NMPlatformLink  **out_link,
                             int                    *out_fd);

    gboolean (*infiniband_partition_add)(NMPlatform            *self,
                                         int                    parent,
                                         int                    p_key,
                                         const NMPlatformLink **out_link);
    gboolean (*infiniband_partition_delete)(NMPlatform *self, int parent, int p_key);

    gboolean (*wifi_get_capabilities)(NMPlatform                *self,
                                      int                        ifindex,
                                      _NMDeviceWifiCapabilities *caps);
    gboolean (*wifi_get_station)(NMPlatform  *self,
                                 int          ifindex,
                                 NMEtherAddr *out_bssid,
                                 int         *out_quality,
                                 guint32     *out_rate);
    gboolean (*wifi_get_bssid)(NMPlatform *self, int ifindex, guint8 *bssid);
    guint32 (*wifi_get_frequency)(NMPlatform *self, int ifindex);
    int (*wifi_get_quality)(NMPlatform *self, int ifindex);
    guint32 (*wifi_get_rate)(NMPlatform *self, int ifindex);
    _NM80211Mode (*wifi_get_mode)(NMPlatform *self, int ifindex);
    void (*wifi_set_mode)(NMPlatform *self, int ifindex, _NM80211Mode mode);
    void (*wifi_set_powersave)(NMPlatform *self, int ifindex, guint32 powersave);
    guint32 (*wifi_find_frequency)(NMPlatform    *self,
                                   int            ifindex,
                                   const guint32 *freqs,
                                   gboolean       ap);
    void (*wifi_indicate_addressing_running)(NMPlatform *self, int ifindex, gboolean running);
    _NMSettingWirelessWakeOnWLan (*wifi_get_wake_on_wlan)(NMPlatform *self, int ifindex);
    gboolean (*wifi_set_wake_on_wlan)(NMPlatform                  *self,
                                      int                          ifindex,
                                      _NMSettingWirelessWakeOnWLan wowl);
    gboolean (*wifi_get_csme_conn_info)(NMPlatform             *self,
                                        int                     ifindex,
                                        NMPlatformCsmeConnInfo *out_conn_info);
    gboolean (*wifi_get_device_from_csme)(NMPlatform *self, int ifindex);

    guint32 (*mesh_get_channel)(NMPlatform *self, int ifindex);
    gboolean (*mesh_set_channel)(NMPlatform *self, int ifindex, guint32 channel);
    gboolean (*mesh_set_ssid)(NMPlatform *self, int ifindex, const guint8 *ssid, gsize len);

    guint16 (*wpan_get_pan_id)(NMPlatform *self, int ifindex);
    gboolean (*wpan_set_pan_id)(NMPlatform *self, int ifindex, guint16 pan_id);
    guint16 (*wpan_get_short_addr)(NMPlatform *self, int ifindex);
    gboolean (*wpan_set_short_addr)(NMPlatform *self, int ifindex, guint16 short_addr);
    gboolean (*wpan_set_channel)(NMPlatform *self, int ifindex, guint8 page, guint8 channel);

    gboolean (*object_delete)(NMPlatform *self, const NMPObject *obj);

    gboolean (*ip4_address_add)(NMPlatform *self,
                                int         ifindex,
                                in_addr_t   address,
                                guint8      plen,
                                in_addr_t   peer_address,
                                in_addr_t   broadcast_address,
                                guint32     lifetime,
                                guint32     preferred_lft,
                                guint32     flags,
                                const char *label,
                                char      **out_extack_msg);
    gboolean (*ip6_address_add)(NMPlatform     *self,
                                int             ifindex,
                                struct in6_addr address,
                                guint8          plen,
                                struct in6_addr peer_address,
                                guint32         lifetime,
                                guint32         preferred_lft,
                                guint32         flags,
                                char          **out_extack_msg);
    gboolean (*ip4_address_delete)(NMPlatform *self,
                                   int         ifindex,
                                   in_addr_t   address,
                                   guint8      plen,
                                   in_addr_t   peer_address);
    gboolean (*ip6_address_delete)(NMPlatform     *self,
                                   int             ifindex,
                                   struct in6_addr address,
                                   guint8          plen);

    int (*ip_route_add)(NMPlatform *self,
                        NMPNlmFlags flags,
                        NMPObject  *obj_stack,
                        char      **out_extack_msg);

    int (*ip_route_get)(NMPlatform   *self,
                        int           addr_family,
                        gconstpointer address,
                        int           oif_ifindex,
                        NMPObject   **out_route);

    int (*routing_rule_add)(NMPlatform                  *self,
                            NMPNlmFlags                  flags,
                            const NMPlatformRoutingRule *routing_rule);

    int (*qdisc_add)(NMPlatform *self, NMPNlmFlags flags, const NMPlatformQdisc *qdisc);
    int (*qdisc_delete)(NMPlatform *self, int ifindex, guint32 parent, gboolean log_error);

    int (*tfilter_add)(NMPlatform *self, NMPNlmFlags flags, const NMPlatformTfilter *tfilter);
    int (*tfilter_delete)(NMPlatform *self, int ifindex, guint32 parent, gboolean log_error);

    guint16 (*genl_get_family_id)(NMPlatform *platform, NMPGenlFamilyType family_type);

    int (*mptcp_addr_update)(NMPlatform *self, NMOptionBool add, const NMPlatformMptcpAddr *addr);

    GPtrArray *(*mptcp_addrs_dump)(NMPlatform *self);

} NMPlatformClass;

/* NMPlatform signals
 *
 * Each signal handler is called with a type-specific object that provides
 * key attributes that constitute identity of the object. They may also
 * provide additional attributes for convenience.
 *
 * The object only intended to be used by the signal handler to determine
 * the current values. It is no longer valid after the signal handler exits
 * but you are free to copy the provided information and use it for later
 * reference.
 */
#define NM_PLATFORM_SIGNAL_LINK_CHANGED         "link-changed"
#define NM_PLATFORM_SIGNAL_IP4_ADDRESS_CHANGED  "ip4-address-changed"
#define NM_PLATFORM_SIGNAL_IP6_ADDRESS_CHANGED  "ip6-address-changed"
#define NM_PLATFORM_SIGNAL_IP4_ROUTE_CHANGED    "ip4-route-changed"
#define NM_PLATFORM_SIGNAL_IP6_ROUTE_CHANGED    "ip6-route-changed"
#define NM_PLATFORM_SIGNAL_ROUTING_RULE_CHANGED "routing-rule-changed"
#define NM_PLATFORM_SIGNAL_QDISC_CHANGED        "qdisc-changed"
#define NM_PLATFORM_SIGNAL_TFILTER_CHANGED      "tfilter-changed"

const char *nm_platform_signal_change_type_to_string(NMPlatformSignalChangeType change_type);

/*****************************************************************************/

GType nm_platform_get_type(void);

/*****************************************************************************/

/**
 * nm_platform_route_table_coerce:
 * @table: the route table, in its original value as received
 *   from rtm_table/RTA_TABLE.
 *
 * Returns: returns the coerced table id, that can be stored in
 *   NMPlatformIPRoute.table_coerced.
 */
static inline guint32
nm_platform_route_table_coerce(guint32 table)
{
    /* For kernel, the default table is RT_TABLE_MAIN (254).
     * We want that in NMPlatformIPRoute.table_coerced a numeric
     * zero is the default. Hence, @table_coerced swaps the
     * value 0 and 254. Use nm_platform_route_table_coerce()
     * and nm_platform_route_table_uncoerce() to convert between
     * the two domains. */
    switch (table) {
    case 0 /* RT_TABLE_UNSPEC */:
        return 254;
    case 254 /* RT_TABLE_MAIN */:
        return 0;
    default:
        return table;
    }
}

/**
 * nm_platform_route_table_uncoerce:
 * @table_coerced: the route table, in its coerced value
 * @normalize: whether to normalize RT_TABLE_UNSPEC to
 *   RT_TABLE_MAIN. For kernel, routes with a table id
 *   RT_TABLE_UNSPEC do not exist and are treated like
 *   RT_TABLE_MAIN.
 *
 * Returns: reverts the coerced table ID in NMPlatformIPRoute.table_coerced
 *   to the original value as kernel understands it.
 */
static inline guint32
nm_platform_route_table_uncoerce(guint32 table_coerced, gboolean normalize)
{
    /* this undoes nm_platform_route_table_coerce().  */
    switch (table_coerced) {
    case 0 /* RT_TABLE_UNSPEC */:
        return 254;
    case 254 /* RT_TABLE_MAIN */:
        return normalize ? 254 : 0;
    default:
        return table_coerced;
    }
}

static inline gboolean
nm_platform_route_table_is_main(guint32 table)
{
    /* same as
     *   nm_platform_route_table_uncoerce (table, TRUE) == RT_TABLE_MAIN
     * and
     *   nm_platform_route_table_uncoerce (nm_platform_route_table_coerce (table), TRUE) == RT_TABLE_MAIN
     *
     * That is, the function operates the same on @table and its coerced
     * form.
     */
    return table == 0 || table == 254;
}

/**
 * nm_platform_route_scope_inv:
 * @scope: the route scope, either its original value, or its inverse.
 *
 * This function is useful, because the constants such as RT_SCOPE_NOWHERE
 * are 'int', so ~scope also gives an 'int'. This function gets the type
 * casts to guint8 right.
 *
 * Returns: the bitwise inverse of the route scope.
 * */
#define nm_platform_route_scope_inv _nm_platform_uint8_inv
static inline guint8
_nm_platform_uint8_inv(guint8 scope)
{
    return (guint8) ~scope;
}

static inline int
_nm_platform_link_get_inet6_addr_gen_mode(const NMPlatformLink *pllink)
{
    if (!pllink)
        return -ENODEV;
    return _nm_platform_uint8_inv(pllink->inet6_addr_gen_mode_inv);
}

static inline gboolean
nm_platform_route_type_is_nodev(guint8 type)
{
    return NM_IN_SET(type,
                     6 /* RTN_BLACKHOLE */,
                     7 /* RTN_UNREACHABLE */,
                     8 /* RTN_PROHIBIT */,
                     9 /* RTN_THROW */);
}

/**
 * nm_platform_route_type_coerce:
 * @table: the route type, in its original value.
 *
 * Returns: returns the coerced type, that can be stored in
 *   NMPlatformIPRoute.type_coerced.
 */
static inline guint8
nm_platform_route_type_coerce(guint8 type)
{
    switch (type) {
    case 0 /* RTN_UNSPEC */:
        return 1;
    case 1 /* RTN_UNICAST */:
        return 0;
    default:
        return type;
    }
}

/**
 * nm_platform_route_type_uncoerce:
 * @table: the type table, in its coerced value
 *
 * Returns: reverts the coerced type in NMPlatformIPRoute.type_coerced
 *   to the original value as kernel understands it.
 */
static inline guint8
nm_platform_route_type_uncoerce(guint8 type_coerced)
{
    return nm_platform_route_type_coerce(type_coerced);
}

static inline guint8
nm_platform_ip4_address_get_scope(in_addr_t addr)
{
    /* For IPv4 addresses, we can set any scope we want (for any address).
     * However, there are scopes that make sense based on the address,
     * so choose those. */
    return nm_ip4_addr_is_loopback(addr)     ? (254 /* RT_SCOPE_HOST */)
           : nm_ip4_addr_is_link_local(addr) ? (253 /* RT_SCOPE_LINK */)
                                             : (0 /* RT_SCOPE_UNIVERSE */);
}

static inline guint8
nm_platform_ip6_address_get_scope(const struct in6_addr *addr)
{
    /* For IPv6, kernel does not allow userspace to configure the address scope.
     * Instead, it is calculated based on the address. See rt_scope() and
     * ipv6_addr_scope(). We do the same here. */
    return IN6_IS_ADDR_LOOPBACK(addr)    ? (254 /* RT_SCOPE_HOST */)
           : IN6_IS_ADDR_LINKLOCAL(addr) ? (253 /* RT_SCOPE_LINK */)
           : IN6_IS_ADDR_SITELOCAL(addr) ? (200 /* RT_SCOPE_SITE */)
                                         : (0 /* RT_SCOPE_UNIVERSE */);
}

static inline guint8
nm_platform_ip_address_get_scope(int addr_family, gconstpointer addr)
{
    /* Note that this function returns the scope as we configure
     * it in kernel (for IPv4) or as kernel chooses it (for IPv6).
     *
     * That means, rfc1918 private addresses nm_ip_addr_is_site_local() are
     * considered RT_SCOPE_UNIVERSE.
     *
     * Also, the deprecated IN6_IS_ADDR_SITELOCAL() addresses (fec0::/10)
     * are considered RT_SCOPE_SITE, while unique local addresses (ULA, fc00::/7)
     * are considered RT_SCOPE_UNIVERSE.
     *
     * You may not want to use this function when reasoning about
     * site-local addresses (RFC1918, ULA). */
    if (NM_IS_IPv4(addr_family))
        return nm_platform_ip4_address_get_scope(*((in_addr_t *) addr));
    return nm_platform_ip6_address_get_scope(addr);
}

gboolean nm_platform_get_use_udev(NMPlatform *self);
gboolean nm_platform_get_log_with_ptr(NMPlatform *self);
gboolean nm_platform_get_cache_tc(NMPlatform *self);

NMPNetns *nm_platform_netns_get(NMPlatform *self);
gboolean  nm_platform_netns_push(NMPlatform *self, NMPNetns **netns);

const char *nm_link_type_to_string(NMLinkType link_type);

#define NMP_SYSCTL_PATHID_ABSOLUTE(path) ((const char *) NULL), -1, (path)

/* Uses alloca(). Use with care.
 *
 * Like NMP_SYSCTL_PATHID_NETDIR_A(), but "path" must not be a string literal.
 * This is the "UNSAFE" part, where there is no compile time check for the
 * maximum string length. It still must be reasonably short to not overflow
 * the stack (the runtime assert checks for <200 chars). */
#define NMP_SYSCTL_PATHID_NETDIR_UNSAFE_A(dirfd, ifname, path)                     \
    nm_sprintf_buf_unsafe_a(NM_STRLEN("net:/sys/class/net//\0") + NM_IFNAMSIZ + ({ \
                                const gsize _l = strlen(path);                     \
                                                                                   \
                                nm_assert(_l < 200);                               \
                                _l;                                                \
                            }),                                                    \
                            "net:/sys/class/net/%s/%s",                            \
                            (ifname),                                              \
                            (path)),                                               \
        (dirfd), (path)

/* Uses alloca(). Use with care. */
#define NMP_SYSCTL_PATHID_NETDIR_A(dirfd, ifname, path)                         \
    nm_sprintf_bufa(NM_STRLEN("net:/sys/class/net//" path "/\0") + NM_IFNAMSIZ, \
                    "net:/sys/class/net/%s/%s",                                 \
                    (ifname),                                                   \
                    path),                                                      \
        (dirfd), ("" path "")

int      nm_platform_sysctl_open_netdir(NMPlatform *self, int ifindex, char *out_ifname);
gboolean nm_platform_sysctl_set(NMPlatform *self,
                                const char *pathid,
                                int         dirfd,
                                const char *path,
                                const char *value);
void     nm_platform_sysctl_set_async(NMPlatform             *self,
                                      const char             *pathid,
                                      int                     dirfd,
                                      const char             *path,
                                      const char *const      *values,
                                      NMPlatformAsyncCallback callback,
                                      gpointer                data,
                                      GCancellable           *cancellable);
char    *nm_platform_sysctl_get(NMPlatform *self, const char *pathid, int dirfd, const char *path);
gint32   nm_platform_sysctl_get_int32(NMPlatform *self,
                                      const char *pathid,
                                      int         dirfd,
                                      const char *path,
                                      gint32      fallback);
gint64   nm_platform_sysctl_get_int_checked(NMPlatform *self,
                                            const char *pathid,
                                            int         dirfd,
                                            const char *path,
                                            guint       base,
                                            gint64      min,
                                            gint64      max,
                                            gint64      fallback);

char *nm_platform_sysctl_ip_conf_get(NMPlatform *self,
                                     int         addr_family,
                                     const char *ifname,
                                     const char *property);

gint64 nm_platform_sysctl_ip_conf_get_int_checked(NMPlatform *self,
                                                  int         addr_family,
                                                  const char *ifname,
                                                  const char *property,
                                                  guint       base,
                                                  gint64      min,
                                                  gint64      max,
                                                  gint64      fallback);

gboolean nm_platform_sysctl_ip_conf_set(NMPlatform *self,
                                        int         addr_family,
                                        const char *ifname,
                                        const char *property,
                                        const char *value);

gboolean nm_platform_sysctl_ip_conf_set_int64(NMPlatform *self,
                                              int         addr_family,
                                              const char *ifname,
                                              const char *property,
                                              gint64      value);

gboolean
nm_platform_sysctl_ip_conf_set_ipv6_hop_limit_safe(NMPlatform *self, const char *iface, int value);
gboolean nm_platform_sysctl_ip_neigh_set_ipv6_reachable_time(NMPlatform *self,
                                                             const char *iface,
                                                             guint       value_ms);
gboolean nm_platform_sysctl_ip_neigh_set_ipv6_retrans_time(NMPlatform *self,
                                                           const char *iface,
                                                           guint       value_ms);
int      nm_platform_sysctl_ip_conf_get_rp_filter_ipv4(NMPlatform *platform,
                                                       const char *iface,
                                                       gboolean    consider_all,
                                                       gboolean   *out_due_to_all);

const char *nm_platform_if_indextoname(NMPlatform *self,
                                       int         ifindex,
                                       char        out_ifname[static 16 /* IFNAMSIZ */]);
int         nm_platform_if_nametoindex(NMPlatform *self, const char *ifname);

const NMPObject *nm_platform_link_get_obj(NMPlatform *self, int ifindex, gboolean visible_only);
const NMPlatformLink *nm_platform_link_get(NMPlatform *self, int ifindex);
const NMPlatformLink *nm_platform_link_get_by_ifname(NMPlatform *self, const char *ifname);
const NMPlatformLink *nm_platform_link_get_by_address(NMPlatform   *self,
                                                      NMLinkType    link_type,
                                                      gconstpointer address,
                                                      size_t        length);

GPtrArray *nm_platform_link_get_all(NMPlatform *self, gboolean sort_by_name);

int nm_platform_link_add(NMPlatform            *self,
                         NMLinkType             type,
                         const char            *name,
                         int                    parent,
                         const void            *address,
                         size_t                 address_len,
                         guint32                mtu,
                         gconstpointer          extra_data,
                         const NMPlatformLink **out_link);

int nm_platform_link_change_extra(NMPlatform   *self,
                                  NMLinkType    type,
                                  int           ifindex,
                                  gconstpointer extra_data);

static inline int
nm_platform_link_veth_add(NMPlatform            *self,
                          const char            *name,
                          const char            *peer,
                          const NMPlatformLink **out_link)
{
    return nm_platform_link_add(self, NM_LINK_TYPE_VETH, name, 0, NULL, 0, 0, peer, out_link);
}

static inline int
nm_platform_link_dummy_add(NMPlatform *self, const char *name, const NMPlatformLink **out_link)
{
    return nm_platform_link_add(self, NM_LINK_TYPE_DUMMY, name, 0, NULL, 0, 0, NULL, out_link);
}

static inline int
nm_platform_link_bridge_add(NMPlatform                *self,
                            const char                *name,
                            const void                *address,
                            size_t                     address_len,
                            guint32                    mtu,
                            const NMPlatformLnkBridge *props,
                            const NMPlatformLink     **out_link)
{
    return nm_platform_link_add(self,
                                NM_LINK_TYPE_BRIDGE,
                                name,
                                0,
                                address,
                                address_len,
                                mtu,
                                props,
                                out_link);
}

static inline int
nm_platform_link_bridge_change(NMPlatform *self, int ifindex, const NMPlatformLnkBridge *props)
{
    return nm_platform_link_change_extra(self, NM_LINK_TYPE_BRIDGE, ifindex, props);
}

static inline int
nm_platform_link_bond_change(NMPlatform *self, int ifindex, const NMPlatformLnkBond *props)
{
    return nm_platform_link_change_extra(self, NM_LINK_TYPE_BOND, ifindex, props);
}

static inline int
nm_platform_link_bond_add(NMPlatform              *self,
                          const char              *name,
                          const NMPlatformLnkBond *props,
                          const NMPlatformLink   **out_link)
{
    return nm_platform_link_add(self, NM_LINK_TYPE_BOND, name, 0, NULL, 0, 0, props, out_link);
}

static inline int
nm_platform_link_team_add(NMPlatform *self, const char *name, const NMPlatformLink **out_link)
{
    return nm_platform_link_add(self, NM_LINK_TYPE_TEAM, name, 0, NULL, 0, 0, NULL, out_link);
}

static inline int
nm_platform_link_wireguard_add(NMPlatform *self, const char *name, const NMPlatformLink **out_link)
{
    return nm_platform_link_add(self, NM_LINK_TYPE_WIREGUARD, name, 0, NULL, 0, 0, NULL, out_link);
}

static inline int
nm_platform_link_gre_add(NMPlatform             *self,
                         const char             *name,
                         const void             *address,
                         size_t                  address_len,
                         const NMPlatformLnkGre *props,
                         const NMPlatformLink  **out_link)
{
    g_return_val_if_fail(props, -NME_BUG);

    return nm_platform_link_add(self,
                                props->is_tap ? NM_LINK_TYPE_GRETAP : NM_LINK_TYPE_GRE,
                                name,
                                0,
                                address,
                                address_len,
                                0,
                                props,
                                out_link);
}

static inline int
nm_platform_link_sit_add(NMPlatform             *self,
                         const char             *name,
                         const NMPlatformLnkSit *props,
                         const NMPlatformLink  **out_link)
{
    return nm_platform_link_add(self, NM_LINK_TYPE_SIT, name, 0, NULL, 0, 0, props, out_link);
}

static inline int
nm_platform_link_vlan_add(NMPlatform              *self,
                          const char              *name,
                          int                      parent,
                          const NMPlatformLnkVlan *props,
                          const NMPlatformLink   **out_link)
{
    return nm_platform_link_add(self, NM_LINK_TYPE_VLAN, name, parent, NULL, 0, 0, props, out_link);
}

static inline int
nm_platform_link_vrf_add(NMPlatform             *self,
                         const char             *name,
                         const NMPlatformLnkVrf *props,
                         const NMPlatformLink  **out_link)
{
    return nm_platform_link_add(self, NM_LINK_TYPE_VRF, name, 0, NULL, 0, 0, props, out_link);
}

static inline int
nm_platform_link_vti_add(NMPlatform             *self,
                         const char             *name,
                         const NMPlatformLnkVti *props,
                         const NMPlatformLink  **out_link)
{
    return nm_platform_link_add(self, NM_LINK_TYPE_VTI, name, 0, NULL, 0, 0, props, out_link);
}

static inline int
nm_platform_link_vti6_add(NMPlatform              *self,
                          const char              *name,
                          const NMPlatformLnkVti6 *props,
                          const NMPlatformLink   **out_link)
{
    return nm_platform_link_add(self, NM_LINK_TYPE_VTI6, name, 0, NULL, 0, 0, props, out_link);
}

static inline int
nm_platform_link_vxlan_add(NMPlatform               *self,
                           const char               *name,
                           const NMPlatformLnkVxlan *props,
                           const NMPlatformLink    **out_link)
{
    return nm_platform_link_add(self, NM_LINK_TYPE_VXLAN, name, 0, NULL, 0, 0, props, out_link);
}

static inline int
nm_platform_link_6lowpan_add(NMPlatform            *self,
                             const char            *name,
                             int                    parent,
                             const NMPlatformLink **out_link)
{
    return nm_platform_link_add(self,
                                NM_LINK_TYPE_6LOWPAN,
                                name,
                                parent,
                                NULL,
                                0,
                                0,
                                NULL,
                                out_link);
}

static inline int
nm_platform_link_ip6tnl_add(NMPlatform                *self,
                            const char                *name,
                            const NMPlatformLnkIp6Tnl *props,
                            const NMPlatformLink     **out_link)
{
    g_return_val_if_fail(props, -NME_BUG);
    g_return_val_if_fail(!props->is_gre, -NME_BUG);

    return nm_platform_link_add(self, NM_LINK_TYPE_IP6TNL, name, 0, NULL, 0, 0, props, out_link);
}

static inline int
nm_platform_link_ip6gre_add(NMPlatform                *self,
                            const char                *name,
                            const void                *address,
                            size_t                     address_len,
                            const NMPlatformLnkIp6Tnl *props,
                            const NMPlatformLink     **out_link)
{
    g_return_val_if_fail(props, -NME_BUG);
    g_return_val_if_fail(props->is_gre, -NME_BUG);

    return nm_platform_link_add(self,
                                props->is_tap ? NM_LINK_TYPE_IP6GRETAP : NM_LINK_TYPE_IP6GRE,
                                name,
                                0,
                                address,
                                address_len,
                                0,
                                props,
                                out_link);
}

static inline int
nm_platform_link_ipip_add(NMPlatform              *self,
                          const char              *name,
                          const NMPlatformLnkIpIp *props,
                          const NMPlatformLink   **out_link)
{
    g_return_val_if_fail(props, -NME_BUG);

    return nm_platform_link_add(self, NM_LINK_TYPE_IPIP, name, 0, NULL, 0, 0, props, out_link);
}

static inline int
nm_platform_link_macsec_add(NMPlatform                *self,
                            const char                *name,
                            int                        parent,
                            const NMPlatformLnkMacsec *props,
                            const NMPlatformLink     **out_link)
{
    g_return_val_if_fail(props, -NME_BUG);
    g_return_val_if_fail(parent > 0, -NME_BUG);

    return nm_platform_link_add(self,
                                NM_LINK_TYPE_MACSEC,
                                name,
                                parent,
                                NULL,
                                0,
                                0,
                                props,
                                out_link);
}

static inline int
nm_platform_link_macvlan_add(NMPlatform                 *self,
                             const char                 *name,
                             int                         parent,
                             const NMPlatformLnkMacvlan *props,
                             const NMPlatformLink      **out_link)
{
    g_return_val_if_fail(props, -NME_BUG);
    g_return_val_if_fail(parent > 0, -NME_BUG);

    return nm_platform_link_add(self,
                                props->tap ? NM_LINK_TYPE_MACVTAP : NM_LINK_TYPE_MACVLAN,
                                name,
                                parent,
                                NULL,
                                0,
                                0,
                                props,
                                out_link);
}

gboolean nm_platform_link_delete(NMPlatform *self, int ifindex);

gboolean nm_platform_link_set_netns(NMPlatform *self, int ifindex, int netns_fd);

struct _NMDedupMultiHeadEntry;
struct _NMPLookup;
const struct _NMDedupMultiHeadEntry *nm_platform_lookup(NMPlatform              *self,
                                                        const struct _NMPLookup *lookup);

#define nm_platform_iter_obj_for_each(iter, self, lookup, obj)                   \
    for (nm_dedup_multi_iter_init((iter), nm_platform_lookup((self), (lookup))); \
         nm_platform_dedup_multi_iter_next_obj((iter), (obj), NMP_OBJECT_TYPE_UNKNOWN);)

gboolean nm_platform_lookup_predicate_routes_main(const NMPObject *obj, gpointer user_data);
gboolean nm_platform_lookup_predicate_routes_main_skip_rtprot_kernel(const NMPObject *obj,
                                                                     gpointer         user_data);

GPtrArray *nm_platform_lookup_clone(NMPlatform              *self,
                                    const struct _NMPLookup *lookup,
                                    NMPObjectPredicateFunc   predicate,
                                    gpointer                 user_data);

/* convenience methods to lookup the link and access fields of NMPlatformLink. */
int         nm_platform_link_get_ifindex(NMPlatform *self, const char *name);
const char *nm_platform_link_get_name(NMPlatform *self, int ifindex);
NMLinkType  nm_platform_link_get_type(NMPlatform *self, int ifindex);
gboolean    nm_platform_link_is_software(NMPlatform *self, int ifindex);
int         nm_platform_link_get_ifi_flags(NMPlatform *self, int ifindex, guint requested_flags);
gboolean    nm_platform_link_is_up(NMPlatform *self, int ifindex);
gboolean    nm_platform_link_is_connected(NMPlatform *self, int ifindex);
gboolean    nm_platform_link_uses_arp(NMPlatform *self, int ifindex);
guint32     nm_platform_link_get_mtu(NMPlatform *self, int ifindex);
int         nm_platform_link_get_inet6_addr_gen_mode(NMPlatform *self, int ifindex);

gconstpointer nm_platform_link_get_address(NMPlatform *self, int ifindex, size_t *length);

int nm_platform_link_get_master(NMPlatform *self, int slave);

gboolean nm_platform_link_can_assume(NMPlatform *self, int ifindex);

gboolean    nm_platform_link_get_unmanaged(NMPlatform *self, int ifindex, gboolean *unmanaged);
gboolean    nm_platform_link_supports_slaves(NMPlatform *self, int ifindex);
const char *nm_platform_link_get_type_name(NMPlatform *self, int ifindex);

gboolean nm_platform_link_refresh(NMPlatform *self, int ifindex);
void     nm_platform_process_events(NMPlatform *self);

const NMPlatformLink *
nm_platform_process_events_ensure_link(NMPlatform *self, int ifindex, const char *ifname);

int nm_platform_link_change_flags_full(NMPlatform *self,
                                       int         ifindex,
                                       unsigned    flags_mask,
                                       unsigned    flags_set);

/**
 * nm_platform_link_change_flags:
 * @self: platform instance
 * @ifindex: interface index
 * @value: flag to be set
 * @set: value to be set
 *
 * Change the interface flag to the value set.
 *
 * Returns: nm-errno code.
 *
 */
static inline int
nm_platform_link_change_flags(NMPlatform *self, int ifindex, unsigned value, gboolean set)
{
    return nm_platform_link_change_flags_full(self, ifindex, value, set ? value : 0u);
}

gboolean nm_platform_link_change(NMPlatform               *self,
                                 int                       ifindex,
                                 NMPlatformLinkProps      *props,
                                 NMPlatformLinkBondPort   *bond_port,
                                 NMPlatformLinkChangeFlags flags);

gboolean    nm_platform_link_get_udev_property(NMPlatform  *self,
                                               int          ifindex,
                                               const char  *name,
                                               const char **out_value);
const char *nm_platform_link_get_udi(NMPlatform *self, int ifindex);
const char *nm_platform_link_get_path(NMPlatform *self, int ifindex);

struct udev_device *nm_platform_link_get_udev_device(NMPlatform *self, int ifindex);

int nm_platform_link_set_inet6_addr_gen_mode(NMPlatform *self, int ifindex, guint8 mode);
gboolean
nm_platform_link_set_ipv6_token(NMPlatform *self, int ifindex, const NMUtilsIPv6IfaceId *iid);

gboolean nm_platform_link_get_permanent_address_ethtool(NMPlatform     *self,
                                                        int             ifindex,
                                                        NMPLinkAddress *out_address);
gboolean nm_platform_link_get_permanent_address(NMPlatform           *self,
                                                const NMPlatformLink *plink,
                                                NMPLinkAddress       *out_address);
int nm_platform_link_set_address(NMPlatform *self, int ifindex, const void *address, size_t length);
int nm_platform_link_set_mtu(NMPlatform *self, int ifindex, guint32 mtu);
gboolean nm_platform_link_set_name(NMPlatform *self, int ifindex, const char *name);

void nm_platform_link_set_sriov_params_async(NMPlatform             *self,
                                             int                     ifindex,
                                             guint                   num_vfs,
                                             NMOptionBool            autoprobe,
                                             NMPlatformAsyncCallback callback,
                                             gpointer                callback_data,
                                             GCancellable           *cancellable);

gboolean
nm_platform_link_set_sriov_vfs(NMPlatform *self, int ifindex, const NMPlatformVF *const *vfs);
gboolean nm_platform_link_set_bridge_vlans(NMPlatform                        *self,
                                           int                                ifindex,
                                           gboolean                           on_master,
                                           const NMPlatformBridgeVlan *const *vlans);
gboolean nm_platform_link_set_bridge_info(NMPlatform                            *self,
                                          int                                    ifindex,
                                          const NMPlatformLinkSetBridgeInfoData *bridge_info);

char    *nm_platform_link_get_physical_port_id(NMPlatform *self, int ifindex);
guint    nm_platform_link_get_dev_id(NMPlatform *self, int ifindex);
gboolean nm_platform_link_get_wake_on_lan(NMPlatform *self, int ifindex);
gboolean nm_platform_link_get_driver_info(NMPlatform *self,
                                          int         ifindex,
                                          char      **out_driver_name,
                                          char      **out_driver_version,
                                          char      **out_fw_version);

gboolean nm_platform_link_supports_carrier_detect(NMPlatform *self, int ifindex);
gboolean nm_platform_link_supports_vlans(NMPlatform *self, int ifindex);
gboolean nm_platform_link_supports_sriov(NMPlatform *self, int ifindex);

gboolean nm_platform_link_enslave(NMPlatform *self, int master, int slave);
gboolean nm_platform_link_release(NMPlatform *self, int master, int slave);

gboolean nm_platform_sysctl_master_set_option(NMPlatform *self,
                                              int         ifindex,
                                              const char *option,
                                              const char *value);
char    *nm_platform_sysctl_master_get_option(NMPlatform *self, int ifindex, const char *option);
gboolean nm_platform_sysctl_slave_set_option(NMPlatform *self,
                                             int         ifindex,
                                             const char *option,
                                             const char *value);
char    *nm_platform_sysctl_slave_get_option(NMPlatform *self, int ifindex, const char *option);

const NMPObject *nm_platform_link_get_lnk(NMPlatform            *self,
                                          int                    ifindex,
                                          NMLinkType             link_type,
                                          const NMPlatformLink **out_link);
const NMPlatformLnkBond *
nm_platform_link_get_lnk_bond(NMPlatform *self, int ifindex, const NMPlatformLink **out_link);
const NMPlatformLnkBridge *
nm_platform_link_get_lnk_bridge(NMPlatform *self, int ifindex, const NMPlatformLink **out_link);
const NMPlatformLnkGre *
nm_platform_link_get_lnk_gre(NMPlatform *self, int ifindex, const NMPlatformLink **out_link);
const NMPlatformLnkGre *
nm_platform_link_get_lnk_gretap(NMPlatform *self, int ifindex, const NMPlatformLink **out_link);
const NMPlatformLnkIp6Tnl *
nm_platform_link_get_lnk_ip6tnl(NMPlatform *self, int ifindex, const NMPlatformLink **out_link);
const NMPlatformLnkIp6Tnl *
nm_platform_link_get_lnk_ip6gre(NMPlatform *self, int ifindex, const NMPlatformLink **out_link);
const NMPlatformLnkIp6Tnl *
nm_platform_link_get_lnk_ip6gretap(NMPlatform *self, int ifindex, const NMPlatformLink **out_link);
const NMPlatformLnkIpIp *
nm_platform_link_get_lnk_ipip(NMPlatform *self, int ifindex, const NMPlatformLink **out_link);
const NMPlatformLnkInfiniband *
nm_platform_link_get_lnk_infiniband(NMPlatform *self, int ifindex, const NMPlatformLink **out_link);
const NMPlatformLnkIpIp *
nm_platform_link_get_lnk_ipip(NMPlatform *self, int ifindex, const NMPlatformLink **out_link);
const NMPlatformLnkMacsec *
nm_platform_link_get_lnk_macsec(NMPlatform *self, int ifindex, const NMPlatformLink **out_link);
const NMPlatformLnkMacvlan *
nm_platform_link_get_lnk_macvlan(NMPlatform *self, int ifindex, const NMPlatformLink **out_link);
const NMPlatformLnkMacvlan *
nm_platform_link_get_lnk_macvtap(NMPlatform *self, int ifindex, const NMPlatformLink **out_link);
const NMPlatformLnkSit *
nm_platform_link_get_lnk_sit(NMPlatform *self, int ifindex, const NMPlatformLink **out_link);
const NMPlatformLnkTun *
nm_platform_link_get_lnk_tun(NMPlatform *self, int ifindex, const NMPlatformLink **out_link);
const NMPlatformLnkVlan *
nm_platform_link_get_lnk_vlan(NMPlatform *self, int ifindex, const NMPlatformLink **out_link);
const NMPlatformLnkVrf *
nm_platform_link_get_lnk_vrf(NMPlatform *self, int ifindex, const NMPlatformLink **out_link);
const NMPlatformLnkVti *
nm_platform_link_get_lnk_vti(NMPlatform *self, int ifindex, const NMPlatformLink **out_link);
const NMPlatformLnkVti6 *
nm_platform_link_get_lnk_vti6(NMPlatform *self, int ifindex, const NMPlatformLink **out_link);
const NMPlatformLnkVxlan *
nm_platform_link_get_lnk_vxlan(NMPlatform *self, int ifindex, const NMPlatformLink **out_link);
const NMPlatformLnkWireGuard *
nm_platform_link_get_lnk_wireguard(NMPlatform *self, int ifindex, const NMPlatformLink **out_link);

gboolean nm_platform_link_vlan_set_ingress_map(NMPlatform *self, int ifindex, int from, int to);
gboolean nm_platform_link_vlan_set_egress_map(NMPlatform *self, int ifindex, int from, int to);
gboolean nm_platform_link_vlan_change(NMPlatform             *self,
                                      int                     ifindex,
                                      _NMVlanFlags            flags_mask,
                                      _NMVlanFlags            flags_set,
                                      gboolean                ingress_reset_all,
                                      const NMVlanQosMapping *ingress_map,
                                      gsize                   n_ingress_map,
                                      gboolean                egress_reset_all,
                                      const NMVlanQosMapping *egress_map,
                                      gsize                   n_egress_map);

int      nm_platform_link_infiniband_add(NMPlatform            *self,
                                         int                    parent,
                                         int                    p_key,
                                         const NMPlatformLink **out_link);
int      nm_platform_link_infiniband_delete(NMPlatform *self, int parent, int p_key);
gboolean nm_platform_link_infiniband_get_properties(NMPlatform  *self,
                                                    int          ifindex,
                                                    int         *parent,
                                                    int         *p_key,
                                                    const char **mode);

gboolean nm_platform_link_veth_get_properties(NMPlatform *self, int ifindex, int *out_peer_ifindex);
gboolean nm_platform_link_tun_get_properties(NMPlatform       *self,
                                             int               ifindex,
                                             NMPlatformLnkTun *out_properties);

gboolean
nm_platform_wifi_get_capabilities(NMPlatform *self, int ifindex, _NMDeviceWifiCapabilities *caps);
guint32      nm_platform_wifi_get_frequency(NMPlatform *self, int ifindex);
gboolean     nm_platform_wifi_get_station(NMPlatform  *self,
                                          int          ifindex,
                                          NMEtherAddr *out_bssid,
                                          int         *out_quality,
                                          guint32     *out_rate);
_NM80211Mode nm_platform_wifi_get_mode(NMPlatform *self, int ifindex);
void         nm_platform_wifi_set_mode(NMPlatform *self, int ifindex, _NM80211Mode mode);
void         nm_platform_wifi_set_powersave(NMPlatform *self, int ifindex, guint32 powersave);
guint32
nm_platform_wifi_find_frequency(NMPlatform *self, int ifindex, const guint32 *freqs, gboolean ap);
void nm_platform_wifi_indicate_addressing_running(NMPlatform *self, int ifindex, gboolean running);
_NMSettingWirelessWakeOnWLan nm_platform_wifi_get_wake_on_wlan(NMPlatform *self, int ifindex);
gboolean
nm_platform_wifi_set_wake_on_wlan(NMPlatform *self, int ifindex, _NMSettingWirelessWakeOnWLan wowl);
gboolean nm_platform_wifi_get_csme_conn_info(NMPlatform             *self,
                                             int                     ifindex,
                                             NMPlatformCsmeConnInfo *out_conn_info);
gboolean nm_platform_wifi_get_device_from_csme(NMPlatform *self, int ifindex);

guint32  nm_platform_mesh_get_channel(NMPlatform *self, int ifindex);
gboolean nm_platform_mesh_set_channel(NMPlatform *self, int ifindex, guint32 channel);
gboolean nm_platform_mesh_set_ssid(NMPlatform *self, int ifindex, const guint8 *ssid, gsize len);

guint16  nm_platform_wpan_get_pan_id(NMPlatform *self, int ifindex);
gboolean nm_platform_wpan_set_pan_id(NMPlatform *self, int ifindex, guint16 pan_id);
guint16  nm_platform_wpan_get_short_addr(NMPlatform *self, int ifindex);
gboolean nm_platform_wpan_set_short_addr(NMPlatform *self, int ifindex, guint16 short_addr);
gboolean nm_platform_wpan_set_channel(NMPlatform *self, int ifindex, guint8 page, guint8 channel);

const NMPObject *nm_platform_ip_address_get(NMPlatform                                 *self,
                                            int                                         addr_family,
                                            int                                         ifindex,
                                            gconstpointer /* (NMPlatformIPAddress *) */ needle);

const NMPlatformIP4Address *nm_platform_ip4_address_get(NMPlatform *self,
                                                        int         ifindex,
                                                        in_addr_t   address,
                                                        guint8      plen,
                                                        in_addr_t   peer_address);

const NMPlatformIP6Address *
nm_platform_ip6_address_get(NMPlatform *self, int ifindex, const struct in6_addr *address);

int      nm_platform_link_sit_add(NMPlatform             *self,
                                  const char             *name,
                                  const NMPlatformLnkSit *props,
                                  const NMPlatformLink  **out_link);
int      nm_platform_link_tun_add(NMPlatform             *self,
                                  const char             *name,
                                  const NMPlatformLnkTun *props,
                                  const NMPlatformLink  **out_link,
                                  int                    *out_fd);
gboolean nm_platform_link_6lowpan_get_properties(NMPlatform *self, int ifindex, int *out_parent);

int
nm_platform_link_wireguard_add(NMPlatform *self, const char *name, const NMPlatformLink **out_link);

int nm_platform_link_wireguard_change(NMPlatform                               *self,
                                      int                                       ifindex,
                                      const NMPlatformLnkWireGuard             *lnk_wireguard,
                                      const struct _NMPWireGuardPeer           *peers,
                                      const NMPlatformWireGuardChangePeerFlags *peer_flags,
                                      guint                                     peers_len,
                                      NMPlatformWireGuardChangeFlags            change_flags);

gboolean nm_platform_object_delete(NMPlatform *self, const NMPObject *route);

gboolean nm_platform_ip4_address_add(NMPlatform *self,
                                     int         ifindex,
                                     in_addr_t   address,
                                     guint8      plen,
                                     in_addr_t   peer_address,
                                     in_addr_t   broadcast_address,
                                     guint32     lifetime,
                                     guint32     preferred_lft,
                                     guint32     flags,
                                     const char *label,
                                     char      **out_extack_msg);
gboolean nm_platform_ip6_address_add(NMPlatform     *self,
                                     int             ifindex,
                                     struct in6_addr address,
                                     guint8          plen,
                                     struct in6_addr peer_address,
                                     guint32         lifetime,
                                     guint32         preferred_lft,
                                     guint32         flags,
                                     char          **out_extack_msg);
gboolean nm_platform_ip4_address_delete(NMPlatform *self,
                                        int         ifindex,
                                        in_addr_t   address,
                                        guint8      plen,
                                        in_addr_t   peer_address);
gboolean
nm_platform_ip6_address_delete(NMPlatform *self, int ifindex, struct in6_addr address, guint8 plen);

static inline gboolean
nm_platform_ip_address_delete(NMPlatform                                       *self,
                              int                                               addr_family,
                              int                                               ifindex,
                              gconstpointer /* (const NMPlatformIPAddress *) */ addr)
{
    if (NM_IS_IPv4(addr_family)) {
        const NMPlatformIP4Address *a = addr;

        if (ifindex <= 0)
            ifindex = a->ifindex;

        return nm_platform_ip4_address_delete(self, ifindex, a->address, a->plen, a->peer_address);
    } else {
        const NMPlatformIP6Address *a = addr;

        if (ifindex <= 0)
            ifindex = a->ifindex;

        return nm_platform_ip6_address_delete(self, ifindex, a->address, a->plen);
    }
}

typedef enum {
    NMP_IP_ADDRESS_SYNC_FLAGS_NONE               = 0,
    NMP_IP_ADDRESS_SYNC_FLAGS_WITH_NOPREFIXROUTE = (1 << 0),
} NMPIPAddressSyncFlags;

gboolean nm_platform_ip_address_sync(NMPlatform           *self,
                                     int                   addr_family,
                                     int                   ifindex,
                                     GPtrArray            *known_addresses,
                                     GPtrArray            *addresses_prune,
                                     NMPIPAddressSyncFlags flags);

GPtrArray *
nm_platform_ip_address_get_prune_list(NMPlatform            *self,
                                      int                    addr_family,
                                      int                    ifindex,
                                      const struct in6_addr *ipv6_temporary_addr_prefixes_keep,
                                      guint                  ipv6_temporary_addr_prefixes_keep_len);

gboolean nm_platform_ip_address_flush(NMPlatform *self, int addr_family, int ifindex);

void nm_platform_ip_route_normalize(int addr_family, NMPlatformIPRoute *route);

static inline guint32
nm_platform_ip4_route_get_effective_metric(const NMPlatformIP4Route *r)
{
    nm_assert(r);

    return r->metric_any ? nm_add_clamped_u32(NM_PLATFORM_ROUTE_METRIC_DEFAULT_IP4, r->metric)
                         : r->metric;
}

static inline guint
nm_platform_ip4_route_get_n_nexthops(const NMPlatformIP4Route *r)
{
    /* The first hop of the "n_nexthops" is in NMPlatformIP4Route
     * itself. Thus, if the caller only sets ifindex and leaves
     * n_nexthops at zero, the number of next hops is still 1
     * (for convenience of the user who wants to initialize a
     * single hop route). */
    if (r->n_nexthops >= 1) {
        nm_assert(r->ifindex > 0);
        return r->n_nexthops;
    }
    if (r->ifindex > 0)
        return 1;
    return 0;
}

static inline guint32
nm_platform_ip6_route_get_effective_metric(const NMPlatformIP6Route *r)
{
    nm_assert(r);

    return r->metric_any ? nm_add_clamped_u32(NM_PLATFORM_ROUTE_METRIC_DEFAULT_IP6, r->metric)
                         : r->metric;
}

static inline guint32
nm_platform_ip_route_get_effective_table(const NMPlatformIPRoute *r)
{
    nm_assert(r);
    nm_assert(!r->table_any || r->table_coerced == 0);

    return r->table_any ? 254u /* RT_TABLE_MAIN */
                        : nm_platform_route_table_uncoerce(r->table_coerced, TRUE);
}

static inline gconstpointer
nm_platform_ip_route_get_gateway(int addr_family, const NMPlatformIPRoute *route)
{
    nm_assert_addr_family(addr_family);

    if (!route)
        return NULL;

    if (NM_IS_IPv4(addr_family))
        return &((NMPlatformIP4Route *) route)->gateway;
    return &((NMPlatformIP6Route *) route)->gateway;
}

static inline gconstpointer
nm_platform_ip_route_get_pref_src(int addr_family, const NMPlatformIPRoute *route)
{
    nm_assert_addr_family(addr_family);

    if (!route)
        return NULL;

    if (NM_IS_IPv4(addr_family))
        return &((NMPlatformIP4Route *) route)->pref_src;
    return &((NMPlatformIP6Route *) route)->pref_src;
}

int nm_platform_ip_route_add(NMPlatform      *self,
                             NMPNlmFlags      flags,
                             const NMPObject *route,
                             char           **out_extack_msg);
int nm_platform_ip4_route_add(NMPlatform                   *self,
                              NMPNlmFlags                   flags,
                              const NMPlatformIP4Route     *route,
                              const NMPlatformIP4RtNextHop *extra_nexthops);
int nm_platform_ip6_route_add(NMPlatform *self, NMPNlmFlags flags, const NMPlatformIP6Route *route);

GPtrArray *nm_platform_ip_route_get_prune_list(NMPlatform            *self,
                                               int                    addr_family,
                                               int                    ifindex,
                                               NMIPRouteTableSyncMode route_table_sync);

gboolean nm_platform_ip_route_sync(NMPlatform *self,
                                   int         addr_family,
                                   int         ifindex,
                                   GPtrArray  *routes,
                                   GPtrArray  *routes_prune,
                                   GPtrArray **out_routes_failed);

gboolean nm_platform_ip_route_flush(NMPlatform *self, int addr_family, int ifindex);

int nm_platform_ip_route_get(NMPlatform   *self,
                             int           addr_family,
                             gconstpointer address,
                             int           oif_ifindex,
                             NMPObject   **out_route);

int nm_platform_routing_rule_add(NMPlatform                  *self,
                                 NMPNlmFlags                  flags,
                                 const NMPlatformRoutingRule *routing_rule);

int nm_platform_qdisc_add(NMPlatform *self, NMPNlmFlags flags, const NMPlatformQdisc *qdisc);
int nm_platform_qdisc_delete(NMPlatform *self, int ifindex, guint32 parent, gboolean log_error);
int nm_platform_tfilter_add(NMPlatform *self, NMPNlmFlags flags, const NMPlatformTfilter *tfilter);
int nm_platform_tfilter_delete(NMPlatform *self, int ifindex, guint32 parent, gboolean log_error);
gboolean nm_platform_tc_sync(NMPlatform *self,
                             int         ifindex,
                             GPtrArray  *known_qdiscs,
                             GPtrArray  *known_tfilters);

const char *nm_platform_link_to_string(const NMPlatformLink *link, char *buf, gsize len);
const char *nm_platform_lnk_bond_to_string(const NMPlatformLnkBond *lnk, char *buf, gsize len);
const char *nm_platform_lnk_bridge_to_string(const NMPlatformLnkBridge *lnk, char *buf, gsize len);
const char *nm_platform_lnk_gre_to_string(const NMPlatformLnkGre *lnk, char *buf, gsize len);
const char *
nm_platform_lnk_infiniband_to_string(const NMPlatformLnkInfiniband *lnk, char *buf, gsize len);
const char *nm_platform_lnk_ip6tnl_to_string(const NMPlatformLnkIp6Tnl *lnk, char *buf, gsize len);
const char *nm_platform_lnk_ipip_to_string(const NMPlatformLnkIpIp *lnk, char *buf, gsize len);
const char *nm_platform_lnk_macsec_to_string(const NMPlatformLnkMacsec *lnk, char *buf, gsize len);
const char *
nm_platform_lnk_macvlan_to_string(const NMPlatformLnkMacvlan *lnk, char *buf, gsize len);
const char *nm_platform_lnk_sit_to_string(const NMPlatformLnkSit *lnk, char *buf, gsize len);
const char *nm_platform_lnk_tun_to_string(const NMPlatformLnkTun *lnk, char *buf, gsize len);
const char *nm_platform_lnk_vlan_to_string(const NMPlatformLnkVlan *lnk, char *buf, gsize len);
const char *nm_platform_lnk_vrf_to_string(const NMPlatformLnkVrf *lnk, char *buf, gsize len);
const char *nm_platform_lnk_vti_to_string(const NMPlatformLnkVti *lnk, char *buf, gsize len);
const char *nm_platform_lnk_vti6_to_string(const NMPlatformLnkVti6 *lnk, char *buf, gsize len);
const char *nm_platform_lnk_vxlan_to_string(const NMPlatformLnkVxlan *lnk, char *buf, gsize len);
const char *
nm_platform_lnk_wireguard_to_string(const NMPlatformLnkWireGuard *lnk, char *buf, gsize len);

const char *nm_platform_ip4_route_to_string_full(const NMPlatformIP4Route     *route,
                                                 const NMPlatformIP4RtNextHop *extra_nexthops,
                                                 char                         *buf,
                                                 gsize                         len);

static inline const char *
nm_platform_ip4_route_to_string(const NMPlatformIP4Route *route, char *buf, gsize len)
{
    return nm_platform_ip4_route_to_string_full(route, NULL, buf, len);
}

const char *nm_platform_ip6_route_to_string(const NMPlatformIP6Route *route, char *buf, gsize len);
const char *
nm_platform_routing_rule_to_string(const NMPlatformRoutingRule *routing_rule, char *buf, gsize len);
const char *nm_platform_qdisc_to_string(const NMPlatformQdisc *qdisc, char *buf, gsize len);
const char *nm_platform_tfilter_to_string(const NMPlatformTfilter *tfilter, char *buf, gsize len);
const char *nm_platform_vf_to_string(const NMPlatformVF *vf, char *buf, gsize len);
const char *
nm_platform_bridge_vlan_to_string(const NMPlatformBridgeVlan *vlan, char *buf, gsize len);

const char *nm_platform_vlan_qos_mapping_to_string(const char             *name,
                                                   const NMVlanQosMapping *map,
                                                   gsize                   n_map,
                                                   char                   *buf,
                                                   gsize                   len);

const char *
nm_platform_wireguard_peer_to_string(const struct _NMPWireGuardPeer *peer, char *buf, gsize len);

const char *
nm_platform_mptcp_addr_to_string(const NMPlatformMptcpAddr *mptcp_addr, char *buf, gsize len);

int nm_platform_link_cmp(const NMPlatformLink *a, const NMPlatformLink *b);
int nm_platform_lnk_bond_cmp(const NMPlatformLnkBond *a, const NMPlatformLnkBond *b);
int nm_platform_lnk_bridge_cmp(const NMPlatformLnkBridge *a, const NMPlatformLnkBridge *b);
int nm_platform_lnk_gre_cmp(const NMPlatformLnkGre *a, const NMPlatformLnkGre *b);
int nm_platform_lnk_infiniband_cmp(const NMPlatformLnkInfiniband *a,
                                   const NMPlatformLnkInfiniband *b);
int nm_platform_lnk_ip6tnl_cmp(const NMPlatformLnkIp6Tnl *a, const NMPlatformLnkIp6Tnl *b);
int nm_platform_lnk_ipip_cmp(const NMPlatformLnkIpIp *a, const NMPlatformLnkIpIp *b);
int nm_platform_lnk_macsec_cmp(const NMPlatformLnkMacsec *a, const NMPlatformLnkMacsec *b);
int nm_platform_lnk_macvlan_cmp(const NMPlatformLnkMacvlan *a, const NMPlatformLnkMacvlan *b);
int nm_platform_lnk_sit_cmp(const NMPlatformLnkSit *a, const NMPlatformLnkSit *b);
int nm_platform_lnk_tun_cmp(const NMPlatformLnkTun *a, const NMPlatformLnkTun *b);
int nm_platform_lnk_vlan_cmp(const NMPlatformLnkVlan *a, const NMPlatformLnkVlan *b);
int nm_platform_lnk_vrf_cmp(const NMPlatformLnkVrf *a, const NMPlatformLnkVrf *b);
int nm_platform_lnk_vti_cmp(const NMPlatformLnkVti *a, const NMPlatformLnkVti *b);
int nm_platform_lnk_vti6_cmp(const NMPlatformLnkVti6 *a, const NMPlatformLnkVti6 *b);
int nm_platform_lnk_vxlan_cmp(const NMPlatformLnkVxlan *a, const NMPlatformLnkVxlan *b);
int nm_platform_lnk_wireguard_cmp(const NMPlatformLnkWireGuard *a, const NMPlatformLnkWireGuard *b);

GHashTable *nm_platform_ip4_address_addr_to_hash(NMPlatform *self, int ifindex);

int nm_platform_ip4_route_cmp(const NMPlatformIP4Route *a,
                              const NMPlatformIP4Route *b,
                              NMPlatformIPRouteCmpType  cmp_type);
int nm_platform_ip4_rt_nexthop_cmp(const NMPlatformIP4RtNextHop *a,
                                   const NMPlatformIP4RtNextHop *b,
                                   gboolean                      for_id);
int nm_platform_ip6_route_cmp(const NMPlatformIP6Route *a,
                              const NMPlatformIP6Route *b,
                              NMPlatformIPRouteCmpType  cmp_type);

int nm_platform_routing_rule_cmp(const NMPlatformRoutingRule *a,
                                 const NMPlatformRoutingRule *b,
                                 NMPlatformRoutingRuleCmpType cmp_type);

int
nm_platform_qdisc_cmp(const NMPlatformQdisc *a, const NMPlatformQdisc *b, gboolean compare_handle);

int nm_platform_tfilter_cmp(const NMPlatformTfilter *a, const NMPlatformTfilter *b);

int nm_platform_mptcp_addr_cmp(const NMPlatformMptcpAddr *a, const NMPlatformMptcpAddr *b);

void nm_platform_link_hash_update(const NMPlatformLink *obj, NMHashState *h);
void nm_platform_link_bond_port_hash_update(const NMPlatformLinkBondPort *obj, NMHashState *h);
int  nm_platform_link_bond_port_cmp(const NMPlatformLinkBondPort *a,
                                    const NMPlatformLinkBondPort *b);
void nm_platform_ip4_route_hash_update(const NMPlatformIP4Route *obj,
                                       NMPlatformIPRouteCmpType  cmp_type,
                                       NMHashState              *h);

static inline guint
nm_platform_ip4_route_hash(const NMPlatformIP4Route *obj, NMPlatformIPRouteCmpType cmp_type)
{
    NMHashState h;

    nm_hash_init(&h, 1118769853u);
    nm_platform_ip4_route_hash_update(obj, cmp_type, &h);
    return nm_hash_complete(&h);
}

void nm_platform_ip4_rt_nexthop_hash_update(const NMPlatformIP4RtNextHop *obj,
                                            gboolean                      for_id,
                                            NMHashState                  *h);
void nm_platform_ip6_route_hash_update(const NMPlatformIP6Route *obj,
                                       NMPlatformIPRouteCmpType  cmp_type,
                                       NMHashState              *h);
void nm_platform_routing_rule_hash_update(const NMPlatformRoutingRule *obj,
                                          NMPlatformRoutingRuleCmpType cmp_type,
                                          NMHashState                 *h);
void nm_platform_lnk_bond_hash_update(const NMPlatformLnkBond *obj, NMHashState *h);
void nm_platform_lnk_bridge_hash_update(const NMPlatformLnkBridge *obj, NMHashState *h);
void nm_platform_lnk_gre_hash_update(const NMPlatformLnkGre *obj, NMHashState *h);
void nm_platform_lnk_infiniband_hash_update(const NMPlatformLnkInfiniband *obj, NMHashState *h);
void nm_platform_lnk_ip6tnl_hash_update(const NMPlatformLnkIp6Tnl *obj, NMHashState *h);
void nm_platform_lnk_ipip_hash_update(const NMPlatformLnkIpIp *obj, NMHashState *h);
void nm_platform_lnk_macsec_hash_update(const NMPlatformLnkMacsec *obj, NMHashState *h);
void nm_platform_lnk_macvlan_hash_update(const NMPlatformLnkMacvlan *obj, NMHashState *h);
void nm_platform_lnk_sit_hash_update(const NMPlatformLnkSit *obj, NMHashState *h);
void nm_platform_lnk_tun_hash_update(const NMPlatformLnkTun *obj, NMHashState *h);
void nm_platform_lnk_vlan_hash_update(const NMPlatformLnkVlan *obj, NMHashState *h);
void nm_platform_lnk_vrf_hash_update(const NMPlatformLnkVrf *obj, NMHashState *h);
void nm_platform_lnk_vti_hash_update(const NMPlatformLnkVti *obj, NMHashState *h);
void nm_platform_lnk_vti6_hash_update(const NMPlatformLnkVti6 *obj, NMHashState *h);
void nm_platform_lnk_vxlan_hash_update(const NMPlatformLnkVxlan *obj, NMHashState *h);
void nm_platform_lnk_wireguard_hash_update(const NMPlatformLnkWireGuard *obj, NMHashState *h);

void nm_platform_qdisc_hash_update(const NMPlatformQdisc *obj, NMHashState *h);
void nm_platform_tfilter_hash_update(const NMPlatformTfilter *obj, NMHashState *h);

void nm_platform_mptcp_addr_hash_update(const NMPlatformMptcpAddr *obj, NMHashState *h);

guint    nm_platform_mptcp_addr_index_addr_cmp(gconstpointer data);
gboolean nm_platform_mptcp_addr_index_addr_equal(gconstpointer data_a, gconstpointer data_b);

#define NM_PLATFORM_LINK_FLAGS2STR_MAX_LEN ((gsize) 162)

gboolean nm_platform_ethtool_set_wake_on_lan(NMPlatform              *self,
                                             int                      ifindex,
                                             _NMSettingWiredWakeOnLan wol,
                                             const char              *wol_password);
gboolean nm_platform_ethtool_set_link_settings(NMPlatform              *self,
                                               int                      ifindex,
                                               gboolean                 autoneg,
                                               guint32                  speed,
                                               NMPlatformLinkDuplexType duplex);
gboolean nm_platform_ethtool_get_link_settings(NMPlatform               *self,
                                               int                       ifindex,
                                               gboolean                 *out_autoneg,
                                               guint32                  *out_speed,
                                               NMPlatformLinkDuplexType *out_duplex);

NMEthtoolFeatureStates *nm_platform_ethtool_get_link_features(NMPlatform *self, int ifindex);
gboolean                nm_platform_ethtool_set_features(
                   NMPlatform                   *self,
                   int                           ifindex,
                   const NMEthtoolFeatureStates *features,
                   const NMOptionBool *requested /* indexed by NMEthtoolID - _NM_ETHTOOL_ID_FEATURE_FIRST */,
                   gboolean            do_set /* or reset */);

gboolean nm_platform_ethtool_get_link_coalesce(NMPlatform             *self,
                                               int                     ifindex,
                                               NMEthtoolCoalesceState *coalesce);

gboolean nm_platform_ethtool_set_coalesce(NMPlatform                   *self,
                                          int                           ifindex,
                                          const NMEthtoolCoalesceState *coalesce);

gboolean nm_platform_ethtool_get_link_ring(NMPlatform *self, int ifindex, NMEthtoolRingState *ring);

gboolean
nm_platform_ethtool_set_ring(NMPlatform *self, int ifindex, const NMEthtoolRingState *ring);

gboolean
nm_platform_ethtool_get_link_pause(NMPlatform *self, int ifindex, NMEthtoolPauseState *pause);

gboolean
nm_platform_ethtool_set_pause(NMPlatform *self, int ifindex, const NMEthtoolPauseState *pause);

void nm_platform_ip4_dev_route_blacklist_set(NMPlatform *self,
                                             int         ifindex,
                                             GPtrArray  *ip4_dev_route_blacklist);

struct _NMDedupMultiIndex *nm_platform_get_multi_idx(NMPlatform *self);

/*****************************************************************************/

guint16 nm_platform_genl_get_family_id(NMPlatform *self, NMPGenlFamilyType family_type);

int
nm_platform_mptcp_addr_update(NMPlatform *self, NMOptionBool add, const NMPlatformMptcpAddr *addr);

GPtrArray *nm_platform_mptcp_addrs_dump(NMPlatform *self);

gboolean nm_platform_ip6_dadfailed_check(NMPlatform *self, int ifindex, const struct in6_addr *ip6);
void     nm_platform_ip6_dadfailed_set(NMPlatform            *self,
                                       int                    ifindex,
                                       const struct in6_addr *ip6,
                                       gboolean               failed);

/*****************************************************************************/

static inline NMPlatformIP4Address *
nm_platform_ip4_address_init_loopback_addr1(NMPlatformIP4Address *a)
{
    *a = ((NMPlatformIP4Address){
        .address      = NM_IPV4LO_ADDR1,
        .peer_address = NM_IPV4LO_ADDR1,
        .ifindex      = NM_LOOPBACK_IFINDEX,
        .plen         = NM_IPV4LO_PREFIXLEN,
    });
    return a;
}

static inline NMPlatformIP6Address *
nm_platform_ip6_address_init_loopback(NMPlatformIP6Address *a)
{
    *a = ((NMPlatformIP6Address){
        .address = IN6ADDR_LOOPBACK_INIT,
        .ifindex = NM_LOOPBACK_IFINDEX,
        .plen    = 128,
    });
    return a;
}

#endif /* __NETWORKMANAGER_PLATFORM_H__ */
