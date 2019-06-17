/* nm-platform.c - Handle runtime kernel networking configuration
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2009 - 2018 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_PLATFORM_H__
#define __NETWORKMANAGER_PLATFORM_H__

#include "nm-dbus-interface.h"
#include "nm-core-types-internal.h"

#include "nm-core-utils.h"
#include "nm-setting-vlan.h"
#include "nm-setting-wired.h"
#include "nm-setting-wireless.h"
#include "nm-setting-ip-tunnel.h"

#define NM_TYPE_PLATFORM            (nm_platform_get_type ())
#define NM_PLATFORM(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_PLATFORM, NMPlatform))
#define NM_PLATFORM_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_PLATFORM, NMPlatformClass))
#define NM_IS_PLATFORM(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_PLATFORM))
#define NM_IS_PLATFORM_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_PLATFORM))
#define NM_PLATFORM_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_PLATFORM, NMPlatformClass))

#define NM_PLATFORM_NETNS_SUPPORT_DEFAULT    FALSE

/*****************************************************************************/

#define NM_PLATFORM_NETNS_SUPPORT      "netns-support"
#define NM_PLATFORM_USE_UDEV           "use-udev"
#define NM_PLATFORM_LOG_WITH_PTR       "log-with-ptr"

/*****************************************************************************/

/* IFNAMSIZ is both defined in <linux/if.h> and <net/if.h>. In the past, these
 * headers conflicted, so we cannot simply include either of them in a header-file.*/
#define NMP_IFNAMSIZ 16

/*****************************************************************************/

struct _NMPWireGuardPeer;

struct udev_device;

typedef gboolean (*NMPObjectPredicateFunc) (const NMPObject *obj,
                                            gpointer user_data);

/* workaround for older libnl version, that does not define these flags. */
#ifndef IFA_F_MANAGETEMPADDR
#define IFA_F_MANAGETEMPADDR 0x100
#endif
#ifndef IFA_F_NOPREFIXROUTE
#define IFA_F_NOPREFIXROUTE 0x200
#endif

#define NM_RT_SCOPE_LINK                       253  /* RT_SCOPE_LINK */

/* Define of the IN6_ADDR_GEN_MODE_* values to workaround old kernel headers
 * that don't define it. */
#define NM_IN6_ADDR_GEN_MODE_UNKNOWN           255  /* no corresponding value.  */
#define NM_IN6_ADDR_GEN_MODE_EUI64             0    /* IN6_ADDR_GEN_MODE_EUI64 */
#define NM_IN6_ADDR_GEN_MODE_NONE              1    /* IN6_ADDR_GEN_MODE_NONE */
#define NM_IN6_ADDR_GEN_MODE_STABLE_PRIVACY    2    /* IN6_ADDR_GEN_MODE_STABLE_PRIVACY */
#define NM_IN6_ADDR_GEN_MODE_RANDOM            3    /* IN6_ADDR_GEN_MODE_RANDOM */

#define NM_IFF_MULTI_QUEUE                     0x0100 /* IFF_MULTI_QUEUE */

/* Redefine this in host's endianness */
#define NM_GRE_KEY      0x2000

typedef enum {
	/* use our own platform enum for the nlmsg-flags. Otherwise, we'd have
	 * to include <linux/netlink.h> */
	NMP_NLM_FLAG_F_REPLACE      = 0x100, /* NLM_F_REPLACE, Override existing */
	NMP_NLM_FLAG_F_EXCL         = 0x200, /* NLM_F_EXCL, Do not touch, if it exists */
	NMP_NLM_FLAG_F_CREATE       = 0x400, /* NLM_F_CREATE, Create, if it does not exist */
	NMP_NLM_FLAG_F_APPEND       = 0x800, /* NLM_F_APPEND, Add to end of list */

	NMP_NLM_FLAG_FMASK          = 0xFFFF, /* a mask for all NMP_NLM_FLAG_F_* flags */

	/* instructs NM to suppress logging an error message for any failures
	 * received from kernel.
	 *
	 * It will still log with debug-level, and it will still log
	 * other failures aside the kernel response. */
	NMP_NLM_FLAG_SUPPRESS_NETLINK_FAILURE = 0x10000,

	/* the following aliases correspond to iproute2's `ip route CMD` for
	 * RTM_NEWROUTE, with CMD being one of add, change, replace, prepend,
	 * append and test. */
	NMP_NLM_FLAG_ADD            = NMP_NLM_FLAG_F_CREATE                          | NMP_NLM_FLAG_F_EXCL,
	NMP_NLM_FLAG_CHANGE         =                         NMP_NLM_FLAG_F_REPLACE,
	NMP_NLM_FLAG_REPLACE        = NMP_NLM_FLAG_F_CREATE | NMP_NLM_FLAG_F_REPLACE,
	NMP_NLM_FLAG_PREPEND        = NMP_NLM_FLAG_F_CREATE,
	NMP_NLM_FLAG_APPEND         = NMP_NLM_FLAG_F_CREATE                                                | NMP_NLM_FLAG_F_APPEND,
	NMP_NLM_FLAG_TEST           =                                                  NMP_NLM_FLAG_F_EXCL,
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
	 * that two routes are idential, while they are not. That can lead to an
	 * inconsistent platform cache. Not much what we can do about that, except
	 * implementing all options that kernel supports *sigh*. See rh#1337860.
	 */
	NM_PLATFORM_IP_ROUTE_CMP_TYPE_ID,

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
	guint8 data[20 /* NM_UTILS_HWADDR_LEN_MAX */ ];
	guint8 len;
} NMPLinkAddress;

gconstpointer nmp_link_address_get (const NMPLinkAddress *addr, size_t *length);

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
	NM_PLATFORM_MATCH_WITH_NONE                                 = 0,

	NM_PLATFORM_MATCH_WITH_ADDRTYPE_NORMAL                      = (1LL <<  0),
	NM_PLATFORM_MATCH_WITH_ADDRTYPE_LINKLOCAL                   = (1LL <<  1),
	NM_PLATFORM_MATCH_WITH_ADDRTYPE__ANY                        =   NM_PLATFORM_MATCH_WITH_ADDRTYPE_NORMAL
	                                                              | NM_PLATFORM_MATCH_WITH_ADDRTYPE_LINKLOCAL,

	NM_PLATFORM_MATCH_WITH_ADDRSTATE_NORMAL                     = (1LL <<  2),
	NM_PLATFORM_MATCH_WITH_ADDRSTATE_TENTATIVE                  = (1LL <<  3),
	NM_PLATFORM_MATCH_WITH_ADDRSTATE_DADFAILED                  = (1LL <<  4),
	NM_PLATFORM_MATCH_WITH_ADDRSTATE__ANY                       =   NM_PLATFORM_MATCH_WITH_ADDRSTATE_NORMAL
	                                                              | NM_PLATFORM_MATCH_WITH_ADDRSTATE_TENTATIVE
	                                                              | NM_PLATFORM_MATCH_WITH_ADDRSTATE_DADFAILED,
} NMPlatformMatchFlags;

#define NM_PLATFORM_LINK_OTHER_NETNS    (-1)

struct _NMPlatformObject {
	/* the object type has no fields of its own, it is only used to having
	 * a special pointer type that can be used to indicate "any" type. */
	char _dummy_don_t_use_me;
};

#define __NMPlatformObjWithIfindex_COMMON \
	int ifindex; \
	;

struct _NMPlatformObjWithIfindex {
	__NMPlatformObjWithIfindex_COMMON;
};

struct _NMPlatformLink {
	__NMPlatformObjWithIfindex_COMMON;
	char name[NMP_IFNAMSIZ];
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

	/* @connected is mostly identical to (@n_ifi_flags & IFF_UP). Except for bridge/bond masters,
	 * where we coerce the link as disconnect if it has no slaves. */
	bool connected:1;

	bool initialized:1;
};

typedef enum { /*< skip >*/
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

guint _nm_platform_signal_id_get (NMPlatformSignalIdType signal_type);

typedef enum {
	NM_PLATFORM_SIGNAL_NONE,
	NM_PLATFORM_SIGNAL_ADDED,
	NM_PLATFORM_SIGNAL_CHANGED,
	NM_PLATFORM_SIGNAL_REMOVED,
} NMPlatformSignalChangeType;

#define NM_PLATFORM_IP_ADDRESS_CAST(address) \
	NM_CONSTCAST (NMPlatformIPAddress, (address), NMPlatformIPXAddress, NMPlatformIP4Address, NMPlatformIP6Address)

#define __NMPlatformIPAddress_COMMON \
	__NMPlatformObjWithIfindex_COMMON; \
	NMIPConfigSource addr_source; \
	\
	/* Timestamp in seconds in the reference system of nm_utils_get_monotonic_timestamp_*().
	 *
	 * The rules are:
	 * 1 @lifetime==0: @timestamp and @preferred is irrelevant (but mostly set to 0 too). Such addresses
	 *   are permanent. This rule is so that unset addresses (calloc) are permanent by default.
	 * 2 @lifetime==@preferred==NM_PLATFORM_LIFETIME_PERMANENT: @timestamp is irrelevant (but mostly
	 *   set to 0). Such addresses are permanent.
	 * 3 Non permanent addresses should (almost) always have @timestamp > 0. 0 is not a valid timestamp
	 *   and never returned by nm_utils_get_monotonic_timestamp_s(). In this case @valid/@preferred
	 *   is anchored at @timestamp.
	 * 4 Non permanent addresses with @timestamp == 0 are implicitly anchored at *now*, thus the time
	 *   moves as time goes by. This is usually not useful, except e.g. nm_platform_ip[46]_address_add().
	 *
	 * Non permanent addresses from DHCP/RA might have the @timestamp set to the moment of when the
	 * lease was received. Addresses from kernel might have the @timestamp based on the last modification
	 * time of the addresses. But don't rely on this behaviour, the @timestamp is only defined for anchoring
	 * @lifetime and @preferred.
	 */ \
	guint32 timestamp; \
	guint32 lifetime;   /* seconds since timestamp */ \
	guint32 preferred;  /* seconds since timestamp */ \
	\
	/* ifa_flags in 'struct ifaddrmsg' from <linux/if_addr.h>, extended to 32 bit by
	 * IFA_FLAGS attribute. */ \
	guint32 n_ifa_flags; \
	\
	guint8 plen; \
	;

/**
 * NMPlatformIPAddress:
 *
 * Common parts of NMPlatformIP4Address and NMPlatformIP6Address.
 **/
typedef struct {
	__NMPlatformIPAddress_COMMON;
	union {
		guint8 address_ptr[1];
		guint32 __dummy_for_32bit_alignment;
	};
} NMPlatformIPAddress;

/**
 * NMPlatformIP4Address:
 * @timestamp: timestamp as returned by nm_utils_get_monotonic_timestamp_s()
 **/
struct _NMPlatformIP4Address {
	__NMPlatformIPAddress_COMMON;

	/* The local address IFA_LOCAL. */
	in_addr_t address;

	/* The IFA_ADDRESS PTP peer address. This field is rather important, because
	 * it constitutes the identifier for the IPv4 address (e.g. you can add two
	 * addresses that only differ by their peer's network-part.
	 *
	 * Beware that for most cases, NetworkManager doesn't want to set an explicit
	 * peer-address. Hoever, that corresponds to setting the peer address to @address
	 * itself. Leaving peer-address unset/zero, means explicitly setting the peer
	 * address to 0.0.0.0, which you probably don't want.
	 * */
	in_addr_t peer_address;  /* PTP peer address */

	char label[NMP_IFNAMSIZ];
};

/**
 * NMPlatformIP6Address:
 * @timestamp: timestamp as returned by nm_utils_get_monotonic_timestamp_s()
 **/
struct _NMPlatformIP6Address {
	__NMPlatformIPAddress_COMMON;
	struct in6_addr address;
	struct in6_addr peer_address;
};

typedef union {
	NMPlatformIPAddress  ax;
	NMPlatformIP4Address a4;
	NMPlatformIP6Address a6;
} NMPlatformIPXAddress;

#undef __NMPlatformIPAddress_COMMON

/* Default value for adding an IPv4 route. This is also what iproute2 does.
 * Note that contrary to IPv6, you can add routes with metric 0 and it is even
 * the default.
 */
#define NM_PLATFORM_ROUTE_METRIC_DEFAULT_IP4 0

/* Default value for adding an IPv6 route. This is also what iproute2 does.
 * Adding an IPv6 route with metric 0, kernel translates to IP6_RT_PRIO_USER (1024). */
#define NM_PLATFORM_ROUTE_METRIC_DEFAULT_IP6 1024

/* For IPv4, kernel adds a device route (subnet routes) with metric 0 when user
 * configures addresses. */
#define NM_PLATFORM_ROUTE_METRIC_IP4_DEVICE_ROUTE 0

#define __NMPlatformIPRoute_COMMON \
	__NMPlatformObjWithIfindex_COMMON; \
	\
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
	 * to zero, in which case the first matching route (with proto ignored) is deleted. */ \
	NMIPConfigSource rt_source; \
	\
	guint8 plen; \
	\
	/* RTA_METRICS:
	 *
	 * For IPv4 routes, these properties are part of their
	 * ID (meaning: you can add otherwise idential IPv4 routes that
	 * only differ by the metric property).
	 * On the other hand, for IPv6 you cannot add two IPv6 routes that only differ
	 * by an RTA_METRICS property.
	 *
	 * When deleting a route, kernel seems to ignore the RTA_METRICS properties.
	 * That is a problem/bug for IPv4 because you cannot explicitly select which
	 * route to delete. Kernel just picks the first. See rh#1475642. */ \
	\
	/* RTA_METRICS.RTAX_LOCK (iproute2: "lock" arguments) */ \
	bool lock_window:1; \
	bool lock_cwnd:1; \
	bool lock_initcwnd:1; \
	bool lock_initrwnd:1; \
	bool lock_mtu:1; \
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
	 * in route-cmp. */ \
	unsigned r_rtm_flags; \
	\
	/* RTA_METRICS.RTAX_ADVMSS (iproute2: advmss) */ \
	guint32 mss; \
	\
	/* RTA_METRICS.RTAX_WINDOW (iproute2: window) */ \
	guint32 window; \
	\
	/* RTA_METRICS.RTAX_CWND (iproute2: cwnd) */ \
	guint32 cwnd; \
	\
	/* RTA_METRICS.RTAX_INITCWND (iproute2: initcwnd) */ \
	guint32 initcwnd; \
	\
	/* RTA_METRICS.RTAX_INITRWND (iproute2: initrwnd) */ \
	guint32 initrwnd; \
	\
	/* RTA_METRICS.RTAX_MTU (iproute2: mtu) */ \
	guint32 mtu; \
	\
	\
	/* RTA_PRIORITY (iproute2: metric) */ \
	guint32 metric; \
	\
	/* rtm_table, RTA_TABLE.
	 *
	 * This is not the original table ID. Instead, 254 (RT_TABLE_MAIN) and
	 * zero (RT_TABLE_UNSPEC) are swapped, so that the default is the main
	 * table. Use nm_platform_route_table_coerce()/nm_platform_route_table_uncoerce(). */ \
	guint32 table_coerced; \
	\
	/*end*/

typedef struct {
	__NMPlatformIPRoute_COMMON;
	union {
		guint8 network_ptr[1];
		guint32 __dummy_for_32bit_alignment;
	};
} NMPlatformIPRoute;

#define NM_PLATFORM_IP_ROUTE_CAST(route) \
	NM_CONSTCAST (NMPlatformIPRoute, (route), NMPlatformIPXRoute, NMPlatformIP4Route, NMPlatformIP6Route)

#define NM_PLATFORM_IP_ROUTE_IS_DEFAULT(route) \
	(NM_PLATFORM_IP_ROUTE_CAST (route)->plen <= 0)

struct _NMPlatformIP4Route {
	__NMPlatformIPRoute_COMMON;
	in_addr_t network;

	/* RTA_GATEWAY. The gateway is part of the primary key for a route */
	in_addr_t gateway;

	/* RTA_PREFSRC (called "src" by iproute2).
	 *
	 * pref_src is part of the ID of an IPv4 route. When deleting a route,
	 * pref_src must match, unless set to 0.0.0.0 to match any. */
	in_addr_t pref_src;

	/* rtm_tos (iproute2: tos)
	 *
	 * For IPv4, tos is part of the weak-id (like metric).
	 *
	 * For IPv6, tos is ignored by kernel.  */
	guint8 tos;

	/* The bitwise inverse of the route scope rtm_scope. It is inverted so that the
	 * default value (RT_SCOPE_NOWHERE) is zero. Use nm_platform_route_scope_inv()
	 * to convert back and forth between the inverese representation and the
	 * real value.
	 *
	 * rtm_scope is part of the primary key for IPv4 routes. When deleting a route,
	 * the scope must match, unless it is left at RT_SCOPE_NOWHERE, in which case the first
	 * matching route is deleted.
	 *
	 * For IPv6 routes, the scope is ignored and kernel always assumes global scope.
	 * Hence, this field is only in NMPlatformIP4Route. */
	guint8 scope_inv;
};

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
	guint8 src_plen;

	/* RTA_PREF router preference.
	 *
	 * The type is guint8 to keep the struct size small. But the values are compatible with
	 * the NMIcmpv6RouterPref enum. */
	guint8 rt_pref;
};

typedef union {
	NMPlatformIPRoute  rx;
	NMPlatformIP4Route r4;
	NMPlatformIP6Route r6;
} NMPlatformIPXRoute;

#undef __NMPlatformIPRoute_COMMON

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
	NMIPAddr src;                        /* FRA_SRC */
	NMIPAddr dst;                        /* FRA_DST */
	guint64  tun_id;                     /* betoh64(FRA_TUN_ID) */
	guint32  table;                      /* (struct fib_rule_hdr).table, FRA_TABLE */
	guint32  flags;                      /* (struct fib_rule_hdr).flags */
	guint32  priority;                   /* RA_PRIORITY */
	guint32  fwmark;                     /* FRA_FWMARK */
	guint32  fwmask;                     /* FRA_FWMASK */
	guint32  goto_target;                /* FRA_GOTO */
	guint32  flow;                       /* FRA_FLOW */
	guint32  suppress_prefixlen_inverse; /* ~(FRA_SUPPRESS_PREFIXLEN) */
	guint32  suppress_ifgroup_inverse;   /* ~(FRA_SUPPRESS_IFGROUP) */
	NMFibRuleUidRange uid_range;         /* FRA_UID_RANGE */
	NMFibRulePortRange sport_range;      /* FRA_SPORT_RANGE */
	NMFibRulePortRange dport_range;      /* FRA_DPORT_RANGE */
	char     iifname[NMP_IFNAMSIZ];      /* FRA_IIFNAME */
	char     oifname[NMP_IFNAMSIZ];      /* FRA_OIFNAME */
	guint8   addr_family;                /* (struct fib_rule_hdr).family */
	guint8   action;                     /* (struct fib_rule_hdr).action */
	guint8   tos;                        /* (struct fib_rule_hdr).tos */
	guint8   src_len;                    /* (struct fib_rule_hdr).src_len */
	guint8   dst_len;                    /* (struct fib_rule_hdr).dst_len */
	guint8   l3mdev;                     /* FRA_L3MDEV */
	guint8   protocol;                   /* FRA_PROTOCOL */
	guint8   ip_proto;                   /* FRA_IP_PROTO */

	bool     uid_range_has:1;            /* has(FRA_UID_RANGE) */
} NMPlatformRoutingRule;

#define NM_PLATFORM_FQ_CODEL_MEMORY_LIMIT_UNSET   (~((guint32) 0))

#define NM_PLATFORM_FQ_CODEL_CE_THRESHOLD_DISABLED ((guint32) 0x83126E97u)

G_STATIC_ASSERT (((((guint64) NM_PLATFORM_FQ_CODEL_CE_THRESHOLD_DISABLED) * 1000u) >> 10) == (guint64) INT_MAX);

typedef struct {
	guint32 limit;
	guint32 flows;
	guint32 target;
	guint32 interval;
	guint32 quantum;
	guint32 ce_threshold; /* TCA_FQ_CODEL_CE_THRESHOLD: kernel internally stores this value as
	                       *   ((val64 * NSEC_PER_USEC) >> CODEL_SHIFT). The default value (in
	                       *   the domain with this coersion) is CODEL_DISABLED_THRESHOLD (INT_MAX).
	                       *   That means, "disabled" is expressed on RTM_NEWQDISC netlink API by absence of the
	                       *   netlink attribute but also as the special value 0x83126E97u
	                       *   (NM_PLATFORM_FQ_CODEL_CE_THRESHOLD_DISABLED).
	                       *   Beware: zero is not the default you must always explicitly set this value. */
	guint32 memory_limit; /* TCA_FQ_CODEL_MEMORY_LIMIT: note that only values <= 2^31 are accepted by kernel
	                       *   and kernel defaults to 32MB.
	                       *   Note that we use the special value NM_PLATFORM_FQ_CODEL_MEMORY_LIMIT_UNSET
	                       *   to indicate that no explicit limit is set (when we send a RTM_NEWQDISC request).
	                       *   This will cause kernel to choose the default (32MB).
	                       *   Beware: zero is not the default you must always explicitly set this value. */
	bool ecn:1;
} NMPlatformQdiscFqCodel;

typedef struct {
	__NMPlatformObjWithIfindex_COMMON;

	/* beware, kind is embedded in an NMPObject, hence you must
	 * take care of the lifetime of the string. */
	const char *kind;

	int addr_family;
	guint32 handle;
	guint32 parent;
	guint32 info;
	union {
		NMPlatformQdiscFqCodel fq_codel;
	};
} NMPlatformQdisc;

typedef struct {
	char sdata[32];
} NMPlatformActionSimple;

typedef struct {
	int ifindex;
	bool egress:1;
	bool ingress:1;
	bool mirror:1;
	bool redirect:1;
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

	int addr_family;
	guint32 handle;
	guint32 parent;
	guint32 info;
	NMPlatformAction action;
} NMPlatformTfilter;

#undef __NMPlatformObjWithIfindex_COMMON

typedef struct {
	gboolean is_ip4;
	NMPObjectType obj_type;
	int addr_family;
	gsize sizeof_route;
	int (*route_cmp) (const NMPlatformIPXRoute *a, const NMPlatformIPXRoute *b, NMPlatformIPRouteCmpType cmp_type);
	const char *(*route_to_string) (const NMPlatformIPXRoute *route, char *buf, gsize len);
	guint32 (*metric_normalize) (guint32 metric);
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
	bool proto_ad:1;
} NMPlatformVFVlan;

typedef struct {
	guint32 index;
	guint32 min_tx_rate;
	guint32 max_tx_rate;
	guint num_vlans;
	NMPlatformVFVlan *vlans;
	struct {
		guint8 data[20]; /* NM_UTILS_HWADDR_LEN_MAX */
		guint8 len;
	} mac;
	gint8 spoofchk;
	gint8 trust;
} NMPlatformVF;

typedef struct {
	guint16 vid_start;
	guint16 vid_end;
	bool untagged:1;
	bool pvid:1;
} NMPlatformBridgeVlan;

typedef struct {
	in_addr_t local;
	in_addr_t remote;
	int parent_ifindex;
	guint16 input_flags;
	guint16 output_flags;
	guint32 input_key;
	guint32 output_key;
	guint8 ttl;
	guint8 tos;
	bool path_mtu_discovery:1;
	bool is_tap:1;
} NMPlatformLnkGre;

typedef struct {
	int p_key;
	const char *mode;
} NMPlatformLnkInfiniband;

typedef struct {
	struct in6_addr local;
	struct in6_addr remote;
	int parent_ifindex;
	guint8 ttl;
	guint8 tclass;
	guint8 encap_limit;
	guint8 proto;
	guint flow_label;
	guint32 flags;

	/* IP6GRE only */
	guint32 input_key;
	guint32 output_key;
	guint16 input_flags;
	guint16 output_flags;
	bool is_tap:1;
	bool is_gre:1;
} NMPlatformLnkIp6Tnl;

typedef struct {
	in_addr_t local;
	in_addr_t remote;
	int parent_ifindex;
	guint8 ttl;
	guint8 tos;
	bool path_mtu_discovery:1;
} NMPlatformLnkIpIp;

typedef struct {
	int parent_ifindex;
	guint64 sci;                    /* host byte order */
	guint64 cipher_suite;
	guint32 window;
	guint8 icv_length;
	guint8 encoding_sa;
	guint8 validation;
	bool encrypt:1;
	bool protect:1;
	bool include_sci:1;
	bool es:1;
	bool scb:1;
	bool replay_protect:1;
} NMPlatformLnkMacsec;

typedef struct {
	guint mode;
	bool no_promisc:1;
	bool tap:1;
} NMPlatformLnkMacvlan;

typedef NMPlatformLnkMacvlan NMPlatformLnkMacvtap;

typedef struct {
	in_addr_t local;
	in_addr_t remote;
	int parent_ifindex;
	guint16 flags;
	guint8 ttl;
	guint8 tos;
	guint8 proto;
	bool path_mtu_discovery:1;
} NMPlatformLnkSit;

typedef struct {
	guint32 owner;
	guint32 group;

	guint8 type;

	bool owner_valid:1;
	bool group_valid:1;

	bool pi:1;
	bool vnet_hdr:1;
	bool multi_queue:1;
	bool persist:1;
} NMPlatformLnkTun;

typedef struct {
	/* rtnl_link_vlan_get_id(), IFLA_VLAN_ID */
	guint16 id;
	NMVlanFlags flags;
} NMPlatformLnkVlan;

typedef struct {
	struct in6_addr group6;
	struct in6_addr local6;
	in_addr_t group;
	in_addr_t local;
	int parent_ifindex;
	guint32 id;
	guint32 ageing;
	guint32 limit;
	guint16 dst_port;
	guint16 src_port_min;
	guint16 src_port_max;
	guint8 tos;
	guint8 ttl;
	bool learning:1;
	bool proxy:1;
	bool rsc:1;
	bool l2miss:1;
	bool l3miss:1;
} NMPlatformLnkVxlan;

#define NMP_WIREGUARD_PUBLIC_KEY_LEN 32
#define NMP_WIREGUARD_SYMMETRIC_KEY_LEN 32

typedef struct {
	guint32 fwmark;
	guint16 listen_port;
	guint8 private_key[NMP_WIREGUARD_PUBLIC_KEY_LEN];
	guint8 public_key[NMP_WIREGUARD_PUBLIC_KEY_LEN];
} NMPlatformLnkWireGuard;

typedef enum {
	NM_PLATFORM_LINK_DUPLEX_UNKNOWN,
	NM_PLATFORM_LINK_DUPLEX_HALF,
	NM_PLATFORM_LINK_DUPLEX_FULL,
} NMPlatformLinkDuplexType;

typedef enum {
	NM_PLATFORM_WIREGUARD_CHANGE_FLAG_NONE                        = 0,
	NM_PLATFORM_WIREGUARD_CHANGE_FLAG_REPLACE_PEERS               = (1LL << 0),
	NM_PLATFORM_WIREGUARD_CHANGE_FLAG_HAS_PRIVATE_KEY             = (1LL << 1),
	NM_PLATFORM_WIREGUARD_CHANGE_FLAG_HAS_LISTEN_PORT             = (1LL << 2),
	NM_PLATFORM_WIREGUARD_CHANGE_FLAG_HAS_FWMARK                  = (1LL << 3),
} NMPlatformWireGuardChangeFlags;

typedef enum {
	NM_PLATFORM_WIREGUARD_CHANGE_PEER_FLAG_NONE                   = 0,
	NM_PLATFORM_WIREGUARD_CHANGE_PEER_FLAG_REMOVE_ME              = (1LL << 0),
	NM_PLATFORM_WIREGUARD_CHANGE_PEER_FLAG_HAS_PRESHARED_KEY      = (1LL << 1),
	NM_PLATFORM_WIREGUARD_CHANGE_PEER_FLAG_HAS_KEEPALIVE_INTERVAL = (1LL << 2),
	NM_PLATFORM_WIREGUARD_CHANGE_PEER_FLAG_HAS_ENDPOINT           = (1LL << 3),
	NM_PLATFORM_WIREGUARD_CHANGE_PEER_FLAG_HAS_ALLOWEDIPS         = (1LL << 4),
	NM_PLATFORM_WIREGUARD_CHANGE_PEER_FLAG_REPLACE_ALLOWEDIPS     = (1LL << 5),

	NM_PLATFORM_WIREGUARD_CHANGE_PEER_FLAG_DEFAULT =   NM_PLATFORM_WIREGUARD_CHANGE_PEER_FLAG_HAS_PRESHARED_KEY
	                                                 | NM_PLATFORM_WIREGUARD_CHANGE_PEER_FLAG_HAS_KEEPALIVE_INTERVAL
	                                                 | NM_PLATFORM_WIREGUARD_CHANGE_PEER_FLAG_HAS_ENDPOINT
	                                                 | NM_PLATFORM_WIREGUARD_CHANGE_PEER_FLAG_HAS_ALLOWEDIPS,

} NMPlatformWireGuardChangePeerFlags;

typedef void (*NMPlatformAsyncCallback) (GError *error, gpointer user_data);

/*****************************************************************************/

typedef enum {
	NM_PLATFORM_KERNEL_SUPPORT_TYPE_EXTENDED_IFA_FLAGS,
	NM_PLATFORM_KERNEL_SUPPORT_TYPE_USER_IPV6LL,
	NM_PLATFORM_KERNEL_SUPPORT_TYPE_RTA_PREF,
	NM_PLATFORM_KERNEL_SUPPORT_TYPE_FRA_L3MDEV,
	NM_PLATFORM_KERNEL_SUPPORT_TYPE_FRA_UID_RANGE,
	NM_PLATFORM_KERNEL_SUPPORT_TYPE_FRA_PROTOCOL,

	/* this also includes FRA_SPORT_RANGE and FRA_DPORT_RANGE which
	 * were added at the same time. */
	NM_PLATFORM_KERNEL_SUPPORT_TYPE_FRA_IP_PROTO,

	_NM_PLATFORM_KERNEL_SUPPORT_NUM,
} NMPlatformKernelSupportType;

extern volatile int _nm_platform_kernel_support_state[_NM_PLATFORM_KERNEL_SUPPORT_NUM];

int _nm_platform_kernel_support_init (NMPlatformKernelSupportType type,
                                      int value);

static inline gboolean
_nm_platform_kernel_support_detected (NMPlatformKernelSupportType type)
{
	nm_assert (   _NM_INT_NOT_NEGATIVE (type)
	           && type < G_N_ELEMENTS (_nm_platform_kernel_support_state));

	return G_LIKELY (_nm_platform_kernel_support_state[type] != 0);
}

static inline gboolean
nm_platform_kernel_support_get (NMPlatformKernelSupportType type)
{
	int v;

	nm_assert (_NM_INT_NOT_NEGATIVE (type)
	           && type < G_N_ELEMENTS (_nm_platform_kernel_support_state));

	v = _nm_platform_kernel_support_state[type];
	if (G_UNLIKELY (v == 0))
		v = _nm_platform_kernel_support_init (type, 0);
	return (v >= 0);
}

/*****************************************************************************/

struct _NMPlatformPrivate;

struct _NMPlatform {
	GObject parent;
	NMPNetns *_netns;
	struct _NMPlatformPrivate *_priv;
};

typedef struct {
	GObjectClass parent;

	gboolean (*sysctl_set) (NMPlatform *self, const char *pathid, int dirfd, const char *path, const char *value);
	void (*sysctl_set_async)  (NMPlatform *self,
	                           const char *pathid,
	                           int dirfd,
	                           const char *path,
	                           const char *const *values,
	                           NMPlatformAsyncCallback callback,
	                           gpointer data,
	                           GCancellable *cancellable);
	char * (*sysctl_get) (NMPlatform *self, const char *pathid, int dirfd, const char *path);

	void (*refresh_all) (NMPlatform *self, NMPObjectType obj_type);
	void (*process_events) (NMPlatform *self);

	int (*link_add) (NMPlatform *self,
	                 const char *name,
	                 NMLinkType type,
	                 const char *veth_peer,
	                 const void *address,
	                 size_t address_len,
	                 const NMPlatformLink **out_link);
	gboolean (*link_delete) (NMPlatform *self, int ifindex);
	gboolean (*link_refresh) (NMPlatform *self, int ifindex);
	gboolean (*link_set_netns) (NMPlatform *self, int ifindex, int netns_fd);
	gboolean (*link_set_up) (NMPlatform *self, int ifindex, gboolean *out_no_firmware);
	gboolean (*link_set_down) (NMPlatform *self, int ifindex);
	gboolean (*link_set_arp) (NMPlatform *self, int ifindex);
	gboolean (*link_set_noarp) (NMPlatform *self, int ifindex);

	const char *(*link_get_udi) (NMPlatform *self, int ifindex);
	struct udev_device *(*link_get_udev_device) (NMPlatform *self, int ifindex);

	int (*link_set_user_ipv6ll_enabled) (NMPlatform *self, int ifindex, gboolean enabled);
	gboolean (*link_set_token) (NMPlatform *self, int ifindex, NMUtilsIPv6IfaceId iid);

	gboolean (*link_get_permanent_address) (NMPlatform *self,
	                                        int ifindex,
	                                        guint8 *buf,
	                                        size_t *length);
	int (*link_set_address) (NMPlatform *self, int ifindex, gconstpointer address, size_t length);
	int (*link_set_mtu) (NMPlatform *self, int ifindex, guint32 mtu);
	gboolean (*link_set_name) (NMPlatform *self, int ifindex, const char *name);
	void (*link_set_sriov_params_async) (NMPlatform *self,
	                                     int ifindex,
	                                     guint num_vfs,
	                                     int autoprobe,
	                                     NMPlatformAsyncCallback callback,
	                                     gpointer callback_data,
	                                     GCancellable *cancellable);
	gboolean (*link_set_sriov_vfs) (NMPlatform *self, int ifindex, const NMPlatformVF *const *vfs);
	gboolean (*link_set_bridge_vlans) (NMPlatform *self, int ifindex, gboolean on_master, const NMPlatformBridgeVlan *const *vlans);

	char *   (*link_get_physical_port_id) (NMPlatform *self, int ifindex);
	guint    (*link_get_dev_id) (NMPlatform *self, int ifindex);
	gboolean (*link_get_wake_on_lan) (NMPlatform *self, int ifindex);
	gboolean (*link_get_driver_info) (NMPlatform *self,
	                                  int ifindex,
	                                  char **out_driver_name,
	                                  char **out_driver_version,
	                                  char **out_fw_version);

	gboolean (*link_supports_carrier_detect) (NMPlatform *self, int ifindex);
	gboolean (*link_supports_vlans) (NMPlatform *self, int ifindex);
	gboolean (*link_supports_sriov) (NMPlatform *self, int ifindex);

	gboolean (*link_enslave) (NMPlatform *self, int master, int slave);
	gboolean (*link_release) (NMPlatform *self, int master, int slave);

	gboolean (*link_can_assume) (NMPlatform *self, int ifindex);

	int (*link_wireguard_change) (NMPlatform *self,
	                              int ifindex,
	                              const NMPlatformLnkWireGuard *lnk_wireguard,
	                              const struct _NMPWireGuardPeer *peers,
	                              const NMPlatformWireGuardChangePeerFlags *peer_flags,
	                              guint peers_len,
	                              NMPlatformWireGuardChangeFlags change_flags);

	gboolean (*vlan_add) (NMPlatform *self, const char *name, int parent, int vlanid, guint32 vlanflags, const NMPlatformLink **out_link);
	gboolean (*link_vlan_change) (NMPlatform *self,
	                              int ifindex,
	                              NMVlanFlags flags_mask,
	                              NMVlanFlags flags_set,
	                              gboolean ingress_reset_all,
	                              const NMVlanQosMapping *ingress_map,
	                              gsize n_ingress_map,
	                              gboolean egress_reset_all,
	                              const NMVlanQosMapping *egress_map,
	                              gsize n_egress_map);
	gboolean (*link_vxlan_add) (NMPlatform *self,
	                            const char *name,
	                            const NMPlatformLnkVxlan *props,
	                            const NMPlatformLink **out_link);
	gboolean (*link_gre_add) (NMPlatform *self,
	                          const char *name,
	                          const NMPlatformLnkGre *props,
	                          const NMPlatformLink **out_link);
	gboolean (*link_ip6tnl_add) (NMPlatform *self,
	                             const char *name,
	                             const NMPlatformLnkIp6Tnl *props,
	                             const NMPlatformLink **out_link);
	gboolean (*link_ip6gre_add) (NMPlatform *self,
	                             const char *name,
	                             const NMPlatformLnkIp6Tnl *props,
	                             const NMPlatformLink **out_link);
	gboolean (*link_ipip_add) (NMPlatform *self,
	                           const char *name,
	                           const NMPlatformLnkIpIp *props,
	                           const NMPlatformLink **out_link);
	gboolean (*link_macsec_add) (NMPlatform *self,
	                             const char *name,
	                             int parent,
	                             const NMPlatformLnkMacsec *props,
	                             const NMPlatformLink **out_link);
	gboolean (*link_macvlan_add) (NMPlatform *self,
	                              const char *name,
	                              int parent,
	                              const NMPlatformLnkMacvlan *props,
	                              const NMPlatformLink **out_link);
	gboolean (*link_sit_add) (NMPlatform *self,
	                          const char *name,
	                          const NMPlatformLnkSit *props,
	                          const NMPlatformLink **out_link);
	gboolean (*link_tun_add) (NMPlatform *self,
	                          const char *name,
	                          const NMPlatformLnkTun *props,
	                          const NMPlatformLink **out_link,
	                          int *out_fd);
	gboolean (*link_6lowpan_add) (NMPlatform *self,
	                              const char *name,
	                              int parent,
	                              const NMPlatformLink **out_link);

	gboolean (*infiniband_partition_add) (NMPlatform *self, int parent, int p_key, const NMPlatformLink **out_link);
	gboolean (*infiniband_partition_delete) (NMPlatform *self, int parent, int p_key);

	gboolean    (*wifi_get_capabilities) (NMPlatform *self, int ifindex, NMDeviceWifiCapabilities *caps);
	gboolean    (*wifi_get_bssid)        (NMPlatform *self, int ifindex, guint8 *bssid);
	guint32     (*wifi_get_frequency)    (NMPlatform *self, int ifindex);
	int         (*wifi_get_quality)      (NMPlatform *self, int ifindex);
	guint32     (*wifi_get_rate)         (NMPlatform *self, int ifindex);
	NM80211Mode (*wifi_get_mode)         (NMPlatform *self, int ifindex);
	void        (*wifi_set_mode)         (NMPlatform *self, int ifindex, NM80211Mode mode);
	void        (*wifi_set_powersave)    (NMPlatform *self, int ifindex, guint32 powersave);
	guint32     (*wifi_find_frequency)   (NMPlatform *self, int ifindex, const guint32 *freqs);
	void        (*wifi_indicate_addressing_running) (NMPlatform *self, int ifindex, gboolean running);
	NMSettingWirelessWakeOnWLan (*wifi_get_wake_on_wlan) (NMPlatform *self, int ifindex);
	gboolean    (*wifi_set_wake_on_wlan) (NMPlatform *self, int ifindex, NMSettingWirelessWakeOnWLan wowl);

	guint32     (*mesh_get_channel)      (NMPlatform *self, int ifindex);
	gboolean    (*mesh_set_channel)      (NMPlatform *self, int ifindex, guint32 channel);
	gboolean    (*mesh_set_ssid)         (NMPlatform *self, int ifindex, const guint8 *ssid, gsize len);

	guint16     (*wpan_get_pan_id)       (NMPlatform *self, int ifindex);
	gboolean    (*wpan_set_pan_id)       (NMPlatform *self, int ifindex, guint16 pan_id);
	guint16     (*wpan_get_short_addr)   (NMPlatform *self, int ifindex);
	gboolean    (*wpan_set_short_addr)   (NMPlatform *self, int ifindex, guint16 short_addr);
	gboolean    (*wpan_set_channel)      (NMPlatform *self, int ifindex, guint8 page, guint8 channel);

	gboolean (*object_delete) (NMPlatform *self, const NMPObject *obj);

	gboolean (*ip4_address_add) (NMPlatform *self,
	                             int ifindex,
	                             in_addr_t address,
	                             guint8 plen,
	                             in_addr_t peer_address,
	                             guint32 lifetime,
	                             guint32 preferred_lft,
	                             guint32 flags,
	                             const char *label);
	gboolean (*ip6_address_add) (NMPlatform *self,
	                             int ifindex,
	                             struct in6_addr address,
	                             guint8 plen,
	                             struct in6_addr peer_address,
	                             guint32 lifetime,
	                             guint32 preferred_lft,
	                             guint32 flags);
	gboolean (*ip4_address_delete) (NMPlatform *self, int ifindex, in_addr_t address, guint8 plen, in_addr_t peer_address);
	gboolean (*ip6_address_delete) (NMPlatform *self, int ifindex, struct in6_addr address, guint8 plen);

	int (*ip_route_add) (NMPlatform *self,
	                     NMPNlmFlags flags,
	                     int addr_family,
	                     const NMPlatformIPRoute *route);
	int (*ip_route_get) (NMPlatform *self,
	                     int addr_family,
	                     gconstpointer address,
	                     int oif_ifindex,
	                     NMPObject **out_route);

	int (*routing_rule_add) (NMPlatform *self,
	                         NMPNlmFlags flags,
	                         const NMPlatformRoutingRule *routing_rule);

	int (*qdisc_add)   (NMPlatform *self,
	                    NMPNlmFlags flags,
	                    const NMPlatformQdisc *qdisc);

	int (*tfilter_add)   (NMPlatform *self,
	                      NMPNlmFlags flags,
	                      const NMPlatformTfilter *tfilter);
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
#define NM_PLATFORM_SIGNAL_LINK_CHANGED "link-changed"
#define NM_PLATFORM_SIGNAL_IP4_ADDRESS_CHANGED "ip4-address-changed"
#define NM_PLATFORM_SIGNAL_IP6_ADDRESS_CHANGED "ip6-address-changed"
#define NM_PLATFORM_SIGNAL_IP4_ROUTE_CHANGED "ip4-route-changed"
#define NM_PLATFORM_SIGNAL_IP6_ROUTE_CHANGED "ip6-route-changed"
#define NM_PLATFORM_SIGNAL_ROUTING_RULE_CHANGED "routing-rule-changed"
#define NM_PLATFORM_SIGNAL_QDISC_CHANGED "qdisc-changed"
#define NM_PLATFORM_SIGNAL_TFILTER_CHANGED "tfilter-changed"

const char *nm_platform_signal_change_type_to_string (NMPlatformSignalChangeType change_type);

/*****************************************************************************/

GType nm_platform_get_type (void);

void nm_platform_setup (NMPlatform *instance);
NMPlatform *nm_platform_get (void);

#define NM_PLATFORM_GET (nm_platform_get ())

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
nm_platform_route_table_coerce (guint32 table)
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
 * @table: the route table, in its coerced value
 * @normalize: whether to normalize RT_TABLE_UNSPEC to
 *   RT_TABLE_MAIN. For kernel, routes with a table id
 *   RT_TABLE_UNSPEC do not exist and are treated like
 *   RT_TABLE_MAIN.
 *
 * Returns: reverts the coerced table ID in NMPlatformIPRoute.table_coerced
 *   to the original value as kernel understands it.
 */
static inline guint32
nm_platform_route_table_uncoerce (guint32 table_coerced, gboolean normalize)
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
nm_platform_route_table_is_main (guint32 table)
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
_nm_platform_uint8_inv (guint8 scope)
{
	return (guint8) ~scope;
}

gboolean nm_platform_get_use_udev (NMPlatform *self);
gboolean nm_platform_get_log_with_ptr (NMPlatform *self);

NMPNetns *nm_platform_netns_get (NMPlatform *self);
gboolean nm_platform_netns_push (NMPlatform *self, NMPNetns **netns);

const char *nm_link_type_to_string (NMLinkType link_type);

#define NMP_SYSCTL_PATHID_ABSOLUTE(path) \
	((const char *) NULL), -1, (path)

#define NMP_SYSCTL_PATHID_NETDIR_unsafe(dirfd, ifname, path) \
	nm_sprintf_buf_unsafe_a (  NM_STRLEN ("net:/sys/class/net//\0") \
	                         + NMP_IFNAMSIZ \
	                         + ({ \
	                             const gsize _l = strlen (path); \
	                             \
	                             nm_assert (_l < 200); \
	                             _l; \
	                            }), \
	                         "net:/sys/class/net/%s/%s", (ifname), (path)), \
	(dirfd), (path)

#define NMP_SYSCTL_PATHID_NETDIR(dirfd, ifname, path) \
	nm_sprintf_bufa (NM_STRLEN ("net:/sys/class/net//"path"/\0") + NMP_IFNAMSIZ, \
	                 "net:/sys/class/net/%s/%s", (ifname), path), \
	(dirfd), (""path"")

int nm_platform_sysctl_open_netdir (NMPlatform *self, int ifindex, char *out_ifname);
gboolean nm_platform_sysctl_set (NMPlatform *self, const char *pathid, int dirfd, const char *path, const char *value);
void nm_platform_sysctl_set_async (NMPlatform *self,
                                   const char *pathid,
                                   int dirfd,
                                   const char *path,
                                   const char *const *values,
                                   NMPlatformAsyncCallback callback,
                                   gpointer data,
                                   GCancellable *cancellable);
char *nm_platform_sysctl_get (NMPlatform *self, const char *pathid, int dirfd, const char *path);
gint32 nm_platform_sysctl_get_int32 (NMPlatform *self, const char *pathid, int dirfd, const char *path, gint32 fallback);
gint64 nm_platform_sysctl_get_int_checked (NMPlatform *self, const char *pathid, int dirfd, const char *path, guint base, gint64 min, gint64 max, gint64 fallback);

char *nm_platform_sysctl_ip_conf_get (NMPlatform *self,
                                      int addr_family,
                                      const char *ifname,
                                      const char *property);

gint64 nm_platform_sysctl_ip_conf_get_int_checked (NMPlatform *self,
                                                   int addr_family,
                                                   const char *ifname,
                                                   const char *property,
                                                   guint base,
                                                   gint64 min,
                                                   gint64 max,
                                                   gint64 fallback);

gboolean nm_platform_sysctl_ip_conf_set (NMPlatform *self,
                                         int addr_family,
                                         const char *ifname,
                                         const char *property,
                                         const char *value);

gboolean nm_platform_sysctl_ip_conf_set_int64 (NMPlatform *self,
                                               int addr_family,
                                               const char *ifname,
                                               const char *property,
                                               gint64 value);

gboolean nm_platform_sysctl_ip_conf_set_ipv6_hop_limit_safe (NMPlatform *self,
                                                             const char *iface,
                                                             int value);
int nm_platform_sysctl_ip_conf_get_rp_filter_ipv4 (NMPlatform *platform,
                                                   const char *iface,
                                                   gboolean consider_all,
                                                   gboolean *out_due_to_all);

const char *nm_platform_if_indextoname (NMPlatform *self, int ifindex, char *out_ifname/* of size IFNAMSIZ */);
int nm_platform_if_nametoindex (NMPlatform *self, const char *ifname);

const NMPObject *nm_platform_link_get_obj (NMPlatform *self,
                                           int ifindex,
                                           gboolean visible_only);
const NMPlatformLink *nm_platform_link_get (NMPlatform *self, int ifindex);
const NMPlatformLink *nm_platform_link_get_by_ifname (NMPlatform *self, const char *ifname);
const NMPlatformLink *nm_platform_link_get_by_address (NMPlatform *self, NMLinkType link_type, gconstpointer address, size_t length);

GPtrArray *nm_platform_link_get_all (NMPlatform *self, gboolean sort_by_name);
int nm_platform_link_dummy_add (NMPlatform *self, const char *name, const NMPlatformLink **out_link);
int nm_platform_link_bridge_add (NMPlatform *self, const char *name, const void *address, size_t address_len, const NMPlatformLink **out_link);
int nm_platform_link_bond_add (NMPlatform *self, const char *name, const NMPlatformLink **out_link);
int nm_platform_link_team_add (NMPlatform *self, const char *name, const NMPlatformLink **out_link);
int nm_platform_link_veth_add (NMPlatform *self, const char *name, const char *peer, const NMPlatformLink **out_link);

gboolean nm_platform_link_delete (NMPlatform *self, int ifindex);

gboolean nm_platform_link_set_netns (NMPlatform *self, int ifindex, int netns_fd);

struct _NMDedupMultiHeadEntry;
struct _NMPLookup;
const struct _NMDedupMultiHeadEntry *nm_platform_lookup (NMPlatform *self,
                                                         const struct _NMPLookup *lookup);

gboolean nm_platform_lookup_predicate_routes_main (const NMPObject *obj,
                                                   gpointer user_data);
gboolean nm_platform_lookup_predicate_routes_main_skip_rtprot_kernel (const NMPObject *obj,
                                                                      gpointer user_data);

GPtrArray *nm_platform_lookup_clone (NMPlatform *self,
                                     const struct _NMPLookup *lookup,
                                     NMPObjectPredicateFunc predicate,
                                     gpointer user_data);

/* convenience methods to lookup the link and access fields of NMPlatformLink. */
int nm_platform_link_get_ifindex (NMPlatform *self, const char *name);
const char *nm_platform_link_get_name (NMPlatform *self, int ifindex);
NMLinkType nm_platform_link_get_type (NMPlatform *self, int ifindex);
gboolean nm_platform_link_is_software (NMPlatform *self, int ifindex);
int nm_platform_link_get_ifi_flags (NMPlatform *self, int ifindex, guint requested_flags);
gboolean nm_platform_link_is_up (NMPlatform *self, int ifindex);
gboolean nm_platform_link_is_connected (NMPlatform *self, int ifindex);
gboolean nm_platform_link_uses_arp (NMPlatform *self, int ifindex);
guint32 nm_platform_link_get_mtu (NMPlatform *self, int ifindex);
gboolean nm_platform_link_get_user_ipv6ll_enabled (NMPlatform *self, int ifindex);

gconstpointer nm_platform_link_get_address (NMPlatform *self, int ifindex, size_t *length);

static inline GBytes *
nm_platform_link_get_address_as_bytes (NMPlatform *self, int ifindex)
{
	gconstpointer p;
	gsize l;

	p = nm_platform_link_get_address (self, ifindex, &l);
	return p
	       ? g_bytes_new (p, l)
	       : NULL;
}

int nm_platform_link_get_master (NMPlatform *self, int slave);

gboolean nm_platform_link_can_assume (NMPlatform *self, int ifindex);

gboolean nm_platform_link_get_unmanaged (NMPlatform *self, int ifindex, gboolean *unmanaged);
gboolean nm_platform_link_supports_slaves (NMPlatform *self, int ifindex);
const char *nm_platform_link_get_type_name (NMPlatform *self, int ifindex);

gboolean nm_platform_link_refresh (NMPlatform *self, int ifindex);
void nm_platform_process_events (NMPlatform *self);

const NMPlatformLink *nm_platform_process_events_ensure_link (NMPlatform *self,
                                                              int ifindex,
                                                              const char *ifname);

gboolean nm_platform_link_set_up (NMPlatform *self, int ifindex, gboolean *out_no_firmware);
gboolean nm_platform_link_set_down (NMPlatform *self, int ifindex);
gboolean nm_platform_link_set_arp (NMPlatform *self, int ifindex);
gboolean nm_platform_link_set_noarp (NMPlatform *self, int ifindex);

const char *nm_platform_link_get_udi (NMPlatform *self, int ifindex);

struct udev_device *nm_platform_link_get_udev_device (NMPlatform *self, int ifindex);

int nm_platform_link_set_user_ipv6ll_enabled (NMPlatform *self, int ifindex, gboolean enabled);
gboolean nm_platform_link_set_ipv6_token (NMPlatform *self, int ifindex, NMUtilsIPv6IfaceId iid);

gboolean nm_platform_link_get_permanent_address (NMPlatform *self, int ifindex, guint8 *buf, size_t *length);
int nm_platform_link_set_address (NMPlatform *self, int ifindex, const void *address, size_t length);
int nm_platform_link_set_mtu (NMPlatform *self, int ifindex, guint32 mtu);
gboolean nm_platform_link_set_name (NMPlatform *self, int ifindex, const char *name);

void nm_platform_link_set_sriov_params_async (NMPlatform *self,
                                              int ifindex,
                                              guint num_vfs,
                                              int autoprobe,
                                              NMPlatformAsyncCallback callback,
                                              gpointer callback_data,
                                              GCancellable *cancellable);

gboolean nm_platform_link_set_sriov_vfs (NMPlatform *self, int ifindex, const NMPlatformVF *const *vfs);
gboolean nm_platform_link_set_bridge_vlans (NMPlatform *self, int ifindex, gboolean on_master, const NMPlatformBridgeVlan *const *vlans);

char    *nm_platform_link_get_physical_port_id (NMPlatform *self, int ifindex);
guint    nm_platform_link_get_dev_id (NMPlatform *self, int ifindex);
gboolean nm_platform_link_get_wake_on_lan (NMPlatform *self, int ifindex);
gboolean nm_platform_link_get_driver_info (NMPlatform *self,
                                           int ifindex,
                                           char **out_driver_name,
                                           char **out_driver_version,
                                           char **out_fw_version);

gboolean nm_platform_link_supports_carrier_detect (NMPlatform *self, int ifindex);
gboolean nm_platform_link_supports_vlans (NMPlatform *self, int ifindex);
gboolean nm_platform_link_supports_sriov (NMPlatform *self, int ifindex);

gboolean nm_platform_link_enslave (NMPlatform *self, int master, int slave);
gboolean nm_platform_link_release (NMPlatform *self, int master, int slave);

gboolean nm_platform_sysctl_master_set_option (NMPlatform *self, int ifindex, const char *option, const char *value);
char *nm_platform_sysctl_master_get_option (NMPlatform *self, int ifindex, const char *option);
gboolean nm_platform_sysctl_slave_set_option (NMPlatform *self, int ifindex, const char *option, const char *value);
char *nm_platform_sysctl_slave_get_option (NMPlatform *self, int ifindex, const char *option);

const NMPObject *nm_platform_link_get_lnk (NMPlatform *self, int ifindex, NMLinkType link_type, const NMPlatformLink **out_link);
const NMPlatformLnkGre *nm_platform_link_get_lnk_gre (NMPlatform *self, int ifindex, const NMPlatformLink **out_link);
const NMPlatformLnkGre *nm_platform_link_get_lnk_gretap (NMPlatform *self, int ifindex, const NMPlatformLink **out_link);
const NMPlatformLnkIp6Tnl *nm_platform_link_get_lnk_ip6tnl (NMPlatform *self, int ifindex, const NMPlatformLink **out_link);
const NMPlatformLnkIp6Tnl *nm_platform_link_get_lnk_ip6gre (NMPlatform *self, int ifindex, const NMPlatformLink **out_link);
const NMPlatformLnkIp6Tnl *nm_platform_link_get_lnk_ip6gretap (NMPlatform *self, int ifindex, const NMPlatformLink **out_link);
const NMPlatformLnkIpIp *nm_platform_link_get_lnk_ipip (NMPlatform *self, int ifindex, const NMPlatformLink **out_link);
const NMPlatformLnkInfiniband *nm_platform_link_get_lnk_infiniband (NMPlatform *self, int ifindex, const NMPlatformLink **out_link);
const NMPlatformLnkIpIp *nm_platform_link_get_lnk_ipip (NMPlatform *self, int ifindex, const NMPlatformLink **out_link);
const NMPlatformLnkMacsec *nm_platform_link_get_lnk_macsec (NMPlatform *self, int ifindex, const NMPlatformLink **out_link);
const NMPlatformLnkMacvlan *nm_platform_link_get_lnk_macvlan (NMPlatform *self, int ifindex, const NMPlatformLink **out_link);
const NMPlatformLnkMacvtap *nm_platform_link_get_lnk_macvtap (NMPlatform *self, int ifindex, const NMPlatformLink **out_link);
const NMPlatformLnkSit *nm_platform_link_get_lnk_sit (NMPlatform *self, int ifindex, const NMPlatformLink **out_link);
const NMPlatformLnkTun *nm_platform_link_get_lnk_tun (NMPlatform *self, int ifindex, const NMPlatformLink **out_link);
const NMPlatformLnkVlan *nm_platform_link_get_lnk_vlan (NMPlatform *self, int ifindex, const NMPlatformLink **out_link);
const NMPlatformLnkVxlan *nm_platform_link_get_lnk_vxlan (NMPlatform *self, int ifindex, const NMPlatformLink **out_link);
const NMPlatformLnkWireGuard *nm_platform_link_get_lnk_wireguard (NMPlatform *self, int ifindex, const NMPlatformLink **out_link);

int nm_platform_link_vlan_add (NMPlatform *self,
                               const char *name,
                               int parent,
                               int vlanid,
                               guint32 vlanflags,
                               const NMPlatformLink **out_link);
gboolean nm_platform_link_vlan_set_ingress_map (NMPlatform *self, int ifindex, int from, int to);
gboolean nm_platform_link_vlan_set_egress_map (NMPlatform *self, int ifindex, int from, int to);
gboolean nm_platform_link_vlan_change (NMPlatform *self,
                                       int ifindex,
                                       NMVlanFlags flags_mask,
                                       NMVlanFlags flags_set,
                                       gboolean ingress_reset_all,
                                       const NMVlanQosMapping *ingress_map,
                                       gsize n_ingress_map,
                                       gboolean egress_reset_all,
                                       const NMVlanQosMapping *egress_map,
                                       gsize n_egress_map);

int nm_platform_link_vxlan_add (NMPlatform *self,
                                const char *name,
                                const NMPlatformLnkVxlan *props,
                                const NMPlatformLink **out_link);

int nm_platform_link_infiniband_add (NMPlatform *self,
                                     int parent,
                                     int p_key,
                                     const NMPlatformLink **out_link);
int nm_platform_link_infiniband_delete (NMPlatform *self,
                                        int parent,
                                        int p_key);
gboolean nm_platform_link_infiniband_get_properties (NMPlatform *self, int ifindex, int *parent, int *p_key, const char **mode);

gboolean nm_platform_link_veth_get_properties   (NMPlatform *self, int ifindex, int *out_peer_ifindex);
gboolean nm_platform_link_tun_get_properties    (NMPlatform *self,
                                                 int ifindex,
                                                 NMPlatformLnkTun *out_properties);

gboolean    nm_platform_wifi_get_capabilities (NMPlatform *self, int ifindex, NMDeviceWifiCapabilities *caps);
gboolean    nm_platform_wifi_get_bssid        (NMPlatform *self, int ifindex, guint8 *bssid);
guint32     nm_platform_wifi_get_frequency    (NMPlatform *self, int ifindex);
int         nm_platform_wifi_get_quality      (NMPlatform *self, int ifindex);
guint32     nm_platform_wifi_get_rate         (NMPlatform *self, int ifindex);
NM80211Mode nm_platform_wifi_get_mode         (NMPlatform *self, int ifindex);
void        nm_platform_wifi_set_mode         (NMPlatform *self, int ifindex, NM80211Mode mode);
void        nm_platform_wifi_set_powersave    (NMPlatform *self, int ifindex, guint32 powersave);
guint32     nm_platform_wifi_find_frequency   (NMPlatform *self, int ifindex, const guint32 *freqs);
void        nm_platform_wifi_indicate_addressing_running (NMPlatform *self, int ifindex, gboolean running);
NMSettingWirelessWakeOnWLan nm_platform_wifi_get_wake_on_wlan (NMPlatform *self, int ifindex);
gboolean    nm_platform_wifi_set_wake_on_wlan (NMPlatform *self, int ifindex, NMSettingWirelessWakeOnWLan wowl);

guint32     nm_platform_mesh_get_channel      (NMPlatform *self, int ifindex);
gboolean    nm_platform_mesh_set_channel      (NMPlatform *self, int ifindex, guint32 channel);
gboolean    nm_platform_mesh_set_ssid         (NMPlatform *self, int ifindex, const guint8 *ssid, gsize len);

guint16     nm_platform_wpan_get_pan_id       (NMPlatform *self, int ifindex);
gboolean    nm_platform_wpan_set_pan_id       (NMPlatform *self, int ifindex, guint16 pan_id);
guint16     nm_platform_wpan_get_short_addr   (NMPlatform *self, int ifindex);
gboolean    nm_platform_wpan_set_short_addr   (NMPlatform *self, int ifindex, guint16 short_addr);
gboolean    nm_platform_wpan_set_channel      (NMPlatform *self, int ifindex, guint8 page, guint8 channel);

void                   nm_platform_ip4_address_set_addr (NMPlatformIP4Address *addr, in_addr_t address, guint8 plen);
const struct in6_addr *nm_platform_ip6_address_get_peer (const NMPlatformIP6Address *addr);

const NMPlatformIP4Address *nm_platform_ip4_address_get (NMPlatform *self, int ifindex, in_addr_t address, guint8 plen, in_addr_t peer_address);

int nm_platform_link_gre_add (NMPlatform *self,
                              const char *name,
                              const NMPlatformLnkGre *props,
                              const NMPlatformLink **out_link);
int nm_platform_link_ip6tnl_add (NMPlatform *self,
                                 const char *name,
                                 const NMPlatformLnkIp6Tnl *props,
                                 const NMPlatformLink **out_link);
int nm_platform_link_ip6gre_add (NMPlatform *self,
                                 const char *name,
                                 const NMPlatformLnkIp6Tnl *props,
                                 const NMPlatformLink **out_link);
int nm_platform_link_ipip_add (NMPlatform *self,
                               const char *name,
                               const NMPlatformLnkIpIp *props,
                               const NMPlatformLink **out_link);
int nm_platform_link_macsec_add (NMPlatform *self,
                                 const char *name,
                                 int parent,
                                 const NMPlatformLnkMacsec *props,
                                 const NMPlatformLink **out_link);
int nm_platform_link_macvlan_add (NMPlatform *self,
                                  const char *name,
                                  int parent,
                                  const NMPlatformLnkMacvlan *props,
                                  const NMPlatformLink **out_link);
int nm_platform_link_sit_add (NMPlatform *self,
                              const char *name,
                              const NMPlatformLnkSit *props,
                              const NMPlatformLink **out_link);
int nm_platform_link_tun_add (NMPlatform *self,
                              const char *name,
                              const NMPlatformLnkTun *props,
                              const NMPlatformLink **out_link,
                              int *out_fd);
int nm_platform_link_6lowpan_add (NMPlatform *self,
                                  const char *name,
                                  int parent,
                                  const NMPlatformLink **out_link);
gboolean nm_platform_link_6lowpan_get_properties (NMPlatform *self,
                                                  int ifindex,
                                                  int *out_parent);

int nm_platform_link_wireguard_add (NMPlatform *self,
                                    const char *name,
                                    const NMPlatformLink **out_link);

int nm_platform_link_wireguard_change (NMPlatform *self,
                                       int ifindex,
                                       const NMPlatformLnkWireGuard *lnk_wireguard,
                                       const struct _NMPWireGuardPeer *peers,
                                       const NMPlatformWireGuardChangePeerFlags *peer_flags,
                                       guint peers_len,
                                       NMPlatformWireGuardChangeFlags change_flags);

const NMPlatformIP6Address *nm_platform_ip6_address_get (NMPlatform *self, int ifindex, struct in6_addr address);

gboolean nm_platform_object_delete (NMPlatform *self, const NMPObject *route);

gboolean nm_platform_ip4_address_add (NMPlatform *self,
                                      int ifindex,
                                      in_addr_t address,
                                      guint8 plen,
                                      in_addr_t peer_address,
                                      guint32 lifetime,
                                      guint32 preferred_lft,
                                      guint32 flags,
                                      const char *label);
gboolean nm_platform_ip6_address_add (NMPlatform *self,
                                      int ifindex,
                                      struct in6_addr address,
                                      guint8 plen,
                                      struct in6_addr peer_address,
                                      guint32 lifetime,
                                      guint32 preferred_lft,
                                      guint32 flags);
gboolean nm_platform_ip4_address_delete (NMPlatform *self, int ifindex, in_addr_t address, guint8 plen, in_addr_t peer_address);
gboolean nm_platform_ip6_address_delete (NMPlatform *self, int ifindex, struct in6_addr address, guint8 plen);
gboolean nm_platform_ip4_address_sync (NMPlatform *self, int ifindex, GPtrArray *known_addresses);
gboolean nm_platform_ip6_address_sync (NMPlatform *self, int ifindex, GPtrArray *known_addresses, gboolean full_sync);
gboolean nm_platform_ip_address_flush (NMPlatform *self,
                                       int addr_family,
                                       int ifindex);

void nm_platform_ip_route_normalize (int addr_family,
                                     NMPlatformIPRoute *route);

int nm_platform_ip_route_add (NMPlatform *self,
                              NMPNlmFlags flags,
                              const NMPObject *route);
int nm_platform_ip4_route_add (NMPlatform *self, NMPNlmFlags flags, const NMPlatformIP4Route *route);
int nm_platform_ip6_route_add (NMPlatform *self, NMPNlmFlags flags, const NMPlatformIP6Route *route);

GPtrArray *nm_platform_ip_route_get_prune_list (NMPlatform *self,
                                                int addr_family,
                                                int ifindex,
                                                NMIPRouteTableSyncMode route_table_sync);

gboolean nm_platform_ip_route_sync (NMPlatform *self,
                                    int addr_family,
                                    int ifindex,
                                    GPtrArray *routes,
                                    GPtrArray *routes_prune,
                                    GPtrArray **out_temporary_not_available);

gboolean nm_platform_ip_route_flush (NMPlatform *self,
                                     int addr_family,
                                     int ifindex);

int nm_platform_ip_route_get (NMPlatform *self,
                              int addr_family,
                              gconstpointer address,
                              int oif_ifindex,
                              NMPObject **out_route);

int nm_platform_routing_rule_add (NMPlatform *self,
                                  NMPNlmFlags flags,
                                  const NMPlatformRoutingRule *routing_rule);

int nm_platform_qdisc_add   (NMPlatform *self,
                             NMPNlmFlags flags,
                             const NMPlatformQdisc *qdisc);
gboolean nm_platform_qdisc_sync         (NMPlatform *self,
                                         int ifindex,
                                         GPtrArray *known_qdiscs);

int nm_platform_tfilter_add   (NMPlatform *self,
                               NMPNlmFlags flags,
                               const NMPlatformTfilter *tfilter);
gboolean nm_platform_tfilter_sync         (NMPlatform *self,
                                           int ifindex,
                                           GPtrArray *known_tfilters);

const char *nm_platform_link_to_string (const NMPlatformLink *link, char *buf, gsize len);
const char *nm_platform_lnk_gre_to_string (const NMPlatformLnkGre *lnk, char *buf, gsize len);
const char *nm_platform_lnk_infiniband_to_string (const NMPlatformLnkInfiniband *lnk, char *buf, gsize len);
const char *nm_platform_lnk_ip6tnl_to_string (const NMPlatformLnkIp6Tnl *lnk, char *buf, gsize len);
const char *nm_platform_lnk_ipip_to_string (const NMPlatformLnkIpIp *lnk, char *buf, gsize len);
const char *nm_platform_lnk_macsec_to_string (const NMPlatformLnkMacsec *lnk, char *buf, gsize len);
const char *nm_platform_lnk_macvlan_to_string (const NMPlatformLnkMacvlan *lnk, char *buf, gsize len);
const char *nm_platform_lnk_sit_to_string (const NMPlatformLnkSit *lnk, char *buf, gsize len);
const char *nm_platform_lnk_tun_to_string (const NMPlatformLnkTun *lnk, char *buf, gsize len);
const char *nm_platform_lnk_vlan_to_string (const NMPlatformLnkVlan *lnk, char *buf, gsize len);
const char *nm_platform_lnk_vxlan_to_string (const NMPlatformLnkVxlan *lnk, char *buf, gsize len);
const char *nm_platform_lnk_wireguard_to_string (const NMPlatformLnkWireGuard *lnk, char *buf, gsize len);
const char *nm_platform_ip4_address_to_string (const NMPlatformIP4Address *address, char *buf, gsize len);
const char *nm_platform_ip6_address_to_string (const NMPlatformIP6Address *address, char *buf, gsize len);
const char *nm_platform_ip4_route_to_string (const NMPlatformIP4Route *route, char *buf, gsize len);
const char *nm_platform_ip6_route_to_string (const NMPlatformIP6Route *route, char *buf, gsize len);
const char *nm_platform_routing_rule_to_string (const NMPlatformRoutingRule *routing_rule, char *buf, gsize len);
const char *nm_platform_qdisc_to_string (const NMPlatformQdisc *qdisc, char *buf, gsize len);
const char *nm_platform_tfilter_to_string (const NMPlatformTfilter *tfilter, char *buf, gsize len);
const char *nm_platform_vf_to_string (const NMPlatformVF *vf, char *buf, gsize len);
const char *nm_platform_bridge_vlan_to_string (const NMPlatformBridgeVlan *vlan, char *buf, gsize len);

const char *nm_platform_vlan_qos_mapping_to_string (const char *name,
                                                    const NMVlanQosMapping *map,
                                                    gsize n_map,
                                                    char *buf,
                                                    gsize len);

const char *nm_platform_wireguard_peer_to_string (const struct _NMPWireGuardPeer *peer,
                                                  char *buf,
                                                  gsize len);

int nm_platform_link_cmp (const NMPlatformLink *a, const NMPlatformLink *b);
int nm_platform_lnk_gre_cmp (const NMPlatformLnkGre *a, const NMPlatformLnkGre *b);
int nm_platform_lnk_infiniband_cmp (const NMPlatformLnkInfiniband *a, const NMPlatformLnkInfiniband *b);
int nm_platform_lnk_ip6tnl_cmp (const NMPlatformLnkIp6Tnl *a, const NMPlatformLnkIp6Tnl *b);
int nm_platform_lnk_ipip_cmp (const NMPlatformLnkIpIp *a, const NMPlatformLnkIpIp *b);
int nm_platform_lnk_macsec_cmp (const NMPlatformLnkMacsec *a, const NMPlatformLnkMacsec *b);
int nm_platform_lnk_macvlan_cmp (const NMPlatformLnkMacvlan *a, const NMPlatformLnkMacvlan *b);
int nm_platform_lnk_sit_cmp (const NMPlatformLnkSit *a, const NMPlatformLnkSit *b);
int nm_platform_lnk_tun_cmp (const NMPlatformLnkTun *a, const NMPlatformLnkTun *b);
int nm_platform_lnk_vlan_cmp (const NMPlatformLnkVlan *a, const NMPlatformLnkVlan *b);
int nm_platform_lnk_vxlan_cmp (const NMPlatformLnkVxlan *a, const NMPlatformLnkVxlan *b);
int nm_platform_lnk_wireguard_cmp (const NMPlatformLnkWireGuard *a, const NMPlatformLnkWireGuard *b);
int nm_platform_ip4_address_cmp (const NMPlatformIP4Address *a, const NMPlatformIP4Address *b);
int nm_platform_ip6_address_cmp (const NMPlatformIP6Address *a, const NMPlatformIP6Address *b);

int nm_platform_ip4_route_cmp (const NMPlatformIP4Route *a, const NMPlatformIP4Route *b, NMPlatformIPRouteCmpType cmp_type);
int nm_platform_ip6_route_cmp (const NMPlatformIP6Route *a, const NMPlatformIP6Route *b, NMPlatformIPRouteCmpType cmp_type);

static inline int
nm_platform_ip4_route_cmp_full (const NMPlatformIP4Route *a, const NMPlatformIP4Route *b)
{
	return nm_platform_ip4_route_cmp (a, b, NM_PLATFORM_IP_ROUTE_CMP_TYPE_FULL);
}

static inline int
nm_platform_ip6_route_cmp_full (const NMPlatformIP6Route *a, const NMPlatformIP6Route *b)
{
	return nm_platform_ip6_route_cmp (a, b, NM_PLATFORM_IP_ROUTE_CMP_TYPE_FULL);
}

int nm_platform_routing_rule_cmp (const NMPlatformRoutingRule *a, const NMPlatformRoutingRule *b, NMPlatformRoutingRuleCmpType cmp_type);

static inline int
nm_platform_routing_rule_cmp_full (const NMPlatformRoutingRule *a, const NMPlatformRoutingRule *b)
{
	return nm_platform_routing_rule_cmp (a, b, NM_PLATFORM_ROUTING_RULE_CMP_TYPE_FULL);
}

int nm_platform_qdisc_cmp (const NMPlatformQdisc *a, const NMPlatformQdisc *b);
int nm_platform_tfilter_cmp (const NMPlatformTfilter *a, const NMPlatformTfilter *b);

void nm_platform_link_hash_update (const NMPlatformLink *obj, NMHashState *h);
void nm_platform_ip4_address_hash_update (const NMPlatformIP4Address *obj, NMHashState *h);
void nm_platform_ip6_address_hash_update (const NMPlatformIP6Address *obj, NMHashState *h);
void nm_platform_ip4_route_hash_update (const NMPlatformIP4Route *obj, NMPlatformIPRouteCmpType cmp_type, NMHashState *h);
void nm_platform_ip6_route_hash_update (const NMPlatformIP6Route *obj, NMPlatformIPRouteCmpType cmp_type, NMHashState *h);
void nm_platform_routing_rule_hash_update (const NMPlatformRoutingRule *obj, NMPlatformRoutingRuleCmpType cmp_type, NMHashState *h);
void nm_platform_lnk_gre_hash_update (const NMPlatformLnkGre *obj, NMHashState *h);
void nm_platform_lnk_infiniband_hash_update (const NMPlatformLnkInfiniband *obj, NMHashState *h);
void nm_platform_lnk_ip6tnl_hash_update (const NMPlatformLnkIp6Tnl *obj, NMHashState *h);
void nm_platform_lnk_ipip_hash_update (const NMPlatformLnkIpIp *obj, NMHashState *h);
void nm_platform_lnk_macsec_hash_update (const NMPlatformLnkMacsec *obj, NMHashState *h);
void nm_platform_lnk_macvlan_hash_update (const NMPlatformLnkMacvlan *obj, NMHashState *h);
void nm_platform_lnk_sit_hash_update (const NMPlatformLnkSit *obj, NMHashState *h);
void nm_platform_lnk_tun_hash_update (const NMPlatformLnkTun *obj, NMHashState *h);
void nm_platform_lnk_vlan_hash_update (const NMPlatformLnkVlan *obj, NMHashState *h);
void nm_platform_lnk_vxlan_hash_update (const NMPlatformLnkVxlan *obj, NMHashState *h);
void nm_platform_lnk_wireguard_hash_update (const NMPlatformLnkWireGuard *obj, NMHashState *h);

void nm_platform_qdisc_hash_update (const NMPlatformQdisc *obj, NMHashState *h);
void nm_platform_tfilter_hash_update (const NMPlatformTfilter *obj, NMHashState *h);

#define NM_PLATFORM_LINK_FLAGS2STR_MAX_LEN ((gsize) 162)

const char *nm_platform_link_flags2str (unsigned flags, char *buf, gsize len);
const char *nm_platform_link_inet6_addrgenmode2str (guint8 mode, char *buf, gsize len);
const char *nm_platform_addr_flags2str (unsigned flags, char *buf, gsize len);
const char *nm_platform_route_scope2str (int scope, char *buf, gsize len);

int nm_platform_ip_address_cmp_expiry (const NMPlatformIPAddress *a, const NMPlatformIPAddress *b);

gboolean nm_platform_ethtool_set_wake_on_lan (NMPlatform *self, int ifindex, NMSettingWiredWakeOnLan wol, const char *wol_password);
gboolean nm_platform_ethtool_set_link_settings (NMPlatform *self, int ifindex, gboolean autoneg, guint32 speed, NMPlatformLinkDuplexType duplex);
gboolean nm_platform_ethtool_get_link_settings (NMPlatform *self, int ifindex, gboolean *out_autoneg, guint32 *out_speed, NMPlatformLinkDuplexType *out_duplex);

typedef struct _NMEthtoolFeatureStates NMEthtoolFeatureStates;

NMEthtoolFeatureStates *nm_platform_ethtool_get_link_features (NMPlatform *self,
                                                               int ifindex);
gboolean nm_platform_ethtool_set_features (NMPlatform *self,
                                           int ifindex,
                                           const NMEthtoolFeatureStates *features,
                                           const NMTernary *requested /* indexed by NMEthtoolID - _NM_ETHTOOL_ID_FEATURE_FIRST */,
                                           gboolean do_set /* or reset */);

const char * nm_platform_link_duplex_type_to_string (NMPlatformLinkDuplexType duplex);

void nm_platform_ip4_dev_route_blacklist_set (NMPlatform *self,
                                              int ifindex,
                                              GPtrArray *ip4_dev_route_blacklist);

struct _NMDedupMultiIndex *nm_platform_get_multi_idx (NMPlatform *self);

#endif /* __NETWORKMANAGER_PLATFORM_H__ */
