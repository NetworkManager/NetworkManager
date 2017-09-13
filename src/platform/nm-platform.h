/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
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
 * Copyright (C) 2009 - 2010 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_PLATFORM_H__
#define __NETWORKMANAGER_PLATFORM_H__

#include <netinet/in.h>
#include <linux/if.h>
#include <linux/if_addr.h>
#include <linux/if_link.h>

#include "nm-dbus-interface.h"
#include "nm-core-types-internal.h"

#include "nm-core-utils.h"
#include "nm-setting-vlan.h"
#include "nm-setting-wired.h"

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

typedef enum { /*< skip >*/

	/* dummy value, to enforce that the enum type is signed and has a size
	 * to hold an integer. We want to encode errno from <errno.h> as negative
	 * values. */
	_NM_PLATFORM_ERROR_MININT = G_MININT,

	NM_PLATFORM_ERROR_SUCCESS = 0,

	NM_PLATFORM_ERROR_BUG,

	NM_PLATFORM_ERROR_UNSPECIFIED,

	NM_PLATFORM_ERROR_NOT_FOUND,
	NM_PLATFORM_ERROR_EXISTS,
	NM_PLATFORM_ERROR_WRONG_TYPE,
	NM_PLATFORM_ERROR_NOT_SLAVE,
	NM_PLATFORM_ERROR_NO_FIRMWARE,
	NM_PLATFORM_ERROR_OPNOTSUPP,
	NM_PLATFORM_ERROR_NETLINK,
} NMPlatformError;

#define NM_PLATFORM_LINK_OTHER_NETNS    (-1)

#define __NMPlatformObject_COMMON \
	int ifindex; \
	;

struct _NMPlatformLink {
	__NMPlatformObject_COMMON;
	char name[IFNAMSIZ];
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

	/* rtnl_link_get_addr(), IFLA_ADDRESS */
	struct {
		guint8 data[20]; /* NM_UTILS_HWADDR_LEN_MAX */
		guint8 len;
	} addr;

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
	_NM_PLATFORM_SIGNAL_ID_LAST,
} NMPlatformSignalIdType;

guint _nm_platform_signal_id_get (NMPlatformSignalIdType signal_type);

typedef enum {
	NM_PLATFORM_SIGNAL_NONE,
	NM_PLATFORM_SIGNAL_ADDED,
	NM_PLATFORM_SIGNAL_CHANGED,
	NM_PLATFORM_SIGNAL_REMOVED,
} NMPlatformSignalChangeType;

struct _NMPlatformObject {
	__NMPlatformObject_COMMON;
};


#define __NMPlatformIPAddress_COMMON \
	__NMPlatformObject_COMMON; \
	NMIPConfigSource addr_source; \
	\
	/* Timestamp in seconds in the reference system of nm_utils_get_monotonic_timestamp_*().
	 *
	 * The rules are:
	 * 1 @lifetime==0: @timestamp and @preferred is irrelevant (but mostly set to 0 too). Such addresses
	 *   are permanent. This rule is so that unset addresses (calloc) are permanent by default.
	 * 2 @lifetime==@preferred==NM_PLATFORM_LIFETIME_PERMANENT: @timestamp is irrelevant (but mostly
	 *   set to 0). Such addresses are permanent.
	 * 3 Non permanent addreses should (almost) always have @timestamp > 0. 0 is not a valid timestamp
	 *   and never returned by nm_utils_get_monotonic_timestamp_s(). In this case @valid/@preferred
	 *   is anchored at @timestamp.
	 * 4 Non permanent addresses with @timestamp == 0 are implicitely anchored at *now*, thus the time
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

	char label[IFNAMSIZ];
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
	__NMPlatformObject_COMMON; \
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
	/* the route has rtm_flags set to RTM_F_CLONED. Such a route
	 * is hidden by platform and does not exist from the point-of-view
	 * of platform users. This flag is internal to track those hidden
	 * routes. Such a route is not alive, according to nmp_object_is_alive(). */ \
	bool rt_cloned:1; \
	\
	\
	/* RTA_METRICS:
	 *
	 * For IPv4 routes, these properties are part of their
	 * ID (meaning: you can add otherwise idential IPv4 routes that
	 * only differ by the metric property).
	 * On the other hand, for IPv6 you cannot add two IPv6 routes that only differ
	 * by an RTA_METRICS property.
	 *
	 * When deleting a route, kernel seems to ignore the RTA_METRICS propeties.
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
	 * table. Use nm_platform_route_table_coerce(). */ \
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

#if _NM_CC_SUPPORT_GENERIC
#define NM_PLATFORM_IP_ROUTE_IS_DEFAULT(route) \
	(_Generic ((route), \
	           const NMPlatformIPRoute  *: ((const NMPlatformIPRoute *) (route))->plen, \
	                 NMPlatformIPRoute  *: ((const NMPlatformIPRoute *) (route))->plen, \
	           const NMPlatformIPXRoute *: ((const NMPlatformIPRoute *) (route))->plen, \
	                 NMPlatformIPXRoute *: ((const NMPlatformIPRoute *) (route))->plen, \
	           const NMPlatformIP4Route *: ((const NMPlatformIPRoute *) (route))->plen, \
	                 NMPlatformIP4Route *: ((const NMPlatformIPRoute *) (route))->plen, \
	           const NMPlatformIP6Route *: ((const NMPlatformIPRoute *) (route))->plen, \
	                 NMPlatformIP6Route *: ((const NMPlatformIPRoute *) (route))->plen, \
	           const void               *: ((const NMPlatformIPRoute *) (route))->plen, \
	                 void               *: ((const NMPlatformIPRoute *) (route))->plen) == 0)
#else
#define NM_PLATFORM_IP_ROUTE_IS_DEFAULT(route) \
	( ((const NMPlatformIPRoute *) (route))->plen <= 0 )
#endif

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
};

typedef union {
	NMPlatformIPRoute  rx;
	NMPlatformIP4Route r4;
	NMPlatformIP6Route r6;
} NMPlatformIPXRoute;

#undef __NMPlatformIPRoute_COMMON


#undef __NMPlatformObject_COMMON


typedef struct {
	gboolean is_ip4;
	NMPObjectType obj_type;
	int addr_family;
	gsize sizeof_route;
	int (*route_cmp) (const NMPlatformIPXRoute *a, const NMPlatformIPXRoute *b, NMPlatformIPRouteCmpType cmp_type);
	const char *(*route_to_string) (const NMPlatformIPXRoute *route, char *buf, gsize len);
	guint32 (*metric_normalize) (guint32 metric);
} NMPlatformVTableRoute;

extern const NMPlatformVTableRoute nm_platform_vtable_route_v4;
extern const NMPlatformVTableRoute nm_platform_vtable_route_v6;

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
	guint8 ttl;
	guint8 tos;
	guint8 proto;
	bool path_mtu_discovery:1;
	guint16 flags;
} NMPlatformLnkSit;

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

typedef struct {
	gint64 owner;
	gint64 group;
	const char *mode;
	bool no_pi:1;
	bool vnet_hdr:1;
	bool multi_queue:1;
} NMPlatformTunProperties;

typedef enum {
	NM_PLATFORM_LINK_DUPLEX_UNKNOWN,
	NM_PLATFORM_LINK_DUPLEX_HALF,
	NM_PLATFORM_LINK_DUPLEX_FULL,
} NMPlatformLinkDuplexType;

/*****************************************************************************/

struct _NMPlatformPrivate;

struct _NMPlatform {
	GObject parent;
	NMPNetns *_netns;
	struct _NMPlatformPrivate *_priv;
};

typedef struct {
	GObjectClass parent;

	gboolean (*sysctl_set) (NMPlatform *, const char *pathid, int dirfd, const char *path, const char *value);
	char * (*sysctl_get) (NMPlatform *, const char *pathid, int dirfd, const char *path);

	gboolean (*link_add) (NMPlatform *,
	                      const char *name,
	                      NMLinkType type,
	                      const char *veth_peer,
	                      const void *address,
	                      size_t address_len,
	                      const NMPlatformLink **out_link);
	gboolean (*link_delete) (NMPlatform *, int ifindex);

	gboolean (*link_refresh) (NMPlatform *, int ifindex);

	gboolean (*link_set_netns) (NMPlatform *, int ifindex, int netns_fd);

	void (*process_events) (NMPlatform *self);

	gboolean (*link_set_up) (NMPlatform *, int ifindex, gboolean *out_no_firmware);
	gboolean (*link_set_down) (NMPlatform *, int ifindex);
	gboolean (*link_set_arp) (NMPlatform *, int ifindex);
	gboolean (*link_set_noarp) (NMPlatform *, int ifindex);

	const char *(*link_get_udi) (NMPlatform *self, int ifindex);
	struct udev_device *(*link_get_udev_device) (NMPlatform *self, int ifindex);

	NMPlatformError (*link_set_user_ipv6ll_enabled) (NMPlatform *, int ifindex, gboolean enabled);
	gboolean (*link_set_token) (NMPlatform *, int ifindex, NMUtilsIPv6IfaceId iid);

	gboolean (*link_get_permanent_address) (NMPlatform *,
	                                        int ifindex,
	                                        guint8 *buf,
	                                        size_t *length);
	NMPlatformError (*link_set_address) (NMPlatform *, int ifindex, gconstpointer address, size_t length);
	gboolean (*link_set_mtu) (NMPlatform *, int ifindex, guint32 mtu);
	gboolean (*link_set_name) (NMPlatform *, int ifindex, const char *name);
	gboolean (*link_set_sriov_num_vfs) (NMPlatform *, int ifindex, guint num_vfs);

	char *   (*link_get_physical_port_id) (NMPlatform *, int ifindex);
	guint    (*link_get_dev_id) (NMPlatform *, int ifindex);
	gboolean (*link_get_wake_on_lan) (NMPlatform *, int ifindex);
	gboolean (*link_get_driver_info) (NMPlatform *,
	                                  int ifindex,
	                                  char **out_driver_name,
	                                  char **out_driver_version,
	                                  char **out_fw_version);

	gboolean (*link_supports_carrier_detect) (NMPlatform *, int ifindex);
	gboolean (*link_supports_vlans) (NMPlatform *, int ifindex);
	gboolean (*link_supports_sriov) (NMPlatform *, int ifindex);

	gboolean (*link_enslave) (NMPlatform *, int master, int slave);
	gboolean (*link_release) (NMPlatform *, int master, int slave);

	gboolean (*link_can_assume) (NMPlatform *, int ifindex);

	gboolean (*vlan_add) (NMPlatform *, const char *name, int parent, int vlanid, guint32 vlanflags, const NMPlatformLink **out_link);
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
	gboolean (*link_vxlan_add) (NMPlatform *,
	                            const char *name,
	                            const NMPlatformLnkVxlan *props,
	                            const NMPlatformLink **out_link);
	gboolean (*link_gre_add) (NMPlatform *,
	                          const char *name,
	                          const NMPlatformLnkGre *props,
	                          const NMPlatformLink **out_link);
	gboolean (*link_ip6tnl_add) (NMPlatform *,
	                             const char *name,
	                             const NMPlatformLnkIp6Tnl *props,
	                             const NMPlatformLink **out_link);
	gboolean (*link_ipip_add) (NMPlatform *,
	                           const char *name,
	                           const NMPlatformLnkIpIp *props,
	                           const NMPlatformLink **out_link);
	gboolean (*link_macsec_add) (NMPlatform *,
	                             const char *name,
	                             int parent,
	                             const NMPlatformLnkMacsec *props,
	                             const NMPlatformLink **out_link);
	gboolean (*link_macvlan_add) (NMPlatform *,
	                              const char *name,
	                              int parent,
	                              const NMPlatformLnkMacvlan *props,
	                              const NMPlatformLink **out_link);
	gboolean (*link_sit_add) (NMPlatform *,
	                          const char *name,
	                          const NMPlatformLnkSit *props,
	                          const NMPlatformLink **out_link);

	gboolean (*infiniband_partition_add) (NMPlatform *, int parent, int p_key, const NMPlatformLink **out_link);
	gboolean (*infiniband_partition_delete) (NMPlatform *, int parent, int p_key);

	gboolean (*tun_add) (NMPlatform *platform, const char *name, gboolean tap, gint64 owner, gint64 group, gboolean pi,
	                     gboolean vnet_hdr, gboolean multi_queue, const NMPlatformLink **out_link);

	gboolean    (*wifi_get_capabilities) (NMPlatform *, int ifindex, NMDeviceWifiCapabilities *caps);
	gboolean    (*wifi_get_bssid)        (NMPlatform *, int ifindex, guint8 *bssid);
	GByteArray *(*wifi_get_ssid)         (NMPlatform *, int ifindex);
	guint32     (*wifi_get_frequency)    (NMPlatform *, int ifindex);
	int         (*wifi_get_quality)      (NMPlatform *, int ifindex);
	guint32     (*wifi_get_rate)         (NMPlatform *, int ifindex);
	NM80211Mode (*wifi_get_mode)         (NMPlatform *, int ifindex);
	void        (*wifi_set_mode)         (NMPlatform *, int ifindex, NM80211Mode mode);
	void        (*wifi_set_powersave)    (NMPlatform *, int ifindex, guint32 powersave);
	guint32     (*wifi_find_frequency)   (NMPlatform *, int ifindex, const guint32 *freqs);
	void        (*wifi_indicate_addressing_running) (NMPlatform *, int ifindex, gboolean running);

	guint32     (*mesh_get_channel)      (NMPlatform *, int ifindex);
	gboolean    (*mesh_set_channel)      (NMPlatform *, int ifindex, guint32 channel);
	gboolean    (*mesh_set_ssid)         (NMPlatform *, int ifindex, const guint8 *ssid, gsize len);

	gboolean (*ip4_address_add) (NMPlatform *,
	                             int ifindex,
	                             in_addr_t address,
	                             guint8 plen,
	                             in_addr_t peer_address,
	                             guint32 lifetime,
	                             guint32 preferred_lft,
	                             guint32 flags,
	                             const char *label);
	gboolean (*ip6_address_add) (NMPlatform *,
	                             int ifindex,
	                             struct in6_addr address,
	                             guint8 plen,
	                             struct in6_addr peer_address,
	                             guint32 lifetime,
	                             guint32 preferred_lft,
	                             guint32 flags);
	gboolean (*ip4_address_delete) (NMPlatform *, int ifindex, in_addr_t address, guint8 plen, in_addr_t peer_address);
	gboolean (*ip6_address_delete) (NMPlatform *, int ifindex, struct in6_addr address, guint8 plen);

	NMPlatformError (*ip_route_add) (NMPlatform *,
	                                 NMPNlmFlags flags,
	                                 int addr_family,
	                                 const NMPlatformIPRoute *route);
	gboolean (*ip_route_delete) (NMPlatform *, const NMPObject *obj);

	NMPlatformError (*ip_route_get) (NMPlatform *self,
	                                 int addr_family,
	                                 gconstpointer address,
	                                 int oif_ifindex,
	                                 NMPObject **out_route);

	gboolean (*check_support_kernel_extended_ifa_flags) (NMPlatform *);
	gboolean (*check_support_user_ipv6ll) (NMPlatform *);
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

const char *nm_platform_signal_change_type_to_string (NMPlatformSignalChangeType change_type);

/*****************************************************************************/

GType nm_platform_get_type (void);

void nm_platform_setup (NMPlatform *instance);
NMPlatform *nm_platform_get (void);

#define NM_PLATFORM_GET (nm_platform_get ())

/*****************************************************************************/

/**
 * nm_platform_route_table_coerce:
 * @table: the route table, either its original value, or its coerced.
 *
 * Returns: returns the coerced table id. If the table id is like
 *   RTA_TABLE, it returns a value for NMPlatformIPRoute.table_coerced
 *   and vice versa.
 */
static inline guint32
nm_platform_route_table_coerce (guint32 table)
{
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
gboolean nm_platform_netns_push (NMPlatform *platform, NMPNetns **netns);

const char *nm_link_type_to_string (NMLinkType link_type);

const char *nm_platform_error_to_string (NMPlatformError error,
                                         char *buf,
                                         gsize buf_len);
#define nm_platform_error_to_string_a(error) \
	(nm_platform_error_to_string ((error), g_alloca (30), 30))

#define NMP_SYSCTL_PATHID_ABSOLUTE(path) \
	((const char *) NULL), -1, (path)

#define NMP_SYSCTL_PATHID_NETDIR_unsafe(dirfd, ifname, path) \
	nm_sprintf_bufa (NM_STRLEN ("net:/sys/class/net//\0") + IFNAMSIZ + strlen (path), \
	                 "net:/sys/class/net/%s/%s", (ifname), (path)), \
	(dirfd), (path)

#define NMP_SYSCTL_PATHID_NETDIR(dirfd, ifname, path) \
	nm_sprintf_bufa (NM_STRLEN ("net:/sys/class/net//"path"/\0") + IFNAMSIZ, \
	                 "net:/sys/class/net/%s/%s", (ifname), path), \
	(dirfd), (""path"")

int nm_platform_sysctl_open_netdir (NMPlatform *self, int ifindex, char *out_ifname);
gboolean nm_platform_sysctl_set (NMPlatform *self, const char *pathid, int dirfd, const char *path, const char *value);
char *nm_platform_sysctl_get (NMPlatform *self, const char *pathid, int dirfd, const char *path);
gint32 nm_platform_sysctl_get_int32 (NMPlatform *self, const char *pathid, int dirfd, const char *path, gint32 fallback);
gint64 nm_platform_sysctl_get_int_checked (NMPlatform *self, const char *pathid, int dirfd, const char *path, guint base, gint64 min, gint64 max, gint64 fallback);

gboolean nm_platform_sysctl_set_ip6_hop_limit_safe (NMPlatform *self, const char *iface, int value);

const char *nm_platform_if_indextoname (NMPlatform *self, int ifindex, char *out_ifname/* of size IFNAMSIZ */);
int nm_platform_if_nametoindex (NMPlatform *self, const char *ifname);

const NMPObject *nm_platform_link_get_obj (NMPlatform *self,
                                           int ifindex,
                                           gboolean visible_only);
const NMPlatformLink *nm_platform_link_get (NMPlatform *self, int ifindex);
const NMPlatformLink *nm_platform_link_get_by_ifname (NMPlatform *self, const char *ifname);
const NMPlatformLink *nm_platform_link_get_by_address (NMPlatform *self, gconstpointer address, size_t length);

GPtrArray *nm_platform_link_get_all (NMPlatform *self, gboolean sort_by_name);
NMPlatformError nm_platform_link_dummy_add (NMPlatform *self, const char *name, const NMPlatformLink **out_link);
NMPlatformError nm_platform_link_bridge_add (NMPlatform *self, const char *name, const void *address, size_t address_len, const NMPlatformLink **out_link);
NMPlatformError nm_platform_link_bond_add (NMPlatform *self, const char *name, const NMPlatformLink **out_link);
NMPlatformError nm_platform_link_team_add (NMPlatform *self, const char *name, const NMPlatformLink **out_link);
NMPlatformError nm_platform_link_veth_add (NMPlatform *self, const char *name, const char *peer, const NMPlatformLink **out_link);

gboolean nm_platform_link_delete (NMPlatform *self, int ifindex);

gboolean nm_platform_link_set_netns (NMPlatform *self, int ifindex, int netns_fd);

struct _NMDedupMultiHeadEntry;
struct _NMPLookup;
const struct _NMDedupMultiHeadEntry *nm_platform_lookup (NMPlatform *platform,
                                                         const struct _NMPLookup *lookup);

gboolean nm_platform_lookup_predicate_routes_main (const NMPObject *obj,
                                                   gpointer user_data);
gboolean nm_platform_lookup_predicate_routes_main_skip_rtprot_kernel (const NMPObject *obj,
                                                                      gpointer user_data);

GPtrArray *nm_platform_lookup_clone (NMPlatform *platform,
                                     const struct _NMPLookup *lookup,
                                     NMPObjectPredicateFunc predicate,
                                     gpointer user_data);

/* convienience methods to lookup the link and access fields of NMPlatformLink. */
int nm_platform_link_get_ifindex (NMPlatform *self, const char *name);
const char *nm_platform_link_get_name (NMPlatform *self, int ifindex);
NMLinkType nm_platform_link_get_type (NMPlatform *self, int ifindex);
gboolean nm_platform_link_is_software (NMPlatform *self, int ifindex);
gboolean nm_platform_link_is_up (NMPlatform *self, int ifindex);
gboolean nm_platform_link_is_connected (NMPlatform *self, int ifindex);
gboolean nm_platform_link_uses_arp (NMPlatform *self, int ifindex);
guint32 nm_platform_link_get_mtu (NMPlatform *self, int ifindex);
gboolean nm_platform_link_get_user_ipv6ll_enabled (NMPlatform *self, int ifindex);
gconstpointer nm_platform_link_get_address (NMPlatform *self, int ifindex, size_t *length);
int nm_platform_link_get_master (NMPlatform *self, int slave);

gboolean nm_platform_link_can_assume (NMPlatform *self, int ifindex);

gboolean nm_platform_link_get_unmanaged (NMPlatform *self, int ifindex, gboolean *unmanaged);
gboolean nm_platform_link_supports_slaves (NMPlatform *self, int ifindex);
const char *nm_platform_link_get_type_name (NMPlatform *self, int ifindex);

gboolean nm_platform_link_refresh (NMPlatform *self, int ifindex);
void nm_platform_process_events (NMPlatform *self);

gboolean nm_platform_link_set_up (NMPlatform *self, int ifindex, gboolean *out_no_firmware);
gboolean nm_platform_link_set_down (NMPlatform *self, int ifindex);
gboolean nm_platform_link_set_arp (NMPlatform *self, int ifindex);
gboolean nm_platform_link_set_noarp (NMPlatform *self, int ifindex);

const char *nm_platform_link_get_udi (NMPlatform *self, int ifindex);

struct udev_device *nm_platform_link_get_udev_device (NMPlatform *self, int ifindex);

NMPlatformError nm_platform_link_set_user_ipv6ll_enabled (NMPlatform *self, int ifindex, gboolean enabled);
gboolean nm_platform_link_set_ipv6_token (NMPlatform *self, int ifindex, NMUtilsIPv6IfaceId iid);

gboolean nm_platform_link_get_permanent_address (NMPlatform *self, int ifindex, guint8 *buf, size_t *length);
NMPlatformError nm_platform_link_set_address (NMPlatform *self, int ifindex, const void *address, size_t length);
gboolean nm_platform_link_set_mtu (NMPlatform *self, int ifindex, guint32 mtu);
gboolean nm_platform_link_set_name (NMPlatform *self, int ifindex, const char *name);
gboolean nm_platform_link_set_sriov_num_vfs (NMPlatform *self, int ifindex, guint num_vfs);

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
const NMPlatformLnkIp6Tnl *nm_platform_link_get_lnk_ip6tnl (NMPlatform *self, int ifindex, const NMPlatformLink **out_link);
const NMPlatformLnkIpIp *nm_platform_link_get_lnk_ipip (NMPlatform *self, int ifindex, const NMPlatformLink **out_link);
const NMPlatformLnkInfiniband *nm_platform_link_get_lnk_infiniband (NMPlatform *self, int ifindex, const NMPlatformLink **out_link);
const NMPlatformLnkIpIp *nm_platform_link_get_lnk_ipip (NMPlatform *self, int ifindex, const NMPlatformLink **out_link);
const NMPlatformLnkMacsec *nm_platform_link_get_lnk_macsec (NMPlatform *self, int ifindex, const NMPlatformLink **out_link);
const NMPlatformLnkMacvlan *nm_platform_link_get_lnk_macvlan (NMPlatform *self, int ifindex, const NMPlatformLink **out_link);
const NMPlatformLnkMacvtap *nm_platform_link_get_lnk_macvtap (NMPlatform *self, int ifindex, const NMPlatformLink **out_link);
const NMPlatformLnkSit *nm_platform_link_get_lnk_sit (NMPlatform *self, int ifindex, const NMPlatformLink **out_link);
const NMPlatformLnkVlan *nm_platform_link_get_lnk_vlan (NMPlatform *self, int ifindex, const NMPlatformLink **out_link);
const NMPlatformLnkVxlan *nm_platform_link_get_lnk_vxlan (NMPlatform *self, int ifindex, const NMPlatformLink **out_link);

NMPlatformError nm_platform_link_vlan_add (NMPlatform *self,
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

NMPlatformError nm_platform_link_vxlan_add (NMPlatform *self,
                                            const char *name,
                                            const NMPlatformLnkVxlan *props,
                                            const NMPlatformLink **out_link);

NMPlatformError nm_platform_link_tun_add (NMPlatform *self,
                                          const char *name,
                                          gboolean tap,
                                          gint64 owner,
                                          gint64 group,
                                          gboolean pi,
                                          gboolean vnet_hdr,
                                          gboolean multi_queue,
                                          const NMPlatformLink **out_link);

NMPlatformError nm_platform_link_infiniband_add (NMPlatform *self,
                                                 int parent,
                                                 int p_key,
                                                 const NMPlatformLink **out_link);
NMPlatformError nm_platform_link_infiniband_delete (NMPlatform *self,
                                                    int parent,
                                                    int p_key);
gboolean nm_platform_link_infiniband_get_properties (NMPlatform *self, int ifindex, int *parent, int *p_key, const char **mode);

gboolean nm_platform_link_veth_get_properties   (NMPlatform *self, int ifindex, int *out_peer_ifindex);
gboolean nm_platform_link_tun_get_properties    (NMPlatform *self, int ifindex, NMPlatformTunProperties *properties);

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

guint32     nm_platform_mesh_get_channel      (NMPlatform *self, int ifindex);
gboolean    nm_platform_mesh_set_channel      (NMPlatform *self, int ifindex, guint32 channel);
gboolean    nm_platform_mesh_set_ssid         (NMPlatform *self, int ifindex, const guint8 *ssid, gsize len);

void                   nm_platform_ip4_address_set_addr (NMPlatformIP4Address *addr, in_addr_t address, guint8 plen);
const struct in6_addr *nm_platform_ip6_address_get_peer (const NMPlatformIP6Address *addr);

const NMPlatformIP4Address *nm_platform_ip4_address_get (NMPlatform *self, int ifindex, in_addr_t address, guint8 plen, in_addr_t peer_address);

NMPlatformError nm_platform_link_gre_add (NMPlatform *self,
                                          const char *name,
                                          const NMPlatformLnkGre *props,
                                          const NMPlatformLink **out_link);
NMPlatformError nm_platform_link_ip6tnl_add (NMPlatform *self,
                                             const char *name,
                                             const NMPlatformLnkIp6Tnl *props,
                                             const NMPlatformLink **out_link);
NMPlatformError nm_platform_link_ipip_add (NMPlatform *self,
                                           const char *name,
                                           const NMPlatformLnkIpIp *props,
                                           const NMPlatformLink **out_link);
NMPlatformError nm_platform_link_macsec_add (NMPlatform *self,
                                             const char *name,
                                             int parent,
                                             const NMPlatformLnkMacsec *props,
                                             const NMPlatformLink **out_link);
NMPlatformError nm_platform_link_macvlan_add (NMPlatform *self,
                                              const char *name,
                                              int parent,
                                              const NMPlatformLnkMacvlan *props,
                                              const NMPlatformLink **out_link);
NMPlatformError nm_platform_link_sit_add (NMPlatform *self,
                                          const char *name,
                                          const NMPlatformLnkSit *props,
                                          const NMPlatformLink **out_link);

const NMPlatformIP6Address *nm_platform_ip6_address_get (NMPlatform *self, int ifindex, struct in6_addr address);

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
gboolean nm_platform_ip4_address_sync (NMPlatform *self, int ifindex, GPtrArray *known_addresse);
gboolean nm_platform_ip6_address_sync (NMPlatform *self, int ifindex, const GPtrArray *known_addresses, gboolean keep_link_local);
gboolean nm_platform_ip_address_flush (NMPlatform *self,
                                       int addr_family,
                                       int ifindex);

void nm_platform_ip_route_normalize (int addr_family,
                                     NMPlatformIPRoute *route);

NMPlatformError nm_platform_ip_route_add (NMPlatform *self,
                                          NMPNlmFlags flags,
                                          const NMPObject *route);
NMPlatformError nm_platform_ip4_route_add (NMPlatform *self, NMPNlmFlags flags, const NMPlatformIP4Route *route);
NMPlatformError nm_platform_ip6_route_add (NMPlatform *self, NMPNlmFlags flags, const NMPlatformIP6Route *route);

gboolean nm_platform_ip_route_delete (NMPlatform *self, const NMPObject *route);

gboolean nm_platform_ip_route_sync (NMPlatform *self,
                                    int addr_family,
                                    int ifindex,
                                    GPtrArray *routes,
                                    NMPObjectPredicateFunc kernel_delete_predicate,
                                    gpointer kernel_delete_userdata,
                                    GPtrArray **out_temporary_not_available);
gboolean nm_platform_ip_route_flush (NMPlatform *self,
                                     int addr_family,
                                     int ifindex);

NMPlatformError nm_platform_ip_route_get (NMPlatform *self,
                                          int addr_family,
                                          gconstpointer address,
                                          int oif_ifindex,
                                          NMPObject **out_route);

const char *nm_platform_link_to_string (const NMPlatformLink *link, char *buf, gsize len);
const char *nm_platform_lnk_gre_to_string (const NMPlatformLnkGre *lnk, char *buf, gsize len);
const char *nm_platform_lnk_infiniband_to_string (const NMPlatformLnkInfiniband *lnk, char *buf, gsize len);
const char *nm_platform_lnk_ip6tnl_to_string (const NMPlatformLnkIp6Tnl *lnk, char *buf, gsize len);
const char *nm_platform_lnk_ipip_to_string (const NMPlatformLnkIpIp *lnk, char *buf, gsize len);
const char *nm_platform_lnk_macsec_to_string (const NMPlatformLnkMacsec *lnk, char *buf, gsize len);
const char *nm_platform_lnk_macvlan_to_string (const NMPlatformLnkMacvlan *lnk, char *buf, gsize len);
const char *nm_platform_lnk_sit_to_string (const NMPlatformLnkSit *lnk, char *buf, gsize len);
const char *nm_platform_lnk_vlan_to_string (const NMPlatformLnkVlan *lnk, char *buf, gsize len);
const char *nm_platform_lnk_vxlan_to_string (const NMPlatformLnkVxlan *lnk, char *buf, gsize len);
const char *nm_platform_ip4_address_to_string (const NMPlatformIP4Address *address, char *buf, gsize len);
const char *nm_platform_ip6_address_to_string (const NMPlatformIP6Address *address, char *buf, gsize len);
const char *nm_platform_ip4_route_to_string (const NMPlatformIP4Route *route, char *buf, gsize len);
const char *nm_platform_ip6_route_to_string (const NMPlatformIP6Route *route, char *buf, gsize len);

const char *nm_platform_vlan_qos_mapping_to_string (const char *name,
                                                    const NMVlanQosMapping *map,
                                                    gsize n_map,
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
int nm_platform_lnk_vlan_cmp (const NMPlatformLnkVlan *a, const NMPlatformLnkVlan *b);
int nm_platform_lnk_vxlan_cmp (const NMPlatformLnkVxlan *a, const NMPlatformLnkVxlan *b);
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

guint nm_platform_link_hash (const NMPlatformLink *obj);
guint nm_platform_ip4_address_hash (const NMPlatformIP4Address *obj);
guint nm_platform_ip6_address_hash (const NMPlatformIP6Address *obj);
guint nm_platform_ip4_route_hash (const NMPlatformIP4Route *obj, NMPlatformIPRouteCmpType cmp_type);
guint nm_platform_ip6_route_hash (const NMPlatformIP6Route *obj, NMPlatformIPRouteCmpType cmp_type);
guint nm_platform_lnk_gre_hash (const NMPlatformLnkGre *obj);
guint nm_platform_lnk_infiniband_hash (const NMPlatformLnkInfiniband *obj);
guint nm_platform_lnk_ip6tnl_hash (const NMPlatformLnkIp6Tnl *obj);
guint nm_platform_lnk_ipip_hash (const NMPlatformLnkIpIp *obj);
guint nm_platform_lnk_macsec_hash (const NMPlatformLnkMacsec *obj);
guint nm_platform_lnk_macvlan_hash (const NMPlatformLnkMacvlan *obj);
guint nm_platform_lnk_sit_hash (const NMPlatformLnkSit *obj);
guint nm_platform_lnk_vlan_hash (const NMPlatformLnkVlan *obj);
guint nm_platform_lnk_vxlan_hash (const NMPlatformLnkVxlan *obj);

static inline guint
nm_platform_ip4_route_hash_full (const NMPlatformIP4Route *obj)
{
	return nm_platform_ip4_route_hash (obj, NM_PLATFORM_IP_ROUTE_CMP_TYPE_FULL);
}

static inline guint
nm_platform_ip6_route_hash_full (const NMPlatformIP6Route *obj)
{
	return nm_platform_ip6_route_hash (obj, NM_PLATFORM_IP_ROUTE_CMP_TYPE_FULL);
}

gboolean nm_platform_check_support_kernel_extended_ifa_flags (NMPlatform *self);
gboolean nm_platform_check_support_user_ipv6ll (NMPlatform *self);

const char *nm_platform_link_flags2str (unsigned flags, char *buf, gsize len);
const char *nm_platform_link_inet6_addrgenmode2str (guint8 mode, char *buf, gsize len);
const char *nm_platform_addr_flags2str (unsigned flags, char *buf, gsize len);
const char *nm_platform_route_scope2str (int scope, char *buf, gsize len);

int nm_platform_ip_address_cmp_expiry (const NMPlatformIPAddress *a, const NMPlatformIPAddress *b);

gboolean nm_platform_ethtool_set_wake_on_lan (NMPlatform *self, int ifindex, NMSettingWiredWakeOnLan wol, const char *wol_password);
gboolean nm_platform_ethtool_set_link_settings (NMPlatform *self, int ifindex, gboolean autoneg, guint32 speed, NMPlatformLinkDuplexType duplex);
gboolean nm_platform_ethtool_get_link_settings (NMPlatform *self, int ifindex, gboolean *out_autoneg, guint32 *out_speed, NMPlatformLinkDuplexType *out_duplex);

void nm_platform_ip4_dev_route_blacklist_set (NMPlatform *self,
                                              int ifindex,
                                              GPtrArray *ip4_dev_route_blacklist);

struct _NMDedupMultiIndex *nm_platform_get_multi_idx (NMPlatform *self);

#endif /* __NETWORKMANAGER_PLATFORM_H__ */
