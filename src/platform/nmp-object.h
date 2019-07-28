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
 * Copyright (C) 2015 - 2018 Red Hat, Inc.
 */

#ifndef __NMP_OBJECT_H__
#define __NMP_OBJECT_H__

#include <netinet/in.h>

#include "nm-glib-aux/nm-obj.h"
#include "nm-glib-aux/nm-dedup-multi.h"
#include "nm-platform.h"

struct udev_device;

/*****************************************************************************/

/* "struct __kernel_timespec" uses "long long", but we use gint64. In practice,
 * these are the same types. */
G_STATIC_ASSERT (sizeof (long long) == sizeof (gint64));

typedef struct {
	/* like "struct __kernel_timespec". */
	gint64 tv_sec;
	gint64 tv_nsec;
} NMPTimespec64;

/*****************************************************************************/

typedef union {
	struct sockaddr     sa;
	struct sockaddr_in  in;
	struct sockaddr_in6 in6;
} NMSockAddrUnion;

#define NM_SOCK_ADDR_UNION_INIT_UNSPEC \
	{ \
		.sa = { \
			.sa_family = AF_UNSPEC, \
		}, \
	}

int nm_sock_addr_union_cmp (const NMSockAddrUnion *a,
                            const NMSockAddrUnion *b);

void nm_sock_addr_union_hash_update (const NMSockAddrUnion *a,
                                     NMHashState *h);

void nm_sock_addr_union_cpy (NMSockAddrUnion *dst,
                             gconstpointer src /* unaligned (const NMSockAddrUnion *) */);

void nm_sock_addr_union_cpy_untrusted (NMSockAddrUnion *dst,
                                       gconstpointer src /* unaligned (const NMSockAddrUnion *) */,
                                       gsize src_len);

const char *nm_sock_addr_union_to_string (const NMSockAddrUnion *sa,
                                          char *buf,
                                          gsize len);

/*****************************************************************************/

typedef struct {
	NMIPAddr addr;
	guint8 family;
	guint8 mask;
} NMPWireGuardAllowedIP;

typedef struct _NMPWireGuardPeer {
	NMSockAddrUnion endpoint;

	NMPTimespec64 last_handshake_time;

	guint64 rx_bytes;
	guint64 tx_bytes;

	union {
		const NMPWireGuardAllowedIP *allowed_ips;
		guint _construct_idx_start;
	};
	union {
		guint allowed_ips_len;
		guint _construct_idx_end;
	};

	guint16 persistent_keepalive_interval;

	guint8 public_key[NMP_WIREGUARD_PUBLIC_KEY_LEN];
	guint8 preshared_key[NMP_WIREGUARD_SYMMETRIC_KEY_LEN];
} NMPWireGuardPeer;

/*****************************************************************************/

typedef enum { /*< skip >*/
	NMP_OBJECT_TO_STRING_ID,
	NMP_OBJECT_TO_STRING_PUBLIC,
	NMP_OBJECT_TO_STRING_ALL,
} NMPObjectToStringMode;

typedef enum { /*< skip >*/
	NMP_CACHE_OPS_UNCHANGED       = NM_PLATFORM_SIGNAL_NONE,
	NMP_CACHE_OPS_ADDED           = NM_PLATFORM_SIGNAL_ADDED,
	NMP_CACHE_OPS_UPDATED         = NM_PLATFORM_SIGNAL_CHANGED,
	NMP_CACHE_OPS_REMOVED         = NM_PLATFORM_SIGNAL_REMOVED,
} NMPCacheOpsType;

/* The NMPCacheIdType are the different index types.
 *
 * An object of a certain object-type, can be candidate to being
 * indexed by a certain NMPCacheIdType or not. For example, all
 * objects are indexed via an index of type NMP_CACHE_ID_TYPE_OBJECT_TYPE,
 * but only route objects can be indexed by NMP_CACHE_ID_TYPE_ROUTES_VISIBLE_NO_DEFAULT.
 *
 * Of one index type, there can be multiple indexes or not.
 * For example, of the index type NMP_CACHE_ID_TYPE_OBJECT_BY_IFINDEX there
 * are multiple instances (for different route/addresses, v4/v6, per-ifindex).
 *
 * But one object, can only be indexed by one particular index of a
 * type. For example, a certain address instance is only indexed by
 * the index NMP_CACHE_ID_TYPE_OBJECT_BY_IFINDEX with
 * matching v4/v6 and ifindex -- or maybe not at all if it isn't visible.
 * */
typedef enum { /*< skip >*/
	NMP_CACHE_ID_TYPE_NONE,

	/* all the objects of a certain type.
	 *
	 * This index is special. It is the only one that contains *all* object.
	 * Other indexes may consider some object as non "partitionable", hence
	 * they don't track all objects.
	 *
	 * Hence, this index type is used when looking at all objects (still
	 * partitioned by type).
	 *
	 * Also, note that links may be considered invisible. This index type
	 * expose all links, even invisible ones. For addresses/routes, this
	 * distinction doesn't exist, as all addresses/routes that are alive
	 * are visible as well. */
	NMP_CACHE_ID_TYPE_OBJECT_TYPE,

	/* index for the link objects by ifname. */
	NMP_CACHE_ID_TYPE_LINK_BY_IFNAME,

	/* indices for the visible default-routes, ignoring ifindex.
	 * This index only contains two partitions: all visible default-routes,
	 * separate for IPv4 and IPv6. */
	NMP_CACHE_ID_TYPE_DEFAULT_ROUTES,

	/* all the objects that have an ifindex (by object-type) for an ifindex. */
	NMP_CACHE_ID_TYPE_OBJECT_BY_IFINDEX,

	/* Consider all the destination fields of a route, that is, the ID without the ifindex
	 * and gateway (meaning: network/plen,metric).
	 * The reason for this is that `ip route change` can replace an existing route
	 * and modify its ifindex/gateway. Effectively, that means it deletes an existing
	 * route and adds a different one (as the ID of the route changes). However, it only
	 * sends one RTM_NEWADDR notification without notifying about the deletion. We detect
	 * that by having this index to contain overlapping routes which require special
	 * cache-resync. */
	NMP_CACHE_ID_TYPE_ROUTES_BY_WEAK_ID,

	/* a filter for objects that track an explicit address family.
	 *
	 * Note that currently on NMPObjectRoutingRule is indexed by this filter. */
	NMP_CACHE_ID_TYPE_OBJECT_BY_ADDR_FAMILY,

	__NMP_CACHE_ID_TYPE_MAX,
	NMP_CACHE_ID_TYPE_MAX = __NMP_CACHE_ID_TYPE_MAX - 1,
} NMPCacheIdType;

typedef struct {
	NMDedupMultiObjClass parent;
	const char *obj_type_name;
	int sizeof_data;
	int sizeof_public;
	NMPObjectType obj_type;
	int addr_family;
	int rtm_gettype;
	NMPlatformSignalIdType signal_type_id;
	const char *signal_type;

	const guint8 *supported_cache_ids;

	/* Only for NMPObjectLnk* types. */
	NMLinkType lnk_link_type;

	void (*cmd_obj_hash_update) (const NMPObject *obj, NMHashState *h);
	int (*cmd_obj_cmp) (const NMPObject *obj1, const NMPObject *obj2);
	void (*cmd_obj_copy) (NMPObject *dst, const NMPObject *src);
	void (*cmd_obj_dispose) (NMPObject *obj);
	gboolean (*cmd_obj_is_alive) (const NMPObject *obj);
	gboolean (*cmd_obj_is_visible) (const NMPObject *obj);
	const char *(*cmd_obj_to_string) (const NMPObject *obj, NMPObjectToStringMode to_string_mode, char *buf, gsize buf_size);

	/* functions that operate on NMPlatformObject */
	void (*cmd_plobj_id_copy) (NMPlatformObject *dst, const NMPlatformObject *src);
	int (*cmd_plobj_id_cmp) (const NMPlatformObject *obj1, const NMPlatformObject *obj2);
	void (*cmd_plobj_id_hash_update) (const NMPlatformObject *obj, NMHashState *h);
	const char *(*cmd_plobj_to_string_id) (const NMPlatformObject *obj, char *buf, gsize buf_size);
	const char *(*cmd_plobj_to_string) (const NMPlatformObject *obj, char *buf, gsize len);
	void (*cmd_plobj_hash_update) (const NMPlatformObject *obj, NMHashState *h);
	int (*cmd_plobj_cmp) (const NMPlatformObject *obj1, const NMPlatformObject *obj2);
} NMPClass;

extern const NMPClass _nmp_classes[NMP_OBJECT_TYPE_MAX];

typedef struct {
	NMPlatformLink _public;

	struct {
		bool is_in_netlink;

		/* Additional data that depends on the link-type (IFLA_INFO_DATA) */
		const NMPObject *lnk;
	} netlink;

	struct {
		/* note that "struct udev_device" references the library context
		 * "struct udev", but doesn't own it.
		 *
		 * Hence, the udev.device shall not be used after the library
		 * context is is destroyed.
		 *
		 * In case of NMPObjectLink instances that you obtained from the
		 * platform cache, that means that you shall no keep references
		 * to those instances that outlife the NMPlatform instance.
		 *
		 * In practice, the requirement is less strict and you'll be even
		 * fine if the platform instance (and the "struct udev" instance)
		 * are already destroyed while you still hold onto a reference to
		 * the NMPObjectLink instance. Just don't make use of udev functions
		 * that cause access to the udev library context.
		 */
		struct udev_device *device;
	} udev;

	/* Auxiliary data object for Wi-Fi and WPAN */
	GObject *ext_data;

	/* FIXME: not every NMPObjectLink should pay the price for tracking
	 * the wireguard family id. This should be tracked via ext_data, which
	 * would be exactly the right place. */
	int wireguard_family_id;
} NMPObjectLink;

typedef struct {
	NMPlatformLnkGre _public;
} NMPObjectLnkGre;

typedef struct {
	NMPlatformLnkInfiniband _public;
} NMPObjectLnkInfiniband;

typedef struct {
	NMPlatformLnkIp6Tnl _public;
} NMPObjectLnkIp6Tnl;

typedef struct {
	NMPlatformLnkIpIp _public;
} NMPObjectLnkIpIp;

typedef struct {
	NMPlatformLnkMacsec _public;
} NMPObjectLnkMacsec;

typedef struct {
	NMPlatformLnkMacvlan _public;
} NMPObjectLnkMacvlan;

typedef NMPObjectLnkMacvlan NMPObjectLnkMacvtap;

typedef struct {
	NMPlatformLnkSit _public;
} NMPObjectLnkSit;

typedef struct {
	NMPlatformLnkTun _public;
} NMPObjectLnkTun;

typedef struct {
	NMPlatformLnkVlan _public;

	guint n_ingress_qos_map;
	guint n_egress_qos_map;
	const NMVlanQosMapping *ingress_qos_map;
	const NMVlanQosMapping *egress_qos_map;
} NMPObjectLnkVlan;

typedef struct {
	NMPlatformLnkVxlan _public;
} NMPObjectLnkVxlan;

typedef struct {
	NMPlatformLnkWireGuard _public;
	const NMPWireGuardPeer *peers;
	const NMPWireGuardAllowedIP *_allowed_ips_buf;
	guint peers_len;
	guint _allowed_ips_buf_len;
} NMPObjectLnkWireGuard;

typedef struct {
	NMPlatformIP4Address _public;
} NMPObjectIP4Address;

typedef struct {
	NMPlatformIP4Route _public;
} NMPObjectIP4Route;

typedef struct {
	NMPlatformIP6Address _public;
} NMPObjectIP6Address;

typedef struct {
	NMPlatformIP6Route _public;
} NMPObjectIP6Route;

typedef struct {
	NMPlatformRoutingRule _public;
} NMPObjectRoutingRule;

typedef struct {
	NMPlatformQdisc _public;
} NMPObjectQdisc;

typedef struct {
	NMPlatformTfilter _public;
} NMPObjectTfilter;

struct _NMPObject {
	union {
		NMDedupMultiObj parent;
		const NMPClass *_class;
	};
	union {
		NMPlatformObject        object;

		NMPlatformObjWithIfindex obj_with_ifindex;

		NMPlatformLink          link;
		NMPObjectLink           _link;

		NMPlatformLnkGre        lnk_gre;
		NMPObjectLnkGre         _lnk_gre;

		NMPlatformLnkInfiniband lnk_infiniband;
		NMPObjectLnkInfiniband  _lnk_infiniband;

		NMPlatformLnkIpIp       lnk_ipip;
		NMPObjectLnkIpIp        _lnk_ipip;

		NMPlatformLnkIp6Tnl     lnk_ip6tnl;
		NMPObjectLnkIp6Tnl      _lnk_ip6tnl;

		NMPlatformLnkMacsec     lnk_macsec;
		NMPObjectLnkMacsec      _lnk_macsec;

		NMPlatformLnkMacvlan    lnk_macvlan;
		NMPObjectLnkMacvlan     _lnk_macvlan;

		NMPlatformLnkSit        lnk_sit;
		NMPObjectLnkSit         _lnk_sit;

		NMPlatformLnkTun        lnk_tun;
		NMPObjectLnkTun         _lnk_tun;

		NMPlatformLnkVlan       lnk_vlan;
		NMPObjectLnkVlan        _lnk_vlan;

		NMPlatformLnkVxlan      lnk_vxlan;
		NMPObjectLnkVxlan       _lnk_vxlan;

		NMPlatformLnkWireGuard  lnk_wireguard;
		NMPObjectLnkWireGuard   _lnk_wireguard;

		NMPlatformIPAddress     ip_address;
		NMPlatformIPXAddress    ipx_address;
		NMPlatformIP4Address    ip4_address;
		NMPlatformIP6Address    ip6_address;
		NMPObjectIP4Address     _ip4_address;
		NMPObjectIP6Address     _ip6_address;

		NMPlatformIPRoute       ip_route;
		NMPlatformIPXRoute      ipx_route;
		NMPlatformIP4Route      ip4_route;
		NMPlatformIP6Route      ip6_route;
		NMPObjectIP4Route       _ip4_route;
		NMPObjectIP6Route       _ip6_route;

		NMPlatformRoutingRule   routing_rule;
		NMPObjectRoutingRule    _routing_rule;

		NMPlatformQdisc         qdisc;
		NMPObjectQdisc          _qdisc;
		NMPlatformTfilter       tfilter;
		NMPObjectTfilter        _tfilter;
	};
};

/*****************************************************************************/

static inline gboolean
NMP_CLASS_IS_VALID (const NMPClass *klass)
{
	return klass >= &_nmp_classes[0]
	    && klass <= &_nmp_classes[G_N_ELEMENTS (_nmp_classes)]
	    && ((((char *) klass) - ((char *) _nmp_classes)) % (sizeof (_nmp_classes[0]))) == 0;
}

static inline const NMPClass *
nmp_class_from_type (NMPObjectType obj_type)
{
	nm_assert (obj_type > 0);
	nm_assert (obj_type <= G_N_ELEMENTS (_nmp_classes));
	nm_assert (_nmp_classes[obj_type - 1].obj_type == obj_type);
	nm_assert (NMP_CLASS_IS_VALID (&_nmp_classes[obj_type - 1]));

	return &_nmp_classes[obj_type - 1];
}

static inline NMPObject *
NMP_OBJECT_UP_CAST(const NMPlatformObject *plobj)
{
	NMPObject *obj;

	obj = plobj
	      ? (NMPObject *) ( &(((char *) plobj)[-((int) G_STRUCT_OFFSET (NMPObject, object))]) )
	      : NULL;
	nm_assert (!obj || (obj->parent._ref_count > 0 && NMP_CLASS_IS_VALID (obj->_class)));
	return obj;
}
#define NMP_OBJECT_UP_CAST(plobj) (NMP_OBJECT_UP_CAST ((const NMPlatformObject *) (plobj)))

static inline gboolean
NMP_OBJECT_IS_VALID (const NMPObject *obj)
{
	nm_assert (!obj || (   obj
	                    && obj->parent._ref_count > 0
	                    && NMP_CLASS_IS_VALID (obj->_class)));

	/* There isn't really much to check. Either @obj is NULL, or we must
	 * assume that it points to valid memory. */
	return obj != NULL;
}

static inline gboolean
NMP_OBJECT_IS_STACKINIT (const NMPObject *obj)
{
	nm_assert (!obj || NMP_OBJECT_IS_VALID (obj));

	return obj && obj->parent._ref_count == NM_OBJ_REF_COUNT_STACKINIT;
}

static inline const NMPClass *
NMP_OBJECT_GET_CLASS (const NMPObject *obj)
{
	nm_assert (NMP_OBJECT_IS_VALID (obj));

	return obj->_class;
}

static inline NMPObjectType
NMP_OBJECT_GET_TYPE (const NMPObject *obj)
{
	nm_assert (!obj || NMP_OBJECT_IS_VALID (obj));

	return obj ? obj->_class->obj_type : NMP_OBJECT_TYPE_UNKNOWN;
}

static inline gboolean
_NMP_OBJECT_TYPE_IS_OBJ_WITH_IFINDEX (NMPObjectType obj_type)
{
	switch (obj_type) {
	case NMP_OBJECT_TYPE_LINK:
	case NMP_OBJECT_TYPE_IP4_ADDRESS:
	case NMP_OBJECT_TYPE_IP6_ADDRESS:
	case NMP_OBJECT_TYPE_IP4_ROUTE:
	case NMP_OBJECT_TYPE_IP6_ROUTE:

	case NMP_OBJECT_TYPE_QDISC:

	case NMP_OBJECT_TYPE_TFILTER:

	case NMP_OBJECT_TYPE_LNK_GRE:
	case NMP_OBJECT_TYPE_LNK_GRETAP:
	case NMP_OBJECT_TYPE_LNK_INFINIBAND:
	case NMP_OBJECT_TYPE_LNK_IP6TNL:
	case NMP_OBJECT_TYPE_LNK_IP6GRE:
	case NMP_OBJECT_TYPE_LNK_IP6GRETAP:
	case NMP_OBJECT_TYPE_LNK_IPIP:
	case NMP_OBJECT_TYPE_LNK_MACSEC:
	case NMP_OBJECT_TYPE_LNK_MACVLAN:
	case NMP_OBJECT_TYPE_LNK_MACVTAP:
	case NMP_OBJECT_TYPE_LNK_SIT:
	case NMP_OBJECT_TYPE_LNK_TUN:
	case NMP_OBJECT_TYPE_LNK_VLAN:
	case NMP_OBJECT_TYPE_LNK_VXLAN:
	case NMP_OBJECT_TYPE_LNK_WIREGUARD:
		return TRUE;
	default:
		nm_assert (nmp_class_from_type (obj_type));
		return FALSE;
	}
}

#define NMP_OBJECT_CAST_OBJECT(obj) \
	({ \
		typeof (obj) _obj = (obj); \
		\
		nm_assert (   !_obj \
		           || nmp_class_from_type (NMP_OBJECT_GET_TYPE (_obj)))); \
		_obj ? &NM_CONSTCAST (NMPObject, _obj)->object : NULL; \
	})

#define NMP_OBJECT_CAST_OBJ_WITH_IFINDEX(obj) \
	({ \
		typeof (obj) _obj = (obj); \
		\
		nm_assert (   !_obj \
		           || _NMP_OBJECT_TYPE_IS_OBJ_WITH_IFINDEX (NMP_OBJECT_GET_TYPE (_obj))); \
		_obj ? &NM_CONSTCAST (NMPObject, _obj)->obj_with_ifindex : NULL; \
	})

#define _NMP_OBJECT_CAST(obj, field, ...) \
	({ \
		typeof (obj) _obj = (obj); \
		\
		nm_assert (!_obj || NM_IN_SET (NMP_OBJECT_GET_TYPE (_obj), __VA_ARGS__)); \
		_obj ? &NM_CONSTCAST (NMPObject, _obj)->field : NULL; \
	})

#define NMP_OBJECT_CAST_LINK(obj)          _NMP_OBJECT_CAST (obj, link,          NMP_OBJECT_TYPE_LINK)
#define NMP_OBJECT_CAST_IP_ADDRESS(obj)    _NMP_OBJECT_CAST (obj, ip_address,    NMP_OBJECT_TYPE_IP4_ADDRESS, NMP_OBJECT_TYPE_IP6_ADDRESS)
#define NMP_OBJECT_CAST_IPX_ADDRESS(obj)   _NMP_OBJECT_CAST (obj, ipx_address,   NMP_OBJECT_TYPE_IP4_ADDRESS, NMP_OBJECT_TYPE_IP6_ADDRESS)
#define NMP_OBJECT_CAST_IP4_ADDRESS(obj)   _NMP_OBJECT_CAST (obj, ip4_address,   NMP_OBJECT_TYPE_IP4_ADDRESS)
#define NMP_OBJECT_CAST_IP6_ADDRESS(obj)   _NMP_OBJECT_CAST (obj, ip6_address,   NMP_OBJECT_TYPE_IP6_ADDRESS)
#define NMP_OBJECT_CAST_IP_ROUTE(obj)      _NMP_OBJECT_CAST (obj, ip_route,      NMP_OBJECT_TYPE_IP4_ROUTE, NMP_OBJECT_TYPE_IP6_ROUTE)
#define NMP_OBJECT_CAST_IPX_ROUTE(obj)     _NMP_OBJECT_CAST (obj, ipx_route,     NMP_OBJECT_TYPE_IP4_ROUTE, NMP_OBJECT_TYPE_IP6_ROUTE)
#define NMP_OBJECT_CAST_IP4_ROUTE(obj)     _NMP_OBJECT_CAST (obj, ip4_route,     NMP_OBJECT_TYPE_IP4_ROUTE)
#define NMP_OBJECT_CAST_IP6_ROUTE(obj)     _NMP_OBJECT_CAST (obj, ip6_route,     NMP_OBJECT_TYPE_IP6_ROUTE)
#define NMP_OBJECT_CAST_ROUTING_RULE(obj)  _NMP_OBJECT_CAST (obj, routing_rule,  NMP_OBJECT_TYPE_ROUTING_RULE)
#define NMP_OBJECT_CAST_QDISC(obj)         _NMP_OBJECT_CAST (obj, qdisc,         NMP_OBJECT_TYPE_QDISC)
#define NMP_OBJECT_CAST_TFILTER(obj)       _NMP_OBJECT_CAST (obj, tfilter,       NMP_OBJECT_TYPE_TFILTER)
#define NMP_OBJECT_CAST_LNK_WIREGUARD(obj) _NMP_OBJECT_CAST (obj, lnk_wireguard, NMP_OBJECT_TYPE_LNK_WIREGUARD)

static inline const NMPObject *
nmp_object_ref (const NMPObject *obj)
{
	if (!obj) {
		/* for convenience, allow NULL. */
		return NULL;
	}

	/* ref and unref accept const pointers. NMPObject is supposed to be shared
	 * and kept immutable. Disallowing to take/return a reference to a const
	 * NMPObject is cumbersome, because callers are precisely expected to
	 * keep a ref on the otherwise immutable object. */
	g_return_val_if_fail (NMP_OBJECT_IS_VALID (obj), NULL);
	g_return_val_if_fail (obj->parent._ref_count != NM_OBJ_REF_COUNT_STACKINIT, NULL);

	return (const NMPObject *) nm_dedup_multi_obj_ref ((const NMDedupMultiObj *) obj);
}

static inline void
nmp_object_unref (const NMPObject *obj)
{
	if (obj) {
		nm_assert (NMP_OBJECT_IS_VALID (obj));

		nm_dedup_multi_obj_unref ((const NMDedupMultiObj *) obj);
	}
}

#define nm_clear_nmp_object(ptr) \
	({ \
		typeof (ptr) _ptr = (ptr); \
		typeof (*_ptr) _pptr; \
		gboolean _changed = FALSE; \
		\
		if (   _ptr \
		    && (_pptr = *_ptr)) { \
			*_ptr = NULL; \
			nmp_object_unref (_pptr); \
			_changed = TRUE; \
		} \
		_changed; \
	})

NMPObject *nmp_object_new (NMPObjectType obj_type, gconstpointer plobj);
NMPObject *nmp_object_new_link (int ifindex);

const NMPObject *nmp_object_stackinit (NMPObject *obj, NMPObjectType obj_type, gconstpointer plobj);

static inline NMPObject *
nmp_object_stackinit_obj (NMPObject *obj, const NMPObject *src)
{
	return obj == src
	         ? obj
	         : (NMPObject *) nmp_object_stackinit (obj, NMP_OBJECT_GET_TYPE (src), &src->object);
}

const NMPObject *nmp_object_stackinit_id  (NMPObject *obj, const NMPObject *src);
const NMPObject *nmp_object_stackinit_id_link (NMPObject *obj, int ifindex);
const NMPObject *nmp_object_stackinit_id_ip4_address (NMPObject *obj, int ifindex, guint32 address, guint8 plen, guint32 peer_address);
const NMPObject *nmp_object_stackinit_id_ip6_address (NMPObject *obj, int ifindex, const struct in6_addr *address);

const char *nmp_object_to_string (const NMPObject *obj, NMPObjectToStringMode to_string_mode, char *buf, gsize buf_size);
void nmp_object_hash_update (const NMPObject *obj, NMHashState *h);
int nmp_object_cmp (const NMPObject *obj1, const NMPObject *obj2);

static inline gboolean
nmp_object_equal (const NMPObject *obj1, const NMPObject *obj2)
{
	return nmp_object_cmp (obj1, obj2) == 0;
}

void nmp_object_copy (NMPObject *dst, const NMPObject *src, gboolean id_only);
NMPObject *nmp_object_clone (const NMPObject *obj, gboolean id_only);

int nmp_object_id_cmp (const NMPObject *obj1, const NMPObject *obj2);
void nmp_object_id_hash_update (const NMPObject *obj, NMHashState *h);
guint nmp_object_id_hash (const NMPObject *obj);

static inline gboolean
nmp_object_id_equal (const NMPObject *obj1, const NMPObject *obj2)
{
	return nmp_object_id_cmp (obj1, obj2) == 0;
}

gboolean nmp_object_is_alive (const NMPObject *obj);
gboolean nmp_object_is_visible (const NMPObject *obj);

void _nmp_object_fixup_link_udev_fields (NMPObject **obj_new, NMPObject *obj_orig, gboolean use_udev);

static inline void
_nm_auto_nmpobj_cleanup (gpointer p)
{
	nmp_object_unref (*((const NMPObject **) p));
}
#define nm_auto_nmpobj nm_auto(_nm_auto_nmpobj_cleanup)

typedef struct _NMPCache NMPCache;

typedef void (*NMPCachePreHook) (NMPCache *cache, const NMPObject *old, const NMPObject *new, NMPCacheOpsType ops_type, gpointer user_data);
typedef gboolean (*NMPObjectMatchFn) (const NMPObject *obj, gpointer user_data);

const NMDedupMultiEntry *nmp_cache_lookup_entry (const NMPCache *cache,
                                                 const NMPObject *obj);
const NMDedupMultiEntry *nmp_cache_lookup_entry_with_idx_type (const NMPCache *cache,
                                                               NMPCacheIdType cache_id_type,
                                                               const NMPObject *obj);
const NMDedupMultiEntry *nmp_cache_lookup_entry_link (const NMPCache *cache,
                                                      int ifindex);
const NMPObject *nmp_cache_lookup_obj (const NMPCache *cache,
                                       const NMPObject *obj);
const NMPObject *nmp_cache_lookup_link (const NMPCache *cache,
                                        int ifindex);

typedef struct _NMPLookup NMPLookup;

struct _NMPLookup {
	NMPCacheIdType cache_id_type;
	NMPObject selector_obj;
};

const NMDedupMultiHeadEntry *nmp_cache_lookup_all (const NMPCache *cache,
                                                   NMPCacheIdType cache_id_type,
                                                   const NMPObject *select_obj);

static inline const NMDedupMultiHeadEntry *
nmp_cache_lookup (const NMPCache *cache,
                  const NMPLookup *lookup)
{
	return nmp_cache_lookup_all (cache, lookup->cache_id_type, &lookup->selector_obj);
}

const NMPLookup *nmp_lookup_init_obj_type (NMPLookup *lookup,
                                           NMPObjectType obj_type);
const NMPLookup *nmp_lookup_init_link_by_ifname (NMPLookup *lookup,
                                                 const char *ifname);
const NMPLookup *nmp_lookup_init_object (NMPLookup *lookup,
                                         NMPObjectType obj_type,
                                         int ifindex);
const NMPLookup *nmp_lookup_init_route_default (NMPLookup *lookup,
                                                NMPObjectType obj_type);
const NMPLookup *nmp_lookup_init_route_by_weak_id (NMPLookup *lookup,
                                                   const NMPObject *obj);
const NMPLookup *nmp_lookup_init_ip4_route_by_weak_id (NMPLookup *lookup,
                                                       in_addr_t network,
                                                       guint plen,
                                                       guint32 metric,
                                                       guint8 tos);
const NMPLookup *nmp_lookup_init_ip6_route_by_weak_id (NMPLookup *lookup,
                                                       const struct in6_addr *network,
                                                       guint plen,
                                                       guint32 metric,
                                                       const struct in6_addr *src,
                                                       guint8 src_plen);
const NMPLookup *nmp_lookup_init_object_by_addr_family (NMPLookup *lookup,
                                                        NMPObjectType obj_type,
                                                        int addr_family);

GArray *nmp_cache_lookup_to_array (const NMDedupMultiHeadEntry *head_entry,
                                   NMPObjectType obj_type,
                                   gboolean visible_only);

static inline gboolean
nmp_cache_iter_next (NMDedupMultiIter *iter, const NMPObject **out_obj)
{
	gboolean has_next;

	has_next = nm_dedup_multi_iter_next (iter);
	nm_assert (!has_next || NMP_OBJECT_IS_VALID (iter->current->obj));
	if (out_obj)
		*out_obj = has_next ? iter->current->obj : NULL;
	return has_next;
}

static inline gboolean
nmp_cache_iter_next_link (NMDedupMultiIter *iter, const NMPlatformLink **out_obj)
{
	gboolean has_next;

	has_next = nm_dedup_multi_iter_next (iter);
	nm_assert (!has_next || NMP_OBJECT_GET_TYPE (iter->current->obj) == NMP_OBJECT_TYPE_LINK);
	if (out_obj)
		*out_obj = has_next ? &(((const NMPObject *) iter->current->obj)->link) : NULL;
	return has_next;
}

#define nmp_cache_iter_for_each(iter, head, obj) \
	for (nm_dedup_multi_iter_init ((iter), \
	                               (head)); \
	     nmp_cache_iter_next ((iter), (obj)); \
	     )

#define nmp_cache_iter_for_each_link(iter, head, obj) \
	for (nm_dedup_multi_iter_init ((iter), \
	                               (head)); \
	     nmp_cache_iter_next_link ((iter), (obj)); \
	     )

const NMPObject *nmp_cache_lookup_link_full (const NMPCache *cache,
                                             int ifindex,
                                             const char *ifname,
                                             gboolean visible_only,
                                             NMLinkType link_type,
                                             NMPObjectMatchFn match_fn,
                                             gpointer user_data);

gboolean nmp_cache_link_connected_for_slave (int ifindex_master, const NMPObject *slave);
gboolean nmp_cache_link_connected_needs_toggle (const NMPCache *cache, const NMPObject *master, const NMPObject *potential_slave, const NMPObject *ignore_slave);
const NMPObject *nmp_cache_link_connected_needs_toggle_by_ifindex (const NMPCache *cache, int master_ifindex, const NMPObject *potential_slave, const NMPObject *ignore_slave);

gboolean nmp_cache_use_udev_get (const NMPCache *cache);

void ASSERT_nmp_cache_is_consistent (const NMPCache *cache);

NMPCacheOpsType nmp_cache_remove (NMPCache *cache,
                                  const NMPObject *obj_needle,
                                  gboolean equals_by_ptr,
                                  gboolean only_dirty,
                                  const NMPObject **out_obj_old);
NMPCacheOpsType nmp_cache_remove_netlink (NMPCache *cache,
                                          const NMPObject *obj_needle,
                                          const NMPObject **out_obj_old,
                                          const NMPObject **out_obj_new);
NMPCacheOpsType nmp_cache_update_netlink (NMPCache *cache,
                                          NMPObject *obj_hand_over,
                                          gboolean is_dump,
                                          const NMPObject **out_obj_old,
                                          const NMPObject **out_obj_new);
NMPCacheOpsType nmp_cache_update_netlink_route (NMPCache *cache,
                                                NMPObject *obj_hand_over,
                                                gboolean is_dump,
                                                guint16 nlmsgflags,
                                                const NMPObject **out_obj_old,
                                                const NMPObject **out_obj_new,
                                                const NMPObject **out_obj_replace,
                                                gboolean *out_resync_required);
NMPCacheOpsType nmp_cache_update_link_udev (NMPCache *cache,
                                            int ifindex,
                                            struct udev_device *udevice,
                                            const NMPObject **out_obj_old,
                                            const NMPObject **out_obj_new);
NMPCacheOpsType nmp_cache_update_link_master_connected (NMPCache *cache,
                                                        int ifindex,
                                                        const NMPObject **out_obj_old,
                                                        const NMPObject **out_obj_new);

static inline const NMDedupMultiEntry *
nmp_cache_reresolve_main_entry (NMPCache *cache,
                                const NMDedupMultiEntry *entry,
                                const NMPLookup *lookup)
{
	const NMDedupMultiEntry *main_entry;

	nm_assert (cache);
	nm_assert (entry);
	nm_assert (lookup);

	if (lookup->cache_id_type == NMP_CACHE_ID_TYPE_OBJECT_TYPE) {
		nm_assert (entry == nmp_cache_lookup_entry (cache, entry->obj));
		return entry;
	}

	/* we only track the dirty flag for the OBJECT-TYPE index. That means,
	 * for other lookup types we need to check the dirty flag of the main-entry. */
	main_entry = nmp_cache_lookup_entry (cache, entry->obj);

	nm_assert (main_entry);
	nm_assert (main_entry->obj == entry->obj);

	return main_entry;
}

void nmp_cache_dirty_set_all_main (NMPCache *cache,
                                   const NMPLookup *lookup);

NMPCache *nmp_cache_new (NMDedupMultiIndex *multi_idx, gboolean use_udev);
void nmp_cache_free (NMPCache *cache);

static inline void
ASSERT_nmp_cache_ops (const NMPCache *cache,
                      NMPCacheOpsType ops_type,
                      const NMPObject *obj_old,
                      const NMPObject *obj_new)
{
#if NM_MORE_ASSERTS
	nm_assert (cache);
	nm_assert (obj_old || obj_new);
	nm_assert (!obj_old || (   NMP_OBJECT_IS_VALID (obj_old)
	                        && !NMP_OBJECT_IS_STACKINIT (obj_old)
	                        && nmp_object_is_alive (obj_old)));
	nm_assert (!obj_new || (   NMP_OBJECT_IS_VALID (obj_new)
	                        && !NMP_OBJECT_IS_STACKINIT (obj_new)
	                        && nmp_object_is_alive (obj_new)));

	switch (ops_type) {
	case NMP_CACHE_OPS_UNCHANGED:
		nm_assert (obj_old == obj_new);
		break;
	case NMP_CACHE_OPS_ADDED:
		nm_assert (!obj_old && obj_new);
		break;
	case NMP_CACHE_OPS_UPDATED:
		nm_assert (obj_old &&  obj_new && obj_old != obj_new);
		break;
	case NMP_CACHE_OPS_REMOVED:
		nm_assert (obj_old && !obj_new);
		break;
	default:
		nm_assert_not_reached ();
	}

	nm_assert (obj_new == NULL || obj_old == NULL || nmp_object_id_equal (obj_new, obj_old));
	nm_assert (!obj_old || !obj_new || NMP_OBJECT_GET_CLASS (obj_old) == NMP_OBJECT_GET_CLASS (obj_new));

	nm_assert (obj_new == nmp_cache_lookup_obj (cache, obj_new ?: obj_old));
#endif
}

const NMDedupMultiHeadEntry *nm_platform_lookup_all (NMPlatform *platform,
                                                     NMPCacheIdType cache_id_type,
                                                     const NMPObject *obj);

const NMDedupMultiEntry *nm_platform_lookup_entry (NMPlatform *platform,
                                                   NMPCacheIdType cache_id_type,
                                                   const NMPObject *obj);

static inline const NMPObject *
nm_platform_lookup_obj (NMPlatform *platform,
                        NMPCacheIdType cache_id_type,
                        const NMPObject *obj)
{
	return nm_dedup_multi_entry_get_obj (nm_platform_lookup_entry (platform,
	                                                               cache_id_type,
	                                                               obj));
}

static inline const NMDedupMultiHeadEntry *
nm_platform_lookup_obj_type (NMPlatform *platform,
                             NMPObjectType obj_type)
{
	NMPLookup lookup;

	nmp_lookup_init_obj_type (&lookup, obj_type);
	return nm_platform_lookup (platform, &lookup);
}

static inline const NMDedupMultiHeadEntry *
nm_platform_lookup_link_by_ifname (NMPlatform *platform,
                                   const char *ifname)
{
	NMPLookup lookup;

	nmp_lookup_init_link_by_ifname (&lookup, ifname);
	return nm_platform_lookup (platform, &lookup);
}

static inline const NMDedupMultiHeadEntry *
nm_platform_lookup_object (NMPlatform *platform,
                           NMPObjectType obj_type,
                           int ifindex)
{
	NMPLookup lookup;

	nmp_lookup_init_object (&lookup, obj_type, ifindex);
	return nm_platform_lookup (platform, &lookup);
}

static inline GPtrArray *
nm_platform_lookup_object_clone (NMPlatform *platform,
                                 NMPObjectType obj_type,
                                 int ifindex,
                                 NMPObjectPredicateFunc predicate,
                                 gpointer user_data)
{
	NMPLookup lookup;

	nmp_lookup_init_object (&lookup, obj_type, ifindex);
	return nm_platform_lookup_clone (platform, &lookup, predicate, user_data);
}

static inline const NMDedupMultiHeadEntry *
nm_platform_lookup_route_default (NMPlatform *platform,
                                  NMPObjectType obj_type)
{
	NMPLookup lookup;

	nmp_lookup_init_route_default (&lookup, obj_type);
	return nm_platform_lookup (platform, &lookup);
}

static inline GPtrArray *
nm_platform_lookup_route_default_clone (NMPlatform *platform,
                                        NMPObjectType obj_type,
                                        NMPObjectPredicateFunc predicate,
                                        gpointer user_data)
{
	NMPLookup lookup;

	nmp_lookup_init_route_default (&lookup, obj_type);
	return nm_platform_lookup_clone (platform, &lookup, predicate, user_data);
}

static inline const NMDedupMultiHeadEntry *
nm_platform_lookup_ip4_route_by_weak_id (NMPlatform *platform,
                                         in_addr_t network,
                                         guint plen,
                                         guint32 metric,
                                         guint8 tos)
{
	NMPLookup lookup;

	nmp_lookup_init_ip4_route_by_weak_id (&lookup, network, plen, metric, tos);
	return nm_platform_lookup (platform, &lookup);
}

static inline const NMDedupMultiHeadEntry *
nm_platform_lookup_ip6_route_by_weak_id (NMPlatform *platform,
                                         const struct in6_addr *network,
                                         guint plen,
                                         guint32 metric,
                                         const struct in6_addr *src,
                                         guint8 src_plen)
{
	NMPLookup lookup;

	nmp_lookup_init_ip6_route_by_weak_id (&lookup, network, plen, metric, src, src_plen);
	return nm_platform_lookup (platform, &lookup);
}

static inline const NMDedupMultiHeadEntry *
nm_platform_lookup_object_by_addr_family (NMPlatform *platform,
                                          NMPObjectType obj_type,
                                          int addr_family)
{
	NMPLookup lookup;

	nmp_lookup_init_object_by_addr_family (&lookup, obj_type, addr_family);
	return nm_platform_lookup (platform, &lookup);
}

#endif /* __NMP_OBJECT_H__ */
