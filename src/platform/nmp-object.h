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
 * Copyright (C) 2015 Red Hat, Inc.
 */

#ifndef __NMP_OBJECT_H__
#define __NMP_OBJECT_H__

#include "nm-utils/nm-obj.h"
#include "nm-utils/nm-dedup-multi.h"
#include "nm-platform.h"

struct udev_device;

typedef enum { /*< skip >*/
	NMP_OBJECT_TO_STRING_ID,
	NMP_OBJECT_TO_STRING_PUBLIC,
	NMP_OBJECT_TO_STRING_ALL,
} NMPObjectToStringMode;

typedef enum { /*< skip >*/
	NMP_CACHE_OPS_UNCHANGED       = NM_PLATFORM_SIGNAL_NONE,
	NMP_CACHE_OPS_UPDATED         = NM_PLATFORM_SIGNAL_CHANGED,
	NMP_CACHE_OPS_ADDED           = NM_PLATFORM_SIGNAL_ADDED,
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
 * For example, of the index type NMP_CACHE_ID_TYPE_ADDRROUTE_BY_IFINDEX there
 * are multiple instances (for different route/addresses, v4/v6, per-ifindex).
 *
 * But one object, can only be indexed by one particular index of a
 * type. For example, a certain address instance is only indexed by
 * the index NMP_CACHE_ID_TYPE_ADDRROUTE_BY_IFINDEX with
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
	 * distiction doesn't exist, as all addresses/routes that are alive
	 * are visible as well. */
	NMP_CACHE_ID_TYPE_OBJECT_TYPE,

	/* index for the link objects by ifname. */
	NMP_CACHE_ID_TYPE_LINK_BY_IFNAME,

	/* indeces for the visible default-routes, ignoring ifindex.
	 * This index only contains two partitions: all visible default-routes,
	 * separate for IPv4 and IPv6. */
	NMP_CACHE_ID_TYPE_DEFAULT_ROUTES,

	/* all the addresses/routes (by object-type) for an ifindex. */
	NMP_CACHE_ID_TYPE_ADDRROUTE_BY_IFINDEX,

	/* Consider all the destination fields of a route, that is, the ID without the ifindex
	 * and gateway (meaning: network/plen,metric).
	 * The reason for this is that `ip route change` can replace an existing route
	 * and modify it's ifindex/gateway. Effectively, that means it deletes an existing
	 * route and adds a different one (as the ID of the route changes). However, it only
	 * sends one RTM_NEWADDR notification without notifying about the deletion. We detect
	 * that by having this index to contain overlapping routes which require special
	 * cache-resync. */
	NMP_CACHE_ID_TYPE_ROUTES_BY_DESTINATION,

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

	guint (*cmd_obj_hash) (const NMPObject *obj);
	int (*cmd_obj_cmp) (const NMPObject *obj1, const NMPObject *obj2);
	void (*cmd_obj_copy) (NMPObject *dst, const NMPObject *src);
	void (*cmd_obj_dispose) (NMPObject *obj);
	gboolean (*cmd_obj_is_alive) (const NMPObject *obj);
	gboolean (*cmd_obj_is_visible) (const NMPObject *obj);
	const char *(*cmd_obj_to_string) (const NMPObject *obj, NMPObjectToStringMode to_string_mode, char *buf, gsize buf_size);

	/* functions that operate on NMPlatformObject */
	void (*cmd_plobj_id_copy) (NMPlatformObject *dst, const NMPlatformObject *src);
	int (*cmd_plobj_id_cmp) (const NMPlatformObject *obj1, const NMPlatformObject *obj2);
	guint (*cmd_plobj_id_hash) (const NMPlatformObject *obj);
	const char *(*cmd_plobj_to_string_id) (const NMPlatformObject *obj, char *buf, gsize buf_size);
	const char *(*cmd_plobj_to_string) (const NMPlatformObject *obj, char *buf, gsize len);
	guint (*cmd_plobj_hash) (const NMPlatformObject *obj);
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

struct _NMPObject {
	union {
		NMDedupMultiObj parent;
		const NMPClass *_class;
	};
	union {
		NMPlatformObject        object;

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

		NMPlatformLnkVlan       lnk_vlan;
		NMPObjectLnkVlan        _lnk_vlan;

		NMPlatformLnkVxlan      lnk_vxlan;
		NMPObjectLnkVxlan       _lnk_vxlan;

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
	};
};

static inline gboolean
NMP_CLASS_IS_VALID (const NMPClass *klass)
{
	return klass >= &_nmp_classes[0]
	    && klass <= &_nmp_classes[G_N_ELEMENTS (_nmp_classes)]
	    && ((((char *) klass) - ((char *) _nmp_classes)) % (sizeof (_nmp_classes[0]))) == 0;
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

#define NMP_OBJECT_CAST_LINK(obj) \
	({ \
		typeof (obj) _obj = (obj); \
		\
		nm_assert (!_obj || NMP_OBJECT_GET_TYPE ((const NMPObject *) _obj) == NMP_OBJECT_TYPE_LINK); \
		_obj ? &_NM_CONSTCAST (NMPObject, _obj)->link : NULL; \
	})

#define NMP_OBJECT_CAST_IP_ADDRESS(obj) \
	({ \
		typeof (obj) _obj = (obj); \
		\
		nm_assert (!_obj || NM_IN_SET (NMP_OBJECT_GET_TYPE (_obj), NMP_OBJECT_TYPE_IP4_ADDRESS, NMP_OBJECT_TYPE_IP6_ADDRESS)); \
		_obj ? &_NM_CONSTCAST (NMPObject, _obj)->ip_address : NULL; \
	})

#define NMP_OBJECT_CAST_IPX_ADDRESS(obj) \
	({ \
		typeof (obj) _obj = (obj); \
		\
		nm_assert (!_obj || NM_IN_SET (NMP_OBJECT_GET_TYPE (_obj), NMP_OBJECT_TYPE_IP4_ADDRESS, NMP_OBJECT_TYPE_IP6_ADDRESS)); \
		_obj ? &_NM_CONSTCAST (NMPObject, _obj)->ipx_address : NULL; \
	})

#define NMP_OBJECT_CAST_IP4_ADDRESS(obj) \
	({ \
		typeof (obj) _obj = (obj); \
		\
		nm_assert (!_obj || NMP_OBJECT_GET_TYPE ((const NMPObject *) _obj) == NMP_OBJECT_TYPE_IP4_ADDRESS); \
		_obj ? &_NM_CONSTCAST (NMPObject, _obj)->ip4_address : NULL; \
	})

#define NMP_OBJECT_CAST_IP6_ADDRESS(obj) \
	({ \
		typeof (obj) _obj = (obj); \
		\
		nm_assert (!_obj || NMP_OBJECT_GET_TYPE ((const NMPObject *) _obj) == NMP_OBJECT_TYPE_IP6_ADDRESS); \
		_obj ? &_NM_CONSTCAST (NMPObject, _obj)->ip6_address : NULL; \
	})

#define NMP_OBJECT_CAST_IPX_ROUTE(obj) \
	({ \
		typeof (obj) _obj = (obj); \
		\
		nm_assert (!_obj || NM_IN_SET (NMP_OBJECT_GET_TYPE (_obj), NMP_OBJECT_TYPE_IP4_ROUTE, NMP_OBJECT_TYPE_IP6_ROUTE)); \
		_obj ? &_NM_CONSTCAST (NMPObject, _obj)->ipx_route : NULL; \
	})

#define NMP_OBJECT_CAST_IP_ROUTE(obj) \
	({ \
		typeof (obj) _obj = (obj); \
		\
		nm_assert (!_obj || NM_IN_SET (NMP_OBJECT_GET_TYPE (_obj), NMP_OBJECT_TYPE_IP4_ROUTE, NMP_OBJECT_TYPE_IP6_ROUTE)); \
		_obj ? &_NM_CONSTCAST (NMPObject, _obj)->ip_route : NULL; \
	})

#define NMP_OBJECT_CAST_IP4_ROUTE(obj) \
	({ \
		typeof (obj) _obj = (obj); \
		\
		nm_assert (!_obj || NMP_OBJECT_GET_TYPE ((const NMPObject *) _obj) == NMP_OBJECT_TYPE_IP4_ROUTE); \
		_obj ? &_NM_CONSTCAST (NMPObject, _obj)->ip4_route : NULL; \
	})

#define NMP_OBJECT_CAST_IP6_ROUTE(obj) \
	({ \
		typeof (obj) _obj = (obj); \
		\
		nm_assert (!_obj || NMP_OBJECT_GET_TYPE ((const NMPObject *) _obj) == NMP_OBJECT_TYPE_IP6_ROUTE); \
		_obj ? &_NM_CONSTCAST (NMPObject, _obj)->ip6_route : NULL; \
	})

const NMPClass *nmp_class_from_type (NMPObjectType obj_type);

static inline const NMPObject *
nmp_object_ref (const NMPObject *obj)
{
	/* ref and unref accept const pointers. NMPObject is supposed to be shared
	 * and kept immutable. Disallowing to take/retrun a reference to a const
	 * NMPObject is cumbersome, because callers are precisely expected to
	 * keep a ref on the otherwise immutable object. */
	g_return_val_if_fail (NMP_OBJECT_IS_VALID (obj), NULL);
	g_return_val_if_fail (obj->parent._ref_count != NM_OBJ_REF_COUNT_STACKINIT, NULL);

	return (const NMPObject *) nm_dedup_multi_obj_ref ((const NMDedupMultiObj *) obj);
}

static inline const NMPObject *
nmp_object_unref (const NMPObject *obj)
{
	nm_dedup_multi_obj_unref ((const NMDedupMultiObj *) obj);
	return NULL;
}

NMPObject *nmp_object_new (NMPObjectType obj_type, const NMPlatformObject *plob);
NMPObject *nmp_object_new_link (int ifindex);

const NMPObject *nmp_object_stackinit (NMPObject *obj, NMPObjectType obj_type, const NMPlatformObject *plobj);

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
const NMPObject *nmp_object_stackinit_id_ip4_route (NMPObject *obj, int ifindex, guint32 network, guint8 plen, guint32 metric);
const NMPObject *nmp_object_stackinit_id_ip6_route (NMPObject *obj, int ifindex, const struct in6_addr *network, guint8 plen, guint32 metric);

const char *nmp_object_to_string (const NMPObject *obj, NMPObjectToStringMode to_string_mode, char *buf, gsize buf_size);
guint nmp_object_hash (const NMPObject *obj);
int nmp_object_cmp (const NMPObject *obj1, const NMPObject *obj2);
gboolean nmp_object_equal (const NMPObject *obj1, const NMPObject *obj2);
void nmp_object_copy (NMPObject *dst, const NMPObject *src, gboolean id_only);
NMPObject *nmp_object_clone (const NMPObject *obj, gboolean id_only);

int nmp_object_id_cmp (const NMPObject *obj1, const NMPObject *obj2);
guint nmp_object_id_hash (const NMPObject *obj);

static inline gboolean
nmp_object_id_equal (const NMPObject *obj1, const NMPObject *obj2)
{
	return nmp_object_id_cmp (obj1, obj2) == 0;
}

gboolean nmp_object_is_alive (const NMPObject *obj);
gboolean nmp_object_is_visible (const NMPObject *obj);

void _nmp_object_fixup_link_udev_fields (NMPObject **obj_new, NMPObject *obj_orig, gboolean use_udev);

#define nm_auto_nmpobj __attribute__((cleanup(_nm_auto_nmpobj_cleanup)))
static inline void
_nm_auto_nmpobj_cleanup (gpointer p)
{
	nmp_object_unref (*((const NMPObject **) p));
}

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
const NMPLookup *nmp_lookup_init_addrroute (NMPLookup *lookup,
                                            NMPObjectType obj_type,
                                            int ifindex);
const NMPLookup *nmp_lookup_init_route_visible (NMPLookup *lookup,
                                                NMPObjectType obj_type,
                                                int ifindex,
                                                gboolean only_default);
const NMPLookup *nmp_lookup_init_route_by_dest (NMPLookup *lookup,
                                                int addr_family,
                                                gconstpointer network,
                                                guint plen,
                                                guint32 metric);

GArray *nmp_cache_lookup_to_array (const NMDedupMultiHeadEntry *head_entry,
                                   NMPObjectType obj_type,
                                   gboolean visible_only);

static inline gboolean
nmp_cache_iter_next (NMDedupMultiIter *iter, const NMPObject **out_obj)
{
	gboolean has_next;

	has_next = nm_dedup_multi_iter_next (iter);
	if (has_next) {
		nm_assert (NMP_OBJECT_IS_VALID (iter->current->obj));
		NM_SET_OUT (out_obj, iter->current->obj);
	}
	return has_next;
}

static inline gboolean
nmp_cache_iter_next_link (NMDedupMultiIter *iter, const NMPlatformLink **out_obj)
{
	gboolean has_next;

	has_next = nm_dedup_multi_iter_next (iter);
	if (has_next) {
		nm_assert (NMP_OBJECT_GET_TYPE (iter->current->obj) == NMP_OBJECT_TYPE_LINK);
		NM_SET_OUT (out_obj, &(((const NMPObject *) iter->current->obj)->link));
	}
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

const NMPObject *nmp_cache_find_other_route_for_same_destination (const NMPCache *cache, const NMPObject *route);

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
                                  const NMPObject **out_obj_old);
NMPCacheOpsType nmp_cache_remove_netlink (NMPCache *cache,
                                          const NMPObject *obj_needle,
                                          const NMPObject **out_obj_old,
                                          const NMPObject **out_obj_new);
NMPCacheOpsType nmp_cache_update_netlink (NMPCache *cache,
                                          NMPObject *obj,
                                          const NMPObject **out_obj_old,
                                          const NMPObject **out_obj_new);
NMPCacheOpsType nmp_cache_update_link_udev (NMPCache *cache,
                                            int ifindex,
                                            struct udev_device *udevice,
                                            const NMPObject **out_obj_old,
                                            const NMPObject **out_obj_new);
NMPCacheOpsType nmp_cache_update_link_master_connected (NMPCache *cache,
                                                        int ifindex,
                                                        const NMPObject **out_obj_old,
                                                        const NMPObject **out_obj_new);

void nmp_cache_dirty_set_all (NMPCache *cache, NMPObjectType obj_type);

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
nm_platform_lookup_addrroute (NMPlatform *platform,
                              NMPObjectType obj_type,
                              int ifindex)
{
	NMPLookup lookup;

	nmp_lookup_init_addrroute (&lookup, obj_type, ifindex);
	return nm_platform_lookup (platform, &lookup);
}

static inline const NMDedupMultiHeadEntry *
nm_platform_lookup_route_visible (NMPlatform *platform,
                                  NMPObjectType obj_type,
                                  int ifindex,
                                  gboolean only_default)
{
	NMPLookup lookup;

	nmp_lookup_init_route_visible (&lookup, obj_type, ifindex, only_default);
	return nm_platform_lookup (platform, &lookup);
}

static inline GPtrArray *
nm_platform_lookup_route_visible_clone (NMPlatform *platform,
                                        NMPObjectType obj_type,
                                        int ifindex,
                                        gboolean only_default,
                                        gboolean (*predicate) (const NMPObject *obj, gpointer user_data),
                                        gpointer user_data)
{
	NMPLookup lookup;

	nmp_lookup_init_route_visible (&lookup, obj_type, ifindex, only_default);
	return nm_platform_lookup_clone (platform, &lookup, predicate, user_data);
}

static inline const NMDedupMultiHeadEntry *
nm_platform_lookup_route_by_dest (NMPlatform *platform,
                                  int addr_family,
                                  gconstpointer network,
                                  guint plen,
                                  guint32 metric)
{
	NMPLookup lookup;

	nmp_lookup_init_route_by_dest (&lookup, addr_family, network, plen, metric);
	return nm_platform_lookup (platform, &lookup);
}

#endif /* __NMP_OBJECT_H__ */
