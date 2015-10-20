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

#include "config.h"

#include "nm-platform.h"
#include "nm-multi-index.h"
#include "nm-macros-internal.h"

#include <netlink/netlink.h>
#include <gudev/gudev.h>


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
 * For example, of the index type NMP_CACHE_ID_TYPE_ADDRROUTE_VISIBLE_BY_IFINDEX there
 * are multiple instances (for different route/addresses, v4/v6, per-ifindex).
 *
 * But one object, can only be indexed by one particular index of a
 * type. For example, a certain address instance is only indexed by
 * the index NMP_CACHE_ID_TYPE_ADDRROUTE_VISIBLE_BY_IFINDEX with
 * matching v4/v6 and ifindex -- or maybe not at all if it isn't visible.
 * */
typedef enum { /*< skip >*/
	/* all the objects of a certain type */
	NMP_CACHE_ID_TYPE_OBJECT_TYPE,

	/* all the visible objects of a certain type */
	NMP_CACHE_ID_TYPE_OBJECT_TYPE_VISIBLE_ONLY,

	/* indeces for the visible routes, ignoring ifindex. */
	NMP_CACHE_ID_TYPE_ROUTES_VISIBLE_NO_DEFAULT,
	NMP_CACHE_ID_TYPE_ROUTES_VISIBLE_ONLY_DEFAULT,

	/* all the visible addresses/routes (by object-type) for an ifindex. */
	NMP_CACHE_ID_TYPE_ADDRROUTE_VISIBLE_BY_IFINDEX,

	/* three indeces for the visible routes, per ifindex. */
	NMP_CACHE_ID_TYPE_ROUTES_VISIBLE_BY_IFINDEX_NO_DEFAULT,
	NMP_CACHE_ID_TYPE_ROUTES_VISIBLE_BY_IFINDEX_ONLY_DEFAULT,

	__NMP_CACHE_ID_TYPE_MAX,
	NMP_CACHE_ID_TYPE_MAX = __NMP_CACHE_ID_TYPE_MAX - 1,
} NMPCacheIdType;

typedef struct _NMPObject NMPObject;

typedef struct {
	union {
		NMMultiIndexId base;
		guint8 _id_type; /* NMPCacheIdType as guint8 */
		struct {
			/* NMP_CACHE_ID_TYPE_OBJECT_TYPE */
			/* NMP_CACHE_ID_TYPE_OBJECT_TYPE_VISIBLE_ONLY */
			/* NMP_CACHE_ID_TYPE_ROUTES_VISIBLE_NO_DEFAULT */
			/* NMP_CACHE_ID_TYPE_ROUTES_VISIBLE_ONLY_DEFAULT */
			guint8 _id_type;
			guint8 obj_type; /* NMPObjectType as guint8 */
		} object_type;
		struct {
			/* NMP_CACHE_ID_TYPE_ADDRROUTE_VISIBLE_BY_IFINDEX */
			/* NMP_CACHE_ID_TYPE_ROUTES_VISIBLE_BY_IFINDEX_NO_DEFAULT */
			/* NMP_CACHE_ID_TYPE_ROUTES_VISIBLE_BY_IFINDEX_ONLY_DEFAULT */
			guint8 _id_type;
			guint8 obj_type; /* NMPObjectType as guint8 */
			int ifindex;
		} object_type_by_ifindex;
	};
} NMPCacheId;

extern NMPCacheId _nmp_cache_id_static;
#define NMP_CACHE_ID_STATIC  (&_nmp_cache_id_static)

typedef struct {
	NMPObjectType obj_type;
	int addr_family;
	int rtm_gettype;
	int sizeof_data;
	int sizeof_public;
	const char *obj_type_name;
	const char *nl_type;
	const char *signal_type;

	/* returns %FALSE, if the obj type would never have an entry for index type @id_type. If @obj has an index,
	 * initialize @id and set @out_id to it. Otherwise, @out_id is NULL. */
	gboolean (*cmd_obj_init_cache_id) (const NMPObject *obj, NMPCacheIdType id_type, NMPCacheId *id, const NMPCacheId **out_id);

	gboolean (*cmd_obj_equal) (const NMPObject *obj1, const NMPObject *obj2);
	void (*cmd_obj_copy) (NMPObject *dst, const NMPObject *src);
	void (*cmd_obj_stackinit_id) (NMPObject *obj, const NMPObject *src);
	void (*cmd_obj_dispose) (NMPObject *obj);
	gboolean (*cmd_obj_is_alive) (const NMPObject *obj);
	gboolean (*cmd_obj_is_visible) (const NMPObject *obj);

	/* functions that operate on NMPlatformObject */
	gboolean (*cmd_plobj_init_from_nl) (NMPlatform *platform, NMPlatformObject *obj, const struct nl_object *nlo, gboolean id_only, gboolean complete_from_cache);
	struct nl_object *(*cmd_plobj_to_nl) (NMPlatform *platform, const NMPlatformObject *obj, gboolean id_only);
	void (*cmd_plobj_id_copy) (NMPlatformObject *dst, const NMPlatformObject *src);
	gboolean (*cmd_plobj_id_equal) (const NMPlatformObject *obj1, const NMPlatformObject *obj2);
	guint (*cmd_plobj_id_hash) (const NMPlatformObject *obj);
	const char *(*cmd_plobj_to_string_id) (const NMPlatformObject *obj, char *buf, gsize buf_size);
	const char *(*cmd_plobj_to_string) (const NMPlatformObject *obj);
	int (*cmd_plobj_cmp) (const NMPlatformObject *obj1, const NMPlatformObject *obj2);
} NMPClass;

extern const NMPClass _nmp_classes[NMP_OBJECT_TYPE_MAX];

typedef struct {
	NMPlatformLink _public;

	struct {
		guint8 is_in_netlink;
	} netlink;

	struct {
		GUdevDevice *device;
	} udev;
} NMPObjectLink;

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
	const NMPClass *_class;
	int _ref_count;
	guint8 is_cached;
	union {
		NMPlatformObject        object;

		NMPlatformLink          link;
		NMPObjectLink           _link;

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
	    && ((((char *) klass) - ((char *) NULL)) % (&_nmp_classes[1] - &_nmp_classes[0])) == 0;
}

#define NMP_REF_COUNT_STACKINIT (G_MAXINT)

static inline NMPObject *
NMP_OBJECT_UP_CAST(const NMPlatformObject *plobj)
{
	NMPObject *obj;

	obj = plobj
	      ? (NMPObject *) ( &(((char *) plobj)[-((int) G_STRUCT_OFFSET (NMPObject, object))]) )
	      : NULL;
	nm_assert (!obj || (obj->_ref_count > 0 && NMP_CLASS_IS_VALID (obj->_class)));
	return obj;
}
#define NMP_OBJECT_UP_CAST(plobj) (NMP_OBJECT_UP_CAST ((const NMPlatformObject *) (plobj)))

static inline gboolean
NMP_OBJECT_IS_VALID (const NMPObject *obj)
{
	nm_assert (!obj || (   obj
	                    && obj->_ref_count > 0
	                    && NMP_CLASS_IS_VALID (obj->_class)));

	/* There isn't really much to check. Either @obj is NULL, or we must
	 * assume that it points to valid memory. */
	return obj != NULL;
}

static inline gboolean
NMP_OBJECT_IS_STACKINIT (const NMPObject *obj)
{
	nm_assert (!obj || NMP_OBJECT_IS_VALID (obj));

	return obj && obj->_ref_count == NMP_REF_COUNT_STACKINIT;
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



const NMPClass *nmp_class_from_type (NMPObjectType obj_type);

NMPObject *nmp_object_ref (NMPObject *object);
void nmp_object_unref (NMPObject *object);
NMPObject *nmp_object_new (NMPObjectType obj_type, const NMPlatformObject *plob);
NMPObject *nmp_object_new_link (int ifindex);

const NMPObject *nmp_object_stackinit (NMPObject *obj, NMPObjectType obj_type, const NMPlatformObject *plobj);
const NMPObject *nmp_object_stackinit_id  (NMPObject *obj, const NMPObject *src);
const NMPObject *nmp_object_stackinit_id_link (NMPObject *obj, int ifindex);
const NMPObject *nmp_object_stackinit_id_ip4_address (NMPObject *obj, int ifindex, guint32 address, int plen, guint32 peer_address);
const NMPObject *nmp_object_stackinit_id_ip6_address (NMPObject *obj, int ifindex, const struct in6_addr *address, int plen);
const NMPObject *nmp_object_stackinit_id_ip4_route (NMPObject *obj, int ifindex, guint32 network, int plen, guint32 metric);
const NMPObject *nmp_object_stackinit_id_ip6_route (NMPObject *obj, int ifindex, const struct in6_addr *network, int plen, guint32 metric);

const char *nmp_object_to_string (const NMPObject *obj, NMPObjectToStringMode to_string_mode, char *buf, gsize buf_size);
int nmp_object_cmp (const NMPObject *obj1, const NMPObject *obj2);
gboolean nmp_object_equal (const NMPObject *obj1, const NMPObject *obj2);
void nmp_object_copy (NMPObject *dst, const NMPObject *src, gboolean id_only);
NMPObject *nmp_object_clone (const NMPObject *obj, gboolean id_only);
gboolean nmp_object_id_equal (const NMPObject *obj1, const NMPObject *obj2);
guint nmp_object_id_hash (const NMPObject *obj);
gboolean nmp_object_is_alive (const NMPObject *obj);
gboolean nmp_object_is_visible (const NMPObject *obj);

void _nmp_object_fixup_link_udev_fields (NMPObject *obj, gboolean use_udev);

#define nm_auto_nmpobj __attribute__((cleanup(_nm_auto_nmpobj_cleanup)))
static inline void
_nm_auto_nmpobj_cleanup (NMPObject **pobj)
{
	nmp_object_unref (*pobj);
}

typedef struct _NMPCache NMPCache;

typedef void (*NMPCachePreHook) (NMPCache *cache, const NMPObject *old, const NMPObject *new, NMPCacheOpsType ops_type, gpointer user_data);
typedef gboolean (*NMPObjectMatchFn) (const NMPObject *obj, gpointer user_data);

gboolean nmp_cache_id_equal (const NMPCacheId *a, const NMPCacheId *b);
guint nmp_cache_id_hash (const NMPCacheId *id);
NMPCacheId *nmp_cache_id_clone (const NMPCacheId *id);
void nmp_cache_id_destroy (NMPCacheId *id);

NMPCacheId *nmp_cache_id_init_object_type (NMPCacheId *id, NMPObjectType obj_type, gboolean visible_only);
NMPCacheId *nmp_cache_id_init_addrroute_visible_by_ifindex (NMPCacheId *id, NMPObjectType obj_type, int ifindex);
NMPCacheId *nmp_cache_id_init_routes_visible (NMPCacheId *id, NMPObjectType obj_type, gboolean with_default, gboolean with_non_default, int ifindex);

const NMPlatformObject *const *nmp_cache_lookup_multi (const NMPCache *cache, const NMPCacheId *cache_id, guint *out_len);
GArray *nmp_cache_lookup_multi_to_array (const NMPCache *cache, NMPObjectType obj_type, const NMPCacheId *cache_id);
const NMPObject *nmp_cache_lookup_obj (const NMPCache *cache, const NMPObject *obj);
const NMPObject *nmp_cache_lookup_link (const NMPCache *cache, int ifindex);

const NMPObject *nmp_cache_lookup_link_full (const NMPCache *cache,
                                             int ifindex,
                                             const char *ifname,
                                             gboolean visible_only,
                                             NMLinkType link_type,
                                             NMPObjectMatchFn match_fn,
                                             gpointer user_data);
GHashTable *nmp_cache_lookup_all_to_hash (const NMPCache *cache,
                                          NMPCacheId *cache_id,
                                          GHashTable *hash);

gboolean nmp_cache_link_connected_needs_toggle (const NMPCache *cache, const NMPObject *master, const NMPObject *potential_slave, const NMPObject *ignore_slave);
const NMPObject *nmp_cache_link_connected_needs_toggle_by_ifindex (const NMPCache *cache, int master_ifindex, const NMPObject *potential_slave, const NMPObject *ignore_slave);

gboolean nmp_cache_use_udev_detect (void);
gboolean nmp_cache_use_udev_get (const NMPCache *cache);
gboolean nmp_cache_use_udev_set (NMPCache *cache, gboolean use_udev);

void ASSERT_nmp_cache_is_consistent (const NMPCache *cache);

NMPCacheOpsType nmp_cache_remove (NMPCache *cache, const NMPObject *obj, gboolean equals_by_ptr, NMPObject **out_obj, gboolean *out_was_visible, NMPCachePreHook pre_hook, gpointer user_data);
NMPCacheOpsType nmp_cache_remove_netlink (NMPCache *cache, const NMPObject *obj, NMPObject **out_obj, gboolean *out_was_visible, NMPCachePreHook pre_hook, gpointer user_data);
NMPCacheOpsType nmp_cache_update_netlink (NMPCache *cache, NMPObject *obj, NMPObject **out_obj, gboolean *out_was_visible, NMPCachePreHook pre_hook, gpointer user_data);
NMPCacheOpsType nmp_cache_update_link_udev (NMPCache *cache, int ifindex, GUdevDevice *udev_device, NMPObject **out_obj, gboolean *out_was_visible, NMPCachePreHook pre_hook, gpointer user_data);
NMPCacheOpsType nmp_cache_update_link_master_connected (NMPCache *cache, int ifindex, NMPObject **out_obj, gboolean *out_was_visible, NMPCachePreHook pre_hook, gpointer user_data);

NMPCache *nmp_cache_new (void);
void nmp_cache_free (NMPCache *cache);

NMPObject *nmp_object_from_nl (NMPlatform *platform, const struct nl_object *nlo, gboolean id_only, gboolean complete_from_cache);
struct nl_object *nmp_object_to_nl (NMPlatform *platform, const NMPObject *obj, gboolean id_only);

/* the following functions are currently implemented inside nm-linux-platform, because
 * they depend on utility functions there. */
NMPObjectType _nlo_get_object_type (const struct nl_object *nlo);
gboolean _nmp_vt_cmd_plobj_init_from_nl_link (NMPlatform *platform, NMPlatformObject *_obj, const struct nl_object *_nlo, gboolean id_only, gboolean complete_from_cache);
gboolean _nmp_vt_cmd_plobj_init_from_nl_ip4_address (NMPlatform *platform, NMPlatformObject *_obj, const struct nl_object *_nlo, gboolean id_only, gboolean complete_from_cache);
gboolean _nmp_vt_cmd_plobj_init_from_nl_ip6_address (NMPlatform *platform, NMPlatformObject *_obj, const struct nl_object *_nlo, gboolean id_only, gboolean complete_from_cache);
gboolean _nmp_vt_cmd_plobj_init_from_nl_ip4_route (NMPlatform *platform, NMPlatformObject *_obj, const struct nl_object *_nlo, gboolean id_only, gboolean complete_from_cache);
gboolean _nmp_vt_cmd_plobj_init_from_nl_ip6_route (NMPlatform *platform, NMPlatformObject *_obj, const struct nl_object *_nlo, gboolean id_only, gboolean complete_from_cache);
struct nl_object *_nmp_vt_cmd_plobj_to_nl_link (NMPlatform *platform, const NMPlatformObject *_obj, gboolean id_only);
struct nl_object *_nmp_vt_cmd_plobj_to_nl_ip4_address (NMPlatform *platform, const NMPlatformObject *_obj, gboolean id_only);
struct nl_object *_nmp_vt_cmd_plobj_to_nl_ip6_address (NMPlatform *platform, const NMPlatformObject *_obj, gboolean id_only);
struct nl_object *_nmp_vt_cmd_plobj_to_nl_ip4_route (NMPlatform *platform, const NMPlatformObject *_obj, gboolean id_only);
struct nl_object *_nmp_vt_cmd_plobj_to_nl_ip6_route (NMPlatform *platform, const NMPlatformObject *_obj, gboolean id_only);

#endif /* __NMP_OBJECT_H__ */
