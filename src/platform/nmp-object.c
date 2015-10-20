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

#include "config.h"

#include <unistd.h>

#include "nm-default.h"
#include "nmp-object.h"
#include "nm-platform-utils.h"
#include "NetworkManagerUtils.h"
#include "nm-utils.h"

/*********************************************************************************************/

#define _NMLOG_DOMAIN LOGD_PLATFORM
#define _NMLOG(level, obj, ...) \
    G_STMT_START { \
        const NMLogLevel __level = (level); \
        \
        if (nm_logging_enabled (__level, _NMLOG_DOMAIN)) { \
            const NMPObject *const __obj = (obj); \
            \
            _nm_log (__level, _NMLOG_DOMAIN, 0, \
                     "nmp-object[%p/%s]: " _NM_UTILS_MACRO_FIRST (__VA_ARGS__), \
                     __obj, \
                     (__obj ? NMP_OBJECT_GET_CLASS (__obj)->obj_type_name : "???") \
                     _NM_UTILS_MACRO_REST (__VA_ARGS__)); \
        } \
    } G_STMT_END

/*********************************************************************************************/

struct _NMPCache {
	/* the cache contains only one hash table for all object types, and similarly
	 * it contains only one NMMultiIndex.
	 * This works, because different object types don't ever compare equal and
	 * because their index ids also don't overlap.
	 *
	 * For routes and addresses, the cache contains an address if (and only if) the
	 * object was reported via netlink.
	 * For links, the cache contain a link if it was reported by either netlink
	 * or udev. That means, a link object can be alive, even if it was already
	 * removed via netlink.
	 *
	 * This effectively merges the udev-device cache into the NMPCache.
	 */

	GHashTable *idx_main;
	NMMultiIndex *idx_multi;

	gboolean use_udev;
};

/******************************************************************/

static inline guint
_id_hash_ip6_addr (const struct in6_addr *addr)
{
	guint hash = (guint) 0x897da53981a13ULL;
	int i;

	for (i = 0; i < sizeof (*addr); i++)
		hash = (hash * 33) + ((const guint8 *) addr)[i];
	return hash;
}

/******************************************************************/

static const char *
_link_get_driver (GUdevDevice *udev_device, const char *kind, const char *ifname)
{
	const char *driver = NULL;

	nm_assert (kind == g_intern_string (kind));

	if (udev_device) {
		driver = nmp_utils_udev_get_driver (udev_device);
		if (driver)
			return driver;
	}

	if (kind)
		return kind;

	if (ifname) {
		char *d;

		if (nmp_utils_ethtool_get_driver_info (ifname, &d, NULL, NULL)) {
			driver = d && d[0] ? g_intern_string (d) : NULL;
			g_free (d);
			if (driver)
				return driver;
		}
	}

	return "unknown";
}

void
_nmp_object_fixup_link_udev_fields (NMPObject *obj, gboolean use_udev)
{
	const char *driver = NULL;
	gboolean initialized = FALSE;

	nm_assert (NMP_OBJECT_GET_TYPE (obj) == NMP_OBJECT_TYPE_LINK);

	/* The link contains internal fields that are combined by
	 * properties from netlink and udev. Update those properties */

	/* When a link is not in netlink, it's udev fields don't matter. */
	if (obj->_link.netlink.is_in_netlink) {
		driver = _link_get_driver (obj->_link.udev.device,
		                           obj->link.kind,
		                           obj->link.name);
		if (obj->_link.udev.device)
			initialized = TRUE;
		else if (!use_udev) {
			/* If we don't use udev, we immediately mark the link as initialized.
			 *
			 * For that, we consult @use_udev argument, that is cached via
			 * nmp_cache_use_udev_get(). It is on purpose not to test
			 * for a writable /sys on every call. A minor reason for that is
			 * performance, but the real reason is reproducibility.
			 *
			 * If you want to support changing of whether udev is enabled,
			 * reset the value via nmp_cache_use_udev_set() carefully -- and
			 * possibly update the links in the cache accordingly.
			 * */
			initialized = TRUE;
		}
	}

	obj->link.driver = driver;
	obj->link.initialized = initialized;
}

static void
_nmp_object_fixup_link_master_connected (NMPObject *obj, const NMPCache *cache)
{
	nm_assert (NMP_OBJECT_GET_TYPE (obj) == NMP_OBJECT_TYPE_LINK);

	if (nmp_cache_link_connected_needs_toggle (cache, obj, NULL, NULL))
		obj->link.connected = !obj->link.connected;
}

/******************************************************************/

const NMPClass *
nmp_class_from_type (NMPObjectType obj_type)
{
	g_return_val_if_fail (obj_type > NMP_OBJECT_TYPE_UNKNOWN && obj_type <= NMP_OBJECT_TYPE_MAX, NULL);

	return &_nmp_classes[obj_type - 1];
}

/******************************************************************/

NMPObject *
nmp_object_ref (NMPObject *obj)
{
	g_return_val_if_fail (NMP_OBJECT_IS_VALID (obj), NULL);
	g_return_val_if_fail (obj->_ref_count != NMP_REF_COUNT_STACKINIT, NULL);
	obj->_ref_count++;

	_LOGT (obj, "ref: %d", obj->_ref_count);

	return obj;
}

void
nmp_object_unref (NMPObject *obj)
{
	if (obj) {
		g_return_if_fail (obj->_ref_count > 0);
		g_return_if_fail (obj->_ref_count != NMP_REF_COUNT_STACKINIT);
		_LOGT (obj, "%s: %d",
		       obj->_ref_count <= 1 ? "destroy" : "unref",
		       obj->_ref_count - 1);
		if (--obj->_ref_count <= 0) {
			const NMPClass *klass = obj->_class;

			nm_assert (!obj->is_cached);
			if (klass->cmd_obj_dispose)
				klass->cmd_obj_dispose (obj);
			g_slice_free1 (klass->sizeof_data + G_STRUCT_OFFSET (NMPObject, object), obj);
		}
	}
}

static void
_vt_cmd_obj_dispose_link (NMPObject *obj)
{
	g_clear_object (&obj->_link.udev.device);
	nmp_object_unref (obj->_link.netlink.lnk);
}

static NMPObject *
_nmp_object_new_from_class (const NMPClass *klass)
{
	NMPObject *obj;

	nm_assert (klass);
	nm_assert (klass->sizeof_data > 0);
	nm_assert (klass->sizeof_public > 0 && klass->sizeof_public <= klass->sizeof_data);

	obj = g_slice_alloc0 (klass->sizeof_data + G_STRUCT_OFFSET (NMPObject, object));
	obj->_class = klass;
	obj->_ref_count = 1;
	_LOGT (obj, "new");
	return obj;
}

NMPObject *
nmp_object_new (NMPObjectType obj_type, const NMPlatformObject *plobj)
{
	const NMPClass *klass = nmp_class_from_type (obj_type);
	NMPObject *obj;

	obj = _nmp_object_new_from_class (klass);
	if (plobj)
		memcpy (&obj->object, plobj, klass->sizeof_public);
	return obj;
}

NMPObject *
nmp_object_new_link (int ifindex)
{
	NMPObject *obj;

	obj = nmp_object_new (NMP_OBJECT_TYPE_LINK, NULL);
	obj->link.ifindex = ifindex;
	return obj;
}

/******************************************************************/

static const NMPObject *
_nmp_object_stackinit_from_class (NMPObject *obj, const NMPClass *klass)
{
	nm_assert (klass);

	memset (obj, 0, sizeof (NMPObject));
	obj->_class = klass;
	obj->_ref_count = NMP_REF_COUNT_STACKINIT;
	return obj;
}

const NMPObject *
nmp_object_stackinit (NMPObject *obj, NMPObjectType obj_type, const NMPlatformObject *plobj)
{
	const NMPClass *klass = nmp_class_from_type (obj_type);

	_nmp_object_stackinit_from_class (obj, klass);
	if (plobj)
		memcpy (&obj->object, plobj, klass->sizeof_public);
	return obj;
}

const NMPObject *
nmp_object_stackinit_id  (NMPObject *obj, const NMPObject *src)
{
	const NMPClass *klass;

	nm_assert (NMP_OBJECT_IS_VALID (src));
	nm_assert (obj);

	klass = NMP_OBJECT_GET_CLASS (src);
	if (!klass->cmd_obj_stackinit_id)
		nmp_object_stackinit (obj, klass->obj_type, NULL);
	else
		klass->cmd_obj_stackinit_id (obj, src);
	return obj;
}

const NMPObject *
nmp_object_stackinit_id_link (NMPObject *obj, int ifindex)
{
	nmp_object_stackinit (obj, NMP_OBJECT_TYPE_LINK, NULL);
	obj->link.ifindex = ifindex;
	return obj;
}

static void
_vt_cmd_obj_stackinit_id_link (NMPObject *obj, const NMPObject *src)
{
	nmp_object_stackinit_id_link (obj, src->link.ifindex);
}

const NMPObject *
nmp_object_stackinit_id_ip4_address (NMPObject *obj, int ifindex, guint32 address, int plen, guint32 peer_address)
{
	nmp_object_stackinit (obj, NMP_OBJECT_TYPE_IP4_ADDRESS, NULL);
	obj->ip4_address.ifindex = ifindex;
	obj->ip4_address.address = address;
	obj->ip4_address.plen = plen;
	obj->ip4_address.peer_address = peer_address;
	return obj;
}

static void
_vt_cmd_obj_stackinit_id_ip4_address (NMPObject *obj, const NMPObject *src)
{
	nmp_object_stackinit_id_ip4_address (obj, src->ip_address.ifindex, src->ip4_address.address, src->ip_address.plen, src->ip4_address.peer_address);
}

const NMPObject *
nmp_object_stackinit_id_ip6_address (NMPObject *obj, int ifindex, const struct in6_addr *address, int plen)
{
	nmp_object_stackinit (obj, NMP_OBJECT_TYPE_IP6_ADDRESS, NULL);
	obj->ip4_address.ifindex = ifindex;
	if (address)
		obj->ip6_address.address = *address;
	obj->ip6_address.plen = plen;
	return obj;
}

static void
_vt_cmd_obj_stackinit_id_ip6_address (NMPObject *obj, const NMPObject *src)
{
	nmp_object_stackinit_id_ip6_address (obj, src->ip_address.ifindex, &src->ip6_address.address, src->ip_address.plen);
}

const NMPObject *
nmp_object_stackinit_id_ip4_route (NMPObject *obj, int ifindex, guint32 network, int plen, guint32 metric)
{
	nmp_object_stackinit (obj, NMP_OBJECT_TYPE_IP4_ROUTE, NULL);
	obj->ip4_route.ifindex = ifindex;
	obj->ip4_route.network = network;
	obj->ip4_route.plen = plen;
	obj->ip4_route.metric = metric;
	return obj;
}

static void
_vt_cmd_obj_stackinit_id_ip4_route (NMPObject *obj, const NMPObject *src)
{
	nmp_object_stackinit_id_ip4_route (obj, src->ip_route.ifindex, src->ip4_route.network, src->ip_route.plen, src->ip_route.metric);
}

const NMPObject *
nmp_object_stackinit_id_ip6_route (NMPObject *obj, int ifindex, const struct in6_addr *network, int plen, guint32 metric)
{
	nmp_object_stackinit (obj, NMP_OBJECT_TYPE_IP6_ROUTE, NULL);
	obj->ip6_route.ifindex = ifindex;
	if (network)
		obj->ip6_route.network = *network;
	obj->ip6_route.plen = plen;
	obj->ip6_route.metric = metric;
	return obj;
}

static void
_vt_cmd_obj_stackinit_id_ip6_route (NMPObject *obj, const NMPObject *src)
{
	nmp_object_stackinit_id_ip6_route (obj, src->ip_route.ifindex, &src->ip6_route.network, src->ip_route.plen, src->ip_route.metric);
}

/******************************************************************/

const char *
nmp_object_to_string (const NMPObject *obj, NMPObjectToStringMode to_string_mode, char *buf, gsize buf_size)
{
	const NMPClass *klass;
	char buf2[sizeof (_nm_utils_to_string_buffer)];
	char buf3[sizeof (_nm_utils_to_string_buffer)];
	char buf4[sizeof (_nm_utils_to_string_buffer)];

	if (!buf) {
		buf = _nm_utils_to_string_buffer;
		buf_size = sizeof (_nm_utils_to_string_buffer);
	}

	if (!obj) {
		g_strlcpy (buf, "(null)", buf_size);
		return buf;
	}

	g_return_val_if_fail (NMP_OBJECT_IS_VALID (obj), NULL);

	klass = NMP_OBJECT_GET_CLASS (obj);

	switch (to_string_mode) {
	case NMP_OBJECT_TO_STRING_ID:
		if (!klass->cmd_plobj_to_string_id) {
			g_snprintf (buf, buf_size, "%p", obj);
			return buf;
		}
		return klass->cmd_plobj_to_string_id (&obj->object, buf, buf_size);
	case NMP_OBJECT_TO_STRING_ALL:
		NMP_OBJECT_GET_CLASS (obj)->cmd_plobj_to_string (&obj->object, buf2, sizeof (buf2));

		if (NMP_OBJECT_GET_TYPE (obj) == NMP_OBJECT_TYPE_LINK) {
			g_snprintf (buf3, sizeof (buf3),
			            ",%cin-nl,%p",
			            obj->_link.netlink.is_in_netlink ? '+' : '-',
			            obj->_link.udev.device);
			if (obj->_link.netlink.lnk) {
				char b[sizeof (_nm_utils_to_string_buffer)];

				g_snprintf (buf4, sizeof (buf4),
				            ", link:%s, %s",
				            NMP_OBJECT_GET_CLASS (obj->_link.netlink.lnk)->obj_type_name,
				            nmp_object_to_string (obj->_link.netlink.lnk, NMP_OBJECT_TO_STRING_PUBLIC, b, sizeof (b)));
			} else
				buf4[0] = '\0';
		} else {
			buf3[0] = '\0';
			buf4[0] = '\0';
		}

		g_snprintf (buf, buf_size,
		            "[%s,%p,%d,%ccache,%calive,%cvisible%s; %s%s]",
		            klass->obj_type_name, obj, obj->_ref_count,
		            obj->is_cached ? '+' : '-',
		            nmp_object_is_alive (obj) ? '+' : '-',
		            nmp_object_is_visible (obj) ? '+' : '-',
		            buf3, buf2, buf4);
		return buf;
	case NMP_OBJECT_TO_STRING_PUBLIC:
		if (   NMP_OBJECT_GET_TYPE (obj) == NMP_OBJECT_TYPE_LINK
		    && obj->_link.netlink.lnk) {
			NMP_OBJECT_GET_CLASS (obj)->cmd_plobj_to_string (&obj->object, buf2, sizeof (buf2));
			nmp_object_to_string (obj->_link.netlink.lnk, NMP_OBJECT_TO_STRING_PUBLIC, buf3, sizeof (buf3));
			g_snprintf (buf, buf_size,
			            "%s; %s",
			            buf2, buf3);
		} else
			NMP_OBJECT_GET_CLASS (obj)->cmd_plobj_to_string (&obj->object, buf, buf_size);
		return buf;
	default:
		g_return_val_if_reached ("ERROR");
	}
}

#define _vt_cmd_plobj_to_string_id(type, plat_type, ...) \
static const char * \
_vt_cmd_plobj_to_string_id_##type (const NMPlatformObject *_obj, char *buf, gsize buf_len) \
{ \
	plat_type *const obj = (plat_type *) _obj; \
	char buf1[NM_UTILS_INET_ADDRSTRLEN]; \
	char buf2[NM_UTILS_INET_ADDRSTRLEN]; \
	\
	(void) buf1; \
	(void) buf2; \
	g_snprintf (buf, buf_len, \
	            __VA_ARGS__); \
	return buf; \
}
_vt_cmd_plobj_to_string_id (link,        NMPlatformLink,       "%d",            obj->ifindex);
_vt_cmd_plobj_to_string_id (ip4_address, NMPlatformIP4Address, "%d: %s/%d%s%s", obj->ifindex, nm_utils_inet4_ntop ( obj->address, buf1), obj->plen,
                                                               obj->peer_address != obj->address ? "," : "",
                                                               obj->peer_address != obj->address ? nm_utils_inet4_ntop (obj->peer_address & nm_utils_ip4_prefix_to_netmask (obj->plen), buf2) : "");
_vt_cmd_plobj_to_string_id (ip6_address, NMPlatformIP6Address, "%d: %s",        obj->ifindex, nm_utils_inet6_ntop (&obj->address, buf1));
_vt_cmd_plobj_to_string_id (ip4_route,   NMPlatformIP4Route,   "%d: %s/%d %d",  obj->ifindex, nm_utils_inet4_ntop ( obj->network, buf1), obj->plen, obj->metric);
_vt_cmd_plobj_to_string_id (ip6_route,   NMPlatformIP6Route,   "%d: %s/%d %d",  obj->ifindex, nm_utils_inet6_ntop (&obj->network, buf1), obj->plen, obj->metric);

int
nmp_object_cmp (const NMPObject *obj1, const NMPObject *obj2)
{
	const NMPClass *klass1, *klass2;

	if (obj1 == obj2)
		return 0;
	if (!obj1)
		return -1;
	if (!obj2)
		return 1;

	g_return_val_if_fail (NMP_OBJECT_IS_VALID (obj1), -1);
	g_return_val_if_fail (NMP_OBJECT_IS_VALID (obj2), 1);

	klass1 = NMP_OBJECT_GET_CLASS (obj1);
	klass2 = NMP_OBJECT_GET_CLASS (obj2);

	if (klass1 != klass2)
		return klass1->obj_type < klass2->obj_type ? -1 : 1;

	if (klass1->cmd_obj_cmp)
		return klass1->cmd_obj_cmp (obj1, obj2);
	return klass1->cmd_plobj_cmp (&obj1->object, &obj2->object);
}

static int
_vt_cmd_obj_cmp_link (const NMPObject *obj1, const NMPObject *obj2)
{
	int i;

	i = nm_platform_link_cmp (&obj1->link, &obj2->link);
	if (i)
		return i;
	if (obj1->_link.netlink.is_in_netlink != obj2->_link.netlink.is_in_netlink)
		return obj1->_link.netlink.is_in_netlink ? -1 : 1;
	i = nmp_object_cmp (obj1->_link.netlink.lnk, obj2->_link.netlink.lnk);
	if (i)
		return i;
	if (obj1->_link.udev.device != obj2->_link.udev.device) {
		if (!obj1->_link.udev.device)
			return -1;
		if (!obj2->_link.udev.device)
			return 1;

		/* Only compare based on pointer values. That is ugly because it's not a
		 * stable sort order, but probably udev gives us always the same GUdevDevice
		 * instance.
		 *
		 * Have this check as very last. */
		return (obj1->_link.udev.device < obj2->_link.udev.device) ? -1 : 1;
	}
	return 0;
}

gboolean
nmp_object_equal (const NMPObject *obj1, const NMPObject *obj2)
{
	return nmp_object_cmp (obj1, obj2) == 0;
}

/* @src is a const object, which is not entirely correct for link types, where
 * we increase the ref count for src->_link.udev.device.
 * Hence, nmp_object_copy() can violate the const promise of @src.
 * */
void
nmp_object_copy (NMPObject *dst, const NMPObject *src, gboolean id_only)
{
	g_return_if_fail (NMP_OBJECT_IS_VALID (dst));
	g_return_if_fail (NMP_OBJECT_IS_VALID (src));
	g_return_if_fail (!NMP_OBJECT_IS_STACKINIT (dst));

	if (src != dst) {
		const NMPClass *klass = NMP_OBJECT_GET_CLASS (dst);

		g_return_if_fail (klass == NMP_OBJECT_GET_CLASS (src));

		if (id_only) {
			if (klass->cmd_plobj_id_copy)
				klass->cmd_plobj_id_copy (&dst->object, &src->object);
		} else if (klass->cmd_obj_copy)
			klass->cmd_obj_copy (dst, src);
		else
			memcpy (&dst->object, &src->object, klass->sizeof_data);
	}
}

static void
_vt_cmd_obj_copy_link (NMPObject *dst, const NMPObject *src)
{
	if (dst->_link.udev.device != src->_link.udev.device) {
		if (src->_link.udev.device)
			g_object_ref (src->_link.udev.device);
		if (dst->_link.udev.device)
			g_object_unref (dst->_link.udev.device);
	}
	if (dst->_link.netlink.lnk != src->_link.netlink.lnk) {
		if (src->_link.netlink.lnk)
			nmp_object_ref (src->_link.netlink.lnk);
		if (dst->_link.netlink.lnk)
			nmp_object_unref (dst->_link.netlink.lnk);
	}
	dst->_link = src->_link;
}

#define _vt_cmd_plobj_id_copy(type, plat_type, cmd) \
static void \
_vt_cmd_plobj_id_copy_##type (NMPlatformObject *_dst, const NMPlatformObject *_src) \
{ \
	plat_type *const dst = (plat_type *) _dst; \
	const plat_type *const src = (const plat_type *) _src; \
	{ cmd } \
}
_vt_cmd_plobj_id_copy (link, NMPlatformLink, {
	dst->ifindex = src->ifindex;
});
_vt_cmd_plobj_id_copy (ip4_address, NMPlatformIP4Address, {
	dst->ifindex = src->ifindex;
	dst->plen = src->plen;
	dst->address = src->address;
	dst->peer_address = src->peer_address;
});
_vt_cmd_plobj_id_copy (ip6_address, NMPlatformIP6Address, {
	dst->ifindex = src->ifindex;
	dst->address = src->address;
});
_vt_cmd_plobj_id_copy (ip4_route, NMPlatformIP4Route, {
	dst->ifindex = src->ifindex;
	dst->plen = src->plen;
	dst->metric = src->metric;
	dst->network = src->network;
});
_vt_cmd_plobj_id_copy (ip6_route, NMPlatformIP6Route, {
	dst->ifindex = src->ifindex;
	dst->plen = src->plen;
	dst->metric = src->metric;
	dst->network = src->network;
});

/* Uses internally nmp_object_copy(), hence it also violates the const
 * promise for @obj.
 * */
NMPObject *
nmp_object_clone (const NMPObject *obj, gboolean id_only)
{
	NMPObject *dst;

	if (!obj)
		return NULL;

	g_return_val_if_fail (NMP_OBJECT_IS_VALID (obj), NULL);

	dst = _nmp_object_new_from_class (NMP_OBJECT_GET_CLASS (obj));
	nmp_object_copy (dst, obj, id_only);
	return dst;
}

gboolean
nmp_object_id_equal (const NMPObject *obj1, const NMPObject *obj2)
{
	const NMPClass *klass;

	if (obj1 == obj2)
		return TRUE;
	if (!obj1 || !obj2)
		return FALSE;

	g_return_val_if_fail (NMP_OBJECT_IS_VALID (obj1), FALSE);
	g_return_val_if_fail (NMP_OBJECT_IS_VALID (obj2), FALSE);

	klass = NMP_OBJECT_GET_CLASS (obj1);
	return    klass == NMP_OBJECT_GET_CLASS (obj2)
	       && klass->cmd_plobj_id_equal
	       && klass->cmd_plobj_id_equal (&obj1->object, &obj2->object);
}

#define _vt_cmd_plobj_id_equal(type, plat_type, cmd) \
static gboolean \
_vt_cmd_plobj_id_equal_##type (const NMPlatformObject *_obj1, const NMPlatformObject *_obj2) \
{ \
	const plat_type *const obj1 = (const plat_type *) _obj1; \
	const plat_type *const obj2 = (const plat_type *) _obj2; \
	return (cmd); \
}
_vt_cmd_plobj_id_equal (link, NMPlatformLink,
                           obj1->ifindex == obj2->ifindex);
_vt_cmd_plobj_id_equal (ip4_address, NMPlatformIP4Address,
                           obj1->ifindex == obj2->ifindex
                        && obj1->plen == obj2->plen
                        && obj1->address == obj2->address
                        /* for IPv4 addresses, you can add the same local address with differing peer-adddress
                         * (IFA_ADDRESS), provided that their net-part differs. */
                        && ((obj1->peer_address ^ obj2->peer_address) & nm_utils_ip4_prefix_to_netmask (obj1->plen)) == 0);
_vt_cmd_plobj_id_equal (ip6_address, NMPlatformIP6Address,
                           obj1->ifindex == obj2->ifindex
                        /* for IPv6 addresses, the prefix length is not part of the primary identifier. */
                        && IN6_ARE_ADDR_EQUAL (&obj1->address, &obj2->address));
_vt_cmd_plobj_id_equal (ip4_route, NMPlatformIP4Route,
                           obj1->ifindex == obj2->ifindex
                        && obj1->plen == obj2->plen
                        && obj1->metric == obj2->metric
                        && obj1->network == obj2->network);
_vt_cmd_plobj_id_equal (ip6_route, NMPlatformIP6Route,
                           obj1->ifindex == obj2->ifindex
                        && obj1->plen == obj2->plen
                        && obj1->metric == obj2->metric
                        && IN6_ARE_ADDR_EQUAL( &obj1->network, &obj2->network));

guint
nmp_object_id_hash (const NMPObject *obj)
{
	const NMPClass *klass;

	if (!obj)
		return 0;

	g_return_val_if_fail (NMP_OBJECT_IS_VALID (obj), 0);

	klass = NMP_OBJECT_GET_CLASS (obj);

	if (klass->cmd_plobj_id_hash)
		return klass->cmd_plobj_id_hash (&obj->object);

	/* unhashable objects implement pointer equality. */
	return g_direct_hash (obj);
}

#define _vt_cmd_plobj_id_hash(type, plat_type, cmd) \
static guint \
_vt_cmd_plobj_id_hash_##type (const NMPlatformObject *_obj) \
{ \
	const plat_type *const obj = (const plat_type *) _obj; \
	guint hash; \
	{ cmd; } \
	return hash; \
}
_vt_cmd_plobj_id_hash (link, NMPlatformLink, {
	hash = (guint) 3982791431u;
	hash = hash      + ((guint) obj->ifindex);
})
_vt_cmd_plobj_id_hash (ip4_address, NMPlatformIP4Address, {
	hash = (guint) 3591309853u;
	hash = hash      + ((guint) obj->ifindex);
	hash = hash * 33 + ((guint) obj->plen);
	hash = hash * 33 + ((guint) obj->address);

	/* for IPv4 we must also consider the net-part of the peer-address (IFA_ADDRESS) */
	hash = hash * 33 + ((guint) (obj->peer_address & nm_utils_ip4_prefix_to_netmask (obj->plen)));
})
_vt_cmd_plobj_id_hash (ip6_address, NMPlatformIP6Address, {
	hash = (guint) 2907861637u;
	hash = hash      + ((guint) obj->ifindex);
	/* for IPv6 addresses, the prefix length is not part of the primary identifier. */
	hash = hash * 33 + _id_hash_ip6_addr (&obj->address);
})
_vt_cmd_plobj_id_hash (ip4_route, NMPlatformIP4Route, {
	hash = (guint) 2569857221u;
	hash = hash      + ((guint) obj->ifindex);
	hash = hash * 33 + ((guint) obj->plen);
	hash = hash * 33 + ((guint) obj->metric);
	hash = hash * 33 + ((guint) obj->network);
})
_vt_cmd_plobj_id_hash (ip6_route, NMPlatformIP6Route, {
	hash = (guint) 3999787007u;
	hash = hash      + ((guint) obj->ifindex);
	hash = hash * 33 + ((guint) obj->plen);
	hash = hash * 33 + ((guint) obj->metric);
	hash = hash * 33 + _id_hash_ip6_addr (&obj->network);
})

gboolean
nmp_object_is_alive (const NMPObject *obj)
{
	const NMPClass *klass;

	/* for convenience, allow NULL. */
	if (!obj)
		return FALSE;

	klass = NMP_OBJECT_GET_CLASS (obj);
	return    !klass->cmd_obj_is_alive
	       || klass->cmd_obj_is_alive (obj);
}

static gboolean
_vt_cmd_obj_is_alive_link (const NMPObject *obj)
{
	return obj->object.ifindex > 0 && (obj->_link.netlink.is_in_netlink || obj->_link.udev.device);
}

static gboolean
_vt_cmd_obj_is_alive_ipx_address (const NMPObject *obj)
{
	return obj->object.ifindex > 0;
}

static gboolean
_vt_cmd_obj_is_alive_ipx_route (const NMPObject *obj)
{
	/* We want to ignore routes that are RTM_F_CLONED but we still
	 * let nmp_object_from_nl() create such route objects, instead of
	 * returning NULL right away.
	 *
	 * The idea is, that if we have the same route (according to its id)
	 * in the cache with !RTM_F_CLONED, an update that changes the route
	 * to be RTM_F_CLONED must remove the instance.
	 *
	 * If nmp_object_from_nl() would just return NULL, we couldn't look
	 * into the cache to see if it contains a route that now disappears
	 * (because it is cloned).
	 *
	 * Instead we create a dead object, and nmp_cache_update_netlink()
	 * will remove the old version of the update.
	 **/
	return obj->object.ifindex > 0 && (obj->ip_route.source != _NM_IP_CONFIG_SOURCE_RTM_F_CLONED);
}

gboolean
nmp_object_is_visible (const NMPObject *obj)
{
	const NMPClass *klass;

	/* for convenience, allow NULL. */
	if (!obj)
		return FALSE;

	klass = NMP_OBJECT_GET_CLASS (obj);

	return    !klass->cmd_obj_is_visible
	       || klass->cmd_obj_is_visible (obj);
}

static gboolean
_vt_cmd_obj_is_visible_link (const NMPObject *obj)
{
	return    obj->object.ifindex > 0
	       && obj->_link.netlink.is_in_netlink
	       && obj->link.name[0];
}

static gboolean
_vt_cmd_obj_is_visible_ipx_address (const NMPObject *obj)
{
	return obj->object.ifindex > 0;
}

static gboolean
_vt_cmd_obj_is_visible_ipx_route (const NMPObject *obj)
{
	NMIPConfigSource source = obj->ip_route.source;

	return obj->object.ifindex > 0 && source != _NM_IP_CONFIG_SOURCE_RTM_F_CLONED;
}

/******************************************************************/

gboolean
nmp_cache_id_equal (const NMPCacheId *a, const NMPCacheId *b)
{
	/* just memcmp() the entire id. This is potentially dangerous, because
	 * the struct is not __attribute__((packed)) and not all types have the
	 * same size. It is important, to memset() the entire struct to 0,
	 * not only the relevant fields.
	 *
	 * You anyway should use the nmp_cache_id_init_*() functions on a stack-allocated
	 * struct. */
	return memcmp (a, b, sizeof (NMPCacheId)) == 0;
}

guint
nmp_cache_id_hash (const NMPCacheId *id)
{
	guint hash = 5381;
	guint i;

	for (i = 0; i < sizeof (NMPCacheId); i++)
		hash = ((hash << 5) + hash) + ((char *) id)[i]; /* hash * 33 + c */
	return hash;
}

NMPCacheId *
nmp_cache_id_clone (const NMPCacheId *id)
{
	NMPCacheId *id2;

	id2 = g_slice_new (NMPCacheId);
	memcpy (id2, id, sizeof (NMPCacheId));
	return id2;
}

void
nmp_cache_id_destroy (NMPCacheId *id)
{
	g_slice_free (NMPCacheId, id);
}

/******************************************************************/

NMPCacheId _nmp_cache_id_static;

static NMPCacheId *
_nmp_cache_id_init (NMPCacheId *id, NMPCacheIdType id_type)
{
	memset (id, 0, sizeof (NMPCacheId));
	id->_id_type = id_type;
	return id;
}

NMPCacheId *
nmp_cache_id_init_object_type (NMPCacheId *id, NMPObjectType obj_type, gboolean visible_only)
{
	_nmp_cache_id_init (id, visible_only
	                        ? NMP_CACHE_ID_TYPE_OBJECT_TYPE_VISIBLE_ONLY
	                        : NMP_CACHE_ID_TYPE_OBJECT_TYPE);
	id->object_type.obj_type = obj_type;
	return id;
}

NMPCacheId *
nmp_cache_id_init_addrroute_visible_by_ifindex (NMPCacheId *id,
                                                NMPObjectType obj_type,
                                                int ifindex)
{
	g_return_val_if_fail (NM_IN_SET (obj_type,
	                                 NMP_OBJECT_TYPE_IP4_ADDRESS, NMP_OBJECT_TYPE_IP4_ROUTE,
	                                 NMP_OBJECT_TYPE_IP6_ADDRESS, NMP_OBJECT_TYPE_IP6_ROUTE), NULL);

	if (ifindex <= 0)
		return nmp_cache_id_init_object_type (id, obj_type, TRUE);

	_nmp_cache_id_init (id, NMP_CACHE_ID_TYPE_ADDRROUTE_VISIBLE_BY_IFINDEX);
	id->object_type_by_ifindex.obj_type = obj_type;
	id->object_type_by_ifindex.ifindex = ifindex;
	return id;
}

NMPCacheId *
nmp_cache_id_init_routes_visible (NMPCacheId *id,
                                  NMPObjectType obj_type,
                                  gboolean with_default,
                                  gboolean with_non_default,
                                  int ifindex)
{
	g_return_val_if_fail (NM_IN_SET (obj_type, NMP_OBJECT_TYPE_IP4_ROUTE, NMP_OBJECT_TYPE_IP6_ROUTE), NULL);

	if (with_default && with_non_default) {
		if (ifindex <= 0)
			return nmp_cache_id_init_object_type (id, obj_type, TRUE);
		return nmp_cache_id_init_addrroute_visible_by_ifindex (id, obj_type, ifindex);
	}

	if (with_default)
		_nmp_cache_id_init (id, NMP_CACHE_ID_TYPE_ROUTES_VISIBLE_BY_IFINDEX_ONLY_DEFAULT);
	else if (with_non_default)
		_nmp_cache_id_init (id, NMP_CACHE_ID_TYPE_ROUTES_VISIBLE_BY_IFINDEX_NO_DEFAULT);
	else
		g_return_val_if_reached (NULL);

	id->object_type_by_ifindex.obj_type = obj_type;
	id->object_type_by_ifindex.ifindex = ifindex;
	return id;
}

/******************************************************************/

static gboolean
_nmp_object_init_cache_id (const NMPObject *obj, NMPCacheIdType id_type, NMPCacheId *id, const NMPCacheId **out_id)
{
	const NMPClass *klass = NMP_OBJECT_GET_CLASS (obj);

	switch (id_type) {
	case NMP_CACHE_ID_TYPE_OBJECT_TYPE:
		*out_id = nmp_cache_id_init_object_type (id, klass->obj_type, FALSE);
		return TRUE;
	case NMP_CACHE_ID_TYPE_OBJECT_TYPE_VISIBLE_ONLY:
		if (nmp_object_is_visible (obj))
			*out_id = nmp_cache_id_init_object_type (id, klass->obj_type, TRUE);
		else
			*out_id = NULL;
		return TRUE;
	default:
		return    klass->cmd_obj_init_cache_id
		       && klass->cmd_obj_init_cache_id (obj, id_type, id, out_id);
	}
}

static gboolean
_vt_cmd_obj_init_cache_id_ipx_address (const NMPObject *obj, NMPCacheIdType id_type, NMPCacheId *id, const NMPCacheId **out_id)
{
	switch (id_type) {
	case NMP_CACHE_ID_TYPE_ADDRROUTE_VISIBLE_BY_IFINDEX:
		if (_vt_cmd_obj_is_visible_ipx_address (obj)) {
			nm_assert (obj->object.ifindex > 0);
			*out_id = nmp_cache_id_init_addrroute_visible_by_ifindex (id, NMP_OBJECT_GET_TYPE (obj), obj->object.ifindex);
			return TRUE;
		}
		break;
	default:
		return FALSE;
	}
	*out_id = NULL;
	return TRUE;
}

static gboolean
_vt_cmd_obj_init_cache_id_ipx_route (const NMPObject *obj, NMPCacheIdType id_type, NMPCacheId *id, const NMPCacheId **out_id)
{
	switch (id_type) {
	case NMP_CACHE_ID_TYPE_ADDRROUTE_VISIBLE_BY_IFINDEX:
		if (_vt_cmd_obj_is_visible_ipx_route (obj)) {
			nm_assert (obj->object.ifindex > 0);
			*out_id = nmp_cache_id_init_addrroute_visible_by_ifindex (id, NMP_OBJECT_GET_TYPE (obj), obj->object.ifindex);
			return TRUE;
		}
		break;
	case NMP_CACHE_ID_TYPE_ROUTES_VISIBLE_NO_DEFAULT:
		if (   _vt_cmd_obj_is_visible_ipx_route (obj)
		    && !NM_PLATFORM_IP_ROUTE_IS_DEFAULT (&obj->ip_route)) {
			nm_assert (obj->object.ifindex > 0);
			*out_id = nmp_cache_id_init_routes_visible (id, NMP_OBJECT_GET_TYPE (obj), FALSE, TRUE, 0);
			return TRUE;
		}
		break;
	case NMP_CACHE_ID_TYPE_ROUTES_VISIBLE_ONLY_DEFAULT:
		if (   _vt_cmd_obj_is_visible_ipx_route (obj)
		    && NM_PLATFORM_IP_ROUTE_IS_DEFAULT (&obj->ip_route)) {
			nm_assert (obj->object.ifindex > 0);
			*out_id = nmp_cache_id_init_routes_visible (id, NMP_OBJECT_GET_TYPE (obj), TRUE, FALSE, 0);
			return TRUE;
		}
		break;
	case NMP_CACHE_ID_TYPE_ROUTES_VISIBLE_BY_IFINDEX_NO_DEFAULT:
		if (   _vt_cmd_obj_is_visible_ipx_route (obj)
		    && !NM_PLATFORM_IP_ROUTE_IS_DEFAULT (&obj->ip_route)) {
			nm_assert (obj->object.ifindex > 0);
			*out_id = nmp_cache_id_init_routes_visible (id, NMP_OBJECT_GET_TYPE (obj), FALSE, TRUE, obj->object.ifindex);
			return TRUE;
		}
		break;
	case NMP_CACHE_ID_TYPE_ROUTES_VISIBLE_BY_IFINDEX_ONLY_DEFAULT:
		if (   _vt_cmd_obj_is_visible_ipx_route (obj)
		    && NM_PLATFORM_IP_ROUTE_IS_DEFAULT (&obj->ip_route)) {
			nm_assert (obj->object.ifindex > 0);
			*out_id = nmp_cache_id_init_routes_visible (id, NMP_OBJECT_GET_TYPE (obj), TRUE, FALSE, obj->object.ifindex);
			return TRUE;
		}
		break;
	default:
		return FALSE;
	}
	*out_id = NULL;
	return TRUE;
}

/******************************************************************/

gboolean
nmp_cache_use_udev_detect ()
{
	return access ("/sys", W_OK) == 0;
}

gboolean
nmp_cache_use_udev_get (const NMPCache *cache)
{
	g_return_val_if_fail (cache, TRUE);

	return cache->use_udev;
}

gboolean
nmp_cache_use_udev_set (NMPCache *cache, gboolean use_udev)
{
	g_return_val_if_fail (cache, FALSE);

	use_udev = !!use_udev;
	if (use_udev == cache->use_udev)
		return FALSE;

	cache->use_udev = use_udev;
	return TRUE;
}

/******************************************************************/

/**
 * nmp_cache_link_connected_needs_toggle:
 * @cache: the platform cache
 * @master: the link object, that is checked whether its connected property
 *   needs to be toggled.
 * @potential_slave: (allow-none): an additional link object that is treated
 *   as if it was inside @cache. If given, it shaddows a link in the cache
 *   with the same ifindex.
 * @ignore_slave: (allow-none): if set, the check will pretend that @ignore_slave
 *   is not in the cache.
 *
 * NMPlatformLink has two connected flags: (master->link.flags&IFF_LOWER_UP) (as reported
 * from netlink) and master->link.connected. For bond and bridge master, kernel reports
 * those links as IFF_LOWER_UP if they have no slaves attached. We want to present instead
 * a combined @connected flag that shows masters without slaves as down.
 *
 * Check if the connected flag of @master should be toggled according to the content
 * of @cache (including @potential_slave).
 *
 * Returns: %TRUE, if @master->link.connected should be flipped/toggled.
 **/
gboolean
nmp_cache_link_connected_needs_toggle (const NMPCache *cache, const NMPObject *master, const NMPObject *potential_slave, const NMPObject *ignore_slave)
{
	const NMPlatformLink *const *links;
	gboolean is_lower_up = FALSE;
	guint len, i;

	if (   !master
	    || NMP_OBJECT_GET_TYPE (master) != NMP_OBJECT_TYPE_LINK
	    || master->link.ifindex <= 0
	    || !nmp_object_is_visible (master)
	    || !NM_IN_SET (master->link.type, NM_LINK_TYPE_BRIDGE, NM_LINK_TYPE_BOND))
		return FALSE;

	/* if native IFF_LOWER_UP is down, link.connected must also be down
	 * regardless of the slaves. */
	if (!NM_FLAGS_HAS (master->link.flags, IFF_LOWER_UP))
		return !!master->link.connected;

	if (potential_slave && NMP_OBJECT_GET_TYPE (potential_slave) != NMP_OBJECT_TYPE_LINK)
		potential_slave = NULL;

	if (   potential_slave
	    && nmp_object_is_visible (potential_slave)
	    && potential_slave->link.ifindex > 0
	    && potential_slave->link.master == master->link.ifindex
	    && potential_slave->link.connected) {
		is_lower_up = TRUE;
	} else {
		links = (const NMPlatformLink *const *) nmp_cache_lookup_multi (cache, nmp_cache_id_init_object_type (NMP_CACHE_ID_STATIC, NMP_OBJECT_TYPE_LINK, FALSE), &len);
		for (i = 0; i < len; i++) {
			const NMPlatformLink *link = links[i];
			const NMPObject *obj = NMP_OBJECT_UP_CAST ((NMPlatformObject *) link);

			nm_assert (NMP_OBJECT_GET_TYPE (NMP_OBJECT_UP_CAST ((NMPlatformObject *) link)) == NMP_OBJECT_TYPE_LINK);

			if (   (!potential_slave || potential_slave->link.ifindex != link->ifindex)
			    && ignore_slave != obj
			    && link->ifindex > 0
			    && link->master == master->link.ifindex
			    && nmp_object_is_visible (obj)
			    && link->connected) {
				is_lower_up = TRUE;
				break;
			}
		}
	}
	return !!master->link.connected != is_lower_up;
}

/**
 * nmp_cache_link_connected_needs_toggle_by_ifindex:
 * @cache:
 * @master_ifindex: the ifindex of a potential master that should be checked
 *   whether it needs toggling.
 * @potential_slave: (allow-none): passed to nmp_cache_link_connected_needs_toggle().
 *   It considers @potential_slave as being inside the cache, replacing an existing
 *   link with the same ifindex.
 * @ignore_slave: (allow-onne): passed to nmp_cache_link_connected_needs_toggle().
 *
 * The flag obj->link.connected depends on the state of other links in the
 * @cache. See also nmp_cache_link_connected_needs_toggle(). Given an ifindex
 * of a master, check if the cache contains such a master link that needs
 * toogling of the connected flag.
 *
 * Returns: NULL if there is no master link with ifindex @master_ifindex that should be toggled.
 *   Otherwise, return the link object from inside the cache with the given ifindex.
 *   The connected flag of that master should be toggled.
 */
const NMPObject *
nmp_cache_link_connected_needs_toggle_by_ifindex (const NMPCache *cache, int master_ifindex, const NMPObject *potential_slave, const NMPObject *ignore_slave)
{
	const NMPObject *master;

	if (master_ifindex > 0) {
		master = nmp_cache_lookup_link (cache, master_ifindex);
		if (nmp_cache_link_connected_needs_toggle (cache, master, potential_slave, ignore_slave))
			return master;
	}
	return NULL;
}

/******************************************************************/

const NMPlatformObject *const *
nmp_cache_lookup_multi (const NMPCache *cache, const NMPCacheId *cache_id, guint *out_len)
{
	return (const NMPlatformObject *const *) nm_multi_index_lookup (cache->idx_multi,
	                                                                (const NMMultiIndexId *) cache_id,
	                                                                out_len);
}

GArray *
nmp_cache_lookup_multi_to_array (const NMPCache *cache, NMPObjectType obj_type, const NMPCacheId *cache_id)
{
	const NMPClass *klass = nmp_class_from_type (obj_type);
	guint len, i;
	const NMPlatformObject *const *objects;
	GArray *array;

	g_return_val_if_fail (klass, NULL);

	objects = nmp_cache_lookup_multi (cache, cache_id, &len);
	array = g_array_sized_new (FALSE, FALSE, klass->sizeof_public, len);

	for (i = 0; i < len; i++) {
		nm_assert (NMP_OBJECT_GET_CLASS (NMP_OBJECT_UP_CAST (objects[i])) == klass);
		g_array_append_vals (array, objects[i], 1);
	}
	return array;
}

const NMPObject *
nmp_cache_lookup_obj (const NMPCache *cache, const NMPObject *obj)
{
	g_return_val_if_fail (obj, NULL);

	return g_hash_table_lookup (cache->idx_main, obj);
}

const NMPObject *
nmp_cache_lookup_link (const NMPCache *cache, int ifindex)
{
	NMPObject obj_needle;

	return nmp_cache_lookup_obj (cache, nmp_object_stackinit_id_link (&obj_needle, ifindex));
}

const NMPObject *
nmp_cache_lookup_link_full (const NMPCache *cache,
                            int ifindex,
                            const char *ifname,
                            gboolean visible_only,
                            NMLinkType link_type,
                            NMPObjectMatchFn match_fn,
                            gpointer user_data)
{
	NMPObject obj_needle;
	const NMPObject *obj;
	const NMPlatformObject *const *list;
	guint i, len;
	NMPCacheId cache_id;

	if (ifindex > 0) {
		obj = nmp_cache_lookup_obj (cache, nmp_object_stackinit_id_link (&obj_needle, ifindex));

		if (   !obj
		    || (visible_only && !nmp_object_is_visible (obj))
		    || (link_type != NM_LINK_TYPE_NONE && obj->link.type != link_type)
		    || (ifname && strcmp (obj->link.name, ifname))
		    || (match_fn && !match_fn (obj, user_data)))
			return NULL;
		return obj;
	} else if (!ifname && !match_fn)
		return NULL;
	else {
		list = nmp_cache_lookup_multi (cache, nmp_cache_id_init_object_type (&cache_id, NMP_OBJECT_TYPE_LINK, visible_only), &len);
		for (i = 0; i < len; i++) {
			obj = NMP_OBJECT_UP_CAST (list[i]);

			if (link_type != NM_LINK_TYPE_NONE && obj->link.type != link_type)
				continue;
			if (ifname && strcmp (ifname, obj->link.name))
				continue;
			if (match_fn && !match_fn (obj, user_data))
				continue;

			return obj;
		}
		return NULL;
	}
}

GHashTable *
nmp_cache_lookup_all_to_hash (const NMPCache *cache,
                              NMPCacheId *cache_id,
                              GHashTable *hash)
{
	NMMultiIndexIdIter iter;
	gpointer plobj;

	nm_multi_index_id_iter_init (&iter, cache->idx_multi, (const NMMultiIndexId *) cache_id);

	if (nm_multi_index_id_iter_next (&iter, &plobj)) {
		if (!hash)
			hash = g_hash_table_new_full (NULL, NULL, (GDestroyNotify) nmp_object_unref, NULL);

		do {
			g_hash_table_add (hash, nmp_object_ref (NMP_OBJECT_UP_CAST (plobj)));
		} while (nm_multi_index_id_iter_next (&iter, &plobj));
	}

	return hash;
}

/******************************************************************/

static void
_nmp_cache_update_cache (NMPCache *cache, NMPObject *obj, gboolean remove)
{
	NMPCacheIdType id_type;

	for (id_type = 0; id_type <= NMP_CACHE_ID_TYPE_MAX; id_type++) {
		NMPCacheId cache_id_storage;
		const NMPCacheId *cache_id;

		if (!_nmp_object_init_cache_id (obj, id_type, &cache_id_storage, &cache_id))
			continue;
		if (!cache_id)
			continue;

		/* We don't put @obj itself into the multi index, but &obj->object. As of now, all
		 * users expect a pointer to NMPlatformObject, not NMPObject.
		 * You can use NMP_OBJECT_UP_CAST() to retrieve the original @obj pointer.
		 *
		 * If need be, we could determine based on @id_type which pointer we want to store. */

		if (remove) {
			if (!nm_multi_index_remove (cache->idx_multi, &cache_id->base, &obj->object))
				g_assert_not_reached ();
		} else {
			if (!nm_multi_index_add (cache->idx_multi, &cache_id->base, &obj->object))
				g_assert_not_reached ();
		}
	}
}

static void
_nmp_cache_update_add (NMPCache *cache, NMPObject *obj)
{
	nm_assert (!obj->is_cached);
	nmp_object_ref (obj);
	nm_assert (!nm_multi_index_lookup_first_by_value (cache->idx_multi, &obj->object));
	if (!nm_g_hash_table_add (cache->idx_main, obj))
		g_assert_not_reached ();
	obj->is_cached = TRUE;
	_nmp_cache_update_cache (cache, obj, FALSE);
}

static void
_nmp_cache_update_remove (NMPCache *cache, NMPObject *obj)
{
	nm_assert (obj->is_cached);
	_nmp_cache_update_cache (cache, obj, TRUE);
	obj->is_cached = FALSE;
	if (!g_hash_table_remove (cache->idx_main, obj))
		g_assert_not_reached ();

	/* @obj is possibly a dangling pointer at this point. No problem, multi-index doesn't dereference. */
	nm_assert (!nm_multi_index_lookup_first_by_value (cache->idx_multi, &obj->object));
}

static void
_nmp_cache_update_update (NMPCache *cache, NMPObject *obj, const NMPObject *new)
{
	NMPCacheIdType id_type;

	nm_assert (NMP_OBJECT_GET_CLASS (obj) == NMP_OBJECT_GET_CLASS (new));
	nm_assert (obj->is_cached);
	nm_assert (!new->is_cached);

	for (id_type = 0; id_type <= NMP_CACHE_ID_TYPE_MAX; id_type++) {
		NMPCacheId cache_id_storage_obj, cache_id_storage_new;
		const NMPCacheId *cache_id_obj, *cache_id_new;

		if (!_nmp_object_init_cache_id (obj, id_type, &cache_id_storage_obj, &cache_id_obj))
			continue;
		if (!_nmp_object_init_cache_id (new, id_type, &cache_id_storage_new, &cache_id_new))
			g_assert_not_reached ();
		if (!nm_multi_index_move (cache->idx_multi, (NMMultiIndexId *) cache_id_obj, (NMMultiIndexId *) cache_id_new, &obj->object))
			g_assert_not_reached ();
	}
	nmp_object_copy (obj, new, FALSE);
}

NMPCacheOpsType
nmp_cache_remove (NMPCache *cache, const NMPObject *obj, gboolean equals_by_ptr, NMPObject **out_obj, gboolean *out_was_visible, NMPCachePreHook pre_hook, gpointer user_data)
{
	NMPObject *old;

	nm_assert (NMP_OBJECT_IS_VALID (obj));

	old = g_hash_table_lookup (cache->idx_main, obj);
	if (!old) {
		if (out_obj)
			*out_obj = NULL;
		if (out_was_visible)
			*out_was_visible = FALSE;
		return NMP_CACHE_OPS_UNCHANGED;
	}

	if (out_obj)
		*out_obj = nmp_object_ref (old);
	if (out_was_visible)
		*out_was_visible = nmp_object_is_visible (old);
	if (equals_by_ptr && old != obj) {
		/* We found an identical object, but we only delete it if it's the same pointer as
		 * @obj. */
		return NMP_CACHE_OPS_UNCHANGED;
	}
	if (pre_hook)
		pre_hook (cache, old, NULL, NMP_CACHE_OPS_REMOVED, user_data);
	_nmp_cache_update_remove (cache, old);
	return NMP_CACHE_OPS_REMOVED;
}

NMPCacheOpsType
nmp_cache_remove_netlink (NMPCache *cache, const NMPObject *obj_needle, NMPObject **out_obj, gboolean *out_was_visible, NMPCachePreHook pre_hook, gpointer user_data)
{
	if (NMP_OBJECT_GET_TYPE (obj_needle) == NMP_OBJECT_TYPE_LINK) {
		NMPObject *old;
		nm_auto_nmpobj NMPObject *obj = NULL;

		/* For nmp_cache_remove_netlink() we have an incomplete @obj_needle instance to be
		 * removed from netlink. Link objects are alive without being in netlink when they
		 * have a udev-device. All we want to do in this case is clear the netlink.is_in_netlink
		 * flag. */

		old = (NMPObject *) nmp_cache_lookup_link (cache, obj_needle->link.ifindex);
		if (!old) {
			if (out_obj)
				*out_obj = NULL;
			if (out_was_visible)
				*out_was_visible = FALSE;
			return NMP_CACHE_OPS_UNCHANGED;
		}

		if (out_obj)
			*out_obj = nmp_object_ref (old);
		if (out_was_visible)
			*out_was_visible = nmp_object_is_visible (old);

		if (!old->_link.netlink.is_in_netlink) {
			nm_assert (old->_link.udev.device);
			return NMP_CACHE_OPS_UNCHANGED;
		}

		if (!old->_link.udev.device) {
			/* the update would make @old invalid. Remove it. */
			if (pre_hook)
				pre_hook (cache, old, NULL, NMP_CACHE_OPS_REMOVED, user_data);
			_nmp_cache_update_remove (cache, old);
			return NMP_CACHE_OPS_REMOVED;
		}

		obj = nmp_object_clone (old, FALSE);
		obj->_link.netlink.is_in_netlink = FALSE;

		_nmp_object_fixup_link_master_connected (obj, cache);
		_nmp_object_fixup_link_udev_fields (obj, cache->use_udev);

		if (pre_hook)
			pre_hook (cache, old, obj, NMP_CACHE_OPS_UPDATED, user_data);
		_nmp_cache_update_update (cache, old, obj);
		return NMP_CACHE_OPS_UPDATED;
	} else
		return nmp_cache_remove (cache, obj_needle, FALSE, out_obj, out_was_visible, pre_hook, user_data);
}

/**
 * nmp_cache_update_netlink:
 * @cache: the platform cache
 * @obj: a #NMPObject instance as received from netlink and created via
 *    nmp_object_from_nl(). Especially for link, it must not have the udev
 *    replated fields set.
 *    This instance will be modified and might be put into the cache. When
 *    calling nmp_cache_update_netlink() you hand @obj over to the cache.
 *    Except, that the cache will increment the ref count as appropriate. You
 *    must still unref the obj to release your part of the ownership.
 * @out_obj: (allow-none): (out): return the object instance that is inside
 *    the cache. If you specify non %NULL, you must always unref the returned
 *    instance. If the return value indicates that the object was removed,
 *    the object is no longer in the cache. Even if the return value indicates
 *    that the object was unchanged, it will still return @out_obj -- if
 *    such an object is in the cache.
 * @out_was_visible: (allow-none): (out): whether the object was visible before
 *    the update operation.
 * @pre_hook: (allow-none): a callback *before* the object gets updated. You cannot
 *    influence the outcome and must not do anything beyong inspecting the changes.
 * @user_data:
 *
 * Returns: how the cache changed.
 **/
NMPCacheOpsType
nmp_cache_update_netlink (NMPCache *cache, NMPObject *obj, NMPObject **out_obj, gboolean *out_was_visible, NMPCachePreHook pre_hook, gpointer user_data)
{
	NMPObject *old;

	nm_assert (NMP_OBJECT_IS_VALID (obj));
	nm_assert (!NMP_OBJECT_IS_STACKINIT (obj));
	nm_assert (!obj->is_cached);

	/* A link object from netlink must have the udev related fields unset.
	 * We could implement to handle that, but there is no need to support such
	 * a use-case */
	nm_assert (NMP_OBJECT_GET_TYPE (obj) != NMP_OBJECT_TYPE_LINK ||
	           (   !obj->_link.udev.device
	            && !obj->link.driver));

	old = g_hash_table_lookup (cache->idx_main, obj);

	if (out_obj)
		*out_obj = NULL;
	if (out_was_visible)
		*out_was_visible = FALSE;

	if (!old) {
		if (!nmp_object_is_alive (obj))
			return NMP_CACHE_OPS_UNCHANGED;

		if (NMP_OBJECT_GET_TYPE (obj) == NMP_OBJECT_TYPE_LINK) {
			_nmp_object_fixup_link_master_connected (obj, cache);
			_nmp_object_fixup_link_udev_fields (obj, cache->use_udev);
		}

		if (out_obj)
			*out_obj = nmp_object_ref (obj);

		if (pre_hook)
			pre_hook (cache, NULL, obj, NMP_CACHE_OPS_ADDED, user_data);
		_nmp_cache_update_add (cache, obj);
		return NMP_CACHE_OPS_ADDED;
	} else if (old == obj) {
		/* updating a cached object inplace is not supported because the object contributes to hash-key
		 * for NMMultiIndex. Modifying an object that is inside NMMultiIndex means that these
		 * keys change.
		 * The problem is, that for a given object NMMultiIndex does not support (efficient)
		 * reverse lookup to get all the NMPCacheIds to which it belongs. If that would be implemented,
		 * it would be possible to implement inplace-update.
		 *
		 * There is an un-optimized reverse lookup via nm_multi_index_iter_init(), but we don't want
		 * that because we might have a large number of indexes to search.
		 *
		 * We could add efficient reverse lookup by adding a reverse index to NMMultiIndex. But that
		 * also adds some cost to support an (uncommon?) usage pattern.
		 *
		 * Instead we just don't support it, instead we expect the user to
		 * create a new instance from netlink.
		 *
		 * TL;DR: a cached object must never be modified.
		 */
		g_assert_not_reached ();
	} else {
		gboolean is_alive = FALSE;

		nm_assert (old->is_cached);

		if (out_obj)
			*out_obj = nmp_object_ref (old);
		if (out_was_visible)
			*out_was_visible = nmp_object_is_visible (old);

		if (NMP_OBJECT_GET_TYPE (obj) == NMP_OBJECT_TYPE_LINK) {
			if (!obj->_link.netlink.is_in_netlink) {
				if (!old->_link.netlink.is_in_netlink) {
					nm_assert (old->_link.udev.device);
					return NMP_CACHE_OPS_UNCHANGED;
				}
				if (old->_link.udev.device) {
					/* @obj is not in netlink.
					 *
					 * This is similar to nmp_cache_remove_netlink(), but there we preserve the
					 * preexisting netlink properties. The use case of that is when kernel_get_object()
					 * cannot load an object (based on the id of a needle).
					 *
					 * Here we keep the data provided from @obj. The usecase is when receiving
					 * a valid @obj instance from netlink with RTM_DELROUTE.
					 */
					is_alive = TRUE;
				}
			} else
				is_alive = TRUE;

			if (is_alive) {
				_nmp_object_fixup_link_master_connected (obj, cache);

				/* Merge the netlink parts with what we have from udev. */
				g_clear_object (&obj->_link.udev.device);
				obj->_link.udev.device = old->_link.udev.device ? g_object_ref (old->_link.udev.device) : NULL;
				_nmp_object_fixup_link_udev_fields (obj, cache->use_udev);
			}
		} else
			is_alive = nmp_object_is_alive (obj);

		if (!is_alive) {
			/* the update would make @old invalid. Remove it. */
			if (pre_hook)
				pre_hook (cache, old, NULL, NMP_CACHE_OPS_REMOVED, user_data);
			_nmp_cache_update_remove (cache, old);
			return NMP_CACHE_OPS_REMOVED;
		}

		if (nmp_object_equal (old, obj))
			return NMP_CACHE_OPS_UNCHANGED;

		if (pre_hook)
			pre_hook (cache, old, obj, NMP_CACHE_OPS_UPDATED, user_data);
		_nmp_cache_update_update (cache, old, obj);
		return NMP_CACHE_OPS_UPDATED;
	}
}

NMPCacheOpsType
nmp_cache_update_link_udev (NMPCache *cache, int ifindex, GUdevDevice *udev_device, NMPObject **out_obj, gboolean *out_was_visible, NMPCachePreHook pre_hook, gpointer user_data)
{
	NMPObject *old;
	nm_auto_nmpobj NMPObject *obj = NULL;

	old = (NMPObject *) nmp_cache_lookup_link (cache, ifindex);

	if (out_obj)
		*out_obj = NULL;
	if (out_was_visible)
		*out_was_visible = FALSE;

	if (!old) {
		if (!udev_device)
			return NMP_CACHE_OPS_UNCHANGED;

		obj = nmp_object_new (NMP_OBJECT_TYPE_LINK, NULL);
		obj->link.ifindex = ifindex;
		obj->_link.udev.device = g_object_ref (udev_device);

		_nmp_object_fixup_link_udev_fields (obj, cache->use_udev);

		nm_assert (nmp_object_is_alive (obj));

		if (out_obj)
			*out_obj = nmp_object_ref (obj);

		if (pre_hook)
			pre_hook (cache, NULL, obj, NMP_CACHE_OPS_ADDED, user_data);
		_nmp_cache_update_add (cache, obj);
		return NMP_CACHE_OPS_ADDED;
	} else {
		nm_assert (old->is_cached);

		if (out_obj)
			*out_obj = nmp_object_ref (old);
		if (out_was_visible)
			*out_was_visible = nmp_object_is_visible (old);

		if (old->_link.udev.device == udev_device)
			return NMP_CACHE_OPS_UNCHANGED;

		if (!udev_device && !old->_link.netlink.is_in_netlink) {
			/* the update would make @old invalid. Remove it. */
			if (pre_hook)
				pre_hook (cache, old, NULL, NMP_CACHE_OPS_REMOVED, user_data);
			_nmp_cache_update_remove (cache, old);
			return NMP_CACHE_OPS_REMOVED;
		}

		obj = nmp_object_clone (old, FALSE);

		g_clear_object (&obj->_link.udev.device);
		obj->_link.udev.device = udev_device ? g_object_ref (udev_device) : NULL;

		_nmp_object_fixup_link_udev_fields (obj, cache->use_udev);

		nm_assert (nmp_object_is_alive (obj));

		if (pre_hook)
			pre_hook (cache, old, obj, NMP_CACHE_OPS_UPDATED, user_data);
		_nmp_cache_update_update (cache, old, obj);
		return NMP_CACHE_OPS_UPDATED;
	}
}

NMPCacheOpsType
nmp_cache_update_link_master_connected (NMPCache *cache, int ifindex, NMPObject **out_obj, gboolean *out_was_visible, NMPCachePreHook pre_hook, gpointer user_data)
{
	NMPObject *old;
	nm_auto_nmpobj NMPObject *obj = NULL;

	old = (NMPObject *) nmp_cache_lookup_link (cache, ifindex);

	if (!old) {
		if (out_obj)
			*out_obj = NULL;
		if (out_was_visible)
			*out_was_visible = FALSE;

		return NMP_CACHE_OPS_UNCHANGED;
	}

	nm_assert (old->is_cached);

	if (out_obj)
		*out_obj = nmp_object_ref (old);
	if (out_was_visible)
		*out_was_visible = nmp_object_is_visible (old);

	if (!nmp_cache_link_connected_needs_toggle (cache, old, NULL, NULL))
		return NMP_CACHE_OPS_UNCHANGED;

	obj = nmp_object_clone (old, FALSE);
	obj->link.connected = !old->link.connected;

	nm_assert (nmp_object_is_alive (obj));

	if (pre_hook)
		pre_hook (cache, old, obj, NMP_CACHE_OPS_UPDATED, user_data);
	_nmp_cache_update_update (cache, old, obj);
	return NMP_CACHE_OPS_UPDATED;
}

/******************************************************************/

NMPCache *
nmp_cache_new ()
{
	NMPCache *cache = g_new (NMPCache, 1);

	cache->idx_main = g_hash_table_new_full ((GHashFunc) nmp_object_id_hash,
	                                         (GEqualFunc) nmp_object_id_equal,
	                                         (GDestroyNotify) nmp_object_unref,
	                                         NULL);
	cache->idx_multi = nm_multi_index_new ((NMMultiIndexFuncHash) nmp_cache_id_hash,
	                                       (NMMultiIndexFuncEqual) nmp_cache_id_equal,
	                                       (NMMultiIndexFuncClone) nmp_cache_id_clone,
	                                       (NMMultiIndexFuncDestroy) nmp_cache_id_destroy);
	cache->use_udev = nmp_cache_use_udev_detect ();
	return cache;
}

void
nmp_cache_free (NMPCache *cache)
{
	GHashTableIter iter;
	NMPObject *obj;

	/* No need to cumbersomely remove the objects properly. They are not hooked up
	 * in a complicated way, we can just unref them together with cache->idx_main.
	 *
	 * But we must clear the @is_cached flag. */
	g_hash_table_iter_init (&iter, cache->idx_main);
	while (g_hash_table_iter_next (&iter, (gpointer *) &obj, NULL)) {
		nm_assert (obj->is_cached);
		obj->is_cached = FALSE;
	}

	nm_multi_index_free (cache->idx_multi);
	g_hash_table_unref (cache->idx_main);

	g_free (cache);
}

/******************************************************************/

void
ASSERT_nmp_cache_is_consistent (const NMPCache *cache)
{
#if NM_MORE_ASSERTS
	NMMultiIndexIter iter_multi;
	GHashTableIter iter_hash;
	guint i, len;
	NMPCacheId cache_id_storage;
	const NMPCacheId *cache_id, *cache_id2;
	const NMPlatformObject *const *objects;
	const NMPObject *obj;

	g_assert (cache);

	g_hash_table_iter_init (&iter_hash, cache->idx_main);
	while (g_hash_table_iter_next (&iter_hash, (gpointer *) &obj, NULL)) {
		NMPCacheIdType id_type;

		g_assert (NMP_OBJECT_IS_VALID (obj));
		g_assert (nmp_object_is_alive (obj));

		for (id_type = 0; id_type <= NMP_CACHE_ID_TYPE_MAX; id_type++) {
			if (!_nmp_object_init_cache_id (obj, id_type, &cache_id_storage, &cache_id))
				continue;
			if (!cache_id)
				continue;
			g_assert (nm_multi_index_contains (cache->idx_multi, &cache_id->base, &obj->object));
		}
	}

	nm_multi_index_iter_init (&iter_multi, cache->idx_multi, NULL);
	while (nm_multi_index_iter_next (&iter_multi,
	                                 (const NMMultiIndexId **) &cache_id,
	                                 (void *const**) &objects,
	                                 &len)) {
		g_assert (len > 0 && objects && objects[len] == NULL);

		for (i = 0; i < len; i++) {
			g_assert (objects[i]);
			obj = NMP_OBJECT_UP_CAST (objects[i]);
			g_assert (NMP_OBJECT_IS_VALID (obj));

			/* for now, enforce that all objects for a certain index are of the same type. */
			g_assert (NMP_OBJECT_GET_CLASS (obj) == NMP_OBJECT_GET_CLASS (NMP_OBJECT_UP_CAST (objects[0])));

			if (!_nmp_object_init_cache_id (obj, cache_id->_id_type, &cache_id_storage, &cache_id2))
				g_assert_not_reached ();
			g_assert (cache_id2);
			g_assert (nmp_cache_id_equal (cache_id, cache_id2));
			g_assert_cmpint (nmp_cache_id_hash (cache_id), ==, nmp_cache_id_hash (cache_id2));

			g_assert (obj == g_hash_table_lookup (cache->idx_main, obj));
		}
	}
#endif
}
/******************************************************************/

const NMPClass _nmp_classes[NMP_OBJECT_TYPE_MAX] = {
	[NMP_OBJECT_TYPE_LINK - 1] = {
		.obj_type                           = NMP_OBJECT_TYPE_LINK,
		.sizeof_data                        = sizeof (NMPObjectLink),
		.sizeof_public                      = sizeof (NMPlatformLink),
		.obj_type_name                      = "link",
		.addr_family                        = AF_UNSPEC,
		.rtm_gettype                        = RTM_GETLINK,
		.signal_type                        = NM_PLATFORM_SIGNAL_LINK_CHANGED,
		.cmd_obj_cmp                        = _vt_cmd_obj_cmp_link,
		.cmd_obj_copy                       = _vt_cmd_obj_copy_link,
		.cmd_obj_stackinit_id               = _vt_cmd_obj_stackinit_id_link,
		.cmd_obj_dispose                    = _vt_cmd_obj_dispose_link,
		.cmd_obj_is_alive                   = _vt_cmd_obj_is_alive_link,
		.cmd_obj_is_visible                 = _vt_cmd_obj_is_visible_link,
		.cmd_plobj_id_copy                  = _vt_cmd_plobj_id_copy_link,
		.cmd_plobj_id_equal                 = _vt_cmd_plobj_id_equal_link,
		.cmd_plobj_id_hash                  = _vt_cmd_plobj_id_hash_link,
		.cmd_plobj_to_string_id             = _vt_cmd_plobj_to_string_id_link,
		.cmd_plobj_to_string                = (const char *(*) (const NMPlatformObject *obj, char *buf, gsize len)) nm_platform_link_to_string,
		.cmd_plobj_cmp                      = (int (*) (const NMPlatformObject *obj1, const NMPlatformObject *obj2)) nm_platform_link_cmp,
	},
	[NMP_OBJECT_TYPE_IP4_ADDRESS - 1] = {
		.obj_type                           = NMP_OBJECT_TYPE_IP4_ADDRESS,
		.sizeof_data                        = sizeof (NMPObjectIP4Address),
		.sizeof_public                      = sizeof (NMPlatformIP4Address),
		.obj_type_name                      = "ip4-address",
		.addr_family                        = AF_INET,
		.rtm_gettype                        = RTM_GETADDR,
		.signal_type                        = NM_PLATFORM_SIGNAL_IP4_ADDRESS_CHANGED,
		.cmd_obj_init_cache_id              = _vt_cmd_obj_init_cache_id_ipx_address,
		.cmd_obj_stackinit_id               = _vt_cmd_obj_stackinit_id_ip4_address,
		.cmd_obj_is_alive                   = _vt_cmd_obj_is_alive_ipx_address,
		.cmd_obj_is_visible                 = _vt_cmd_obj_is_visible_ipx_address,
		.cmd_plobj_id_copy                  = _vt_cmd_plobj_id_copy_ip4_address,
		.cmd_plobj_id_equal                 = _vt_cmd_plobj_id_equal_ip4_address,
		.cmd_plobj_id_hash                  = _vt_cmd_plobj_id_hash_ip4_address,
		.cmd_plobj_to_string_id             = _vt_cmd_plobj_to_string_id_ip4_address,
		.cmd_plobj_to_string                = (const char *(*) (const NMPlatformObject *obj, char *buf, gsize len)) nm_platform_ip4_address_to_string,
		.cmd_plobj_cmp                      = (int (*) (const NMPlatformObject *obj1, const NMPlatformObject *obj2)) nm_platform_ip4_address_cmp,
	},
	[NMP_OBJECT_TYPE_IP6_ADDRESS - 1] = {
		.obj_type                           = NMP_OBJECT_TYPE_IP6_ADDRESS,
		.sizeof_data                        = sizeof (NMPObjectIP6Address),
		.sizeof_public                      = sizeof (NMPlatformIP6Address),
		.obj_type_name                      = "ip6-address",
		.addr_family                        = AF_INET6,
		.rtm_gettype                        = RTM_GETADDR,
		.signal_type                        = NM_PLATFORM_SIGNAL_IP6_ADDRESS_CHANGED,
		.cmd_obj_init_cache_id              = _vt_cmd_obj_init_cache_id_ipx_address,
		.cmd_obj_stackinit_id               = _vt_cmd_obj_stackinit_id_ip6_address,
		.cmd_obj_is_alive                   = _vt_cmd_obj_is_alive_ipx_address,
		.cmd_obj_is_visible                 = _vt_cmd_obj_is_visible_ipx_address,
		.cmd_plobj_id_copy                  = _vt_cmd_plobj_id_copy_ip6_address,
		.cmd_plobj_id_equal                 = _vt_cmd_plobj_id_equal_ip6_address,
		.cmd_plobj_id_hash                  = _vt_cmd_plobj_id_hash_ip6_address,
		.cmd_plobj_to_string_id             = _vt_cmd_plobj_to_string_id_ip6_address,
		.cmd_plobj_to_string                = (const char *(*) (const NMPlatformObject *obj, char *buf, gsize len)) nm_platform_ip6_address_to_string,
		.cmd_plobj_cmp                      = (int (*) (const NMPlatformObject *obj1, const NMPlatformObject *obj2)) nm_platform_ip6_address_cmp
	},
	[NMP_OBJECT_TYPE_IP4_ROUTE - 1] = {
		.obj_type                           = NMP_OBJECT_TYPE_IP4_ROUTE,
		.sizeof_data                        = sizeof (NMPObjectIP4Route),
		.sizeof_public                      = sizeof (NMPlatformIP4Route),
		.obj_type_name                      = "ip4-route",
		.addr_family                        = AF_INET,
		.rtm_gettype                        = RTM_GETROUTE,
		.signal_type                        = NM_PLATFORM_SIGNAL_IP4_ROUTE_CHANGED,
		.cmd_obj_init_cache_id              = _vt_cmd_obj_init_cache_id_ipx_route,
		.cmd_obj_stackinit_id               = _vt_cmd_obj_stackinit_id_ip4_route,
		.cmd_obj_is_alive                   = _vt_cmd_obj_is_alive_ipx_route,
		.cmd_obj_is_visible                 = _vt_cmd_obj_is_visible_ipx_route,
		.cmd_plobj_id_copy                  = _vt_cmd_plobj_id_copy_ip4_route,
		.cmd_plobj_id_equal                 = _vt_cmd_plobj_id_equal_ip4_route,
		.cmd_plobj_id_hash                  = _vt_cmd_plobj_id_hash_ip4_route,
		.cmd_plobj_to_string_id             = _vt_cmd_plobj_to_string_id_ip4_route,
		.cmd_plobj_to_string                = (const char *(*) (const NMPlatformObject *obj, char *buf, gsize len)) nm_platform_ip4_route_to_string,
		.cmd_plobj_cmp                      = (int (*) (const NMPlatformObject *obj1, const NMPlatformObject *obj2)) nm_platform_ip4_route_cmp,
	},
	[NMP_OBJECT_TYPE_IP6_ROUTE - 1] = {
		.obj_type                           = NMP_OBJECT_TYPE_IP6_ROUTE,
		.sizeof_data                        = sizeof (NMPObjectIP6Route),
		.sizeof_public                      = sizeof (NMPlatformIP6Route),
		.obj_type_name                      = "ip6-route",
		.addr_family                        = AF_INET6,
		.rtm_gettype                        = RTM_GETROUTE,
		.signal_type                        = NM_PLATFORM_SIGNAL_IP6_ROUTE_CHANGED,
		.cmd_obj_init_cache_id              = _vt_cmd_obj_init_cache_id_ipx_route,
		.cmd_obj_stackinit_id               = _vt_cmd_obj_stackinit_id_ip6_route,
		.cmd_obj_is_alive                   = _vt_cmd_obj_is_alive_ipx_route,
		.cmd_obj_is_visible                 = _vt_cmd_obj_is_visible_ipx_route,
		.cmd_plobj_id_copy                  = _vt_cmd_plobj_id_copy_ip6_route,
		.cmd_plobj_id_equal                 = _vt_cmd_plobj_id_equal_ip6_route,
		.cmd_plobj_id_hash                  = _vt_cmd_plobj_id_hash_ip6_route,
		.cmd_plobj_to_string_id             = _vt_cmd_plobj_to_string_id_ip6_route,
		.cmd_plobj_to_string                = (const char *(*) (const NMPlatformObject *obj, char *buf, gsize len)) nm_platform_ip6_route_to_string,
		.cmd_plobj_cmp                      = (int (*) (const NMPlatformObject *obj1, const NMPlatformObject *obj2)) nm_platform_ip6_route_cmp,
	},
	[NMP_OBJECT_TYPE_LNK_GRE - 1] = {
		.obj_type                           = NMP_OBJECT_TYPE_LNK_GRE,
		.sizeof_data                        = sizeof (NMPObjectLnkGre),
		.sizeof_public                      = sizeof (NMPlatformLnkGre),
		.obj_type_name                      = "gre",
		.cmd_plobj_to_string                = (const char *(*) (const NMPlatformObject *obj, char *buf, gsize len)) nm_platform_lnk_gre_to_string,
		.cmd_plobj_cmp                      = (int (*) (const NMPlatformObject *obj1, const NMPlatformObject *obj2)) nm_platform_lnk_gre_cmp,
	},
	[NMP_OBJECT_TYPE_LNK_INFINIBAND - 1] = {
		.obj_type                           = NMP_OBJECT_TYPE_LNK_INFINIBAND,
		.sizeof_data                        = sizeof (NMPObjectLnkInfiniband),
		.sizeof_public                      = sizeof (NMPlatformLnkInfiniband),
		.obj_type_name                      = "infiniband",
		.cmd_plobj_to_string                = (const char *(*) (const NMPlatformObject *obj, char *buf, gsize len)) nm_platform_lnk_infiniband_to_string,
		.cmd_plobj_cmp                      = (int (*) (const NMPlatformObject *obj1, const NMPlatformObject *obj2)) nm_platform_lnk_infiniband_cmp,
	},
	[NMP_OBJECT_TYPE_LNK_MACVLAN - 1] = {
		.obj_type                           = NMP_OBJECT_TYPE_LNK_MACVLAN,
		.sizeof_data                        = sizeof (NMPObjectLnkMacvlan),
		.sizeof_public                      = sizeof (NMPlatformLnkMacvlan),
		.obj_type_name                      = "macvlan",
		.cmd_plobj_to_string                = (const char *(*) (const NMPlatformObject *obj, char *buf, gsize len)) nm_platform_lnk_macvlan_to_string,
		.cmd_plobj_cmp                      = (int (*) (const NMPlatformObject *obj1, const NMPlatformObject *obj2)) nm_platform_lnk_macvlan_cmp,
	},
	[NMP_OBJECT_TYPE_LNK_VLAN - 1] = {
		.obj_type                           = NMP_OBJECT_TYPE_LNK_VLAN,
		.sizeof_data                        = sizeof (NMPObjectLnkVlan),
		.sizeof_public                      = sizeof (NMPlatformLnkVlan),
		.obj_type_name                      = "vlan",
		.cmd_plobj_to_string                = (const char *(*) (const NMPlatformObject *obj, char *buf, gsize len)) nm_platform_lnk_vlan_to_string,
		.cmd_plobj_cmp                      = (int (*) (const NMPlatformObject *obj1, const NMPlatformObject *obj2)) nm_platform_lnk_vlan_cmp,
	},
	[NMP_OBJECT_TYPE_LNK_VXLAN - 1] = {
		.obj_type                           = NMP_OBJECT_TYPE_LNK_VXLAN,
		.sizeof_data                        = sizeof (NMPObjectLnkVxlan),
		.sizeof_public                      = sizeof (NMPlatformLnkVxlan),
		.obj_type_name                      = "vxlan",
		.cmd_plobj_to_string                = (const char *(*) (const NMPlatformObject *obj, char *buf, gsize len)) nm_platform_lnk_vxlan_to_string,
		.cmd_plobj_cmp                      = (int (*) (const NMPlatformObject *obj1, const NMPlatformObject *obj2)) nm_platform_lnk_vxlan_cmp,
	},
};

